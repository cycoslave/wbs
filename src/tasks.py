# src/tasks.py
"""
Core task registry (NET-9).

Every periodic job of the Core process runs through one TaskRegistry, so
`.tasks` can list what really runs and `.taskset` can switch a job off or
change its interval:

  * a Task has a name, description, interval, enabled flag and the run
    state last_run / next_run / last_error / runs;
  * each enabled task is one asyncio loop: sleep until next_run, call the
    job, record the outcome (an exception is logged and kept in
    last_error, it never ends the loop);
  * `.taskset` overrides (enabled, interval) are stored in the
    task_settings table and applied when the task is registered again
    after a restart.

Plugin core timers (Core.register_timer) are registered here as well.
IRC-process timers are not: `.timers` asks the IRC process for them.
"""
import asyncio
import logging
import random
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from .db import get_db

log = logging.getLogger("wbs.tasks")

MIN_INTERVAL = 1
MAX_INTERVAL = 86400

Job = Callable[[], Awaitable[None]]


@dataclass
class Task:
    name: str
    fn: Job
    interval: float
    description: str = ""
    enabled: bool = True
    first_delay: Optional[float] = None   # None: one interval
    jitter: float = 0.0                   # +/- seconds per run
    can_disable: bool = True
    last_run: Optional[float] = None
    next_run: Optional[float] = None
    last_error: Optional[str] = None
    runs: int = 0
    handle: Optional[asyncio.Task] = None


class TaskRegistry:
    def __init__(self, db_path: Optional[str] = None, spawn=None):
        self.db_path = db_path
        self.tasks: dict[str, Task] = {}
        # name -> (enabled, interval|None) from task_settings.
        self._saved: dict[str, tuple[bool, Optional[float]]] = {}
        self._spawn = spawn
        self.started = False

    # -- persistence ---------------------------------------------------------
    async def load(self) -> None:
        """Read the saved `.taskset` overrides (call before registering)."""
        if not self.db_path:
            return
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT name, enabled, interval FROM task_settings")
        self._saved = {r["name"]: (bool(r["enabled"]), r["interval"]) for r in rows}
        for name, task in self.tasks.items():
            self._apply_saved(task)

    async def _save(self, task: Task) -> None:
        if not self.db_path:
            return
        async with get_db(self.db_path) as db:
            await db.execute(
                "INSERT INTO task_settings(name, enabled, interval) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET enabled = excluded.enabled, "
                "interval = excluded.interval",
                (task.name, int(task.enabled), task.interval))
            await db.commit()
        self._saved[task.name] = (task.enabled, task.interval)

    def _apply_saved(self, task: Task) -> None:
        saved = self._saved.get(task.name)
        if not saved:
            return
        enabled, interval = saved
        if task.can_disable:
            task.enabled = enabled
        if interval:
            task.interval = clamp_interval(interval)

    # -- registration --------------------------------------------------------
    def register(self, name: str, fn: Job, interval: float, description: str = "",
                 *, first_delay: Optional[float] = None, jitter: float = 0.0,
                 can_disable: bool = True, enabled: bool = True) -> Task:
        """Add (or replace) a job; it starts at once if the registry runs.
        `enabled` is the default; a saved `.taskset` choice wins over it."""
        self.unregister(name)
        task = Task(name=name, fn=fn, interval=clamp_interval(interval),
                    description=description, first_delay=first_delay,
                    jitter=jitter, can_disable=can_disable, enabled=enabled)
        self._apply_saved(task)
        self.tasks[name] = task
        if self.started:
            self._launch(task)
        return task

    def unregister(self, name: str) -> None:
        task = self.tasks.pop(name, None)
        if task is not None:
            self._cancel(task)

    def start(self) -> None:
        """Launch every enabled task (from inside the running event loop)."""
        self.started = True
        for task in self.tasks.values():
            if task.handle is None:
                self._launch(task)

    def stop_all(self) -> None:
        self.started = False
        for task in self.tasks.values():
            self._cancel(task)

    # -- control (`.taskset`) -------------------------------------------------
    async def set_enabled(self, name: str, enabled: bool) -> Task:
        task = self.tasks[name]
        if not enabled and not task.can_disable:
            raise ValueError(f"Task {name} cannot be disabled.")
        task.enabled = enabled
        self._cancel(task)
        if self.started:
            self._launch(task)
        await self._save(task)
        return task

    async def set_interval(self, name: str, interval: float) -> Task:
        if not MIN_INTERVAL <= interval <= MAX_INTERVAL:
            raise ValueError(f"interval must be {MIN_INTERVAL}..{MAX_INTERVAL} seconds")
        task = self.tasks[name]
        task.interval = float(interval)
        # Restart the loop so the new interval applies to the next run.
        self._cancel(task)
        if self.started:
            self._launch(task, delay=task.interval)
        await self._save(task)
        return task

    # -- running -------------------------------------------------------------
    async def run_once(self, task: Task) -> None:
        task.last_run = time.time()
        task.runs += 1
        try:
            await task.fn()
            task.last_error = None
        except asyncio.CancelledError:
            raise
        except Exception as e:
            task.last_error = f"{type(e).__name__}: {e}"
            log.error("Task %s error: %s", task.name, e)

    def _launch(self, task: Task, delay: Optional[float] = None) -> None:
        if not task.enabled:
            task.next_run = None
            return
        if delay is None:
            delay = task.interval if task.first_delay is None else task.first_delay
        coro = self._loop(task, delay)
        if self._spawn is not None:
            task.handle = self._spawn(coro, f"task:{task.name}")
        else:
            task.handle = asyncio.get_running_loop().create_task(coro, name=f"task:{task.name}")

    def _cancel(self, task: Task) -> None:
        if task.handle is not None:
            task.handle.cancel()
            task.handle = None
        task.next_run = None

    async def _loop(self, task: Task, delay: float) -> None:
        while True:
            task.next_run = time.time() + delay
            await asyncio.sleep(delay)
            await self.run_once(task)
            delay = task.interval
            if task.jitter:
                delay = max(float(MIN_INTERVAL), delay + random.uniform(-task.jitter, task.jitter))


def clamp_interval(value: float) -> float:
    return float(min(max(float(value), MIN_INTERVAL), MAX_INTERVAL))


def _ago(ts: Optional[float], now: float) -> str:
    return "never" if ts is None else f"{int(max(0, now - ts))}s ago"


def _until(ts: Optional[float], now: float) -> str:
    return "-" if ts is None else f"in {int(max(0, ts - now))}s"


def format_tasks(tasks, now: Optional[float] = None) -> list[str]:
    """`.tasks` lines."""
    now = time.time() if now is None else now
    lines = [f"Tasks ({len(tasks)}):"]
    for t in sorted(tasks, key=lambda t: t.name):
        state = "ON " if t.enabled else "OFF"
        lines.append(f"  {t.name:<20} [{state}] every {int(t.interval)}s, "
                     f"last {_ago(t.last_run, now)}, next {_until(t.next_run, now)}"
                     f" - {t.description}")
        if t.last_error:
            lines.append(f"  {'':<20} last error: {t.last_error}")
    return lines
