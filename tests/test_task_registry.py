"""
Regression tests for NET-9: `.tasks`, `.taskset` and `.timers` were dead.

`.tasks` always said "No tasks registered." and `.taskset` "Unknown task"
because nothing ever populated `core.tasks`; `.timers` always said "No
active IRC timers." because it read `core.irc_timers`, which only exists
in the IRC process.

Now the Core's periodic jobs run through src/tasks.TaskRegistry (the
`.taskset` choice is saved in task_settings and survives a restart) and
`.timers` is a request/response over the core->irc queue answered by the
real WbsIrcBot (no socket).
"""
import asyncio
import queue
import time
from types import SimpleNamespace as NS

import pytest

from src import tasks as tasks_mod
from src.commands import cmd_tasks, cmd_taskset, cmd_timers
from src.core import Core
from src.db import get_db, init_db
from src.tasks import TaskRegistry

from test_irc_channel_sync import make_core, make_irc

CORE_TASKS = {"autolink", "ircreq_expire", "flood_unban", "lag_check", "update_check",
              "game_tick"}


class EventQ:
    def __init__(self):
        self.items = []

    def put_nowait(self, item):
        self.items.append(item)

    def put(self, item, block=True):
        self.items.append(item)


def real_core(db: str, **cfg) -> Core:
    config = {"bot": {"nick": "wbs"}, "db": {"path": db},
              "settings": {"allow_plaintext": True}, **cfg}
    return Core(config, db + ".json", NS(db_path=None), core_q=EventQ(), irc_q=EventQ())


def run_cmd(core, func, arg=""):
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    async def go():
        await func(core, "boss", 1, arg, respond)
    asyncio.run(go())
    return out


async def settle(n=20):
    for _ in range(n):
        await asyncio.sleep(0)


@pytest.fixture
def fast(monkeypatch):
    """Allow sub-second intervals so a loop can run several times."""
    monkeypatch.setattr(tasks_mod, "MIN_INTERVAL", 0.001)


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "wbs.db")
    asyncio.run(init_db(path))
    return path


# ---------------------------------------------------------------------------
# .tasks lists the wired Core jobs
# ---------------------------------------------------------------------------
def test_core_registers_its_periodic_jobs(db):
    core = real_core(db)
    asyncio.run(core._register_core_tasks())
    assert set(core.tasks.tasks) == CORE_TASKS
    out = run_cmd(core, cmd_tasks)
    assert out[0] == f"Tasks ({len(CORE_TASKS)}):"
    body = "\n".join(out)
    for name in CORE_TASKS:
        assert name in body
    assert "No tasks registered" not in body
    # no update.host -> the update check is off by default
    assert "update_check         [OFF]" in body
    assert "autolink             [ON ] every 5s" in body


def test_update_check_on_when_host_configured(db):
    core = real_core(db, update={"host": "https://upd.example"})
    asyncio.run(core._register_core_tasks())
    assert core.tasks.tasks["update_check"].enabled


def test_plugin_core_timer_is_a_registry_task(db, fast):
    core = real_core(db)
    calls = []

    async def cb():
        calls.append(1)

    async def go():
        core.tasks.start()
        await core.register_timer("example_core_timer", cb, 0.01)
        await asyncio.sleep(0.05)
        assert "example_core_timer" in core.tasks.tasks
        core.unregister_timer("example_core_timer")
        assert "example_core_timer" not in core.tasks.tasks
        n = len(calls)
        await asyncio.sleep(0.05)
        assert len(calls) == n
        core.tasks.stop_all()
    asyncio.run(go())
    assert calls


def test_autolink_runs_through_the_registry_not_its_own_loop(db):
    core = real_core(db)

    async def go():
        await core.botnet.start()
        assert core.botnet.autolink._task is None      # no private loop any more
        ticks = []

        async def tick():
            ticks.append(1)
        core.botnet.autolink._tick = tick
        await core._register_core_tasks()
        await core.tasks.run_once(core.tasks.tasks["autolink"])
        assert ticks == [1]
    asyncio.run(go())


# ---------------------------------------------------------------------------
# .taskset off stops the job and survives a restart
# ---------------------------------------------------------------------------
def test_taskset_off_stops_the_job(db, fast):
    runs = []

    async def job():
        runs.append(time.monotonic())

    async def go():
        reg = TaskRegistry(db)
        await reg.load()
        reg.register("job", job, 0.005, "test job", first_delay=0)
        reg.start()
        await asyncio.sleep(0.05)
        assert runs, "job never ran"
        t = await reg.set_enabled("job", False)
        assert t.handle is None and t.next_run is None
        n = len(runs)
        await asyncio.sleep(0.05)
        assert len(runs) == n, "disabled job kept running"
        await reg.set_enabled("job", True)
        await asyncio.sleep(0.05)
        assert len(runs) > n
        reg.stop_all()
    asyncio.run(go())


def test_taskset_command_persists_across_restart(db):
    core = real_core(db)
    asyncio.run(core._register_core_tasks())
    assert run_cmd(core, cmd_taskset, "lag_check off") == ["Task lag_check disabled."]
    assert run_cmd(core, cmd_taskset, "flood_unban interval=60") == \
        ["Task flood_unban interval set to 60s."]

    async def rows():
        async with get_db(db) as d:
            return {r["name"]: (r["enabled"], r["interval"]) for r in
                    await d.execute_fetchall("SELECT * FROM task_settings")}
    assert asyncio.run(rows()) == {"lag_check": (0, 30.0), "flood_unban": (1, 60.0)}

    # "restart": a fresh Core on the same DB
    core2 = real_core(db)

    async def boot():
        await core2._register_core_tasks()
        core2.tasks.start()
        state = {n: (t.enabled, t.interval, t.handle is not None)
                 for n, t in core2.tasks.tasks.items()}
        core2.tasks.stop_all()
        return state
    state = asyncio.run(boot())
    assert state["lag_check"] == (False, 30.0, False)     # off: no loop launched
    assert state["flood_unban"] == (True, 60.0, True)
    assert state["autolink"][2] is True
    out = "\n".join(run_cmd(core2, cmd_tasks))
    assert "lag_check            [OFF]" in out
    assert "flood_unban          [ON ] every 60s" in out


def test_saved_on_overrides_default_off(db):
    core = real_core(db)
    asyncio.run(core._register_core_tasks())
    assert not core.tasks.tasks["update_check"].enabled
    run_cmd(core, cmd_taskset, "update_check on")
    core2 = real_core(db)
    asyncio.run(core2._register_core_tasks())
    assert core2.tasks.tasks["update_check"].enabled


def test_taskset_validation(db):
    core = real_core(db)
    asyncio.run(core._register_core_tasks())
    assert run_cmd(core, cmd_taskset, "nope off")[0].startswith("Unknown task: nope")
    assert run_cmd(core, cmd_taskset, "")[0].startswith("Usage: .taskset")
    assert run_cmd(core, cmd_taskset, "lag_check maybe")[0].startswith("Usage: .taskset")
    assert "whole seconds" in run_cmd(core, cmd_taskset, "lag_check interval=abc")[0]
    assert "1..86400" in run_cmd(core, cmd_taskset, "lag_check interval=0")[0]
    assert "1..86400" in run_cmd(core, cmd_taskset, "lag_check interval=999999")[0]
    assert "cannot be disabled" in run_cmd(core, cmd_taskset, "ircreq_expire off")[0]
    assert core.tasks.tasks["ircreq_expire"].enabled


def test_job_error_is_recorded_and_loop_survives(db, fast):
    calls = []

    async def bad():
        calls.append(1)
        raise RuntimeError("boom")

    async def go():
        reg = TaskRegistry(db)
        reg.register("bad", bad, 0.005, first_delay=0)
        reg.start()
        await asyncio.sleep(0.05)
        t = reg.tasks["bad"]
        reg.stop_all()
        return t
    t = asyncio.run(go())
    assert len(calls) >= 2
    assert t.last_error == "RuntimeError: boom" and t.last_run is not None
    lines = tasks_mod.format_tasks([t])
    assert any("last error: RuntimeError: boom" in l for l in lines)


# ---------------------------------------------------------------------------
# .timers: request/response through the queue with the real IRC side
# ---------------------------------------------------------------------------
@pytest.fixture
def irc_env(tmp_path):
    from test_irc_channel_sync import build_db
    path = str(tmp_path / "wbs.db")
    asyncio.run(build_db(path))
    core = make_core(path)
    core.handlers["IRC_TIMERS"] = core.on_irc_timers
    irc, _ = make_irc(path)
    return core, irc


def deliver(core, irc):
    """core->irc queue through WbsIrcBot.execute_command, then every event
    the IRC process emits back through Core.handle_event."""
    for p in core.irc_q.items:
        irc.execute_command(p)
    core.irc_q.items.clear()
    events = []
    while True:
        try:
            events.append(irc.core_q.get_nowait())
        except queue.Empty:
            break
    return events


def test_timers_asks_the_irc_process(irc_env):
    core, irc = irc_env
    assert not hasattr(core, "irc_timers")
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    async def go():
        await irc._register_irc_timer("chanlock", 30)
        irc._timer_ran("maintenance", irc.MAINTENANCE_INTERVAL)
        await cmd_timers(core, "boss", 1, "", respond)
        assert out == []                              # answer not there yet
        assert core.irc_q.items[0]["cmd"] == "timers"
        events = deliver(core, irc)
        assert [e["type"] for e in events] == ["IRC_TIMERS"]
        for ev in events:
            await core.handle_event(ev)
        await irc._unregister_irc_timer("chanlock")
    asyncio.run(go())
    assert out[0] == "IRC timers (2):"
    assert "chanlock" in out[1] and "every 30s" in out[1] and "last never" in out[1]
    assert "maintenance" in out[2] and "every 15s" in out[2] and "nick reclaim" in out[2]
    assert core.ircreq.pending == []


def test_timers_answer_matches_its_request_and_stale_ones_ignored(irc_env):
    core, irc = irc_env
    a, b = [], []

    async def ra(m):
        a.append(m)

    async def rb(m):
        b.append(m)

    async def go():
        await cmd_timers(core, "boss", 1, "", ra)
        await cmd_timers(core, "boss", 1, "", rb)
        ids = [p["req_id"] for p in core.irc_q.items]
        assert len(set(ids)) == 2
        events = deliver(core, irc)
        for ev in reversed(events):              # answers out of order
            await core.handle_event(ev)
        # an unknown / repeated answer changes nothing
        await core.handle_event(dict(events[0]))
    asyncio.run(go())
    assert a == ["No active IRC timers."] and b == ["No active IRC timers."]


def test_timers_times_out_without_irc(irc_env):
    core, irc = irc_env
    out = []

    async def respond(m):
        out.append(m)

    async def go():
        await cmd_timers(core, "boss", 1, "", respond)
        p = core.ircreq.pending[0]
        await core.ircreq.expire(now=p.deadline + 1)
    asyncio.run(go())
    assert out == ["No reply from the IRC process to .timers."]


def test_timers_snapshot_drops_finished_plugin_timers(irc_env):
    _, irc = irc_env

    async def go():
        await irc._register_irc_timer("limit", 300)
        irc.irc_timers["limit"].cancel()
        await asyncio.sleep(0)
        return irc.timers_snapshot()
    assert asyncio.run(go()) == []
