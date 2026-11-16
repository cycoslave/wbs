"""
System lifecycle regressions (SYS-1, SYS-2, SYS-6, SYS-8).

SYS-1  the pidfile names the surviving (daemonized) supervisor, is held
       with an exclusive flock, and a second start is refused with rc!=0
       ("WBS is already running (pid N)"); stale pidfiles are taken over.
SYS-2  SIGTERM/SIGINT stop Core gracefully (IRC QUIT, tasks stopped, DB
       checkpointed) inside the grace period: no "sending SIGKILL".
SYS-6  db 0600, log 0640, pidfile 0644, backups 0600; one log line per
       record in daemon mode; size-based log rotation (logging.max_bytes /
       logging.backup_count).
SYS-8  `.checkupdate` / `.update` without update.host say so; `.update`
       installs only with an explicit `confirm`.

The end-to-end tests run the real ``./wbs`` launcher (detached, and ``-f``
in a pseudo terminal) against the local fake IRC server of test_lifecycle.
"""
from __future__ import annotations

import asyncio
import collections
import logging
import os
import signal
import sqlite3
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_lifecycle import (  # noqa: F401  (shared helpers/fixtures)
    LAUNCHER, VENV_PY, FakeIrcServer, PtyBot, _alive, _descendants, _env, _free_port,
    _kill_procs_in, _log, _seed_db_only, _write_config, botdir, ptybot,
)

from src import commands
from src import main as wbs_main
from src.configcheck import validate_config
from src.update import UpdateManager


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


@pytest.fixture(autouse=True)
def _no_leftover_bots(tmp_path):
    yield
    _kill_procs_in(tmp_path)


def _start(tmp: Path, *extra: str, timeout: float = 30) -> subprocess.CompletedProcess:
    """Run the detached launcher; output via a file (a daemon must not keep
    the caller's pipe open)."""
    out = tmp / f"launch-{time.monotonic_ns()}.out"
    with open(out, "w") as fh:
        p = subprocess.run([str(VENV_PY), str(LAUNCHER), *extra], cwd=tmp, env=_env(),
                           stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                           timeout=timeout)
    return subprocess.CompletedProcess(p.args, p.returncode, out.read_text(), "")


def _pidfile_pid(tmp: Path) -> int:
    return int((tmp / "wbs.pid").read_text().split()[0])


def _wait(cond, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


def _bot_procs(tmp: Path) -> set[int]:
    """Live processes whose cwd is tmp (the bots started in this test)."""
    out = set()
    for d in Path("/proc").iterdir():
        try:
            if d.name.isdigit() and (d / "cwd").resolve() == tmp.resolve() \
                    and _alive(int(d.name)):
                out.add(int(d.name))
        except OSError:
            pass
    return out


@pytest.fixture
def daemon(botdir):
    """A detached bot (./wbs, no -f) that is connected to the fake ircd."""
    tmp, irc, listen_port = botdir
    res = _start(tmp)
    assert res.returncode == 0, res.stdout
    assert _wait(lambda: "Core event loop running" in _log(tmp)), _log(tmp)
    assert _wait(lambda: any("USER " in " ".join(c["lines"]) for c in irc.snapshot())), _log(tmp)
    yield tmp, irc
    _kill_procs_in(tmp)


# ---------------------------------------------------------------------------
# SYS-1: pidfile, lock, double start
# ---------------------------------------------------------------------------
def test_daemon_pidfile_names_the_running_supervisor(daemon):
    tmp, _ = daemon
    pid = _pidfile_pid(tmp)
    assert _alive(pid), f"pidfile holds dead pid {pid}"
    kids = _descendants(pid)
    assert len(kids) >= 2, f"pid {pid} is not the supervisor (children: {kids})"
    assert _bot_procs(tmp) == kids | {pid}


def test_second_start_is_refused_and_keeps_the_pidfile(daemon):
    tmp, _ = daemon
    pid = _pidfile_pid(tmp)
    before = _bot_procs(tmp)
    for extra in ((), ("-f",)):
        res = _start(tmp, *extra)
        assert res.returncode != 0, res.stdout
        assert f"WBS is already running (pid {pid})" in res.stdout
        time.sleep(1.0)
        assert _pidfile_pid(tmp) == pid
        assert _bot_procs(tmp) == before, "a second bot tree started"


def test_concurrent_starts_start_exactly_one_bot(botdir):
    tmp, _, _ = botdir
    outs = [tmp / f"race{i}.out" for i in range(3)]
    fhs = [open(o, "w") for o in outs]
    procs = [subprocess.Popen([str(VENV_PY), str(LAUNCHER)], cwd=tmp, env=_env(),
                              stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT)
             for fh in fhs]
    codes = [p.wait(timeout=30) for p in procs]
    for fh in fhs:
        fh.close()
    text = "".join(o.read_text() for o in outs)
    assert codes.count(0) == 1, (codes, text)
    assert "WBS is already running" in text
    assert _wait(lambda: "Core event loop running" in _log(tmp))
    time.sleep(1.0)
    pid = _pidfile_pid(tmp)
    assert _alive(pid)
    assert _bot_procs(tmp) == _descendants(pid) | {pid}, "more than one bot tree"


def test_stale_pidfile_is_taken_over(botdir):
    tmp, _, _ = botdir
    dead = subprocess.Popen(["true"])
    dead.wait()
    (tmp / "wbs.pid").write_text(f"{dead.pid} 1.0\n")
    res = _start(tmp)
    assert res.returncode == 0, res.stdout
    assert _wait(lambda: "Core event loop running" in _log(tmp))
    pid = _pidfile_pid(tmp)
    assert pid != dead.pid and _alive(pid) and _descendants(pid)


def test_acquire_pidfile_lock_excludes_a_second_owner(tmp_path):
    """Unit: while one process holds the pidfile, another cannot take it,
    whatever the file says; once the holder is gone the file is free."""
    path = str(tmp_path / "run" / "wbs.pid")
    r, w = os.pipe()
    child = os.fork()
    if child == 0:                                   # the "running bot"
        try:
            os.close(r)
            wbs_main.acquire_pidfile(path)
            os.write(w, b"x")
            time.sleep(30)
        finally:
            os._exit(0)
    os.close(w)
    try:
        assert os.read(r, 1) == b"x"
        Path(path).write_text("1 1.0\n")             # garbage must not matter
        with pytest.raises(wbs_main.AlreadyRunning):
            wbs_main.acquire_pidfile(path)
        with pytest.raises(SystemExit) as ei:
            wbs_main.check_already_running(path)
        assert ei.value.code == 1
    finally:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        os.close(r)
    try:
        wbs_main.acquire_pidfile(path)               # stale now: taken over
        assert int(Path(path).read_text().split()[0]) == os.getpid()
        assert _mode(Path(path)) == 0o644
    finally:
        wbs_main.release_pidfile()
    assert not Path(path).exists()


# ---------------------------------------------------------------------------
# SYS-2: graceful SIGTERM / SIGINT
# ---------------------------------------------------------------------------
def _assert_graceful(log: str, irc, quit_msg: str | None = "Shutting down") -> None:
    assert "sending SIGKILL" not in log, log
    assert "did not terminate" not in log, log
    assert "[Core] Shutdown complete" in log, log
    assert "[Core] Database closed" in log, log
    assert "Traceback" not in log, log
    quits = [l for c in irc.snapshot() for l in c["lines"] if l.startswith("QUIT")]
    assert len(quits) == 1, quits
    if quit_msg is not None:
        assert quits == [f"QUIT :{quit_msg}"], quits


def test_sigterm_stops_daemon_gracefully(daemon):
    tmp, irc = daemon
    pid = _pidfile_pid(tmp)
    procs = _bot_procs(tmp)
    t0 = time.time()
    os.kill(pid, signal.SIGTERM)
    assert _wait(lambda: not _bot_procs(tmp), 15), _log(tmp)
    assert time.time() - t0 < wbs_main.SHUTDOWN_GRACE["core"]
    assert not [p for p in procs if _alive(p)]
    _assert_graceful(_log(tmp), irc)
    assert not (tmp / "wbs.pid").exists()
    assert not (tmp / "db" / "wbs.db-wal").exists() or \
        (tmp / "db" / "wbs.db-wal").stat().st_size == 0


@pytest.mark.parametrize("how", ["sigterm", "ctrl-c"])
def test_foreground_shutdown_is_graceful(ptybot, how):
    bot, tmp, irc, _ = ptybot
    if how == "sigterm":
        os.kill(bot.pidfile_pid(), signal.SIGTERM)
    else:
        os.write(bot.master, b"\x03")
    assert bot.wait_for(lambda: bot.proc.poll() is not None, 15), bot.text()
    bot.wait_for(lambda: False, 0.5)
    # ^C also reaches the console, which ends with "Console exited" first.
    _assert_graceful(bot.text() + _log(tmp), irc,
                     "Shutting down" if how == "sigterm" else None)
    assert bot.proc.returncode == 0


# ---------------------------------------------------------------------------
# SYS-6: file modes, single log lines, rotation
# ---------------------------------------------------------------------------
def test_runtime_file_modes(daemon):
    tmp, _ = daemon
    assert _mode(tmp / "db" / "wbs.db") == 0o600
    assert _mode(tmp / "logs" / "wbs.log") == 0o640
    assert _mode(tmp / "wbs.pid") == 0o644
    wal = tmp / "db" / "wbs.db-wal"
    if wal.exists():
        assert _mode(wal) & 0o077 == 0


def test_existing_world_readable_db_and_log_are_tightened(tmp_path):
    from src.db import init_db
    db = tmp_path / "db" / "wbs.db"
    db.parent.mkdir()
    sqlite3.connect(db).close()
    os.chmod(db, 0o644)
    asyncio.run(init_db(str(db)))
    assert _mode(db) == 0o600
    log = tmp_path / "old.log"
    log.write_text("x\n")
    os.chmod(log, 0o644)
    h = wbs_main.SharedRotatingFileHandler(str(log))
    h.close()
    assert _mode(log) == 0o640


def test_daemon_logs_each_line_once(daemon):
    tmp, _ = daemon
    os.kill(_pidfile_pid(tmp), signal.SIGTERM)
    assert _wait(lambda: not _bot_procs(tmp), 15)
    lines = _log(tmp).splitlines()
    dups = [l for l, n in collections.Counter(lines).items() if n > 1]
    assert not dups, dups
    for marker in ("Launching WBS", "Core event loop running", "Supervisor shutting down"):
        assert sum(marker in l for l in lines) == 1, (marker, lines)


def test_backups_are_owner_only(tmp_path, monkeypatch):
    from src.db import _backup_db
    db = tmp_path / "wbs.db"
    sqlite3.connect(db).close()
    os.chmod(db, 0o644)
    cfg = tmp_path / "config.json"
    cfg.write_text("{}")
    os.chmod(cfg, 0o644)
    assert _mode(Path(_backup_db(str(db), "test"))) == 0o600

    async def allow(*a, **k):
        return True
    monkeypatch.setattr(commands, "_require_flag", allow)
    out = []

    async def respond(m):
        out.append(m)
    core = SimpleNamespace(db_path=str(db), config_path=str(cfg))
    asyncio.run(commands.cmd_backup(core, "op", 1, "", respond))
    assert out[-1] == "Backup complete."
    baks = sorted(tmp_path.glob("*.json.*.bak")) + sorted(tmp_path.glob("wbs.db.2*.bak"))
    assert len(baks) == 2
    for b in baks:
        assert _mode(b) == 0o600, b


def _rot_logger(path: Path, max_bytes: int, backups: int) -> logging.Logger:
    lg = logging.getLogger(f"wbs.test.rot.{path.name}")
    lg.propagate = False
    lg.setLevel(logging.INFO)
    h = wbs_main.SharedRotatingFileHandler(str(path), maxBytes=max_bytes, backupCount=backups)
    h.setFormatter(logging.Formatter(wbs_main.LOG_FORMAT))
    lg.addHandler(h)
    return lg


def test_log_rotation_by_size_across_processes(tmp_path):
    """Supervisor and forked children share the handler: rotation still
    happens at size, keeps backup_count files, loses no line."""
    path = tmp_path / "logs" / "wbs.log"
    lg = _rot_logger(path, 2000, 3)
    lg.info("start")
    kids = []
    for n in range(3):
        pid = os.fork()
        if pid == 0:
            try:
                for i in range(150):
                    lg.info(f"child{n} line {i:04d} " + "x" * 40)
            finally:
                os._exit(0)
        kids.append(pid)
    for i in range(150):
        lg.info(f"parent line {i:04d} " + "y" * 40)
    for pid in kids:
        os.waitpid(pid, 0)
    for h in lg.handlers:
        h.close()
    files = sorted(path.parent.iterdir())
    assert [f.name for f in files] == ["wbs.log", "wbs.log.1", "wbs.log.2", "wbs.log.3"]
    for f in files:
        assert f.stat().st_size <= 2000 + 200, (f, f.stat().st_size)
        assert _mode(f) == 0o640
    lines = path.read_text().splitlines()
    assert lines and all(" INFO " in l for l in lines)


def test_log_rotation_settings_from_config():
    assert wbs_main.log_rotation({}) == (wbs_main.DEFAULT_LOG_MAX_BYTES,
                                         wbs_main.DEFAULT_LOG_BACKUP_COUNT)
    assert wbs_main.DEFAULT_LOG_MAX_BYTES > 0 and wbs_main.DEFAULT_LOG_BACKUP_COUNT > 0
    assert wbs_main.log_rotation({"logging": {"max_bytes": 4096, "backup_count": 2}}) == (4096, 2)
    errs, _ = validate_config({"logging": {"max_bytes": "big", "backup_count": -1}},
                              require_bot=False)
    paths = {p for p, _ in errs}
    assert {"logging.max_bytes", "logging.backup_count"} <= paths
    assert validate_config({"logging": {"max_bytes": 0, "backup_count": 3}},
                           require_bot=False)[0] == []


def test_daemon_uses_rotating_handler_only(tmp_path):
    """Unit: daemon logging = exactly one root handler, the rotating file."""
    root = logging.getLogger()
    saved = root.handlers[:]
    try:
        root.handlers = [logging.StreamHandler()]
        wbs_main.use_file_logging(str(tmp_path / "l" / "wbs.log"),
                                  {"logging": {"max_bytes": 1234, "backup_count": 2}})
        wbs_main.use_file_logging(str(tmp_path / "l" / "wbs.log"), {})
        hs = root.handlers
        assert len(hs) == 1 and isinstance(hs[0], wbs_main.SharedRotatingFileHandler)
        assert (hs[0].maxBytes, hs[0].backupCount) == (1234, 2)
        hs[0].close()
    finally:
        root.handlers = saved


def test_foreground_logging_is_console_plus_rotating_file_then_detach(tmp_path):
    """Live O-3 unit: -f keeps the console handler and adds the same file
    handler; the later .detach swaps the console for the file only."""
    root = logging.getLogger()
    saved = root.handlers[:]
    logfile = str(tmp_path / "l" / "wbs.log")
    try:
        console = logging.StreamHandler()
        root.handlers = [console]
        cfg = {"logging": {"max_bytes": 1234, "backup_count": 2}}
        wbs_main.use_file_logging(logfile, cfg, keep_console=True)
        wbs_main.use_file_logging(logfile, cfg, keep_console=True)   # idempotent
        files = [h for h in root.handlers if isinstance(h, wbs_main.SharedRotatingFileHandler)]
        assert root.handlers[0] is console and len(root.handlers) == 2 and len(files) == 1
        assert (files[0].maxBytes, files[0].backupCount) == (1234, 2)
        assert files[0].formatter is not None
        assert files[0].formatter._fmt == wbs_main.LOG_FORMAT  # type: ignore[union-attr]
        wbs_main.use_file_logging(logfile, cfg)                       # .detach
        assert root.handlers == files
        files[0].close()
    finally:
        root.handlers = saved


def test_foreground_mode_writes_log_file(ptybot):
    """Live O-3: ./wbs -f logs to the console AND to logging.file."""
    bot, tmp, irc, _ = ptybot
    marker = "Launching WBS"
    assert bot.wait_for(lambda: marker in _log(tmp), 10), (_log(tmp), bot.text())
    assert marker in bot.text()
    log = _log(tmp)
    # Lines logged after the seed step, once the bot is running.
    assert bot.wait_for(lambda: "Core event loop running" in _log(tmp), 10), log
    assert "Core event loop running" in bot.text()
    assert _mode(tmp / "logs" / "wbs.log") == 0o640


# ---------------------------------------------------------------------------
# SYS-8: update messages and confirmation
# ---------------------------------------------------------------------------
def _run_cmd(fn, core, arg=""):
    out = []

    async def respond(m):
        out.append(m)
    asyncio.run(fn(core, "op", 1, arg, respond))
    return out


@pytest.mark.parametrize("cfg", [{}, {"update": {"host": ""}}, {"update": {"host": "  "}}])
def test_update_commands_without_host_say_not_configured(cfg):
    core = SimpleNamespace(update=UpdateManager(cfg))
    msg = "Updates are not configured (update.host missing)."
    assert _run_cmd(commands.cmd_checkupdate, core) == [msg]
    assert _run_cmd(commands.cmd_update, core) == [msg]
    assert _run_cmd(commands.cmd_update, core, "confirm") == [msg]


class _FakeUpdate:
    configured = True
    NOT_CONFIGURED = "Updates are not configured (update.host missing)"
    last_error = None

    def __init__(self):
        self.installed = []

    async def check_update(self):
        return SimpleNamespace(version_str="9.9.9", author="dev")

    async def perform_update(self, manifest):
        self.installed.append(manifest.version_str)
        return True


def test_update_installs_only_with_confirm():
    upd = _FakeUpdate()
    core = SimpleNamespace(update=upd)
    out = _run_cmd(commands.cmd_update, core)
    assert upd.installed == []
    assert any("9.9.9" in m and ".update confirm" in m for m in out), out
    assert _run_cmd(commands.cmd_update, core, "now") == ["Usage: .update [confirm]"]
    assert upd.installed == []
    out = _run_cmd(commands.cmd_update, core, "confirm")
    assert upd.installed == ["9.9.9"]
    assert out[-1].startswith("Update installed")


def test_update_help_mentions_confirm():
    out = []

    async def respond(m):
        out.append(m)
    asyncio.run(commands.cmd_help(SimpleNamespace(), "op", 1, "update", respond))
    assert "confirm" in "\n".join(out)
