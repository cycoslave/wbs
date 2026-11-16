"""
Process lifecycle regressions (USR-9, USR-15, USR-16, USR-18, USR-20).

USR-15  ``--seed`` (and ``-f --seed``) seeds the database, then exits.
USR-9   ``.detach`` on the foreground console really sends the bot to the
        background: the launched command returns, the bot keeps running and
        stays reachable (here: its IRC connection and the telnet listener).
USR-16  ``.rehash`` replaces Core without the ``execv(sys.argv)`` that handed
        ``-f`` to the interpreter ("Unknown option: -f"); IRC is kept.
USR-18  supervisor shutdown (SIGTERM / Ctrl+C) prints no traceback: the
        children no longer inherit the supervisor's signal handler.
USR-20  ``.die`` gets the IRC QUIT to the server before the socket closes,
        and the shutdown's second quit no longer logs "Not connected".

The end-to-end tests run the real ``./wbs`` launcher in a pseudo terminal
against a local fake IRC server (127.0.0.1, no TLS, no real network).
"""
from __future__ import annotations

import json
import os
import pty
import re
import select
import signal
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "wbs"
VENV_PY = ROOT / ".venv" / "bin" / "python"

pytestmark = pytest.mark.skipif(not VENV_PY.exists(), reason="project .venv missing")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakeIrcServer:
    """Minimal IRC server: welcomes every client and records its lines."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.conns: list[dict] = []
        self.lock = threading.Lock()
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self._stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            rec = {"lines": [], "closed": False}
            with self.lock:
                self.conns.append(rec)
            threading.Thread(target=self._serve, args=(c, rec), daemon=True).start()

    def _serve(self, c, rec):
        buf = b""
        nick = "bot"
        try:
            while True:
                data = c.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.decode(errors="replace").rstrip("\r")
                    with self.lock:
                        rec["lines"].append(line)
                    if line.startswith("NICK "):
                        nick = line.split()[1]
                    elif line.startswith("USER "):
                        c.sendall(f":fake 001 {nick} :Welcome\r\n"
                                  f":fake 376 {nick} :End of MOTD\r\n".encode())
                    elif line.startswith("PING "):
                        c.sendall(f":fake PONG fake {line[5:]}\r\n".encode())
        except OSError:
            pass
        finally:
            with self.lock:
                rec["closed"] = True
            c.close()

    def snapshot(self) -> list[dict]:
        with self.lock:
            return [{"lines": list(r["lines"]), "closed": r["closed"]} for r in self.conns]

    def close(self):
        self._stop = True
        self.sock.close()


def _write_config(tmp: Path, irc_port: int, listen_port: int) -> Path:
    cfg = {
        "bot": {"nick": "wLife", "user": "life", "realname": "lifecycle test",
                "servers": [{"host": "127.0.0.1", "port": irc_port, "ssl": False}],
                "channels": []},
        "users": [],
        "subnet": {"id": 1, "name": "default"},
        "botnet": {"relay_from": {}},
        "db": {"path": "db/wbs.db"},
        "logging": {"level": "INFO", "file": "logs/wbs.log"},
        "plugins": [],
        "dcc": {"enabled": False},
        "update": {"host": "", "auto_updates": False},
        "settings": {"pid_file": "wbs.pid", "botnet": False,
                     "listen_host": "127.0.0.1", "listen_port": listen_port,
                     "ssl": False, "allow_plaintext": True},
    }
    path = tmp / "config.json"
    path.write_text(json.dumps(cfg))
    path.chmod(0o600)       # WB3-001: group/other-readable configs are refused
    return path


def _env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in ("VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME", "_WBS_VENV_REEXEC")}
    env["TERM"] = "dumb"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _seed(tmp: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(VENV_PY), str(LAUNCHER), *extra, "--seed"], cwd=tmp,
                          env=_env(), capture_output=True, text=True, timeout=30,
                          stdin=subprocess.DEVNULL)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers kill(0); count it as gone.
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except OSError:
        return False


def _descendants(pid: int) -> set[int]:
    """All live descendants of pid (from /proc), even after reparenting."""
    out, frontier = set(), {pid}
    while frontier:
        nxt = set()
        for d in Path("/proc").iterdir():
            if not d.name.isdigit():
                continue
            try:
                ppid = int((d / "stat").read_text().split(") ", 1)[1].split()[1])
            except (OSError, IndexError, ValueError):
                continue
            if ppid in frontier and int(d.name) not in out:
                nxt.add(int(d.name))
        out |= nxt
        frontier = nxt
    return out


class PtyBot:
    """./wbs -f in a pseudo terminal; collects everything it prints."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        master, slave = pty.openpty()
        self.master = master
        self.proc = subprocess.Popen(
            [str(VENV_PY), str(LAUNCHER), "-f"], cwd=tmp, env=_env(),
            stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        self.out = b""
        self.pids: set[int] = set()

    def _pump(self, timeout: float = 0.1) -> None:
        r, _, _ = select.select([self.master], [], [], timeout)
        if r:
            try:
                self.out += os.read(self.master, 65536)
            except OSError:
                time.sleep(timeout)     # slave side closed

    def text(self) -> str:
        return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", self.out.decode(errors="replace"))

    def wait_for(self, cond, timeout: float = 20.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self._pump()
            if self.proc.pid:
                self.pids |= _descendants(self.proc.pid)
            if cond():
                return True
        return False

    def send(self, line: str) -> None:
        os.write(self.master, line.encode() + b"\r")

    def pidfile_pid(self) -> int:
        return int((self.tmp / "wbs.pid").read_text().split()[0])

    def kill_all(self) -> None:
        for pid in self.pids | _descendants(self.proc.pid) | {self.proc.pid}:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            pass
        try:
            os.close(self.master)
        except OSError:
            pass


def _kill_procs_in(tmp: Path) -> None:
    """SIGKILL every process whose cwd is tmp (bots the test left behind)."""
    for d in Path("/proc").iterdir():
        try:
            if d.name.isdigit() and Path(d / "cwd").resolve() == tmp.resolve():
                os.kill(int(d.name), signal.SIGKILL)
        except OSError:
            pass


@pytest.fixture(autouse=True)
def _no_leftover_bots(tmp_path):
    yield
    _kill_procs_in(tmp_path)


SEED_DEADLINE = 60.0   # generous: a seed under heavy suite load took >10s once
SEED_POLL = 0.1        # poll interval (never sleep longer than 0.2s per poll)


def _db_has_schema(db: Path) -> bool:
    """True if db exists and holds at least one committed table."""
    if not db.exists():
        return False
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=0.2)
        try:
            return con.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0] > 0
        finally:
            con.close()
    except sqlite3.Error:
        return False


def _seed_db_only(tmp: Path) -> None:
    """Fixture seeding that also works on a build whose --seed never exits.

    Ready = the seed process has exited with the database in place. A seed
    that is still running is never killed before SEED_DEADLINE, however slow
    the machine is. Only at the deadline, and only if the schema is already
    committed (a --seed that never exits), is it stopped; otherwise fail with
    the seed's own stdout/stderr."""
    db = tmp / "db" / "wbs.db"
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        t0 = time.monotonic()
        p = subprocess.Popen([str(VENV_PY), str(LAUNCHER), "--seed"], cwd=tmp, env=_env(),
                             stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                             start_new_session=True)
        exited = db_ready = False
        try:
            while p.poll() is None and time.monotonic() - t0 < SEED_DEADLINE:
                time.sleep(SEED_POLL)
            exited = p.poll() is not None
            if not exited:
                db_ready = _db_has_schema(db)   # judged before the kill
        finally:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)
        elapsed = time.monotonic() - t0
        out.seek(0)
        err.seek(0)
        stdout = out.read().decode(errors="replace")
        stderr = err.read().decode(errors="replace")
    ok = db.exists() and (_db_has_schema(db) if exited else db_ready)
    pidfile = tmp / "wbs.pid"
    if pidfile.exists():               # --seed started a (daemonized) bot
        time.sleep(1.0)
        _kill_procs_in(tmp)
        time.sleep(0.5)
        pidfile.unlink(missing_ok=True)
        (tmp / "logs" / "wbs.log").unlink(missing_ok=True)
    assert ok, (
        f"--seed did not produce a usable {db} within {SEED_DEADLINE:.0f}s "
        f"(exited={exited}, returncode={p.returncode}, elapsed={elapsed:.1f}s, "
        f"db_exists={db.exists()})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}")


@pytest.fixture
def botdir(tmp_path):
    irc = FakeIrcServer()
    listen_port = _free_port()
    _write_config(tmp_path, irc.port, listen_port)
    _seed_db_only(tmp_path)
    irc_seed_conns = len(irc.snapshot())
    irc.conns[:irc_seed_conns] = []     # drop connections made by a non-exiting --seed
    yield tmp_path, irc, listen_port
    irc.close()


@pytest.fixture
def ptybot(botdir):
    tmp, irc, listen_port = botdir
    bot = PtyBot(tmp)
    try:
        assert bot.wait_for(lambda: "console> " in bot.text()
                            and any("USER " in " ".join(c["lines"]) for c in irc.snapshot())), \
            bot.text()
        assert bot.wait_for(lambda: (tmp / "wbs.pid").exists(), 5)
        yield bot, tmp, irc, listen_port
    finally:
        bot.kill_all()


def _log(tmp: Path) -> str:
    p = tmp / "logs" / "wbs.log"
    return p.read_text(errors="replace") if p.exists() else ""


# ---------------------------------------------------------------------------
# USR-15: --seed exits
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("extra", [(), ("-f",)], ids=["seed", "f-seed"])
def test_seed_initializes_db_then_exits(tmp_path, extra):
    _write_config(tmp_path, _free_port(), _free_port())
    t0 = time.time()
    res = _seed(tmp_path, *extra)
    elapsed = time.time() - t0
    assert res.returncode == 0, res.stdout + res.stderr
    assert elapsed < 10, f"--seed took {elapsed:.1f}s"
    assert (tmp_path / "db" / "wbs.db").exists()
    assert "Database seeded" in res.stdout
    assert not (tmp_path / "wbs.pid").exists(), "--seed started the bot"
    assert "Continuing startup" not in res.stdout + res.stderr + _log(tmp_path)
    assert "Traceback" not in res.stdout + res.stderr


# ---------------------------------------------------------------------------
# USR-20: .die sends QUIT before the socket closes
# ---------------------------------------------------------------------------
def test_die_sends_irc_quit_before_disconnect(ptybot):
    bot, tmp, irc, _ = ptybot
    bot.send(".die bye from test")
    assert bot.wait_for(lambda: bot.proc.poll() is not None, 20), bot.text()
    conns = irc.snapshot()
    assert conns and conns[0]["closed"]
    quits = [l for l in conns[0]["lines"] if l.startswith("QUIT")]
    assert quits == ["QUIT :bye from test"], conns[0]["lines"]
    assert len(conns) == 1, "bot reconnected after QUIT"
    out = bot.text() + _log(tmp)
    assert "Not connected, dropping command" not in out
    assert "Traceback" not in out, out
    assert bot.proc.returncode == 0


def test_execute_quit_disconnects_with_message_and_second_quit_is_quiet(caplog):
    """Unit: the IRC side sends QUIT via disconnect() (QUIT, then shutdown/
    close of the socket) and a later quit while disconnected is not an error."""
    from src.irc import WbsIrcBot
    bot = object.__new__(WbsIrcBot)
    conn = mock.MagicMock()
    conn.is_connected.return_value = True
    order = []
    conn.disconnect.side_effect = lambda msg: (order.append(("disconnect", msg)),
                                               conn.is_connected.configure_mock(return_value=False))
    bot.connection = conn
    bot.core_q = mock.MagicMock()
    bot.core_q.put_nowait.side_effect = lambda m: order.append(("core", m["cmd"]))

    with caplog.at_level("INFO"):
        bot.execute_command({"cmd": "quit", "message": "bye"})
        bot.execute_command({"cmd": "quit", "message": "Shutting down", "reply": False})
    assert order == [("disconnect", "bye"), ("core", "quit")]
    assert conn.disconnect.call_count == 1
    conn.quit.assert_not_called()
    assert bot._quitting is True
    assert "Not connected" not in caplog.text
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


def test_no_reconnect_after_quit():
    from src.irc import WbsIrcBot
    bot = object.__new__(WbsIrcBot)
    bot._quitting = True
    bot.recon = mock.MagicMock()
    bot.channels = {"#x": object()}
    bot._on_disconnect(mock.MagicMock(), mock.MagicMock())
    bot.recon.run.assert_not_called()
    assert bot.connect_now() is False


# ---------------------------------------------------------------------------
# USR-18: supervisor shutdown prints no traceback
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("how", ["sigterm", "ctrl-c", "sigterm-after-restart"])
def test_supervisor_shutdown_has_no_traceback(ptybot, how):
    bot, tmp, irc, _ = ptybot
    sup = bot.pidfile_pid()
    if how == "sigterm-after-restart":
        # Children spawned after the supervisor installed its handler (here
        # by a full .restart) inherited it: SIGTERM then ran the supervisor's
        # _shutdown inside IRC -> "can only test a child process".
        bot.send(".restart")
        assert bot.wait_for(lambda: "Full restart complete" in bot.text()
                            and bot.text().count("Core event loop running") >= 2, 30), bot.text()
        bot.wait_for(lambda: False, 2.0)
    if how.startswith("sigterm"):
        os.kill(sup, signal.SIGTERM)
    else:
        os.write(bot.master, b"\x03")      # ^C: SIGINT to the whole process group
    assert bot.wait_for(lambda: bot.proc.poll() is not None, 20), bot.text()
    bot.wait_for(lambda: False, 1.0)      # collect late output from children
    out = bot.text() + _log(tmp)
    assert "Traceback" not in out, out
    assert "can only test a child process" not in out
    assert not [p for p in bot.pids if _alive(p)], "children left running"


def test_children_reset_supervisor_signal_handlers():
    """Unit: a supervised child gets default SIGTERM and ignores SIGINT/SIGHUP."""
    from src import main as wbs_main
    seen = {}
    def target():
        seen.update({s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)})
    old = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        signal.signal(signal.SIGTERM, lambda *a: None)
        wbs_main._run_child(target)
    finally:
        for s, h in old.items():
            signal.signal(s, h)
    assert seen[signal.SIGTERM] is signal.SIG_DFL
    assert seen[signal.SIGINT] is signal.SIG_IGN
    assert seen[signal.SIGHUP] is signal.SIG_IGN


# ---------------------------------------------------------------------------
# USR-9: .detach backgrounds the bot
# ---------------------------------------------------------------------------
def test_detach_backgrounds_bot_and_keeps_it_reachable(ptybot):
    bot, tmp, irc, listen_port = ptybot
    sup = bot.pidfile_pid()
    bot.send(".detach")
    # The launched command returns: the shell gets its terminal back.
    assert bot.wait_for(lambda: bot.proc.poll() is not None, 15), bot.text()
    assert bot.proc.returncode == 0
    out = bot.text()
    assert "Detaching. Bot continues in background." in out
    assert "has no attribute 'console'" not in out
    assert "Traceback" not in out

    # The bot keeps running, off the terminal, still connected to IRC.
    time.sleep(1.0)
    assert _alive(sup)
    tty = Path(f"/proc/{sup}/fd/0").resolve()
    assert str(tty) == os.devnull, tty
    conns = irc.snapshot()
    assert len(conns) == 1 and not conns[0]["closed"]
    assert not any(l.startswith("QUIT") for l in conns[0]["lines"])
    # Telnet listener still answers.
    s = socket.create_connection(("127.0.0.1", listen_port), timeout=5)
    s.close()
    log = _log(tmp)
    assert "Detached from the terminal" in log
    assert "Traceback" not in log

    os.kill(sup, signal.SIGTERM)
    end = time.time() + 15
    while time.time() < end and _alive(sup):
        time.sleep(0.1)
    assert not _alive(sup)


def test_detach_refused_without_supervisor_console():
    """Unit: a console that is not the supervised foreground console refuses."""
    import asyncio
    from types import SimpleNamespace
    from src.commands import cmd_detach
    out = []
    async def respond(m):
        out.append(m)
    core = SimpleNamespace(
        partyline=SimpleNamespace(sessions={0: {"type": "console", "handle": "console"}},
                                  unregister_session=mock.MagicMock()),
        can_detach=lambda: False, request_detach=mock.MagicMock())
    asyncio.run(cmd_detach(core, "console", 0, "", respond))
    assert out and out[0].startswith("Cannot detach")
    core.partyline.unregister_session.assert_not_called()
    core.request_detach.assert_not_called()

    core.partyline.sessions[0]["type"] = "telnet"
    out.clear()
    asyncio.run(cmd_detach(core, "alice", 0, "", respond))
    assert out == ["Error: .detach is only valid for console sessions."]


# ---------------------------------------------------------------------------
# USR-16: .rehash replaces Core cleanly, IRC preserved
# ---------------------------------------------------------------------------
def test_rehash_restarts_core_keeps_irc(ptybot):
    bot, tmp, irc, _ = ptybot
    sup = bot.pidfile_pid()
    before = _descendants(sup)
    bot.send(".rehash")
    assert bot.wait_for(lambda: "Rehash: starting a fresh Core" in bot.text()
                        and bot.text().count("Core event loop running") >= 2, 20), bot.text()
    assert bot.wait_for(lambda: bot.text().count("console> Type .help") >= 2, 10), bot.text()
    out = bot.text()
    assert "Unknown option" not in out
    assert "usage:" not in out
    assert "Relaunching Core" not in out
    assert "Traceback" not in out
    after = _descendants(sup)
    assert len(before & after) >= 1, "IRC process was replaced"
    conns = irc.snapshot()
    assert len(conns) == 1 and not conns[0]["closed"], "IRC connection was dropped"

    # The new Core works: console commands answer and .die still quits cleanly.
    bot.send(".version")
    assert bot.wait_for(lambda: "WBS " in bot.text().split(".version", 1)[-1], 10)
    bot.send(".die after rehash")
    assert bot.wait_for(lambda: bot.proc.poll() is not None, 20), bot.text()
    assert [l for l in irc.snapshot()[0]["lines"] if l.startswith("QUIT")] == ["QUIT :after rehash"]
    assert "Traceback" not in bot.text() + _log(tmp)
