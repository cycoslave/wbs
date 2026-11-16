"""
Offline regression tests for SAST-011: telnet partyline authentication and
the single-reader session lifecycle (with the SAST-012 admission-slot rules
the same code path has to honour).

Covered:
  * one explicit DB path; canonical awaited UserManager.authenticate(handle,
    password) plus active/unlocked/+p (local subnet) checks on the real schema
  * valid / wrong / empty / oversize / missing-hash / unknown / locked /
    deleted / no-+p / +p-on-another-subnet logins
  * partial-fix regressions: a truthy non-True verifier result (e.g. an
    un-awaited coroutine) never authenticates; argument order is
    (handle, password); no legacy password_hash/locked columns
  * framing: fragmented handshake lines are reassembled, coalesced input
    after the password stays buffered for the session, oversize/EOF/bad
    UTF-8 lines are rejected
  * handshake and auth timeouts
  * secure transport: plaintext logins refused unless allow_plaintext=true
  * lifecycle: every rejected connection is closed and its admission slot
    released exactly once; an accepted one holds one slot through pending
    -> claimed -> Session.run (one task, one reader) -> disconnect
  * unclaimed pending streams are reaped and released

Every DB is a throwaway sqlite file under pytest's tmp_path.  No network
sockets, no IRC, no bot process.
"""
import asyncio
import inspect
import os
import shutil
import tempfile
import time
import types
from pathlib import Path
from types import SimpleNamespace as NS

import bcrypt
import pytest

from src.core import Core
from src.db import get_db, init_db
from src.net import AccessGuard, NetListener
from src.partyline import Partyline
from src.session import Session
from src.user import UserManager

ROOT = Path(__file__).resolve().parent.parent
PEER_IP = "198.51.100.7"
GOOD_PW = "correct horse battery"     # test-only credential, throwaway DB
LOCAL_SUBNET = 1

_TEMPLATE_DB: str | None = None


def run(coro):
    async def wrapped():
        try:
            return await coro
        finally:
            # Let fire-and-forget work (AccessGuard.record_success's DB
            # cleanup, session tasks) finish before the loop closes.
            me = asyncio.current_task()
            rest = [t for t in asyncio.all_tasks() if t is not me]
            if rest:
                _, pending = await asyncio.wait(rest, timeout=2)
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
    return asyncio.run(wrapped())


# ---------------------------------------------------------------------------
# real-schema database
# ---------------------------------------------------------------------------
# handle -> (access rows [(subnet_id, {columns})], post-create state)
USERS = {
    "alice":   ([(None, {"has_partyline"})], None),            # global +p
    "Bob":     ([(1, {"has_partyline"})], None),               # local +p, mixed case
    "locky":   ([(None, {"has_partyline"})], "locked"),
    "gone":    ([(None, {"has_partyline", "is_owner"})], "deleted"),
    "noflag":  ([(None, {"is_op"})], None),                    # no +p at all
    "faraway": ([(2, {"has_partyline"})], None),               # +p on subnet 2 only
    "nohash":  ([(None, {"has_partyline"})], "nopassword"),
}


async def build_db(tmp_path) -> str:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-sast011-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    db = str(tmp_path / "wbs.db")
    shutil.copyfile(_TEMPLATE_DB, db)
    pw_hash = bcrypt.hashpw(GOOD_PW.encode(), bcrypt.gensalt(rounds=4)).decode()
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        for handle, (rows, state) in USERS.items():
            await d.execute("INSERT INTO users(handle, password, hostmasks) VALUES (?, ?, '[]')",
                            (handle, None if state == "nopassword" else pw_hash))
            for sid, cols in rows:
                names = ["handle", "channel", "subnet_id", *sorted(cols)]
                vals = [handle, None, sid, *([1] * len(cols))]
                await d.execute(f"INSERT INTO user_access ({', '.join(names)}) "
                                f"VALUES ({', '.join('?' * len(names))})", vals)
            if state == "locked":
                await d.execute("UPDATE users SET is_locked = 1 WHERE handle = ?", (handle,))
            if state == "deleted":
                await d.execute("UPDATE users SET deleted_at = 1 WHERE handle = ?", (handle,))
        await d.commit()
    return db


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------
class FakeWriter:
    def __init__(self, ip=PEER_IP, tls=False):
        self.buf = bytearray()
        self.closed = 0
        self.ip = ip
        self.tls = tls

    def write(self, data: bytes):
        if not self.closed:
            self.buf += data

    async def drain(self):
        pass

    def close(self):
        self.closed += 1

    async def wait_closed(self):
        pass

    def is_closing(self):
        return bool(self.closed)

    def get_extra_info(self, key, default=None):
        if key == "peername":
            return (self.ip, 40000)
        if key == "ssl_object":
            return object() if self.tls else None
        return default

    @property
    def text(self) -> str:
        return self.buf.decode(errors="replace")


class EventQ:
    def __init__(self, fail=False):
        self.events: list[dict] = []
        self.fail = fail

    def put_nowait(self, ev):
        if self.fail:
            raise RuntimeError("queue full")
        self.events.append(ev)

    def of(self, etype):
        return [e for e in self.events if e.get("type") == etype]


class CountingGuard(AccessGuard):
    """Real AccessGuard (real DB tables) that also records every release."""

    def __init__(self, db, settings):
        super().__init__(db, {"settings": settings})
        self.releases: list[str] = []

    def release(self, ip):
        self.releases.append(ip)
        super().release(ip)


def make_listener(db, *, plaintext=True, guard=True, q=None, **settings):
    cfg = {"allow_plaintext": plaintext, "auth_timeout": 2, "handshake_timeout": 2,
           "max_failures": 100, **settings}
    g = CountingGuard(db, cfg) if guard else None
    if not guard:
        cfg["dev_mode"] = True
    config = {"settings": cfg, "botnet": {"subnet_id": LOCAL_SUBNET}}
    return NetListener(q or EventQ(), config, g, db_path=db), g


async def connect(listener, data=b"", *, tls=False, eof=False, ip=PEER_IP):
    reader = asyncio.StreamReader()
    if data:
        reader.feed_data(data)
    if eof:
        reader.feed_eof()
    writer = FakeWriter(ip=ip, tls=tls)
    await listener.handle_connection(reader, writer)
    await asyncio.sleep(0)            # let record_success's DB task run
    return reader, writer


def assert_rejected(listener, guard, writer, ip=PEER_IP):
    assert writer.closed == 1, "rejected socket must be closed exactly once"
    assert guard.releases.count(ip) == 1, "slot must be released exactly once"
    assert guard._active == {}, "admission count must return to baseline"
    assert listener._pending_streams == {} and listener._stream_peers == {}
    assert listener.core_q.of("PARTYLINE_CONNECT") == []


# ---------------------------------------------------------------------------
# authentication matrix (real schema)
# ---------------------------------------------------------------------------
def test_valid_login_hands_off_canonical_handle(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        reader, writer = await connect(listener, f"alice\r\n{GOOD_PW}\r\n".encode())
        [ev] = listener.core_q.of("PARTYLINE_CONNECT")
        assert ev["handle"] == "alice" and ev["peer_ip"] == PEER_IP
        assert writer.text == "Password: " and writer.closed == 0
        # the listener owns the stream (and the one slot) until core claims it
        assert listener._pending_streams[ev["conn_id"]] == (reader, writer)
        assert guard._active == {PEER_IP: 1} and guard.releases == []
        assert PEER_IP not in guard._failures
    run(main())


def test_handle_lookup_is_case_insensitive_and_returns_stored_spelling(tmp_path):
    async def main():
        listener, _ = make_listener(await build_db(tmp_path))
        await connect(listener, f"bob\n{GOOD_PW}\n".encode())
        [ev] = listener.core_q.of("PARTYLINE_CONNECT")
        assert ev["handle"] == "Bob"          # local +p on subnet 1 is enough
    run(main())


@pytest.mark.parametrize("handle,password", [
    ("alice", "wrong password"),          # wrong password
    ("alice", ""),                        # empty password
    ("alice", "x" * 300),                 # oversize (refused unchecked)
    ("alice", GOOD_PW + " "),             # near miss: no trimming of the secret
    ("nobody", GOOD_PW),                  # unknown user
    ("locky", GOOD_PW),                   # locked
    ("gone", GOOD_PW),                    # soft-deleted
    ("noflag", GOOD_PW),                  # no +p
    ("faraway", GOOD_PW),                 # +p only on another subnet
    ("nohash", GOOD_PW),                  # no stored password
])
def test_denied_logins_fail_closed_and_release(tmp_path, handle, password):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        _, writer = await connect(listener, f"{handle}\n{password}\n".encode())
        assert "ERROR :Connection refused" in writer.text
        assert_rejected(listener, guard, writer)
        assert guard._failures[PEER_IP].count == 1
    run(main())


def test_authenticate_partyline_direct_matrix(tmp_path):
    async def main():
        listener, _ = make_listener(await build_db(tmp_path))
        auth = listener.authenticate_partyline
        assert await auth("alice", GOOD_PW) == "alice"
        assert await auth("ALICE", GOOD_PW) == "alice"
        assert await auth("Bob", GOOD_PW) == "Bob"
        for h in ("locky", "gone", "noflag", "faraway", "nohash", "nobody"):
            assert await auth(h, GOOD_PW) is None, h
        assert await auth("alice", "nope") is None
        assert await auth("", GOOD_PW) is None
        # lock / unlock / delete take effect on the very next login
        async with get_db(listener.db_path) as d:
            await d.execute("UPDATE users SET is_locked = 1 WHERE handle = 'alice'")
            await d.commit()
        assert await auth("alice", GOOD_PW) is None
        async with get_db(listener.db_path) as d:
            await d.execute("UPDATE users SET is_locked = 0 WHERE handle = 'alice'")
            await d.commit()
        assert await auth("alice", GOOD_PW) == "alice"
        await UserManager(listener.db_path).deluser("alice", "test")
        assert await auth("alice", GOOD_PW) is None
    run(main())


def test_usermanager_authenticate_uses_real_schema(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        assert await um.authenticate("alice", GOOD_PW) is True
        assert await um.authenticate("alice", "wrong") is False
        assert await um.authenticate("locky", GOOD_PW) is False
        assert await um.authenticate("gone", GOOD_PW) is False
        assert await um.authenticate("nohash", GOOD_PW) is False
        assert await um.authenticate("nobody", GOOD_PW) is False
        assert await um.authenticate("alice", "") is False
        assert await um.authenticate("alice", None) is False
    run(main())


# ---------------------------------------------------------------------------
# partial-fix regressions (the latent coroutine bypass)
# ---------------------------------------------------------------------------
def test_verifier_is_awaited_with_handle_then_password(tmp_path, monkeypatch):
    calls = []
    real = UserManager.verify_password

    async def spy(self, handle, password):
        calls.append((handle, password))
        return await real(self, handle, password)

    monkeypatch.setattr(UserManager, "verify_password", spy)

    async def main():
        listener, _ = make_listener(await build_db(tmp_path))
        await connect(listener, f"ALICE\n{GOOD_PW}\n".encode())
        assert calls == [("alice", GOOD_PW)]          # canonical handle, right order
        assert len(listener.core_q.of("PARTYLINE_CONNECT")) == 1
    run(main())


@pytest.mark.parametrize("truthy", ["yes", 1, object(), "coroutine"])
def test_truthy_non_true_verifier_result_never_authenticates(tmp_path, monkeypatch, truthy):
    async def never_awaited():
        return True

    async def fake_verify(self, handle, password):
        # Emulate a partial repair: the verifier hands back something truthy
        # that is not an awaited True, e.g. a raw coroutine object (the
        # audit's case: verify_password called without await).
        return never_awaited() if truthy == "coroutine" else truthy

    monkeypatch.setattr(UserManager, "verify_password", fake_verify)

    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        _, writer = await connect(listener, b"alice\nwrong-password\n")
        assert_rejected(listener, guard, writer)
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)   # the deliberate un-awaited coroutine
        run(main())


def test_unawaited_authenticate_result_is_rejected(tmp_path):
    """If authenticate itself returned a coroutine/truthy object, still deny."""
    async def main():
        listener, _ = make_listener(await build_db(tmp_path))

        class Sloppy(UserManager):
            async def authenticate(self, handle, password):
                return "truthy"

        listener.users = Sloppy(listener.db_path)
        assert await listener.authenticate_partyline("alice", "anything") is None
    run(main())


def test_static_no_legacy_columns_or_double_reader():
    net_src = (ROOT / "src/net.py").read_text()
    user_src = inspect.getsource(UserManager.authenticate)
    for src in (net_src, user_src):
        assert "password_hash" not in src
        assert "locked FROM" not in src
    assert "await self.verify_password(handle, password)" in user_src
    core_src = (ROOT / "src/core.py").read_text()
    assert "self.net.listener" not in core_src
    body = inspect.getsource(Core.on_partyline_connect)
    assert body.count("session.run()") == 1
    assert "asyncio.create_task" not in body and "asyncio.timeout" not in body


def test_listener_uses_one_explicit_db_path(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db)
        assert listener.db_path == db == guard.db_path == listener.users.db_path
        with pytest.raises(RuntimeError, match="conflicting"):
            NetListener(EventQ(), {"settings": {}}, guard, db_path=str(tmp_path / "other.db"))
        with pytest.raises(RuntimeError, match="conflicting"):
            NetListener(EventQ(), {"settings": {}}, guard,
                        user_manager=UserManager(str(tmp_path / "other.db")))
    run(main())


def test_no_database_fails_closed():
    async def main():
        listener = NetListener(EventQ(), {"settings": {"dev_mode": True, "allow_plaintext": True,
                                                       "auth_timeout": 1}}, None)
        assert listener.db_path is None and listener.users is None
        assert await listener.authenticate_partyline("alice", GOOD_PW) is None
        _, writer = await connect(listener, f"alice\n{GOOD_PW}\n".encode())
        assert writer.closed == 1 and listener.core_q.events == []
    run(main())


def test_core_wires_listener_to_core_db(tmp_path):
    db = str(tmp_path / "core.db")
    config = {"bot": {"nick": "wbs"}, "db": {"path": db},
              "settings": {"allow_plaintext": True}}
    core = Core(config, str(tmp_path / "config.json"), NS(db_path=None),
                core_q=EventQ(), irc_q=EventQ())
    assert core.net_listener.db_path == db
    assert core.net_listener.users is core.user
    assert core.net_listener.guard is core.guard


# ---------------------------------------------------------------------------
# framing
# ---------------------------------------------------------------------------
def test_fragmented_handshake_is_reassembled(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        reader = asyncio.StreamReader()
        writer = FakeWriter()
        payload = f"alice\r\n{GOOD_PW}\r\n".encode()

        async def trickle():
            for i in range(len(payload)):
                reader.feed_data(payload[i:i + 1])
                await asyncio.sleep(0)

        feeder = asyncio.create_task(trickle())
        await listener.handle_connection(reader, writer)
        await feeder
        [ev] = listener.core_q.of("PARTYLINE_CONNECT")
        assert ev["handle"] == "alice" and writer.closed == 0
        assert guard._active == {PEER_IP: 1}
    run(main())


def test_coalesced_input_after_password_is_preserved(tmp_path):
    async def main():
        listener, _ = make_listener(await build_db(tmp_path))
        reader, writer = await connect(
            listener, f"alice\n{GOOD_PW}\n.whoami\nhello there\n".encode())
        assert len(listener.core_q.of("PARTYLINE_CONNECT")) == 1
        # nothing the client sent after the password was consumed or dropped
        assert await reader.readuntil(b"\n") == b".whoami\n"
        assert await reader.readuntil(b"\n") == b"hello there\n"
    run(main())


def test_coalesced_botlink_frame_stays_buffered(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        reader, writer = await connect(listener, b"BOTLINK alpha beta 1 WBS x\nLINKAUTH next\n")
        [ev] = listener.core_q.of("BOT_CONNECT")
        assert ev["data"] == "BOTLINK alpha beta 1 WBS x"
        assert await reader.readuntil(b"\n") == b"LINKAUTH next\n"
        assert guard._active == {PEER_IP: 1} and writer.closed == 0
    run(main())


@pytest.mark.parametrize("data,eof", [
    (b"a" * 600 + b"\n", False),                      # oversize handle line
    (b"alice", True),                                 # EOF before end of line
    (b"\n", False),                                   # empty line
    (b"\xff\xfe\n", False),                           # not UTF-8
    (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", False),    # HTTP probe
    (b"bad handle!\n", False),                        # invalid handle characters
    (b"BOTLINK short\n", False),                      # malformed botlink
    (b"alice\n" + b"p" * 600 + b"\n", False),         # oversize password line
    (b"alice\n" + b"\xff\n", False),                  # password not UTF-8
    (b"alice\npartial", True),                        # EOF mid-password
])
def test_bad_framing_and_probes_release_slot(tmp_path, data, eof):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        _, writer = await connect(listener, data, eof=eof)
        assert_rejected(listener, guard, writer)
        assert listener.core_q.events == []
    run(main())


# ---------------------------------------------------------------------------
# timeouts
# ---------------------------------------------------------------------------
def test_handshake_timeout_releases_slot(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path), handshake_timeout=0.05)
        _, writer = await connect(listener, b"ali")       # never finishes the line
        assert_rejected(listener, guard, writer)
    run(main())


def test_auth_timeout_releases_slot_and_counts_failure(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path), auth_timeout=0.05)
        t0 = time.monotonic()
        _, writer = await connect(listener, b"alice\n")   # no password ever arrives
        assert time.monotonic() - t0 < 2
        assert "Password: " in writer.text and "ERROR :Login timeout" in writer.text
        assert_rejected(listener, guard, writer)
        assert guard._failures[PEER_IP].count == 1
    run(main())


# ---------------------------------------------------------------------------
# secure transport policy
# ---------------------------------------------------------------------------
def test_plaintext_login_refused_without_opt_in(tmp_path, monkeypatch):
    calls = []

    async def spy(self, handle, password):
        calls.append(handle)
        return True

    monkeypatch.setattr(UserManager, "authenticate", spy)

    async def main():
        listener, guard = make_listener(await build_db(tmp_path), plaintext=False)
        _, writer = await connect(listener, f"alice\n{GOOD_PW}\n".encode())
        assert "ERROR :TLS required" in writer.text
        assert "Password:" not in writer.text              # never prompted
        assert calls == []                                 # password never checked
        assert_rejected(listener, guard, writer)
    run(main())


def test_tls_login_accepted_without_plaintext_opt_in(tmp_path):
    async def main():
        listener, _ = make_listener(await build_db(tmp_path), plaintext=False)
        _, writer = await connect(listener, f"alice\n{GOOD_PW}\n".encode(), tls=True)
        assert [e["handle"] for e in listener.core_q.of("PARTYLINE_CONNECT")] == ["alice"]
    run(main())


def test_startup_requires_tls_or_explicit_plaintext():
    listener = NetListener(EventQ(), {"settings": {"dev_mode": True}}, None)
    with pytest.raises(RuntimeError, match="allow_plaintext"):
        listener._build_ssl_context()


# ---------------------------------------------------------------------------
# admission lifecycle
# ---------------------------------------------------------------------------
def test_repeated_rejections_do_not_lock_out_shared_ip(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        for data in (b"GET / HTTP/1.0\n", b"bad handle!\n", b"alice\nwrong\n",
                     b"locky\n" + GOOD_PW.encode() + b"\n", b"\n"):
            _, writer = await connect(listener, data)
            assert writer.closed == 1
        assert guard._active == {}
        assert guard.releases == [PEER_IP] * 5
        # a legitimate user behind the same address still gets in
        _, writer = await connect(listener, f"alice\n{GOOD_PW}\n".encode())
        assert len(listener.core_q.of("PARTYLINE_CONNECT")) == 1
    run(main())


def test_failed_queue_handoff_closes_and_releases(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path), q=EventQ(fail=True))
        _, writer = await connect(listener, f"alice\n{GOOD_PW}\n".encode())
        assert writer.closed == 1 and guard.releases == [PEER_IP] and guard._active == {}
        assert listener._pending_streams == {}
    run(main())


def test_unclaimed_stream_is_reaped_and_released_once(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        _, writer = await connect(listener, f"alice\n{GOOD_PW}\n".encode())
        [ev] = listener.core_q.of("PARTYLINE_CONNECT")
        assert await listener._reap_stale(60.0) == 0          # still fresh
        assert await listener._reap_stale(0.0, now=time.monotonic() + 1) == 1
        assert writer.closed == 1 and guard.releases == [PEER_IP] and guard._active == {}
        assert listener.claim_stream(ev["conn_id"]) is None   # core arrives too late
        assert await listener._reap_stale(0.0, now=time.monotonic() + 1) == 0
        assert guard.releases == [PEER_IP]
    run(main())


class FakeCore:
    """Just what Core.on_partyline_connect/disconnect need, offline."""

    def __init__(self, listener, guard, db):
        self.net_listener = listener
        self.guard = guard
        self.core_q = EventQ()
        self.irc_q = None
        self.botname = "wbs"
        self.config = {"botnet": {"subnet_id": LOCAL_SUBNET}}
        self.user = UserManager(db)
        self.botnet = NS(peers={})
        self.party_sessions = {}
        self.partyline = Partyline(self)
        self.tasks: list[asyncio.Task] = []

    def _create_safe_task(self, coro, *, name="unnamed"):
        task = types.MethodType(Core._create_safe_task, self)(coro, name=name)
        self.tasks.append(task)
        return task


async def wait_for(pred, timeout=2.0):
    end = time.monotonic() + timeout
    while not pred():
        if time.monotonic() > end:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.01)


def test_accepted_session_single_reader_and_single_release(tmp_path, monkeypatch):
    runs = []
    real_run = Session.run

    async def counting_run(self):
        runs.append(self.session_id)
        return await real_run(self)

    monkeypatch.setattr(Session, "run", counting_run)

    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db)
        reader, writer = await connect(
            listener, f"alice\n{GOOD_PW}\n.whoami\nhello the".encode())
        [ev] = listener.core_q.of("PARTYLINE_CONNECT")
        core = FakeCore(listener, guard, db)

        await Core.on_partyline_connect(core, ev)
        # a replayed/duplicate connect event finds no stream: no second session
        await Core.on_partyline_connect(core, ev)
        assert len(core.tasks) == 1 and len(core.party_sessions) == 1
        [sid] = core.party_sessions
        session = core.party_sessions[sid]
        assert session.task is core.tasks[0] and session.peer_ip == PEER_IP
        assert session.handle == "alice"
        assert core.partyline.sessions[sid]["type"] == "telnet"
        assert listener._pending_streams == {}
        assert guard._active == {PEER_IP: 1} and guard.releases == []

        # coalesced lines and a line split across segments reach core, in order
        reader.feed_data(b"re\n")
        await wait_for(lambda: len(core.core_q.of("PARTYLINE_INPUT")) == 2)
        assert [e["text"] for e in core.core_q.of("PARTYLINE_INPUT")] == [".whoami", "hello there"]
        assert runs == [sid]                       # exactly one Session.run (one reader)
        assert "Welcome to WBS partyline, alice!" in writer.text

        # no auth-timeout eviction of an authenticated session
        assert not session.task.done()

        reader.feed_eof()
        await wait_for(lambda: core.core_q.of("PARTYLINE_DISCONNECT"))
        [dis] = core.core_q.of("PARTYLINE_DISCONNECT")
        await Core.on_partyline_disconnect(core, dis)
        await Core.on_partyline_disconnect(core, dis)      # duplicate is harmless
        assert guard.releases == [PEER_IP] and guard._active == {}
        assert writer.closed >= 1
        assert core.party_sessions == {} and sid not in core.partyline.sessions
        await asyncio.wait_for(session.task, 1)
        assert runs == [sid]
    run(main())


def test_session_setup_failure_releases_slot(tmp_path, monkeypatch):
    def broken_init(self, *a, **kw):
        raise RuntimeError("boom")

    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db)
        _, writer = await connect(listener, f"alice\n{GOOD_PW}\n".encode())
        [ev] = listener.core_q.of("PARTYLINE_CONNECT")
        core = FakeCore(listener, guard, db)
        monkeypatch.setattr(Session, "__init__", broken_init)
        await Core.on_partyline_connect(core, ev)
        assert writer.closed == 1 and guard.releases == [PEER_IP] and guard._active == {}
        assert core.party_sessions == {} and core.partyline.sessions == {}
        assert core.tasks == []
    run(main())


def test_bot_connect_failure_releases_slot(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db)
        _, writer = await connect(listener, b"BOTLINK alpha beta 1 WBS x\n")
        [ev] = listener.core_q.of("BOT_CONNECT")
        core = FakeCore(listener, guard, db)

        async def boom(*a, **kw):
            raise RuntimeError("handshake setup failed")

        core.botnet = NS(peers={}, process_incoming=boom)
        await Core.on_bot_connect(core, ev)
        assert writer.closed == 1 and guard.releases == [PEER_IP] and guard._active == {}
        assert core.tasks == []
    run(main())


def test_response_pump_does_not_spin_on_asyncio_queue():
    """Telnet sessions use an asyncio.Queue; an empty queue must yield, not busy-loop."""
    async def main():
        s = Session(1, "telnet", "alice", EventQ(), response_q=asyncio.Queue(),
                    writer=FakeWriter())
        pump = asyncio.create_task(s._handle_responses())
        ticks = 0

        async def ticker():
            nonlocal ticks
            for _ in range(5):
                ticks += 1
                await asyncio.sleep(0.01)

        await asyncio.wait_for(ticker(), 1)        # would hang if the pump spun
        s.response_q.put_nowait({"text": "hi"})
        await wait_for(lambda: b"hi\n" in s.writer.buf)
        s.running = False
        pump.cancel()
        assert ticks == 5
    run(main())
