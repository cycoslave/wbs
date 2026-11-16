"""
Offline regression tests for SAST-012: rejected connections must never keep
a listener admission slot.

Ownership contract under test (src/net.py):
  * NetListener.handle_connection owns the socket and its AccessGuard slot
    until a handler returns exactly True (stream registered as pending);
  * the pending table owns it until core claims it (claim_stream) or the
    reaper closes it;
  * the claimer owns it until teardown.
Whoever owns the connection when it ends closes the socket and releases the
slot, exactly once.

Covered:
  * the auditor's repro: three HTTP rejects from one IP, then a fourth
    connection from that IP is still admitted
  * every failed handshake path (HTTP probes, invalid handle, bad/unknown
    login, auth timeout, handshake timeout, disconnect before/mid line,
    oversize/non-UTF-8 line, plaintext refusal, malformed BOTLINK), repeated
    beyond PER_IP_MAX: socket closed once, slot released once, counts back
    to baseline, and a legitimate login from the same IP still gets in
  * handler exceptions, cancellation mid-handshake, a truthy non-True
    handler result, a handler that registers a stream but reports failure,
    write/close errors while rejecting, admit() raising
  * accepted connections hold exactly one slot (pending -> claimed ->
    teardown) and free it once; BOT_DISCONNECT does not double-free
  * shared-NAT and global-cap behaviour, multiple IPs, concurrent admits
  * pending-stream reaping, reaper resilience, no pending-key replacement

Every DB is a throwaway sqlite file under pytest's tmp_path.  No network
sockets, no IRC, no bot process.
"""
import asyncio
import os
import shutil
import tempfile
import time
from types import SimpleNamespace as NS

import bcrypt
import pytest

from src import net as net_mod
from src.core import Core
from src.db import get_db, init_db
from src.net import PER_IP_MAX, AccessGuard, NetListener

IP_A = "198.51.100.7"
IP_B = "198.51.100.8"
GOOD_PW = "correct horse battery"     # test-only credential, throwaway DB
LOCAL_SUBNET = 1

_TEMPLATE_DB: str | None = None


def run(coro):
    async def wrapped():
        try:
            return await coro
        finally:
            me = asyncio.current_task()
            rest = [t for t in asyncio.all_tasks() if t is not me]
            if rest:
                _, pending = await asyncio.wait(rest, timeout=2)
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
    return asyncio.run(wrapped())


async def build_db(tmp_path) -> str:
    """Real schema; one user 'alice' with global +p."""
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-sast012-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    db = str(tmp_path / "wbs.db")
    shutil.copyfile(_TEMPLATE_DB, db)
    pw_hash = bcrypt.hashpw(GOOD_PW.encode(), bcrypt.gensalt(rounds=4)).decode()
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one')")
        await d.execute("INSERT INTO users(handle, password, hostmasks) VALUES (?, ?, '[]')",
                        ("alice", pw_hash))
        await d.execute("INSERT INTO user_access (handle, channel, subnet_id, has_partyline) "
                        "VALUES ('alice', NULL, NULL, 1)")
        await d.commit()
    return db


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------
class FakeWriter:
    def __init__(self, ip=IP_A, *, fail_write=False, fail_wait_closed=False):
        self.buf = bytearray()
        self.closed = 0
        self.ip = ip
        self.fail_write = fail_write
        self.fail_wait_closed = fail_wait_closed

    def write(self, data: bytes):
        if self.fail_write:
            raise ConnectionResetError("peer reset")
        if not self.closed:
            self.buf += data

    async def drain(self):
        if self.fail_write:
            raise ConnectionResetError("peer reset")

    def close(self):
        self.closed += 1

    async def wait_closed(self):
        if self.fail_wait_closed:
            raise ConnectionResetError("reset during close")

    def is_closing(self):
        return bool(self.closed)

    def get_extra_info(self, key, default=None):
        if key == "peername":
            return (self.ip, 40000)
        return default

    @property
    def text(self) -> str:
        return self.buf.decode(errors="replace")


class EventQ:
    def __init__(self):
        self.events: list[dict] = []

    def put_nowait(self, ev):
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


def make_listener(db, **settings):
    cfg = {"allow_plaintext": True, "auth_timeout": 2, "handshake_timeout": 2,
           "max_failures": 1000, **settings}
    guard = CountingGuard(db, cfg)
    config = {"settings": cfg, "botnet": {"subnet_id": LOCAL_SUBNET}}
    return NetListener(EventQ(), config, guard, db_path=db), guard


async def connect(listener, data=b"", *, eof=False, ip=IP_A, writer=None):
    reader = asyncio.StreamReader()
    if data:
        reader.feed_data(data)
    if eof:
        reader.feed_eof()
    writer = writer or FakeWriter(ip=ip)
    await listener.handle_connection(reader, writer)
    await asyncio.sleep(0)            # let record_success's DB task run
    return reader, writer


def login(pw=GOOD_PW) -> bytes:
    return f"alice\n{pw}\n".encode()


def assert_baseline(listener, guard):
    assert guard._active == {}, f"admission counts not at baseline: {guard._active}"
    assert guard.active_count() == 0
    assert listener._pending_streams == {}
    assert listener._stream_peers == {} and listener._stream_timestamps == {}


# (data, eof, extra settings) for every way a handshake can fail
FAILED_HANDSHAKES = {
    "http_get":         (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", False, {}),
    "http_post":        (b"POST /login HTTP/1.1\r\n\r\n", False, {}),
    "http_head":        (b"HEAD / HTTP/1.0\r\n\r\n", False, {}),
    "http_options":     (b"OPTIONS * HTTP/1.1\r\n\r\n", False, {}),
    "invalid_handle":   (b"bad handle!\n", False, {}),
    "bad_password":     (login("wrong password"), False, {}),
    "empty_password":   (b"alice\n\n", False, {}),
    "unknown_user":     (f"nobody\n{GOOD_PW}\n".encode(), False, {}),
    "auth_timeout":     (b"alice\n", False, {"auth_timeout": 0.05}),
    "handshake_timeout": (b"ali", False, {"handshake_timeout": 0.05}),
    "silent_timeout":   (b"", False, {"handshake_timeout": 0.05}),
    "disconnect_early": (b"", True, {}),
    "disconnect_mid_line": (b"ali", True, {}),
    "disconnect_mid_password": (b"alice\npart", True, {}),
    "empty_line":       (b"\n", False, {}),
    "oversize_line":    (b"a" * 700 + b"\n", False, {}),
    "not_utf8":         (b"\xff\xfe\n", False, {}),
    "plaintext_refused": (login(), False, {"allow_plaintext": False}),
    "malformed_botlink": (b"BOTLINK short\n", False, {}),
}


# ---------------------------------------------------------------------------
# the auditor's repro
# ---------------------------------------------------------------------------
def test_three_http_rejects_do_not_deny_next_same_ip_connection(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        writers = []
        for _ in range(3):
            _, w = await connect(listener, b"GET / HTTP/1.0\r\n\r\n")
            writers.append(w)
            assert "400 Bad Request" in w.text
        assert [w.closed for w in writers] == [1, 1, 1]
        assert guard.releases == [IP_A] * 3
        assert_baseline(listener, guard)
        # the 4th request from the same IP is admitted (not "Connection refused")
        _, w = await connect(listener, b"GET / HTTP/1.0\r\n\r\n")
        assert "Connection refused" not in w.text and "400 Bad Request" in w.text
        assert_baseline(listener, guard)
    run(main())


# ---------------------------------------------------------------------------
# every failed handshake path, repeated past the per-IP cap
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("case", sorted(FAILED_HANDSHAKES))
def test_failed_handshake_path_returns_counts_to_baseline(tmp_path, case):
    data, eof, settings = FAILED_HANDSHAKES[case]
    rounds = PER_IP_MAX + 2

    async def main():
        listener, guard = make_listener(await build_db(tmp_path), **settings)
        for i in range(rounds):
            _, writer = await connect(listener, data, eof=eof)
            assert "Connection refused\r\n" not in writer.text or case in (
                "invalid_handle", "bad_password", "empty_password", "unknown_user"), \
                f"round {i}: refused at admission"
            assert writer.closed == 1, f"round {i}: socket must be closed exactly once"
            assert guard.releases.count(IP_A) == i + 1, f"round {i}: release once"
            assert_baseline(listener, guard)
        assert listener.core_q.of("PARTYLINE_CONNECT") == []
        assert listener.core_q.of("BOT_CONNECT") == []
        # The same IP (e.g. a user behind the same NAT) can still log in.
        if settings.get("allow_plaintext", True):
            listener.config["settings"]["auth_timeout"] = 2
            listener.config["settings"]["handshake_timeout"] = 2
            await connect(listener, login())
            assert len(listener.core_q.of("PARTYLINE_CONNECT")) == 1
            assert guard.active_count(IP_A) == 1
    run(main())


def test_mixed_rejections_from_many_ips_never_exhaust_global_cap(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path), max_connections=3)
        cases = list(FAILED_HANDSHAKES.values())
        for n in range(12):
            data, eof, _ = cases[n % len(cases)]
            if data == b"" and not eof:
                continue            # skip timeout cases (default timeout is 2s)
            await connect(listener, data, eof=eof, ip=f"203.0.113.{n}")
        assert_baseline(listener, guard)
        for n in range(3):
            await connect(listener, login(), ip=f"192.0.2.{n}")
        assert guard.active_count() == 3
        assert len(listener.core_q.of("PARTYLINE_CONNECT")) == 3
    run(main())


# ---------------------------------------------------------------------------
# exceptions / cancellation / handler contract
# ---------------------------------------------------------------------------
def test_handler_exception_closes_and_releases_once(tmp_path, monkeypatch):
    async def boom(self, *a, **kw):
        raise RuntimeError("handler crashed")

    monkeypatch.setattr(NetListener, "_handle_partyline", boom)

    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        for _ in range(PER_IP_MAX + 1):
            _, w = await connect(listener, b"alice\n")
            assert w.closed == 1
        assert guard.releases == [IP_A] * (PER_IP_MAX + 1)
        assert_baseline(listener, guard)
    run(main())


@pytest.mark.parametrize("result", [None, 1, "yes", object(), [("r", "w")]])
def test_only_exact_true_counts_as_handoff(tmp_path, monkeypatch, result):
    async def fake(self, *a, **kw):
        return result

    monkeypatch.setattr(NetListener, "_handle_partyline", fake)

    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        _, w = await connect(listener, b"alice\n")
        assert w.closed == 1 and guard.releases == [IP_A]
        assert_baseline(listener, guard)
    run(main())


def test_registered_but_unreported_handoff_is_taken_back(tmp_path, monkeypatch):
    """A handler that queued the stream but returned False must not leave a
    pending entry pointing at a socket the acceptor closes (no double free
    when the reaper or core later finds it)."""
    async def half(self, line, peer, peer_ip, reader, writer):
        self._add_pending("partyline:stray", reader, writer, peer_ip)
        return False

    monkeypatch.setattr(NetListener, "_handle_partyline", half)

    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        _, w = await connect(listener, b"alice\n")
        assert w.closed == 1 and guard.releases == [IP_A]
        assert_baseline(listener, guard)
        assert await listener._reap_stale(0.0, now=time.monotonic() + 1) == 0
        assert listener.claim_stream("partyline:stray") is None
        assert guard.releases == [IP_A]
    run(main())


def test_cancellation_mid_handshake_releases_once(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path), auth_timeout=30)
        reader = asyncio.StreamReader()
        reader.feed_data(b"alice\n")                 # waits for the password
        writer = FakeWriter()
        task = asyncio.create_task(listener.handle_connection(reader, writer))
        for _ in range(50):
            if "Password: " in writer.text:
                break
            await asyncio.sleep(0.01)
        assert guard.active_count(IP_A) == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert writer.closed == 1 and guard.releases == [IP_A]
        assert_baseline(listener, guard)
    run(main())


def test_write_and_close_errors_while_rejecting_still_release(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        for kw in ({"fail_write": True}, {"fail_wait_closed": True},
                   {"fail_write": True, "fail_wait_closed": True}):
            w = FakeWriter(**kw)
            await connect(listener, b"GET / HTTP/1.0\r\n\r\n", writer=w)
            assert w.closed == 1
        for kw in ({"fail_write": True}, {"fail_wait_closed": True}):
            await connect(listener, login("wrong"), writer=FakeWriter(**kw))
        assert guard.releases == [IP_A] * 5
        assert_baseline(listener, guard)
    run(main())


def test_admit_error_refuses_without_taking_a_slot(tmp_path, monkeypatch):
    async def broken(self, ip):
        raise RuntimeError("db unavailable")

    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        monkeypatch.setattr(CountingGuard, "admit", broken)
        _, w = await connect(listener, login())
        assert "ERROR :Connection refused" in w.text and w.closed == 1
        assert guard.releases == [] and listener.core_q.events == []
        assert_baseline(listener, guard)
    run(main())


def test_refused_at_admission_is_closed_and_not_released(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        await guard.block(IP_A, reason="test")
        _, w = await connect(listener, login())
        assert "ERROR :Connection refused" in w.text and w.closed == 1
        assert guard.releases == []
        assert_baseline(listener, guard)
    run(main())


# ---------------------------------------------------------------------------
# accepted connections: exactly one slot, freed once
# ---------------------------------------------------------------------------
class FakeCore:
    """Just what Core's connect/disconnect handlers touch, offline."""

    def __init__(self, listener, guard):
        self.net_listener = listener
        self.guard = guard
        self.core_q = EventQ()
        self.bot_sessions = {}
        self.party_sessions = {}
        self.partyline = NS(broadcast=lambda *a, **k: None, sessions={}, next_id=1)
        self.tasks = []

    def _create_safe_task(self, coro, *, name="unnamed"):
        task = asyncio.create_task(coro, name=name)
        self.tasks.append(task)
        return task


def test_accepted_partyline_holds_one_slot_and_frees_once(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        reader, writer = await connect(listener, login())
        [ev] = listener.core_q.of("PARTYLINE_CONNECT")
        assert writer.closed == 0 and guard.active_count(IP_A) == 1 and guard.releases == []
        core = FakeCore(listener, guard)
        core.botnet = NS(peers={})
        await Core.on_partyline_connect(core, ev)
        assert listener._pending_streams == {}
        assert guard.active_count(IP_A) == 1 and guard.releases == []
        # the reaper must never touch a claimed stream
        assert await listener._reap_stale(0.0, now=time.monotonic() + 1) == 0
        assert guard.releases == []
        reader.feed_eof()
        for _ in range(200):
            if core.core_q.of("PARTYLINE_DISCONNECT"):
                break
            await asyncio.sleep(0.01)
        [dis] = core.core_q.of("PARTYLINE_DISCONNECT")
        await Core.on_partyline_disconnect(core, dis)
        await Core.on_partyline_disconnect(core, dis)    # duplicate event
        assert guard.releases == [IP_A]
        assert_baseline(listener, guard)
    run(main())


def test_accepted_botlink_holds_one_slot_bot_disconnect_does_not_double_free(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        reader, writer = await connect(listener, b"BOTLINK alpha beta 1 WBS x\n")
        [ev] = listener.core_q.of("BOT_CONNECT")
        assert guard.active_count(IP_A) == 1 and guard.releases == [] and writer.closed == 0

        core = FakeCore(listener, guard)

        async def read_peer(handle, r, w):
            # stands in for BotnetManager.read_peer: the connection owner
            await r.read()
            w.close()
            guard.release(IP_A)

        core.botnet = NS(peers={}, process_incoming=lambda *a: asyncio.sleep(0),
                         read_peer=read_peer)
        await Core.on_bot_connect(core, ev)
        assert listener._pending_streams == {} and guard.active_count(IP_A) == 1
        reader.feed_eof()
        await asyncio.wait_for(core.tasks[0], 2)
        assert guard.releases == [IP_A]
        # A late BOT_DISCONNECT (even one carrying peer_ip) must not release
        # a second time and steal another connection's slot.
        await connect(listener, b"BOTLINK gamma beta 1 WBS x\n")
        assert guard.active_count(IP_A) == 1
        await Core.on_bot_disconnect(core, {"type": "BOT_DISCONNECT", "handle": "alpha",
                                            "peer_ip": IP_A, "session_id": 1})
        assert guard.releases == [IP_A] and guard.active_count(IP_A) == 1
    run(main())


# ---------------------------------------------------------------------------
# shared NAT / global cap / multiple IPs
# ---------------------------------------------------------------------------
def test_shared_nat_per_ip_cap_counts_only_live_connections(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        for _ in range(PER_IP_MAX):
            await connect(listener, login())
        assert guard.active_count(IP_A) == PER_IP_MAX
        # cap reached: refused at admission, nothing taken, nothing released
        _, w = await connect(listener, login())
        assert "ERROR :Connection refused" in w.text and guard.releases == []
        assert guard.active_count(IP_A) == PER_IP_MAX
        # another IP is unaffected; its rejects don't touch IP_A's count
        await connect(listener, b"GET / HTTP/1.0\n", ip=IP_B)
        await connect(listener, login(), ip=IP_B)
        assert guard.active_count(IP_B) == 1 and guard.active_count(IP_A) == PER_IP_MAX
        # one IP_A session ends (reaped here) -> exactly one slot frees
        [first, *_] = listener.core_q.of("PARTYLINE_CONNECT")
        streams = listener.claim_stream(first["conn_id"])
        await listener._close_and_release(streams[1], IP_A, admitted=True)
        assert guard.active_count(IP_A) == PER_IP_MAX - 1
        await connect(listener, login())
        assert guard.active_count(IP_A) == PER_IP_MAX
    run(main())


def test_global_cap_released_by_rejects(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path), max_connections=2)
        await connect(listener, login(), ip="192.0.2.1")
        assert guard.active_count() == 1
        for n in range(10):              # rejects cycle through the free slot
            await connect(listener, login("nope"), ip=f"203.0.113.{n}")
        assert guard.active_count() == 1
        await connect(listener, login(), ip="192.0.2.2")
        assert guard.active_count() == 2
        _, w = await connect(listener, login(), ip="192.0.2.3")
        assert "ERROR :Connection refused" in w.text and guard.active_count() == 2
    run(main())


def test_concurrent_admits_cannot_overshoot_per_ip_cap(tmp_path, monkeypatch):
    """Admission check-and-take is atomic even when whitelist I/O awaits."""
    async def slow_whitelist(self, ip):
        await asyncio.sleep(0.01)
        return True

    monkeypatch.setattr(AccessGuard, "_whitelist_check", slow_whitelist)

    async def main():
        listener, guard = make_listener(await build_db(tmp_path), access_mode="whitelist",
                                        max_connections=4)
        results = await asyncio.gather(*(guard.admit(IP_A) for _ in range(PER_IP_MAX + 3)))
        assert sum(ok for ok, _ in results) == PER_IP_MAX
        assert guard.active_count(IP_A) == PER_IP_MAX
        results = await asyncio.gather(*(guard.admit(f"192.0.2.{n}") for n in range(5)))
        assert sum(ok for ok, _ in results) == 1          # global cap 4
        assert guard.active_count() == 4
    run(main())


# ---------------------------------------------------------------------------
# pending-stream reaping and replacement
# ---------------------------------------------------------------------------
def test_unclaimed_streams_are_reaped_and_released_once(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        writers = []
        for ip in (IP_A, IP_A, IP_B):
            _, w = await connect(listener, login(), ip=ip)
            writers.append(w)
        await connect(listener, b"BOTLINK alpha beta 1 WBS x\n", ip=IP_B)
        assert guard.active_count() == 4 and len(listener._pending_streams) == 4
        assert await listener._reap_stale(60.0) == 0
        assert await listener._reap_stale(0.0, now=time.monotonic() + 1) == 4
        assert all(w.closed == 1 for w in writers)
        assert sorted(guard.releases) == sorted([IP_A, IP_A, IP_B, IP_B])
        assert_baseline(listener, guard)
        # core arriving late finds nothing; a second sweep releases nothing
        for ev in listener.core_q.events:
            assert listener.claim_stream(ev["conn_id"]) is None
        assert await listener._reap_stale(0.0, now=time.monotonic() + 1) == 0
        assert len(guard.releases) == 4
    run(main())


def test_reap_releases_even_if_close_fails(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        await connect(listener, login(), writer=FakeWriter(fail_wait_closed=True))
        assert await listener._reap_stale(0.0, now=time.monotonic() + 1) == 1
        assert guard.releases == [IP_A]
        assert_baseline(listener, guard)
    run(main())


def test_reaper_survives_a_failed_sweep(tmp_path, monkeypatch):
    real_sleep = asyncio.sleep
    sweeps = []

    async def fast_sleep(delay, *a, **kw):
        await real_sleep(0)

    async def main():
        listener, _ = make_listener(await build_db(tmp_path))

        async def flaky(ttl, now=None):
            sweeps.append(ttl)
            if len(sweeps) == 1:
                raise RuntimeError("transient")
            if len(sweeps) >= 3:
                raise asyncio.CancelledError
            return 0

        listener._reap_stale = flaky
        monkeypatch.setattr(net_mod.asyncio, "sleep", fast_sleep)
        try:
            with pytest.raises(asyncio.CancelledError):
                await listener._reap_pending_streams()
        finally:
            monkeypatch.setattr(net_mod.asyncio, "sleep", real_sleep)
        assert sweeps == [60.0, 60.0, 60.0]
    run(main())


def test_pending_entry_is_never_replaced(tmp_path):
    async def main():
        listener, guard = make_listener(await build_db(tmp_path))
        _, w1 = await connect(listener, login())
        [ev] = listener.core_q.of("PARTYLINE_CONNECT")
        key = ev["conn_id"]
        r2, w2 = asyncio.StreamReader(), FakeWriter()
        assert listener._enqueue(key, r2, w2, IP_A, {"type": "PARTYLINE_CONNECT"}) is False
        assert listener._pending_streams[key][1] is w1
        assert len(listener.core_q.events) == 1
        # distinct per-connection keys: two pending logins from one IP coexist
        await connect(listener, login())
        assert len(listener._pending_streams) == 2 and guard.active_count(IP_A) == 2
        assert await listener._reap_stale(0.0, now=time.monotonic() + 1) == 2
        assert guard.releases == [IP_A, IP_A]
        assert_baseline(listener, guard)
    run(main())
