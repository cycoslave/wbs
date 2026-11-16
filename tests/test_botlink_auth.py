"""
Offline regression tests for SAST-001: botlink peer mutual authentication (AUTH2).

No network: handshakes run over in-memory fake writers, or over a local
socket.socketpair() for the end-to-end case. Every DB is a throwaway sqlite
file under pytest's tmp_path.
"""
import asyncio
import socket
import time
from types import SimpleNamespace as NS
from unittest.mock import patch

import pytest

from src import botnet as botnet_mod
from src.botnet import AUTH_PROTO, BotnetManager, _auth_proof, _derive_shared_password
from src.bot import BotManager
from src.db import get_db, init_db
from src.net import NetListener

PSK = "test-only-link-key-0123456789"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class FakeWriter:
    """Minimal StreamWriter stand-in that records written lines."""

    def __init__(self, ip="192.0.2.10"):
        self.sent: list[str] = []
        self.closed = False
        self.ip = ip

    def write(self, data: bytes):
        if self.closed:
            return
        self.sent.extend(l for l in data.decode().split("\n") if l)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def is_closing(self):
        return self.closed

    def get_extra_info(self, key):
        return (self.ip, 4444) if key == "peername" else None

    def take(self) -> list[str]:
        out, self.sent = self.sent, []
        return out


class FakeGuard:
    def __init__(self):
        self.released: list[str] = []
        self.failures: list[tuple[str, str]] = []
        self.successes: list[str] = []

    def release(self, ip):
        self.released.append(ip)

    async def record_failure(self, ip, handle="", **kw):
        self.failures.append((ip, handle))

    def record_success(self, ip, handle=""):
        self.successes.append(ip)


async def _nop(*a, **k):
    return None


_TEMPLATE_DB: str | None = None


async def _fresh_db(path: str) -> None:
    """Copy a once-initialised schema DB (init_db is slow on some filesystems)."""
    global _TEMPLATE_DB
    import os
    import shutil
    import tempfile
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-sast001-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


async def make_mgr(tmp_path, nick: str, peers: dict[str, str | None], settings=None):
    """BotnetManager for `nick` with a fresh DB holding the given peer rows."""
    db = str(tmp_path / f"{nick}.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        for handle, pw in peers.items():
            # Peers share the local subnet 1 (stored, authoritative scope; SAST-002).
            await d.execute(
                "INSERT INTO bots(handle, password, address, port, subnet_id) "
                "VALUES (?, ?, '192.0.2.1', 3333, 1)",
                (handle, pw),
            )
        await d.commit()
    sent_irc: list[dict] = []
    core = NS(
        db_path=db,
        config={"bot": {"nick": nick}, "botnet": {"subnet_id": 1},
                "settings": settings or {"ssl": False}},
        bot_sessions={},
        send_irc=sent_irc.append,
        partyline=NS(broadcast=lambda *a, **k: None),
        botname=nick,
    )
    mgr = BotnetManager(core)
    core.botnet = mgr
    mgr.share_all_data = _nop
    mgr.broadcast_topology = _nop
    mgr._register_net_handlers()
    mgr.sent_irc = sent_irc
    return mgr


async def start_outbound(a: BotnetManager, peer: str) -> FakeWriter:
    """Run a.connect_peer(peer) with a fake transport; return A's writer."""
    w = FakeWriter()

    async def fake_open(*args, **kwargs):
        return None, w

    with patch.object(botnet_mod.asyncio, "open_connection", fake_open), \
            patch.object(a, "read_peer", _nop):
        await a.connect_peer(peer)
    return w


async def handshake(a, b, a_nick="alpha", b_nick="beta"):
    """Full AUTH2 handshake A(initiator) -> B(responder). Returns (a_w, b_w, transcript)."""
    a_w = await start_outbound(a, b_nick)
    b_w = FakeWriter()
    t = {}
    t["hello"] = a_w.take()[0]
    await b.process_incoming(a_nick, t["hello"], None, b_w)
    t["ack"] = b_w.take()[0]
    await a.process_incoming(b_nick, t["ack"], None, a_w)
    t["auth"] = a_w.take()[0]
    await b.process_incoming(a_nick, t["auth"], None, b_w)
    t["ready"] = b_w.take()[0]
    await a.process_incoming(b_nick, t["ready"], None, a_w)
    return a_w, b_w, t


def run(coro):
    return asyncio.run(coro)


def authed(mgr, handle) -> bool:
    link = mgr.peers.get(handle)
    return bool(link and link.authed and link.connected and link.state == "ready")


async def cmd_executes(mgr, handle, writer) -> bool:
    mgr.sent_irc.clear()
    await mgr.process_incoming(handle, "CMD op victim #chan", None, writer)
    return bool(mgr.sent_irc)


# ---------------------------------------------------------------------------
# positive path
# ---------------------------------------------------------------------------
def test_positive_mutual_auth_over_mocked_streams(tmp_path):
    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        a_w, b_w, t = await handshake(a, b)

        assert t["hello"].split()[:3] == ["BOTLINK", "alpha", "beta"]
        assert AUTH_PROTO in t["hello"].split()
        assert PSK not in " ".join(t.values())            # key never on the wire
        assert authed(a, "beta") and authed(b, "alpha")
        assert a.peers["beta"].writer is a_w and b.peers["alpha"].writer is b_w
        assert a._handshakes == {} and b._handshakes == {}
        assert not a_w.closed and not b_w.closed
        # authenticated peers may issue commands in both directions
        assert await cmd_executes(b, "alpha", b_w)
        assert await cmd_executes(a, "beta", a_w)

    run(main())


def test_positive_mutual_auth_end_to_end_socketpair(tmp_path):
    """Real StreamReader/Writer over a local socketpair, exercising read_peer."""

    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        s1, s2 = socket.socketpair()
        ra, wa = await asyncio.open_connection(sock=s1)
        rb, wb = await asyncio.open_connection(sock=s2)

        async def fake_open(*args, **kwargs):
            return ra, wa

        with patch.object(botnet_mod.asyncio, "open_connection", fake_open):
            await a.connect_peer("beta")

        # emulate NetListener + Core.on_bot_connect on the responder side
        first = (await rb.readline()).decode().strip()
        await b.process_incoming("alpha", first, rb, wb)
        b_task = asyncio.create_task(b.read_peer("alpha", rb, wb))

        for _ in range(200):
            if authed(a, "beta") and authed(b, "alpha"):
                break
            await asyncio.sleep(0.01)
        assert authed(a, "beta") and authed(b, "alpha")

        # command over the live authenticated link reaches B
        b.sent_irc.clear()
        wa.write(b"CMD op victim #chan\n")
        await wa.drain()
        for _ in range(200):
            if b.sent_irc:
                break
            await asyncio.sleep(0.01)
        assert b.sent_irc == [{"cmd": "mode", "channel": "#chan", "modes": "+o victim"}]

        a.running = b.running = False
        wa.close()
        await asyncio.wait_for(b_task, 2)
        assert "alpha" not in b.peers                      # connection-owned cleanup
        await asyncio.sleep(0.05)

    run(main())


# ---------------------------------------------------------------------------
# READY first
# ---------------------------------------------------------------------------
def test_linkready_first_on_inbound_is_denied(tmp_path):
    async def main():
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        # exact audit repro: legacy hello then LINKREADY, no LINKAUTH
        w = FakeWriter()
        await b.process_incoming("alpha", "BOTLINK alpha beta 1 WBS test", None, w)
        await b.process_incoming("alpha", "LINKREADY alpha WBS test", None, w)
        assert not authed(b, "alpha") and w.closed
        assert not await cmd_executes(b, "alpha", w)

        # AUTH2 hello then LINKREADY instead of LINKAUTH
        w2 = FakeWriter()
        await b.process_incoming("alpha", f"BOTLINK alpha beta 1 WBS x {AUTH_PROTO} {'a' * 64}", None, w2)
        await b.process_incoming("alpha", f"LINKREADY alpha {AUTH_PROTO} {'0' * 64}", None, w2)
        assert not authed(b, "alpha") and w2.closed
        assert b._handshakes == {} and b.peers == {}

        # bare LINKREADY on a fresh connection
        w3 = FakeWriter()
        await b.process_incoming("alpha", f"LINKREADY alpha {AUTH_PROTO} {int(time.time())}", None, w3)
        assert not authed(b, "alpha") and w3.closed

    run(main())


def test_linkready_before_key_proof_on_outbound_is_denied(tmp_path):
    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        a_w = await start_outbound(a, "beta")
        a_w.take()
        # responder skips LINKACK/proof and claims READY
        await a.process_incoming("beta", f"LINKREADY beta {AUTH_PROTO} {'0' * 64}", None, a_w)
        assert not authed(a, "beta") and a_w.closed
        assert a._handshakes == {}

    run(main())


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------
def test_replayed_linkauth_is_denied(tmp_path):
    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        _, b_w, t = await handshake(a, b)
        assert authed(b, "alpha")

        # the legitimate link goes away; attacker replays the captured hello + LINKAUTH
        b.peers.clear()
        b.core.bot_sessions.clear()
        evil = FakeWriter("198.51.100.7")
        await b.process_incoming("alpha", t["hello"], None, evil)
        fresh_ack = evil.take()[0]
        assert fresh_ack != t["ack"]                         # responder nonce is fresh
        await b.process_incoming("alpha", t["auth"], None, evil)
        assert not authed(b, "alpha") and evil.closed
        assert "alpha" not in b.peers
        assert not await cmd_executes(b, "alpha", evil)

    run(main())


def test_replayed_linkack_and_linkready_are_denied(tmp_path):
    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        _, _, t = await handshake(a, b)
        a.peers.clear()

        # replay old LINKACK against a new outbound handshake (new initiator nonce)
        w = await start_outbound(a, "beta")
        w.take()
        await a.process_incoming("beta", t["ack"], None, w)
        assert w.closed and not authed(a, "beta") and w.take() == []

        # replay old LINKREADY: fresh handshake reaches await_ready via a real B,
        # then the attacker substitutes the recorded LINKREADY proof
        b.peers.clear()
        b.core.bot_sessions.clear()
        w2 = await start_outbound(a, "beta")
        bw = FakeWriter()
        await b.process_incoming("alpha", w2.take()[0], None, bw)
        await a.process_incoming("beta", bw.take()[0], None, w2)
        w2.take()
        await a.process_incoming("beta", t["ready"], None, w2)
        assert w2.closed and not authed(a, "beta")

    run(main())


def test_legacy_static_name_hmac_is_denied(tmp_path):
    """Old protocol: LINKAUTH carrying HMAC(pw, name) with optional timestamp."""
    import hashlib
    import hmac

    async def main():
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        w = FakeWriter()
        await b.process_incoming("alpha", "BOTLINK alpha beta 1 WBS 5.9.7", None, w)
        assert w.closed
        assert any("AUTH2 required" in l for l in w.sent)
        static = hmac.new(PSK.encode(), b"alphabeta", hashlib.sha256).hexdigest()
        await b.process_incoming("alpha", f"LINKAUTH alpha {static}", None, w)
        await b.process_incoming("alpha", f"LINKAUTH alpha {static} {int(time.time())}", None, w)
        assert not authed(b, "alpha")

    run(main())


def test_legacy_key_bootstrap_removed(tmp_path):
    with pytest.raises(RuntimeError):
        _derive_shared_password("00" * 16, "11" * 16)

    async def main():
        # peer offering the old partial with no local key: no key is ever derived/stored
        b = await make_mgr(tmp_path, "beta", {"alpha": None})
        w = FakeWriter()
        await b.process_incoming("alpha", f"BOTLINK alpha beta 1 WBS 5.9.7 {'ab' * 16}", None, w)
        assert w.closed and not any(l.startswith("LINKACK") for l in w.sent)
        assert (await BotManager(b.db_path).get("alpha")).password is None

    run(main())


# ---------------------------------------------------------------------------
# wrong key / identity / time
# ---------------------------------------------------------------------------
def test_wrong_key_denied_both_directions(tmp_path):
    async def main():
        # responder holds a different key -> initiator rejects LINKACK proof
        (tmp_path / "x").mkdir()
        (tmp_path / "y").mkdir()
        a = await make_mgr(tmp_path / "x", "alpha", {"beta": PSK})
        b = await make_mgr(tmp_path / "y", "beta", {"alpha": "some-other-key-xyz"})
        a_w = await start_outbound(a, "beta")
        b_w = FakeWriter()
        await b.process_incoming("alpha", a_w.take()[0], None, b_w)
        await a.process_incoming("beta", b_w.take()[0], None, a_w)
        assert a_w.closed and not authed(a, "beta")
        assert not any(l.startswith("LINKAUTH") for l in a_w.sent)

        # initiator holds the wrong key; responder rejects forged LINKAUTH
        b2 = await make_mgr(tmp_path / "y", "beta2", {"alpha": PSK})
        w = FakeWriter()
        await b2.process_incoming("alpha", f"BOTLINK alpha beta2 1 WBS x {AUTH_PROTO} {'c' * 64}", None, w)
        _, _, _, _, nonce_r, ts_r, _ = w.take()[0].split()
        ts_i = int(time.time())
        forged = _auth_proof("wrong-key", "initiator", "alpha", "beta2", "1", "c" * 64, nonce_r, int(ts_r), ts_i)
        await b2.process_incoming("alpha", f"LINKAUTH alpha {AUTH_PROTO} {ts_i} {forged}", None, w)
        assert w.closed and not authed(b2, "alpha")
        assert not any(l.startswith("LINKREADY") for l in w.sent)

    run(main())


def test_wrong_identity_denied(tmp_path):
    async def main():
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK, "gamma": PSK})
        hello = lambda remote, local: f"BOTLINK {remote} {local} 1 WBS x {AUTH_PROTO} {'d' * 64}"

        # addressed to a different local bot
        w = FakeWriter()
        await b.process_incoming("alpha", hello("alpha", "notbeta"), None, w)
        assert w.closed and b._handshakes == {}
        # claims a handle different from the connection's handle
        w = FakeWriter()
        await b.process_incoming("alpha", hello("gamma", "beta"), None, w)
        assert w.closed and b._handshakes == {}
        # unknown bot
        w = FakeWriter()
        await b.process_incoming("mallory", hello("mallory", "beta"), None, w)
        assert w.closed and b._handshakes == {}

        # proof made for gamma (same key) presented on alpha's connection
        w = FakeWriter()
        await b.process_incoming("alpha", hello("alpha", "beta"), None, w)
        _, _, _, _, nonce_r, ts_r, _ = w.take()[0].split()
        ts_i = int(time.time())
        p_gamma = _auth_proof(PSK, "initiator", "gamma", "beta", "1", "d" * 64, nonce_r, int(ts_r), ts_i)
        await b.process_incoming("alpha", f"LINKAUTH alpha {AUTH_PROTO} {ts_i} {p_gamma}", None, w)
        assert w.closed and not authed(b, "alpha")

        # reflection: responder's own LINKACK proof sent back as LINKAUTH (wrong role)
        w = FakeWriter()
        await b.process_incoming("alpha", hello("alpha", "beta"), None, w)
        ack = w.take()[0].split()
        await b.process_incoming("alpha", f"LINKAUTH alpha {AUTH_PROTO} {ack[5]} {ack[6]}", None, w)
        assert w.closed and not authed(b, "alpha")

        # LINKAUTH naming another initiator
        w = FakeWriter()
        await b.process_incoming("alpha", hello("alpha", "beta"), None, w)
        w.take()
        await b.process_incoming("alpha", f"LINKAUTH gamma {AUTH_PROTO} {int(time.time())} {'0' * 64}", None, w)
        assert w.closed and not authed(b, "alpha")

    run(main())


def test_wrong_identity_in_linkack_denied(tmp_path):
    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        a_w = await start_outbound(a, "beta")
        nonce_i = a_w.take()[0].split()[7]
        ts = int(time.time())
        # correct key, but proof/responder identity for "gamma"
        p = _auth_proof(PSK, "responder", "alpha", "gamma", "1", nonce_i, "e" * 64, ts)
        await a.process_incoming("beta", f"LINKACK gamma alpha {AUTH_PROTO} {'e' * 64} {ts} {p}", None, a_w)
        assert a_w.closed and not authed(a, "beta")

    run(main())


def test_missing_changed_and_skewed_timestamps_denied(tmp_path):
    async def main():
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})

        async def fresh():
            w = FakeWriter()
            await b.process_incoming("alpha", f"BOTLINK alpha beta 1 WBS x {AUTH_PROTO} {'f' * 64}", None, w)
            _, _, _, _, nonce_r, ts_r, _ = w.take()[0].split()
            return w, nonce_r, int(ts_r)

        def proof(nonce_r, ts_r, ts_i):
            return _auth_proof(PSK, "initiator", "alpha", "beta", "1", "f" * 64, nonce_r, ts_r, ts_i)

        # missing timestamp
        w, nr, tr = await fresh()
        now = int(time.time())
        await b.process_incoming("alpha", f"LINKAUTH alpha {AUTH_PROTO} {proof(nr, tr, now)}", None, w)
        assert w.closed and not authed(b, "alpha")

        # non-numeric timestamp
        w, nr, tr = await fresh()
        await b.process_incoming("alpha", f"LINKAUTH alpha {AUTH_PROTO} soon {proof(nr, tr, now)}", None, w)
        assert w.closed and not authed(b, "alpha")

        # changed timestamp (proof computed over a different ts)
        w, nr, tr = await fresh()
        now = int(time.time())
        await b.process_incoming("alpha", f"LINKAUTH alpha {AUTH_PROTO} {now + 1} {proof(nr, tr, now)}", None, w)
        assert w.closed and not authed(b, "alpha")

        # validly-signed but stale timestamp (clock skew beyond limit)
        w, nr, tr = await fresh()
        old = int(time.time()) - 600
        await b.process_incoming("alpha", f"LINKAUTH alpha {AUTH_PROTO} {old} {proof(nr, tr, old)}", None, w)
        assert w.closed and not authed(b, "alpha")
        assert any("clock skew" in l for l in w.sent)

        # initiator rejects a validly-signed but skewed LINKACK
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        a_w = await start_outbound(a, "beta")
        nonce_i = a_w.take()[0].split()[7]
        old = int(time.time()) - 600
        p = _auth_proof(PSK, "responder", "alpha", "beta", "1", nonce_i, "9" * 64, old)
        await a.process_incoming("beta", f"LINKACK beta alpha {AUTH_PROTO} {'9' * 64} {old} {p}", None, a_w)
        assert a_w.closed and not authed(a, "beta")

    run(main())


def test_no_provisioned_key_denied(tmp_path):
    async def main():
        b = await make_mgr(tmp_path, "beta", {"alpha": None})
        w = FakeWriter()
        await b.process_incoming("alpha", f"BOTLINK alpha beta 1 WBS x {AUTH_PROTO} {'1' * 64}", None, w)
        assert w.closed and b._handshakes == {}

        a = await make_mgr(tmp_path, "alpha", {"beta": None})
        opened = []

        async def fake_open(*args, **kwargs):
            opened.append(args)
            return None, FakeWriter()

        with patch.object(botnet_mod.asyncio, "open_connection", fake_open):
            await a.connect_peer("beta")
        assert opened == [] and a._handshakes == {}

    run(main())


# ---------------------------------------------------------------------------
# second writer / duplicate handle
# ---------------------------------------------------------------------------
def test_second_writer_cannot_inherit_or_replace_live_link(tmp_path):
    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        _, b_w, t = await handshake(a, b)
        link = b.peers["alpha"]

        other = FakeWriter("198.51.100.9")
        # audit repro: second socket re-sends hello and then a command
        await b.process_incoming("alpha", t["hello"], None, other)
        assert other.closed and any("already linked" in l for l in other.sent)
        assert not await cmd_executes(b, "alpha", other)
        # legacy-style hello on the second socket is also refused
        other2 = FakeWriter("198.51.100.9")
        await b.process_incoming("alpha", "BOTLINK alpha beta 2 WBS test", None, other2)
        assert not await cmd_executes(b, "alpha", other2)

        # the live link is untouched and still works
        assert b.peers["alpha"] is link and link.writer is b_w and not b_w.closed
        assert await cmd_executes(b, "alpha", b_w)

    run(main())


def test_second_writer_cannot_hijack_pending_handshake(tmp_path):
    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        a_w = await start_outbound(a, "beta")
        b_w = FakeWriter()
        await b.process_incoming("alpha", a_w.take()[0], None, b_w)
        await a.process_incoming("beta", b_w.take()[0], None, a_w)
        auth_line = a_w.take()[0]

        # attacker on a second socket injects the victim's in-flight LINKAUTH
        evil = FakeWriter("198.51.100.9")
        await b.process_incoming("alpha", auth_line, None, evil)
        assert evil.closed and not authed(b, "alpha")
        assert b_w in b._handshakes                       # legit handshake not disturbed

        await b.process_incoming("alpha", auth_line, None, b_w)
        assert authed(b, "alpha") and b.peers["alpha"].writer is b_w
        assert not await cmd_executes(b, "alpha", evil)

    run(main())


def test_duplicate_completion_race_rejected(tmp_path):
    """Two inbound handshakes for one handle: the second to complete is refused."""

    async def main():
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        a1 = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        a2 = await make_mgr(tmp_path, "alpha2db", {"beta": PSK})
        a2.my_handle = "alpha"

        async def half(a):
            aw = await start_outbound(a, "beta")
            bw = FakeWriter()
            await b.process_incoming("alpha", aw.take()[0], None, bw)
            await a.process_incoming("beta", bw.take()[0], None, aw)
            return aw.take()[0], bw

        auth1, bw1 = await half(a1)
        auth2, bw2 = await half(a2)
        await b.process_incoming("alpha", auth1, None, bw1)
        assert b.peers["alpha"].writer is bw1
        await b.process_incoming("alpha", auth2, None, bw2)
        assert bw2.closed and b.peers["alpha"].writer is bw1 and not bw1.closed

    run(main())


# ---------------------------------------------------------------------------
# connection-owned cleanup
# ---------------------------------------------------------------------------
def test_failed_handshake_cleanup_and_guard_release(tmp_path):
    async def main():
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        guard = FakeGuard()
        b.guard = guard
        reader = asyncio.StreamReader()
        w = FakeWriter("203.0.113.5")
        await b.process_incoming("alpha", f"BOTLINK alpha beta 1 WBS x {AUTH_PROTO} {'2' * 64}", reader, w)
        assert w in b._handshakes
        reader.feed_data(f"LINKAUTH alpha {AUTH_PROTO} {int(time.time())} {'0' * 64}\n".encode())
        reader.feed_eof()
        await asyncio.wait_for(b.read_peer("alpha", reader, w), 2)
        assert w.closed and b._handshakes == {} and b.peers == {} and b.core.bot_sessions == {}
        assert guard.released == ["203.0.113.5"]
        assert guard.failures == [("203.0.113.5", "alpha")]
        assert guard.successes == []

    run(main())


def test_stalled_handshake_times_out(tmp_path):
    async def main():
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK},
                           settings={"ssl": False, "handshake_timeout": 0.2})
        reader = asyncio.StreamReader()
        w = FakeWriter()
        await b.process_incoming("alpha", f"BOTLINK alpha beta 1 WBS x {AUTH_PROTO} {'3' * 64}", reader, w)
        await asyncio.wait_for(b.read_peer("alpha", reader, w), 2)
        assert w.closed and b._handshakes == {} and b.peers == {}

    run(main())


def test_rejected_second_connection_cleanup_keeps_live_link(tmp_path):
    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK})
        _, b_w, t = await handshake(a, b)
        link = b.peers["alpha"]

        reader = asyncio.StreamReader()
        other = FakeWriter("198.51.100.9")
        await b.process_incoming("alpha", t["hello"], reader, other)
        reader.feed_eof()
        await asyncio.wait_for(b.read_peer("alpha", reader, other), 2)
        # the rejected socket's teardown must not unlink the live peer
        assert b.peers.get("alpha") is link and b.core.bot_sessions.get("alpha") is link
        assert not b_w.closed and await cmd_executes(b, "alpha", b_w)

    run(main())


def test_connect_peer_skips_when_already_linked_or_pending(tmp_path):
    async def main():
        a = await make_mgr(tmp_path, "alpha", {"beta": PSK})
        w1 = await start_outbound(a, "beta")
        assert len(a._handshakes) == 1
        opened = []

        async def fake_open(*args, **kwargs):
            opened.append(args)
            return None, FakeWriter()

        with patch.object(botnet_mod.asyncio, "open_connection", fake_open):
            await a.connect_peer("beta")
        assert opened == [] and len(a._handshakes) == 1 and not w1.closed

    run(main())


# ---------------------------------------------------------------------------
# key confidentiality + listener
# ---------------------------------------------------------------------------
def test_link_keys_not_shared_with_peers(tmp_path):
    async def main():
        b = await make_mgr(tmp_path, "beta", {"alpha": PSK, "gamma": "gamma-key-123456"})
        rows = await BotManager(b.db_path).serialize_for_peer("alpha")
        assert rows and all("password" not in r for r in rows)
        # peer-supplied password is never stored either
        await BotManager(b.db_path).merge_from_peer(
            [{"handle": "gamma", "password": "attacker", "updated_at": int(time.time()) + 100}], "alpha")
        assert (await BotManager(b.db_path).get("gamma")).password == "gamma-key-123456"

    run(main())


def test_listener_keys_pending_botlink_streams_per_connection():
    async def main():
        events = []
        listener = NetListener(NS(put_nowait=events.append), {"settings": {"dev_mode": True}}, None)
        w1, w2 = FakeWriter(), FakeWriter()
        line = f"BOTLINK alpha beta 1 WBS x {AUTH_PROTO} {'4' * 64}"
        await listener._handle_botlink(line, ("192.0.2.1", 1), "192.0.2.1", None, w1)
        await listener._handle_botlink(line, ("192.0.2.2", 2), "192.0.2.2", None, w2)
        keys = [e["conn_id"] for e in events]
        assert len(set(keys)) == 2
        assert listener._pending_streams[keys[0]][1] is w1
        assert listener._pending_streams[keys[1]][1] is w2

    run(main())
