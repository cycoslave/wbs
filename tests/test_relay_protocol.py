"""
Offline regression tests for SAST-017: interactive partyline relay with
authenticated, owner-bound sessions.

Topology: four real BotnetManagers linked over the real AUTH2 handshake on
in-memory fake writers, each with a real Partyline + RelayManager and a real
UserManager over a throwaway sqlite DB (pytest tmp_path).  No sockets, no IRC.

    alpha  subnet 1   origin bot of the relayed user
    beta   subnet 1   relay target; config botnet.relay_from delegates
                      alice to alpha only, eps's own users to eps
    eps    subnet 1   a second trusted, delegating peer (the would-be spoofer)
    gamma  subnet 2   cross-subnet peer (wildcard-delegated, still denied)
    zeta   subnet 1   linked same-subnet peer delegated nothing

Covered:
  * valid lifecycle: open -> opened -> input -> output -> close, persistent and
    one-shot; no missing APIs, no awaiting of the synchronous send_to_session
  * relayed input runs through Partyline._handle_command with the *target's*
    authorization for the relayed handle (never console privileges)
  * cross-peer spoofing of identity / session for input, output, close and
    opened is denied; a duplicate open never hijacks a live session
  * open denied for non-delegating, cross-subnet, unknown/locked/deleted/no-+p
    users and the console pseudo-user; origin side requires +A, refuses the
    console, and stops forwarding when the user loses +A
  * strict typed payload parsing; legacy RELAY_OPEN/INPUT/CLOSE/OUTPUT denied
  * unpredictable 128-bit session ids; link loss and session end clean up
"""
import asyncio
import inspect
import json
import os
import shutil
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import patch

import pytest

from src import botnet as botnet_mod
from src import relay as relay_mod
from src.botnet import BotnetManager
from src.db import get_db, init_db
from src.partyline import Partyline
from src.relay import RelayManager, new_relay_id, parse_relay_payload
from src.user import UserManager

PSK = "test-only-link-key-0123456789"
BOT_SUBNETS = {"alpha": 1, "beta": 1, "eps": 1, "gamma": 2, "zeta": 1}
# beta delegates: alice may arrive only via alpha; eps vouches for its own
# users (and the bad ones, so the denial reason is the user state); gamma gets
# a wildcard but is cross-subnet; zeta is not delegated anything.
RELAY_FROM = {"beta": {
    "alpha": ["alice"],
    "EPS": ["Mallory", "locky", "gone", "noflag", "faraway", "nobody", "console"],
    "gamma": ["*"],
}}

# Users per bot: handle -> (access rows [(subnet_id, {columns})], state)
ORIGIN_USERS = {
    "alice": ([(None, {"has_partyline", "is_admin"})], None),   # may .relay
    "carol": ([(None, {"has_partyline"})], None),               # no +A: may not
    "mallory": ([(None, {"has_partyline", "is_admin"})], None),  # on eps
}
TARGET_USERS = {
    "alice":   ([(None, {"has_partyline"})], None),            # +p only on beta
    "Mallory": ([(None, {"has_partyline"})], None),
    "locky":   ([(None, {"has_partyline"})], "locked"),
    "gone":    ([(None, {"has_partyline"})], "deleted"),
    "noflag":  ([(None, {"is_op"})], None),
    "faraway": ([(2, {"has_partyline"})], None),
    "console": ([(None, {"has_partyline", "is_admin", "is_owner"})], None),
}


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


class FakeWriter:
    def __init__(self):
        self.sent: list[str] = []
        self.closed = False

    def write(self, data: bytes):
        if not self.closed:
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
        return ("192.0.2.10", 4444) if key == "peername" else None

    def take(self) -> list[str]:
        out, self.sent = self.sent, []
        return out


async def _nop(*a, **k):
    return None


_TEMPLATE_DB: str | None = None


async def _db(path: str, users: dict) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-sast017-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)
    async with get_db(path) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        for handle, sid in BOT_SUBNETS.items():
            await d.execute(
                "INSERT INTO bots(handle, password, address, port, subnet_id) "
                "VALUES (?, ?, '192.0.2.1', 3333, ?)", (handle, PSK, sid))
        for handle, (rows, state) in users.items():
            await d.execute("INSERT INTO users(handle, password, hostmasks) VALUES (?, NULL, '[]')",
                            (handle,))
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


async def make_bot(tmp_path, nick: str, users: dict):
    db = str(tmp_path / f"{nick}.db")
    await _db(db, users)
    botnet_cfg: dict = {"subnet_id": BOT_SUBNETS[nick]}
    if nick in RELAY_FROM:
        botnet_cfg["relay_from"] = {k: list(v) for k, v in RELAY_FROM[nick].items()}
    core = NS(
        db_path=db,
        config={"bot": {"nick": nick}, "botnet": botnet_cfg, "settings": {"ssl": False}},
        bot_sessions={},
        send_irc=lambda *a, **k: None,
        botname=nick,
        irc_q=None,
        user=UserManager(db),
        bot_isop=lambda chan: True,
        channels={},
    )
    core.partyline = Partyline(core)
    mgr = BotnetManager(core)
    core.botnet = mgr
    mgr.share_all_data = _nop
    mgr.broadcast_topology = _nop
    mgr.broadcast_chat = _nop            # keep chat floods out of the relay traces
    await mgr.subnet.load()
    return core


class Net:
    """Linked bots plus a pump that delivers queued lines in both directions."""

    def __init__(self):
        self.bots: dict[str, NS] = {}
        self.pipes: list[tuple[str, str, FakeWriter, FakeWriter]] = []

    async def link(self, a: str, b: str):
        ia, rb = self.bots[a].botnet, self.bots[b].botnet
        i_w = FakeWriter()

        async def fake_open(*args, **kwargs):
            return None, i_w

        with patch.object(botnet_mod.asyncio, "open_connection", fake_open), \
                patch.object(ia, "read_peer", _nop):
            await ia.connect_peer(b)
        r_w = FakeWriter()
        await rb.process_incoming(a, i_w.take()[0], None, r_w)
        await ia.process_incoming(b, r_w.take()[0], None, i_w)
        await rb.process_incoming(a, i_w.take()[0], None, r_w)
        await ia.process_incoming(b, r_w.take()[0], None, i_w)
        assert rb.peers[a].authed and ia.peers[b].authed
        # Link-up SUBNET announcements (NET-7): deliver them like the wire would.
        for line in i_w.take():
            await rb.process_incoming(a, line, None, r_w)
        for line in r_w.take():
            await ia.process_incoming(b, line, None, i_w)
        # a writes on i_w (read by b); b writes on r_w (read by a)
        self.pipes.append((a, b, i_w, r_w))

    def writer(self, src: str, dst: str) -> FakeWriter:
        """The writer `src` uses to talk to `dst`."""
        for a, b, i_w, r_w in self.pipes:
            if (a, b) == (src, dst):
                return i_w
            if (b, a) == (src, dst):
                return r_w
        raise KeyError((src, dst))

    async def inject(self, src: str, dst: str, line: str):
        """Deliver a raw line to `dst` as if sent by authenticated peer `src`."""
        await self.bots[dst].botnet.process_incoming(src, line, None, self.writer(dst, src))

    async def pump(self, rounds: int = 20) -> list[tuple[str, str, str]]:
        delivered = []
        for _ in range(rounds):
            await asyncio.sleep(0)
            moved = False
            for a, b, i_w, r_w in self.pipes:
                for line in i_w.take():
                    moved = True
                    delivered.append((a, b, line))
                    await self.bots[b].botnet.process_incoming(a, line, None, r_w)
                for line in r_w.take():
                    moved = True
                    delivered.append((b, a, line))
                    await self.bots[a].botnet.process_incoming(b, line, None, i_w)
            if not moved:
                break
        return delivered


def relay_msgs(delivered, src=None, dst=None):
    out = []
    for s, d, line in delivered:
        if line.startswith("RELAY ") and (src is None or s == src) and (dst is None or d == dst):
            out.append(json.loads(line.split(None, 1)[1]))
    return out


async def build(tmp_path) -> Net:
    net = Net()
    for nick in BOT_SUBNETS:
        users = TARGET_USERS if nick == "beta" else ORIGIN_USERS
        net.bots[nick] = await make_bot(tmp_path, nick, users)
    await net.link("alpha", "beta")
    await net.link("eps", "beta")
    await net.link("gamma", "beta")
    await net.link("zeta", "beta")
    await net.link("eps", "alpha")
    return net


def login(net: Net, bot: str, handle: str, kind: str = "dcc"):
    """Register a remote partyline session; returns (session_id, response queue)."""
    q = asyncio.Queue()
    sid = net.bots[bot].partyline.register_remote(kind, handle, q)
    return sid, q


def drain(q: asyncio.Queue) -> list[str]:
    out = []
    while not q.empty():
        out.append(q.get_nowait()["text"])
    return out


async def open_relay(net: Net, handle="alice", bot="alpha", target="beta"):
    sid, q = login(net, bot, handle)
    await net.bots[bot].partyline.handle_input(sid, f".relay {target}")
    delivered = await net.pump()
    return sid, q, delivered


def rel_of(net: Net, sid: int, bot="alpha"):
    return net.bots[bot].partyline.relay.outbound_for(sid)


def inbound(net: Net, bot="beta"):
    return net.bots[bot].partyline.relay.inbound


# ---------------------------------------------------------------------------
# valid lifecycle
# ---------------------------------------------------------------------------
def test_persistent_relay_full_lifecycle(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, delivered = await open_relay(net)
        rel = rel_of(net, sid)
        assert rel is not None and rel.state == "open" and rel.target == "beta"
        out = drain(q)
        assert any("Relaying to beta" in l for l in out) and "*** Relayed to beta." in out

        # the open on the wire carries no origin/session fields: only rid + handle
        opened = relay_msgs(delivered, "alpha", "beta")
        assert opened[0] == {"v": 1, "op": "open", "rid": rel.rid, "handle": "alice"}

        # target side: a virtual 'relay' session for alice bound to the alpha link
        (key, irel), = inbound(net).items()
        assert key == ("alpha", rel.rid)
        beta_pl = net.bots["beta"].partyline
        assert beta_pl.sessions[irel.vsid]["type"] == "relay"
        assert beta_pl.sessions[irel.vsid]["handle"] == "alice"
        assert irel.link is net.bots["beta"].botnet.peers["alpha"]

        # input runs on beta, as alice, output comes back to the real session
        await net.bots["alpha"].partyline.handle_input(sid, ".whoami")
        await net.pump()
        assert drain(q) == ["You are alice@beta"]

        # close from the origin removes both sides
        await net.bots["alpha"].partyline.handle_input(sid, ".relay")
        delivered = await net.pump()
        assert rel_of(net, sid) is None
        assert inbound(net) == {}
        assert irel.vsid not in beta_pl.sessions
        assert relay_msgs(delivered, "alpha", "beta")[-1]["op"] == "close"
        assert any("Relay to beta closed. Back on alpha." in l for l in drain(q))

        # back on alpha: commands run locally again
        await net.bots["alpha"].partyline.handle_input(sid, ".whoami")
        assert drain(q) == ["You are alice@alpha"]
    run(go())


def test_one_shot_relay(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q = login(net, "alpha", "alice")
        await net.bots["alpha"].partyline.handle_input(sid, ".relay beta whoami")
        # cmd_relay strips nothing: the remote command is sent verbatim
        assert drain(q) == ["-> [beta] whoami"]
        await net.pump()
        # 'whoami' is chat on beta (no dot), so use the dotted form too
        await net.bots["alpha"].partyline.handle_input(sid, ".relay beta .whoami")
        await net.pump()
        out = drain(q)
        assert "[beta] You are alice@beta" in out
        assert net.bots["alpha"].partyline.relay.outbound == {}
        assert inbound(net) == {}
        assert rel_of(net, sid) is None             # one-shot never captures input
    run(go())


def test_target_authorization_applies_not_origin_or_console(tmp_path):
    """alice is +A on alpha but only +p on beta: beta's policy wins."""
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        drain(q)
        for cmd in (".status", ".chattr alice +A", ".die", ".+user evil"):
            await net.bots["alpha"].partyline.handle_input(sid, cmd)
            await net.pump()
            out = drain(q)
            assert out and out[0].startswith("Access denied for ."), (cmd, out)
        # the virtual session is never a console session
        irel = next(iter(inbound(net).values()))
        assert net.bots["beta"].partyline.sessions[irel.vsid]["type"] == "relay"
        from src.helper import _is_console
        assert not _is_console(net.bots["beta"], irel.vsid)
    run(go())


def test_identity_changing_and_nested_commands_refused_on_relay(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        drain(q)
        for cmd in ("handle", "chpass", "detach", "relay"):
            await net.bots["alpha"].partyline.handle_input(sid, f".{cmd} zeta")
            await net.pump()
            assert drain(q) == [f"Not allowed over a relay: .{cmd}"]
        irel = next(iter(inbound(net).values()))
        assert net.bots["beta"].partyline.sessions[irel.vsid]["handle"] == "alice"
    run(go())


def test_sync_async_contract():
    """send_to_session is synchronous; relay entry points are coroutines."""
    assert not inspect.iscoroutinefunction(Partyline.send_to_session)
    assert inspect.iscoroutinefunction(RelayManager.on_message)
    assert inspect.iscoroutinefunction(RelayManager.open)
    assert inspect.iscoroutinefunction(RelayManager.send_input)
    assert not hasattr(BotnetManager, "send_to_peer")      # no phantom transport API
    assert not hasattr(Partyline, "relay_sessions")
    import src.commands as commands
    src = inspect.getsource(commands.cmd_relay)
    assert "send_to_peer" not in src and "relay_sessions" not in src


# ---------------------------------------------------------------------------
# spoofing: cross-peer input / output / close / opened
# ---------------------------------------------------------------------------
def test_cross_peer_input_and_close_denied(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        drain(q)
        rid = rel_of(net, sid).rid
        irel = inbound(net)[("alpha", rid)]
        seen = []
        orig = net.bots["beta"].partyline._handle_command

        async def spy(vsid, handle, text):
            seen.append((vsid, handle, text))
            await orig(vsid, handle, text)
        net.bots["beta"].partyline._handle_command = spy

        # eps knows the rid (worst case) and tries to type into alice's session
        await net.inject("eps", "beta", "RELAY " + json.dumps(
            {"v": 1, "op": "input", "rid": rid, "text": ".whoami"}))
        # ... and to close it
        await net.inject("eps", "beta", "RELAY " + json.dumps(
            {"v": 1, "op": "close", "rid": rid}))
        await net.pump()
        assert seen == []
        assert inbound(net).get(("alpha", rid)) is irel
        assert drain(q) == []

        # a re-assertion of the origin in the payload is rejected outright
        await net.inject("eps", "beta", "RELAY " + json.dumps(
            {"v": 1, "op": "input", "rid": rid, "text": ".whoami", "origin": "alpha"}))
        await net.pump()
        assert seen == []

        # the real owner still works
        await net.bots["alpha"].partyline.handle_input(sid, ".whoami")
        await net.pump()
        assert drain(q) == ["You are alice@beta"]
    run(go())


def test_cross_peer_output_opened_close_denied_on_origin(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        drain(q)
        rel = rel_of(net, sid)
        # eps (linked to alpha) forges output / opened / close for alpha's relay to beta
        for payload in ({"op": "output", "rid": rel.rid, "text": "you are owned"},
                        {"op": "opened", "rid": rel.rid},
                        {"op": "close", "rid": rel.rid, "reason": "bye"}):
            await net.inject("eps", "alpha", "RELAY " + json.dumps({"v": 1, **payload}))
        await net.pump()
        assert drain(q) == []
        assert rel_of(net, sid) is rel and rel.state == "open"

        # output for a rid that is not ours, from the right peer, is dropped too
        await net.inject("beta", "alpha", "RELAY " + json.dumps(
            {"v": 1, "op": "output", "rid": new_relay_id(), "text": "x"}))
        assert drain(q) == []
    run(go())


def test_duplicate_open_never_hijacks_session(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        rid = rel_of(net, sid).rid
        irel = inbound(net)[("alpha", rid)]
        # same peer re-opens the rid under another identity: ignored
        await net.inject("alpha", "beta", "RELAY " + json.dumps(
            {"v": 1, "op": "open", "rid": rid, "handle": "Mallory"}))
        assert inbound(net)[("alpha", rid)] is irel
        assert net.bots["beta"].partyline.sessions[irel.vsid]["handle"] == "alice"
        # another peer using the same rid gets its own (peer, rid) slot only
        await net.inject("eps", "beta", "RELAY " + json.dumps(
            {"v": 1, "op": "open", "rid": rid, "handle": "Mallory"}))
        assert inbound(net)[("alpha", rid)] is irel
        assert inbound(net)[("eps", rid)].handle == "Mallory"
        assert inbound(net)[("eps", rid)].vsid != irel.vsid
    run(go())


def test_cross_peer_identity_spoof_denied(tmp_path):
    """eps is trusted for its own users but may not assert alpha's user alice."""
    async def go():
        net = await build(tmp_path)
        cases = [("eps", "alice"), ("eps", "ALICE"), ("alpha", "Mallory"), ("zeta", "alice")]
        for peer, handle in cases:
            rid = new_relay_id()
            await net.inject(peer, "beta", "RELAY " + json.dumps(
                {"v": 1, "op": "open", "rid": rid, "handle": handle, "text": ".whoami"}))
            lines = net.writer("beta", peer).take()
            assert not any("@beta" in l for l in lines), (peer, handle, lines)
            assert relay_msgs([("beta", peer, l) for l in lines]) == [
                {"v": 1, "op": "close", "rid": rid, "reason": "access denied"}], (peer, handle)
        assert inbound(net) == {}
        # the legitimate pairing still works
        rid = new_relay_id()
        await net.inject("eps", "beta", "RELAY " + json.dumps(
            {"v": 1, "op": "open", "rid": rid, "handle": "mallory", "text": ".whoami"}))
        out = relay_msgs([("beta", "eps", l) for l in net.writer("beta", "eps").take()])
        assert {"v": 1, "op": "output", "rid": rid, "text": "You are Mallory@beta"} in out
    run(go())


@pytest.mark.parametrize("relay_from", [
    None, [], ["alpha"], "alpha", {"alpha": "alice"}, {"alpha": []}, {"alpha": None},
    {"other": ["*"]},
])
def test_delegation_config_default_deny(tmp_path, relay_from):
    async def go():
        net = await build(tmp_path)
        net.bots["beta"].config["botnet"]["relay_from"] = relay_from
        sid, q, _ = await open_relay(net)
        assert inbound(net) == {}
        assert rel_of(net, sid) is None
        assert any("Relay to beta closed (access denied)." in l for l in drain(q))
    run(go())


def test_spoofed_identity_is_only_the_delegating_peers_own_user(tmp_path):
    """A delegating peer vouches for its user; the target re-checks that user."""
    async def go():
        net = await build(tmp_path)
        for handle in ("locky", "gone", "noflag", "faraway", "nobody", "console", "CONSOLE"):
            rid = new_relay_id()
            await net.inject("eps", "beta", "RELAY " + json.dumps(
                {"v": 1, "op": "open", "rid": rid, "handle": handle}))
            assert ("eps", rid) not in inbound(net), handle
            reply = relay_msgs([("beta", "eps", l) for l in net.writer("beta", "eps").take()])
            assert reply == [{"v": 1, "op": "close", "rid": rid, "reason": "access denied"}], handle
        assert all(s["type"] != "relay" for s in net.bots["beta"].partyline.sessions.values())
    run(go())


def test_non_delegating_and_cross_subnet_peers_denied(tmp_path):
    async def go():
        net = await build(tmp_path)
        for peer in ("zeta", "gamma"):     # not in relay_from / other subnet
            rid = new_relay_id()
            await net.inject(peer, "beta", "RELAY " + json.dumps(
                {"v": 1, "op": "open", "rid": rid, "handle": "alice"}))
            assert inbound(net) == {}, peer
            # a one-shot carrying a command is denied before anything runs
            await net.inject(peer, "beta", "RELAY " + json.dumps(
                {"v": 1, "op": "open", "rid": new_relay_id(), "handle": "alice",
                 "text": ".whoami"}))
            lines = net.writer("beta", peer).take()
            assert not any("alice@beta" in l for l in lines)
            assert inbound(net) == {}
        # default: no relay_from configured on alpha -> nobody may relay into alpha
        rid = new_relay_id()
        await net.inject("eps", "alpha", "RELAY " + json.dumps(
            {"v": 1, "op": "open", "rid": rid, "handle": "alice"}))
        assert inbound(net, "alpha") == {}
    run(go())


def test_revocation_mid_session_closes_relay(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        drain(q)
        rid = rel_of(net, sid).rid
        # lock alice on the target: the next input is refused and the relay closes
        async with get_db(net.bots["beta"].db_path) as d:
            await d.execute("UPDATE users SET is_locked = 1 WHERE handle = 'alice'")
            await d.commit()
        await net.bots["alpha"].partyline.handle_input(sid, ".whoami")
        await net.pump()
        out = drain(q)
        assert "You are alice@beta" not in out
        assert ("alpha", rid) not in inbound(net)
        assert rel_of(net, sid) is None
        assert any("closed (access denied)" in l for l in out)
    run(go())


def test_target_delegation_withdrawn_mid_session(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        drain(q)
        net.bots["beta"].config["botnet"]["relay_from"] = {"eps": ["*"]}
        await net.bots["alpha"].partyline.handle_input(sid, ".whoami")
        await net.pump()
        assert "You are alice@beta" not in drain(q)
        assert inbound(net) == {}
    run(go())


# ---------------------------------------------------------------------------
# origin-side authorization
# ---------------------------------------------------------------------------
def test_origin_requires_admin_and_refuses_console(tmp_path):
    async def go():
        net = await build(tmp_path)
        alpha = net.bots["alpha"].partyline
        sid, q = login(net, "alpha", "carol")
        await alpha.handle_input(sid, ".relay beta")
        assert drain(q) == ["Access denied for .relay (need +A)."]
        assert alpha.relay.outbound == {}

        out = []
        csid = alpha.register_console("console", out.append)
        await alpha.handle_input(csid, ".relay beta")
        assert any("console has no identity" in l for l in out)
        assert alpha.relay.outbound == {}
        assert net.writer("alpha", "beta").take() == []

        sid, q = login(net, "alpha", "alice")
        for target in ("nosuchbot", "gamma", "alpha"):   # not linked / not a peer / self
            await alpha.handle_input(sid, f".relay {target}")
        assert alpha.relay.outbound == {}
    run(go())


def test_origin_stops_forwarding_when_flag_revoked(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        drain(q)
        async with get_db(net.bots["alpha"].db_path) as d:
            await d.execute("UPDATE user_access SET is_admin = 0 WHERE handle = 'alice'")
            await d.commit()
        await net.bots["alpha"].partyline.handle_input(sid, ".whoami")
        delivered = await net.pump()
        assert [m["op"] for m in relay_msgs(delivered, "alpha", "beta")] == ["close"]
        assert rel_of(net, sid) is None and inbound(net) == {}
        assert "You are alice@beta" not in drain(q)
    run(go())


def test_input_before_opened_is_not_forwarded(tmp_path):
    async def go():
        net = await build(tmp_path)
        alpha = net.bots["alpha"].partyline
        sid, q = login(net, "alpha", "alice")
        await alpha.handle_input(sid, ".relay beta")
        net.writer("alpha", "beta").take()       # the open never reaches beta
        await alpha.handle_input(sid, ".whoami")
        assert net.writer("alpha", "beta").take() == []
        assert "Relay to beta is not established yet." in drain(q)
    run(go())


# ---------------------------------------------------------------------------
# lifecycle cleanup
# ---------------------------------------------------------------------------
def test_origin_session_end_closes_remote(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        net.bots["alpha"].partyline.unregister_session(sid)
        await net.pump()
        assert net.bots["alpha"].partyline.relay.outbound == {}
        assert inbound(net) == {}
    run(go())


def test_target_revoke_handle_closes_relay(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        assert net.bots["beta"].partyline.revoke_handle("alice", "locked") == 1
        await net.pump()
        assert inbound(net) == {}
        assert rel_of(net, sid) is None
    run(go())


def test_link_loss_drops_bound_relays(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        drain(q)
        await net.bots["beta"].botnet.disconnect_peer("alpha")
        assert inbound(net) == {}
        await net.bots["alpha"].botnet.disconnect_peer("beta")
        assert rel_of(net, sid) is None
        assert any("link lost" in l for l in drain(q))
    run(go())


def test_relay_bound_to_link_object_not_name(tmp_path):
    """A different connection under the same peer name cannot use old sessions."""
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        rid = rel_of(net, sid).rid
        beta = net.bots["beta"].botnet
        old = beta.peers["alpha"]
        beta.peers["alpha"] = botnet_mod.BotLink(
            name="alpha", host="x", port=1, writer=FakeWriter(), state="ready",
            authed=True, connected=True, subnet_ids=frozenset({1}), subnet_id=1)
        w = beta.peers["alpha"].writer
        await beta.process_incoming("alpha", "RELAY " + json.dumps(
            {"v": 1, "op": "input", "rid": rid, "text": ".whoami"}), None, w)
        assert not any("alice@beta" in l for l in w.take() + old.writer.take())
    run(go())


# ---------------------------------------------------------------------------
# protocol parsing
# ---------------------------------------------------------------------------
def test_relay_ids_are_unpredictable():
    ids = {new_relay_id() for _ in range(2000)}
    assert len(ids) == 2000
    assert all(len(i) == 32 and int(i, 16) >= 0 for i in ids)


@pytest.mark.parametrize("payload", [
    "not json",
    "[]",
    '{"v": 2, "op": "input", "rid": "%s", "text": "x"}' % ("a" * 32),
    '{"v": true, "op": "input", "rid": "%s", "text": "x"}' % ("a" * 32),
    '{"v": 1, "op": "exec", "rid": "%s"}' % ("a" * 32),
    '{"v": 1, "op": "input", "rid": "1", "text": "x"}',
    '{"v": 1, "op": "input", "rid": "%s", "text": ["x", "y"]}' % ("a" * 32),
    '{"v": 1, "op": "input", "rid": "%s"}' % ("a" * 32),
    '{"v": 1, "op": "open", "rid": "%s", "handle": "a b"}' % ("a" * 32),
    '{"v": 1, "op": "open", "rid": "%s", "handle": "alice", "origin": "x"}' % ("a" * 32),
    '{"v": 1, "op": "open", "rid": "%s", "handle": "alice", "session_id": 1}' % ("a" * 32),
    '{"v": 1, "op": "output", "rid": "%s", "text": "%s"}' % ("a" * 32, "x" * 5000),
])
def test_malformed_payloads_rejected(payload):
    msg, err = parse_relay_payload(payload)
    assert msg is None and err


def test_legacy_relay_verbs_denied(tmp_path):
    async def go():
        net = await build(tmp_path)
        beta = net.bots["beta"]
        for line in ("RELAY_OPEN alice alpha 1", "RELAY_INPUT alpha 1 .whoami",
                     "RELAY_CLOSE alpha 1", "RELAY_OUTPUT 0 pwned"):
            await net.inject("eps", "beta", line)
        assert inbound(net) == {}
        assert all(s["type"] != "relay" for s in beta.partyline.sessions.values())
        assert not hasattr(beta.partyline, "dispatch_command")
    run(go())


def test_unauthenticated_connection_cannot_relay(tmp_path):
    async def go():
        net = await build(tmp_path)
        stray = FakeWriter()
        await net.bots["beta"].botnet.process_incoming("alpha", "RELAY " + json.dumps(
            {"v": 1, "op": "open", "rid": new_relay_id(), "handle": "alice"}), None, stray)
        assert inbound(net) == {}
        assert stray.sent == []
    run(go())


def test_output_is_single_line_and_bounded(tmp_path):
    async def go():
        net = await build(tmp_path)
        sid, q, _ = await open_relay(net)
        drain(q)
        irel = next(iter(inbound(net).values()))
        net.bots["beta"].partyline.send_to_session(irel.vsid, "a\r\nRELAY_OUTPUT 0 x" + "y" * 5000)
        delivered = await net.pump()
        msgs = relay_msgs(delivered, "beta", "alpha")
        assert len(msgs) == 1 and "\n" not in msgs[0]["text"]
        assert len(msgs[0]["text"]) <= relay_mod.MAX_TEXT
        assert len(drain(q)) == 1
    run(go())
