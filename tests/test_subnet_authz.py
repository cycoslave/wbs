"""
Offline regression tests for SAST-002: same-subnet peer ops and command authorization.

Operator rule: bots of different subnets may share an IRC server and may link,
but channel ops, modes and botnet commands only flow between same-subnet bots.

Topology (local bot "beta", local subnet 1), every peer linked over a real
AUTH2 handshake on in-memory fake writers:

    alpha   stored subnet 1       same subnet
    eps     stored subnet 1       same subnet (second one, for relay checks)
    gamma   stored subnet 2       cross subnet
    delta   no stored subnet      unknown scope

Every peer's hello carries its own local subnet id (NET-7: delta's says 3,
gamma's 2): a peer-asserted token that must never become its scope (a forged
claim of the local subnet is covered in tests/test_subnet_management.py).
Each DB is a throwaway sqlite file under pytest's tmp_path; no network, no IRC.
"""
import asyncio
import os
import shutil
import tempfile
import uuid
from types import SimpleNamespace as NS
from unittest.mock import patch

import pytest

from src import botnet as botnet_mod
from src import commands
from src.botnet import BotnetManager
from src.db import get_db, init_db
from src.plugins.netop import netopPlugin

PSK = "test-only-link-key-0123456789"
LOCAL = "beta"
SAME, SAME2, CROSS, UNKNOWN = "alpha", "eps", "gamma", "delta"
PEER_SUBNETS = {SAME: 1, SAME2: 1, CROSS: 2, UNKNOWN: None}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
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


async def _fresh_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-sast002-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


async def make_mgr(tmp_path, nick: str, local_subnet: int, peers: dict[str, int | None]):
    """BotnetManager for `nick` whose DB stores each peer's authoritative subnet."""
    db = str(tmp_path / f"{nick}.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        for handle, sid in peers.items():
            await d.execute(
                "INSERT INTO bots(handle, password, address, port, subnet_id) "
                "VALUES (?, ?, '192.0.2.1', 3333, ?)",
                (handle, PSK, sid),
            )
        await d.commit()
    sent_irc: list[dict] = []
    shutdowns: list[str] = []

    async def shutdown(reason=""):
        shutdowns.append(reason)

    core = NS(
        db_path=db,
        config={"bot": {"nick": nick}, "botnet": {"subnet_id": local_subnet},
                "settings": {"ssl": False}},
        bot_sessions={},
        send_irc=sent_irc.append,
        partyline=NS(broadcast=lambda *a, **k: None),
        botname=nick,
        shutdown=shutdown,
        bot_isop=lambda chan: True,
        nick_isop=lambda nick, chan: False,
        channels={},
    )
    mgr = BotnetManager(core)
    core.botnet = mgr
    mgr.share_all_data = _nop
    mgr.broadcast_topology = _nop
    mgr._register_net_handlers()
    await mgr.subnet.load()
    mgr.sent_irc = sent_irc
    mgr.shutdowns = shutdowns
    return mgr


async def link(initiator: BotnetManager, responder: BotnetManager):
    """Full AUTH2 handshake initiator -> responder. Returns (init_w, resp_w)."""
    i_w = FakeWriter()

    async def fake_open(*args, **kwargs):
        return None, i_w

    with patch.object(botnet_mod.asyncio, "open_connection", fake_open), \
            patch.object(initiator, "read_peer", _nop):
        await initiator.connect_peer(responder.my_handle)
    r_w = FakeWriter()
    i, r = initiator.my_handle, responder.my_handle
    await responder.process_incoming(i, i_w.take()[0], None, r_w)
    await initiator.process_incoming(r, r_w.take()[0], None, i_w)
    await responder.process_incoming(i, i_w.take()[0], None, r_w)
    await initiator.process_incoming(r, r_w.take()[0], None, i_w)
    assert responder.peers[i].authed and initiator.peers[r].authed
    return i_w, r_w


async def build(tmp_path):
    """Local bot beta (subnet 1) linked to alpha, eps (1), gamma (2), delta (unknown)."""
    beta = await make_mgr(tmp_path, LOCAL, 1, PEER_SUBNETS)
    net = NS(beta=beta, peer={}, w={})
    for handle, sid in PEER_SUBNETS.items():
        peer = await make_mgr(tmp_path, handle, sid or 3, {LOCAL: 1})
        _, beta_w = await link(peer, beta)      # each hello carries the peer's own subnet
        net.peer[handle] = peer
        net.w[handle] = beta_w
    net.plugin = netopPlugin(beta.core)
    return net


def run(coro):
    return asyncio.run(coro)


async def send(net, frm: str, line: str) -> None:
    await net.beta.process_incoming(frm, line, None, net.w[frm])


def effects(net) -> list:
    return list(net.beta.sent_irc) + [("shutdown", r) for r in net.beta.shutdowns]


def reset(net) -> None:
    net.beta.sent_irc.clear()
    net.beta.shutdowns.clear()
    for w in net.w.values():
        w.take()
    net.plugin.reqop.clear()
    net.plugin.sugop.clear()


def rid() -> str:
    return str(uuid.uuid4())


# Privileged commands and the IRC effect a same-subnet request must produce.
PRIV = [
    ("op victim #chan",       {"cmd": "mode", "channel": "#chan", "modes": "+o victim"}),
    ("deop victim #chan",     {"cmd": "mode", "channel": "#chan", "modes": "-o victim"}),
    ("mode #chan +o victim",  {"cmd": "mode", "channel": "#chan", "modes": "+o victim"}),
    ("join #chan",            {"cmd": "join", "channel": "#chan"}),
    ("part #chan",            {"cmd": "part", "channel": "#chan", "reason": ""}),
    ("say #chan hi",          {"cmd": "msg", "target": "#chan", "text": "hi"}),
    ("die bye",               {"cmd": "quit", "message": "bye"}),
    ("restart",               ("shutdown", "Restart via botnet")),
]
DENIED = [CROSS, UNKNOWN]


# ---------------------------------------------------------------------------
# authoritative scope
# ---------------------------------------------------------------------------
def test_peer_scope_comes_from_stored_db_not_local_default_or_hello(tmp_path):
    async def main():
        net = await build(tmp_path)
        b = net.beta
        assert b.peers[SAME].subnet_ids == frozenset({1}) and b.peers[SAME].subnet_id == 1
        # gamma's hello now carries its real subnet (2, NET-7) and delta's its
        # local 3; neither token becomes scope: only stored rows do.
        assert b.peers[CROSS].subnet_field == "2"
        assert b.peers[UNKNOWN].subnet_field == "3"
        assert b.peers[CROSS].subnet_ids == frozenset({2}) and b.peers[CROSS].subnet_id == 2
        assert b.peers[UNKNOWN].subnet_ids == frozenset() and b.peers[UNKNOWN].subnet_id is None
        assert b.subnet.subnet_of_peer(CROSS) == 2 and b.subnet.subnet_of_peer(UNKNOWN) is None
        assert b.same_subnet_peer(SAME) and not b.same_subnet_peer(CROSS)
        assert not b.same_subnet_peer(UNKNOWN)
        assert set(b.same_subnet_bot_nicks()) == {SAME, SAME2}
        # outbound links load stored scope too (peer side: beta is stored as subnet 1)
        gamma = net.peer[CROSS]
        assert gamma.peers[LOCAL].subnet_ids == frozenset({1})
        assert not gamma.same_subnet_peer(LOCAL)          # gamma is subnet 2
        # bot_subnets bindings extend a stored scope
        await b.bot.bind_to_subnet(CROSS, 1)
        await b.refresh_peer_scope(CROSS)
        assert b.peers[CROSS].subnet_ids == frozenset({1, 2}) and b.same_subnet_peer(CROSS)

    run(main())


# ---------------------------------------------------------------------------
# direct CMD path
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("line,effect", PRIV, ids=[p[0].split()[0] for p in PRIV])
def test_direct_cmd_matrix(tmp_path, line, effect):
    async def main():
        net = await build(tmp_path)
        for frm in DENIED:
            reset(net)
            await send(net, frm, f"CMD {line}")
            assert effects(net) == [], f"{frm}: {line}"
        reset(net)
        await send(net, SAME, f"CMD {line}")
        assert effects(net) == [effect]

    run(main())


# ---------------------------------------------------------------------------
# routed CMD_ROUTE path
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("line,effect", PRIV, ids=[p[0].split()[0] for p in PRIV])
def test_routed_cmd_matrix(tmp_path, line, effect):
    async def main():
        net = await build(tmp_path)
        for frm in DENIED:
            for routed in (
                f"CMD_ROUTE broadcast {rid()} {frm} - {line}",
                f"CMD_ROUTE unicast {rid()} {frm} {LOCAL} {line}",
                # claims our subnet 1 in the routing field; must not matter
                f"CMD_ROUTE subnet {rid()} {frm} - 1 {line}",
            ):
                reset(net)
                await send(net, frm, routed)
                assert effects(net) == [], routed
        for routed in (
            f"CMD_ROUTE broadcast {rid()} {SAME} - {line}",
            f"CMD_ROUTE unicast {rid()} {SAME} {LOCAL} {line}",
            f"CMD_ROUTE subnet {rid()} {SAME} - 1 {line}",
        ):
            reset(net)
            await send(net, SAME, routed)
            assert effects(net) == [effect], routed

    run(main())


def test_routed_forged_origin_and_relay_scope(tmp_path):
    async def main():
        net = await build(tmp_path)
        # a same-subnet hop relaying a command that originated on another subnet
        for origin in (CROSS, UNKNOWN, LOCAL):
            reset(net)
            await send(net, SAME, f"CMD_ROUTE broadcast {rid()} {origin} - op victim #chan")
            assert effects(net) == [], origin

        # cross-subnet broadcast is neither executed nor relayed to anyone
        reset(net)
        await send(net, CROSS, f"CMD_ROUTE broadcast {rid()} {CROSS} - op victim #chan")
        assert effects(net) == []
        assert all(w.sent == [] for w in net.w.values())

        # cross-subnet unicast to another bot is not relayed either
        reset(net)
        await send(net, CROSS, f"CMD_ROUTE unicast {rid()} {CROSS} {SAME} restart")
        assert all(w.sent == [] for w in net.w.values())

        # cross-subnet "subnet 1" route is not relayed into subnet 1
        reset(net)
        await send(net, CROSS, f"CMD_ROUTE subnet {rid()} {CROSS} - 1 restart")
        assert all(w.sent == [] for w in net.w.values())

        # same-subnet broadcast is relayed only to same-subnet peers
        reset(net)
        line = f"CMD_ROUTE broadcast {rid()} {SAME} - op victim #chan"
        await send(net, SAME, line)
        assert net.w[SAME2].sent == [line]
        assert net.w[CROSS].sent == [] and net.w[UNKNOWN].sent == [] and net.w[SAME].sent == []

        # invalid subnet id in a subnet route is dropped, not defaulted to 1
        reset(net)
        await send(net, SAME, f"CMD_ROUTE subnet {rid()} {SAME} - x op victim #chan")
        assert effects(net) == [] and all(w.sent == [] for w in net.w.values())

    run(main())


def test_outbound_subnet_route_only_reaches_same_subnet_peers(tmp_path):
    async def main():
        net = await build(tmp_path)
        reset(net)
        await net.beta.broadcast_subnet("op", "victim #chan")
        assert len(net.w[SAME].sent) == 1 and len(net.w[SAME2].sent) == 1
        assert net.w[CROSS].sent == [] and net.w[UNKNOWN].sent == []

    run(main())


# ---------------------------------------------------------------------------
# target authorization
# ---------------------------------------------------------------------------
def test_same_subnet_sender_cannot_target_cross_subnet_bot_or_channel(tmp_path):
    async def main():
        net = await build(tmp_path)
        b = net.beta
        await b.chan.addchan("#two", subnet_id=2)
        await b.chan.addchan("#one", subnet_id=1)
        for line in (
            f"CMD op {CROSS} #chan",             # op a cross-subnet bot
            f"CMD op {UNKNOWN} #chan",           # op an unknown-scope bot
            f"CMD mode #chan +o {CROSS}",
            f"CMD deop {SAME2} #two",            # channel bound to another subnet
            "CMD op victim #two",
            "CMD join #two",
            "CMD say #two hi",
            f"CMD reqop {CROSS} #chan",          # netop on behalf of a cross-subnet bot
            f"CMD reqop {SAME} #two",
        ):
            reset(net)
            await send(net, SAME, line)
            assert effects(net) == [], line
        for line, eff in (
            (f"CMD op {SAME2} #one", {"cmd": "mode", "channel": "#one", "modes": f"+o {SAME2}"}),
            ("CMD op victim #chan", {"cmd": "mode", "channel": "#chan", "modes": "+o victim"}),
        ):
            reset(net)
            await send(net, SAME, line)
            assert effects(net) == [eff], line

    run(main())


# ---------------------------------------------------------------------------
# automatic netop path
# ---------------------------------------------------------------------------
def test_netop_reqop_matrix(tmp_path):
    async def main():
        net = await build(tmp_path)
        b = net.beta
        b.register("netop", "reqop", net.plugin.on_reqop)
        b.register("netop", "sugop", net.plugin.on_sugop)

        # wire path: CMD reqop <self> #chan
        for frm in DENIED:
            reset(net)
            await send(net, frm, f"CMD reqop {frm} #chan")
            assert effects(net) == [], frm
            reset(net)
            await send(net, frm, f"CMD_ROUTE subnet {rid()} {frm} - 1 reqop {frm} #chan")
            assert effects(net) == [], frm
        # same-subnet sender asking ops for a cross/unknown bot
        for target in DENIED:
            reset(net)
            await send(net, SAME, f"CMD reqop {target} #chan")
            assert effects(net) == [], target
        # plugin-level check too, bypassing the botnet gate
        for frm, target in ((CROSS, CROSS), (UNKNOWN, UNKNOWN), (SAME, CROSS), (CROSS, SAME)):
            reset(net)
            await net.plugin.on_reqop(None, [target, "#chan"], frm)
            assert effects(net) == [], (frm, target)

        reset(net)
        await send(net, SAME, f"CMD reqop {SAME} #chan")
        assert effects(net) == [{"cmd": "mode", "channel": "#chan", "modes": f"+o {SAME}"}]
        reset(net)
        await send(net, SAME2, f"CMD_ROUTE subnet {rid()} {SAME2} - 1 reqop {SAME2} #chan")
        assert effects(net) == [{"cmd": "mode", "channel": "#chan", "modes": f"+o {SAME2}"}]

    run(main())


def test_netop_automatic_requests_stay_in_subnet(tmp_path):
    async def main():
        net = await build(tmp_path)
        b, p = net.beta, net.plugin
        b.register("netop", "sugop", p.on_sugop)

        # sugop from a cross/unknown peer: we never ask it for ops, even when opless
        b.core.bot_isop = lambda chan: False
        for frm in DENIED:
            reset(net)
            await send(net, frm, f"CMD sugop {LOCAL} #chan")
            await p.on_sugop(None, [LOCAL, "#chan"], frm)
            assert all(w.sent == [] for w in net.w.values()), frm
        # sugop from a same-subnet peer: reqop goes back to it only
        reset(net)
        await send(net, SAME, f"CMD sugop {LOCAL} #chan")
        assert net.w[SAME].sent == [f"CMD reqop {LOCAL} #chan"]
        assert net.w[CROSS].sent == [] and net.w[UNKNOWN].sent == []

        # deopped with no opped peer: broadcast reqop reaches same-subnet peers only
        reset(net)
        await p.on_MODE({"channel": "#chan", "modes": "-o", "args": [LOCAL]})
        assert len(net.w[SAME].sent) == 1 and len(net.w[SAME2].sent) == 1
        assert net.w[CROSS].sent == [] and net.w[UNKNOWN].sent == []
        assert "reqop" in net.w[SAME].sent[0]

        # a cross-subnet bot that holds ops is never asked
        b.core.nick_isop = lambda nick, chan: nick == CROSS
        reset(net)
        await p.on_MODE({"channel": "#chan", "modes": "-o", "args": [LOCAL]})
        assert net.w[CROSS].sent == []
        # explicit send to a cross-subnet bot is refused
        reset(net)
        await p.msg_to_bot(CROSS, f"reqop {LOCAL} #chan")
        assert net.w[CROSS].sent == []

        # a cross-subnet bot getting opped / joining does not trigger requests or sugop
        reset(net)
        await p.on_MODE({"channel": "#chan", "modes": "+o", "args": [CROSS]})
        await p.on_JOIN({"channel": "#chan", "nick": CROSS})
        await p.on_JOIN({"channel": "#chan", "nick": UNKNOWN})
        assert all(w.sent == [] for w in net.w.values())
        # same-subnet bot joining: sugop goes to same-subnet peers only
        reset(net)
        await p.on_JOIN({"channel": "#chan", "nick": SAME})
        assert net.w[SAME].sent and net.w[SAME2].sent
        assert net.w[CROSS].sent == [] and net.w[UNKNOWN].sent == []

        # timer-driven reqop stays in subnet
        reset(net)
        await p.on_IRC_TIMER_NETOP({"irc_data": {"connected": True,
                                                  "channels": {"#chan": {"bot_op": False}}}})
        assert net.w[SAME].sent and net.w[CROSS].sent == [] and net.w[UNKNOWN].sent == []

    run(main())


# ---------------------------------------------------------------------------
# REQUEST_* path
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("req", ["REQUEST_INVITE", "REQUEST_UNBAN", "REQUEST_LIMIT_RAISE"])
def test_request_matrix(tmp_path, req):
    async def main():
        net = await build(tmp_path)
        for frm in DENIED:
            reset(net)
            await send(net, frm, f"{req} #chan {frm}")
            assert effects(net) == [], frm
        # same-subnet sender on behalf of a cross-subnet bot
        if req != "REQUEST_LIMIT_RAISE":
            reset(net)
            await send(net, SAME, f"{req} #chan {CROSS}")
            assert effects(net) == []
        reset(net)
        await send(net, SAME, f"{req} #chan {SAME}")
        assert len(effects(net)) == 1

    run(main())


# ---------------------------------------------------------------------------
# operator provisioning of scope
# ---------------------------------------------------------------------------
def test_botattr_subnet_sets_scope_and_is_not_replicated(tmp_path):
    async def main():
        net = await build(tmp_path)
        b = net.beta
        out: list[str] = []

        async def respond(msg):
            out.append(msg)

        synced: list[dict] = []

        async def sync_bot_access(data):
            synced.append(data)

        b.sync_bot_access = sync_bot_access
        core = b.core

        reset(net)
        await send(net, UNKNOWN, "CMD op victim #chan")
        assert effects(net) == []

        await commands.cmd_botattr(core, "owner", 1, f"{UNKNOWN} subnet=one", respond)
        await asyncio.sleep(0)
        assert b.peers[UNKNOWN].subnet_ids == frozenset({1})
        reset(net)
        await send(net, UNKNOWN, "CMD op victim #chan")
        assert effects(net) == [{"cmd": "mode", "channel": "#chan", "modes": "+o victim"}]
        assert all("subnet_id" not in d.get("flags", {}) for d in synced)

        await commands.cmd_botattr(core, "owner", 1, f"{UNKNOWN} subnet=2", respond)
        reset(net)
        await send(net, UNKNOWN, "CMD op victim #chan")
        assert effects(net) == []

        await commands.cmd_botattr(core, "owner", 1, f"{UNKNOWN} subnet=nosuch", respond)
        assert out[-1].startswith("Unknown subnet")

        await commands.cmd_botattr(core, "owner", 1, f"{UNKNOWN} subnet=none", respond)
        assert b.peers[UNKNOWN].subnet_ids == frozenset()

        # peer replication cannot change a stored subnet scope
        await b.bot.merge_from_peer(
            [{"handle": CROSS, "subnet_id": 1, "updated_at": 2**31}], SAME)
        assert await b.bot.get_subnet_scope(CROSS) == frozenset({2})

    run(main())
