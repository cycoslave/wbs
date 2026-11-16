"""
Regression tests for NET-3 / prior D17: subnet op-segregation.

Operator rule: bots of one subnet never op/deop/voice/mode bots of another
subnet.  The botnet-received path already denied it
(BotnetManager.authorize_peer_command); the local `.op/.deop/.voice/
.devoice/.mode`, `.net op|deop|mode` (which also executes locally), `.mass`
and the pubcom `!op/!mode` paths did not.  All of them now use one rule
(subnet.bot_target_scope via helper.is_same_subnet_bot):

  * a bot whose stored scope includes the local subnet: allowed
  * a bot of another subnet, or of unknown scope (no stored subnet): refused
  * a nick that is not a known bot (a human): unaffected

This bot (BOT in the helpers) is subnet 1.  Bots table: nwA2 subnet 1,
nwB1 / nwB2 subnet 2, nwX no subnet (unknown scope).
"""
import asyncio
import logging
from types import SimpleNamespace as NS

import pytest

from src.commands import (cmd_deop, cmd_devoice, cmd_mass, cmd_mode, cmd_net, cmd_op,
                          cmd_voice)
from src.db import get_db
from src.helper import is_same_subnet_bot
from src.plugins.pubcom import pubcomPlugin

from test_automode import env, flush, join_synced  # noqa: F401  (fixture)
from test_irc_channel_sync import BOT, run_cmd

BOTS = {"nwA2": 1, "nwB1": 2, "nwB2": 2, "nwX": None}


def add_bots(core):
    async def go():
        async with get_db(core.db_path) as d:
            await d.execute("INSERT OR IGNORE INTO subnets(id, name) VALUES (2, 'two')")
            for handle, sid in BOTS.items():
                await d.execute(
                    "INSERT INTO bots(handle, address, port, subnet_id) "
                    "VALUES (?, '192.0.2.1', 3333, ?)", (handle, sid))
            await d.commit()
    asyncio.run(go())


class FakeBotnet:
    """Linked peers (live scope as loaded from our DB) + the .net broadcast."""

    def __init__(self, peers=None):
        self.peers = peers or {}
        self.broadcasts: list[tuple] = []

    async def broadcast_subnet(self, command, args=""):
        self.broadcasts.append((command, args))


@pytest.fixture
def net(env):  # noqa: F811
    core, irc, sent = env
    add_bots(core)
    core.botnet = FakeBotnet()
    return core, irc, sent


REFUSED = "is a bot outside this bot's subnet"


# ---------------------------------------------------------------------------
# the shared rule
# ---------------------------------------------------------------------------
def test_is_same_subnet_bot(net):
    core, _, _ = net
    res = {n: asyncio.run(is_same_subnet_bot(core, n))
           for n in ("nwA2", "NWA2", "nwB1", "nwX", BOT, "somehuman", "")}
    assert res == {"nwA2": True, "NWA2": True, "nwB1": False, "nwX": False,
                   BOT: True, "somehuman": None, "": False}


def test_live_link_scope_counts_by_irc_nick(net):
    """A linked peer whose IRC nick differs from its handle is matched by nick,
    with the scope loaded for the link (subnet_ids), not its handle row."""
    core, _, _ = net
    core.botnet.peers = {
        "nwb1": NS(name="nwb1", nick="Bee1", subnet_ids=frozenset({2})),
        "nwa2": NS(name="nwa2", nick="Ay2", subnet_ids=frozenset({1})),
        "ghost": NS(name="ghost", nick="Gho", subnet_ids=frozenset()),
    }
    assert asyncio.run(is_same_subnet_bot(core, "Bee1")) is False
    assert asyncio.run(is_same_subnet_bot(core, "ay2")) is True
    assert asyncio.run(is_same_subnet_bot(core, "Gho")) is False


# ---------------------------------------------------------------------------
# .op / .deop / .voice / .devoice / .mode
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("func", [cmd_op, cmd_deop, cmd_voice, cmd_devoice])
@pytest.mark.parametrize("target", ["nwB1", "nwX"])
def test_chan_mode_cmd_refuses_cross_and_unknown_subnet_bot(net, caplog, func, target):
    core, irc, sent = net
    with caplog.at_level(logging.WARNING, logger="wbs.helper"):
        out = run_cmd(core, func, f"{target} #wbs")
    assert len(out) == 1 and REFUSED in out[0] and target in out[0], out
    assert flush(core, irc, sent) == []
    assert any("outside the local subnet" in r.getMessage() and target in r.getMessage()
               for r in caplog.records)


def test_op_same_subnet_bot_and_human_still_work(net):
    core, irc, sent = net
    for target in ("nwA2", "somehuman"):
        assert run_cmd(core, cmd_op, f"{target} #wbs") == []
        assert flush(core, irc, sent) == [f"MODE #wbs +o {target}"]


@pytest.mark.parametrize("modes", ["+o nwB1", "+v-o nwA2 nwB2", "-o+o somehuman nwX"])
def test_mode_refuses_any_cross_subnet_bot_target(net, modes):
    core, irc, sent = net
    out = run_cmd(core, cmd_mode, f"#wbs {modes}")
    assert len(out) == 1 and REFUSED in out[0], out
    assert flush(core, irc, sent) == []


def test_mode_same_subnet_and_humans_unaffected(net):
    core, irc, sent = net
    assert run_cmd(core, cmd_mode, "#wbs +ov nwA2 somehuman") == []
    assert flush(core, irc, sent) == ["MODE #wbs +ov nwA2 somehuman"]
    assert run_cmd(core, cmd_mode, "#wbs +m") == []
    assert flush(core, irc, sent) == ["MODE #wbs +m"]


# ---------------------------------------------------------------------------
# .net op|deop|mode: refused before anything is sent or run locally
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("line", ["op nwB2 #wbs", "deop nwB1 #wbs", "op nwX #wbs",
                                  "mode #wbs +o nwB2"])
def test_net_refuses_cross_subnet_target_locally(net, line):
    core, irc, sent = net
    out = run_cmd(core, cmd_net, line)
    assert len(out) == 1 and REFUSED in out[0], out
    assert core.botnet.broadcasts == []
    assert flush(core, irc, sent) == []


def test_net_op_same_subnet_bot_and_human(net):
    core, irc, sent = net
    core.botnet.peers = {"nwa2": NS(name="nwa2", nick="nwA2", subnet_ids=frozenset({1}))}
    for target in ("nwA2", "somehuman"):
        core.botnet.broadcasts.clear()
        run_cmd(core, cmd_net, f"op {target} #wbs")
        assert core.botnet.broadcasts == [("op", f"{target} #wbs")]
        assert flush(core, irc, sent) == [f"MODE #wbs +o {target}"]


# ---------------------------------------------------------------------------
# .mass op: cross-subnet bots in the channel are skipped
# ---------------------------------------------------------------------------
def test_mass_op_skips_cross_subnet_bots(net):
    core, irc, sent = net
    join_synced(core, irc, sent, present="nwA2!~a@a.example nwB1!~b@b.example "
                                          "nwX!~x@x.example human!~h@h.example")
    out = run_cmd(core, cmd_mass, "op #wbs")
    assert any("Skipped" in l and "nwb1" in l.lower() and "nwx" in l.lower() for l in out), out
    lines = flush(core, irc, sent)
    assert len(lines) == 1 and lines[0].startswith("MODE #wbs +oo")
    assert sorted(lines[0].split()[3:]) == ["human", "nwa2"]


# ---------------------------------------------------------------------------
# pubcom !op / !mode
# ---------------------------------------------------------------------------
def test_pubcom_op_and_mode_refuse_cross_subnet_bot(net):
    core, _, _ = net
    plugin = pubcomPlugin(core)
    sent_irc: list[dict] = []
    core.send_irc = sent_irc.append

    async def go():
        await plugin._priv_user_mode("own", "own", "#wbs", "nwB1", "+o")
        await plugin.priv_mode("own", "own", "#wbs", "+o nwX")
        await plugin._priv_user_mode("own", "own", "#wbs", "nwA2", "+o")
        await plugin.priv_mode("own", "own", "#wbs", "+v somehuman")
    asyncio.run(go())
    modes = [p for p in sent_irc if p.get("cmd") == "mode"]
    notices = [p["text"] for p in sent_irc if p.get("cmd") == "notice"]
    assert modes == [{"cmd": "mode", "channel": "#wbs", "modes": "+o nwA2"},
                     {"cmd": "mode", "channel": "#wbs", "modes": "+v somehuman"}]
    assert any("nwB1" in n and "outside my subnet" in n for n in notices), notices
    assert any("nwX" in n and "outside my subnet" in n for n in notices), notices
