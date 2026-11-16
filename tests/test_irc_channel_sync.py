"""
Regression tests for IRC-1 / IRC-2: live channel state, `.channels`, `.mass`.

IRC-1: on the bot's own JOIN the IRC process emitted NEWCHAN with a 1-user
snapshot and never asked for WHO/MODE (Core only did that for OTHER users'
JOINs), the numeric handlers were registered under names the library never
fires and indexed one argument too far.  `.chaninfo` showed
"Synced no, Users 1, Ops 0, Bot status none" after join and reconnect.

IRC-2: `.channels` and `.mass` read `core.irc_snapshot`, which never
existed (AttributeError).

The IRC side runs the real WbsIrcBot reactor on raw server lines (no
socket); every event it emits goes through the real Core.handle_event and
the commands read Core's state.  Throwaway sqlite DB per test.
"""
import asyncio
import os
import queue
import shutil
import tempfile
import time

import pytest

from src.channel import ChannelManager
from src.commands import cmd_channels, cmd_chaninfo, cmd_mass
from src.core import Core
from src.db import get_db, init_db
from src.irc import WbsIrcBot
from src.partyline import Partyline
from src.plugins import PluginManager
from src.user import UserManager

BOT = "wI1"
SRV = ":irc.example.net"
_TEMPLATE_DB: str | None = None


async def build_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-irc1-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)
    async with get_db(path) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one')")
        for name in ("#wbs", "#other"):
            await d.execute("INSERT INTO channels(name) VALUES (?)", (name,))
            await d.execute("INSERT INTO channel_subnets(channel_name, subnet_id) "
                            "VALUES (?, 1)", (name,))
        users = {
            "boss": ('["*!*boss@boss.example"]', {"has_partyline", "is_owner", "is_admin"}),
            "opper": ('["*!*op@op.example"]', {"has_partyline", "is_op"}),
            "plain": ('["*!*pl@plain.example"]', {"has_partyline"}),
        }
        for handle, (masks, cols) in users.items():
            await d.execute("INSERT INTO users(handle, hostmasks) VALUES (?, ?)", (handle, masks))
            names = ["handle", "channel", "subnet_id", *sorted(cols)]
            vals = [handle, None, 1, *([1] * len(cols))]
            await d.execute(
                f"INSERT INTO user_access ({', '.join(names)}) "
                f"VALUES ({', '.join('?' * len(names))})", vals)


class FakeIrcQ:
    def __init__(self):
        self.items: list[dict] = []

    def put_nowait(self, payload):
        self.items.append(payload)


class FakeDcc:
    def reset(self, reason):
        pass

    def forget_nick(self, nick):
        pass


def make_core(db: str) -> Core:
    core = object.__new__(Core)
    core.config = {"bot": {"nick": BOT}, "botnet": {"subnet_id": 1}, "db": {"path": db}}
    core.db_path = db
    core.botname = BOT
    core.irc_q = FakeIrcQ()
    core.core_q = None
    core.start_time = time.time()
    core.connected = False
    core.connected_on = None
    core.dcc = FakeDcc()
    core.botnet = None
    core.channels = {}
    core.user = UserManager(db)
    core.chan = ChannelManager(db)
    core.partyline = Partyline(core)
    core.plugin = PluginManager(core)

    async def no_games():
        return None
    core._autoload_games = no_games
    core._create_safe_task = lambda coro, **kw: coro.close()
    core.handlers = {
        "NEWCHAN": core.on_newchan, "JOIN": core.on_join, "PART": core.on_part,
        "KICK": core.on_kick, "QUIT": core.on_quit, "MODE": core.on_mode,
        "NICK": core.on_nick, "WHO_REPLY": core.on_who_reply,
        "WHO_END": core.on_who_end, "NAMES_REPLY": core.on_names_reply,
        "NAMES_END": core.on_names_end, "IRC_STATE": core.on_irc_state,
        "READY": core.on_ready, "DISCONNECT": core.on_disconnect,
        "CHANNEL_TOPIC": core.on_332, "CHANNEL_TOPIC_META": core.on_333,
        "CHANNEL_MODES": core.on_324, "CHANNEL_CREATED": core.on_329,
        "BANLIST_ADD": core.on_367, "BANLIST_END": core.on_null,
        "IRC_NUMERIC": core.on_irc_numeric, "WHOIS_NUMERIC": core.on_whois_numeric,
    }
    return core


def make_irc(db: str):
    config = {"bot": {"nick": BOT, "servers": [{"host": "irc.example", "port": 6667}]},
              "botnet": {"subnet_id": 1}, "db": {"path": db}, "id": 1}
    bot = WbsIrcBot(config, queue.Queue(), queue.Queue())
    bot.core_q.get_nowait()          # REQUEST_BOTLINKS from __init__
    bot.connection.real_server_name = "irc.example.net"
    bot.connection.real_nickname = BOT
    bot.connection.handlers = {}
    bot.connection.connected = True
    sent: list[str] = []
    bot.connection.send_raw = sent.append
    return bot, sent


@pytest.fixture
def env(tmp_path):
    db = str(tmp_path / "wbs.db")
    asyncio.run(build_db(db))
    irc, sent = make_irc(db)
    return make_core(db), irc, sent


def pump(core, irc, *lines):
    """Feed raw server lines through the IRC reactor; hand every emitted
    event to Core."""
    events = []
    for line in ("",) + lines:
        if line:
            irc.connection._process_line(line)
        while True:
            try:
                events.append(irc.core_q.get_nowait())
            except queue.Empty:
                break

    async def go():
        for ev in events:
            await core.handle_event(ev)
    asyncio.run(go())
    return [e.get("type") for e in events]


def run_cmd(core, func, arg, handle="boss"):
    out: list[str] = []

    async def respond(msg):
        out.append(msg)
    asyncio.run(func(core, handle, 1, arg, respond))
    return out


def chaninfo(core, chan="#wbs") -> dict:
    out = "\n".join(run_cmd(core, cmd_chaninfo, chan)).splitlines()
    live = {}
    if "  --- Live IRC State ---" in out:
        for line in out[out.index("  --- Live IRC State ---") + 1:]:
            key, _, val = line.strip().partition(":")
            live[key.strip()] = val.strip()
    return live


# A server's answer to our JOIN #wbs (NAMES is automatic) and the WHO/MODE
# the bot asks for.  Prefixes: ~owner, @op, %half, +voice, plus multi-prefix.
JOIN_BURST = [
    f":{BOT}!~wbs@bot.example JOIN #wbs",
    f"{SRV} 332 {BOT} #wbs :welcome to wbs",
    f"{SRV} 333 {BOT} #wbs setter!u@h 1700000000",
    f"{SRV} 353 {BOT} = #wbs :{BOT} ~own @op %half +vo @+both plain1 plain2",
    f"{SRV} 366 {BOT} #wbs :End of /NAMES list.",
]
WHO_BURST = [
    f"{SRV} 352 {BOT} #wbs ~wbs bot.example irc.example.net {BOT} H :0 bot",
    f"{SRV} 352 {BOT} #wbs ~own own.example irc.example.net own H~@ :0 o",
    f"{SRV} 352 {BOT} #wbs ~op op.example irc.example.net op H@ :0 o",
    f"{SRV} 352 {BOT} #wbs ~h h.example irc.example.net half G% :0 h",
    f"{SRV} 352 {BOT} #wbs ~v v.example irc.example.net vo H+ :0 v",
    f"{SRV} 352 {BOT} #wbs ~b b.example irc.example.net both H@+ :0 b",
    f"{SRV} 352 {BOT} #wbs ~p1 p.example irc.example.net plain1 H :0 p",
    f"{SRV} 352 {BOT} #wbs ~p2 p.example irc.example.net plain2 H :0 p",
    f"{SRV} 315 {BOT} #wbs :End of /WHO list.",
    f"{SRV} 324 {BOT} #wbs +ntl 50",
    f"{SRV} 329 {BOT} #wbs 1600000000",
]


def own_join(core, irc, sent, opped=True):
    sent.clear()
    types = pump(core, irc, *JOIN_BURST)
    assert "NEWCHAN" in types
    # IRC-1: the bot's own JOIN asks for WHO and MODE (NAMES comes by itself).
    assert f"WHO #wbs" in sent and f"MODE #wbs" in sent, sent
    pump(core, irc, *WHO_BURST)
    if opped:
        pump(core, irc, f":op!~op@op.example MODE #wbs +o {BOT}")


def test_own_join_syncs_chaninfo(env):
    core, irc, sent = env
    core.connected = True
    own_join(core, irc, sent, opped=False)
    live = chaninfo(core)
    assert live["Synced"] == "yes", live
    assert live["Users"] == "8", live
    assert live["Ops"] == "3", live          # ~own (op level), @op, @+both
    assert live["Voiced"] == "2", live
    assert live["Bot status"] == "none", live
    assert live["Modes"] == "+ntl:50", live
    assert live["Topic"] == "welcome to wbs", live

    pump(core, irc, f":op!~op@op.example MODE #wbs +o {BOT}")
    assert chaninfo(core)["Bot status"] == "op"
    chan = core.get_chan("#wbs")
    assert chan.prefixes["half"] == "h" and "half" in chan.halfops
    assert chan.prefixes["own"] == "qo"
    assert chan.hosts["plain1"] == "~p1@p.example"


def test_state_tracks_join_part_quit_kick_nick_mode(env):
    core, irc, sent = env
    core.connected = True
    own_join(core, irc, sent)
    chan = core.get_chan("#wbs")
    pump(core, irc,
         ":newbie!~n@n.example JOIN #wbs",
         ":op!~op@op.example MODE #wbs +ov-v newbie newbie vo",
         ":plain1!~p1@p.example NICK renamed",
         ":plain2!~p2@p.example PART #wbs :bye",
         ":op!~op@op.example KICK #wbs half :out",
         ":both!~b@b.example QUIT :gone",
         ":op!~op@op.example MODE #wbs +b-l *!*@bad.example")
    assert sorted(chan.users) == sorted([BOT.lower(), "own", "op", "vo", "newbie", "renamed"])
    assert chan.is_op("newbie") and chan.is_voiced("newbie")
    assert not chan.is_voiced("vo")
    assert "half" not in chan.halfops and "both" not in chan.ops
    assert chan.hosts["renamed"] == "~p1@p.example"
    assert chan.live_bans == ["*!*@bad.example"] and chan.limit == 0
    assert chan.bot_op and chan.synced

    pump(core, irc, f":op!~op@op.example MODE #wbs -o {BOT}")
    assert not chan.bot_op
    # Bot's own PART drops the live state.
    pump(core, irc, f":{BOT}!~wbs@bot.example PART #wbs")
    assert core.live_channel("#wbs") is None


def test_reconnect_resyncs(env):
    core, irc, sent = env
    core.connected = True
    own_join(core, irc, sent)
    assert chaninfo(core)["Synced"] == "yes"

    pump(core, irc)                                   # nothing pending
    asyncio.run(core.handle_event({"type": "DISCONNECT"}))
    live = chaninfo(core)
    assert live["Synced"] == "no" and live["Users"] == "0", live
    assert run_cmd(core, cmd_channels, "")[1].endswith("| (not connected)")

    # Reconnect: welcome -> READY, then the server answers our JOIN again.
    types = pump(core, irc, f"{SRV} 001 {BOT} :Welcome")
    assert "READY" in types and core.connected
    assert chaninfo(core)["Synced"] == "no"
    own_join(core, irc, sent)
    live = chaninfo(core)
    assert live["Synced"] == "yes" and live["Users"] == "8" and live["Bot status"] == "op", live


def test_new_core_asks_irc_for_state(env):
    """A Core started after IRC (relaunch/.rehash) sees no JOIN: it asks the
    IRC process, which reports its channels and resyncs them."""
    core, irc, sent = env
    core.connected = True
    own_join(core, irc, sent)

    fresh = make_core(core.db_path)
    sent.clear()
    irc.execute_command({"cmd": "state"})
    assert {"WHO #wbs", "MODE #wbs", "NAMES #wbs"} <= set(sent), sent
    pump(fresh, irc)
    assert fresh.connected and fresh.get_chan("#wbs").joined
    pump(fresh, irc, *JOIN_BURST[3:], *WHO_BURST)
    assert chaninfo(fresh)["Synced"] == "yes"
    assert chaninfo(fresh)["Users"] == "8"


def test_channels_is_truthful(env):
    core, irc, sent = env
    out = run_cmd(core, cmd_channels, "")
    assert "irc_snapshot" not in " ".join(out)
    assert all("(not connected)" in l for l in out if l.startswith("-->")), out

    pump(core, irc, f"{SRV} 001 {BOT} :Welcome")
    own_join(core, irc, sent)
    out = run_cmd(core, cmd_channels, "")
    lines = {l.split()[1]: l for l in out if l.startswith("-->")}
    assert lines["#wbs"].endswith("| users:8 ops:4 voice:2 bot:op"), lines
    assert lines["#other"].endswith("| (not joined)"), lines
    assert out[-1] == "TOTAL CHANNELS: 2"


def _mass(core, irc, sent, arg, handle="boss"):
    core.irc_q.items.clear()
    out = run_cmd(core, cmd_mass, arg, handle)
    sent.clear()
    for p in core.irc_q.items:
        irc.execute_command(p)
    return out, list(sent)


def test_mass_op_batches_non_opped_only(env):
    core, irc, sent = env
    pump(core, irc, f"{SRV} 001 {BOT} :Welcome",
         f"{SRV} 005 {BOT} PREFIX=(qaohv)~&@%+ MODES=3 CHANMODES=beI,k,l,imnpst :are supported")
    own_join(core, irc, sent)
    pump(core, irc, *[f":x{i}!~x@x.example JOIN #wbs" for i in range(5)])
    out, lines = _mass(core, irc, sent, "op #wbs")
    assert out == ["Mass op sent for 9 user(s) in #wbs."], out
    # Not opped: half, vo, plain1, plain2, x0..x4.  Never the bot, ~own,
    # @op or @+both.  MODES=3 per line.
    assert lines == ["MODE #wbs +ooo half vo plain1",
                     "MODE #wbs +ooo plain2 x0 x1",
                     "MODE #wbs +ooo x2 x3 x4"], lines


def test_mass_respects_server_modes_and_skips_protected(env):
    core, irc, sent = env
    pump(core, irc, f"{SRV} 001 {BOT} :Welcome",
         f"{SRV} 005 {BOT} MODES=4 :are supported")
    own_join(core, irc, sent)
    # Known user with +o (opper) is opped in the channel as "op"; boss-host
    # user joins too.
    pump(core, irc, ":bossy!~boss@boss.example JOIN #wbs",
         ":op!~op@op.example MODE #wbs +o bossy")
    out, lines = _mass(core, irc, sent, "deop #wbs")
    # ~own is op level but has no +o mode letter to remove -> -o only for
    # nicks carrying 'o'; op (matches *!*op@op.example, +o user) and bossy
    # (+n/+A) are protected.
    assert lines == ["MODE #wbs -oo own both"], (out, lines)

    out, lines = _mass(core, irc, sent, "voice #wbs")
    assert lines == ["MODE #wbs +vvvv own op half plain1",
                     "MODE #wbs +vv plain2 bossy"], lines
    out, lines = _mass(core, irc, sent, "kick #wbs flood")
    assert sorted(lines) == sorted([f"KICK #wbs {n} :flood" for n in
                                    ("half", "vo", "plain1", "plain2")]), lines


def test_mass_refusals(env):
    core, irc, sent = env
    assert _mass(core, irc, sent, "op #wbs", handle="plain")[0] == ["Access denied (need +o)."]
    assert _mass(core, irc, sent, "op #wbs")[0] == ["I'm not on #wbs."]
    assert _mass(core, irc, sent, "zap #wbs")[0][0].startswith("Unknown mass action")
    pump(core, irc, f"{SRV} 001 {BOT} :Welcome")
    own_join(core, irc, sent, opped=False)
    assert _mass(core, irc, sent, "op #wbs") == (["I need op on #wbs."], [])


def test_mass_mode_lines_byte_limit(env):
    _, irc, _ = env
    irc.server_caps.ingest(["MODES=100"])
    nicks = [f"n{i:02d}" + "x" * 25 for i in range(30)]
    lines = irc.mass_mode_lines("#wbs", "+", "o", nicks)
    assert all(len(l.encode()) <= 510 for l in lines)
    assert len(lines) > 1
    assert [n for l in lines for n in l.split()[3:]] == nicks
