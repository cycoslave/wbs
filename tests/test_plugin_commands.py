"""
Regression tests for PLG-6 / PLG-9.

PLG-6  the partyline commands of the plugins (.seen .seenstats .purgeseens
       .limitset .chanlock .topiclock .netop .stats .topstats) were not
       registered anywhere: every one answered "Unknown command".  Plugins now
       register commands through Plugin.register_command(); they appear in
       commands.COMMANDS, partyline.COMMAND_MIN_FLAGS and `.help` on load and
       are gone again after unload.
PLG-9  after pubcom (`identify`) or seen (`seen`) answered a /msg, the core
       answered again ("Unknown command" / the command itself); `!a` with no
       argument looked up '' instead of printing usage; seen tell-seens were
       queued once per ask and so delivered once per ask.

Throwaway sqlite DB per test, real plugin modules, fake sessions, no IRC.
"""
import asyncio
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import pytest

from src import commands
from src import plugins as plugin_mod
from src.core import Core
from src.db import get_db
from src.partyline import COMMAND_MIN_FLAGS
from src.plugins import Plugin, PluginManager

from test_console_operator import FakeCore as _BaseCore, build_db


class PluginCore(_BaseCore):
    def __init__(self, db, tmp_path):
        super().__init__(db, tmp_path)
        self.sent: list[dict] = []
        self.channels: dict = {}
        self.plugin = PluginManager(self)
        peers = {"peerbot": "alice"}
        self.botnet = NS(
            peers={}, register=MagicMock(), unregister_plugin=MagicMock(),
            broadcast_subnet=AsyncMock(),
            same_subnet_bot_nicks=lambda: dict(peers))

    def send_irc(self, payload):
        self.sent.append(payload)

    def nick_isop(self, nick, channel):
        return False


@pytest.fixture(autouse=True)
def clean_registry():
    """The registry is process-global: never leak a command into other tests."""
    yield
    for name in list(plugin_mod.PLUGIN_COMMANDS):
        commands.COMMANDS.pop(name, None)
        COMMAND_MIN_FLAGS.pop(name, None)
    plugin_mod.PLUGIN_COMMANDS.clear()


@pytest.fixture
def core(tmp_path):
    db = asyncio.run(build_db(tmp_path))

    async def prep():
        async with get_db(db) as d:
            await d.execute("UPDATE user_access SET is_admin = 1 WHERE handle = 'bob'")
            await d.execute("INSERT INTO users(handle, password, hostmasks) "
                            "VALUES ('nopart', '$2b$12$x', '[]')")
            await d.execute("INSERT INTO user_access (handle, channel, subnet_id, has_partyline) "
                            "VALUES ('nopart', NULL, 1, 0)")
            await d.commit()
    asyncio.run(prep())
    return PluginCore(db, tmp_path)


def session(core, handle):
    q = asyncio.Queue()
    return core.partyline.register_remote("dcc", handle, q), q


async def say(core, handle, text):
    sid, q = session(core, handle)
    await core.partyline._handle_command(sid, handle, text)
    out = []
    while not q.empty():
        out.append(q.get_nowait()["text"])
    core.partyline.unregister_session(sid)
    return out


def unknown(out):
    return any("Unknown command" in line for line in out)


def denied(out):
    return any("Access denied" in line and "need" in line for line in out)


async def count(core, sql, *params):
    async with get_db(core.db_path) as d:
        rows = await d.execute_fetchall(sql, params)
    return rows[0][0]


# plugin, command, min flag, arguments that run it successfully
CASES = [
    ("seen", "seen", "p", "somebody"),
    ("seen", "seenstats", "p", ""),
    ("seen", "purgeseens", "A", "2020-01-01"),
    ("limit", "limitset", "A", "#chan"),
    ("chanlock", "chanlock", "A", "status #chan"),
    ("topiclock", "topiclock", "A", "#chan"),
    ("netop", "netop", "A", ""),
    ("stats", "stats", "p", ""),
    ("stats", "topstats", "p", ""),
]
IDS = [c[1] for c in CASES]


# --- PLG-6: registration lifecycle -----------------------------------------

@pytest.mark.parametrize("plugin,cmd,flag,arg", CASES, ids=IDS)
def test_command_resolves_after_load_and_disappears_after_unload(core, plugin, cmd, flag, arg):
    async def go():
        assert unknown(await say(core, "bob", f".{cmd} {arg}")), "must not exist before load"
        assert cmd not in commands.COMMANDS and cmd not in COMMAND_MIN_FLAGS

        await core.plugin.load_plugin(plugin)
        assert cmd in commands.COMMANDS
        assert COMMAND_MIN_FLAGS[cmd] == flag
        out = await say(core, "bob", f".{cmd} {arg}")
        assert out and not unknown(out) and not denied(out), out

        await core.plugin.unload_plugin(plugin)
        assert cmd not in commands.COMMANDS and cmd not in COMMAND_MIN_FLAGS
        assert cmd not in plugin_mod.PLUGIN_COMMANDS
        assert unknown(await say(core, "bob", f".{cmd} {arg}"))
    asyncio.run(go())


@pytest.mark.parametrize("plugin,cmd,flag,arg", CASES, ids=IDS)
def test_command_enforces_its_flag(core, plugin, cmd, flag, arg):
    async def go():
        await core.plugin.load_plugin(plugin)
        # a session without partyline access is refused by either flag
        out = await say(core, "nopart", f".{cmd} {arg}")
        assert denied(out) and not unknown(out), out
        if flag == "A":
            out = await say(core, "plainp", f".{cmd} {arg}")      # +p only
            assert denied(out) and not unknown(out), out
        else:
            out = await say(core, "plainp", f".{cmd} {arg}")
            assert not denied(out) and not unknown(out), out
    asyncio.run(go())


def test_denied_command_does_not_run(core):
    async def go():
        await core.plugin.load_plugin("limit")
        await core.plugin.load_plugin("chanlock")
        await core.plugin.load_plugin("topiclock")
        for text in (".limitset #chan limitadd 40",
                     ".chanlock lock #chan",
                     ".topiclock #chan locked topic"):
            assert denied(await say(core, "plainp", text)), text
        assert await count(core, "SELECT COUNT(*) FROM limit_settings") == 0
        assert await count(core, "SELECT COUNT(*) FROM chanlock_settings") == 0
        assert await count(core, "SELECT COUNT(*) FROM topiclock") == 0
        assert not [s for s in core.sent if s.get("cmd") in ("mode", "topic", "TOPIC")]
    asyncio.run(go())


def test_help_lists_plugin_commands_only_while_loaded_and_by_flag(core):
    async def help_names(handle):
        out = await say(core, handle, ".help")
        return {w for line in out if line.startswith("      ") for w in line.split()}

    async def go():
        assert not ({"seen", "limitset", "stats"} & await help_names("bob"))
        await core.plugin.load_plugin("seen")
        await core.plugin.load_plugin("limit")
        await core.plugin.load_plugin("stats")
        admin = await help_names("bob")
        assert {"seen", "seenstats", "purgeseens", "limitset", "stats", "topstats"} <= admin
        plain = await help_names("plainp")                  # +p, no +A
        assert {"seen", "seenstats", "stats", "topstats"} <= plain
        assert not ({"purgeseens", "limitset"} & plain)
        detail = await say(core, "bob", ".help limitset")
        assert any("limitset" in line for line in detail) and not any("ERROR" in l for l in detail)
        await core.plugin.unload_plugin("limit")
        assert "limitset" not in await help_names("bob")
        assert any("ERROR" in line for line in await say(core, "bob", ".help limitset"))
    asyncio.run(go())


def test_reload_keeps_exactly_one_registration(core):
    async def go():
        await core.plugin.load_plugin("seen")
        await core.plugin.reload_plugin("seen")
        assert sorted(n for n, c in plugin_mod.PLUGIN_COMMANDS.items() if c.owner == "seen") \
            == ["purgeseens", "seen", "seenstats"]
        assert await say(core, "bob", ".seenstats")
    asyncio.run(go())


def test_plugin_that_skips_super_unload_still_loses_its_commands(core, monkeypatch):
    """The manager removes the commands itself: a plugin whose unload() does
    not call super() cannot leave a dead command behind."""
    async def go():
        from src.plugins.seen import seenPlugin

        async def bare_unload(self):
            pass
        monkeypatch.setattr(seenPlugin, "unload", bare_unload)
        await core.plugin.load_plugin("seen")
        assert "seen" in commands.COMMANDS
        await core.plugin.unload_plugin("seen")
        assert "seen" not in commands.COMMANDS and "seen" not in COMMAND_MIN_FLAGS
    asyncio.run(go())


def test_failed_load_leaves_no_command(core, monkeypatch):
    async def go():
        from src.plugins.seen import seenPlugin

        async def boom(self, db):
            raise RuntimeError("boom")
        monkeypatch.setattr(seenPlugin, "_migrate", boom)
        with pytest.raises(RuntimeError):
            await core.plugin.load_plugin("seen")
        assert "seen" not in commands.COMMANDS and not plugin_mod.PLUGIN_COMMANDS
    asyncio.run(go())


def test_register_command_refuses_core_names_duplicates_and_bad_input(core):
    class A(Plugin):
        name = "a"

    class B(Plugin):
        name = "b"

    async def h(handle, arg):
        return "x"

    a, b = A(core), B(core)
    with pytest.raises(ValueError):
        a.register_command("die", h, "A")                  # core command
    with pytest.raises(ValueError):
        a.register_command("Bad Name", h, "A")
    with pytest.raises(ValueError):
        a.register_command("ok", h, "?")                   # not a GLOBAL_FLAGS letter
    a.register_command("ok", h, None, "ok - test")
    with pytest.raises(ValueError):
        b.register_command("ok", h, "A")                   # owned by plugin a
    assert COMMAND_MIN_FLAGS["ok"] is None
    assert a.unregister_commands() == ["ok"]
    assert "ok" not in commands.COMMANDS and b.unregister_commands() == []


# --- PLG-6: the wired handlers do their job --------------------------------

def test_limitset_shows_and_saves(core):
    async def go():
        await core.plugin.load_plugin("limit")
        assert "limitadd=15" in (await say(core, "bob", ".limitset #chan"))[0]
        out = await say(core, "bob", ".limitset #chan limitadd 40")
        assert "set to 40" in out[0]
        assert await count(core, "SELECT limitadd FROM limit_settings WHERE channel='#chan'") == 40
        assert "Usage" in (await say(core, "bob", ".limitset"))[0]
        assert "Usage" in (await say(core, "bob", ".limitset #chan bogus 1"))[0]
        assert "Invalid channel" in (await say(core, "bob", ".limitset nochan limitadd 1"))[0]
        assert "number" in (await say(core, "bob", ".limitset #chan limitadd \u00b2"))[0]
    asyncio.run(go())


def test_chanlock_lock_status_set_unlock(core):
    async def go():
        await core.plugin.load_plugin("chanlock")
        core.sent.clear()
        out = await say(core, "bob", ".chanlock lock #chan m secs=60")
        assert "locked (+i +m)" in out[0] and "auto-unlock in 60s" in out[0]
        assert {"cmd": "mode", "channel": "#chan", "modes": "+im"} in core.sent
        assert "LOCKED" in (await say(core, "bob", ".chanlock status #chan"))[0]
        assert "set to 0" in (await say(core, "bob", ".chanlock set #chan use_m 0"))[0]
        assert "unlocked" in (await say(core, "bob", ".chanlock unlock #chan"))[0]
        assert "NOT locked" in (await say(core, "bob", ".chanlock status #chan"))[0]
        assert await count(core, "SELECT COUNT(*) FROM chanlock_audit") >= 2
        for bad in (".chanlock", ".chanlock lock", ".chanlock frob #chan",
                    ".chanlock lock #chan key=a,b", ".chanlock set #chan use_m"):
            assert any("Usage" in l or "Invalid" in l for l in await say(core, "bob", bad)), bad
    asyncio.run(go())


def test_topiclock_partyline_toggle_and_set(core):
    async def go():
        await core.plugin.load_plugin("topiclock")
        core.sent.clear()
        out = await say(core, "bob", ".topiclock #chan Welcome home")
        assert "locked to: Welcome home" in out[0]
        assert {"cmd": "topic", "channel": "#chan", "topic": "Welcome home"} in core.sent
        assert "disabled" in (await say(core, "bob", ".topiclock #chan"))[0]
        assert "enabled" in (await say(core, "bob", ".topiclock #chan"))[0]
        assert "Usage" in (await say(core, "bob", ".topiclock"))[0]
    asyncio.run(go())


def pub(nick, text, chan="#chan", host="n!u@h"):
    return {"type": "PUBMSG", "nick": nick, "channel": chan, "text": text, "host": host}


def test_public_topiclock_needs_identified_chanop(core):
    async def go():
        await core.plugin.load_plugin("topiclock")
        pc = NS(is_pubcom_enabled=AsyncMock(return_value=True),
                verify_session=AsyncMock(return_value=None),
                authorize=AsyncMock(return_value=False))
        core.plugin.plugins["pubcom"] = pc
        tl = core.plugin.plugins["topiclock"]
        core.sent.clear()

        await tl.on_PUBMSG(pub("eve", "!topiclock my topic"))             # not identified
        assert [s["text"] for s in core.sent] == ["You must identify first"]
        assert await count(core, "SELECT COUNT(*) FROM topiclock") == 0

        core.sent.clear()
        pc.verify_session.return_value = "eve"
        await tl.on_PUBMSG(pub("eve", "!topiclock my topic"))             # identified, no op
        assert [s["text"] for s in core.sent] == ["Access denied for !topiclock."]
        assert await count(core, "SELECT COUNT(*) FROM topiclock") == 0

        core.sent.clear()
        pc.authorize.return_value = True
        await tl.on_PUBMSG(pub("op", "!topiclock my topic"))
        assert await count(core, "SELECT enabled FROM topiclock WHERE channel='#chan'") == 1
        assert any(s.get("cmd") == "msg" and "locked to: my topic" in s["text"] for s in core.sent)
        pc.authorize.assert_awaited_with("eve", "chanop", "#chan")

        core.sent.clear()
        pc.is_pubcom_enabled.return_value = False                        # channel not enabled
        await tl.on_PUBMSG(pub("op", "!topiclock again"))
        assert core.sent == []
        del core.plugin.plugins["pubcom"]
        await tl.on_PUBMSG(pub("op", "!topiclock again"))                # no pubcom at all
        assert core.sent == []
    asyncio.run(go())


def test_stats_and_topstats(core):
    async def go():
        await core.plugin.load_plugin("stats")
        st = core.plugin.plugins["stats"]
        for text in ("hello", "world"):
            await st.on_PUBMSG(pub("zed", text))
        out = await say(core, "plainp", ".stats #chan zed")
        assert "msgs: 2" in out[0] and "[#chan]" in out[0]
        assert "msgs: 2" in (await say(core, "plainp", ".stats zed"))[0]
        assert "No stats found for plainp" in (await say(core, "plainp", ".stats"))[0]
        assert "1. zed (2 msgs)" in (await say(core, "plainp", ".topstats #chan 3"))[0]
        assert "Usage" in (await say(core, "plainp", ".topstats #chan x"))[0]
    asyncio.run(go())


def test_netop_lists_peers_and_requests_ops(core):
    async def go():
        await core.plugin.load_plugin("netop")
        out = await say(core, "bob", ".netop")
        assert "peerbot" in out[0]
        out = await say(core, "bob", ".netop reqop #Chan")
        assert "asked linked bots for ops on #chan" in out[0]
        core.botnet.broadcast_subnet.assert_awaited_with("reqop beta #chan")
        assert "Usage" in (await say(core, "bob", ".netop reqop"))[0]
        assert "Usage" in (await say(core, "bob", ".netop reqop x y"))[0]
        assert "Invalid channel" in (await say(core, "bob", ".netop reqop nochan"))[0]
    asyncio.run(go())


def test_seen_and_purgeseens_partyline(core):
    async def go():
        await core.plugin.load_plugin("seen")
        sn = core.plugin.plugins["seen"]
        await sn._update("zed", "z!u@h", "#chan", "said something")
        assert "zed" in (await say(core, "plainp", ".seen zed"))[0]
        assert "don't remember" in (await say(core, "plainp", ".seen nobody"))[0]
        assert "Usage" in (await say(core, "plainp", ".seen"))[0]
        assert "tracking 1 nick" in (await say(core, "plainp", ".seenstats"))[0]
        assert "Purged 0" in (await say(core, "bob", ".purgeseens 2000-01-01"))[0]
        assert "Purged 1" in (await say(core, "bob", ".purgeseens 2999-01-01"))[0]
        assert await count(core, "SELECT COUNT(*) FROM seen") == 0
        assert "Usage" in (await say(core, "bob", ".purgeseens"))[0]
        assert "Invalid date" in (await say(core, "bob", ".purgeseens soon"))[0]
    asyncio.run(go())


# --- PLG-9: no double replies ----------------------------------------------

class IrcCore:
    """Just what Core.on_command touches."""
    def __init__(self, handle="bob"):
        self.sent = []
        # F-01a: /msg commands are off by default and need a live pubcom
        # identify session for the matched handle.
        self.config = {"botnet": {"subnet_id": 1}, "settings": {"msg_commands": True}}
        self.user = NS(match_user=AsyncMock(return_value=handle),
                       matchattr=AsyncMock(return_value=True))
        self.plugin = NS(plugins={"pubcom": NS(verify_session=AsyncMock(return_value=handle))})

    def send_cmd(self, cmd_type, target, text="", **kw):
        self.sent.append((target, text))


async def privmsg(core_plugins, ircore, text):
    ev = {"type": "PRIVMSG", "nick": "bobnick", "host": "bobnick!u@h.example", "text": text}
    for p in list(core_plugins.plugin.plugins.values()):
        await p.on_PRIVMSG(ev)
    await Core.on_command(ircore, dict(ev, type="COMMAND", handled=ev.get("handled")))
    return ev


def test_seen_msg_is_answered_once(core):
    async def go():
        await core.plugin.load_plugin("seen")
        ircore = IrcCore()
        core.sent.clear()
        ev = await privmsg(core, ircore, "seen nobody")
        assert ev["handled"] is True
        notices = [s for s in core.sent if s.get("cmd") == "notice"]
        assert len(notices) == 1 and "don't remember" in notices[0]["text"]
        assert ircore.sent == [], f"core also replied: {ircore.sent}"       # was .seen/Unknown
        core.sent.clear()
        await privmsg(core, ircore, "seenstats")
        assert len([s for s in core.sent if s.get("cmd") == "notice"]) == 1
        assert ircore.sent == []
        core.sent.clear()
        await privmsg(core, ircore, "seen")
        assert "Usage" in core.sent[0]["text"] and ircore.sent == []
    asyncio.run(go())


def test_core_still_answers_commands_nobody_consumed(core):
    async def go():
        await core.plugin.load_plugin("seen")
        ircore = IrcCore()
        await privmsg(core, ircore, "frobnicate")
        assert ircore.sent == [("bobnick", "Unknown command: .frobnicate")]
    asyncio.run(go())


def test_identify_is_consumed_by_pubcom_without_a_core_reply(core):
    async def go():
        await core.plugin.load_plugin("pubcom")
        ircore = IrcCore()
        core.sent.clear()
        ev = await privmsg(core, ircore, "identify")           # usage path, no DB needed
        assert ev["handled"] is True
        assert len(core.sent) == 1 and "Usage: /msg" in core.sent[0]["text"]
        assert ircore.sent == []
        # the core drops a handled event even for a command that does exist
        await Core.on_command(ircore, {"nick": "n", "host": "n!u@h", "text": "uptime",
                                       "handled": True})
        assert ircore.sent == []
    asyncio.run(go())


ARG_COMMANDS = ["!a", "!aaaa", "!ptr", "!mx", "!ns", "!dmarc", "!spf", "!dkim", "!soa",
                "!srv", "!caa", "!txt", "!ptr6"]


@pytest.mark.parametrize("cmd", ARG_COMMANDS)
def test_lookup_command_without_argument_prints_usage(core, cmd):
    async def go():
        await core.plugin.load_plugin("pubcom")
        pc = core.plugin.plugins["pubcom"]
        pc.is_pubcom_enabled = AsyncMock(return_value=True)
        pc.get_dns_records = AsyncMock(return_value=[])
        core.sent.clear()
        for text in (cmd, f"{cmd}   "):
            await pc.on_PUBMSG(pub("eve", text))
        assert [s["text"] for s in core.sent] == [f"Usage: {cmd} <{'ipv6' if cmd == '!ptr6' else 'domain'}>"] * 2
        pc.get_dns_records.assert_not_awaited()
        core.sent.clear()
        await pc.on_PUBMSG(pub("eve", f"{cmd} bad!domain"))     # with an argument: unchanged path
        assert core.sent and "Usage" not in core.sent[0]["text"]
    asyncio.run(go())


def test_seen_tell_is_delivered_once_however_often_asked(core):
    async def go():
        await core.plugin.load_plugin("seen")
        sn = core.plugin.plugins["seen"]
        for _ in range(4):
            await sn._cmd_seen("alice", "#chan", "ghost")
        assert await count(core, "SELECT COUNT(*) FROM seen_notify") == 1
        await sn._cmd_seen("carol", "#chan", "ghost")           # another asker: its own line
        assert await count(core, "SELECT COUNT(*) FROM seen_notify") == 2

        core.sent.clear()
        await sn._deliver_notifications("ghost", "#chan")
        lines = [s["text"] for s in core.sent if s.get("cmd") == "msg"]
        assert len(lines) == 2
        assert any("alice was looking for you" in l for l in lines)
        assert any("carol was looking for you" in l for l in lines)
        core.sent.clear()
        await sn._deliver_notifications("ghost", "#chan")        # nothing is delivered twice
        assert core.sent == []
    asyncio.run(go())


def test_seen_tell_rows_already_duplicated_give_one_line(core):
    async def go():
        await core.plugin.load_plugin("seen")
        sn = core.plugin.plugins["seen"]
        async with get_db(core.db_path) as d:
            for _ in range(3):
                await d.execute("INSERT INTO seen_notify(asker, target, channel, asked_at) "
                                "VALUES ('Alice', 'ghost', '#chan', 1)")
            await d.commit()
        core.sent.clear()
        await sn._deliver_notifications("ghost", "#chan")
        assert len([s for s in core.sent if s.get("cmd") == "msg"]) == 1
        assert await count(core, "SELECT COUNT(*) FROM seen_notify") == 0
    asyncio.run(go())


def test_concurrent_events_deliver_a_tell_once(core):
    async def go():
        await core.plugin.load_plugin("seen")
        sn = core.plugin.plugins["seen"]
        await sn._queue_notification("alice", "ghost", "#chan")
        core.sent.clear()
        await asyncio.gather(sn._deliver_notifications("ghost", "#chan"),
                             sn._deliver_notifications("ghost", "#chan"))
        assert len([s for s in core.sent if s.get("cmd") == "msg"]) == 1
    asyncio.run(go())
