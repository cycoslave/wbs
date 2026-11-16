"""
Offline regression tests for SAST-006: the pubcom plugin's privileged public
commands (!op/!deop/!voice/!devoice/!kick/!ban/!mode/!rehash/!restart).

Acceptance under test:
  * a password-valid user without the required role produces NO privileged
    IRC effect (nothing queued for IRC, no rehash/restart);
  * authorized users operate only in permitted channels and on this bot's
    subnet, and their commands now reach the real IRC consumer schema
    (irc.py WbsIrcBot.execute_command) and produce the intended call;
  * channels where pubcom is not enabled (not configured, inactive, or bound
    to another subnet) reject every command;
  * sessions are bound to the canonical handle and the caller's full
    nick!user@host (SAST-007 overlap): other hosts, nick changes, quits,
    disconnects and locked accounts lose access;
  * arguments are typed/validated (no IRC line smuggling).

Throwaway sqlite under pytest's tmp_path; no network, no IRC, no bot process.
"""
import asyncio
import os
import shutil
import tempfile
from unittest import mock

import bcrypt
import pytest

from src.channel import ChannelManager
from src.db import get_db, init_db
from src.irc import WbsIrcBot
from src.plugins import pubcom as pc
from src.plugins.pubcom import pubcomPlugin
from src.user import UserManager

LOCAL_SUBNET = 1
PASSWORD = "correct-horse"          # test-only fixture value
HASH = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()

_TEMPLATE_DB: str | None = None

# handle -> access rows (channel, subnet_id, {flag columns})
USERS = {
    "plain":    [(None, None, {"has_partyline"})],                 # password-valid, no role
    "voiceonly": [("#one", 1, {"is_voice"})],                      # channel +v only
    "gop":      [(None, None, {"is_op"})],                         # global +o
    "chanop":   [("#one", 1, {"is_op"})],                          # +o on #one, subnet 1
    "foreignop": [(None, 2, {"is_op", "is_admin"}),                # subnet 2 only
                  ("#one", 2, {"is_op"})],
    "admin":    [(None, None, {"is_admin"})],                      # +A, not +o
    "ladmin":   [(None, 1, {"is_admin", "is_op"})],                # subnet-1 admin+op
    "lockme":   [(None, None, {"is_op", "is_admin"})],
}

# channel -> (subnet binding or None for global, is_inactive)
CHANNELS = {
    "#one": (None, 0),
    "#two": (None, 0),
    "#off": (None, 0),        # active, but NOT listed in config pubcom.channels
    "#dead": (None, 1),       # listed, but inactive
    "#sub2": (2, 0),          # listed, but bound to subnet 2 only
}
ENABLED = ["#one", "#two", "#DEAD", "#sub2"]


async def _fresh_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-sast006-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


async def build_db(tmp_path) -> str:
    db = str(tmp_path / "wbs.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        for handle, rows in USERS.items():
            await d.execute("INSERT INTO users(handle, password, hostmasks) VALUES (?, ?, '[]')",
                            (handle, HASH))
            for channel, sid, cols in rows:
                names = ["handle", "channel", "subnet_id", *sorted(cols)]
                vals = [handle, channel, sid, *([1] * len(cols))]
                await d.execute(
                    f"INSERT INTO user_access ({', '.join(names)}) "
                    f"VALUES ({', '.join('?' * len(names))})", vals)
        for name, (sid, inactive) in CHANNELS.items():
            await d.execute("INSERT INTO channels(name, is_inactive) VALUES (?, ?)", (name, inactive))
            if sid is not None:
                await d.execute("INSERT INTO channel_subnets(channel_name, subnet_id) VALUES (?, ?)",
                                (name, sid))
        await d.commit()
    return db


class FakeCore:
    """Just enough of Core for the pubcom plugin, fully offline."""

    def __init__(self, db: str, enabled=ENABLED, local_subnet: int = LOCAL_SUBNET):
        self.db_path = db
        self.config = {"bot": {"nick": "wbs"}, "botnet": {"subnet_id": local_subnet},
                       "pubcom": {"channels": list(enabled)}}
        self.botname = "wbs"
        self.user = UserManager(db)
        self.chan = ChannelManager(db)
        self.sent: list[dict] = []
        self.rehashed = 0
        self.restarted = 0

    def send_irc(self, payload: dict) -> None:
        self.sent.append(payload)

    async def do_rehash(self):
        self.rehashed += 1

    async def do_restart(self):
        self.restarted += 1

    # helpers
    def effects(self) -> list[dict]:
        """Queued IRC payloads that change channel state."""
        return [p for p in self.sent if p.get("cmd") not in ("msg", "notice")]

    def notices(self) -> list[str]:
        return [p["text"] for p in self.sent if p.get("cmd") == "notice"]

    def reset(self):
        self.sent.clear()


def host(nick: str, user: str = "u", h: str = "home.example") -> str:
    return f"{nick}!{user}@{h}"


@pytest.fixture
def env(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    core = FakeCore(db)
    plugin = pubcomPlugin(core)
    return core, plugin


def run(coro):
    return asyncio.run(coro)


async def identify(plugin, nick, handle=None, password=PASSWORD, hostmask=None):
    text = f"identify {handle} {password}" if handle else f"identify {password}"
    await plugin.on_PRIVMSG({"nick": nick, "host": hostmask or host(nick), "text": text,
                             "target": "wbs"})


async def say(plugin, nick, channel, text, hostmask=None):
    await plugin.on_PUBMSG({"nick": nick, "host": hostmask or host(nick),
                            "channel": channel, "text": text})


PRIV_LINES = ["!op", "!op victim", "!deop victim", "!voice victim", "!devoice victim",
              "!kick victim bye", "!ban victim", "!ban *!*@evil.example", "!mode +m",
              "!mode +o victim", "!rehash", "!restart"]


def fake_irc_bot():
    """Real WbsIrcBot.execute_command with a mocked connection (no sockets)."""
    bot = object.__new__(WbsIrcBot)
    bot.connection = mock.MagicMock()
    bot.connection.is_connected.return_value = True
    bot.core_q = mock.MagicMock()
    return bot


# ---------------------------------------------------------------------------
# 1. Low privilege / unauthenticated: no privileged effects
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("handle", ["plain", "voiceonly"])
def test_password_valid_user_without_op_gets_no_chanop_effect(env, handle):
    core, plugin = env

    async def go():
        await identify(plugin, "lowly", handle)
        assert core.notices()[-1] == "Logged in successfully!"
        core.reset()
        for line in PRIV_LINES[:10]:            # channel-op commands
            await say(plugin, "lowly", "#one", line)
    run(go())
    assert core.effects() == []
    assert all("Access denied" in n for n in core.notices())
    assert len(core.notices()) == 10


@pytest.mark.parametrize("handle", ["plain", "gop", "chanop", "voiceonly"])
def test_non_admin_cannot_rehash_or_restart(env, handle):
    core, plugin = env

    async def go():
        await identify(plugin, "someone", handle)
        await say(plugin, "someone", "#one", "!rehash")
        await say(plugin, "someone", "#one", "!restart")
    run(go())
    assert (core.rehashed, core.restarted) == (0, 0)
    assert core.effects() == []


def test_unidentified_user_gets_no_effect(env):
    core, plugin = env

    async def go():
        for line in PRIV_LINES:
            await say(plugin, "stranger", "#one", line)
    run(go())
    assert core.effects() == []
    assert (core.rehashed, core.restarted) == (0, 0)
    assert set(core.notices()) == {"You must identify first"}


def test_wrong_password_creates_no_session(env):
    core, plugin = env

    async def go():
        await identify(plugin, "gopnick", "gop", password="nope")
        await say(plugin, "gopnick", "#one", "!op")
    run(go())
    assert "Invalid credentials!" in core.notices()
    assert core.effects() == []
    assert plugin.auth_sessions == {}


def test_locked_user_after_identify_is_denied(env):
    core, plugin = env

    async def go():
        await identify(plugin, "lk", "lockme")
        await say(plugin, "lk", "#one", "!op")
        assert len(core.effects()) == 1
        core.reset()
        await core.user.set_locked("lockme", True)
        await say(plugin, "lk", "#one", "!op")
        await say(plugin, "lk", "#one", "!restart")
    run(go())
    assert core.effects() == []
    assert core.restarted == 0


def test_locked_user_cannot_identify(env):
    core, plugin = env

    async def go():
        await core.user.set_locked("lockme", True)
        await identify(plugin, "lk", "lockme")
    run(go())
    assert "Invalid credentials!" in core.notices()
    assert plugin.auth_sessions == {}


# ---------------------------------------------------------------------------
# 2. Authorized users, after schema repair, reach the real IRC consumer
# ---------------------------------------------------------------------------
def test_global_op_commands_use_consumer_schema(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
        await say(plugin, "Boss", "#one", "!deop victim")
        await say(plugin, "Boss", "#one", "!voice victim")
        await say(plugin, "Boss", "#one", "!devoice victim")
        await say(plugin, "Boss", "#one", "!kick victim go away")
        await say(plugin, "Boss", "#one", "!ban victim spam")
        await say(plugin, "Boss", "#one", "!ban *!*@evil.example")
        await say(plugin, "Boss", "#one", "!mode +ntk-s sekrit")
    run(go())
    assert core.effects() == [
        {"cmd": "mode", "channel": "#one", "modes": "+o Boss"},
        {"cmd": "mode", "channel": "#one", "modes": "-o victim"},
        {"cmd": "mode", "channel": "#one", "modes": "+v victim"},
        {"cmd": "mode", "channel": "#one", "modes": "-v victim"},
        {"cmd": "kick", "channel": "#one", "nick": "victim", "reason": "go away"},
        {"cmd": "mode", "channel": "#one", "modes": "+b victim!*@*"},
        {"cmd": "kick", "channel": "#one", "nick": "victim", "reason": "spam"},
        {"cmd": "mode", "channel": "#one", "modes": "+b *!*@evil.example"},
        {"cmd": "mode", "channel": "#one", "modes": "+ntk-s sekrit"},
    ]

    # Feed the queued payloads through the real IRC-side consumer.
    bot = fake_irc_bot()
    for payload in core.effects():
        bot.execute_command(payload)
    conn = bot.connection
    assert conn.mode.call_args_list == [
        mock.call("#one", "+o Boss"), mock.call("#one", "-o victim"),
        mock.call("#one", "+v victim"), mock.call("#one", "-v victim"),
        mock.call("#one", "+b victim!*@*"), mock.call("#one", "+b *!*@evil.example"),
        mock.call("#one", "+ntk-s sekrit"),
    ]
    assert conn.kick.call_args_list == [mock.call("#one", "victim", "go away"),
                                        mock.call("#one", "victim", "spam")]


def test_channel_op_only_in_own_channel(env):
    core, plugin = env

    async def go():
        await identify(plugin, "cop", "chanop")
        await say(plugin, "cop", "#one", "!voice friend")
        await say(plugin, "cop", "#ONE", "!voice friend2")   # IRC channel case
        await say(plugin, "cop", "#two", "!voice friend")
        await say(plugin, "cop", "#two", "!kick friend")
    run(go())
    assert core.effects() == [
        {"cmd": "mode", "channel": "#one", "modes": "+v friend"},
        {"cmd": "mode", "channel": "#ONE", "modes": "+v friend2"},
    ]
    assert core.notices()[-2:] == ["Access denied for !voice.", "Access denied for !kick."]


def test_foreign_subnet_grants_do_not_apply(env):
    core, plugin = env

    async def go():
        await identify(plugin, "fop", "foreignop")
        for line in PRIV_LINES:
            await say(plugin, "fop", "#one", line)
    run(go())
    assert core.effects() == []
    assert (core.rehashed, core.restarted) == (0, 0)


def test_foreign_subnet_grants_apply_on_their_own_subnet(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    core = FakeCore(db, enabled=["#one"], local_subnet=2)
    plugin = pubcomPlugin(core)

    async def go():
        await identify(plugin, "fop", "foreignop")
        await say(plugin, "fop", "#one", "!op")
    run(go())
    assert core.effects() == [{"cmd": "mode", "channel": "#one", "modes": "+o fop"}]


def test_admin_restart_and_rehash(env):
    core, plugin = env

    async def go():
        await identify(plugin, "adm", "admin")
        await say(plugin, "adm", "#one", "!rehash")
        await say(plugin, "adm", "#one", "!restart")
        await identify(plugin, "ladm", "ladmin")
        await say(plugin, "ladm", "#two", "!restart")
    run(go())
    assert (core.rehashed, core.restarted) == (1, 2)
    assert core.effects() == []              # no legacy event_q / RESTART payloads


def test_identify_binds_canonical_handle(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Gop", "GOP")       # case-insensitive login name
        await say(plugin, "Gop", "#one", "!op")
    run(go())
    assert plugin.auth_sessions["gop"]["handle"] == "gop"
    assert core.effects() == [{"cmd": "mode", "channel": "#one", "modes": "+o Gop"}]


def test_identify_without_handle_uses_nick_not_host(env):
    core, plugin = env

    async def go():
        await identify(plugin, "gop")               # "identify <password>"
        await say(plugin, "gop", "#one", "!op")
    run(go())
    assert core.effects() == [{"cmd": "mode", "channel": "#one", "modes": "+o gop"}]


# ---------------------------------------------------------------------------
# 3. Channel enablement
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("channel", ["#off", "#dead", "#sub2", "#unknown", "#ONE,#two"])
def test_disabled_channels_reject_everything(env, channel):
    core, plugin = env

    async def go():
        await identify(plugin, "adm", "ladmin")
        core.reset()
        for line in PRIV_LINES + ["!version", "!time", "!info"]:
            await say(plugin, "adm", channel, line)
    run(go())
    assert core.sent == []
    assert (core.rehashed, core.restarted) == (0, 0)


def test_no_pubcom_config_disables_everywhere(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    core = FakeCore(db, enabled=[])
    del core.config["pubcom"]
    plugin = pubcomPlugin(core)

    async def go():
        await identify(plugin, "adm", "ladmin")
        core.reset()
        await say(plugin, "adm", "#one", "!op")
        await say(plugin, "adm", "#one", "!version")
    run(go())
    assert core.sent == []


def test_enabled_channel_answers_public_commands(env):
    core, plugin = env
    run(say(plugin, "anyone", "#one", "!version"))
    assert [p["cmd"] for p in core.sent] == ["msg"]


def test_unidentified_user_cannot_portscan_or_reach_network(env):
    core, plugin = env

    async def go():
        with mock.patch.object(pc, "resolve_public", new=mock.AsyncMock()) as resolve, \
                mock.patch.object(pc.asyncio, "open_connection", new=mock.AsyncMock()) as connect:
            await say(plugin, "stranger", "#one", "!portscan example.com")
        return resolve, connect

    resolve, connect = run(go())
    resolve.assert_not_awaited()
    connect.assert_not_awaited()
    assert core.notices() == ["You must identify first"]


def test_identified_operator_can_portscan(env):
    _, plugin = env
    plugin.cmd_portscan = mock.AsyncMock()

    async def go():
        await identify(plugin, "Boss", "gop")
        await say(plugin, "Boss", "#one", "!portscan example.com")

    run(go())
    plugin.cmd_portscan.assert_awaited_once_with("gop", "Boss", "#one", "example.com")


def test_identified_nonoperator_cannot_portscan(env):
    core, plugin = env
    plugin.cmd_portscan = mock.AsyncMock()

    async def go():
        await identify(plugin, "Plain", "plain")
        core.reset()
        await say(plugin, "Plain", "#one", "!portscan example.com")

    run(go())
    plugin.cmd_portscan.assert_not_awaited()
    assert core.notices() == ["Access denied for !portscan."]


def test_portscan_cooldown_is_per_channel(env):
    core, plugin = env
    plugin.cmd_portscan = mock.AsyncMock()

    async def go():
        await identify(plugin, "Boss", "gop")
        core.reset()
        with mock.patch.object(pc.time, "monotonic", return_value=1000.0):
            await say(plugin, "Boss", "#one", "!portscan first.example")
            await say(plugin, "Boss", "#one", "!portscan second.example")
            await say(plugin, "Boss", "#two", "!portscan other.example")

    run(go())
    assert plugin.cmd_portscan.await_args_list == [
        mock.call("gop", "Boss", "#one", "first.example"),
        mock.call("gop", "Boss", "#two", "other.example"),
    ]
    assert any("cooldown" in p["text"].lower() for p in core.sent if p.get("cmd") == "msg")


def test_info_marks_portscan_operator_only_and_rate_limited(env):
    core, plugin = env
    run(say(plugin, "anyone", "#one", "!info"))
    text = " ".join(p["text"] for p in core.sent if p.get("cmd") == "msg").lower()
    assert "!portscan requires an identified operator" in text
    assert "60-second per-channel cooldown" in text


def test_unknown_and_removed_commands_are_ignored(env):
    core, plugin = env

    async def go():
        await identify(plugin, "adm", "ladmin")
        core.reset()
        for line in ["!jump irc.evil.example", "!raw QUIT", "!OPS", "!", "hello"]:
            await say(plugin, "adm", "#one", line)
    run(go())
    assert core.sent == []


# ---------------------------------------------------------------------------
# 4. Session binding (coordinates with SAST-007)
# ---------------------------------------------------------------------------
def test_session_not_inherited_by_other_host(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        core.reset()
        await say(plugin, "Boss", "#one", "!op", hostmask=host("Boss", h="attacker.example"))
        # The legitimate host's session was dropped too: must re-identify.
        await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert core.effects() == []


@pytest.mark.parametrize("event_name,event", [
    ("on_NICK", {"old_nick": "Boss", "new_nick": "Boss_"}),
    ("on_QUIT", {"nick": "Boss", "reason": "bye"}),
    ("on_DISCONNECT", {}),
])
def test_session_ends_on_nick_quit_disconnect(env, event_name, event):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        await getattr(plugin, event_name)(event)
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
        await say(plugin, "Boss_", "#one", "!op", hostmask=host("Boss_"))
    run(go())
    assert core.effects() == []


def test_nick_change_to_authenticated_nick_does_not_inherit(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        await plugin.on_NICK({"old_nick": "Boss", "new_nick": "Gone"})
        await plugin.on_NICK({"old_nick": "thief", "new_nick": "Boss"})
        core.reset()
        await say(plugin, "Boss", "#one", "!op", hostmask=host("Boss", h="home.example"))
    run(go())
    assert core.effects() == []


def test_session_expiry(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        plugin.auth_sessions["boss"]["ts"] -= plugin.auth_timeout + 1
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert core.effects() == []
    assert "boss" not in plugin.auth_sessions


def test_failed_reidentify_drops_existing_session(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        await identify(plugin, "Boss", "gop", password="wrong")
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert core.effects() == []


# ---------------------------------------------------------------------------
# 5. Typed arguments
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("line", [
    "!op bad,nick",
    "!op #chan",
    "!kick 1digit",
    "!kick",
    "!kick wbs",                         # never the bot itself
    "!deop WBS",
    "!ban",
    "!ban *!*@*",                        # ban everyone
    "!ban a!b",                          # malformed mask
    "!ban x!y@z,#other",
    "!mode",
    "!mode o",                           # missing sign
    "!mode +o a b c d e",                # too many params
    "!mode +k :trailing",
    "!mode +b a,b",
    "!mode +l 5\rQUIT :x",
    "!mode +l 5\nPRIVMSG #x :hi",
    "!mode +-",
])
def test_invalid_arguments_produce_no_effect(env, line):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        core.reset()
        await say(plugin, "Boss", "#one", line)
    run(go())
    assert core.effects() == []


def test_kick_reason_is_sanitized(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        core.reset()
        await say(plugin, "Boss", "#one", "!kick victim " + "x\x01y" + "z" * 400)
    run(go())
    (kick,) = core.effects()
    assert kick["cmd"] == "kick" and kick["nick"] == "victim"
    assert "\x01" not in kick["reason"] and len(kick["reason"]) <= pc.KICK_REASON_MAX


def test_every_privileged_command_has_a_role_and_handler(env):
    _, plugin = env
    handlers = plugin._privileged_commands()
    assert set(handlers) == set(pc.PRIVILEGED_COMMANDS)
    assert not set(handlers) & set(plugin._public_commands())
    assert set(pc.PRIVILEGED_COMMANDS.values()) <= {pc.ROLE_CHANOP, pc.ROLE_ADMIN}


def test_unknown_role_denies(env):
    _, plugin = env
    assert run(plugin.authorize("ladmin", "superuser", "#one")) is False
    assert run(plugin.authorize("", pc.ROLE_ADMIN, "#one")) is False


def test_base_plugin_send_mode_matches_irc_consumer(env):
    core, plugin = env
    run(plugin.send_mode("#one", "+o", "nick"))
    run(plugin.send_mode("#one", "+m"))
    run(plugin.send_kick("#one", "nick", "r"))
    assert core.sent == [{"cmd": "mode", "channel": "#one", "modes": "+o nick"},
                         {"cmd": "mode", "channel": "#one", "modes": "+m"},
                         {"cmd": "kick", "channel": "#one", "nick": "nick", "reason": "r"}]
    bot = fake_irc_bot()
    for p in core.sent:
        bot.execute_command(p)
    assert bot.connection.mode.call_args_list == [mock.call("#one", "+o nick"),
                                                  mock.call("#one", "+m")]
    bot.connection.kick.assert_called_once_with("#one", "nick", "r")
