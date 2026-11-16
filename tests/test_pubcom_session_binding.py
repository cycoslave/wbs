"""
Offline regression tests for SAST-007: pubcom sessions must be bound to a
verified IRC identity, never to a nickname alone.

Acceptance under test:
  * nickname reuse from another identity (other user@host, other/missing
    services account, a client that changes nick *to* the session nick) is
    denied and never inherits the session;
  * QUIT, bot QUIT, IRC disconnect and a new IRC connection revoke sessions,
    and a stale session can't survive into a new connection epoch;
  * a nick change is a deliberate, safe invalidation: the session is NOT
    carried to the new nick, and re-identify under the new nick works;
  * revocation in the user DB (password change, delete, lock) ends the
    session on the next privileged command;
  * leaving every channel the bot shares with the user (PART/KICK, or the
    bot parting/being kicked) drops the session, since lifecycle events are
    then no longer observable;
  * valid identities keep working (repeat commands, RFC 1459 casemapping,
    matching services account);
  * irc.py exposes the server-set IRCv3 `account` tag to plugins.

Throwaway sqlite under pytest's tmp_path; no network, no IRC, no bot process.
"""
import asyncio
from types import SimpleNamespace
from unittest import mock

import irc.client
import pytest

from src.irc import WbsIrcBot, _account_tag
from src.plugins.pubcom import pubcomPlugin

# Shared offline fixtures from the SAST-006 suite (helpers only, no tests).
from test_pubcom_authz import FakeCore, build_db, host, identify, run, say  # noqa: E402


@pytest.fixture
def env(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    core = FakeCore(db)
    plugin = pubcomPlugin(core)
    return core, plugin


def ops(core) -> list[dict]:
    return [p for p in core.effects() if p.get("cmd") == "mode"]


async def ident_acct(plugin, nick, handle, account, hostmask=None):
    await plugin.on_PRIVMSG({"nick": nick, "host": hostmask or host(nick),
                             "text": f"identify {handle} correct-horse",
                             "target": "wbs", "account": account})


async def say_acct(plugin, nick, channel, text, account, hostmask=None):
    await plugin.on_PUBMSG({"nick": nick, "host": hostmask or host(nick),
                            "channel": channel, "text": text, "account": account})


def chan(*nicks):
    return SimpleNamespace(users=[n.lower() for n in nicks])


# ---------------------------------------------------------------------------
# 1. Nickname reuse from another identity is denied
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("other", [
    host("Boss", user="u", h="attacker.example"),     # other host
    host("Boss", user="evil", h="home.example"),      # other ident
])
def test_nick_reuse_from_other_connection_identity_denied(env, other):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        core.reset()
        await say(plugin, "Boss", "#one", "!op", hostmask=other)
    run(go())
    assert core.effects() == []
    assert "You must identify first" in core.notices()
    assert plugin.auth_sessions == {}


def test_nick_reuse_after_quit_from_same_looking_identity_requires_reidentify(env):
    """Owner quits; someone reconnects with the same nick (even the same
    user@host, e.g. a shared bouncer/NAT): the old session is gone."""
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        await plugin.on_QUIT({"nick": "Boss", "reason": "Quit"})
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
        await say(plugin, "Boss", "#one", "!op", hostmask=host("Boss", h="attacker.example"))
    run(go())
    assert core.effects() == []


def test_client_renaming_into_session_nick_does_not_inherit(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        # Another client takes the nick without the owner ever leaving it
        # (e.g. missed events): the stale entry is cleared, not handed over.
        await plugin.on_NICK({"old_nick": "thief", "new_nick": "BOSS"})
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert core.effects() == []
    assert plugin.auth_sessions == {}


@pytest.mark.parametrize("cmd_account", [None, "*", "mallory", ""])
def test_account_bound_session_rejects_other_or_missing_account(env, cmd_account):
    core, plugin = env

    async def go():
        await ident_acct(plugin, "Boss", "gop", "BossAcct")
        core.reset()
        await say_acct(plugin, "Boss", "#one", "!op", cmd_account)
    run(go())
    assert core.effects() == []
    assert plugin.auth_sessions == {}


def test_account_appearing_after_unaccounted_identify_requires_reidentify(env):
    core, plugin = env

    async def go():
        await ident_acct(plugin, "Boss", "gop", None)
        core.reset()
        await say_acct(plugin, "Boss", "#one", "!op", "someaccount")
    run(go())
    assert core.effects() == []


def test_matching_account_is_case_insensitive_and_allowed(env):
    core, plugin = env

    async def go():
        await ident_acct(plugin, "Boss", "gop", "BossAcct")
        core.reset()
        await say_acct(plugin, "Boss", "#one", "!op", "bossacct")
        await say_acct(plugin, "Boss", "#one", "!voice", "BOSSACCT")
    run(go())
    assert [p["modes"] for p in ops(core)] == ["+o Boss", "+v Boss"]


# ---------------------------------------------------------------------------
# 2. QUIT / disconnect / reconnect revoke
# ---------------------------------------------------------------------------
def test_quit_revokes_and_reidentify_restores(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        await plugin.on_QUIT({"nick": "boss", "reason": "bye"})
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
        assert core.effects() == []
        await identify(plugin, "Boss", "gop")
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert len(ops(core)) == 1


def test_other_users_quit_does_not_touch_session(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        await plugin.on_QUIT({"nick": "someoneelse", "reason": "bye"})
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert len(ops(core)) == 1


@pytest.mark.parametrize("handler,event", [
    ("on_DISCONNECT", {}),
    ("on_READY", {"botname": "wbs"}),
    ("on_QUIT", {"nick": "WBS", "reason": "restart"}),      # the bot itself
])
def test_bot_lifecycle_revokes_every_session(env, handler, event):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        await identify(plugin, "Chief", "admin")
        await getattr(plugin, handler)(event)
        assert plugin.auth_sessions == {}
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
        await say(plugin, "Chief", "#one", "!rehash")
    run(go())
    assert core.effects() == []
    assert core.rehashed == 0


def test_stale_session_from_previous_connection_is_rejected(env):
    """Even if an entry survived (e.g. events lost), it is bound to the IRC
    connection epoch it was created in."""
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        saved = dict(plugin.auth_sessions)
        await plugin.on_DISCONNECT({})
        await plugin.on_READY({})
        plugin.auth_sessions.update(saved)          # simulate a leaked entry
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert core.effects() == []
    assert plugin.auth_sessions == {}


# ---------------------------------------------------------------------------
# 3. Nick change: intentional invalidation, safe re-identify
# ---------------------------------------------------------------------------
def test_nick_change_invalidates_and_new_nick_must_reidentify(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        await plugin.on_NICK({"old_nick": "Boss", "new_nick": "Boss_away"})
        core.reset()
        await say(plugin, "Boss_away", "#one", "!op", hostmask=host("Boss_away"))
        await say(plugin, "Boss", "#one", "!op")
        assert core.effects() == []
        assert set(core.notices()) == {"You must identify first"}
        await identify(plugin, "Boss_away", "gop")
        core.reset()
        await say(plugin, "Boss_away", "#one", "!op", hostmask=host("Boss_away"))
    run(go())
    assert len(ops(core)) == 1


def test_rfc1459_casemapping_same_nick(env):
    """'Boss[]' and 'boss{}' are the same nick under RFC 1459: a QUIT under
    either spelling ends the session, and the session works under either."""
    core, plugin = env

    async def go():
        await identify(plugin, "Boss[]", "gop", hostmask="Boss[]!u@home.example")
        core.reset()
        await say(plugin, "boss{}", "#one", "!op", hostmask="boss{}!u@home.example")
        assert len(ops(core)) == 1
        await plugin.on_QUIT({"nick": "BOSS{}"})
        core.reset()
        await say(plugin, "Boss[]", "#one", "!op", hostmask="Boss[]!u@home.example")
    run(go())
    assert core.effects() == []


# ---------------------------------------------------------------------------
# 4. Revocation in the user database
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("revoke", [
    lambda u: u.set_password("gop", "rotated-secret"),
    lambda u: u.deluser("gop", deleted_by="test"),
    lambda u: u.set_locked("gop", True),
])
def test_user_revocation_ends_session(env, revoke):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        await say(plugin, "Boss", "#one", "!op")
        assert len(ops(core)) == 1
        await revoke(core.user)
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert core.effects() == []
    assert plugin.auth_sessions == {}


def test_reverify_fails_closed_on_db_error(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        core.reset()
        with mock.patch.object(core.user, "get", side_effect=RuntimeError("db down")):
            await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert core.effects() == []


# ---------------------------------------------------------------------------
# 5. Losing visibility (PART/KICK) drops the session
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("handler,event", [
    ("on_PART", {"nick": "Boss", "channel": "#one", "reason": ""}),
    ("on_KICK", {"nick": "op", "kicked": "Boss", "channel": "#one", "reason": ""}),
])
def test_leaving_last_shared_channel_revokes(env, handler, event):
    core, plugin = env
    core.channels = {"#one": chan("wbs", "boss"), "#two": chan("wbs")}

    async def go():
        await identify(plugin, "Boss", "gop")
        await getattr(plugin, handler)(event)
        core.reset()
        await say(plugin, "Boss", "#two", "!op")
    run(go())
    assert core.effects() == []
    assert plugin.auth_sessions == {}


def test_leaving_one_of_two_shared_channels_keeps_session(env):
    core, plugin = env
    core.channels = {"#one": chan("wbs", "boss"), "#two": chan("wbs", "Boss")}

    async def go():
        await identify(plugin, "Boss", "gop")
        await plugin.on_PART({"nick": "Boss", "channel": "#one", "reason": ""})
        core.reset()
        await say(plugin, "Boss", "#two", "!op")
    run(go())
    assert len(ops(core)) == 1


@pytest.mark.parametrize("handler,event", [
    ("on_PART", {"nick": "wbs", "channel": "#one", "reason": ""}),
    ("on_KICK", {"nick": "op", "kicked": "WBS", "channel": "#one", "reason": ""}),
])
def test_bot_leaving_channel_drops_only_users_no_longer_visible(env, handler, event):
    core, plugin = env
    core.channels = {"#one": chan("wbs", "boss", "chief"), "#two": chan("wbs", "chief")}

    async def go():
        await identify(plugin, "Boss", "gop")
        await identify(plugin, "Chief", "gop")
        await getattr(plugin, handler)(event)
    run(go())
    assert set(plugin.auth_sessions) == {"chief"}


# ---------------------------------------------------------------------------
# 6. Valid identity behaviour preserved
# ---------------------------------------------------------------------------
def test_valid_session_keeps_working_across_commands(env):
    core, plugin = env

    async def go():
        await identify(plugin, "Boss", "gop")
        core.reset()
        for line in ("!op", "!voice victim", "!devoice victim", "!kick victim bye"):
            await say(plugin, "Boss", "#one", line)
    run(go())
    assert [p["cmd"] for p in core.effects()] == ["mode", "mode", "mode", "kick"]
    sess = plugin.auth_sessions["boss"]
    assert sess["handle"] == "gop"
    assert sess["hostmask"] == "boss!u@home.example"
    assert sess["account"] is None
    assert sess["cred"] and "correct-horse" not in sess["cred"]


def test_unknown_nick_events_are_harmless(env):
    core, plugin = env

    async def go():
        await plugin.on_NICK({})
        await plugin.on_QUIT({})
        await plugin.on_PART({})
        await plugin.on_KICK({})
        await identify(plugin, "Boss", "gop")
        await plugin.on_PART({"nick": "x", "channel": "#one"})   # no channel state
        core.reset()
        await say(plugin, "Boss", "#one", "!op")
    run(go())
    assert len(ops(core)) == 1


# ---------------------------------------------------------------------------
# 7. irc.py surfaces the IRCv3 account tag
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("tags,expected", [
    (None, None),
    ([], None),
    ([{"key": "account", "value": "bob"}], "bob"),
    ([{"key": "time", "value": "x"}, {"key": "account", "value": "Bob"}], "Bob"),
    ([{"key": "account", "value": "*"}], None),
    ([{"key": "account", "value": None}], None),
    ([{"key": "+account", "value": "bob"}], None),          # client-only tag
    ([{"key": "account", "value": "a b"}], None),
    ([{"key": "account", "value": "a\r\nb"}], None),
])
def test_account_tag_parsing(tags, expected):
    ev = irc.client.Event("pubmsg", irc.client.NickMask("n!u@h"), "#c", ["hi"], tags)
    assert _account_tag(ev) == expected


def test_irc_pubmsg_and_privmsg_emit_account():
    bot = object.__new__(WbsIrcBot)
    emitted = []
    bot._emit_event = emitted.append
    src = irc.client.NickMask("Boss!u@home.example")
    tags = [{"key": "account", "value": "bossacct"}]
    bot.on_pubmsg(None, irc.client.Event("pubmsg", src, "#one", ["!op"], tags))
    bot.on_privmsg(None, irc.client.Event("privmsg", src, "wbs", ["identify x"], None))
    assert emitted[0]["account"] == "bossacct"
    assert emitted[0]["host"] == "Boss!u@home.example"
    assert emitted[1]["account"] is None
