"""
Regression tests for SAST-001: plugin `on_PUBMSG` handlers ran BEFORE the
Core public flood check (Core dispatched to plugins, then `Core.on_pubmsg`
counted flood_pub), so a flooding channel user could drive pubcom's
network-capable public commands (`!website`, `!youtube`, ...) and url title
fetches at will.  The flood decision for public channel text is now made in
`Core.handle_event` before any plugin or game runs; a flooding host's text is
dropped there for the channel's flood_pub_time window, opped or not.

Raw server lines go through the real WbsIrcBot reactor into the real Core
and the real pubcom/url plugin `on_PUBMSG` routing; only the outbound
network work (`cmd_website`, `cmd_youtube`, `fetch_title`) is replaced by
recorders.  Time is a fake clock.  Throwaway sqlite DB per test.
"""
import asyncio
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import pytest

from src.flood import FloodGuard, FloodProtect
from src.plugins.pubcom import pubcomPlugin
from src.plugins.url import urlPlugin

from test_automode import env as _automode_env  # noqa: E402,F401
from test_flood import RANDO, env as _flood_env, lines, ready  # noqa: E402,F401
from test_irc_channel_sync import BOT, pump  # noqa: E402

LIMIT, WINDOW = 5, 10
WEBSITE = "!website https://example.com/"
YOUTUBE = "!youtube https://youtube.com/watch?v=test"
LINK = "look https://example.com/page"


class Probe:
    """A plugin that records every public-text event it is handed."""
    name = "probe"

    def __init__(self):
        self.seen: list = []

    async def on_PUBMSG(self, event):
        self.seen.append(("PUBMSG", event.get("nick"), event.get("text")))

    async def on_ACTION(self, event):
        self.seen.append(("ACTION", event.get("nick"), event.get("text")))

    async def on_CHAN_ACTIVITY(self, event):
        self.seen.append(("CHAN_ACTIVITY", event.get("nick"), event.get("kind")))


def _count_calls(plugin, calls: list):
    original = plugin.on_PUBMSG

    async def on_PUBMSG(event):
        calls.append((plugin.name, event.get("nick"), event.get("text")))
        await original(event)
    plugin.on_PUBMSG = on_PUBMSG


@pytest.fixture
def env(_flood_env):
    core, irc, sent, clock = _flood_env
    core.botnet = NS(peers={})                  # url.is_exempt reads it
    pubcom = pubcomPlugin(core)
    pubcom.is_pubcom_enabled = AsyncMock(return_value=True)
    pubcom.cmd_website = AsyncMock()            # outbound HTTP
    pubcom.cmd_youtube = AsyncMock()            # outbound HTTP
    url = urlPlugin(core)
    url.fetch_title = AsyncMock(return_value=None)   # outbound HTTP
    probe = Probe()
    calls: list = []
    _count_calls(pubcom, calls)
    _count_calls(url, calls)
    core.plugin.plugins = {"pubcom": pubcom, "url": url, "probe": probe}
    return NS(core=core, irc=irc, sent=sent, clock=clock, pubcom=pubcom, url=url,
              probe=probe, calls=calls, game=core.game)


def ready_env(e, **kw):
    ready(e.core, e.irc, e.sent, e.clock, flood_pub=LIMIT, flood_pub_time=WINDOW, **kw)


def say(e, who, *texts, chan="#wbs", step=1.0):
    return lines(e.core, e.irc, e.sent, e.clock,
                 *[f":{who} PRIVMSG {chan} :{t}" for t in texts], step=step)


def network_work(e) -> int:
    return (e.pubcom.cmd_website.await_count + e.pubcom.cmd_youtube.await_count
            + e.url.fetch_title.await_count)


def _reset(e):
    e.pubcom.cmd_website.reset_mock()
    e.pubcom.cmd_youtube.reset_mock()
    e.url.fetch_title.reset_mock()
    e.calls.clear()
    e.probe.seen.clear()
    e.game.pub.clear()


# ---------------------------------------------------------------------------
# Allowed text: reaches every plugin and the games exactly once
# ---------------------------------------------------------------------------
def test_allowed_event_reaches_pubcom_url_and_games_once(env):
    e = env
    ready_env(e)
    assert say(e, RANDO, WEBSITE, YOUTUBE, LINK) == []
    e.pubcom.cmd_website.assert_awaited_once_with(
        "rando", RANDO, "#wbs", "https://example.com/")
    e.pubcom.cmd_youtube.assert_awaited_once_with(
        "rando", RANDO, "#wbs", "https://youtube.com/watch?v=test")
    e.url.fetch_title.assert_awaited_once_with("https://example.com/page")
    texts = [WEBSITE, YOUTUBE, LINK]
    assert e.calls == [(p, "rando", t) for t in texts for p in ("pubcom", "url")]
    assert e.probe.seen == [("PUBMSG", "rando", t) for t in texts]
    assert e.game.pub == [("#wbs", "rando", t) for t in texts]


def test_up_to_the_limit_is_never_dropped(env):
    """Counted once per message (Core.on_pubmsg no longer counts again):
    exactly flood_pub messages in the window all get through."""
    e = env
    ready_env(e)
    assert say(e, RANDO, *[WEBSITE] * LIMIT) == []
    assert e.pubcom.cmd_website.await_count == LIMIT
    assert len(e.game.pub) == LIMIT


# ---------------------------------------------------------------------------
# Flooded text: never reaches any plugin handler or a game
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("trigger", [WEBSITE, YOUTUBE, LINK])
def test_flooded_event_never_reaches_plugins_or_games(env, trigger):
    e = env
    ready_env(e)
    assert say(e, RANDO, *[f"chatter {i}" for i in range(LIMIT)]) == []
    _reset(e)
    # The (LIMIT+1)th inside the window: kicked + banned, and dropped.
    assert say(e, RANDO, trigger) == [
        "MODE #wbs +b *!*@stranger.example", "KICK #wbs rando :Channel flood"]
    assert network_work(e) == 0
    assert e.calls == [] and e.probe.seen == [] and e.game.pub == []
    # Lines already in flight (sent before the ban landed) stay dropped.
    pump(e.core, e.irc, f":{BOT}!~wbs@bot.example KICK #wbs rando :Channel flood")
    assert say(e, RANDO, WEBSITE, YOUTUBE, LINK, step=0.5) == []
    assert network_work(e) == 0
    assert e.calls == [] and e.probe.seen == [] and e.game.pub == []


def test_flood_without_op_still_drops_and_mutes_for_the_window(env):
    """No op: nothing can be kicked, but the flood decision still holds;
    the host's text is dropped until flood_pub_time has passed."""
    e = env
    ready_env(e, bot_prefix="")
    burst = [WEBSITE, YOUTUBE, LINK] * 10                  # 30 lines, 0.1 s apart
    assert say(e, RANDO, *burst, step=0.1) == []            # no op: nothing sent
    assert e.pubcom.cmd_website.await_count + e.pubcom.cmd_youtube.await_count \
        + e.url.fetch_title.await_count == LIMIT
    assert len(e.game.pub) == LIMIT and len(e.probe.seen) == LIMIT
    _reset(e)
    # Still inside the mute: dropped.
    e.clock.tick(WINDOW - 4)
    assert say(e, RANDO, YOUTUBE) == []
    assert network_work(e) == 0 and e.game.pub == [] and e.probe.seen == []
    # Mute over: heard again, once.
    e.clock.tick(WINDOW)
    assert say(e, RANDO, YOUTUBE) == []
    e.pubcom.cmd_youtube.assert_awaited_once()
    assert e.game.pub == [("#wbs", "rando", YOUTUBE)]


def test_flood_state_is_per_host(env):
    """Same host, another nick: muted too; another host: unaffected."""
    e = env
    ready_env(e)
    pump(e.core, e.irc, ":clone!~c@stranger.example JOIN #wbs",
         ":other!~o@elsewhere.example JOIN #wbs")
    say(e, RANDO, *["x"] * (LIMIT + 1), step=0.1)
    _reset(e)
    assert say(e, "clone!~c@stranger.example", WEBSITE) == []
    assert network_work(e) == 0 and e.game.pub == []
    assert say(e, "other!~o@elsewhere.example", WEBSITE, YOUTUBE, LINK) == []
    assert network_work(e) == 3
    assert [n for _, n, _ in e.game.pub] == ["other"] * 3


@pytest.mark.parametrize("who", ["own!~own@own.example",       # owner
                                 "oper!~oper@oper.example"])   # recognised +o
def test_exempt_users_are_never_dropped(env, who):
    e = env
    ready_env(e)
    assert say(e, who, *[WEBSITE] * 12, step=0.1) == []
    assert e.pubcom.cmd_website.await_count == 12
    assert len(e.game.pub) == 12


def test_opped_stranger_is_exempt_and_op_lifts_a_mute(env):
    e = env
    ready_env(e, bot_prefix="")
    say(e, RANDO, *["x"] * (LIMIT + 1), step=0.1)
    _reset(e)
    pump(e.core, e.irc, ":ChanServ!s@services. MODE #wbs +o rando")
    assert say(e, RANDO, *[WEBSITE] * 12, step=0.1) == []
    assert e.pubcom.cmd_website.await_count == 12


def test_action_and_channel_notice_are_gated_too(env):
    """/me and channel NOTICE count against flood_pub; once the host is
    muted, its ACTION never reaches plugins either."""
    e = env
    ready_env(e)
    out = lines(e.core, e.irc, e.sent, e.clock,
                *[f":{RANDO} PRIVMSG #wbs :\x01ACTION waves\x01"] * 3,
                *[f":{RANDO} NOTICE #wbs :hi"] * 3, step=0.1)
    assert out == ["MODE #wbs +b *!*@stranger.example", "KICK #wbs rando :Channel flood"]
    # Only text counts here (an ACTION is also a CTCP: flood_ctcp is off).
    seen = [k for k, _, kind in e.probe.seen if kind != "ctcp"]
    # 3 actions (CHAN_ACTIVITY + ACTION each) and 2 notices pass; the 6th
    # counted event (a NOTICE) is dropped.
    assert seen == ["CHAN_ACTIVITY", "ACTION"] * 3 + ["CHAN_ACTIVITY"] * 2
    _reset(e)
    say(e, RANDO, f"\x01ACTION {WEBSITE}\x01", WEBSITE, step=0.1)
    assert [s for s in e.probe.seen if s[2] != "ctcp"] == []
    assert network_work(e) == 0 and e.game.pub == []


def test_flood_limits_off_gate_nothing(env):
    e = env
    ready(e.core, e.irc, e.sent, e.clock, flood_pub=0, flood_pub_time=WINDOW)
    assert say(e, RANDO, *[YOUTUBE] * 30, step=0.1) == []
    assert e.pubcom.cmd_youtube.await_count == 30
    assert len(e.game.pub) == 30


def test_gate_runs_before_plugin_dispatch(env):
    """Ordering contract: the flood decision is taken before the first
    plugin handler is entered, not after."""
    e = env
    ready_env(e)
    order: list = []
    fp = e.core.flood
    real_public = fp.public

    async def public(*a, **kw):
        order.append("flood")
        return await real_public(*a, **kw)
    fp.public = public

    async def probe_pubmsg(event):
        order.append("plugin")
    e.probe.on_PUBMSG = probe_pubmsg

    async def game(channel, nick, text, event=None):
        order.append("game")
    e.game.dispatch_pubmsg = game
    say(e, RANDO, "hello")
    assert order == ["flood", "plugin", "game"]


# ---------------------------------------------------------------------------
# FloodProtect.public: per-channel state (unit level)
# ---------------------------------------------------------------------------
class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Chan:
    def __init__(self, name):
        self.name = name
        self.joined = True
        self.bot_op = False
        self.hosts: dict = {}
        self.users: dict = {}
        self.live_bans: set = set()

    def is_op(self, nick):
        return False


def test_flood_state_is_per_channel():
    chans = {"#a": Chan("#a"), "#b": Chan("#b")}
    core = NS(botname="bot", get_chan=lambda n: chans.get(n.lower()),
              send_irc=lambda p: None, config={})
    fp = FloodProtect(core, clock=Clock())

    async def settings(channel):
        return {"flood_pub": 2, "flood_pub_time": 10}
    fp.settings = settings

    async def not_exempt(*a, **kw):
        return False
    fp.exempt = not_exempt

    async def go():
        host = "x!~x@flood.example"
        a = [await fp.public("#a", "x", host) for _ in range(4)]
        b = [await fp.public("#b", "x", host) for _ in range(2)]
        return a, b
    a, b = asyncio.run(go())
    assert a == [False, False, True, True]       # 3rd floods #a, 4th still muted
    assert b == [False, False]                   # #b has its own counter
    assert isinstance(fp.guard, FloodGuard)


def test_mute_table_is_bounded(monkeypatch):
    from src import flood
    monkeypatch.setattr(flood, "MAX_KEYS", 3)
    fp = FloodProtect(NS(config={}), clock=Clock())
    for i in range(10):
        fp._mute(("pub", "#a", f"h{i}"), 2000.0 + i, 1000.0)
    assert len(fp.muted) == 3
    assert ("pub", "#a", "h9") in fp.muted
