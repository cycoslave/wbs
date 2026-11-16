"""
Regression tests for IRC-7: the channels table's flood_* limits were stored
and shown (`.chaninfo`) but nothing read them; there was no flood
protection at all.

Raw server lines go through the real WbsIrcBot reactor into the real Core
(helpers shared with test_irc_channel_sync / test_automode); what the bot
sends back is the real IRC-side output of the payloads Core queued.  Time
is a fake clock.  Throwaway sqlite DB per test.
"""
import asyncio
import logging

import pytest

from src import flood
from src.configcheck import validate_config
from src.db import get_db
from src.flood import FloodGuard, FloodProtect, parse_rate

from test_irc_channel_sync import BOT, SRV, FakeDcc, pump  # noqa: E402
from test_automode import env as _automode_env, flush, join_synced, set_chan  # noqa: E402,F401


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def tick(self, seconds: float) -> None:
        self.t += seconds


class FakeGame:
    def __init__(self):
        self.pub: list = []
        self.priv: list = []

    async def dispatch_pubmsg(self, channel, nick, text, event=None):
        self.pub.append((channel, nick, text))

    async def dispatch_privmsg(self, nick, text, event=None):
        self.priv.append((nick, text))


class PmDcc(FakeDcc):
    async def on_privmsg(self, event):
        return False


@pytest.fixture
def env(_automode_env):
    core, irc, sent = _automode_env
    clock = Clock()
    core.flood = FloodProtect(core, clock=clock)
    core.game = FakeGame()
    core.dcc = PmDcc()
    core.handlers.update({
        "PUBMSG": core.on_pubmsg, "PRIVMSG": core.on_privmsg,
        "CHAN_ACTIVITY": core.on_chan_activity, "FLOOD_IGNORE": core.on_flood_ignore,
    })
    irc.ctcp_guard = FloodGuard(clock)
    # Channel tests: no limit hit for anything but the setting under test.
    set_chan(core, flood_pub=0, flood_ctcp=0, flood_join=0, flood_kick=0,
             flood_deop=0, flood_nick=0)
    return core, irc, sent, clock


def lines(core, irc, sent, clock, *raw, step=1.0) -> list[str]:
    """Feed `raw` lines `step` seconds apart; return what the bot sent."""
    flush(core, irc, sent)
    out = []
    for line in raw:
        pump(core, irc, line)
        out += flush(core, irc, sent)
        clock.tick(step)
    return out


def say(who: str, n: int, chan: str = "#wbs") -> list[str]:
    return [f":{who} PRIVMSG {chan} :line {i}" for i in range(n)]


RANDO = "rando!~r@stranger.example"
PRESENT = (f"{RANDO} oper!~oper@oper.example own!~own@own.example "
           "pee!~pee@pee.example evil!~e@evil.example")


def ready(core, irc, sent, clock, bot_prefix="@", **cols):
    set_chan(core, **cols)
    core.flood.invalidate()
    join_synced(core, irc, sent, bot_prefix=bot_prefix, present=PRESENT)


# ---------------------------------------------------------------------------
# FloodGuard / rate parsing
# ---------------------------------------------------------------------------
def test_guard_sliding_window():
    clock = Clock()
    g = FloodGuard(clock)
    assert [g.hit("k", 5, 10) for _ in range(5)] == [False] * 5
    assert g.hit("k", 5, 10) is True          # 6th inside 10 s
    assert g.hit("k", 5, 10) is False         # starts over after a trigger
    g2 = FloodGuard(clock)
    hits = []
    for _ in range(12):                       # 1 event / 2.5 s: never > 5 in 10 s
        hits.append(g2.hit("k", 5, 10))
        clock.tick(2.5)
    assert not any(hits)


def test_guard_zero_is_disabled():
    g = FloodGuard(Clock())
    assert not any(g.hit("k", 0, 10) for _ in range(50))
    assert not any(g.hit("k", 5, 0) for _ in range(50))
    assert len(g) == 0


def test_guard_prunes_idle_keys():
    clock = Clock()
    g = FloodGuard(clock, max_keys=10)
    for i in range(10):
        g.hit(i, 5, 10)
    clock.tick(11)
    g.hit("new", 5, 10)
    assert len(g) == 1


@pytest.mark.parametrize("value,want", [("5:60", (5, 60)), ("0", None), (0, None),
                                        ("0:60", None), ("5:0", None), (" 3:10 ", (3, 10))])
def test_parse_rate(value, want):
    assert parse_rate(value) == want


@pytest.mark.parametrize("value", ["5", "a:b", "5:-1", "5/60", 5, True, None, [5, 60]])
def test_parse_rate_rejects(value):
    with pytest.raises(ValueError):
        parse_rate(value)


def test_configcheck_flags_bad_rate():
    cfg = {"settings": {"flood_msg": "lots", "flood_ctcp": "3:60"}}
    errors, _ = validate_config(cfg, require_bot=False)
    assert [p for p, _ in errors] == ["settings.flood_msg"]
    assert validate_config({"settings": {"flood_msg": 0}}, require_bot=False)[0] == []


# ---------------------------------------------------------------------------
# flood_pub
# ---------------------------------------------------------------------------
def test_pub_flood_kicks_and_bans_once(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_pub=5, flood_pub_time=10)
    # 5 lines in 10 s: allowed.
    assert lines(core, irc, sent, clock, *say(RANDO, 5)) == []
    # 6th inside the window: kicked once, host banned.
    assert lines(core, irc, sent, clock, *say(RANDO, 1)) == [
        "MODE #wbs +b *!*@stranger.example", "KICK #wbs rando :Channel flood"]
    pump(core, irc, f":{BOT}!~wbs@bot.example KICK #wbs rando :Channel flood")
    # Messages already in flight do not cause a second kick.
    assert lines(core, irc, sent, clock, *say(RANDO, 4)) == []


def test_pub_flood_slow_talker_untouched(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_pub=5, flood_pub_time=10)
    assert lines(core, irc, sent, clock, *say(RANDO, 20), step=2.5) == []


def test_pub_flood_counts_per_host(env):
    """Same host, different nicks: one counter."""
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_pub=5, flood_pub_time=10)
    pump(core, irc, ":clone!~c@stranger.example JOIN #wbs")
    out = lines(core, irc, sent, clock, *say(RANDO, 3), *say("clone!~c@stranger.example", 3))
    assert out == ["MODE #wbs +b *!*@stranger.example", "KICK #wbs clone :Channel flood"]


def test_pub_flood_counts_actions_and_notices(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_pub=2, flood_pub_time=10)
    out = lines(core, irc, sent, clock,
                f":{RANDO} PRIVMSG #wbs :\x01ACTION waves\x01",
                f":{RANDO} NOTICE #wbs :hi",
                f":{RANDO} PRIVMSG #wbs :again")
    assert out == ["MODE #wbs +b *!*@stranger.example", "KICK #wbs rando :Channel flood"]


@pytest.mark.parametrize("who", ["oper!~oper@oper.example",     # recognised +o
                                 "own!~own@own.example",        # owner
                                 f"{BOT}!~wbs@bot.example"])    # the bot itself
def test_pub_flood_exempt_users(env, who):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_pub=5, flood_pub_time=10)
    assert lines(core, irc, sent, clock, *say(who, 12)) == []


def test_pub_flood_opped_stranger_exempt(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_pub=5, flood_pub_time=10)
    pump(core, irc, f":ChanServ!s@services. MODE #wbs +o rando")
    assert lines(core, irc, sent, clock, *say(RANDO, 12)) == []


@pytest.mark.parametrize("cols", [{"flood_pub": 0, "flood_pub_time": 10},
                                  {"flood_pub": 5, "flood_pub_time": 0}])
def test_pub_flood_disabled(env, cols):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, **cols)
    assert lines(core, irc, sent, clock, *say(RANDO, 30), step=0.1) == []


def test_pub_flood_without_op_logs_once(env, caplog):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, bot_prefix="", flood_pub=2, flood_pub_time=10)
    with caplog.at_level(logging.WARNING, logger="wbs.flood"):
        assert lines(core, irc, sent, clock, *say(RANDO, 12), step=0.1) == []
    no_op = [r for r in caplog.records if "no op" in r.getMessage()]
    assert len(no_op) == 1, [r.getMessage() for r in caplog.records]


def test_pub_flood_inactive_channel(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_pub=2, flood_pub_time=10, is_inactive=1)
    assert lines(core, irc, sent, clock, *say(RANDO, 10)) == []


def test_flood_ban_is_lifted(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_pub=2, flood_pub_time=10)
    assert lines(core, irc, sent, clock, *say(RANDO, 3))[0] == "MODE #wbs +b *!*@stranger.example"
    pump(core, irc, f":{BOT}!~wbs@bot.example MODE #wbs +b *!*@stranger.example")
    core.flood.expire_bans()
    assert flush(core, irc, sent) == []
    clock.tick(flood.FLOOD_BAN_SECONDS)
    core.flood.expire_bans()
    assert flush(core, irc, sent) == ["MODE #wbs -b *!*@stranger.example"]


# ---------------------------------------------------------------------------
# flood_ctcp / flood_join / flood_nick
# ---------------------------------------------------------------------------
def test_channel_ctcp_flood(env):
    core, irc, sent, clock = env
    irc.ctcp_rate = None            # the bot's own CTCP limit: tested below
    ready(core, irc, sent, clock, flood_ctcp=3, flood_ctcp_time=60)
    out = lines(core, irc, sent, clock, *[f":{RANDO} PRIVMSG #wbs :\x01VERSION\x01"] * 3)
    assert out == []
    out = lines(core, irc, sent, clock, f":{RANDO} PRIVMSG #wbs :\x01VERSION\x01")
    assert out == ["MODE #wbs +b *!*@stranger.example", "KICK #wbs rando :CTCP flood"]


def test_join_flood(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_join=3, flood_join_time=60)
    flap = [":j!~j@joiner.example JOIN #wbs", ":j!~j@joiner.example PART #wbs"]
    assert lines(core, irc, sent, clock, *flap * 3) == []
    out = lines(core, irc, sent, clock, ":j!~j@joiner.example JOIN #wbs")
    assert out == ["MODE #wbs +b *!*@joiner.example", "KICK #wbs j :Join flood"]


def test_join_flood_disabled(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_join=0, flood_join_time=60)
    flap = [":j!~j@joiner.example JOIN #wbs", ":j!~j@joiner.example PART #wbs"]
    assert lines(core, irc, sent, clock, *flap * 10) == []


def test_nick_flood(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_nick=3, flood_nick_time=60)
    out = lines(core, irc, sent, clock, f":{RANDO} NICK n1", ":n1!~r@stranger.example NICK n2",
                ":n2!~r@stranger.example NICK n3")
    assert out == []
    out = lines(core, irc, sent, clock, ":n3!~r@stranger.example NICK n4")
    assert out == ["KICK #wbs n4 :Nick flood"]     # kick, no ban


def test_nick_flood_exempt_owner(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_nick=1, flood_nick_time=60)
    out = lines(core, irc, sent, clock, ":own!~own@own.example NICK o1",
                ":o1!~own@own.example NICK o2", ":o2!~own@own.example NICK o3")
    assert out == []


# ---------------------------------------------------------------------------
# flood_kick / flood_deop: the op doing it is deopped
# ---------------------------------------------------------------------------
def test_kick_flood_deops_the_op(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_kick=2, flood_kick_time=10)
    pump(core, irc, ":ChanServ!s@services. MODE #wbs +o evil")
    out = lines(core, irc, sent, clock, ":evil!~e@evil.example KICK #wbs pee :x",
                f":evil!~e@evil.example KICK #wbs rando :x")
    assert out == []
    out = lines(core, irc, sent, clock, ":evil!~e@evil.example KICK #wbs oper :x")
    assert out == ["MODE #wbs -o evil"]


def test_kick_flood_by_recognised_op_untouched(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_kick=1, flood_kick_time=10)
    pump(core, irc, ":ChanServ!s@services. MODE #wbs +o oper")
    out = lines(core, irc, sent, clock, ":oper!~oper@oper.example KICK #wbs pee :x",
                f":oper!~oper@oper.example KICK #wbs rando :x",
                ":oper!~oper@oper.example KICK #wbs evil :x")
    assert out == []


def test_deop_flood_deops_the_op(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_deop=2, flood_deop_time=10)
    pump(core, irc, ":ChanServ!s@services. MODE #wbs +ooo evil pee rando")
    out = lines(core, irc, sent, clock, ":evil!~e@evil.example MODE #wbs -oo pee rando")
    assert out == []
    pump(core, irc, ":ChanServ!s@services. MODE #wbs +o pee")
    out = lines(core, irc, sent, clock, ":evil!~e@evil.example MODE #wbs -o pee")
    assert out == ["MODE #wbs -o evil"]


def test_deop_flood_by_server_or_bot_ignored(env):
    core, irc, sent, clock = env
    ready(core, irc, sent, clock, flood_deop=1, flood_deop_time=10)
    pump(core, irc, ":ChanServ!s@services. MODE #wbs +ooo evil pee rando")
    out = lines(core, irc, sent, clock, f":{BOT}!~wbs@bot.example MODE #wbs -ooo evil pee rando",
                f"{SRV} MODE #wbs -o oper")
    assert out == []


# ---------------------------------------------------------------------------
# The bot's own private-message / CTCP limit
# ---------------------------------------------------------------------------
def ignore_rows(core):
    async def go():
        async with get_db(core.db_path) as d:
            return [dict(r) for r in await d.execute_fetchall(
                "SELECT hostmask, flags FROM ignores WHERE deleted_at IS NULL")]
    return asyncio.run(go())


def test_pm_flood_drops_and_ignores_sender(env):
    core, irc, sent, clock = env
    flush(core, irc, sent)
    for i in range(7):
        pump(core, irc, f":{RANDO} PRIVMSG {BOT} :hello {i}")
        clock.tick(1)
    # Default 5:60 -> the first 5 are processed, the 6th and 7th are dropped.
    assert [t for _, t in core.game.priv] == [f"hello {i}" for i in range(5)]
    assert ignore_rows(core) == [{"hostmask": "*!*@stranger.example", "flags": "1m"}]
    payloads = list(core.irc_q.items)
    assert {"cmd": "reload_ignores"} in payloads
    # After 60 s the sender is heard again (Core side; the ignore row
    # expires the same way).
    clock.tick(flood.PRIVATE_IGNORE_SECONDS)
    pump(core, irc, f":{RANDO} PRIVMSG {BOT} :back")
    assert core.game.priv[-1] == ("rando", "back")


def test_pm_flood_owner_never_ignored(env):
    core, irc, sent, clock = env
    for i in range(10):
        pump(core, irc, f":own!~own@own.example PRIVMSG {BOT} :x{i}")
    assert len(core.game.priv) == 10
    assert ignore_rows(core) == []


def test_pm_flood_disabled(env):
    core, irc, sent, clock = env
    core.config["settings"] = {"flood_msg": "0"}
    core.flood = FloodProtect(core, clock=clock)
    for i in range(20):
        pump(core, irc, f":{RANDO} PRIVMSG {BOT} :x{i}")
    assert len(core.game.priv) == 20
    assert ignore_rows(core) == []


def test_ctcp_flood_to_bot(env):
    core, irc, sent, clock = env
    replies = []
    for i in range(5):
        sent.clear()
        pump(core, irc, f":{RANDO} PRIVMSG {BOT} :\x01VERSION\x01")
        replies += [s for s in sent if s.startswith("NOTICE rando")]
    # Default 3:60: three answers, then silence.
    assert len(replies) == 3, replies
    assert ignore_rows(core) == [{"hostmask": "*!*@stranger.example", "flags": "1m"}]
    # Everything else from that host is dropped in the reactor too.
    pump(core, irc, f":{RANDO} PRIVMSG {BOT} :hello")
    assert core.game.priv == []


def test_ctcp_flood_owner_still_answered(env):
    core, irc, sent, clock = env
    replies = []
    for i in range(6):
        sent.clear()
        pump(core, irc, f":own!~own@own.example PRIVMSG {BOT} :\x01VERSION\x01")
        replies += [s for s in sent if s.startswith("NOTICE own")]
    assert len(replies) == 6
    assert ignore_rows(core) == []
