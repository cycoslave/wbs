"""
Regression tests for game input/output wiring and round flow
(GAM-6, GAM-11, GAM-13).

GAM-6   GameManager.tick() was never called (lottery's daily draw could not
        fire) and NOTICEs from users never reached dispatch_notice
        (werewolf night actions were impossible).
GAM-11  Round loops ran inside the pubmsg handler and blocked event
        dispatch; poker never prompted the next player after an action
        (hands ended by the 60 s auto-fold); werewolf day votes were not
        counted until the round ended.
GAM-13  {'cmd': 'notice'} went out as PRIVMSG; poker hole cards were resent
        with every prompt.

Throwaway sqlite DB per test, real game modules, fake IRC (recorded
payloads), fake clock for the lottery draw.  Turn / phase timeouts are set
far above the per-test deadline, so a test that passes cannot have relied
on a timeout.
"""
import asyncio
import queue
from datetime import datetime, timezone
from types import SimpleNamespace as NS

import pytest

from src.core import Core
from src.db import init_db
from src.games import Game, GameManager
import src.games.lottery as lottery_mod
import src.games.poker as poker_mod
import src.games.werewolf as werewolf_mod

from test_irc_channel_sync import make_irc

DEADLINE = 30          # seconds; every phase timeout below is far longer
LONG = 600
QUICK = 5              # a handler's own DB work, even on a loaded box; a
                       # handler awaiting a round would wait LONG instead


class FakeCore:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        self.sent: list[dict] = []
        self.config = {"games": []}
        self.ops: set[str] = set()
        self.game = GameManager(self)

    def send_irc(self, payload):
        self.sent.append(payload)

    def nick_isop(self, nick, channel):
        return nick in self.ops

    def texts(self, target=None, cmd=None):
        return [p["text"] for p in self.sent
                if (target is None or p.get("target") == target)
                and (cmd is None or p.get("cmd") == cmd)]


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "games.db"
    asyncio.run(init_db(str(path)))
    return path


@pytest.fixture(autouse=True)
def fast_saves(monkeypatch):
    monkeypatch.setattr(Game, "SAVE_DEBOUNCE", 0.01)


async def until(cond, what, timeout=DEADLINE):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not cond():
        if loop.time() > end:
            raise AssertionError(f"timed out waiting for: {what}")
        await asyncio.sleep(0.005)


async def quick(coro, what):
    """A handler must return at once (it must never await a round)."""
    try:
        return await asyncio.wait_for(coro, timeout=QUICK)
    except asyncio.TimeoutError:
        raise AssertionError(f"handler blocked: {what}") from None


# ---------------------------------------------------------------------------
# GAM-13: NOTICE delivery
# ---------------------------------------------------------------------------

def test_notice_cmd_goes_out_as_NOTICE(tmp_path):
    asyncio.run(init_db(str(tmp_path / "w.db")))
    bot, sent = make_irc(str(tmp_path / "w.db"))
    bot.execute_command({"cmd": "notice", "target": "wgg1",
                         "text": "[Poker] Your hole cards: A♠ K♠"})
    bot.execute_command({"cmd": "msg", "target": "#c", "text": "hi"})
    assert any(line.startswith("NOTICE wgg1 :[Poker] Your hole cards") for line in sent), sent
    assert not any(line.startswith("PRIVMSG wgg1") for line in sent), sent
    assert "PRIVMSG #c :hi" in sent


# ---------------------------------------------------------------------------
# GAM-6: NOTICE input from IRC to the games
# ---------------------------------------------------------------------------

def test_irc_emits_NOTICE_event_for_user_notices_only(tmp_path):
    asyncio.run(init_db(str(tmp_path / "w.db")))
    bot, _ = make_irc(str(tmp_path / "w.db"))
    bot.connection._process_line(":wgg1!u@h.example NOTICE wbs :!wkill wgg2")
    bot.connection._process_line(":irc.example.net NOTICE wbs :*** server notice")
    events = []
    while True:
        try:
            events.append(bot.core_q.get_nowait())
        except queue.Empty:
            break
    notices = [e for e in events if e.get("type") == "NOTICE"]
    assert len(notices) == 1, events
    assert notices[0]["nick"] == "wgg1"
    assert notices[0]["text"] == "!wkill wgg2"
    assert notices[0]["host"] == "wgg1!u@h.example"


class EventQ:
    def __init__(self):
        self.items = []

    def put_nowait(self, item):
        self.items.append(item)

    def put(self, item, block=True):
        self.items.append(item)


def real_core(db: str) -> Core:
    config = {"bot": {"nick": "wbs"}, "db": {"path": db},
              "settings": {"allow_plaintext": True}}
    return Core(config, db + ".json", NS(db_path=None), core_q=EventQ(), irc_q=EventQ())


def test_core_routes_NOTICE_events_to_dispatch_notice(db_path):
    core = real_core(str(db_path))
    seen = []

    async def fake_dispatch(nick, text, event=None):
        seen.append((nick, text))
        return True
    core.game.dispatch_notice = fake_dispatch

    asyncio.run(core.handle_event({"type": "NOTICE", "nick": "wgg1",
                                   "host": "wgg1!u@h.example", "uhost": "u@h.example",
                                   "target": "wbs", "text": "!wkill wgg2"}))
    assert seen == [("wgg1", "!wkill wgg2")]
    # nothing is answered by the core (NOTICE never triggers replies)
    assert core.irc_q.items == []


# ---------------------------------------------------------------------------
# GAM-6: periodic tick -> lottery draw
# ---------------------------------------------------------------------------

def test_core_game_tick_task_runs_lottery_draw(db_path, monkeypatch):
    core = real_core(str(db_path))
    # fake clock: 21:30 UTC, after the 20:00 draw hour
    monkeypatch.setattr(lottery_mod, "_utc_now",
                        lambda: datetime(2026, 10, 7, 21, 30, tzinfo=timezone.utc))

    async def go():
        await core.game.start_game("lottery", "channel", "#lotto")
        await core._register_core_tasks()
        task = core.tasks.tasks["game_tick"]
        assert task.enabled and not task.can_disable
        assert 1 <= task.interval <= 5
        await core.tasks.run_once(task)
        texts = [p.get("text", "") for p in core.irc_q.items if p.get("target") == "#lotto"]
        assert any("Daily 6/49 draw!" in t for t in texts), texts
        # the draw happens once per day, not once per tick
        n = len(core.irc_q.items)
        await core.tasks.run_once(task)
        assert not any("Daily 6/49 draw!" in p.get("text", "")
                       for p in core.irc_q.items[n:])
        # started with the core, cancelled on shutdown
        core.tasks.start()
        assert task.handle is not None and not task.handle.done()
        handle = task.handle
        core.tasks.stop_all()
        await asyncio.sleep(0)
        assert handle.cancelled() or handle.done()
        await core.game.unload_game("lottery")
    asyncio.run(go())


def test_tick_errors_are_logged_not_fatal(db_path, caplog):
    core = FakeCore(db_path)

    class Boom:
        name = "boom"

        async def on_tick(self):
            raise RuntimeError("kaboom")

        def request_save(self):
            pass

    calls = []

    class Fine:
        name = "fine"

        async def on_tick(self):
            calls.append(1)

        def request_save(self):
            pass

    core.game.games = {"boom": Boom(), "fine": Fine()}
    asyncio.run(core.game.tick())
    assert calls == [1]
    assert "kaboom" in caplog.text


# ---------------------------------------------------------------------------
# GAM-6 / GAM-11: a full werewolf game
# ---------------------------------------------------------------------------

def _werewolf_fast(monkeypatch):
    monkeypatch.setattr(werewolf_mod, "NIGHT_SECS", LONG)
    monkeypatch.setattr(werewolf_mod, "DAY_SECS", LONG)
    monkeypatch.setattr(werewolf_mod, "PAUSE_SECS", 0)
    roles = {"wa": werewolf_mod.WEREWOLF, "wb": werewolf_mod.SEER,
             "wc": werewolf_mod.DOCTOR, "wd": werewolf_mod.VILLAGER}
    monkeypatch.setattr(werewolf_mod, "_assign_roles",
                        lambda players: {n: roles[n] for n in players})


def test_werewolf_full_game_notice_kill_votes_and_win(db_path, monkeypatch):
    _werewolf_fast(monkeypatch)
    core = FakeCore(db_path)
    core.ops.add("wa")
    gm = core.game
    chan = "#ww"

    async def go():
        session = await gm.start_game("werewolf", "channel", chan, owner="wa")
        for n in ("wa", "wb", "wc", "wd"):
            await quick(gm.dispatch_pubmsg(chan, n, "!wjoin"), "!wjoin")
        # forced start returns at once; the game runs as the session task
        await quick(gm.dispatch_pubmsg(chan, "wa", "!wstart"), "!wstart")
        await until(lambda: session.data.get("phase") == "night", "night 1")
        assert session.task is not None and not session.task.done()

        # roles went out as NOTICE
        role_notices = [p for p in core.sent if "Your role" in p.get("text", "")]
        assert {p["target"] for p in role_notices} == {"wa", "wb", "wc", "wd"}
        assert all(p["cmd"] == "notice" for p in role_notices)

        # wolf kills by /notice; seer uses the PRIVMSG fallback; doctor saves
        # himself by notice.  Another event is dispatched while the round runs.
        await quick(gm.dispatch_notice("wa", "!wkill wd"), "!wkill")
        ev = {"type": "COMMAND", "nick": "wb", "text": "!wsee wa"}
        await quick(gm.dispatch_privmsg("wb", "!wsee wa", event=ev), "!wsee")
        assert ev.get("handled") is True      # core will not answer "Unknown command"
        await quick(gm.dispatch_notice("wc", "!wsave wc"), "!wsave")

        await until(lambda: session.data.get("phase") == "day", "day 1")
        assert any("wd\x02 was found dead" in t for t in core.texts(chan))
        assert any("wa is a" in t and "Werewolf" in t for t in core.texts("wb", "notice"))

        # day votes are counted as they arrive: majority (2 of 3) ends the day
        await quick(gm.dispatch_pubmsg(chan, "wb", "!wvote wa"), "!wvote")
        await quick(gm.dispatch_pubmsg(chan, "wc", "!wvote WA"), "!wvote")
        await until(lambda: gm.get_session("werewolf", "channel", chan) is None,
                    "game over")
        await until(lambda: session.task.done(), "session task finished")

    asyncio.run(asyncio.wait_for(go(), DEADLINE * 2))
    texts = core.texts(chan)
    assert any("wa\x02 is lynched" in t for t in texts), texts
    assert any("Villagers win!" in t for t in texts), texts
    assert not any("Time's up" in t for t in texts)
    assert not any("Miraculously" in t for t in texts)


def test_werewolf_wolves_win_and_night_action_errors(db_path, monkeypatch):
    _werewolf_fast(monkeypatch)
    core = FakeCore(db_path)
    core.ops.add("wa")
    gm = core.game
    chan = "#ww2"

    async def go():
        session = await gm.start_game("werewolf", "channel", chan)
        for n in ("wa", "wb", "wc", "wd"):
            await gm.dispatch_pubmsg(chan, n, "!wjoin")
        # a night action outside the night is refused, by notice
        await gm.dispatch_notice("wa", "!wkill wd")
        assert any("only work at night" in t for t in core.texts("wa", "notice"))
        await quick(gm.dispatch_pubmsg(chan, "wa", "!wstart"), "!wstart")
        await until(lambda: session.data.get("phase") == "night", "night 1")
        # a villager cannot kill
        await gm.dispatch_notice("wd", "!wkill wb")
        assert any("cannot use !wkill" in t for t in core.texts("wd", "notice"))
        await gm.dispatch_notice("wa", "!wkill wc")
        await gm.dispatch_notice("wb", "!wsee wd")
        await gm.dispatch_notice("wc", "!wsave wb")
        await until(lambda: session.data.get("phase") == "day", "day 1")
        # wd and wb lynch nobody useful: wd votes wb, wa votes wb -> wb dies
        await gm.dispatch_pubmsg(chan, "wd", "!wvote wb")
        await gm.dispatch_pubmsg(chan, "wa", "!wvote wb")
        await until(lambda: gm.get_session("werewolf", "channel", chan) is None,
                    "game over")

    asyncio.run(asyncio.wait_for(go(), DEADLINE * 2))
    assert any("Werewolves win!" in t for t in core.texts(chan))


# ---------------------------------------------------------------------------
# GAM-11 / GAM-13: poker hands complete without timeouts
# ---------------------------------------------------------------------------

def _poker_fast(monkeypatch):
    real = poker_mod.PokerGame._load_settings

    async def settings(self, channel):
        cfg = await real(self, channel)
        cfg["turn_secs"] = LONG
        return cfg
    monkeypatch.setattr(poker_mod.PokerGame, "_load_settings", settings)


async def _poker_table(core, chan, nicks):
    gm = core.game
    session = await gm.start_game("poker", "channel", chan)
    await quick(gm.dispatch_pubmsg(chan, nicks[0], "!pkstart"), "!pkstart")
    for n in nicks[1:]:
        await quick(gm.dispatch_pubmsg(chan, n, "!pkjoin"), "!pkjoin")
    # chan-op skips the countdown; the handler returns at once
    await quick(gm.dispatch_pubmsg(chan, nicks[0], "!pkstart"), "!pkstart (force)")
    await until(lambda: session.data.get("phase") == "playing", "hand started")
    return session


def test_poker_three_players_reach_showdown_without_timeouts(db_path, monkeypatch):
    _poker_fast(monkeypatch)
    core = FakeCore(db_path)
    core.ops.add("p1")
    gm = core.game
    chan = "#pk"
    actions = []

    async def go():
        session = await _poker_table(core, chan, ["p1", "p2", "p3"])
        bet_on = {"preflop", "turn"}
        while True:
            await until(lambda: session.data.get("action_player")
                        or session.data.get("phase") != "playing", "next prompt")
            if session.data.get("phase") != "playing":
                break
            nick = session.data["action_player"]
            p = session.data["players"][nick]
            to_call = session.data["current_bet"] - p.street_bet
            street = session.data["street"]
            if street in bet_on:
                bet_on.discard(street)
                cmd = "!pkbet 20"
            elif to_call > 0:
                cmd = "!pkcall"
            else:
                cmd = "!pkcheck"
            actions.append((street, nick, cmd))
            await quick(gm.dispatch_pubmsg(chan, nick, cmd), cmd)
            # the next player is prompted right away (no 60 s auto-fold)
            await until(lambda nick=nick: session.data.get("action_player") != nick
                        or session.data.get("phase") != "playing", "turn passed")
        return session

    session = asyncio.run(asyncio.wait_for(go(), DEADLINE * 2))
    texts = core.texts(chan)
    assert any("*** FLOP ***" in t for t in texts), (actions, core.sent)
    assert any("*** TURN ***" in t for t in texts)
    assert any("*** RIVER ***" in t for t in texts)
    assert any("*** SHOWDOWN ***" in t for t in texts), texts
    assert any("raises to" in t for t in texts)
    assert any((" wins $" in t) or ("Split pot" in t) for t in texts)
    assert not any("timed out" in t for t in texts)
    assert {s for s, _, _ in actions} == {"preflop", "flop", "turn", "river"}
    # every player acted on every street
    for street in ("preflop", "flop", "turn", "river"):
        assert {n for s, n, _ in actions if s == street} == {"p1", "p2", "p3"}
    # GAM-13: hole cards by NOTICE, once per player per hand
    holes = [p for p in core.sent if "Your hole cards" in p.get("text", "")]
    assert sorted(p["target"] for p in holes) == ["p1", "p2", "p3"]
    assert all(p["cmd"] == "notice" for p in holes)


def test_poker_allin_and_call_runs_out_the_board(db_path, monkeypatch):
    _poker_fast(monkeypatch)
    core = FakeCore(db_path)
    core.ops.add("a1")
    gm = core.game
    chan = "#pk2"

    async def go():
        session = await _poker_table(core, chan, ["a1", "a2"])
        await until(lambda: session.data.get("action_player"), "first prompt")
        first = session.data["action_player"]
        await quick(gm.dispatch_pubmsg(chan, first, "!pkallin"), "!pkallin")
        await until(lambda: session.data.get("action_player") not in (None, first),
                    "second prompt")
        second = session.data["action_player"]
        await quick(gm.dispatch_pubmsg(chan, second, "!pkcall"), "!pkcall")
        await until(lambda: any("*** SHOWDOWN ***" in t for t in core.texts(chan)),
                    "showdown")
        # !pkcards resends the hand on request only
        before = len([p for p in core.sent if "Your hole cards" in p.get("text", "")])
        await gm.dispatch_pubmsg(chan, first, "!pkcards")
        after = [p for p in core.sent if "Your hole cards" in p.get("text", "")]
        assert len(after) == before + 1 and after[-1]["target"] == first
        assert after[-1]["cmd"] == "notice"
        await gm.stop_game("poker", "channel", chan)

    asyncio.run(asyncio.wait_for(go(), DEADLINE * 2))
    texts = core.texts(chan)
    assert any("ALL IN" in t for t in texts)
    assert any("*** RIVER ***" in t for t in texts)
    assert not any("timed out" in t for t in texts)


def test_poker_fold_pays_pot_once(db_path, monkeypatch):
    _poker_fast(monkeypatch)
    core = FakeCore(db_path)
    core.ops.add("f1")
    gm = core.game
    chan = "#pk3"

    async def go():
        session = await _poker_table(core, chan, ["f1", "f2"])
        await until(lambda: session.data.get("action_player"), "first prompt")
        nick = session.data["action_player"]
        await quick(gm.dispatch_pubmsg(chan, nick, "!pkfold"), "!pkfold")
        await until(lambda: session.data.get("phase") == "finished", "hand over")
        await asyncio.sleep(0.05)
        return session

    session = asyncio.run(asyncio.wait_for(go(), DEADLINE))
    wins = [t for t in core.texts(chan) if "Everyone else folded" in t]
    assert len(wins) == 1, wins
    cash = sorted(p.cash for p in session.data["players"].values())
    assert sum(cash) == 2 * poker_mod.DEFAULT_STARTING_CASH


# ---------------------------------------------------------------------------
# GAM-11: forced starts of the other round games do not block dispatch
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("game, start, join, extra", [
    ("blackjack", "!bjstart", "!bjjoin", None),
    ("russianroulette", "!rrstart", "!rrjoin", None),
])
def test_forced_start_returns_immediately(db_path, game, start, join, extra):
    core = FakeCore(db_path)
    core.ops.add("o1")
    gm = core.game
    chan = f"#{game}"

    async def go():
        session = await gm.start_game(game, "channel", chan)
        await quick(gm.dispatch_pubmsg(chan, "o1", start), start)
        await quick(gm.dispatch_pubmsg(chan, "o2", join), join)
        await quick(gm.dispatch_pubmsg(chan, "o1", start), f"{start} (force)")
        assert session.task is not None and not session.task.done()
        # stopping cancels the round task
        task = session.task
        await gm.stop_game(game, "channel", chan)
        await asyncio.sleep(0)
        assert task.done()

    asyncio.run(asyncio.wait_for(go(), DEADLINE))
