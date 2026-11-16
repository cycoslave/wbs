"""
Regression tests for the game framework (GAM-1, GAM-2, GAM-3, GAM-4, GAM-7, GAM-8).

GAM-1  `.gunload` always failed: Game.unload bound `(self.name)` (a str, one
       binding per character) and GameManager.unload_game bound two values for
       one placeholder, after the game was already popped (sessions vanished
       without a stop message, tasks kept running, rows stayed).
GAM-2  session.data held a set -> json.dumps failed -> werewolf could not start.
GAM-3  `.gstop` did not lowercase the key (stored keys are lowercase) and said
       "Stopped" for sessions that do not exist.
GAM-4  blackjack.unload() dropped blackjack_settings / blackjack_cash.
GAM-7  session state was saved only at start (lottery cfg went stale).
GAM-8  mid-round state was never saved (dataclass players dumped as {}), and a
       restart mid-round dropped the round silently.

Throwaway sqlite DB per test, real game modules, fake IRC (recorded payloads).
"""
import asyncio
import enum
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

from src import commands
from src.core import Core
from src.db import get_db, init_db
from src.games import Game, GameManager, decode_state, encode_state
import src.games.blackjack as blackjack_mod
import src.games.werewolf as werewolf_mod
from src.games.blackjack import PlayerState
from src.games.werewolf import WPlayer

ALL_GAMES = (
    "blackjack", "duckhunt", "fishing", "horseracing", "lottery",
    "poker", "roulette", "russianroulette", "slots", "werewolf",
)


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

    def texts(self, target=None):
        return [p["text"] for p in self.sent
                if target is None or p.get("target") == target]


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "games.db"
    run(init_db(str(path)))
    return path


@pytest.fixture(autouse=True)
def fast_saves(monkeypatch):
    monkeypatch.setattr(Game, "SAVE_DEBOUNCE", 0.01)


async def rows(db_path, sql, *params):
    async with get_db(str(db_path)) as db:
        async with db.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def session_rows(db_path, game=None):
    if game:
        return await rows(db_path, "SELECT * FROM game_sessions WHERE game_name=?", game)
    return await rows(db_path, "SELECT * FROM game_sessions")


async def module_rows(db_path, game):
    return await rows(db_path,
                      "SELECT * FROM loaded_modules WHERE name=? AND type='game'", game)


async def responses(coro_fn, core, arg):
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    await coro_fn(core, "admin", 1, arg, respond)
    return out


# --- GAM-2: JSON state ------------------------------------------------------

class Colour(enum.Enum):
    RED = "red"


@dataclass
class Hand:
    nick: str
    cards: list = field(default_factory=list)
    seen: set = field(default_factory=set)
    when: datetime | None = None
    colour: Colour = Colour.RED
    timer: object = None


def test_encode_decode_roundtrip_set_dataclass_datetime_enum():
    async def scenario():
        when = datetime(2026, 10, 7, 20, 0, tzinfo=timezone.utc)
        task = asyncio.create_task(asyncio.sleep(0))
        data = {
            "done": {"kill", "see"},
            "players": {"alice": Hand("alice", ["AS"], {"x"}, when, Colour.RED, task)},
            "when": when,
            "colour": Colour.RED,
            "lock": asyncio.Lock(),
            "nested": [{"a": frozenset({1, 2})}, (1, 2)],
        }
        blob = json.dumps(encode_state(data))     # must not raise
        back = decode_state(json.loads(blob))
        await task
        return back, when

    back, when = run(scenario())
    assert back["done"] == {"kill", "see"}
    assert "lock" not in back
    alice = back["players"]["alice"]
    assert isinstance(alice, Hand)
    assert (alice.nick, alice.cards, alice.seen, alice.when, alice.colour) == (
        "alice", ["AS"], {"x"}, when, Colour.RED)
    assert alice.timer is None            # runtime task never persisted
    assert back["when"] == when and back["colour"] is Colour.RED
    assert back["nested"] == [{"a": {1, 2}}, [1, 2]]


def test_decode_refuses_classes_outside_loaded_or_game_modules():
    blob = {"__dataclass__": "subprocess:Popen", "fields": {}}
    with pytest.raises(ValueError):
        decode_state(blob)


def test_werewolf_starts_and_saves(db_path):
    async def scenario():
        core = FakeCore(db_path)
        session = await core.game.start_game("werewolf", "channel", "#ww", owner="admin")
        game = core.game.games["werewolf"]
        await game.on_PUBMSG(session, "alice", "!wjoin")
        await game.flush_sessions()
        saved = await session_rows(db_path, "werewolf")
        loaded = await game.session_load("channel", "#ww")
        state = session.state
        await core.game.unload_game("werewolf")
        return state, saved, loaded

    state, saved, loaded = run(scenario())
    assert state == "running"
    assert len(saved) == 1 and saved[0]["state"] == "running"
    raw = json.loads(saved[0]["data"])
    assert raw["actions_done"] == {"__set__": []}
    assert loaded["actions_done"] == set()
    assert loaded["phase"] == "registering"
    assert isinstance(loaded["players"]["alice"], WPlayer)
    assert "vote_event" not in loaded


# --- GAM-1: unload ------------------------------------------------------------

@pytest.mark.parametrize("name", ALL_GAMES)
def test_load_start_unload_is_clean_for_every_game(db_path, name):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.load_game(name)
        session = await core.game.start_game(name, "channel", "#Play", owner="admin")
        game = core.game.games[name]
        tasks = [session.task] if session.task else []
        before_rows = await session_rows(db_path, name)
        core.sent.clear()
        out = await responses(commands.cmd_gunload, core, name)
        await asyncio.sleep(0.05)               # no stray save may come back
        return (core, game, session, tasks, before_rows, out,
                await session_rows(db_path, name), await module_rows(db_path, name))

    core, game, session, tasks, before, out, after, modules = run(scenario())
    assert out == [f"Unloaded game {name}"]
    assert len(before) == 1
    assert after == [] and modules == []
    assert name not in core.game.games and game.sessions == {}
    assert session.state == "stopped"
    assert all(t.done() for t in tasks)
    # the stop is announced in the session's channel
    assert core.texts("#Play"), core.sent


def test_unload_cancels_registration_task_and_announces(db_path):
    async def scenario():
        core = FakeCore(db_path)
        session = await core.game.start_game("blackjack", "channel", "#bj")
        game = core.game.games["blackjack"]
        await game.on_PUBMSG(session, "alice", "!bjstart")
        task = session.task
        assert task is not None and not task.done()
        core.sent.clear()
        await core.game.unload_game("blackjack")
        return core, task

    core, task = run(scenario())
    assert task.cancelled()
    assert "[Blackjack] Game over." in core.texts("#bj")


def test_unload_is_atomic_when_the_database_step_fails(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("slots", "channel", "#s")
        async with get_db(str(db_path)) as db:
            await db.execute("ALTER TABLE game_sessions RENAME TO game_sessions_off")
        with pytest.raises(Exception):
            await core.game.unload_game("slots")
        still_loaded = "slots" in core.game.games
        module_kept = await module_rows(db_path, "slots")
        async with get_db(str(db_path)) as db:
            await db.execute("ALTER TABLE game_sessions_off RENAME TO game_sessions")
        assert await core.game.unload_game("slots") is True
        return still_loaded, module_kept, await module_rows(db_path, "slots")

    still_loaded, module_kept, module_after = run(scenario())
    assert still_loaded                      # not popped before the DB work
    assert len(module_kept) == 1             # first DELETE rolled back
    assert module_after == []


def test_unloaded_game_is_not_restored_after_restart(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("roulette", "channel", "#r")
        await core.game.unload_game("roulette")
        core2 = FakeCore(db_path)
        await Core._autoload_games(core2)
        return core2

    assert "roulette" not in run(scenario()).game.games


# --- GAM-4: blackjack keeps its tables ---------------------------------------

def test_blackjack_balances_survive_unload_and_load(db_path):
    async def scenario():
        core = FakeCore(db_path)
        game = await core.game.load_game("blackjack")
        await game._save_cash("alice", 1234)
        await core.game.unload_game("blackjack")
        game = await core.game.load_game("blackjack")
        return await game._load_cash("alice", 1500)

    assert run(scenario()) == 1234


def test_gpurge_is_the_only_way_to_drop_game_tables(db_path):
    async def scenario():
        core = FakeCore(db_path)
        game = await core.game.load_game("blackjack")
        await game._save_cash("alice", 1234)
        refused = await responses(commands.cmd_gpurge, core, "blackjack")
        await core.game.unload_game("blackjack")
        done = await responses(commands.cmd_gpurge, core, "blackjack")
        tables = await rows(db_path, "SELECT name FROM sqlite_master "
                                     "WHERE type='table' AND name LIKE 'blackjack_%'")
        return refused, done, tables

    refused, done, tables = run(scenario())
    assert refused == ["blackjack is loaded; .gunload blackjack first"]
    assert done == ["Purged blackjack: dropped blackjack_settings, blackjack_cash"]
    assert tables == []


# --- GAM-3: .gstop keys -----------------------------------------------------

def test_gstop_is_case_insensitive_like_start(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("roulette", "channel", "#Other-Chan")
        out = await responses(commands.cmd_gstop, core, "ROULETTE channel #OTHER-chan")
        return core, out, await session_rows(db_path, "roulette")

    core, out, saved = run(scenario())
    assert out == ["Stopped roulette in channel:#OTHER-chan"]
    assert core.game.games["roulette"].sessions == {}
    assert saved == []


def test_gstop_unknown_game_or_session_says_no_such_session(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("roulette", "channel", "#a")
        a = await responses(commands.cmd_gstop, core, "nosuch channel #x")
        b = await responses(commands.cmd_gstop, core, "roulette channel #b")
        return core, a, b

    core, a, b = run(scenario())
    assert a == ["No such session: nosuch in channel:#x"]
    assert b == ["No such session: roulette in channel:#b"]
    assert list(core.game.games["roulette"].sessions) == ["channel:#a"]


# --- GAM-7 / GAM-8: saves after every change, restore mid-round --------------

def test_state_changes_are_saved_with_debounce(db_path):
    async def scenario():
        core = FakeCore(db_path)
        session = await core.game.start_game("blackjack", "channel", "#bj")
        await core.game.dispatch_pubmsg("#bj", "alice", "!bjstart")
        await core.game.dispatch_pubmsg("#bj", "bob", "!bjjoin")
        game = core.game.games["blackjack"]
        for _ in range(500):                     # debounced flush finishes
            await asyncio.sleep(0.01)
            if game._flush_task is None:
                break
        saved = await session_rows(db_path, "blackjack")
        await core.game.unload_game("blackjack")
        return saved

    saved = run(scenario())
    data = json.loads(saved[0]["data"])
    assert data["phase"] == "registering"
    assert set(data["players"]) == {"alice", "bob"}
    alice = data["players"]["alice"]
    assert alice["__dataclass__"] == "src.games.blackjack:PlayerState"
    assert alice["fields"]["cash"] == 1500 and alice["fields"]["nick"] == "alice"


def test_lottery_cfg_in_saved_session_follows_the_jackpot(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("lottery", "channel", "#l")
        game = core.game.games["lottery"]
        await game.on_tick()  # nothing to draw yet is fine either way
        await core.game.dispatch_pubmsg("#l", "alice", "!lotto 1 2 3 4 5 6")
        await asyncio.sleep(0.1)
        await game.flush_sessions()
        saved = await session_rows(db_path, "lottery")
        settings = await rows(db_path, "SELECT jackpot FROM lottery_settings WHERE channel='#l'")
        await core.game.unload_game("lottery")
        return saved, settings

    saved, settings = run(scenario())
    data = json.loads(saved[0]["data"])
    assert data["cfg"]["jackpot"] == settings[0]["jackpot"]


def test_gsessions_counts_players(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("blackjack", "channel", "#bj", owner="admin")
        await core.game.dispatch_pubmsg("#bj", "alice", "!bjstart")
        await core.game.dispatch_pubmsg("#bj", "bob", "!bjjoin")
        out = await responses(commands.cmd_gsessions, core, "")
        await core.game.unload_game("blackjack")
        return out

    assert run(scenario()) == ["blackjack channel:#bj state=running players=2 owner=admin"]


def test_restart_mid_registration_restores_and_round_continues(db_path, monkeypatch):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("blackjack", "channel", "#bj", owner="admin")
        await core.game.dispatch_pubmsg("#bj", "alice", "!bjstart")
        await core.game.dispatch_pubmsg("#bj", "bob", "!bjjoin")
        await core.game.games["blackjack"].flush_sessions()
        # "crash": the old process just disappears (no stop, no unload)
        old_task = core.game.games["blackjack"].sessions["channel:#bj"].task
        old_task.cancel()

        monkeypatch.setattr(blackjack_mod, "REGISTRATION_SECS", 2.0)
        monkeypatch.setattr(blackjack_mod, "REGISTRATION_WARN", 1.0)
        core2 = FakeCore(db_path)
        await Core._autoload_games(core2)
        game = core2.game.games["blackjack"]
        session = game.sessions["channel:#bj"]
        restored = (session.data["phase"], dict(session.data["players"]))
        await core2.game.dispatch_pubmsg("#bj", "carol", "!bjjoin")
        for _ in range(1000):
            if session.data["phase"] == "betting":
                break
            await asyncio.sleep(0.01)
        phase_after = session.data["phase"]
        await core2.game.unload_game("blackjack")
        return core2, restored, phase_after

    core2, (phase, players), phase_after = run(scenario())
    assert phase == "registering"
    assert set(players) == {"alice", "bob"}
    assert all(isinstance(p, PlayerState) and p.cash == 1500 for p in players.values())
    texts = core2.texts("#bj")
    assert any("Game restored after a restart" in t and "alice, bob" in t for t in texts), texts
    assert "[Blackjack] carol joined with $1500." in texts
    assert not any("Registration is closed" in t for t in core2.texts())
    assert phase_after == "betting"            # registration timer was re-armed


def test_werewolf_restart_at_night_restores_roles_and_accepts_kill(db_path, monkeypatch):
    async def scenario():
        core = FakeCore(db_path)
        core.ops.add("op")
        session = await core.game.start_game("werewolf", "channel", "#ww")
        game = core.game.games["werewolf"]
        for nick in ("op", "b", "c", "d"):
            await game.on_PUBMSG(session, nick, "!wjoin")
        monkeypatch.setattr(werewolf_mod, "_assign_roles", lambda players: {
            "op": werewolf_mod.WEREWOLF, "b": werewolf_mod.SEER,
            "c": werewolf_mod.DOCTOR, "d": werewolf_mod.VILLAGER})
        session.task.cancel()
        night = asyncio.create_task(game._begin_game(session))
        for _ in range(100):
            if session.data["phase"] == "night":
                break
            await asyncio.sleep(0.01)
        await game.flush_sessions()
        night.cancel()                           # "crash"

        core2 = FakeCore(db_path)
        await Core._autoload_games(core2)
        game2 = core2.game.games["werewolf"]
        s2 = game2.sessions["channel:#ww"]
        roles = {n: p.role for n, p in s2.data["players"].items()}
        await game2.on_NOTICE(s2, "op", "!wkill d")
        result = (s2.data["phase"], roles, s2.data["night_kill"],
                  s2.data["actions_done"], s2.task is not None and not s2.task.done())
        await core2.game.unload_game("werewolf")
        return core2, result

    core2, (phase, roles, kill, done, armed) = run(scenario())
    assert phase == "night"
    assert roles == {"op": "werewolf", "b": "seer", "c": "doctor", "d": "villager"}
    assert kill == "d" and done == {"kill"}
    assert armed
    assert any("Game restored after a restart" in t for t in core2.texts("#ww"))
