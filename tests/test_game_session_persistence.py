"""
Regression tests for SAST-019: retired sample-game session persistence.

Bug: src/games/__init__.py defined _UNSERIALIZABLE at module level only, but
Game.session_save() filtered with ``self._UNSERIALIZABLE``. The base Game class
had no such attribute, so any save through the base class (or a subclass that
did not copy the tuple) raised AttributeError before touching the database.
The "no such table" fallback in the same method also retried with a literal
placeholder statement (``db.execute("INSERT ...", ...)``), so a save against a
DB without game_sessions could never succeed either.

Games are retired from production; these tests only exercise the persistence
helpers on a throwaway sqlite under pytest's tmp_path. No GameManager.load_game
(which would register a game in loaded_modules), no network, no IRC, no bots.
"""
import asyncio
import importlib
import json
import os
from pathlib import Path

import pytest

import src.games as games_pkg
from src.db import get_db, init_db
from src.games import Game, GameSession

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_GAMES = (
    "blackjack", "duckhunt", "fishing", "horseracing", "lottery",
    "poker", "roulette", "russianroulette", "slots", "werewolf",
)


class FakeCore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.sent: list[dict] = []

    def send_irc(self, payload: dict) -> None:
        self.sent.append(payload)


class SampleGame(Game):
    """Plain subclass that does NOT override _UNSERIALIZABLE (the failing case)."""
    name = "sample"


def run(coro):
    return asyncio.run(coro)


def make_game(tmp_path, cls=SampleGame, with_schema=True):
    db_path = tmp_path / "games.db"
    if with_schema:
        run(init_db(str(db_path)))
    return cls(FakeCore(str(db_path)))


async def fetch_rows(db_path):
    async with get_db(db_path) as db:
        async with db.execute(
            "SELECT game_name, scope, target, owner, state, data FROM game_sessions"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


ORDINARY = {
    "round": 3,
    "pot": 12.5,
    "dealer": "WbsBot",
    "active": True,
    "winner": None,
    "hands": {"alice": ["AS", "KD"], "bob": []},
    "history": [1, 2, 3],
}


# --- the constant itself --------------------------------------------------

def test_base_game_exposes_unserializable_class_attribute():
    assert hasattr(Game, "_UNSERIALIZABLE")
    assert Game._UNSERIALIZABLE is games_pkg._UNSERIALIZABLE
    for t in (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore):
        assert t in Game._UNSERIALIZABLE
    # inherited by subclasses that don't redefine it
    assert SampleGame._UNSERIALIZABLE is games_pkg._UNSERIALIZABLE


@pytest.mark.parametrize("mod_name", SAMPLE_GAMES)
def test_sample_game_overrides_stay_consistent_with_base(mod_name):
    # Import only (no load/start) -- confirms every retained sample still
    # filters at least the base runtime primitives.
    mod = importlib.import_module(f"src.games.{mod_name}")
    classes = [
        obj for obj in vars(mod).values()
        if isinstance(obj, type) and issubclass(obj, Game)
        and obj is not Game and obj.__module__ == mod.__name__
    ]
    assert classes, f"no Game subclass in {mod_name}"
    for cls in classes:
        assert set(games_pkg._UNSERIALIZABLE) <= set(cls._UNSERIALIZABLE)


# --- save / restore ------------------------------------------------------

def test_ordinary_data_save_and_restore_roundtrip(tmp_path):
    game = make_game(tmp_path)

    async def scenario():
        session = await game.create_session("channel", "#aibot", owner="alice", **ORDINARY)
        await game.session_save(session)  # AttributeError before the fix
        return await game.session_load("channel", "#aibot")

    restored = run(scenario())
    assert restored == ORDINARY

    rows = run(fetch_rows(game.core.db_path))
    assert len(rows) == 1
    row = rows[0]
    assert (row["game_name"], row["scope"], row["target"], row["owner"]) == (
        "sample", "channel", "#aibot", "alice")
    assert row["state"] == "starting"


def test_async_primitives_and_callables_are_excluded(tmp_path):
    game = make_game(tmp_path)

    async def scenario():
        async def sleeper():
            await asyncio.sleep(3600)

        task = asyncio.create_task(sleeper())
        try:
            session = await game.create_session("channel", "#aibot", **ORDINARY)
            session.data.update({
                "lock": asyncio.Lock(),
                "event": asyncio.Event(),
                "sem": asyncio.Semaphore(2),
                "task": task,
                "callback": lambda: None,
                "coro_fn": sleeper,
            })
            session.task = task
            await game.session_save(session)
            return await game.session_load("channel", "#aibot")
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    restored = run(scenario())
    assert restored is not None
    assert restored == ORDINARY
    for k in ("lock", "event", "sem", "task", "callback", "coro_fn"):
        assert k not in restored
    raw = run(fetch_rows(game.core.db_path))[0]["data"]
    assert json.loads(raw) == ORDINARY


def test_resave_updates_existing_row(tmp_path):
    game = make_game(tmp_path)

    async def scenario():
        session = await game.create_session("channel", "#aibot", round=1)
        await game.session_save(session)
        session.data["round"] = 2
        session.state = "running"
        await game.session_save(session)
        return await game.session_load("channel", "#aibot")

    assert run(scenario()) == {"round": 2}
    rows = run(fetch_rows(game.core.db_path))
    assert len(rows) == 1 and rows[0]["state"] == "running"


def test_start_and_stop_session_lifecycle(tmp_path):
    game = make_game(tmp_path)

    async def scenario():
        session = await game.create_session("channel", "#aibot", **ORDINARY)
        await game.start_session(session, restore=True)
        after_start = await fetch_rows(game.core.db_path)
        loaded = await game.session_load("channel", "#aibot")
        await game.stop_session(session.key)
        after_stop = await fetch_rows(game.core.db_path)
        return after_start, loaded, after_stop

    after_start, loaded, after_stop = run(scenario())
    assert after_start[0]["state"] == "running"
    assert loaded == {**ORDINARY, "_restore": True}
    assert after_stop == []
    assert game.sessions == {}


def test_save_autocreates_missing_table(tmp_path):
    # Fresh DB with no schema: the fallback must create game_sessions and
    # actually persist the row (it previously retried with "INSERT ...").
    game = make_game(tmp_path, with_schema=False)

    async def scenario():
        session = await game.create_session("channel", "#aibot", **ORDINARY)
        await game.session_save(session)
        return await game.session_load("channel", "#aibot")

    assert run(scenario()) == ORDINARY


def test_session_without_scope_or_target_is_not_saved(tmp_path):
    game = make_game(tmp_path)
    session = GameSession(game_name="sample", scope="", target="#aibot", data={"x": 1})
    run(game.session_save(session))
    assert run(fetch_rows(game.core.db_path)) == []


# --- no runtime artifacts in the repository -------------------------------

def _repo_snapshot():
    # .tmp/.audit/.backup are git-ignored agent scratch areas that other
    # processes may be appending to concurrently; they are not runtime paths
    # the game code could ever write to, so they are left out of the diff.
    skip = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache",
            ".tmp", ".audit", ".backup"}
    out = {}
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for f in filenames:
            if f == ".coverage" or f.startswith(".coverage."):
                continue  # pytest-cov's own data file
            p = Path(dirpath) / f
            try:
                st = p.stat()
            except FileNotFoundError:
                continue
            out[str(p.relative_to(REPO_ROOT))] = (st.st_size, st.st_mtime_ns)
    return out


def test_persistence_writes_nothing_into_repo(tmp_path):
    before = _repo_snapshot()
    game = make_game(tmp_path)

    async def scenario():
        session = await game.create_session("channel", "#aibot", **ORDINARY)
        await game.start_session(session)
        await game.session_load("channel", "#aibot")
        await game.stop_session(session.key)

    run(scenario())
    after = _repo_snapshot()
    assert after == before
    assert Path(game.core.db_path).is_relative_to(tmp_path)
    assert Path(game.core.db_path).exists()
