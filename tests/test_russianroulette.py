"""Regression coverage for russian roulette round registration (D19)."""
import asyncio
import json
from unittest.mock import AsyncMock

from src.db import init_db
from src.games import GameSession
from src.games.russianroulette import RussianRouletteGame


class FakeCore:
    def __init__(self, db_path):
        self.db_path = str(db_path)

    def send_irc(self, payload):
        pass

    def nick_isop(self, nick, channel):
        return False


async def wait_until(predicate):
    for _ in range(100):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("game did not reach the expected state")


async def cancel_registration(session):
    task = session.task
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    session.task = None


def test_two_registered_players_complete_round_and_reset(tmp_path, monkeypatch):
    async def scenario():
        db_path = tmp_path / "russianroulette.db"
        await init_db(str(db_path))
        game = RussianRouletteGame(FakeCore(db_path))
        game.say = AsyncMock()
        await game.load()

        session = GameSession("russianroulette", "channel", "#aibot")
        await game.start_session(session)
        await game.on_PUBMSG(session, "alice", "!rrstart")
        await game.on_PUBMSG(session, "bob", "!rrjoin")

        assert set(session.data["players"]) == {"alice", "bob"}
        json.dumps(session.data)
        await cancel_registration(session)

        monkeypatch.setattr("src.games.russianroulette.random.shuffle", lambda order: None)
        monkeypatch.setattr("src.games.russianroulette.random.randint", lambda low, high: 2)
        round_task = asyncio.create_task(game._begin_round(session))
        await wait_until(lambda: session.data["phase"] == "playing")
        assert session.data["order"] == ["alice", "bob"]

        pulls = 0
        while session.data["phase"] == "playing":
            player = session.data["current_player"]
            await game.on_PUBMSG(session, player, "!rrpull")
            pulls += 1
            await wait_until(
                lambda player=player: session.data["phase"] != "playing"
                or session.data["current_player"] != player
            )

        await round_task
        assert pulls == 3
        assert any("BANG!" in call.args[1] for call in game.say.await_args_list)
        assert session.data["phase"] == "finished"
        assert session.data["players"] == {}
        assert session.data["order"] == []
        json.dumps(session.data)

    asyncio.run(scenario())


def test_one_registered_player_cancels_round(tmp_path):
    async def scenario():
        db_path = tmp_path / "russianroulette.db"
        await init_db(str(db_path))
        game = RussianRouletteGame(FakeCore(db_path))
        game.say = AsyncMock()
        await game.load()

        session = GameSession("russianroulette", "channel", "#aibot")
        await game.start_session(session)
        await game.on_PUBMSG(session, "alice", "!rrstart")
        assert list(session.data["players"]) == ["alice"]
        json.dumps(session.data)
        await cancel_registration(session)

        await game._begin_round(session)

        assert session.data["phase"] == "idle"
        assert any(
            "Not enough players. Round cancelled." in call.args[1]
            for call in game.say.await_args_list
        )

    asyncio.run(scenario())
