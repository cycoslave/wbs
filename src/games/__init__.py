# games/__init__.py
"""
Game manager for WBS.

Games are logic/session engines. Plugins or commands modules should call into
GameManager to start games, stop games, and dispatch player actions.
"""
import asyncio
import importlib
import inspect
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Type

log = logging.getLogger("wbs.games")

@dataclass
class GameContext:
    source: str          # "irc", "partyline", "botnet"
    scope: str           # "channel", "user", "subnet", "botnet"
    target: str          # "#wbs", nick, subnet id
    nick: str | None = None
    handle: str | None = None
    session_id: int | None = None

@dataclass
class GameSession:
    game_name: str
    scope: str                  # "channel", "user", "subnet", "botnet"
    target: str                 # "#chan", nick, subnet id, etc.
    owner: Optional[str] = None
    state: str = "idle"
    data: Dict[str, Any] = field(default_factory=dict)
    players: set[str] = field(default_factory=set)
    task: Optional[asyncio.Task] = None

    @property
    def key(self) -> str:
        return f"{self.scope}:{self.target}".lower()

class Game:
    name = "base"
    scopes = {"channel"}
    allow_multiple_sessions = False

    def __init__(self, core):
        self.core = core
        self.log = logging.getLogger(f"wbs.games.{self.name}")
        self.sessions: Dict[str, GameSession] = {}

    async def load(self):
        pass

    async def unload(self):
        for key in list(self.sessions.keys()):
            await self.stop_session(key)

    async def start_session(self, session: GameSession):
        session.state = "running"

    async def stop_session(self, key: str):
        session = self.sessions.pop(key, None)
        if not session:
            return

        if session.task and not session.task.done():
            session.task.cancel()
            try:
                await session.task
            except asyncio.CancelledError:
                pass

        session.state = "stopped"

    async def on_pubmsg(self, session: GameSession, nick: str, text: str, event=None):
        pass

    async def on_privmsg(self, nick: str, text: str, event=None):
        pass

    def get_session(self, scope: str, target: str):
        return self.sessions.get(f"{scope}:{target}".lower())
    
    async def create_session(self, scope: str, target: str, owner=None, **kwargs):
        key = f"{scope}:{target}".lower()
        if not self.allow_multiple_sessions and key in self.sessions:
            raise ValueError(f"{self.name} already running in {target}")

        session = GameSession(
            game_name=self.name,
            scope=scope,
            target=target,
            owner=owner,
            state="starting",
            data=dict(kwargs),
        )
        self.sessions[key] = session
        return session
    
    # Helper methods for IRC communication
    async def send_privmsg(self, target, message):
        """Send message to channel/user"""
        self.core.irc_q.put({
            'cmd': 'msg',
            'target': target,
            'text': message
        })
    
    async def send_notice(self, target, message):
        """Send notice to user"""
        self.core.irc_q.put({
            'cmd': 'notice',
            'target': target,
            'text': message
        })    

class GameManager:
    def __init__(self, core):
        self.core = core
        self.games: Dict[str, Game] = {}

    async def load_game(self, game_name: str) -> Game:
        if game_name in self.games:
            return self.games[game_name]

        try:
            module = importlib.import_module(f"src.games.{game_name}")

            game_classes = [
                obj for _, obj in inspect.getmembers(module, inspect.isclass)
                if issubclass(obj, Game)
                and obj is not Game
                and obj.__module__ == module.__name__
            ]

            if not game_classes:
                raise ValueError(f"No Game subclass found in src.games.{game_name}")

            game_cls: Type[Game] = game_classes[0]
            game = game_cls(self.core)
            self.games[game_name] = game

            await game.load()
            log.info("Loaded game: %s", game_name)
            return game

        except Exception as e:
            raise RuntimeError(f"Failed to load game {game_name}: {e}") from e

    async def unload_game(self, game_name: str):
        game = self.games.pop(game_name, None)
        if not game:
            log.warning("Game %s not loaded", game_name)
            return

        await game.unload()
        log.info("Unloaded game: %s", game_name)

    async def start_game(
        self,
        game_name: str,
        scope: str,
        target: str,
        owner: Optional[str] = None,
        **kwargs: Any,
    ) -> GameSession:
        game = await self.load_game(game_name)

        if scope not in game.scopes:
            raise ValueError(f"{game_name} does not support scope {scope}")

        session = await game.create_session(scope, target, owner=owner, **kwargs)
        await game.start_session(session)
        return session

    async def stop_game(self, game_name: str, scope: str, target: str):
        game = self.games.get(game_name)
        if not game:
            return
        await game.stop_session(f"{scope}:{target}")

    def get_game(self, game_name: str) -> Optional[Game]:
        return self.games.get(game_name)

    def get_session(self, game_name: str, scope: str, target: str) -> Optional[GameSession]:
        game = self.games.get(game_name)
        if not game:
            return None
        return game.get_session(scope, target)

    async def dispatch_pubmsg(self, channel: str, nick: str, text: str, event=None):
        for game in self.games.values():
            session = game.get_session("channel", channel)
            if not session:
                continue
            try:
                await game.on_PUBMSG(session, nick, text, event=event)
            except Exception as e:
                log.error("Game %s on_pubmsg error: %s", game.name, e, exc_info=True)

    async def dispatch_privmsg(self, nick: str, text: str, event=None):
        for game in self.games.values():
            try:
                await game.on_privmsg(nick, text, event=event)
            except Exception as e:
                log.error("Game %s on_privmsg error: %s", game.name, e, exc_info=True)

    async def tick(self):
        for name, game in self.games.items():
            try:
                await game.on_tick()
            except Exception as e:
                log.error("Game %s tick error: %s", name, e, exc_info=True)


__all__ = [
    "Game",
    "GameSession",
    "GameManager",
]
