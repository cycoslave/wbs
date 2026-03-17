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
import json
import aiosqlite
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

log = logging.getLogger("wbs.games")
_UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)

@asynccontextmanager
async def _db(db_path):
    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    try:
        yield db
        await db.commit()
    finally:
        await db.close()

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
    TABLE_SQL: List[str] = []

    def __init__(self, core):
        self.core = core
        self.log = logging.getLogger(f"wbs.games.{self.name}")
        self.sessions: Dict[str, GameSession] = {}

    async def load(self):
        async with _db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO loaded_modules(name, type, scope, owner, autoload) VALUES(?,?,?,?,1) "
                "ON CONFLICT(name, type) DO UPDATE SET "
                "autoload=1, owner=excluded.owner, loaded_at=strftime('%s','now')",
                (self.name, "game", None, None)
            )

    async def unload(self):
        async with _db(self.core.db_path) as db:
            await db.execute(
                "DELETE FROM loaded_modules WHERE name=? AND type='game'",
                (self.name)
            )

    async def start_session(self, session: GameSession):
        session.state = "running"
        await self.session_save(session)
        #session.task = asyncio.create_task(self.game_loop(session))

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
        await self.session_clear(session)

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
    
    async def session_save(self, session: GameSession):
        if not session.scope or not session.target:
            return 
        safe = {k: v for k, v in session.data.items()
                if not callable(v) and not isinstance(v, self._UNSERIALIZABLE)}
        
        async with _db(self.core.db_path) as db:
            # Auto-create if missing
            try:
                await db.execute("""
                    INSERT INTO game_sessions(game_name, scope, target, owner, state, data) 
                    VALUES(?,?,?,?,?,?) 
                    ON CONFLICT(game_name, scope, target) DO UPDATE SET 
                    state = excluded.state, 
                    data = excluded.data, 
                    saved_at = strftime('%s','now')
                """, (self.name, session.scope, session.target, session.owner, 
                    session.state, json.dumps(safe)))
            except sqlite3.OperationalError as e:
                if "no such table" in str(e):
                    await db.execute("""
                        CREATE TABLE game_sessions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            game_name TEXT NOT NULL,
                            scope TEXT NOT NULL,
                            target TEXT NOT NULL,
                            owner TEXT DEFAULT NULL,
                            state TEXT DEFAULT 'running',
                            data TEXT DEFAULT '{}',
                            saved_at INTEGER DEFAULT (strftime('%s','now')),
                            UNIQUE(game_name, scope, target)
                        )
                    """)
                    # Retry save
                    await db.execute("INSERT ...", ...)  # repeat params
                else:
                    raise

    async def session_load(self, scope: str, target: str) -> Optional[dict]:
        async with _db(self.core.db_path) as db:
            async with db.execute(
                "SELECT data FROM game_sessions "
                "WHERE game_name=? AND scope=? AND target=?",
                (self.name, scope, target)
            ) as cursor:
                row = await cursor.fetchone()
        return json.loads(row["data"]) if row else None

    async def session_clear(self, session: GameSession):
        async with _db(self.core.db_path) as db:
            await db.execute(
                "DELETE FROM game_sessions "
                "WHERE game_name=? AND scope=? AND target=?",
                (self.name, session.scope, session.target)
            )

    async def on_pubmsg(self, session: GameSession, nick: str, text: str, event=None):
        pass

    async def on_privmsg(self, nick: str, text: str, event=None):
        pass

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

    async def load_game(self, game_name: str, scope: str = None, target: str = None, owner: str = None) -> Game:
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

            async with _db(self.core.db_path) as db:
                await db.execute(
                    "INSERT INTO loaded_modules(name, type, scope, owner) VALUES(?,?,?,?) "
                    "ON CONFLICT(name, type) DO UPDATE SET "
                    "owner=excluded.owner, loaded_at=strftime('%s','now')",
                    (game_name, "game", target, owner)
                )

            log.info("Loaded game: %s", game_name)
            return game

        except Exception as e:
            raise RuntimeError(f"Failed to load game {game_name}: {e}") from e

    async def unload_game(self, game_name: str, scope: str = None, target: str = None):
        game = self.games.pop(game_name, None)
        if not game:
            return
        await game.unload()

        async with _db(self.core.db_path) as db:
            await db.execute(
                "DELETE FROM loaded_modules WHERE name=? AND type='game'",
                (game_name, target)
            )

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

    async def dispatch_notice(self, nick: str, text: str, event=None):
        for game in self.games.values():
            # NOTICE is not channel-scoped, iterate all channel sessions
            for session in game.sessions.values():
                try:
                    await game.on_NOTICE(session, nick, text, event=event)
                except Exception as e:
                    log.error("Game %s on_NOTICE error: %s", game.name, e, exc_info=True)                

    async def tick(self):
        for name, game in self.games.items():
            try:
                if hasattr(game, "on_tick"):
                    await game.on_tick()
            except Exception as e:
                log.error("Game %s tick error: %s", name, e, exc_info=True)


__all__ = ["Game", "GameSession", "GameContext", "GameManager"]