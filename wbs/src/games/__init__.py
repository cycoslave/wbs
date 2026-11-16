# games/__init__.py
"""
Game manager for WBS.

Games are logic/session engines. Plugins or commands modules should call into
GameManager to start games, stop games, and dispatch player actions.
"""
import asyncio
import dataclasses
import enum
import importlib
import inspect
import logging
import json
import math
import re
import sys
import aiosqlite
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Type

from ..db import get_db 
from ..logsafe import handler_error

log = logging.getLogger("wbs.games")
_UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)
_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`\[]?([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)
_GAME_MODULE_PREFIX = "src.games."
_SKIP = object()


# ---------------------------------------------------------------------------
# session.data <-> JSON (GAM-2 / GAM-8)
#
# session.data holds sets, dataclass players, datetimes and enums; plain
# json.dumps refused the first one (werewolf could not start) and turned the
# others into {} / strings.  encode_state() turns the data into tagged JSON
# values, decode_state() rebuilds the original objects.  Runtime-only values
# (locks, events, tasks, callables) are dropped: inside a dataclass they
# become None, anywhere else they are left out.
# ---------------------------------------------------------------------------

def _qualname(cls) -> str:
    return f"{cls.__module__}:{cls.__qualname__}"


def _resolve_class(ref: str):
    """Resolve 'module:QualName'.  Only game modules are imported for this;
    any other module must already be loaded (no import side effects)."""
    mod_name, _, qual = ref.partition(":")
    obj = sys.modules.get(mod_name)
    if obj is None:
        if not mod_name.startswith(_GAME_MODULE_PREFIX):
            raise ValueError(f"refusing to restore {ref!r}: not a game class")
        obj = importlib.import_module(mod_name)
    for part in qual.split("."):
        obj = getattr(obj, part)
    return obj


def encode_state(value: Any, unserializable=_UNSERIALIZABLE) -> Any:
    """Turn session data into JSON-safe values (sets/dataclasses/... tagged)."""
    if isinstance(value, unserializable) or (callable(value) and not isinstance(value, type)
                                              and not dataclasses.is_dataclass(value)):
        return _SKIP
    if isinstance(value, enum.Enum):
        return {"__enum__": _qualname(type(value)),
                "value": encode_state(value.value, unserializable)}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, datetime):
        return {"__datetime__": value.isoformat()}
    if isinstance(value, date):
        return {"__date__": value.isoformat()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {}
        for f in dataclasses.fields(value):
            v = encode_state(getattr(value, f.name), unserializable)
            fields[f.name] = None if v is _SKIP else v
        return {"__dataclass__": _qualname(type(value)), "fields": fields}
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            ev = encode_state(v, unserializable)
            if ev is not _SKIP:
                out[str(k)] = ev
        return out
    if isinstance(value, (set, frozenset)):
        items = [encode_state(v, unserializable) for v in value]
        items = [v for v in items if v is not _SKIP]
        try:
            items = sorted(items)
        except TypeError:
            pass
        return {"__set__": items}
    if isinstance(value, (list, tuple)):
        items = [encode_state(v, unserializable) for v in value]
        return [v for v in items if v is not _SKIP]
    return _SKIP


def decode_state(value: Any) -> Any:
    """Inverse of encode_state()."""
    if isinstance(value, list):
        return [decode_state(v) for v in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"__set__"}:
        return set(decode_state(v) for v in value["__set__"])
    if set(value) == {"__datetime__"}:
        return datetime.fromisoformat(value["__datetime__"])
    if set(value) == {"__date__"}:
        return date.fromisoformat(value["__date__"])
    if set(value) == {"__enum__", "value"}:
        cls = _resolve_class(value["__enum__"])
        if not (isinstance(cls, type) and issubclass(cls, enum.Enum)):
            raise ValueError(f"{value['__enum__']} is not an Enum")
        return cls(decode_state(value["value"]))
    if set(value) == {"__dataclass__", "fields"}:
        cls = _resolve_class(value["__dataclass__"])
        if not (isinstance(cls, type) and dataclasses.is_dataclass(cls)):
            raise ValueError(f"{value['__dataclass__']} is not a dataclass")
        known = {f.name for f in dataclasses.fields(cls) if f.init}
        kwargs = {k: decode_state(v) for k, v in value["fields"].items() if k in known}
        return cls(**kwargs)
    return {k: decode_state(v) for k, v in value.items()}


def _collect_tasks(value: Any, out: list, depth: int = 0):
    """Every asyncio.Task held anywhere in session data (nested dataclasses too)."""
    if depth > 6:
        return
    if isinstance(value, asyncio.Task):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _collect_tasks(v, out, depth + 1)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            _collect_tasks(v, out, depth + 1)
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            _collect_tasks(getattr(value, f.name, None), out, depth + 1)


# GAM-9: only the "channel" scope is supported.  Every game declares
# scopes={"channel"}, `.gstart` refuses the others and dispatch_pubmsg looks
# up channel sessions only.  The "user" / "subnet" / "botnet" values in the
# comments below (and GameContext) are NOT implemented: they are reserved
# names, nothing creates or reaches such a session.
SUPPORTED_SCOPES = ("channel",)


@dataclass
class GameContext:
    """Unused (GAM-9): reserved for scopes other than "channel"."""
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
    task: Optional[asyncio.Task] = None

    @property
    def key(self) -> str:
        return f"{self.scope}:{self.target}".lower()

    @property
    def players(self) -> set[str]:
        """Nicks taking part in the current round (shown by .gsessions)."""
        players = self.data.get("players")
        if isinstance(players, dict):
            return {str(nick) for nick in players}
        # Betting games keep no player table: their bettors / casters are
        # the players (roulette bets {nick: [Bet]}, horseracing [Bet],
        # fishing lines {nick: ActiveLine}).
        nicks: set[str] = set()
        for name in ("players", "bets", "lines"):
            value = self.data.get(name)
            if not value:
                continue
            items = value.values() if isinstance(value, dict) else value
            for item in items:
                for obj in (item if isinstance(item, list) else [item]):
                    nick = obj if isinstance(obj, str) else getattr(obj, "nick", None)
                    if nick:
                        nicks.add(nick)
            if nicks:
                break
        return nicks

class Game:
    name = "base"
    scopes = {"channel"}
    allow_multiple_sessions = False
    TABLE_SQL: List[str] = []
    # Runtime-only session.data values (locks, events, tasks) that must never be
    # JSON-persisted. Exposed as a class attribute so session_save() can use
    # self._UNSERIALIZABLE on the base class too (SAST-019); subclasses may
    # override it with a wider tuple.
    _UNSERIALIZABLE = _UNSERIALIZABLE
    # GAM-8: games whose round state (players, bets, hands, phase) is put
    # back after a restart.  The others restart clean with fresh settings.
    RESTORE_STATE = False
    # phase -> coroutine method that continues a round restored after a
    # restart (the method receives the session).
    RESUME_PHASES: Dict[str, str] = {}
    # Debounce for the save that follows every state change (GAM-7/GAM-8).
    SAVE_DEBOUNCE = 0.5
    # GAM-5: settings that `.gstart <game> channel <#c> key=value` may
    # override for one session: name -> (type, min, max).  Anything else is
    # refused with the list of valid names.
    SETTINGS: Dict[str, tuple] = {}
    # (low, high) setting names that must satisfy cfg[low] <= cfg[high].
    SETTING_PAIRS: tuple = ()

    @classmethod
    def parse_start_args(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Validate `.gstart` key=value args against SETTINGS (GAM-5).

        Returns the cleaned {name: number}; raises ValueError naming the
        problem (unknown keys come with the list of valid ones).
        """
        if not raw:
            return {}
        valid = ", ".join(sorted(cls.SETTINGS)) or "none"
        unknown = sorted(k for k in raw if k not in cls.SETTINGS)
        if unknown:
            raise ValueError(
                f"unknown setting{'s' if len(unknown) > 1 else ''} "
                f"{', '.join(unknown)} for {cls.name}; valid settings: {valid}")
        out: Dict[str, Any] = {}
        for key, value in raw.items():
            kind, lo, hi = cls.SETTINGS[key]
            try:
                if isinstance(value, bool):
                    raise ValueError
                num = float(value)
                if not math.isfinite(num):
                    raise ValueError
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be a number") from None
            if kind is int:
                if num != int(num):
                    raise ValueError(f"{key} must be a whole number")
                num = int(num)
            if not lo <= num <= hi:
                raise ValueError(f"{key} must be between {lo} and {hi}")
            out[key] = num
        return out

    def check_settings(self, cfg: Dict[str, Any]) -> Optional[str]:
        """Cross-check a merged settings dict (min <= max ...): an error
        text, or None when fine."""
        for low, high in self.SETTING_PAIRS:
            if low in cfg and high in cfg and cfg[low] > cfg[high]:
                return f"{low} ({cfg[low]}) must not be above {high} ({cfg[high]})"
        return None

    def settings_of(self, session: GameSession) -> Dict[str, Any]:
        """The live settings dict of a session (what the game code reads)."""
        return session.data.setdefault("cfg", {})

    def __init__(self, core):
        self.core = core
        self.log = logging.getLogger(f"wbs.games.{self.name}")
        self.sessions: Dict[str, GameSession] = {}
        self._save_lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._save_pending = False
        self._last_saved: Dict[str, str] = {}

    @classmethod
    def owned_tables(cls) -> List[str]:
        """Tables this game creates (from TABLE_SQL)."""
        tables: List[str] = []
        for sql in cls.TABLE_SQL:
            for name in _CREATE_TABLE_RE.findall(sql):
                if name not in tables:
                    tables.append(name)
        return tables

    @classmethod
    async def uninstall(cls, db_path: str) -> List[str]:
        """Drop every table the game owns (only `.gpurge` calls this)."""
        tables = cls.owned_tables()
        async with get_db(db_path) as db:
            for table in tables:
                await db.execute(f'DROP TABLE IF EXISTS "{table}"')
        return tables

    async def load(self):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO loaded_modules(name, type, scope, owner, autoload) VALUES(?,?,?,?,1) "
                "ON CONFLICT(name, type) DO UPDATE SET "
                "autoload=1, owner=excluded.owner, loaded_at=strftime('%s','now')",
                (self.name, "game", None, None)
            )

    async def unload(self):
        """Forget the game: its loaded_modules row and saved sessions, in one
        transaction.  Game tables (cash, stats, settings) are kept (GAM-4)."""
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "DELETE FROM loaded_modules WHERE name=? AND type='game'",
                (self.name,)
            )
            await db.execute(
                "DELETE FROM game_sessions WHERE game_name=?",
                (self.name,)
            )
        self._last_saved.clear()

    async def start_session(self, session: GameSession, restore: bool = False):
        # GAM-5: `.gstart` key=value args beat the stored settings for this
        # session (the games load their settings before calling this).
        args = session.data.get("start_args")
        if args:
            cfg = self.settings_of(session)
            cfg.update(args)
            err = self.check_settings(cfg)
            if err:
                raise ValueError(err)
        session.state = "running"
        session.data['_restore'] = restore
        await self.session_save(session)

    async def resume_session(self, session: GameSession) -> bool:
        """Continue a round that was in progress when the bot restarted.

        Re-arms the phase's timer/loop task and tells the channel, so a
        restart mid-round no longer drops the round silently (GAM-8).
        """
        phase = session.data.get("phase")
        method = self.RESUME_PHASES.get(phase)
        if not method:
            return False
        players = sorted(session.players)
        who = f" Players: {', '.join(players)}." if players else ""
        await self.send_privmsg(
            session.target,
            f"[{self.name}] Game restored after a restart: the round continues ({phase}).{who}",
        )
        self.spawn_round(session, getattr(self, method)(session))
        return True

    def spawn_round(self, session: GameSession, coro) -> asyncio.Task:
        """Run a round / phase loop as the session's own task (GAM-11).

        Handlers must never await a whole round: core dispatches events one
        at a time, so a round awaited inside on_PUBMSG blocks every later
        command (the players' own moves included) until it ends.  The task
        replaces session.task (an older one is cancelled unless it is the
        caller itself) and is cancelled by stop_session / `.gunload`.
        """
        old = session.task
        if old is not None and not old.done() and old is not asyncio.current_task():
            old.cancel()
        task = asyncio.create_task(self._run_round(session, coro),
                                   name=f"game:{self.name}:{session.key}")
        # Cancelled before its first step, the wrapper never awaits `coro`;
        # close it then (no "coroutine was never awaited" warning).
        task.add_done_callback(lambda _t: coro.close())
        session.task = task
        return task

    async def _run_round(self, session: GameSession, coro):
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.log.error("round task of %s failed: %s", session.key, e, exc_info=True)

    async def stop_session(self, key: str):
        session = self.sessions.pop(key.lower(), None)
        if not session:
            return

        session.state = "stopped"
        tasks: list = []
        if session.task is not None:
            tasks.append(session.task)
        _collect_tasks(session.data, tasks)
        current = asyncio.current_task()
        for task in tasks:
            if task is current or task.done():
                continue
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                self.log.warning("task of %s ended with %s", session.key, e)
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

    def _encode_session(self, session: GameSession) -> str:
        safe = encode_state(session.data, self._UNSERIALIZABLE)
        return json.dumps(safe if safe is not _SKIP else {})

    async def session_save(self, session: GameSession, only_if_changed: bool = False):
        if not session.scope or not session.target:
            return 
        async with self._save_lock:
            if only_if_changed and self.sessions.get(session.key) is not session:
                return  # stopped/unloaded meanwhile: never resurrect its row
            blob = self._encode_session(session)
            marker = f"{session.state}\0{blob}"
            if only_if_changed and self._last_saved.get(session.key) == marker:
                return
            await self._write_session(session, blob)
            self._last_saved[session.key] = marker

    async def _write_session(self, session: GameSession, blob: str):
        upsert_sql = """
                    INSERT INTO game_sessions(game_name, scope, target, owner, state, data) 
                    VALUES(?,?,?,?,?,?) 
                    ON CONFLICT(game_name, scope, target) DO UPDATE SET 
                    state = excluded.state, 
                    data = excluded.data, 
                    saved_at = strftime('%s','now')
                """
        params = (self.name, session.scope, session.target, session.owner,
                  session.state, blob)

        async with get_db(self.core.db_path) as db:
            # Auto-create if missing
            try:
                await db.execute(upsert_sql, params)
            except aiosqlite.OperationalError as e:
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
                    await db.execute(upsert_sql, params)
                else:
                    raise

    def request_save(self):
        """Schedule a debounced save of every changed session (GAM-7/GAM-8).

        A request that arrives while a flush is already writing marks the
        game dirty, so the flush runs once more afterwards (no lost update).
        """
        self._save_pending = True
        if self._flush_task is not None and not self._flush_task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._flush_task = loop.create_task(self._flush_later())

    async def _flush_later(self):
        while self._save_pending:
            await asyncio.sleep(self.SAVE_DEBOUNCE)
            self._save_pending = False
            await self.flush_sessions()
        self._flush_task = None

    async def flush_sessions(self):
        """Save every running session whose state changed since its last save."""
        for session in list(self.sessions.values()):
            if session.state != "running":
                continue
            try:
                await self.session_save(session, only_if_changed=True)
            except Exception as e:
                self.log.error("saving %s failed: %s", session.key, e, exc_info=True)

    async def session_load(self, scope: str, target: str) -> Optional[dict]:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT data FROM game_sessions "
                "WHERE game_name=? AND scope=? AND target=?",
                (self.name, scope, target)
            ) as cursor:
                row = await cursor.fetchone()
        return decode_state(json.loads(row["data"])) if row else None

    async def session_clear(self, session: GameSession):
        async with self._save_lock:
            async with get_db(self.core.db_path) as db:
                await db.execute(
                    "DELETE FROM game_sessions "
                    "WHERE game_name=? AND scope=? AND target=?",
                    (self.name, session.scope, session.target)
                )
            self._last_saved.pop(session.key, None)

    async def on_pubmsg(self, session: GameSession, nick: str, text: str, event=None):
        pass

    async def on_privmsg(self, nick: str, text: str, event=None):
        pass

    async def send_privmsg(self, target, message):
        """Send message to channel/user"""
        self.core.send_irc({
            'cmd': 'msg',
            'target': target,
            'text': message
        })
        # Every state change in a game is announced: save after it.
        self.request_save()
    
    async def send_notice(self, target, message):
        """Send notice to user"""
        self.core.send_irc({
            'cmd': 'notice',
            'target': target,
            'text': message
        })    
        self.request_save()

class GameManager:
    def __init__(self, core):
        self.core = core
        self.games: Dict[str, Game] = {}

    @staticmethod
    def _game_class(game_name: str) -> Type[Game]:
        module = importlib.import_module(f"src.games.{game_name}")
        game_classes = [
            obj for _, obj in inspect.getmembers(module, inspect.isclass)
            if issubclass(obj, Game)
            and obj is not Game
            and obj.__module__ == module.__name__
        ]
        if not game_classes:
            raise ValueError(f"No Game subclass found in src.games.{game_name}")
        return game_classes[0]

    async def load_game(self, game_name: str, scope: str = None, target: str = None, owner: str = None) -> Game:
        if game_name in self.games:
            return self.games[game_name]

        try:
            game_cls = self._game_class(game_name)
            game = game_cls(self.core)
            self.games[game_name] = game

            await game.load()

            async with get_db(self.core.db_path) as db:
                await db.execute(
                    "INSERT INTO loaded_modules(name, type, scope, owner) VALUES(?,?,?,?) "
                    "ON CONFLICT(name, type) DO UPDATE SET "
                    "owner=excluded.owner, loaded_at=strftime('%s','now')",
                    (game_name, "game", target, owner)
                )

            #log.info("Loaded game: %s", game_name)
            return game

        except Exception as e:
            raise RuntimeError(f"Failed to load game {game_name}: {e}") from e

    async def unload_game(self, game_name: str, scope: str = None, target: str = None):
        """GAM-1: stop every session (tasks cancelled, stop announced in its
        channel), then drop the loaded_modules + game_sessions rows in one
        transaction, then forget the game.  If the database step fails the
        game stays registered (no half-unloaded state) and the error is raised.
        """
        game = self.games.get(game_name)
        if not game:
            return False
        for key in list(game.sessions):
            await game.stop_session(key)
        if game._flush_task is not None and not game._flush_task.done():
            game._flush_task.cancel()
        await game.unload()
        if self.games.get(game_name) is game:
            del self.games[game_name]

        log.info("Unloaded game: %s", game_name)
        return True

    async def purge_game(self, game_name: str) -> List[str]:
        """Delete a game's stored data (tables + rows).  Refused while loaded."""
        if game_name in self.games:
            raise RuntimeError(f"{game_name} is loaded; .gunload {game_name} first")
        tables = await self._game_class(game_name).uninstall(self.core.db_path)
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "DELETE FROM loaded_modules WHERE name=? AND type='game'", (game_name,))
            await db.execute(
                "DELETE FROM game_sessions WHERE game_name=?", (game_name,))
        log.warning("Purged game %s: dropped tables %s", game_name, tables or "none")
        return tables

    async def start_game(
        self,
        game_name: str,
        scope: str,
        target: str,
        owner: Optional[str] = None,
        restore: bool = False,
        **kwargs: Any,
    ) -> GameSession:
        game = await self.load_game(game_name)

        if scope not in game.scopes:
            raise ValueError(f"{game_name} does not support scope {scope}")

        saved = None
        if restore:
            try:
                saved = await game.session_load(scope, target)
            except Exception as e:
                log.error("Could not decode saved %s session %s:%s: %s",
                          game_name, scope, target, e)
        # GAM-5: start args are checked against the game's SETTINGS and kept
        # as session.data["start_args"], so they survive a restart.
        if restore and not kwargs and saved:
            kwargs = dict(saved.get("start_args") or {})
        start_args = game.parse_start_args(kwargs)
        kwargs = {"start_args": start_args} if start_args else {}
        session = await game.create_session(scope, target, owner=owner, **kwargs)
        try:
            # start_session sets fresh defaults and reloads cfg from the
            # game's settings table; the saved round state goes on top.
            await game.start_session(session, restore=restore)
            if saved and game.RESTORE_STATE:
                for key, value in saved.items():
                    if key not in ("cfg", "_restore", "start_args"):
                        session.data[key] = value
                await game.resume_session(session)
                await game.session_save(session)
        except Exception:
            # Never leave a half-started session behind.
            if game.sessions.get(session.key) is session:
                del game.sessions[session.key]
            raise
        return session

    async def stop_game(self, game_name: str, scope: str, target: str) -> bool:
        """Stop one session; False if the game or session does not exist."""
        game = self.games.get(game_name.lower())
        if not game or game.get_session(scope, target) is None:
            return False
        await game.stop_session(f"{scope}:{target}".lower())
        return True

    def get_game(self, game_name: str) -> Optional[Game]:
        return self.games.get(game_name)

    def get_session(self, game_name: str, scope: str, target: str) -> Optional[GameSession]:
        game = self.games.get(game_name)
        if not game:
            return None
        return game.get_session(scope, target)

    # Handlers await while `.gload`/`.gunload` and session start/stop change
    # self.games / game.sessions: iterate snapshots (same class as PLG-1).
    async def dispatch_pubmsg(self, channel: str, nick: str, text: str, event=None):
        for game in list(self.games.values()):
            session = game.get_session("channel", channel)
            if not session:
                continue
            try:
                await game.on_PUBMSG(session, nick, text, event=event)
            except Exception as e:
                handler_error(log, f"Game {game.name} on_pubmsg error", "PUBMSG", e)
            game.request_save()

    async def dispatch_privmsg(self, nick: str, text: str, event=None):
        for game in list(self.games.values()):
            try:
                await game.on_privmsg(nick, text, event=event)
            except Exception as e:
                handler_error(log, f"Game {game.name} on_privmsg error", "PRIVMSG", e)
            game.request_save()
        # GAM-6: private game commands (werewolf night actions) are taken by
        # PRIVMSG too, as a fallback for clients that cannot /notice.
        if text.lstrip().startswith("!"):
            if await self.dispatch_notice(nick, text, event=event) and event is not None:
                event["handled"] = True    # no "Unknown command" reply

    async def dispatch_notice(self, nick: str, text: str, event=None) -> bool:
        """A NOTICE from a user to the bot (GAM-6).  NOTICE is not channel
        scoped: every session of a game with on_NOTICE sees it.  True when a
        handler said it consumed the command."""
        consumed = False
        for game in list(self.games.values()):
            handler = getattr(game, "on_NOTICE", None)
            if handler is None:
                continue
            for session in list(game.sessions.values()):
                try:
                    if await handler(session, nick, text, event=event):
                        consumed = True
                except Exception as e:
                    handler_error(log, f"Game {game.name} on_NOTICE error", "NOTICE", e)
            game.request_save()
        return consumed

    async def tick(self):
        """Run every game's on_tick (Core calls this from its `game_tick`
        registry task, GAM-6)."""
        for name, game in list(self.games.items()):
            handler = getattr(game, "on_tick", None)
            if handler is None:
                continue
            try:
                await handler()
            except Exception as e:
                log.error("Game %s tick error: %s", name, e, exc_info=True)
            game.request_save()


__all__ = ["Game", "GameSession", "GameContext", "GameManager",
           "encode_state", "decode_state"]
