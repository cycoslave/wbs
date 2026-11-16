# plugins/__init__.py
"""
Plugin manager for WBS.
"""
import importlib
import inspect
import logging
import asyncio
import re
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, NamedTuple, Optional

from ..db import get_db 
from ..logsafe import event_summary, handler_error

log = logging.getLogger("wbs.plugins")

# Plugin names (PLG-5 / D8): checked before any path or import use.
PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
PLUGIN_NAME_RULE_TEXT = ("Invalid plugin name. Use 1-32 characters: a lowercase letter, "
                         "then lowercase letters, digits or '_' (no paths, no '.py').")
# The plugins package directory; never the process CWD.
PLUGINS_DIR = Path(__file__).resolve().parent

_CREATE_TABLE_RE = re.compile(r"CREATE TABLE IF NOT EXISTS\s+(\w+)", re.IGNORECASE)


def valid_plugin_name(name: str) -> bool:
    return isinstance(name, str) and PLUGIN_NAME_RE.fullmatch(name) is not None


def plugin_files() -> List[str]:
    """Names of the plugin modules on disk in the plugins package."""
    return sorted(p.stem for p in PLUGINS_DIR.glob("*.py")
                  if p.name != "__init__.py" and valid_plugin_name(p.stem))


def plugin_exists(name: str) -> bool:
    return valid_plugin_name(name) and (PLUGINS_DIR / f"{name}.py").is_file()


class PluginCommand(NamedTuple):
    """A partyline command contributed by a plugin (PLG-6)."""
    name: str
    owner: str                  # plugin name
    min_flag: Optional[str]     # COMMAND_MIN_FLAGS value (None = any session)
    help: str                   # "<usage> - what it does"


# name -> PluginCommand for every command currently registered by a loaded
# plugin.  The matching entries in commands.COMMANDS and
# partyline.COMMAND_MIN_FLAGS exist exactly as long as the entry here does.
PLUGIN_COMMANDS: Dict[str, PluginCommand] = {}


class Plugin:
    """Base plugin interface"""
    name = "base"
    TABLE_SQL: List[str] = []

    def __init__(self, core):
        self.core = core
        self.log = logging.getLogger(f"wbs.plugins.{self.name}")

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.unload()        
    
    async def load(self):
        """Record the plugin in loaded_modules, then run custom setup."""
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO loaded_modules(name, type, scope, autoload) VALUES(?, 'plugin', NULL, 1) "
                "ON CONFLICT(name, type) DO UPDATE SET loaded_at=strftime('%s','now')",
                (self.name,)
            )
    
    def register_command(self, name: str, handler: Callable[[str, str], Awaitable[Any]],
                         min_flag: Optional[str], help: str = "") -> None:
        """Add a partyline command (call from load()).

        `handler(handle, arg)` returns a string, a list of strings or None;
        each line goes to the caller.  The command is merged into
        commands.COMMANDS, partyline.COMMAND_MIN_FLAGS (the flag gate for
        telnet/DCC/IRC `/msg` sessions; the console is the operator and
        bypasses it) and `.help`.  Unloading the plugin removes it again.
        `min_flag` is one GLOBAL_FLAGS letter, or None for any session.
        A name that a core command or another plugin owns is refused.
        """
        from .. import commands
        from ..partyline import COMMAND_MIN_FLAGS
        from ..user import GLOBAL_FLAGS

        name = (name or "").lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name):
            raise ValueError(f"invalid plugin command name {name!r}")
        if min_flag is not None and (len(min_flag) != 1 or min_flag not in GLOBAL_FLAGS):
            raise ValueError(f"unknown flag {min_flag!r} for command .{name}")
        existing = PLUGIN_COMMANDS.get(name)
        if existing is not None:
            if existing.owner != self.name:
                raise ValueError(f".{name} is already provided by plugin {existing.owner}")
        elif name in commands.COMMANDS or name in COMMAND_MIN_FLAGS:
            raise ValueError(f".{name} is a core command")

        async def run(core, handle, session_id, arg, respond):
            out = await handler(handle, arg)
            if out is None:
                return
            for item in ([out] if isinstance(out, str) else out):
                for line in str(item).split("\n"):
                    if line.strip():
                        await respond(line)

        run.__name__ = f"cmd_{name}"
        run.__doc__ = help
        commands.COMMANDS[name] = run
        COMMAND_MIN_FLAGS[name] = min_flag
        PLUGIN_COMMANDS[name] = PluginCommand(name, self.name, min_flag, help or name)

    def unregister_commands(self) -> List[str]:
        """Remove every command this plugin registered; returns the names."""
        from .. import commands
        from ..partyline import COMMAND_MIN_FLAGS

        gone = [n for n, c in PLUGIN_COMMANDS.items() if c.owner == self.name]
        for n in gone:
            del PLUGIN_COMMANDS[n]
            commands.COMMANDS.pop(n, None)
            COMMAND_MIN_FLAGS.pop(n, None)
        return gone

    async def unload(self):
        """Release runtime resources (timers, handlers, clients).

        Plugin data (every table in TABLE_SQL) is kept: an unload/load or a
        reload never loses settings, stats or audit rows (PLG-3).  Deleting
        the data is `uninstall()`, reached only through `.plugin purge`.
        Registered partyline commands are removed here, and by the
        PluginManager too for plugins whose unload() skips super().
        """
        self.unregister_commands()

    @classmethod
    def owned_tables(cls) -> List[str]:
        """Tables this plugin creates (from TABLE_SQL)."""
        tables: List[str] = []
        for sql in cls.TABLE_SQL:
            for name in _CREATE_TABLE_RE.findall(sql):
                if name not in tables:
                    tables.append(name)
        return tables

    @classmethod
    async def uninstall(cls, db_path: str) -> List[str]:
        """Drop every table the plugin owns; returns the dropped names.

        Destroys the plugin's data for good.  Only `.plugin purge <name>`
        (PluginManager.purge_plugin) calls this, never unload or reload.
        """
        tables = cls.owned_tables()
        async with get_db(db_path) as db:
            for table in tables:
                await db.execute(f'DROP TABLE IF EXISTS "{table}"')
        return tables

    async def on_UNKNOWN(self, event):
        pass

    async def msg_to_bots(self, command: str):
        """Broadcast space-separated: netop reqop target=WBS2 chan=#wbs."""
        await self.core.botnet.broadcast_all(command)

    async def msg_to_bot(self, botname: str, command: str):
        """Send to specific bot."""
        peer = self.core.botnet.peers.get(botname.lower())
        if peer and peer.connected:
            await self.core.botnet._safe_send(peer.writer, f"CMD {command}\n")
            
    # Helper methods for IRC communication
    async def send_privmsg(self, target, message):
        """Send message to channel/user"""
        self.core.send_irc({
            'cmd': 'msg',
            'target': target,
            'text': message
        })
    
    async def send_notice(self, target, message):
        """Send notice to user"""
        self.core.send_irc({
            'cmd': 'notice',
            'target': target,
            'text': message
        })
    
    async def send_mode(self, channel, mode, target=None):
        """Send mode command.

        Emits the schema the IRC consumer (irc.py execute_command, cmd 'mode')
        reads: a single 'modes' string.  Callers must validate channel, mode
        and target before calling (no whitespace/CR/LF smuggling).
        """
        modes = f"{mode} {target}" if target else mode
        self.core.send_irc({
            'cmd': 'mode',
            'channel': channel,
            'modes': modes,
        })

    async def send_kick(self, channel, nick, reason=''):
        """Send kick command (irc.py execute_command, cmd 'kick')."""
        self.core.send_irc({
            'cmd': 'kick',
            'channel': channel,
            'nick': nick,
            'reason': reason,
        })


class PluginManager:
    def __init__(self, core):
        self.core = core
        self.plugins: Dict[str, Any] = {}
        # Serialises load/unload/purge so two `.load x` never build two
        # instances and an unload never interleaves with a half-done load.
        self._lock = asyncio.Lock()

    @staticmethod
    def _check_name(plugin_name: str) -> None:
        """PLG-5 / D8: validate before any path or import use."""
        if not valid_plugin_name(plugin_name):
            raise ValueError(PLUGIN_NAME_RULE_TEXT)
        if not plugin_exists(plugin_name):
            raise FileNotFoundError(f"{plugin_name}.py not found in src/plugins/")

    @staticmethod
    def _plugin_class(plugin_name: str):
        """The plugin class defined in src.plugins.<plugin_name>.

        Any subclass of the base Plugin that the module itself defines counts,
        whatever its class name (the shipped example is `class Plugin(Plugin)`,
        PLG-2); the base class is excluded by identity, not by name.  If the
        module defines several, the one whose `name` matches the module wins.
        """
        module = importlib.import_module(f"src.plugins.{plugin_name}")
        classes = [
            obj for _, obj in inspect.getmembers(module, inspect.isclass)
            if issubclass(obj, Plugin) and obj is not Plugin
            and obj.__module__ == module.__name__
        ]
        if not classes:
            raise ValueError(f"No Plugin subclass found in src.plugins.{plugin_name}")
        for cls in classes:
            if getattr(cls, "name", None) == plugin_name:
                return cls
        return classes[0]

    async def _set_autoload(self, plugin_name: str, autoload: bool) -> None:
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO loaded_modules(name, type, autoload) VALUES(?, 'plugin', ?) "
                "ON CONFLICT(name, type) DO UPDATE SET autoload=excluded.autoload"
                + (", loaded_at=strftime('%s','now')" if autoload else ""),
                (plugin_name, 1 if autoload else 0)
            )

    async def autoload_names(self) -> List[str]:
        """Plugins flagged to load on start (loaded_modules autoload=1)."""
        async with get_db(self.core.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT name FROM loaded_modules WHERE type='plugin' AND autoload=1")
        return sorted(r["name"] for r in rows)

    async def load_plugin(self, plugin_name: str):
        async with self._lock:
            return await self._load(plugin_name)

    async def _load(self, plugin_name: str):
        if plugin_name in self.plugins:
            return self.plugins[plugin_name]

        try:
            self._check_name(plugin_name)
            plugin_instance = self._plugin_class(plugin_name)(self.core)
            try:
                await plugin_instance.load()
            except BaseException:
                # A half-loaded plugin must not stay registered.
                try:
                    await plugin_instance.unload()
                except Exception as e:
                    log.warning("Cleanup after failed load of %s: %s", plugin_name, e)
                plugin_instance.unregister_commands()
                raise
            self.plugins[plugin_name] = plugin_instance
            # PLG-4: `.load` (re)enables autoload after an earlier `.unload`.
            await self._set_autoload(plugin_name, True)
            return plugin_instance
        except Exception as e:
            raise RuntimeError(f"Failed to load {plugin_name}: {e}")

    async def unload_plugin(self, name: str) -> bool:
        """Unload a plugin; it stays unloaded across restarts (autoload=0).

        Plugin data is kept (PLG-3).  Returns False if it was not loaded.
        """
        async with self._lock:
            return await self._unload(name)

    async def _unload(self, name: str) -> bool:
        plugin = self.plugins.pop(name, None)
        if not plugin:
            log.warning("Plugin %s not loaded", name)
            return False
        try:
            await plugin.unload()
        finally:
            plugin.unregister_commands()    # PLG-6, even if unload() skipped super()
            # PLG-4: remembered, so a restart does not bring it back.
            await self._set_autoload(name, False)
        log.info("Unloaded plugin: %s", name)
        return True

    async def reload_plugin(self, name: str) -> Plugin:
        """Unload then reload a plugin by name (data kept)."""
        async with self._lock:
            await self._unload(name)
            return await self._load(name)

    async def purge_plugin(self, plugin_name: str) -> List[str]:
        """Delete a plugin's data: drop its tables, forget its autoload row.

        Refused while the plugin is loaded.  Returns the dropped table names.
        """
        async with self._lock:
            if plugin_name in self.plugins:
                raise RuntimeError(f"{plugin_name} is loaded; .unload {plugin_name} first")
            self._check_name(plugin_name)
            tables = await self._plugin_class(plugin_name).uninstall(self.core.db_path)
            async with get_db(self.core.db_path) as db:
                await db.execute(
                    "DELETE FROM loaded_modules WHERE name=? AND type='plugin'", (plugin_name,))
            log.warning("Purged plugin %s: dropped tables %s", plugin_name, tables or "none")
            return tables

    async def dispatch(self, event_type: str, event: dict):
        # SAST-002: metadata only, never the event text (a PRIVMSG may be
        # `identify <password>`).
        log.debug("[DISPATCH] %s", event_summary(event_type, event))
        method_name = f"on_{event_type}"
        # PLG-1: handlers await, and `.load`/`.unload` change self.plugins
        # meanwhile; iterate a snapshot, and skip a plugin that was unloaded
        # (or replaced) after the snapshot was taken.
        for name, plugin in list(self.plugins.items()):
            if self.plugins.get(name) is not plugin:
                continue
            method = getattr(plugin, method_name, None)
            if method:
                log.debug("[DISPATCH] Calling %s.%s", name, method_name)
                try:
                    if asyncio.iscoroutinefunction(method):
                        await method(event)
                    else:
                        method(event)
                except Exception as e:
                    handler_error(log, f"Plugin {name}.{method_name} error", event_type, e)
            else:
                log.debug(f"[DISPATCH] No handler {name}.{method_name}")
