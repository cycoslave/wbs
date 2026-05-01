# plugins/__init__.py
"""
Plugin manager for WBS.
"""
import importlib
import inspect
import logging
import asyncio
import re
import aiosqlite
from contextlib import asynccontextmanager
from typing import Any, Dict, List

log = logging.getLogger("wbs.plugins")

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
        """Create plugin-owned tables, then run custom setup."""
        async with _db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO loaded_modules(name, type, scope, autoload) VALUES(?, 'plugin', NULL, 1) "
                "ON CONFLICT(name, type) DO UPDATE SET loaded_at=strftime('%s','now')",
                (self.name,)
            )
    
    async def unload(self):
        if not self.TABLE_SQL:
            return
        async with _db(self.core.db_path) as db:
            for sql in self.TABLE_SQL:
                match = re.search(r'CREATE TABLE IF NOT EXISTS\s+(\w+)', sql, re.IGNORECASE)
                if match:
                    await db.execute(f"DROP TABLE IF EXISTS {match.group(1)}")

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
    
    async def send_mode(self, channel, mode, target):
        """Send mode command"""
        self.core.irc_q.put({
            'cmd': 'mode',
            'channel': channel,
            'mode': mode,
            'target': target
        })            

class PluginManager:
    def __init__(self, core):
        self.core = core
        self.plugins: Dict[str, Any] = {}
    
    async def load_plugin(self, plugin_name: str):
        if plugin_name in self.plugins:
            return self.plugins[plugin_name]

        try:
            module = importlib.import_module(f'src.plugins.{plugin_name}')

            plugin_classes = [
                obj for name, obj in inspect.getmembers(module, inspect.isclass)
                if issubclass(obj, Plugin) and obj.__name__ != 'Plugin' and obj.__module__ == module.__name__
            ]

            if not plugin_classes:
                raise ValueError(f"No Plugin subclass found in src.plugins.{plugin_name}")

            plugin_instance = plugin_classes[0](self.core)
            self.plugins[plugin_name] = plugin_instance
            await plugin_instance.load()

            async with _db(self.core.db_path) as db:
                await db.execute(
                    "INSERT INTO loaded_modules(name, type, autoload) VALUES(?,?,1) "
                    "ON CONFLICT(name, type) DO UPDATE SET "
                    "loaded_at=strftime('%s','now')",
                    (plugin_name, "plugin")
                )

            #log.info("Loaded plugin: %s", plugin_name)
            return plugin_instance
        except Exception as e:
            raise RuntimeError(f"Failed to load {plugin_name}: {e}")

    async def unload_plugin(self, name: str):
        plugin = self.plugins.pop(name, None)
        if not plugin:
            log.warning(f"Plugin {name} not loaded")
            return
        await plugin.unload()

        async with _db(self.core.db_path) as db:
            await db.execute(
                "DELETE FROM loaded_modules WHERE name=? AND type='plugin'",
                (name,)   # note the comma — single-element tuple
            )

        log.info("Unloaded plugin: %s", name)

    async def reload_plugin(self, name: str) -> Plugin:
        """Unload then reload a plugin by name."""
        await self.unload_plugin(name)
        return await self.load_plugin(name)        
    
    async def dispatch(self, event_type: str, event: dict):
        log.debug(f"[DISPATCH] {event_type}: {event}") 
        
        for name, plugin in self.plugins.items():
            method_name = f"on_{event_type}"
            method = getattr(plugin, method_name, None)
            if method:
                log.debug(f"[DISPATCH] Calling {name}.{method_name}") 
                try:
                    if asyncio.iscoroutinefunction(method):
                        await method(event)
                    else:
                        method(event)
                except Exception as e:
                    log.error(f"Plugin {name}.{method_name} error: {e}", exc_info=True)  # ADD exc_info=True
            else:
                log.debug(f"[DISPATCH] No handler {name}.{method_name}")