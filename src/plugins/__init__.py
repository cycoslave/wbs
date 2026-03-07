# plugins/__init__.py
"""
Plugin manager for WBS.
"""
import importlib
import inspect
import logging
import asyncio
from typing import Any

log = logging.getLogger("wbs.core")

class Plugin:
    """Base plugin interface"""
    def __init__(self, core):
        self.core = core

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.unload()        
    
    async def load(self):
        """Called when plugin loads"""
        pass
    
    async def unload(self):
        """Called when plugin unloads - cleanup timers/resources"""
        pass

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
            
            # Call load() method if it exists
            if hasattr(plugin_instance, 'load') and inspect.iscoroutinefunction(plugin_instance.load):
                await plugin_instance.load()
            elif hasattr(plugin_instance, 'load'):
                plugin_instance.load()
            
            # Call init() if it exists (separate lifecycle)
            if hasattr(plugin_instance, 'init') and inspect.iscoroutinefunction(plugin_instance.init):
                await plugin_instance.init()
            
            return plugin_instance
        except Exception as e:
            raise RuntimeError(f"Failed to load {plugin_name}: {e}")
    
    async def unload_plugin(self, name: str):
        """Unload plugin with cleanup"""
        if name not in self.plugins:
            log.warning(f"Plugin {name} not loaded")
            return
        plugin = self.plugins.pop(name)
        if hasattr(plugin, 'unload'):
            await plugin.unload()
        log.info(f"Unloaded plugin: {name}")
    
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