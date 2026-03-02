# plugins/__init__.py
"""
Plugin manager for WBS.
"""
import importlib
import logging
import asyncio

log = logging.getLogger("wbs.core")

class Plugin:
    """Base plugin interface"""
    def __init__(self, core):
        self.core = core
    
    async def load(self):
        """Called when plugin loads"""
        pass
    
    async def unload(self):
        """Called when plugin unloads - cleanup timers/resources"""
        pass

class PluginManager:
    def __init__(self, core):
        self.core = core
        self.plugins = {}
    
    async def load_plugin(self, name: str):
        """Dynamically load plugin module"""
        module = importlib.import_module(f'.{name}', package='src.plugins')
        plugin = module.Plugin(self.core)
        await plugin.load()
        self.plugins[name] = plugin
        log.info(f"Loaded plugin: {name}")
    
    async def unload_plugin(self, name: str):
        """Unload and cleanup plugin"""
        if name in self.plugins:
            plugin = self.plugins.pop(name)
            await plugin.unload()
            log.info(f"Unloaded plugin: {name}")
    
    async def dispatch(self, event_type: str, event: dict):
        """Dispatch events to plugin handlers: on_<EVENT_TYPE>"""
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
                    log.error(f"Plugin {name}.{method_name} error: {e}")
            else:
                log.debug(f"[DISPATCH] No handler {name}.{method_name}") 
