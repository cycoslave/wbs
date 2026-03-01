# plugins/example.py
import asyncio
import logging
from typing import Optional
from . import Plugin

log = logging.getLogger("wbs.core")

class Plugin(Plugin):
    """Example plugin with core and IRC timers"""
    
    def __init__(self, core):
        super().__init__(core)
        # Plugin state
        self.data = {}
        self.core_timer_name = None
        self.irc_timer_name = None
    
    async def load(self):
        """Initialize plugin and register timers"""
        # Register core timer (runs in core.py main loop)
        self.core_timer_name = 'example_core_timer'
        await self.core.register_timer(
            self.core_timer_name,
            self.core_timer_callback,
            interval=60,  # seconds
            random=False  # optional jitter
        )
        
        # Register IRC timer (runs in irc.py process)
        self.irc_timer_name = 'example_irc_timer'
        self.core.irc_q.put({
            'cmd': 'REGISTER_TIMER',
            'name': self.irc_timer_name,
            'interval': 30,
            'random': True
        })
        
        log.info("Example plugin loaded")
    
    async def unload(self):
        """Cleanup: unregister timers"""
        if self.core_timer_name:
            self.core.unregister_timer(self.core_timer_name)
        
        if self.irc_timer_name:
            self.core.irc_q.put({
                'cmd': 'UNREGISTER_TIMER',
                'name': self.irc_timer_name
            })
        
        log.info("Example plugin unloaded")
    
    # Core timer callback
    async def core_timer_callback(self):
        """Runs in core process - for database ops, botnet logic"""
        log.debug("Core timer fired")
        # Access core managers directly
        channels = await self.core.chan.getchans()
        # Process channels...
    
    # Event handlers
    async def on_PUBMSG(self, event):
        """Handle public messages"""
        nick = event['nick']
        text = event['text']
        channel = event['channel']
        # Plugin logic...
    
    async def on_MODE(self, event):
        """Handle mode changes"""
        modes = event['modes']
        # Plugin logic...
