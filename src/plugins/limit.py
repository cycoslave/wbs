# src/plugins/limit.py
"""
WBS Plugin: limit.py 
version: 0.1.0
by: cyco
Description: Set and watch channel limit
"""
import asyncio
import time
import random
import logging
from typing import Dict
from . import Plugin

log = logging.getLogger("wbs.core")

class Plugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.limit_last_change: Dict[str, float] = {}
        self.LIMITADD = 15
        self.LIMITTOL = 2
        self.LIMITDELTA = 300
    
    async def load(self):
        """Register IRC timer from core"""
        self.core.irc_q.put({
            'cmd': 'REGISTER_IRC_TIMER',
            'name': 'limit',
            'interval': 300
        })
        log.info("Limit plugin loaded")
    
    async def unload(self):
        """Unregister IRC timer"""
        self.core.irc_q.put({
            'cmd': 'UNREGISTER_IRC_TIMER',
            'name': 'limit'
        })
        log.info("Limit plugin unloaded")

    async def on_UNKNOWN(self, event):
        pass

    async def on_IRC_TIMER_LIMIT(self, event):
        """ALL limit logic runs here - direct access to IRC.channels data"""
        irc_data = event['irc_data']
        
        if not irc_data['connected']:
            return
        
        log.debug("IRC limit timer fired")
        now = time.time()
        
        for chan, chan_data in irc_data['channels'].items():
            last_change = self.limit_last_change.get(chan, 0)
            if now - last_change < self.LIMITDELTA:
                continue
            
            chan_obj = await self.core.chan.get_channel(chan)
            if not chan_obj or not chan_obj.is_limit:
                continue
            
            user_count = chan_data['users']
            bot_is_op = chan_data['bot_op']
            current_limit = chan_data['mode_params'].get('l', 0)
            
            if not bot_is_op:
                log.debug(f"Bot not op in {chan}, skipping")
                continue
            
            limit_add = chan_obj.limit_add or self.LIMITADD
            limit_tol = chan_obj.limit_tolerance or self.LIMITTOL
            new_limit = user_count + limit_add
            
            if (abs(new_limit - current_limit) > limit_tol):
                log.info(f"{chan}: {current_limit} → {new_limit} (users={user_count})")
                
                self.core.irc_q.put({
                    'cmd': 'mode',
                    'channel': chan,
                    'modes': f"+l {new_limit}"
                })
                self.limit_last_change[chan] = now
    
    async def on_MODE(self, event):
        """Track manual +l changes"""
        chan = event['chan']
        if '+l' in event['modes']:
            self.limit_last_change[chan] = time.time()