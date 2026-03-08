# src/plugins/limit.py
"""
WBS Plugin: limit.py 
version: 0.1.0
by: cyco
Description: Set and watch channel limit
"""
import time
import logging
from typing import Dict
from . import Plugin

log = logging.getLogger("wbs.core")

class limitPlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = 'limit'
        self.version = '0.1.0'
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
        log.info(f"Plugin {self.name} {self.version} loaded")
    
    async def unload(self):
        """Unregister IRC timer"""
        self.core.irc_q.put({
            'cmd': 'UNREGISTER_IRC_TIMER',
            'name': 'limit'
        })
        log.info("Limit plugin unloaded")

    async def on_IRC_TIMER_LIMIT(self, event):
        """Periodic op enforcement - FULL IRC access via event"""
        irc_data = event['irc_data']
        #log.info(f"data: {irc_data}")
        
        if not irc_data['connected']:
            return
        
        for chan, chan_data in irc_data['channels'].items():
            bot_is_op = chan_data['bot_op']
            if bot_is_op:
                now = time.time()
                
                # Initialize channel if not present
                if chan not in self.limit_last_change:
                    self.limit_last_change[chan] = now - self.LIMITDELTA
                
                # Skip if changed recently
                if self.limit_last_change[chan] + self.LIMITDELTA > now:
                    continue
                
                # Extract current limit from mode string and params
                current_limit = self.core.channels[chan].limit
                newlimit = chan_data['users'] + self.LIMITADD
                
                # Skip if current limit is within tolerance
                if abs(current_limit - newlimit) <= self.LIMITTOL:
                    continue
                
                log.info(f"Setting limit on {chan} from {current_limit} to {newlimit}")
                
                self.core.irc_q.put_nowait({
                    'cmd': 'mode',
                    'channel': chan,
                    'modes': f"+l {newlimit}"
                })
                
                self.limit_last_change[chan] = now

    def _get_current_limit(self, chan_data: dict) -> int:
        """Extract current +l limit from mode string and params"""
        mode_str = chan_data.get('mode', '')
        mode_params = chan_data.get('mode_params', {})
        
        # Check if +l is active in modes
        if 'l' in mode_str and 'l' in mode_params:
            try:
                return int(mode_params['l'])
            except (ValueError, TypeError):
                pass
        
        # No limit set
        return 0
    
    async def on_MODE(self, event):
        """Track manual +l changes"""
        chan = event['channel']
        if 'l' in event['modes']:
            self.limit_last_change[chan] = time.time()