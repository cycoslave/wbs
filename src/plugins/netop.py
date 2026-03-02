# src/plugins/netop.py
"""
WBS Plugin: netop.py 
version: 0.1.0
by: cyco
Description: Get op from linked bots & Give ops to linked bots.
"""
import time
import logging
from typing import Dict
from . import Plugin

log = logging.getLogger("wbs.core")

class Plugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.reqop: Dict[str, float] = {}  # chan → last request
        self.sugop: Dict[str, float] = {}  # chan → last sugop
        
    async def load(self):
        """Register IRC-side op check timer (every 30s)"""
        self.core.irc_q.put({
            'cmd': 'REGISTER_IRC_TIMER',
            'name': 'netop',
            'interval': 30  # Frequent op checks
        })
        log.info("Netop plugin loaded")
    
    async def unload(self):
        """Unregister IRC timer"""
        self.core.irc_q.put({
            'cmd': 'UNREGISTER_IRC_TIMER',
            'name': 'netop'
        })
        log.info("Netop plugin unloaded")

    async def on_UNKNOWN(self, event):
        pass        
    
    async def on_IRC_TIMER_NETOP(self, event):
        """Periodic op enforcement - FULL IRC access via event"""
        irc_data = event['irc_data']
        
        if not irc_data['connected'] or not self.core.config.get('botnet', {}).get('enabled', False):
            return
        
        botnick = irc_data['botnick'].lower()
        linked_bots = getattr(self.core, 'linked_bots', {})
        
        for chan, chan_data in irc_data['channels'].items():
            bot_is_op = chan_data['bot_op']
            if not bot_is_op:
                now = time.time()
                last_req = self.reqop.get(chan, 0)
                if now - last_req > 60:  # 1min cooldown
                    # Request op from botnet
                    await self.core.botnet.request_needop(chan)
                    self.reqop[chan] = now
                    log.debug(f"NEEDOP {chan}")
                    continue
            
            for vhand, vnick in linked_bots.items():
                vnick_lower = vnick.lower()
                if (chan_data['bot_op'] and  # Bot has ops
                    chan_data['users'] > 0 and  # Someone on channel
                    vnick_lower in [u.lower() for u in chan_data.get('user_list', [])] and  # Botlink present
                    not chan_data.get('ops', {}).get(vnick_lower, False)):  # Deopped
                    
                    self.core.irc_q.put({
                        'cmd': 'mode',
                        'channel': chan,
                        'modes': f"+o {vnick}"
                    })
                    log.debug(f"Re-OP {vnick} on {chan}")
    
    async def on_MODE(self, event):
        """Netop deop/op handling - botnet protection"""
        chan = event['chan'].lower()
        modes = event['modes'].lower()
        args = [a.lower() for a in event.get('args', [])]
        
        if not self.core.config.get('botnet', {}).get('enabled', False):
            return
        
        now = time.time()
        linked_bots = getattr(self.core, 'linked_bots', {})
        
        # Parse affected nicks
        i = 0
        while i < len(modes):
            mode_char = modes[i]
            
            if i < len(args):
                victim = args[i]
                vhand = await self.core.user.match_user(f"{victim}!*@*")  # user lookup
                
                # === -o DEOP ===
                if mode_char == 'o' and (i == 0 or modes[i-1] == '-'):
                    # Protect botlinked ops (+b +o flags)
                    if (vhand and 
                        'b' in (await self.core.user.get(vhand)).flags and  # bot flag
                        vhand in linked_bots and  # is linked
                        self.core.connected and  # rough bot op check
                        victim in linked_bots.values()):  # on channel (approx)
                        
                        self.core.irc_q.put({
                            'cmd': 'mode',
                            'channel': chan,
                            'modes': f"+o {victim}"
                        })
                        log.debug(f"Protected botlink op {victim} on {chan}")
                    
                    # Self deopped → NEEDOP
                    elif victim == self.core.botname.lower():
                        await self.core.botnet.request_needop(chan, 'op')
                        self.reqop[chan] = now
                        log.debug(f"Self deopped {chan} → NEEDOP")
                
                # === +o OP ===
                elif mode_char == 'o' and (i == 0 or modes[i-1] == '+'):
                    # Self opped → SUGOP
                    if victim == self.core.botname.lower():
                        last_sugop = self.sugop.get(chan, 0)
                        if now - last_sugop > 60:
                            await self.core.botnet.sugop(chan)
                            self.sugop[chan] = now
                            log.debug(f"SUGOP {chan}")
                    
                    # Botlink opped us → request op back
                    elif (vhand and 
                          'b' in (await self.core.user.get(vhand)).flags and
                          vhand in linked_bots):
                        
                        last_req = self.reqop.get(chan, 0)
                        if now - last_req > 60:
                            await self.core.botnet.request_needop_from(vhand, self.core.botname, chan)
                            self.reqop[chan] = now
                            log.debug(f"NEEDOP from {vhand} on {chan}")
            
            i += 1