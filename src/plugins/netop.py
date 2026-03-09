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
from ..botnet import BotCommand

log = logging.getLogger("wbs.plugins.netop")

class netopPlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = 'netop'
        self.version = '0.1.0'
        self.reqop: Dict[str, float] = {}  # chan → last request
        self.sugop: Dict[str, float] = {}  # chan → last sugop
        
    async def load(self):
        """Loads the plugin"""
        self.core.irc_q.put({
            'cmd': 'REGISTER_IRC_TIMER',
            'name': 'netop',
            'interval': 30  # Frequent op checks
        })
        self.core.botnet.register('netop', 'reqop', self.on_reqop)
        self.core.botnet.register('netop', 'sugop', self.on_sugop)
        log.info(f"Plugin {self.name} {self.version} loaded")
    
    async def unload(self):
        """Unloads the plugin"""
        self.core.irc_q.put({
            'cmd': 'UNREGISTER_IRC_TIMER',
            'name': 'netop'
        })
        self.core.botnet.unregister_plugin(self.name)
        log.info(f"Plugin {self.name} {self.version} unloaded")      

    async def on_IRC_TIMER_NETOP(self, event):
        """Periodic op enforcement - FULL IRC access via event"""
        irc_data = event['irc_data']
        
        if not irc_data['connected']:
            return
        
        for chan, chan_data in irc_data['channels'].items():
            bot_is_op = chan_data['bot_op']
            if not bot_is_op:
                await self.msg_to_bots(f"reqop {self.core.botname} {chan}")
    
    async def on_MODE(self, event):
        """Netop deop/op handling - botnet protection."""

        chan = event.get('channel', '').lower()
        modes = event.get('modes', '')
        victims = [a.lower() for a in event.get('args', [])]

        now = time.time()
        peers = getattr(self.core.botnet, 'peers', {})   # handle -> BotLink
        bot_nicks = {
            (link.nick or link.name).lower(): handle
            for handle, link in peers.items()
            if (link.nick or link.name)
        }

        sign = '+'
        arg_idx = 0

        for i, char in enumerate(modes):
            if char in '+-':
                sign = char
                continue

            if char != 'o':
                continue

            if arg_idx >= len(victims):
                log.warning(f"Malformed MODE {chan} {modes}: missing arg for +o/-o")
                break

            victim = victims[arg_idx]
            arg_idx += 1

            # self got opped/deopped
            if victim == self.core.botname.lower():
                if sign == '-':
                    await self.msg_to_bots(f"reqop {self.core.botname} {chan}")
                    self.reqop[chan] = now
                    log.info(f"Got deopped on {chan}, requesting op.")
                #else:
                #    last_sugop = self.sugop.get(chan, 0)
                #    if now - last_sugop > 10:
                #        await self.msg_to_bots(f"sugop {self.core.botname} {chan}")
                #        self.sugop[chan] = now
                #        log.debug(f"Got opped on {chan}, suggesting op.")
                continue

            # linked bot got opped/deopped
            if victim in bot_nicks:
                if sign == '-':
                    #self.core.irc_q.put_nowait({
                    #    'cmd': 'mode',
                    #    'channel': chan,
                    #    'modes': f"+o {victim}"
                    #})
                    #log.info(f"Reopped linked bot {victim} on {chan}")
                    pass
                else:
                    #if not self.core.bot_isop(chan):
                    last_req = self.reqop.get(chan, 0)
                    if now - last_req > 10:
                        await self.msg_to_bot(victim, f"reqop {self.core.botname} {chan}")
                        self.reqop[chan] = now
                        log.debug(f"Linked bot {victim} got opped on {chan}, requesting op.")

    async def on_JOIN(self, event):
        channel = event.get('channel', '').lower()
        nick = event.get('nick', '').lower()
        
        # Check if a linked bot joined - request ops for them
        if nick in self.core.botnet.peers.keys():
            await self.msg_to_bots(f"reqop {nick} {channel}")
            log.info(f"Linked bot {nick} joined {channel}; suggesting op")

    async def on_NEWCHAN(self, event):
        channel = event.get('channel', '').lower()
        nick = event.get('nick', '').lower()
        await self.msg_to_bots(f"reqop {self.core.botname} {channel}")
        log.info(f"Joined {channel}; requested ops from peers")            

    async def on_reqop(self, cmd: BotCommand, args: list, from_peer: str = ''):
        """Handle reqop from botnet peer."""
        target = args[0].lower() if args else ''
        channel = args[1].lower() if len(args) > 1 else ''
        
        #now = time.time()
        #if self.reqop.get(channel, 0) + 30 > now:
        #    log.debug(f"Reqop cooldown {channel}")
        #    return
        #
        #self.reqop[channel] = now
        try:
            if not self.core.nick_isop(target, channel) and self.core.bot_isop(channel):
                self.core.irc_q.put_nowait({
                    'cmd': 'mode',
                    'channel': channel,
                    'modes': f"+o {target}"
                })
                log.info(f"Giving op to {target} in {channel} (req)")
        except Exception as e:
            log.error(f"Op failed {channel} {target}: {e}")

    async def on_sugop(self, cmd: BotCommand, args: list, from_peer: str = ''):
        """Handle sugop—lower priority."""
        #target = args[0].lower() if args else ''
        #channel = args[1].lower() if len(args) > 1 else ''
        
        #now = time.time()
        #if self.sugop.get(channel, 0) + 60 > now:
        #    return
        #self.sugop[channel] = now
        
        #try:
        #    if not self.core.bot_isop(channel):
        #        await self.msg_to_bot(from_peer, f"reqop {self.core.botname} {channel}")
        #        log.info(f"Got sugop, requesting op from granted {from_peer} in {channel}")
        #except Exception as e:
        #    log.error(f"Sugop failed {channel} {target}: {e}")
        pass