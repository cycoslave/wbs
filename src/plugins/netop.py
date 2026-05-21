# src/plugins/netop.py
"""
WBS Plugin: netop.py 
version: 0.1.1
by: cyco
Description: Get op from linked bots & Give ops to linked bots.
"""
import time
from typing import Dict
from . import Plugin
from ..botnet import BotCommand

class netopPlugin(Plugin):
    name    = "netop"
    version = "0.1.1"

    def __init__(self, core):
        super().__init__(core) 
        self.reqop: Dict[str, float] = {}
        self.sugop: Dict[str, float] = {}
        
    async def load(self):
        """Initialize plugin and register timers"""
        await super().load()
        self.core.irc_q.put({
            'cmd': 'REGISTER_IRC_TIMER',
            'name': 'netop',
            'interval': 30  # Frequent op checks
        })
        self.core.botnet.register('netop', 'reqop', self.on_reqop)
        self.core.botnet.register('netop', 'sugop', self.on_sugop)
        self.log.info(f"Plugin {self.name} {self.version} loaded")
    
    async def unload(self):
        """Unload plugin and unregister timers"""
        self.core.irc_q.put({
            'cmd': 'UNREGISTER_IRC_TIMER',
            'name': 'netop'
        })
        self.core.botnet.unregister_plugin(self.name)
        await super().unload()
        self.log.info(f"Plugin {self.name} {self.version} unloaded")      

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
        chan = event.get('channel', '').lower()
        modes = event.get('modes', '')
        victims = [a.lower() for a in event.get('args', [])]

        now = time.time()
        peers = getattr(self.core.botnet, 'peers', {})
        bot_nicks = {
            (link.nick or link.name).lower(): handle
            for handle, link in peers.items()
            if (link.nick or link.name)
        }

        sign = '+'
        arg_idx = 0

        for char in modes:
            if char in '+-':
                sign = char
                continue
            if char != 'o':
                continue
            if arg_idx >= len(victims):
                break

            victim = victims[arg_idx]
            arg_idx += 1

            if victim == self.core.botname.lower():
                if sign == '-':
                    await self.msg_to_bots(f"reqop {self.core.botname} {chan}")
                    self.reqop[(chan, victim)] = now
                    self.log.info(f"Got deopped on {chan}, requesting op.")
                else:
                    # Bot got opped — clear cooldown so we can reqop others freely
                    self.reqop.pop((chan, victim), None)
                continue

            if victim in bot_nicks:
                if sign == '+':
                    # Linked bot got opped — clear their cooldown, request op for self if needed
                    self.reqop.pop((chan, victim), None)
                    last_req = self.reqop.get((chan, self.core.botname.lower()), 0)
                    if now - last_req > 10:
                        await self.msg_to_bot(victim, f"reqop {self.core.botname} {chan}")
                        self.reqop[(chan, self.core.botname.lower())] = now
                        self.log.debug(f"Linked bot {victim} got opped on {chan}, requesting op.")
                elif sign == '-':
                    pass  # deop handling if needed later

    #async def on_JOIN(self, event):
    #    channel = event.get('channel', '').lower()
    #    nick = event.get('nick', '').lower()
    #    
    #    # Check if a linked bot joined - request ops for them
    #    if nick in self.core.botnet.peers.keys():
    #        await self.msg_to_bots(f"reqop {nick} {channel}")
    #        self.log.info(f"Linked bot {nick} joined {channel}; suggesting op")

    async def on_NEWCHAN(self, event):
        channel = event.get('channel', '').lower()
        nick = event.get('nick', '').lower()
        await self.msg_to_bots(f"reqop {self.core.botname} {channel}")
        self.log.info(f"Joined {channel}; requested ops from peers")            

    async def on_reqop(self, cmd: BotCommand, args: list, from_peer: str = ''):
        target = args[0].lower() if args else ''
        channel = args[1].lower() if len(args) > 1 else ''
        now = time.time()
        key = (channel, target)
        if self.reqop.get(key, 0) + 10 > now:
            self.log.debug(f"Reqop cooldown {channel}/{target}, skipping")
            return

        try:
            if not self.core.nick_isop(target, channel) and self.core.bot_isop(channel):
                self.core.irc_q.put_nowait({
                    'cmd': 'mode',
                    'channel': channel,
                    'modes': f"+o {target}"
                })
                self.reqop[key] = now
                self.log.info(f"Giving op to {target} in {channel} (req)")
        except Exception as e:
            self.log.error(f"Op failed {channel} {target}: {e}")

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
        #        self.log.info(f"Got sugop, requesting op from granted {from_peer} in {channel}")
        #except Exception as e:
        #    self.log.error(f"Sugop failed {channel} {target}: {e}")
        pass