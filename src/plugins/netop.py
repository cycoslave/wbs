# src/plugins/netop.py
"""
WBS Plugin: netop.py
version: 0.2.0
by: cyco
Description: Get op from linked bots & Give ops to linked bots.

Security hardening (0.2.0):
  - from_peer validated against authenticated botnet peers on all botnet handlers
  - target nick verified as a known linked bot before issuing +o
  - Input sanitization on nick/channel args from botnet messages
  - on_MODE now requires authed+connected peers (consistent with on_JOIN)
  - Cooldown dicts pruned on timer tick (bounded memory)
  - on_NEWCHAN rate-limited per channel
  - on_sugop implemented and no longer a registered no-op
  - COOLDOWN raised to 30s
  - Rejected requests from unknown peers logged at WARNING
  - Exception handling narrowed to ValueError/RuntimeError
"""
import time
from typing import Dict, Optional, Tuple

from . import Plugin
from ..botnet import BotCommand
from ..helper import _valid_nick, _valid_channel

_MAX_COOLDOWN_ENTRIES = 1000

class netopPlugin(Plugin):
    name    = "netop"
    version = "0.2.0"
    COOLDOWN = 30       # seconds — raised from 10; op-granting actions need a longer window
    NEWCHAN_COOLDOWN: Dict[str, float] = {}  # per-channel rate limit for on_NEWCHAN

    def __init__(self, core):
        super().__init__(core)
        self.reqop: Dict[Tuple[str, str], float] = {}
        self.sugop: Dict[Tuple[str, str], float] = {}

    def _authed_bot_nicks(self) -> Dict[str, str]:
        """Return {nick_lower: handle} for every authenticated, connected peer."""
        peers = getattr(self.core.botnet, 'peers', {})
        return {
            (link.nick or link.name).lower(): handle
            for handle, link in peers.items()
            if (link.nick or link.name) and link.authed and link.connected
        }

    def _peer_is_trusted(self, from_peer: str) -> bool:
        """Return True if from_peer is an authenticated, connected botnet peer."""
        if not from_peer:
            return False
        peers = getattr(self.core.botnet, 'peers', {})
        link = peers.get(from_peer)
        return bool(link and link.authed and link.connected)

    def _prune_cooldowns(self, now: float) -> None:
        """Evict expired entries; hard-cap dict size to prevent unbounded growth."""
        cutoff = now - self.COOLDOWN * 2
        for d in (self.reqop, self.sugop):
            expired = [k for k, v in d.items() if v < cutoff]
            for k in expired:
                del d[k]
            # Hard cap: drop oldest entries if still over limit
            if len(d) > _MAX_COOLDOWN_ENTRIES:
                oldest = sorted(d.items(), key=lambda x: x[1])
                for k, _ in oldest[:len(d) - _MAX_COOLDOWN_ENTRIES]:
                    del d[k]

    async def load(self):
        """Initialize plugin and register timers."""
        await super().load()
        self.core.send_irc({
            'cmd': 'REGISTER_IRC_TIMER',
            'name': 'netop',
            'interval': 30
        })
        self.core.botnet.register('netop', 'reqop', self.on_reqop)
        self.core.botnet.register('netop', 'sugop', self.on_sugop)
        self.log.info(f"Plugin {self.name} {self.version} loaded")

    async def unload(self):
        """Unload plugin and unregister timers."""
        self.core.send_irc({
            'cmd': 'UNREGISTER_IRC_TIMER',
            'name': 'netop'
        })
        self.core.botnet.unregister_plugin(self.name)
        await super().unload()
        self.log.info(f"Plugin {self.name} {self.version} unloaded")

    async def on_IRC_TIMER_NETOP(self, event):
        """Periodic op enforcement and housekeeping."""
        irc_data = event['irc_data']
        if not irc_data['connected']:
            return

        now = time.time()
        self._prune_cooldowns(now)

        for chan, chan_data in irc_data['channels'].items():
            if not chan_data['bot_op']:
                await self.msg_to_bots(f"reqop {self.core.botname} {chan}")

    async def on_MODE(self, event):
        chan    = event.get('channel', '').lower()
        modes  = event.get('modes', '')
        victims = [a.lower() for a in event.get('args', [])]
        now = time.time()
        bot_nicks = self._authed_bot_nicks()
        sign    = '+'
        arg_idx = 0

        for char in modes:
            if char in '+-':
                sign = char
                continue
            if char != 'o':
                continue
            if arg_idx >= len(victims):
                break

            victim  = victims[arg_idx]
            arg_idx += 1

            if victim == self.core.botname.lower():
                if sign == '-':
                    self.reqop[(chan, victim)] = now
                    opped_peer = next((n for n in bot_nicks if self.core.nick_isop(n, chan)), None)
                    if opped_peer:
                        await self.msg_to_bot(opped_peer, f"reqop {self.core.botname} {chan}")
                        self.log.info(f"Got deopped on {chan}, requesting op from {opped_peer}.")
                    else:
                        await self.msg_to_bots(f"reqop {self.core.botname} {chan}")
                        self.log.info(f"Got deopped on {chan}, broadcasting reqop.")
                else:
                    self.reqop.pop((chan, victim), None)
                continue

            if victim in bot_nicks:
                if sign == '+':
                    self.reqop.pop((chan, victim), None)
                    if not self.core.bot_isop(chan):
                        last_req = self.reqop.get((chan, self.core.botname.lower()), 0)
                        if now - last_req > self.COOLDOWN:
                            await self.msg_to_bot(victim, f"reqop {self.core.botname} {chan}")
                            self.reqop[(chan, self.core.botname.lower())] = now
                            self.log.debug(f"Linked bot {victim} got opped on {chan}, requesting op.")

    async def on_JOIN(self, event):
        channel = event.get('channel', '').lower()
        nick    = event.get('nick', '').lower()

        if nick == self.core.botname.lower():
            return

        bot_nicks = self._authed_bot_nicks()  # reuses helper — consistent auth check

        if nick not in bot_nicks:
            return

        now = time.time()
        key = (channel, nick)
        if self.sugop.get(key, 0) + self.COOLDOWN > now:
            self.log.debug("sugop cooldown %s/%s, skipping", channel, nick)
            return

        await self.msg_to_bots(f"sugop {nick} {channel}")
        self.sugop[key] = now
        self.log.info("Linked bot %s joined %s; broadcasting sugop", nick, channel)

    async def on_NEWCHAN(self, event):
        channel = event.get('channel', '').lower()
        now     = time.time()
        if self.NEWCHAN_COOLDOWN.get(channel, 0) + self.COOLDOWN > now:
            self.log.debug("on_NEWCHAN cooldown for %s, skipping", channel)
            return
        self.NEWCHAN_COOLDOWN[channel] = now
        await self.msg_to_bots(f"reqop {self.core.botname} {channel}")
        self.log.info(f"Joined {channel}; requested ops from peers")

    async def on_reqop(self, cmd: BotCommand, args: list, from_peer: str = ''):
        """Grant op to a linked bot that requested it."""
        if not self._peer_is_trusted(from_peer):
            self.log.warning(f"on_reqop: rejected from untrusted peer '{from_peer}'")
            return

        target  = args[0].lower() if args else ''
        channel = args[1].lower() if len(args) > 1 else ''

        if not _valid_nick(target) or not _valid_channel(channel):
            self.log.warning(
                f"on_reqop: invalid args from '{from_peer}': target={target!r} chan={channel!r}"
            )
            return

        bot_nicks = self._authed_bot_nicks()
        if target not in bot_nicks:
            self.log.warning(
                f"on_reqop: '{from_peer}' requested op for non-linked nick '{target}' in {channel}"
            )
            return

        now = time.time()
        key = (channel, target)
        if self.reqop.get(key, 0) + self.COOLDOWN > now:
            self.log.debug(f"Reqop cooldown {channel}/{target}, skipping")
            return

        try:
            if not self.core.nick_isop(target, channel) and self.core.bot_isop(channel):
                self.core.send_irc({
                    'cmd': 'mode',
                    'channel': channel,
                    'modes': f"+o {target}"
                })
                self.reqop[key] = now
                self.log.info(f"Giving op to {target} in {channel} (req from {from_peer})")
        except (ValueError, RuntimeError) as e:
            self.log.error(f"Op failed {channel} {target}: {e}")

    async def on_sugop(self, cmd: BotCommand, args: list, from_peer: str = ''):
        """Handle sugop: a peer suggests we may need op in a channel."""
        if not self._peer_is_trusted(from_peer):
            self.log.warning(f"on_sugop: rejected from untrusted peer '{from_peer}'")
            return

        target  = args[0].lower() if args else ''
        channel = args[1].lower() if len(args) > 1 else ''

        if not _valid_nick(target) or not _valid_channel(channel):
            self.log.warning(
                f"on_sugop: invalid args from '{from_peer}': target={target!r} chan={channel!r}"
            )
            return

        now = time.time()
        key = (channel, target)
        if self.sugop.get(key, 0) + self.COOLDOWN > now:
            self.log.debug(f"Sugop cooldown {channel}/{target}, skipping")
            return
        self.sugop[key] = now

        # If we don't have op and the peer who sent sugop does, ask them for it
        try:
            if not self.core.bot_isop(channel):
                await self.msg_to_bot(from_peer, f"reqop {self.core.botname} {channel}")
                self.log.info(f"Got sugop from {from_peer}, requesting op in {channel}")
        except (ValueError, RuntimeError) as e:
            self.log.error(f"Sugop handling failed {channel}: {e}")

    async def _op_unoped_peers(self, chan: str, bot_nicks: dict, now: float):
        """Op any authenticated linked bots on chan that don't have op yet."""
        # bot_nicks should always come from _authed_bot_nicks() — callers must ensure this
        for nick in bot_nicks:
            if self.core.nick_isop(nick, chan):
                continue
            last_opped = self.reqop.get((chan, nick), 0)
            if now - last_opped > self.COOLDOWN:
                self.core.send_irc({'cmd': 'mode', 'channel': chan, 'modes': f'+o {nick}'})
                self.reqop[(chan, nick)] = now
                self.log.debug(f"Opping peer {nick} on {chan}.")