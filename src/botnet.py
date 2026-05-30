# src/botnet.py
"""
Botnet peer manager for WBS.
Handles bot-to-bot linking, command routing, and data sharing.
"""
import asyncio
import json
import logging
import secrets
import hmac
import ssl as ssl_lib
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Any, Literal, Callable
from dataclasses import dataclass

from . import __version__
from .bot import BotManager
from .user import UserManager
from .channel import ChannelManager
from .subnet import SubnetManager

log = logging.getLogger("wbs.botnet")
CLOCK_SKEW_WARN_SECONDS = 30

class AutoLinkManager:
    """
    Periodically attempts to connect to peers marked autolink=1 in the DB.
    Each peer has its own retry interval; connection attempts are jittered
    slightly to avoid thundering herd on startup.
    """

    # Hard floor: never retry faster than this regardless of DB setting
    MIN_RETRY_INTERVAL = 15   # seconds
    # Cap: don't let DB set absurdly long intervals that mask problems
    MAX_RETRY_INTERVAL = 600  # seconds

    def __init__(self, botnet_manager: "BotnetManager"):
        self._mgr = botnet_manager
        self._running = False
        self._task: asyncio.Task | None = None
        # Track next-attempt time per peer handle (epoch float)
        self._next_attempt: dict[str, float] = {}

    def start(self):
        """Launch the background loop."""
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="autolink-loop")
        log.info("AutoLinkManager started")

    def stop(self):
        """Cancel the background loop cleanly."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        log.info("AutoLinkManager stopped")

    async def _loop(self):
        """
        Main loop: polls DB for autolink peers, attempts connection
        for any that are due and not already connected.
        """
        # Short initial delay so botnet manager finishes init
        await asyncio.sleep(5)

        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("AutoLink loop error: %s", exc, exc_info=True)
            await asyncio.sleep(5)   # poll granularity

    async def _tick(self):
        """One pass: check all autolink peers and connect those that are due."""
        peers_cfg = await self._mgr.bot.get_autolink_peers()
        now = time.monotonic()

        for peer in peers_cfg:
            handle = peer["handle"].lower()

            # Already linked and authenticated — skip
            link = self._mgr.peers.get(handle)
            if link and link.connected and link.authed:
                # Reset the backoff counter since we're healthy
                self._next_attempt.pop(handle, None)
                continue

            # Not yet due for a retry?
            if now < self._next_attempt.get(handle, 0):
                continue

            # Clamp retry interval to safe bounds
            raw_interval = peer.get("autolink_retry_interval", 60)
            interval = max(
                self.MIN_RETRY_INTERVAL,
                min(raw_interval, self.MAX_RETRY_INTERVAL)
            )

            log.info("AutoLink: attempting connection to %s", handle)
            try:
                await self._mgr.connect_peer(peer["handle"])
            except Exception as exc:
                log.warning("AutoLink: connect to %s failed: %s", handle, exc)

            # Schedule next attempt regardless of success/failure.
            # On success, _tick will see authed=True next pass and skip.
            self._next_attempt[handle] = now + interval

@dataclass
class BotLink:
    """Bot peer configuration."""
    name: str
    host: str
    port: int
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    nick: str = None
    subnet_id: Optional[int] = None
    session_id: Optional[int] = None
    password: Optional[str] = None
    temp_partial: Optional[str] = None  # For key exchange
    share_level: str = 'subnet'
    role: Literal['hub', 'backup', 'leaf', 'none'] = 'none'
    authed: bool = False
    connected: bool = False
    connected_at: Optional[datetime] = None

@dataclass(frozen=True)
class BotCommand:
    """Minimal botnet command key."""
    name: str
    plugin: str = 'core'    

class BotnetManager:
    """Manages botnet peer connections and routing."""
    
    def __init__(self, core):
        self.core = core
        self.db_path = self.core.db_path
        self.config = self.core.config
        self.irc_q = self.core.irc_q
        self.user = UserManager(self.db_path)
        self.chan = ChannelManager(self.db_path)
        self.bot = BotManager(self.db_path)
        self.subnet = SubnetManager(self.db_path)
        self.peers: Dict[BotLink] = {}
        self.cmds: Dict[BotCommand, Callable] = {}
        self._peer_skew: dict[str, int] = {}
        
        # Settings
        self.subnet_id = self.config.get('botnet', {}).get('subnet_id', 1)
        self.my_handle = self.config.get('bot', {}).get('nick', 'WBS')
        self.autolink = AutoLinkManager(self)
        self.running = True
        self.loop = None
        
    def stop(self):
        """Shutdown."""
        self.running = False
        self.autolink.stop()
        for _, writer in self.peers.values():
            writer.close()

    async def start(self):
        """Start background tasks. Must be called from inside a running event loop."""
        self.autolink.start()

    async def connect_peer(self, handle: str):
        """Establish outgoing connection to peer."""
        try:
            bot = await self.bot.get(handle)

            cfg = self.config.get('settings', {})
            use_ssl = cfg.get('ssl', False)

            if use_ssl:
                ssl_ctx = ssl_lib.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl_lib.CERT_NONE
                reader, writer = await asyncio.open_connection(bot.address, bot.port, ssl=ssl_ctx, limit=4096)
            else:
                reader, writer = await asyncio.open_connection(bot.address, bot.port, limit=4096)
            
            link = BotLink(
                name=handle,
                host=bot.address,
                port=bot.port,
                nick=handle
            )
            link.reader = reader
            link.writer = writer
            link.subnet_id = self.subnet_id
            link.password = bot.password
            
            if link.password is None:
                link.temp_partial = secrets.token_hex(16)
                handshake = f"BOTLINK {self.my_handle} {handle} 1 WBS {__version__} {link.temp_partial}\n"
            else:
                handshake = f"BOTLINK {self.my_handle} {handle} 1 WBS {__version__}\n"
            
            writer.write(handshake.encode())
            await writer.drain()
            
            self.peers[handle.lower()] = link
            asyncio.create_task(self.read_peer(handle, reader, writer))
            log.info(f"Connected to peer {handle} at {bot.address}:{bot.port}")
            link.connected = True
            self.core.irc_q.put({
                'type': 'BOTLINK_LINK', 
                'handle': link.name,
                'nick': link.name
            })
            
        except Exception as e:
            log.error(f"Failed to connect to {handle}: {e}")

    async def disconnect_peer(self, botname: str):
        link = self.peers.pop(botname.lower(), None)
        if not link:
            return
        if link.writer and not link.writer.is_closing():
            link.writer.close()
            await link.writer.wait_closed()
        self.subnet.unregister_peer(botname)
        self.core.partyline.broadcast(f"*** {botname} unlinked from botnet", True)
        log.info(f"Peer {botname} disconnected.")

    async def read_peer(self, handle: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Continuously read messages from a peer connection."""
        try:
            while self.running:
                try:
                    line = await reader.readline()
                except asyncio.LimitOverrunError:
                    await reader.read(4096)  # drain
                    log.warning(f"Oversized line from {handle}, discarding")
                    continue
                if not line:
                    log.info(f"Connection closed by {handle}")
                    break
                
                decoded = line.decode().strip()
                if decoded:
                    await self.process_incoming(handle, decoded, reader, writer)
                    
        except asyncio.CancelledError:
            log.info(f"Read task cancelled for {handle}")
        except Exception as e:
            log.error(f"Read error from {handle}: {e}")
        finally:
            self.subnet.unregister_peer(handle)
            # Clean up on disconnect
            if handle.lower() in self.peers:
                del self.peers[handle.lower()]
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            log.info(f"Peer {handle} disconnected")

    async def process_incoming(self, from_bot: str, line: str, reader, writer):
        """Process message from peer."""
        parts = line.split()
        cmd = parts[0].upper()
        
        if cmd == "BOTLINK":
            if from_bot.lower() not in self.peers:
                bot = await self.bot.get(from_bot.lower())
                link = BotLink(
                    name=from_bot,
                    host=bot.address,
                    port=bot.port,
                    writer=writer,
                    reader=reader
                )
                link.subnet_id = self.subnet_id
                link.password = bot.password
                self.peers[from_bot.lower()] = link
                link.connected = True
                self.core.irc_q.put({
                    'type': 'BOTLINK_LINK', 
                    'handle': link.name,
                    'nick': link.name
                })
                asyncio.create_task(self.read_peer(from_bot, reader, writer))
            else:
                link = self.peers[from_bot.lower()]

            remote = parts[1]
            local = parts[2]
            
            if local.lower() != self.my_handle.lower() or remote.lower() != from_bot.lower():
                log.error(f"Botlink mismatch from {from_bot}")
                writer.close()
                return
            
            if link.password is None and len(parts) <= 6:
                log.error(f"Credential mismatch from {from_bot}: local password unset and peer offered no exchange token")
                writer.close()
                return

            if link.password is None:
                if len(parts) > 6:  
                    their_partial = parts[6]
                    our_partial = secrets.token_hex(16)

                    #shared_password = hashlib.sha256((min(their_partial, our_partial) + max(their_partial, our_partial)).encode()).hexdigest()
                    shared_password = hmac.new(b"wbs-keyexchange-v1", f"{min(their_partial, our_partial)}:{max(their_partial, our_partial)}".encode(), "sha256").hexdigest()
                    link.password = shared_password
                    log.info(f"Generated shared password with {from_bot}")
                    await self.bot.chpass(from_bot.lower(), password=shared_password)
                    ack = f"LINKACK {self.my_handle} {remote} 1 WBS {__version__} {our_partial}\n"
                    log.info(f"Sending {ack}")
                    await self._safe_send(writer, ack)
                else:
                    log.error(f"No password configured for {from_bot} and no key exchange offered")
                    writer.close()
                    return
            else:
                await self._safe_send(writer, f"LINKACK {self.my_handle} {remote} 1 WBS {__version__}\n")
            return
        
        if from_bot.lower() not in self.peers:
            log.error(f"Unknown peer {from_bot}")
            return
        
        link = self.peers[from_bot.lower()]

        if cmd == "LINKACK":
            if link.password is None:
                if len(parts) > 6:
                    their_partial = parts[6]
                    our_partial = link.temp_partial
                    #shared_password = hashlib.sha256((min(their_partial, our_partial) + max(their_partial, our_partial)).encode()).hexdigest()
                    shared_password = hmac.new(b"wbs-keyexchange-v1", f"{min(their_partial, our_partial)}:{max(their_partial, our_partial)}".encode(), "sha256").hexdigest()
                    link.password = shared_password
                    
                    log.info(f"Generated shared password with {from_bot}")
                    await self.bot.chpass(from_bot.lower(), password=shared_password)
                    #chalhash = hashlib.sha256(f"{self.my_handle}{link.password}{parts[1]}".encode()).hexdigest()
                    chalhash = hmac.new(link.password.encode(), f"{self.my_handle}{parts[1]}".encode(), "sha256").hexdigest()
                    challenge = f"LINKAUTH {self.my_handle} {chalhash} {int(time.time())}\n"
                    await self._safe_send(writer, challenge)
                else:
                    log.error(f"Credential mismatch with {from_bot}: peer sent LINKACK without exchange token while local password is unset")
                    writer.close()
                    return
            else:
                #chalhash = hashlib.sha256(f"{self.my_handle}{link.password}{parts[1]}".encode()).hexdigest()
                chalhash = hmac.new(link.password.encode(), f"{self.my_handle}{parts[1]}".encode(), "sha256").hexdigest()
                challenge = f"LINKAUTH {self.my_handle} {chalhash} {int(time.time())}\n"
                await self._safe_send(writer, challenge)
            return
        
        elif cmd == "LINKAUTH":
            #expectedhash = hashlib.sha256(f"{parts[1]}{link.password}{self.my_handle}".encode()).hexdigest()
            expectedhash = hmac.new(link.password.encode(), f"{parts[1]}{self.my_handle}".encode(), "sha256").hexdigest()
            if len(parts) < 3 or not hmac.compare_digest(parts[2], expectedhash):
                log.error(f"Auth failed from {from_bot}")
                writer.close()
                return

            if len(parts) >= 4:
                try:
                    peer_ts = int(parts[3])
                    if not await self.check_clock_skew(peer_ts, from_bot):
                        await self._safe_send(writer, f"ERROR :clock skew too large\n")
                        writer.close()
                        return
                except ValueError:
                    log.error(f"LINKAUTH from {from_bot} has invalid or missing timestamp — rejecting link")
                    await self._safe_send(writer, f"ERROR :missing or invalid timestamp\n")
                    writer.close()
                    return

            self.core.partyline.broadcast(f"*** {from_bot} linked to botnet", True)
            link.authed = True
            link.connected_at = datetime.now(timezone.utc)
            self.subnet.register_peer(from_bot, link.subnet_id)
            await self._safe_send(writer, f"LINKREADY {self.my_handle} WBS {__version__} {int(time.time())}\n")
            asyncio.create_task(self.share_all_data(from_bot))
            return
        
        elif cmd == "LINKREADY":
            if len(parts) >= 4:
                try:
                    peer_ts = int(parts[4])
                    if not await self.check_clock_skew(peer_ts, from_bot):
                        await self._safe_send(writer, f"ERROR :clock skew too large\n")
                        writer.close()
                        return
                except ValueError:
                    log.error(f"LINKREADY from {from_bot} has invalid or missing timestamp — rejecting link")
                    await self._safe_send(writer, f"ERROR :missing or invalid timestamp\n")
                    writer.close()
                    return

            self.core.partyline.broadcast(f"*** {from_bot} linked to botnet", True)
            link.authed = True
            self.subnet.register_peer(from_bot, link.subnet_id)
            self.core.bot_sessions[from_bot.lower()] = link
            link.connected_at = datetime.now(timezone.utc)
            asyncio.create_task(self.share_all_data(from_bot))
            return
        
        # BLOCK UNAUTHED
        if not link.authed:
            log.warning(f"Unauthed from {from_bot}: {line[:50]}")
            return
        
        elif cmd == "CHAT":
            # Format: CHAT <from_bot> <message>
            # parts[0] = "CHAT", parts[1] = from_bot, parts[2:] = message
            from_bot = parts[1]
            nick = parts[2]
            message = ' '.join(parts[3:])
            self.core.partyline.broadcast(f"<{from_bot}@{nick.rstrip(':')}> {message}", True)

        elif cmd == "CMD":
            # Format: CMD <command> [args]
            if len(parts) < 2:
                return
            name = parts[1].lower()
            args = parts[2:]
            
            for pluginkey, handler in self.cmds.items():
                if pluginkey.name == name:
                    await handler(pluginkey, args, from_bot)  # Add frombot parameter
                    return
            log.warning(f"No handler for CMD {name}")
        
        elif cmd == 'RELAY_OPEN':
            # Remote user attached — register a virtual relay session
            from_handle = parts[1]
            origin_bot  = parts[2]
            orig_sid    = parts[3]
            relay_key   = f"relay:{origin_bot}:{orig_sid}"

            async def relay_respond(text):
                """Send output back to the user's real session on the origin bot."""
                if origin_bot in self.peers:
                    await self.send_to_peer(origin_bot, {
                        'type': 'RELAY_OUTPUT',
                        'session_id': orig_sid,
                        'text': text
                    })

            self.core.partyline.relay_sessions[relay_key] = {
                'handle':   from_handle,
                'origin':   origin_bot,
                'orig_sid': orig_sid,
                'respond':  relay_respond
            }
            log.info(f"Relay session opened: {from_handle}@{origin_bot} → {self.core.botname}")

        elif cmd == 'RELAY_INPUT':
            # Incoming keystrokes from relayed user — run as a real partyline command
            origin_bot = parts[1]
            orig_sid   = parts[2]
            relay_key  = f"relay:{origin_bot}:{orig_sid}"
            text       = parts[3:]

            rs = self.core.partyline.relay_sessions.get(relay_key)
            if rs:
                await self.core.partyline.dispatch_command(
                    handle=rs['handle'],
                    session_id=relay_key,   # virtual session id
                    text=text,
                    respond=rs['respond']
                )

        elif cmd == 'RELAY_CLOSE':
            origin_bot = parts[1]
            orig_sid   = parts[2]
            relay_key  = f"relay:{origin_bot}:{orig_sid}"
            self.core.partyline.relay_sessions.pop(relay_key, None)
            log.info(f"Relay session closed: {relay_key}")

        elif cmd == 'RELAY_OUTPUT':
            # Output coming back from the remote bot — deliver to user's real session
            sid  = parts[1]
            text = parts[2:]
            await self.core.partyline.send_to_session(sid, text)

        #elif line.startswith('RESPONSE:'):
        #    # Command response from another bot
        #    msg = line[9:]
        #    #self.party_q.put_nowait({
        #    #    'type': 'botnet_response',
        #    #    'from': from_bot,
        #    #    'text': msg
        #    #})
        
        elif cmd == "SHARE":
            share = parts[1]
            if share == "SUBNETS":
                asyncio.create_task(self.handle_share_subnets(' '.join(parts[2:]), from_bot))

            elif share == "CHANNELS":
                asyncio.create_task(self.handle_share_channels(' '.join(parts[2:]), from_bot))

            elif share == "USERS":
                asyncio.create_task(self.handle_share_users(' '.join(parts[2:]), from_bot))

            elif share == "USERACCESS":
                asyncio.create_task(self.handle_share_user_access(' '.join(parts[2:]), from_bot))

            elif share == "BOTS":
                asyncio.create_task(self.handle_share_bots(' '.join(parts[2:]), from_bot))

            elif share == "BOTACCESS":
                asyncio.create_task(self.handle_share_bot_access(' '.join(parts[2:]), from_bot))

        else:
            log.error(f"Invalid command {cmd} from {from_bot}")
        
    async def broadcast_chat(self, from_bot: str, msg: str, exclude: Optional[str] = None):
        """Broadcast chat to all peers."""
        line = f"CHAT {from_bot} {msg}\n"
        tasks = []
        for name,link in self.peers.items():
            if link.name != exclude and link.authed and link.connected and link.writer:
                tasks.append(self._safe_send(link.writer, line))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def broadcast_all(self, cmd: str):
        """Broadcast command to all peers."""
        msg = f"CMD {cmd}\n"
        tasks = [self._safe_send(peer.writer, msg) for peer in self.peers.values()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_subnet(self, cmd: str, subnet_id: int):
        targets = self.subnet.resolve_targets(
            self.peers, scope="subnet", subnet_id=subnet_id
        )
        msg = f"CMD {cmd}\n"
        await asyncio.gather(
            *[self._safe_send(t.writer, msg) for t in targets],
            return_exceptions=True,
        )
    
    async def _safe_send(self, writer: asyncio.StreamWriter, msg: str):
        """Send with error handling."""
        try:
            if writer is None or writer.is_closing():
                log.error("Send failed: writer already closing")
                return
            writer.write(msg.encode())
            await writer.drain()
        except Exception as e:
            log.error(f"Send failed: {e}")

    def register(self, plugin: str, name: str, handler: Callable):
        key = BotCommand(name.lower(), plugin.lower())
        if key in self.cmds:
            log.warning(f"Skipping duplicate {plugin}:{name} (existing)")
            return
        self.cmds[key] = handler
        log.info(f"Registered {plugin}:{name}")

    async def dispatch(self, plugin: str, name: str, **kwargs):
        """Find handler, pass cmd_key + kwargs."""
        key = BotCommand(plugin.lower(), name.lower())
        handler = self.cmds.get(key)
        if handler:
            await handler(key, **kwargs)
        else:
            log.warning(f"No handler for {plugin}:{name}")

    def unregister(self, plugin: str, name: str):
        """Unregister handler."""
        key = BotCommand(plugin.lower(), name.lower())
        if key in self.cmds:
            del self.cmds[key]
            log.info(f"Unregistered {plugin}:{name}")
            return True
        log.warning(f"No handler for {plugin}:{name}")
        return False

    def unregister_plugin(self, plugin: str):
        """Unregister all handlers for plugin."""
        removed = 0
        to_remove = [k for k in self.cmds if k.plugin == plugin.lower()]
        for key in to_remove:
            del self.cmds[key]
            removed += 1
        log.info(f"Unregistered {removed} cmds for {plugin}")
        return removed            

    async def check_clock_skew(self, peer_timestamp: int, peer_name: str) -> bool:
        """
        Called during handshake. Returns False if skew is unacceptable.
        Caller must abort the link if False is returned.
        """
        skew = abs(int(time.time()) - peer_timestamp)
        self._peer_skew[peer_name] = skew
        if skew > CLOCK_SKEW_WARN_SECONDS:
            log.error(
                "Rejecting link from %s: clock skew is %ds (max %ds). "
                "Ensure NTP is running on both hosts.",
                peer_name, skew, CLOCK_SKEW_WARN_SECONDS
            )
            return False
        if skew > 0:
            log.debug("Clock skew with %s: %ds (acceptable)", peer_name, skew)
        return True

    async def share_all_data(self, target_bot: str):
        """Comprehensive data sharing based on share_level."""
        link = self.peers.get(target_bot.lower())
        if not link or link.share_level == 'none':
            return
        
        # Share in dependency order
        await self.share_subnets(link)
        await self.share_users(link)
        await self.share_user_access(link)
        await self.share_bots(link, target_bot)  # Exclude target
        await self.share_bot_access(link)
        await self.share_channels(link)

    async def share_users(self, link: BotLink):
        users = await self.user.serialize_for_peer()
        await self._safe_send(link.writer, f"SHARE USERS {json.dumps(users)}\n")
        log.info(f"Shared {len(users)} users to {link.name}")

    async def share_user_access(self, link: BotLink):
        access = await self.user.serialize_access_for_peer()
        await self._safe_send(link.writer, f"SHARE USERACCESS {json.dumps(access)}\n")
        log.info(f"Shared {len(access)} user_access rows to {link.name}")

    async def share_channels(self, link: BotLink):
        channels = await self.chan.serialize_for_peer()
        await self._safe_send(link.writer, f"SHARE CHANNELS {json.dumps(channels)}\n")
        log.info(f"Shared {len(channels)} channels to {link.name}")

    async def share_bots(self, link: BotLink, exclude_bot: str):
        bots = await self.bot.serialize_for_peer(exclude_bot)
        await self._safe_send(link.writer, f"SHARE BOTS {json.dumps(bots)}\n")
        log.info(f"Shared {len(bots)} bots to {link.name}")

    async def share_bot_access(self, link: BotLink):
        access = await self.bot.serialize_access_for_peer()
        await self._safe_send(link.writer, f"SHARE BOTACCESS {json.dumps(access)}\n")
        log.info(f"Shared {len(access)} bot_access rows to {link.name}")

    async def share_subnets(self, link: BotLink):
        subnets = await self.subnet.serialize_for_peer(link.share_level, link.subnet_id)
        await self._safe_send(link.writer, f"SHARE SUBNETS {json.dumps(subnets)}\n")
        log.info(f"Shared {len(subnets)} subnets to {link.name}")

    async def handle_share_subnets(self, data: str, from_bot: str):
        subnets = json.loads(data)
        await self.subnet.merge_from_peer(subnets, from_bot)

    async def handle_share_users(self, data: str, from_bot: str) -> None:
        users = json.loads(data)
        await self.user.merge_from_peer(users, from_bot)

    async def handle_share_user_access(self, data: str, from_bot: str) -> None:
        access_list = json.loads(data)
        await self.user.merge_access_from_peer(access_list, from_bot)

    async def handle_share_bots(self, data: str, from_bot: str) -> None:
        bots = json.loads(data)
        await self.bot.merge_from_peer(bots, from_bot)

    async def handle_share_bot_access(self, data: str, from_bot: str) -> None:
        access_list = json.loads(data)
        await self.bot.merge_access_from_peer(access_list, from_bot)

    async def handle_share_channels(self, data: str, from_bot: str) -> None:
        channels = json.loads(data)
        await self.chan.merge_from_peer(channels, from_bot)