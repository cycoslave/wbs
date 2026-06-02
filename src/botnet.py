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
import hashlib
import time
import uuid
import ssl as ssl_lib
from datetime import datetime, timezone
from collections import OrderedDict
from typing import Dict, Optional, Any, Literal, Callable, Coroutine
from dataclasses import dataclass, field

from . import __version__
from .bot import BotManager
from .user import UserManager
from .channel import ChannelManager
from .subnet import SubnetManager
from .net import AccessGuard

log = logging.getLogger("wbs.botnet")
CLOCK_SKEW_WARN_SECONDS = 30
MAX_MSG_CACHE_SIZE = 2048
MSG_TTL = 30

def _derive_shared_password(partial_a: str, partial_b: str) -> str:
    """
    Derive the shared link password from the two per-link nonces.
    Both sides produce the same result because XOR is commutative.
    """
    bytes_a = bytes.fromhex(partial_a)
    bytes_b = bytes.fromhex(partial_b)
    xor_key = bytes(x ^ y for x, y in zip(bytes_a, bytes_b))
    return hmac.new(
        xor_key,
        b"wbs-keyexchange-v1",
        hashlib.sha256
    ).hexdigest()

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
    """Represents a connected or pending botnet peer."""
    # Required fields — no default, must be supplied at construction
    name: str
    host: str
    port: int

    # Optional connection handles — set after the asyncio connection is established
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None

    # Optional identity/config fields
    nick:         str | None = None      # ← was: str = None (incorrect)
    subnet_id:    int | None = None
    session_id:   int | None = None
    password:     str | None = None
    temp_partial: str | None = None      # ephemeral key-exchange nonce

    # Settings with meaningful defaults
    share_level: str = 'subnet'
    role: Literal['hub', 'backup', 'leaf', 'none'] = 'none'

    # State flags
    authed:       bool = False
    connected:    bool = False
    connected_at: datetime | None = None

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
        self.peers: Dict[str, BotLink] = {}
        self.topology: Dict[str, str] = {}   # handle → via_peer (indirect bots)
        self.cmds: Dict[BotCommand, Callable] = {}
        self._peer_skew: dict[str, int] = {}
        
        # Settings
        self.subnet_id = self.config.get('botnet', {}).get('subnet_id', 1)
        self.my_handle = self.config.get('bot', {}).get('nick', 'WBS')
        self.autolink = AutoLinkManager(self)
        self._msg_cache: OrderedDict[str, float] = OrderedDict()
        self.guard: Optional["AccessGuard"] = None
        self.running = True
        self.loop = None
        
    def stop(self):
        """Shutdown."""
        self.running = False
        self.autolink.stop()
        for link in self.peers.values():
            if link.writer and not link.writer.is_closing():
                link.writer.close()

    async def start(self):
        """Start background tasks. Must be called from inside a running event loop."""
        self._register_net_handlers()
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
            log.info(f"Connecting to peer {handle} at {bot.address}:{bot.port} — awaiting auth")
            
        except Exception as e:
            #log.error(f"Failed to connect to {handle}: {e}")
            pass

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
        peer_ip: str | None = None
        try:
            peer_info = writer.get_extra_info("peername")
            peer_ip = peer_info[0] if peer_info else None
        except Exception:
            pass

        try:
            while self.running:
                try:
                    line = await reader.readline()
                except asyncio.LimitOverrunError:
                    await reader.read(4096)
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
            if handle.lower() in self.peers:
                del self.peers[handle.lower()]
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            if self.guard and peer_ip:
                self.guard.release(peer_ip)
            self.topology = {
                h: via for h, via in self.topology.items()
                if via != handle.lower()
            }
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
                    shared_password = _derive_shared_password(their_partial, our_partial)
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
                    shared_password = _derive_shared_password(our_partial, their_partial)
                    link.password = shared_password
                    link.temp_partial = None 
                    log.info(f"Generated shared password with {from_bot}")
                    await self.bot.chpass(from_bot.lower(), password=shared_password)
                    #chalhash = hashlib.sha256(f"{self.my_handle}{link.password}{parts[1]}".encode()).hexdigest()
                    chalhash = hmac.new(link.password.encode(), f"{self.my_handle}{parts[1]}".encode(), hashlib.sha256).hexdigest()
                    challenge = f"LINKAUTH {self.my_handle} {chalhash} {int(time.time())}\n"
                    await self._safe_send(writer, challenge)
                else:
                    log.error(f"Credential mismatch with {from_bot}: peer sent LINKACK without exchange token while local password is unset")
                    writer.close()
                    return
            else:
                chalhash = hmac.new(link.password.encode(), f"{self.my_handle}{parts[1]}".encode(), hashlib.sha256).hexdigest()
                challenge = f"LINKAUTH {self.my_handle} {chalhash} {int(time.time())}\n"
                await self._safe_send(writer, challenge)
            return
        
        elif cmd == "LINKAUTH":
            expectedhash = hmac.new(link.password.encode(), f"{parts[1]}{self.my_handle}".encode(), hashlib.sha256).hexdigest()
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
            link.connected = True
            link.connected_at = datetime.now(timezone.utc)
            self.subnet.register_peer(from_bot, link.subnet_id)
            self.core.bot_sessions[from_bot.lower()] = link
            self.core.irc_q.put({
                'type': 'BOTLINK_LINK',
                'handle': link.name,
                'nick': link.name
            })
            await self._safe_send(writer, f"LINKREADY {self.my_handle} WBS {__version__} {int(time.time())}\n")
            asyncio.create_task(self.share_all_data(from_bot))
            asyncio.create_task(self.broadcast_topology())
            return
        
        elif cmd == "LINKREADY":
            if len(parts) >= 5:
                try:
                    peer_ts = int(parts[-1])
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
            link.connected = True
            self.subnet.register_peer(from_bot, link.subnet_id)
            self.core.bot_sessions[from_bot.lower()] = link
            link.connected_at = datetime.now(timezone.utc)
            self.core.irc_q.put({
                'type': 'BOTLINK_LINK',
                'handle': link.name,
                'nick': link.name
            })
            asyncio.create_task(self.share_all_data(from_bot))
            return
        
        # BLOCK UNAUTHED
        if not link.authed:
            log.warning(f"Unauthed from {from_bot}: {line[:50]}")
            return
        
        elif cmd == "CHAT":
            if len(parts) < 3:
                log.warning("Malformed CHAT from %s: %r", from_bot, line[:80])
                return
            nick    = parts[1]
            message = ' '.join(parts[2:])
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

        elif cmd == "CMD_ROUTE":
            # Format: CMD_ROUTE <routing> <msg_id> <source> <target_or_dash> [subnet_id] <command> [args...]
            # routing: broadcast | subnet | unicast
            if len(parts) < 6:
                log.warning(f"Malformed CMD_ROUTE from {from_bot}: {line[:80]}")
                return

            routing = parts[1].lower()

            if routing == "subnet":
                # CMD_ROUTE subnet <msg_id> <source> - <subnet_id> <command> [args...]
                if len(parts) < 7:
                    log.warning(f"Malformed CMD_ROUTE subnet from {from_bot}: {line[:80]}")
                    return
                msg_id    = parts[2]
                source    = parts[3]
                try:
                    subnet_id = int(parts[5])
                except ValueError:
                    log.warning(f"Malformed botnet message (bad subnet_id): {parts!r} — defaulting to subnet 1")
                    subnet_id = 1
                command   = parts[6].lower()
                args      = " ".join(parts[7:])
                target    = None
            else:
                # CMD_ROUTE broadcast|unicast <msg_id> <source> <target_or_dash> <command> [args...]
                msg_id  = parts[2]
                source  = parts[3]
                target  = parts[4]
                command = parts[5].lower()
                args    = " ".join(parts[6:])

            if not self._register_message(msg_id):
                return  # duplicate — drop silently

            addressed_to_me = (
                routing == "broadcast"
                or (routing == "unicast" and target.lower() == self.my_handle.lower())
                or (routing == "subnet"  and self.subnet_id == subnet_id)
            )

            if addressed_to_me:
                for pluginkey, handler in self.cmds.items():
                    if pluginkey.name == command:
                        await handler(pluginkey, args.split(), from_bot)
                        break
                else:
                    log.warning(f"No handler for routed CMD_ROUTE command: {command}")

            # Relay logic
            if routing == "broadcast":
                relay_peers = [
                    link for name, link in self.peers.items()
                    if link.authed and link.connected and link.writer
                    and name != from_bot.lower()
                ]
            elif routing == "subnet":
                relay_peers = [
                    link for name, link in self.peers.items()
                    if link.authed and link.connected and link.writer
                    and name != from_bot.lower()
                    and link.subnet_id == subnet_id
                ]
            elif routing == "unicast":
                # Relay if we're not the target; flood-fill reaches the target eventually
                relay_peers = [] if addressed_to_me else [
                    link for name, link in self.peers.items()
                    if link.authed and link.connected and link.writer
                    and name != from_bot.lower()
                ]
            else:
                relay_peers = []

            if relay_peers:
                tasks = [self._safe_send(link.writer, f"{line}\n") for link in relay_peers]
                await asyncio.gather(*tasks, return_exceptions=True)
        
        elif cmd == "CHAT_ROUTE":
            # Format: CHAT_ROUTE <msg_id> <source_bot> <nick> :<message text>
            if len(parts) < 4:
                log.warning(f"Malformed CHAT_ROUTE from {from_bot}: {line[:80]}")
                return

            msg_id     = parts[1]
            source_bot = parts[2]
            nick       = parts[3]
            # Colon-prefixed message body (IRC convention)
            msg        = " ".join(parts[4:]).lstrip(":")

            if not self._register_message(msg_id):
                return  # duplicate — drop silently

            # Display locally on the partyline
            self.core.partyline.broadcast(f"<{source_bot}@{nick}> {msg}", True)

            # Relay to all other authenticated peers except sender
            relay_line = f"CHAT_ROUTE {msg_id} {source_bot} {nick} :{msg}\n"
            tasks = [
                self._safe_send(link.writer, relay_line)
                for name, link in self.peers.items()
                if link.authed and link.connected and link.writer
                and name != from_bot.lower()
            ]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        elif cmd == "UPDATE":
            # Format: UPDATE <msg_id> <entity> <action_or_payload> <json>
            if len(parts) < 4:
                log.warning(f"Malformed UPDATE from {from_bot}: {line[:80]}")
                return

            msg_id  = parts[1]
            entity  = parts[2].upper()

            if not self._register_message(msg_id):
                return  # duplicate — drop silently

            # Relay to all other authenticated peers before processing
            relay_line = " ".join(parts) + "\n"  # forward the original line verbatim
            relay_tasks = [
                self._safe_send(link.writer, relay_line)
                for name, link in self.peers.items()
                if link.authed and link.connected and link.writer
                and name != from_bot.lower()
            ]
            if relay_tasks:
                await asyncio.gather(*relay_tasks, return_exceptions=True)

            # Now apply locally
            try:
                if entity in ("CHANNEL", "USER", "BOT"):
                    action  = parts[3].upper()   # ADD or DEL
                    payload = json.loads(" ".join(parts[4:]))

                    if entity == "CHANNEL":
                        if action == "ADD":
                            await self.chan.merge_from_peer([payload], from_bot)
                        elif action == "DEL":
                            await self.chan.delete_from_peer(payload, from_bot)

                    elif entity == "USER":
                        if action == "ADD":
                            await self.user.merge_from_peer([payload], from_bot)
                        elif action == "DEL":
                            await self.user.delete_from_peer(payload, from_bot)

                    elif entity == "BOT":
                        if action == "ADD":
                            await self.bot.merge_from_peer([payload], from_bot)
                        elif action == "DEL":
                            await self.bot.delete_from_peer(payload, from_bot)

                elif entity == "USERACCESS":
                    payload = json.loads(" ".join(parts[3:]))
                    await self.user.merge_access_from_peer([payload], from_bot)

                elif entity == "BOTACCESS":
                    payload = json.loads(" ".join(parts[3:]))
                    await self.bot.merge_access_from_peer([payload], from_bot)

                else:
                    log.warning(f"Unknown UPDATE entity '{entity}' from {from_bot}")

            except (json.JSONDecodeError, KeyError, IndexError) as exc:
                log.error(f"Failed to apply UPDATE {entity} from {from_bot}: {exc}")

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

        elif cmd == "TOPOLOGY":
            # TOPOLOGY <msg_id> <source_bot> <peer1> [peer2 ...]
            if len(parts) < 3:
                log.warning("Malformed TOPOLOGY from %s: %r", from_bot, line[:80])
                return

            msg_id     = parts[1]
            source_bot = parts[2].lower()
            peers_seen = [p.lower() for p in parts[3:]]

            if not self._register_message(msg_id):
                return  # duplicate — drop silently

            # Register all peers the source bot can directly see as indirect for us,
            # but only if we don't already have a direct link to them.
            for handle in peers_seen:
                if handle == self.my_handle.lower():
                    continue   # that's us
                if handle not in self.peers:
                    self.topology[handle] = source_bot   # reachable via source_bot
                else:
                    self.topology.pop(handle, None)      # we have direct — clean up any stale indirect entry

            # Flood-fill to our other peers
            relay_line = f"TOPOLOGY {msg_id} {source_bot} {' '.join(parts[3:])}\n"
            tasks = [
                self._safe_send(link.writer, relay_line)
                for name, link in self.peers.items()
                if link.authed and link.connected and link.writer
                and name != from_bot.lower()
            ]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        else:
            log.error(f"Invalid command {cmd} from {from_bot}")
    
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
        key = BotCommand(name.lower(), plugin.lower())
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

    async def broadcast_chat(self, nick: str, msg: str, exclude: set[str] | None = None) -> None:
        """
        Broadcast a partyline chat message to every bot in the network.

        Flood-fills via CHAT_ROUTE. Each hop relays to its own peers.
        Loop prevention via msg_id stops cycles.

        Args:
            nick:    The handle/nick of the user who sent the message.
            msg:     The chat message text.
            exclude: Peer handles to skip (e.g. the peer this came from).
        """
        msg_id = str(uuid.uuid4())
        line   = f"CHAT_ROUTE {msg_id} {self.my_handle} {nick} :{msg}\n"
        tasks  = [
            self._safe_send(link.writer, line)
            for name, link in self.peers.items()
            if link.authed and link.connected and link.writer
            and name not in (exclude or set())
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_all(self, command: str, args: str = "") -> None:
        """
        Send a command to every bot in the network, directly linked or not.

        Flood-fills via CMD_ROUTE broadcast. Each hop relays to its own
        peers. Loop prevention via msg_id stops cycles.

        Args:
            command: Command name.
            args:    Command arguments as a string.
        """
        msg_id = str(uuid.uuid4())
        line   = f"CMD_ROUTE broadcast {msg_id} {self.my_handle} - {command} {args}\n"
        tasks  = [
            self._safe_send(link.writer, line)
            for link in self.peers.values()
            if link.authed and link.connected and link.writer
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


    async def broadcast_subnet(self, command: str, args: str = "", subnet_id: int | None = None) -> None:
        """
        Send a command to all bots on a specific subnet, directly linked or not.

        Uses CMD_ROUTE with routing=subnet so intermediate bots only relay
        to peers that belong to the same subnet.

        Args:
            command:   Command name.
            args:      Command arguments as a string.
            subnet_id: Target subnet. Defaults to this bot's own subnet.
        """
        sid    = subnet_id if subnet_id is not None else self.subnet_id
        msg_id = str(uuid.uuid4())
        line   = f"CMD_ROUTE subnet {msg_id} {self.my_handle} - {sid} {command} {args}\n"
        tasks  = [
            self._safe_send(link.writer, line)
            for link in self.peers.values()
            if link.authed and link.connected and link.writer
            and link.subnet_id == sid
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


    async def unicast(self, target: str, command: str, args: str = "") -> None:
        """
        Send a command to one specific bot anywhere in the network.

        Flood-fills via CMD_ROUTE unicast. Only the named target executes
        it; intermediate bots relay silently. No routing table required.

        Args:
            target:  Destination bot handle.
            command: Command name.
            args:    Command arguments as a string.
        """
        msg_id = str(uuid.uuid4())
        line   = f"CMD_ROUTE unicast {msg_id} {self.my_handle} {target} {command} {args}\n"
        tasks  = [
            self._safe_send(link.writer, line)
            for link in self.peers.values()
            if link.authed and link.connected and link.writer
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

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

    async def _sync(self, payload: str, exclude: set[str] | None = None) -> None:
        """
        Send a pre-built UPDATE line to all authenticated peers.
        Internal helper — all public sync_* methods go through here.
        """
        msg_id = str(uuid.uuid4())
        line   = f"UPDATE {msg_id} {payload}\n"
        tasks  = [
            self._safe_send(link.writer, line)
            for name, link in self.peers.items()
            if link.authed and link.connected and link.writer
            and name not in (exclude or set())
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def sync_channel(self, action: str, channel_data: dict) -> None:
        """
        Broadcast a channel add or delete to the network.

        Args:
            action:       'ADD' or 'DEL'
            channel_data: Dict representation of the channel row.
        """
        await self._sync(f"CHANNEL {action} {json.dumps(channel_data)}")

    async def sync_user(self, action: str, user_data: dict) -> None:
        """
        Broadcast a user add or delete to the network.

        Args:
            action:    'ADD' or 'DEL'
            user_data: Dict representation of the user row.
        """
        await self._sync(f"USER {action} {json.dumps(user_data)}")

    async def sync_bot(self, action: str, bot_data: dict) -> None:
        """
        Broadcast a bot add or delete to the network.

        Args:
            action:   'ADD' or 'DEL'
            bot_data: Dict representation of the bot row.
        """
        await self._sync(f"BOT {action} {json.dumps(bot_data)}")

    async def sync_user_access(self, access_data: dict) -> None:
        """
        Broadcast a user flag or hostmask change to the network.

        Args:
            access_data: Dict with at minimum {'handle': ..., 'flags': ..., 'hosts': ...}
        """
        await self._sync(f"USERACCESS {json.dumps(access_data)}")

    async def sync_bot_access(self, access_data: dict) -> None:
        """
        Broadcast a bot flag or hostmask change to the network.

        Args:
            access_data: Dict with at minimum {'handle': ..., 'flags': ...}
        """
        await self._sync(f"BOTACCESS {json.dumps(access_data)}")

    def _register_message(self, msg_id: str) -> bool:
        """
        Deduplication guard for flood-fill routing.

        Returns True if msg_id is new (caller should process + relay).
        Returns False if msg_id was already seen (caller should drop silently).

        Uses an OrderedDict as a bounded FIFO cache keyed by msg_id.
        Entries expire after MSG_TTL seconds; cache is also capped at
        MAX_MSG_CACHE_SIZE to bound memory under flood conditions.
        """
        now = time.monotonic()

        # Already seen — drop
        if msg_id in self._msg_cache:
            return False

        # Evict expired entries from the front (oldest inserted first)
        while self._msg_cache:
            oldest_id, oldest_ts = next(iter(self._msg_cache.items()))
            if now - oldest_ts > MSG_TTL:
                self._msg_cache.popitem(last=False)
            else:
                break  # remaining entries are newer

        # Hard cap: if still over limit, evict oldest regardless of age
        while len(self._msg_cache) >= MAX_MSG_CACHE_SIZE:
            self._msg_cache.popitem(last=False)

        # Register new message
        self._msg_cache[msg_id] = now
        return True
    
    async def broadcast_topology(self) -> None:
        """
        Announce our directly-linked peers to the network so all bots
        can build an indirect-link map for display and unicast routing.
        """
        direct = [
            name for name, link in self.peers.items()
            if link.authed and link.connected
        ]
        if not direct:
            return
        msg_id = str(uuid.uuid4())
        peer_list = " ".join(direct)
        line = f"TOPOLOGY {msg_id} {self.my_handle} {peer_list}\n"
        tasks = [
            self._safe_send(link.writer, line)
            for link in self.peers.values()
            if link.authed and link.connected and link.writer
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)    

    def _register_net_handlers(self) -> None:
        """
        Register handlers for commands dispatched via .net (CMD_ROUTE).
        Each handler receives (cmd_key, args_list, from_bot) and executes
        the action locally on this bot using the IRC queue.
        """
        net_cmds = {
            'join':    self._net_join,
            'part':    self._net_part,
            'say':     self._net_say,
            'msg':     self._net_say,
            'op':      self._net_op,
            'deop':    self._net_deop,
            'mode':    self._net_mode,
            'restart': self._net_restart,
            'die':     self._net_die,
        }
        for name, handler in net_cmds.items():
            self.register('net', name, handler)

    async def _net_join(self, cmd_key, args, from_bot):
        """CMD_ROUTE join #channel"""
        if not args:
            return
        channel = args[0] if isinstance(args, list) else args.split()[0]
        self.irc_q.put_nowait({'cmd': 'join', 'channel': channel})
        log.info("net join %s (from %s)", channel, from_bot)

    async def _net_part(self, cmd_key, args, from_bot):
        """CMD_ROUTE part #channel [reason]"""
        parts = args if isinstance(args, list) else args.split()
        if not parts:
            return
        channel = parts[0]
        reason  = ' '.join(parts[1:]) if len(parts) > 1 else ''
        self.irc_q.put_nowait({'cmd': 'part', 'channel': channel, 'reason': reason})
        log.info("net part %s (from %s)", channel, from_bot)

    async def _net_say(self, cmd_key, args, from_bot):
        """CMD_ROUTE say|msg #target message text"""
        parts = args if isinstance(args, list) else args.split()
        if len(parts) < 2:
            return
        target = parts[0]
        text   = ' '.join(parts[1:])
        self.irc_q.put_nowait({'cmd': 'msg', 'target': target, 'text': text})
        log.info("net say %s (from %s)", target, from_bot)

    async def _net_op(self, cmd_key, args, from_bot):
        """CMD_ROUTE op nick #channel"""
        parts = args if isinstance(args, list) else args.split()
        if len(parts) < 2:
            return
        nick, chan = parts[0], parts[1]
        self.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': f'+o {nick}'})
        log.info("net op %s on %s (from %s)", nick, chan, from_bot)

    async def _net_deop(self, cmd_key, args, from_bot):
        """CMD_ROUTE deop nick #channel"""
        parts = args if isinstance(args, list) else args.split()
        if len(parts) < 2:
            return
        nick, chan = parts[0], parts[1]
        self.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': f'-o {nick}'})
        log.info("net deop %s on %s (from %s)", nick, chan, from_bot)

    async def _net_mode(self, cmd_key, args, from_bot):
        """CMD_ROUTE mode #channel +modes"""
        parts = args if isinstance(args, list) else args.split()
        if len(parts) < 2:
            return
        chan  = parts[0]
        modes = ' '.join(parts[1:])
        self.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': modes})
        log.info("net mode %s %s (from %s)", chan, modes, from_bot)

    async def _net_restart(self, cmd_key, args, from_bot):
        """CMD_ROUTE restart"""
        log.info("net restart triggered by %s", from_bot)
        await self.core.shutdown("Restart via botnet")

    async def _net_die(self, cmd_key, args, from_bot):
        """CMD_ROUTE die [message]"""
        msg = ' '.join(args) if isinstance(args, list) else args
        log.info("net die triggered by %s: %s", from_bot, msg)
        self.irc_q.put_nowait({'cmd': 'quit', 'message': msg or 'Killed via botnet'})                 