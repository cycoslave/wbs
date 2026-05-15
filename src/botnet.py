# src/botnet.py
"""
Botnet peer manager for WBS.
Handles bot-to-bot linking, command routing, and data sharing.
"""
import asyncio
import json
import logging
import aiosqlite
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Dict, Optional, Any, Literal, Callable
from dataclasses import dataclass

from . import __version__
from .bot import BotManager
from .subnet import SubnetManager

log = logging.getLogger("wbs.botnet")

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
        self.bot = BotManager(self.db_path)
        self.subnet = SubnetManager(self.db_path)
        self.peers: Dict[BotLink] = {}
        self.cmds: Dict[BotCommand, Callable] = {}
        
        # Settings
        self.subnet_id = self.config.get('botnet', {}).get('subnet_id', 1)
        self.my_handle = self.config.get('bot', {}).get('nick', 'WBS')
        self.running = True
        self.loop = None
        
    def stop(self):
        """Shutdown."""
        self.running = False
        for _, writer in self.peers.values():
            writer.close()

    async def connect_peer(self, handle: str):
        """Establish outgoing connection to peer."""
        try:
            bot = await self.bot.get(handle)
            
            # Connect first
            reader, writer = await asyncio.open_connection(bot.address, bot.port)
            
            # Create link and assign streams
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
            
            #log.info(f"password: {link.password}")

            # If no password, generate partial key for exchange
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
            """Disconnect specific bot"""
            if self.peer_socket and self.connected_bots.get(botname):
                self.peer_socket.close()
                self.peer_socket = None
                del self.connected_bots[botname]
                self.core.irc_q.put({
                    'type': 'BOTLINK_UNLINK', 
                    'handle': botname
                })

    async def read_peer(self, handle: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Continuously read messages from a peer connection."""
        try:
            while self.running:
                line = await reader.readline()
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

        #log.info(f"Processing from {from_bot}: {line[:100]}")
        
        if cmd == "BOTLINK":
            # Incoming connection request
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

            #log.info(f"password: {link.password}")

            remote = parts[1]
            local = parts[2]
            
            if local.lower() != self.my_handle.lower() or remote.lower() != from_bot.lower():
                log.error(f"Botlink mismatch from {from_bot}")
                #log.info(f"local {self.my_handle.lower()}/{local}  remote {from_bot}/{remote}")
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
                    #log.info(f"remote {their_partial} - local {our_partial}")

                    shared_password = hashlib.sha256((min(their_partial, our_partial) + max(their_partial, our_partial)).encode()).hexdigest()
                    link.password = shared_password
                    #log.info(f"shared pass: {shared_password}")
                    log.info(f"Generated shared password with {from_bot}")
                    await self.bot.chpass(from_bot.lower(), password=shared_password)
                    ack = f"LINKACK {self.my_handle} {remote} 1 WBS {__version__} {our_partial}\n"
                    log.info(f"Sending {ack}")
                    await self._safe_send(writer, ack)
                    #asyncio.create_task(self.read_peer(from_bot, reader, writer))
                else:
                    log.error(f"No password configured for {from_bot} and no key exchange offered")
                    writer.close()
                    return
            else:
                # Password exists, ACKAUTH
                await self._safe_send(writer, f"LINKACK {self.my_handle} {remote} 1 WBS {__version__}\n")
                #asyncio.create_task(self.read_peer(from_bot, reader, writer))
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
                    #log.info(f"remote {their_partial} - local {our_partial}")

                    shared_password = hashlib.sha256((min(their_partial, our_partial) + max(their_partial, our_partial)).encode()).hexdigest()
                    link.password = shared_password
                    #log.info(f"shared pass: {shared_password}")
                    
                    log.info(f"Generated shared password with {from_bot}")
                    await self.bot.chpass(from_bot.lower(), password=shared_password)
                    #log.info(f"auth string: {self.my_handle}{link.password}{parts[1]}")
                    chalhash = hashlib.sha256(f"{self.my_handle}{link.password}{parts[1]}".encode()).hexdigest()
                    challenge = f"LINKAUTH {self.my_handle} {chalhash}\n"
                    #log.info(f"Sending authentication token {challenge}")
                    await self._safe_send(writer, challenge)
                else:
                    log.error(f"Credential mismatch with {from_bot}: peer sent LINKACK without exchange token while local password is unset")
                    writer.close()
                    return
            else:
                #log.info(f"auth string: {self.my_handle}{link.password}{parts[1]}")
                chalhash = hashlib.sha256(f"{self.my_handle}{link.password}{parts[1]}".encode()).hexdigest()
                challenge = f"LINKAUTH {self.my_handle} {chalhash}\n"
                #log.info(f"Sending authentication token {challenge}")
                await self._safe_send(writer, challenge)
            return
        
        elif cmd == "LINKAUTH":
            # Validate authentication
            #log.info(f"auth string: {parts[1]}{link.password}{self.my_handle}")
            expectedhash = hashlib.sha256(f"{parts[1]}{link.password}{self.my_handle}".encode()).hexdigest()
            
            #log.info(f"expected: {expectedhash} - got: {parts[2]}")
            if len(parts) < 2 or parts[2] != expectedhash:
                log.error(f"Auth failed from {from_bot}")
                writer.close()
                return
            
            self.core.partyline.broadcast(f"*** {from_bot} linked to botnet", True)
            link.authed = True
            #log.info(f"Auth success: {from_bot}")
            #self.core.bot_sessions[from_bot.lower()] = link
            link.connected_at = datetime.now(timezone.utc)
            self.subnet.register_peer(from_bot, link.subnet_id)
            await self._safe_send(writer, f"LINKREADY {self.my_handle} WBS {__version__}\n")
            asyncio.create_task(self.share_all_data(from_bot))
            return
        
        elif cmd == "LINKREADY":
            # Link established
            self.core.partyline.broadcast(f"*** {from_bot} linked to botnet", True)
            link.authed = True
            #log.info(f"Link established with {from_bot}")
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

    async def share_subnets(self, link: BotLink):
        """Share subnet definitions."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            if link.share_level == 'subnet':
                # Only share the specific subnet
                cursor = await db.execute(
                    "SELECT * FROM subnets WHERE id = ?",
                    (link.subnet_id,)
                )
            else:  # 'full'
                cursor = await db.execute("SELECT * FROM subnets")
            
            rows = await cursor.fetchall()
            subnets = [dict(row) for row in rows]
        
        msg = f"SHARE SUBNETS {json.dumps(subnets)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(subnets)} subnets to {link.name}")

    async def share_bots(self, link: BotLink, exclude_bot: str):
        """Share bot registry, exclude target and strip passwords."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            if link.share_level == 'subnet':
                cursor = await db.execute(
                    """SELECT * FROM bots 
                    WHERE handle != ? AND (subnet_id = ? OR subnet_id IS NULL)""",
                    (exclude_bot.lower(), link.subnet_id)
                )
            else:  # 'full'
                cursor = await db.execute(
                    "SELECT * FROM bots WHERE handle != ?",
                    (exclude_bot.lower(),)
                )
            
            rows = await cursor.fetchall()
            bots = []
            for row in rows:
                bot = dict(row)
                bot['password'] = None  # Never share bot passwords
                bots.append(bot)
        
        msg = f"SHARE BOTS {json.dumps(bots)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(bots)} bots to {link.name} (excluded {exclude_bot})")

    async def share_bot_access(self, link: BotLink):
        """Share bot permissions to peer."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM bot_access")
            rows = await cursor.fetchall()
            access = [dict(row) for row in rows]

        msg = f"SHARE BOTACCESS {json.dumps(access)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(access)} bot_access to {link.name}")

    async def handle_share_bots(self, data: str, from_bot: str):
        """Merge received bots with conflict resolution."""
        bots = json.loads(data)
        
        async with aiosqlite.connect(self.db_path) as db:
            for bot in bots:
                handle = bot['handle'].lower()
                
                # CRITICAL: Skip self-reference
                if handle == self.my_handle.lower():
                    log.warning(f"Skipping self-reference from {from_bot}")
                    continue
                
                # Check if bot exists locally
                cursor = await db.execute(
                    "SELECT password, updated_at FROM bots WHERE handle = ?",
                    (handle,)
                )
                existing = await cursor.fetchone()
                
                if existing:
                    # Merge strategy: keep local password, update metadata
                    await db.execute("""
                        UPDATE bots SET
                            hostmasks = ?,
                            address = ?,
                            port = ?,
                            role = ?,
                            subnet_id = ?,
                            share_level = ?,
                            comment = ?
                        WHERE handle = ? AND updated_at < ?
                    """, (
                        bot['hostmasks'], bot['address'], bot['port'],
                        bot['role'], bot['subnet_id'], bot['share_level'],
                        bot['comment'], handle, bot['updated_at']
                    ))
                else:
                    # New bot: insert without password
                    await db.execute("""
                        INSERT INTO bots (handle, hostmasks, address, port, role,
                                        subnet_id, share_level, comment, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        handle, bot['hostmasks'], bot['address'], bot['port'],
                        bot['role'], bot['subnet_id'], bot['share_level'],
                        bot['comment'], bot['created_at']
                    ))
            
            await db.commit()
        
        log.info(f"Merged {len(bots)} bots from {from_bot}")


    async def share_users(self, link: BotLink):
        """Share ALL users (including soft-deleted) with passwords."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM users")
            rows = await cursor.fetchall()
            users = [dict(row) for row in rows]

        msg = f"SHARE USERS {json.dumps(users)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(users)} users to {link.name}")

    async def handle_share_users(self, data: str, from_bot: str):
        """
        Merge users. Last-write-wins on updated_at.
        Soft-deletes propagate but cannot resurrect a more-recently-deleted local row.
        """
        users = json.loads(' '.join(data) if isinstance(data, list) else data)

        async with aiosqlite.connect(self.db_path) as db:
            for user in users:
                handle = user["handle"].lower()

                cur = await db.execute(
                    "SELECT updated_at, deleted_at FROM users WHERE handle = ?", (handle,)
                )
                existing = await cur.fetchone()
                remote_updated = user.get("updated_at") or 0
                remote_deleted = user.get("deleted_at")

                if existing:
                    local_updated = existing[0] or 0
                    local_deleted = existing[1]

                    if remote_updated <= local_updated:
                        continue  # Local is newer or equal

                    # Remote is newer — compute final deleted_at
                    if remote_deleted is not None:
                        final_deleted = remote_deleted
                    elif local_deleted is not None and local_deleted > remote_updated:
                        final_deleted = local_deleted  # Keep more-recent local delete
                    else:
                        final_deleted = None  # Active

                    await db.execute("""
                        UPDATE users SET
                            password=?, hostmasks=?, is_locked=?, comment=?,
                            updated_at=?, updated_by=?, deleted_at=?
                        WHERE handle=?
                    """, (
                        user.get("password"), user.get("hostmasks","[]"),
                        user.get("is_locked",0), user.get("comment",""),
                        remote_updated, from_bot, final_deleted, handle
                    ))
                else:
                    await db.execute("""
                        INSERT INTO users
                            (handle, password, hostmasks, is_locked, comment,
                             created_at, updated_at, created_by, deleted_at)
                        VALUES (?,?,?,?,?,?,?,?,?)
                    """, (
                        handle, user.get("password"), user.get("hostmasks","[]"),
                        user.get("is_locked",0), user.get("comment",""),
                        user.get("created_at",0), remote_updated,
                        from_bot, remote_deleted
                    ))

            await db.commit()
        log.info(f"Merged {len(users)} users from {from_bot}")

    async def share_user_access(self, link: BotLink):
        """Share ALL user_access rows (all subnets, including soft-deleted)."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM user_access")
            rows = await cursor.fetchall()
            access = [dict(row) for row in rows]

        msg = f"SHARE USERACCESS {json.dumps(access)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(access)} user_access rows to {link.name}")

    async def handle_share_user_access(self, data: str, from_bot: str):
        """
        Merge user_access. PK is (handle, channel, subnet_id).
        Last-write-wins. Soft-deletes propagate safely.
        """
        access_list = json.loads(' '.join(data) if isinstance(data, list) else data)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")

            for acc in access_list:
                handle = acc["handle"].lower()
                channel = acc.get("channel")         # May be NULL
                subnet_id = acc.get("subnet_id")     # May be NULL
                remote_updated = acc.get("updated_at") or 0
                remote_deleted = acc.get("deleted_at")

                # Match on the composite PK, accounting for NULL values
                cur = await db.execute(
                    """SELECT updated_at, deleted_at FROM user_access
                       WHERE handle=?
                         AND (channel=? OR (channel IS NULL AND ? IS NULL))
                         AND (subnet_id=? OR (subnet_id IS NULL AND ? IS NULL))""",
                    (handle, channel, channel, subnet_id, subnet_id)
                )
                existing = await cur.fetchone()

                if existing:
                    local_updated = existing[0] or 0
                    local_deleted = existing[1]

                    if remote_updated <= local_updated:
                        continue

                    if remote_deleted is not None:
                        final_deleted = remote_deleted
                    elif local_deleted is not None and local_deleted > remote_updated:
                        final_deleted = local_deleted
                    else:
                        final_deleted = None

                    await db.execute("""
                        UPDATE user_access SET
                            has_partyline=?, is_admin=?, is_owner=?, is_friend=?,
                            is_autoop=?, is_op=?, is_deop=?,
                            is_autohop=?, is_hop=?, is_dehop=?,
                            is_voice=?, is_devoice=?,
                            is_autokick=?,
                            updated_at=?, updated_by=?, deleted_at=?
                        WHERE handle=?
                          AND (channel=? OR (channel IS NULL AND ? IS NULL))
                          AND (subnet_id=? OR (subnet_id IS NULL AND ? IS NULL))
                    """, (
                        acc.get("has_partyline",0), acc.get("is_admin",0),
                        acc.get("is_owner",0), acc.get("is_friend",0),
                        acc.get("is_autoop",0), acc.get("is_op",0), acc.get("is_deop",0),
                        acc.get("is_autohop",0), acc.get("is_hop",0), acc.get("is_dehop",0),
                        acc.get("is_voice",0), acc.get("is_devoice",0),
                        acc.get("is_autokick",0),
                        remote_updated, from_bot, final_deleted,
                        handle, channel, channel, subnet_id, subnet_id
                    ))
                else:
                    await db.execute("""
                        INSERT INTO user_access (
                            handle, channel, subnet_id,
                            has_partyline, is_admin, is_owner, is_friend,
                            is_autoop, is_op, is_deop,
                            is_autohop, is_hop, is_dehop,
                            is_voice, is_devoice, is_autokick,
                            created_at, updated_at, created_by, deleted_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        handle, channel, subnet_id,
                        acc.get("has_partyline",0), acc.get("is_admin",0),
                        acc.get("is_owner",0), acc.get("is_friend",0),
                        acc.get("is_autoop",0), acc.get("is_op",0), acc.get("is_deop",0),
                        acc.get("is_autohop",0), acc.get("is_hop",0), acc.get("is_dehop",0),
                        acc.get("is_voice",0), acc.get("is_devoice",0),
                        acc.get("is_autokick",0),
                        acc.get("created_at",0), remote_updated, from_bot,
                        remote_deleted
                    ))

            await db.commit()
        log.info(f"Merged {len(access_list)} user_access from {from_bot}")

    async def handle_share_subnets(self, data: str, from_bot: str):
        """Merge subnets with conflict resolution."""
        subnets = json.loads(data)
        await self.subnet.merge_from_peer(subnets, from_bot)
        
        async with aiosqlite.connect(self.db_path) as db:
            for subnet in subnets:
                subnet_id = subnet['id']
                name = subnet['name']
                
                # Check if exists by ID or name
                cursor = await db.execute(
                    "SELECT id, created_at FROM subnets WHERE id = ? OR name = ?",
                    (subnet_id, name)
                )
                existing = await cursor.fetchone()
                
                if existing:
                    # Subnet exists - keep local version (subnets rarely change)
                    log.debug(f"Subnet {name} (id={subnet_id}) already exists, keeping local")
                else:
                    # Insert new subnet with same ID
                    await db.execute("""
                        INSERT INTO subnets (id, name, created_at, created_by)
                        VALUES (?, ?, ?, ?)
                    """, (
                        subnet_id, name, subnet['created_at'], from_bot
                    ))
                    log.info(f"Added subnet {name} (id={subnet_id}) from {from_bot}")
            
            await db.commit()
        
        log.info(f"Merged {len(subnets)} subnets from {from_bot}")

    async def share_channels(self, link: BotLink):
        """Share ALL channel rows (including soft-deleted) for full sync."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            # Always share everything — receiver filters by subnet for IRC joins,
            # not for storage.
            cursor = await db.execute("SELECT * FROM channels")
            rows = await cursor.fetchall()

            # Enrich with subnet_ids from join table
            channels = []
            for row in rows:
                data = dict(row)
                sub_cur = await db.execute(
                    "SELECT subnet_id FROM channel_subnets WHERE channel_name = ?",
                    (data["name"],)
                )
                data["subnet_ids"] = [r[0] for r in await sub_cur.fetchall()]
                channels.append(data)

        msg = f"SHARE CHANNELS {json.dumps(channels)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(channels)} channels to {link.name}")

    async def handle_share_channels(self, data: str, from_bot: str):
        """
        Merge channels. Rules:
        - Share entire table (both active and soft-deleted rows).
        - Last-write-wins on updated_at.
        - A deleted_at is never cleared by an older record.
        - channel_subnets rows are merged independently.
        """
        channels = json.loads(' '.join(data) if isinstance(data, list) else data)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")

            for ch in channels:
                name = ch["name"]

                cur = await db.execute(
                    "SELECT updated_at, deleted_at FROM channels WHERE name = ?", (name,)
                )
                existing = await cur.fetchone()

                if existing:
                    local_updated = existing[0] or 0
                    local_deleted = existing[1]
                    remote_updated = ch.get("updated_at") or 0
                    remote_deleted = ch.get("deleted_at")

                    if remote_updated <= local_updated:
                        # Local is newer or equal — skip channel row, still sync subnets
                        pass
                    else:
                        # Remote is newer
                        # Protect against resurrection: if locally deleted MORE RECENTLY,
                        # keep local deleted_at
                        final_deleted = local_deleted
                        if remote_deleted is not None:
                            # Remote is deleting — accept if remote_updated > local_updated
                            final_deleted = remote_deleted
                        elif local_deleted is not None and local_deleted > remote_updated:
                            # Local was deleted after remote's last update — keep deleted
                            final_deleted = local_deleted
                        else:
                            final_deleted = remote_deleted  # None = active

                        await db.execute("""
                            UPDATE channels SET
                                modes=?, bans=?, invites=?, exempts=?,
                                flood_pub=?, flood_pub_time=?,
                                flood_ctcp=?, flood_ctcp_time=?,
                                flood_join=?, flood_join_time=?,
                                flood_kick=?, flood_kick_time=?,
                                flood_deop=?, flood_deop_time=?,
                                flood_nick=?, flood_nick_time=?,
                                is_bitch=?, is_autoop=?, is_autovoice=?,
                                is_revenge=?, is_revengebots=?,
                                is_protectfriends=?, is_protectops=?,
                                is_dontkickops=?, is_inactive=?,
                                is_enforcebans=?, is_dynamicbans=?,
                                is_dynamicexempts=?, is_dynamicinvites=?,
                                comment=?, updated_at=?, updated_by=?,
                                deleted_at=?
                            WHERE name=?
                        """, (
                            ch.get("modes",""), ch.get("bans","[]"),
                            ch.get("invites","[]"), ch.get("exempts","[]"),
                            ch.get("flood_pub",15), ch.get("flood_pub_time",60),
                            ch.get("flood_ctcp",3), ch.get("flood_ctcp_time",60),
                            ch.get("flood_join",5), ch.get("flood_join_time",60),
                            ch.get("flood_kick",3), ch.get("flood_kick_time",10),
                            ch.get("flood_deop",3), ch.get("flood_deop_time",10),
                            ch.get("flood_nick",5), ch.get("flood_nick_time",60),
                            ch.get("is_bitch",0), ch.get("is_autoop",0), ch.get("is_autovoice",0),
                            ch.get("is_revenge",0), ch.get("is_revengebots",0),
                            ch.get("is_protectfriends",0), ch.get("is_protectops",0),
                            ch.get("is_dontkickops",0), ch.get("is_inactive",0),
                            ch.get("is_enforcebans",0), ch.get("is_dynamicbans",0),
                            ch.get("is_dynamicexempts",0), ch.get("is_dynamicinvites",0),
                            ch.get("comment",""), remote_updated, from_bot,
                            final_deleted, name
                        ))
                else:
                    # New row — insert as-is
                    await db.execute("""
                        INSERT INTO channels (
                            name, modes, bans, invites, exempts,
                            flood_pub, flood_pub_time, flood_ctcp, flood_ctcp_time,
                            flood_join, flood_join_time, flood_kick, flood_kick_time,
                            flood_deop, flood_deop_time, flood_nick, flood_nick_time,
                            is_bitch, is_autoop, is_autovoice, is_revenge, is_revengebots,
                            is_protectfriends, is_protectops, is_dontkickops, is_inactive,
                            is_enforcebans, is_dynamicbans, is_dynamicexempts, is_dynamicinvites,
                            comment, created_at, updated_at, created_by, deleted_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        name, ch.get("modes",""), ch.get("bans","[]"),
                        ch.get("invites","[]"), ch.get("exempts","[]"),
                        ch.get("flood_pub",15), ch.get("flood_pub_time",60),
                        ch.get("flood_ctcp",3), ch.get("flood_ctcp_time",60),
                        ch.get("flood_join",5), ch.get("flood_join_time",60),
                        ch.get("flood_kick",3), ch.get("flood_kick_time",10),
                        ch.get("flood_deop",3), ch.get("flood_deop_time",10),
                        ch.get("flood_nick",5), ch.get("flood_nick_time",60),
                        ch.get("is_bitch",0), ch.get("is_autoop",0), ch.get("is_autovoice",0),
                        ch.get("is_revenge",0), ch.get("is_revengebots",0),
                        ch.get("is_protectfriends",0), ch.get("is_protectops",0),
                        ch.get("is_dontkickops",0), ch.get("is_inactive",0),
                        ch.get("is_enforcebans",0), ch.get("is_dynamicbans",0),
                        ch.get("is_dynamicexempts",0), ch.get("is_dynamicinvites",0),
                        ch.get("comment",""), ch.get("created_at",0),
                        ch.get("updated_at",0), from_bot, ch.get("deleted_at")
                    ))

                # Merge channel_subnets (idempotent inserts)
                for sid in ch.get("subnet_ids", []):
                    await db.execute(
                        "INSERT OR IGNORE INTO channel_subnets (channel_name, subnet_id, added_by) "
                        "VALUES (?, ?, ?)",
                        (name, sid, from_bot)
                    )

            await db.commit()
        log.info(f"Merged {len(channels)} channels from {from_bot}")

    async def handle_share_bot_access(self, data: str, from_bot: str):
        """Merge bot_access with conflict resolution."""
        access_list = json.loads(data)
        
        async with aiosqlite.connect(self.db_path) as db:
            for access in access_list:
                handle = access['handle'].lower()
                channel = access['channel']
                
                # Skip if this is the receiving bot's own access
                if handle == self.my_handle.lower():
                    log.debug(f"Skipping own bot_access from {from_bot}")
                    continue
                
                # Check if exists
                cursor = await db.execute(
                    "SELECT updated_at FROM bot_access WHERE handle = ? AND channel = ?",
                    (handle, channel)
                )
                existing = await cursor.fetchone()
                
                if existing:
                    # Update if remote is newer
                    if access['updated_at'] > existing[0]:
                        await db.execute("""
                            UPDATE bot_access SET
                                subnet_id = ?,
                                has_partyline = ?,
                                is_admin = ?,
                                is_bot = ?,
                                is_op = ?,
                                is_deop = ?,
                                is_voice = ?,
                                is_devoice = ?,
                                is_friend = ?,
                                updated_at = ?,
                                updated_by = ?
                            WHERE handle = ? AND channel = ?
                        """, (
                            access['subnet_id'], access['has_partyline'],
                            access['is_admin'], access['is_bot'], access['is_op'],
                            access['is_deop'], access['is_voice'], access['is_devoice'],
                            access['is_friend'], access['updated_at'], from_bot,
                            handle, channel
                        ))
                        log.debug(f"Updated bot_access for {handle} on {channel}")
                else:
                    # Insert new access
                    await db.execute("""
                        INSERT INTO bot_access (
                            handle, channel, subnet_id, has_partyline, is_admin,
                            is_bot, is_op, is_deop, is_voice, is_devoice, is_friend,
                            created_at, updated_at, created_by
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        handle, channel, access['subnet_id'], access['has_partyline'],
                        access['is_admin'], access['is_bot'], access['is_op'],
                        access['is_deop'], access['is_voice'], access['is_devoice'],
                        access['is_friend'], access['created_at'], access['updated_at'],
                        from_bot
                    ))
                    log.info(f"Added bot_access for {handle} on {channel}")
            
            await db.commit()
        
        log.info(f"Merged {len(access_list)} bot_access from {from_bot}")