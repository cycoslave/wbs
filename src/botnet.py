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
from typing import Dict, Optional, Any, Literal, Callable
from dataclasses import dataclass

from . import __version__
from .bot import BotManager

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
            link.subnet_id = bot.subnet_id
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
            
            self.peers[handle] = link
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
            if from_bot not in self.peers:
                bot = await self.bot.get(from_bot.lower())
                link = BotLink(
                    name=from_bot,
                    host=bot.address,
                    port=bot.port,
                    writer=writer,
                    reader=reader
                )
                link.subnet_id = bot.subnet_id
                link.password = bot.password
                self.peers[from_bot.lower()] = link
                link.connected = True
                self.core.irc_q.put({
                    'type': 'BOTLINK_LINK', 
                    'handle': link.name,
                    'nick': link.name
                })
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
            
            if link.password is None:
                if len(parts) > 5:  
                    their_partial = parts[6]
                    our_partial = secrets.token_hex(16)
                    #log.info(f"remote {their_partial} - local {our_partial}")

                    shared_password = hashlib.sha256(f"{their_partial}{our_partial}".encode()).hexdigest()
                    link.password = shared_password
                    #log.info(f"shared pass: {shared_password}")
                    log.info(f"Generated shared password with {from_bot}")
                    await self.bot.chpass(from_bot.lower(), password=shared_password)
                    ack = f"LINKACK {self.my_handle} {remote} 1 WBS {__version__} {our_partial}\n"
                    log.info(f"Sending {ack}")
                    await self._safe_send(writer, ack)
                    asyncio.create_task(self.read_peer(from_bot, reader, writer))
                else:
                    log.error(f"No password configured for {from_bot} and no key exchange offered")
                    writer.close()
                    return
            else:
                # Password exists, ACKAUTH
                await self._safe_send(writer, f"LINKACK {self.my_handle} {remote} 1 WBS {__version__}\n")
                asyncio.create_task(self.read_peer(from_bot, reader, writer))
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

                    shared_password = hashlib.sha256(f"{our_partial}{their_partial}".encode()).hexdigest()
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
                    log.error(f"Unknown LINKACK from {from_bot}")
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
            #link.connected_at = time.time()
            await self._safe_send(writer, f"LINKREADY {self.my_handle} WBS {__version__}\n")
            return
        
        elif cmd == "LINKREADY":
            # Link established
            self.core.partyline.broadcast(f"*** {from_bot} linked to botnet", True)
            link.authed = True
            #log.info(f"Link established with {from_bot}")
            self.core.bot_sessions[from_bot.lower()] = link
            #link.connected_at = time.time()
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
                self.handle_share_subnets(parts[2:], from_bot)

            elif share == "CHANNELS":
                self.handle_share_channels(parts[2:], from_bot)

            elif share == "USERS":
                self.handle_share_users(parts[2:], from_bot)

            elif share == "USERACCESS":
                self.handle_share_user_access(parts[2:], from_bot)

            elif share == "BOTS":
                self.handle_share_bots(parts[2:], from_bot)

            elif share == "BOTACCESS":
                self.handle_share_bot_access(parts[2:], from_bot)

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

    async def broadcast_subnet(self, cmd: Dict):
        """Broadcast to subnet peers only."""
        msg = f"CMD:{json.dumps(cmd)}\n"
        tasks = []
        for name, (_, writer) in self.peers.items():
            peer = self.peers.get(name)
            if peer and peer.subnet_id == self.subnet_id:
                tasks.append(self._safe_send(writer, msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _safe_send(self, writer: asyncio.StreamWriter, msg: str):
        """Send with error handling."""
        try:
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

    async def share_users(self, link: BotLink):
        """Share users INCLUDING password hashes for unified auth."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM users")
            rows = await cursor.fetchall()
            
            users = [dict(row) for row in rows]
        
        msg = f"SHARE USERS {json.dumps(users)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(users)} users (with passwords) to {link.name}")

    async def share_user_access(self, link: BotLink):
        """Share user permissions filtered by subnet."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            if link.share_level == 'subnet':
                # Only share matching subnet or global (NULL)
                cursor = await db.execute(
                    """SELECT * FROM user_access 
                    WHERE subnet_id = ? OR subnet_id IS NULL""",
                    (link.subnet_id,)
                )
            else:  # 'full'
                cursor = await db.execute("SELECT * FROM user_access")
            
            rows = await cursor.fetchall()
            access = [dict(row) for row in rows]
        
        msg = f"SHARE USERACCESS {json.dumps(access)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(access)} user_access to {link.name}")

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
        """Share bot permissions filtered by subnet."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            if link.share_level == 'subnet':
                # Only share matching subnet or global (NULL)
                cursor = await db.execute(
                    """SELECT * FROM bot_access 
                    WHERE subnet_id = ? OR subnet_id IS NULL""",
                    (link.subnet_id,)
                )
            else:  # 'full'
                cursor = await db.execute("SELECT * FROM bot_access")
            
            rows = await cursor.fetchall()
            access = [dict(row) for row in rows]
        
        msg = f"SHARE BOTACCESS {json.dumps(access)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(access)} bot_access to {link.name}")

    async def share_channels(self, link: BotLink):
        """Share channel configs filtered by subnet."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            if link.share_level == 'subnet':
                cursor = await db.execute(
                    "SELECT * FROM channels WHERE subnet_id = ? OR subnet_id IS NULL",
                    (link.subnet_id,)
                )
            else:  # 'full'
                cursor = await db.execute("SELECT * FROM channels")
            
            rows = await cursor.fetchall()
            channels = [dict(row) for row in rows]
        
        msg = f"SHARE CHANNELS {json.dumps(channels)}\n"
        await self._safe_send(link.writer, msg)
        log.info(f"Shared {len(channels)} channels to {link.name}")

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

    async def handle_share_users(self, data: str, from_bot: str):
        """Merge users with password conflict resolution."""
        users = json.loads(data)
        
        async with aiosqlite.connect(self.db_path) as db:
            for user in users:
                handle = user['handle'].lower()
                
                cursor = await db.execute(
                    "SELECT password, updated_at FROM users WHERE handle = ?",
                    (handle,)
                )
                existing = await cursor.fetchone()
                
                if existing:
                    # Conflict resolution strategy
                    local_pass = existing[0]
                    remote_pass = user['password']
                    local_updated = existing[1]
                    remote_updated = user['updated_at']
                    
                    # Keep newer password (by updated_at timestamp)
                    if remote_updated > local_updated:
                        # Remote is newer, update everything including password
                        await db.execute("""
                            UPDATE users SET
                                password = ?,
                                hostmasks = ?,
                                is_locked = ?,
                                comment = ?,
                                updated_at = ?,
                                updated_by = ?
                            WHERE handle = ?
                        """, (
                            remote_pass, user['hostmasks'], user['is_locked'],
                            user['comment'], remote_updated, from_bot, handle
                        ))
                        log.debug(f"Updated user {handle} from {from_bot} (newer)")
                    else:
                        # Local is newer or equal, skip
                        log.debug(f"Kept local user {handle} (newer/equal)")
                else:
                    # New user: insert with password
                    await db.execute("""
                        INSERT INTO users (handle, password, hostmasks, is_locked,
                                        comment, created_at, updated_at, created_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        handle, user['password'], user['hostmasks'],
                        user['is_locked'], user['comment'],
                        user['created_at'], user['updated_at'], from_bot
                    ))
                    log.info(f"Added new user {handle} from {from_bot}")
            
            await db.commit()
        
        log.info(f"Merged {len(users)} users from {from_bot}")

    async def handle_share_subnets(self, data: str, from_bot: str):
        """Merge subnets with conflict resolution."""
        subnets = json.loads(data)
        
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

    async def handle_share_channels(self, data: str, from_bot: str):
        """Merge channels with conflict resolution."""
        channels = json.loads(data)
        
        async with aiosqlite.connect(self.db_path) as db:
            for channel in channels:
                name = channel['name']
                
                # Check if exists
                cursor = await db.execute(
                    "SELECT updated_at FROM channels WHERE name = ?",
                    (name,)
                )
                existing = await cursor.fetchone()
                
                if existing:
                    # Update if remote is newer
                    if channel['updated_at'] > existing[0]:
                        await db.execute("""
                            UPDATE channels SET
                                subnet_id = ?,
                                modes = ?,
                                bans = ?,
                                invites = ?,
                                exempts = ?,
                                flood_pub = ?, flood_pub_time = ?,
                                flood_ctcp = ?, flood_ctcp_time = ?,
                                flood_join = ?, flood_join_time = ?,
                                flood_kick = ?, flood_kick_time = ?,
                                flood_deop = ?, flood_deop_time = ?,
                                flood_nick = ?, flood_nick_time = ?,
                                is_bitch = ?, is_autoop = ?, is_autovoice = ?,
                                is_revenge = ?, is_revengebots = ?,
                                is_protectfriends = ?, is_protectops = ?,
                                is_dontkickops = ?, is_inactive = ?,
                                is_enforcebans = ?, is_dynamicbans = ?,
                                is_dynamicexempts = ?, is_dynamicinvites = ?,
                                is_pubcom = ?, is_news = ?, is_url = ?, is_stats = ?,
                                is_locked = ?, lock_by = ?, lock_at = ?, lock_reason = ?,
                                is_topiclock = ?, topiclock = ?, topiclock_by = ?,
                                topiclock_at = ?, topiclock_reason = ?,
                                is_limit = ?, limit_add = ?, limit_rand = ?,
                                limit_tolerance = ?, limit_delta = ?, limit_at = ?,
                                comment = ?, updated_at = ?, updated_by = ?
                            WHERE name = ?
                        """, (
                            channel['subnet_id'], channel['modes'],
                            channel['bans'], channel['invites'], channel['exempts'],
                            channel['flood_pub'], channel['flood_pub_time'],
                            channel['flood_ctcp'], channel['flood_ctcp_time'],
                            channel['flood_join'], channel['flood_join_time'],
                            channel['flood_kick'], channel['flood_kick_time'],
                            channel['flood_deop'], channel['flood_deop_time'],
                            channel['flood_nick'], channel['flood_nick_time'],
                            channel['is_bitch'], channel['is_autoop'], channel['is_autovoice'],
                            channel['is_revenge'], channel['is_revengebots'],
                            channel['is_protectfriends'], channel['is_protectops'],
                            channel['is_dontkickops'], channel['is_inactive'],
                            channel['is_enforcebans'], channel['is_dynamicbans'],
                            channel['is_dynamicexempts'], channel['is_dynamicinvites'],
                            channel['is_pubcom'], channel['is_news'], channel['is_url'],
                            channel['is_stats'], channel['is_locked'], channel['lock_by'],
                            channel['lock_at'], channel['lock_reason'],
                            channel['is_topiclock'], channel['topiclock'],
                            channel['topiclock_by'], channel['topiclock_at'],
                            channel['topiclock_reason'], channel['is_limit'],
                            channel['limit_add'], channel['limit_rand'],
                            channel['limit_tolerance'], channel['limit_delta'],
                            channel['limit_at'], channel['comment'],
                            channel['updated_at'], from_bot, name
                        ))
                        log.debug(f"Updated channel {name} from {from_bot}")
                else:
                    # Insert new channel
                    await db.execute("""
                        INSERT INTO channels (
                            name, subnet_id, modes, bans, invites, exempts,
                            flood_pub, flood_pub_time, flood_ctcp, flood_ctcp_time,
                            flood_join, flood_join_time, flood_kick, flood_kick_time,
                            flood_deop, flood_deop_time, flood_nick, flood_nick_time,
                            is_bitch, is_autoop, is_autovoice, is_revenge, is_revengebots,
                            is_protectfriends, is_protectops, is_dontkickops, is_inactive,
                            is_enforcebans, is_dynamicbans, is_dynamicexempts, is_dynamicinvites,
                            is_pubcom, is_news, is_url, is_stats,
                            is_locked, lock_by, lock_at, lock_reason,
                            is_topiclock, topiclock, topiclock_by, topiclock_at, topiclock_reason,
                            is_limit, limit_add, limit_rand, limit_tolerance, limit_delta, limit_at,
                            comment, created_at, updated_at, created_by
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                ?, ?, ?)
                    """, (
                        name, channel['subnet_id'], channel['modes'],
                        channel['bans'], channel['invites'], channel['exempts'],
                        channel['flood_pub'], channel['flood_pub_time'],
                        channel['flood_ctcp'], channel['flood_ctcp_time'],
                        channel['flood_join'], channel['flood_join_time'],
                        channel['flood_kick'], channel['flood_kick_time'],
                        channel['flood_deop'], channel['flood_deop_time'],
                        channel['flood_nick'], channel['flood_nick_time'],
                        channel['is_bitch'], channel['is_autoop'], channel['is_autovoice'],
                        channel['is_revenge'], channel['is_revengebots'],
                        channel['is_protectfriends'], channel['is_protectops'],
                        channel['is_dontkickops'], channel['is_inactive'],
                        channel['is_enforcebans'], channel['is_dynamicbans'],
                        channel['is_dynamicexempts'], channel['is_dynamicinvites'],
                        channel['is_pubcom'], channel['is_news'], channel['is_url'],
                        channel['is_stats'], channel['is_locked'], channel['lock_by'],
                        channel['lock_at'], channel['lock_reason'],
                        channel['is_topiclock'], channel['topiclock'],
                        channel['topiclock_by'], channel['topiclock_at'],
                        channel['topiclock_reason'], channel['is_limit'],
                        channel['limit_add'], channel['limit_rand'],
                        channel['limit_tolerance'], channel['limit_delta'],
                        channel['limit_at'], channel['comment'],
                        channel['created_at'], channel['updated_at'], from_bot
                    ))
                    log.info(f"Added channel {name} from {from_bot}")
            
            await db.commit()
        
        log.info(f"Merged {len(channels)} channels from {from_bot}")

    async def handle_share_user_access(self, data: str, from_bot: str):
        """Merge user_access with conflict resolution."""
        access_list = json.loads(data)
        
        async with aiosqlite.connect(self.db_path) as db:
            for access in access_list:
                handle = access['handle'].lower()
                channel = access['channel']
                
                # Check if exists
                cursor = await db.execute(
                    "SELECT updated_at FROM user_access WHERE handle = ? AND channel = ?",
                    (handle, channel)
                )
                existing = await cursor.fetchone()
                
                if existing:
                    # Update if remote is newer
                    if access['updated_at'] > existing[0]:
                        await db.execute("""
                            UPDATE user_access SET
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
                        log.debug(f"Updated user_access for {handle} on {channel}")
                else:
                    # Insert new access
                    await db.execute("""
                        INSERT INTO user_access (
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
                    log.info(f"Added user_access for {handle} on {channel}")
            
            await db.commit()
        
        log.info(f"Merged {len(access_list)} user_access from {from_bot}")

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