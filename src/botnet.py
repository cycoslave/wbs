# src/botnet.py
"""
Botnet peer manager for WBS.
Handles bot-to-bot linking, command routing, and data sharing.
"""

import os
import time
import asyncio
import json
import logging
import queue
import threading
import aiosqlite
import secrets
import hashlib
from typing import Dict, Optional, Any, Literal
from dataclasses import dataclass

from . import __version__
from .bot import BotManager

log = logging.getLogger(__name__)

@dataclass
class BotLink:
    """Bot peer configuration."""
    name: str
    host: str
    port: int
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    subnet_id: Optional[int] = None
    session_id: Optional[int] = None
    password: Optional[str] = None
    temp_partial: Optional[str] = None  # For key exchange
    share_level: str = 'subnet'
    role: Literal['hub', 'backup', 'leaf', 'none'] = 'none'
    authed: bool = False
    connected: bool = False

class BotnetManager:
    """Manages botnet peer connections and routing."""
    
    def __init__(self, core):
        self.core = core
        self.db_path = self.core.db_path
        self.config = self.core.config
        self.irc_q = self.core.irc_q
        self.bot = BotManager(self.db_path)
        self.peers: Dict[BotLink] = {}
        
        # Settings
        self.subnet_id = self.config.get('botnet', {}).get('subnet_id', 1)
        self.my_handle = self.config.get('bot', {}).get('nick', 'WBS')
        self.running = True
        self.loop = None
        
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
                port=bot.port
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
            
        except Exception as e:
            log.error(f"Failed to connect to {handle}: {e}")

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
                if len(parts) > 5:
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
            await self._safe_send(writer, f"LINKREADY {self.my_handle} WBS {__version__}\n")
            return
        
        elif cmd == "LINKREADY":
            # Link established
            self.core.partyline.broadcast(f"*** {from_bot} linked to botnet", True)
            link.authed = True
            #log.info(f"Link established with {from_bot}")
            return
        
        # BLOCK UNAUTHED
        if not link.authed:
            log.warning(f"Unauthed from {from_bot}: {line[:50]}")
            return
        
        elif cmd == "CHAT":
            # Format: CHAT <from_bot> <message>
            # parts[0] = "CHAT", parts[1] = from_bot, parts[2:] = message
            from_bot_name = parts[1]
            nick = parts[2]
            message = ' '.join(parts[3:])
            self.core.partyline.broadcast(f"<{from_bot_name}@{nick.rstrip(':')}> {message}", True)

        elif line.startswith('CMD:'):
            # JSON command (existing logic)
            try:
                cmd = json.loads(line[4:])
                await self.route_command(cmd, from_bot)
            except json.JSONDecodeError as e:
                log.error(f"Invalid CMD from {from_bot}: {e}")
        
        elif line.startswith('RESPONSE:'):
            # Command response from another bot
            msg = line[9:]
            #self.party_q.put_nowait({
            #    'type': 'botnet_response',
            #    'from': from_bot,
            #    'text': msg
            #})
        
        elif line.startswith('SHAREUSERS:'):
            await self.handle_share_users(line[11:], from_bot)
        
        elif line.startswith('SHARECHANS:'):
            await self.handle_share_channels(line[11:], from_bot)
        
        else:
            log.error(f"Invalid command {cmd} from {from_bot}")
    
    def parse_command(self, line: str) -> Dict[str, Any]:
        """Parse .command [target=X] args"""
        parts = line[1:].split(maxsplit=1)
        cmd_name = parts[0]
        args = parts[1] if len(parts) > 1 else ''
        
        target = 'me'
        if 'target=' in args:
            idx = args.index('target=') + 7
            rest = args[idx:]
            if ' ' in rest:
                target, args = rest.split(maxsplit=1)
            else:
                target, args = rest, ''
        
        return {'cmd': cmd_name, 'args': args, 'target': target}
    
    async def route_command(self, cmd: Dict, from_bot: str):
        """Route command to appropriate destination."""
        target = cmd.get('target', 'me')
        
        if target in ('me', self.my_handle):
            # Local execution
            #self.core_q.put_nowait({
            #    'type': 'COMMAND',
            #    'text': f"{cmd['cmd']} {cmd.get('args', '')}",
            #    'nick': from_bot,
            #    'source': 'botnet'
            #})
            pass
        
        elif target == 'subnet':
            await self.broadcast_subnet(cmd)
        
        elif target == 'botnet':
            await self.broadcast_all(cmd)
        
    async def broadcast_chat(self, from_bot: str, msg: str, exclude: Optional[str] = None):
        """Broadcast chat to all peers."""
        line = f"CHAT {from_bot} {msg}\n"
        tasks = []
        for name,link in self.peers.items():
            if link.name != exclude and link.authed and link.connected and link.writer:
                tasks.append(self._safe_send(link.writer, line))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def broadcast_all(self, cmd: Dict):
        """Broadcast command to all peers."""
        msg = f"CMD:{json.dumps(cmd)}\n"
        tasks = [self._safe_send(w, msg) for _, w in self.peers.values()]
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
        
    async def share_data(self, writer: asyncio.StreamWriter):
        """Share users and channels (aggressive mode)."""
        await self.share_users(writer)
        await self.share_channels(writer)
    
    async def share_users(self, writer: asyncio.StreamWriter):
        """Share user database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute("SELECT * FROM users")
                rows = await cursor.fetchall()
                users = [dict(row) for row in rows]
            
            msg = f"SHAREUSERS:{json.dumps(users)}\n"
            writer.write(msg.encode())
            await writer.drain()
            log.info(f"Shared {len(users)} users")
        except Exception as e:
            log.error(f"Share users failed: {e}")
    
    async def share_channels(self, writer: asyncio.StreamWriter):
        """Share channel configs."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute("SELECT * FROM channels")
                rows = await cursor.fetchall()
                chans = [dict(row) for row in rows]
            
            msg = f"SHARECHANS:{json.dumps(chans)}\n"
            writer.write(msg.encode())
            await writer.drain()
            log.info(f"Shared {len(chans)} channels")
        except Exception as e:
            log.error(f"Share channels failed: {e}")
    
    async def handle_share_users(self, data: str, from_bot: str):
        """Receive shared users."""
        try:
            users = json.loads(data)
            log.info(f"Received {len(users)} users from {from_bot}")
            # TODO: Merge with conflict resolution
        except Exception as e:
            log.error(f"Handle share users error: {e}")
    
    async def handle_share_channels(self, data: str, from_bot: str):
        """Receive shared channels."""
        try:
            chans = json.loads(data)
            log.info(f"Received {len(chans)} channels from {from_bot}")
            # TODO: Merge with conflict resolution
        except Exception as e:
            log.error(f"Handle share channels error: {e}")
    
    def execute_command(self, cmd_data: dict):
        """Execute command (called by poller thread)."""
        if not self.loop:
            return
        
        try:
            cmd_type = cmd_data.get('type')
            
            if cmd_type == 'chat':
                asyncio.run_coroutine_threadsafe(
                    self.broadcast_chat(
                        f"<{cmd_data.get('user', 'core')}> {cmd_data['text']}",
                        cmd_data.get('channel', 0)
                    ),
                    self.loop
                )
            
            elif cmd_type == 'cmd':
                parsed = self.parse_command(f".{cmd_data['cmd']}")
                asyncio.run_coroutine_threadsafe(
                    self.route_command(parsed, 'core'),
                    self.loop
                )
            
            elif cmd_type == 'link':
                botname = cmd_data['botname']
                log.info(f"link request to {botname}")
                asyncio.run_coroutine_threadsafe(
                    self.connect_peer(botname),
                    self.loop
                )
            
            elif cmd_type == 'unlink':
                name = cmd_data['name']
                if name in self.peers:
                    self.peers[name].writer.close()
                    del self.peers[name]
                log.info(f"Unlinked from {name}")

            elif cmd_type == 'botlink':                
                parts = cmd_data['line'].split()
                from_bot = parts[1]
                self.process_peer_line(cmd_data['line'], from_bot)

        except Exception as e:
            log.error(f"Execute command failed: {e}")
    
    def stop(self):
        """Shutdown."""
        self.running = False
        for _, writer in self.peers.values():
            writer.close()
