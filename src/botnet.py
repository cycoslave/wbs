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
from typing import Dict, Optional, Any, Literal, Callable
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

        log.debug(f"Processing from {from_bot}: {line[:100]}")
        
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
        
        #elif line.startswith('SHAREUSERS:'):
        #    await self.handle_share_users(line[11:], from_bot)
        
        #elif line.startswith('SHARECHANS:'):
        #    await self.handle_share_channels(line[11:], from_bot)
        
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

    ## To be reviewed.
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