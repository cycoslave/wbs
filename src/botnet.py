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
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    subnet_id: Optional[int] = None
    password: Optional[str] = None
    share_level: str = 'subnet'
    role: Literal['hub', 'backup', 'leaf', 'none'] = 'none'
    authed: bool = False
    connected: bool = False


class BotnetManager:
    """Manages botnet peer connections and routing."""
    
    def __init__(self, config, core_q, irc_q, botnet_q):
        self.config = config
        self.db_path = config['db']['path']
        self.core_q = core_q      # Events to core
        self.irc_q = irc_q        #        to IRC
        self.botnet_q = botnet_q  #        to botnet
        self.bot = BotManager(self.db_path)
        
        # Peer connections: {name: (reader, writer)}
        self.peers: Dict[BotLink] = {}
        
        # Settings
        self.subnet_id = config.get('botnet', {}).get('subnet_id', 1)
        self.my_handle = config.get('bot', {}).get('nick', 'WBS')
        self.running = True
        self.loop = None
        
    async def connect_peer(self, handle: str):
        """Establish outgoing connection to peer."""
        try:
            bot = await self.bot.get(handle)

            host = bot.address
            port = bot.port
            if not host or not port:
                raise ValueError(f"Bot {handle} missing address/port")

            reader, writer = await asyncio.open_connection(host, port)
            handshake = f"BOTLINK {self.my_handle} {handle} 1 :WBS {__version__}\n"
            writer.write(handshake.encode())
            await writer.drain()

            link = BotLink(name=handle, host=host, port=port, reader=reader, writer=writer)
            self.peers[handle] = link
            log.info(f"Connected to peer: {handle} ({host}:{port})")

            asyncio.create_task(self.read_peer(handle, reader, writer))

        except Exception as e:
            log.error(f"Failed to connect to {handle}: {e}")
    
    async def read_peer(self, name: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Read and process messages from peer."""
        buffer = bytearray()
        try:
            while self.running:
                data = await reader.read(4096)
                if not data:
                    break
                
                buffer.extend(data)
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    if line_str:
                        await self.process_peer_line(line_str, name, writer)
                        
        except Exception as e:
            log.error(f"Peer {name} read error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            if name in self.peers:
                del self.peers[name]
            log.info(f"Peer {name} disconnected")
        
    async def process_peer_line(self, line: str, from_bot: str, writer: asyncio.StreamWriter):
        """Process message from peer."""
        
        if from_bot not in self.peers:
            log.error(f"Unknown peer {from_bot}")
            return
        
        link: BotLink = self.peers[from_bot]
        
        parts = line.split()
        cmd = parts[0].upper()
        
        if cmd == 'BOTLINK':
            remote = parts[1].lower()
            local = parts[2].lower()
            if local != self.my_handle.lower() or remote != from_bot:
                log.error(f"Botlink mismatch from {from_bot}: {line}")
                log.error(f"local: {local}/{self.my_handle.lower()}  remote: {remote}/{from_bot}")
                writer.close()
                return
            
            if link.password is None:
                password = secrets.token_hex(16)
                link.password = password
                log.info(f"Generated pw for {from_bot}")
            
            chal_hash = hashlib.sha256(f"{self.my_handle}:{link.password}:{remote}".encode()).hexdigest()
            await self._safe_send(writer, f"LINKREPLY {chal_hash}\n")
            return
        
        elif cmd == 'LINKREPLY':
            expected_hash = hashlib.sha256(f"{from_bot}:{link.password}:{self.my_handle}".encode()).hexdigest()
            if len(parts) < 2 or parts[1] != expected_hash:
                log.error(f"Auth failed from {from_bot}")
                writer.close()
                return
            
            link.authed = True
            log.info(f"Auth success: {from_bot}")
            await self._safe_send(writer, f"LINK {self.my_handle} :WBS {__version__}\n")
            return
        
        # BLOCK UNAUTHED
        if not link.authed:
            log.warning(f"Unauthed from {from_bot}: {line[:50]}")
            return
        
        if line.startswith('.'):
            # Bot command - route to botcmds
            cmd_parts = line[1:].split(maxsplit=1)
            cmd_name = cmd_parts[0].lower()
            args = cmd_parts[1] if len(cmd_parts) > 1 else ''
            
            from .botcmds import BOTCMDS
            
            if cmd_name in BOTCMDS:
                async def respond(msg: str):
                    """Send response back to requesting bot"""
                    await self._safe_send(writer, f"RESPONSE:{msg}\n")
                
                try:
                    await BOTCMDS[cmd_name](self, from_bot, args, respond)
                except Exception as e:
                    log.error(f"Bot command '{cmd_name}' error: {e}")
                    await respond(f"Error executing .{cmd_name}")
            else:
                # Unknown command - maybe forward to core
                log.warning(f"Unknown bot command from {from_bot}: {line}")
                await respond(f"Unknown command: {cmd_name}")
        
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
        
        elif line.startswith('CHAT:'):
            # Chat message (existing logic)
            parts = line.split(':', 2)
            if len(parts) == 3:
                chan = int(parts[1])
                msg = parts[2]
                #self.party_q.put_nowait({
                #    'type': 'botnet_chat',
                #    'channel': chan,
                #    'text': f"<{from_bot}> {msg}"
                #})
        
        elif line.startswith('SHAREUSERS:'):
            await self.handle_share_users(line[11:], from_bot)
        
        elif line.startswith('SHARECHANS:'):
            await self.handle_share_channels(line[11:], from_bot)
        
        else:
            # Regular chat - broadcast
            await self.broadcast_chat(f"<{from_bot}> {line}", 0, exclude=from_bot)
    
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
            self.core_q.put_nowait({
                'type': 'COMMAND',
                'text': f"{cmd['cmd']} {cmd.get('args', '')}",
                'nick': from_bot,
                'source': 'botnet'
            })
        
        elif target == 'subnet':
            await self.broadcast_subnet(cmd)
        
        elif target == 'botnet':
            await self.broadcast_all(cmd)
        
    async def broadcast_chat(self, msg: str, chan: int, exclude: Optional[str] = None):
        """Broadcast chat to all peers."""
        line = f"CHAT:{chan}:{msg}\n"
        tasks = []
        for name, (_, writer) in self.peers.items():
            if name != exclude:
                tasks.append(self._safe_send(writer, line))
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
        """Execute command from botnet_q (called by poller thread)."""
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
        
        except Exception as e:
            log.error(f"Execute command failed: {e}")
    
    def stop(self):
        """Shutdown."""
        self.running = False
        for _, writer in self.peers.values():
            writer.close()

def start_botnet_process(config, core_q, irc_q, botnet_q):
    manager = BotnetManager(config, core_q, irc_q, botnet_q)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    manager.loop = loop
    
    def command_poller():
        while manager.running:
            try:
                cmd_data = botnet_q.get_nowait()
                log.info(f"BOTNET RX: {cmd_data}")
                manager.execute_command(cmd_data)
            except queue.Empty:
                time.sleep(0.01)
            except Exception as e:
                log.error(f"Botnet poller: {e}")
                time.sleep(0.1)
    
    poller = threading.Thread(target=command_poller, daemon=True)
    poller.start()
    log.info(f"Botnet started (pid={os.getpid()})")
    
    try:
        loop.run_forever()  # Keep loop alive for runcoroutine_threadsafe
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()

def botnet_process_launcher(config_path, core_q, irc_q, botnet_q):
    """Launcher for Botnet multiprocessing.Process."""
    config = json.load(open(config_path))
    start_botnet_process(config, core_q, irc_q, botnet_q)