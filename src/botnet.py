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
from typing import Dict, Optional, Any
from dataclasses import dataclass

from . import __version__

log = logging.getLogger(__name__)

@dataclass
class BotLink:
    """Bot peer configuration."""
    name: str
    host: str
    port: int
    flags: str = ''  # 's'=aggressive share, 'p'=passive, 'h'=hub, 'l'=leaf
    subnet_id: Optional[int] = None

class BotnetManager:
    """Manages botnet peer connections and routing."""
    
    def __init__(self, config, core_q, irc_q, botnet_q, party_q, db_path='db/wbs.db'):
        self.config = config
        self.core_q = core_q      # Events to core
        self.irc_q = irc_q        # Commands to IRC
        self.botnet_q = botnet_q  # Commands from core
        self.party_q = party_q
        self.db_path = db_path
        
        # Peer connections: {name: (reader, writer)}
        self.links: Dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.peers: Dict[str, BotLink] = {}  # Config for known peers
        
        # Settings
        self.subnet_id = config.get('botnet', {}).get('subnet_id', 1)
        self.my_handle = config.get('bot', {}).get('nick', 'WBS')
        self.running = True
        self.loop = None
    
    # ===== Connection Management =====
    
    async def connect_peer(self, link: BotLink):
        """Establish outgoing connection to peer."""
        try:
            reader, writer = await asyncio.open_connection(link.host, link.port)
            
            # Send BOTLINK handshake
            handshake = f"BOTLINK {self.my_handle} {link.name} 1 :WBS {__version__}\n"
            writer.write(handshake.encode())
            await writer.drain()
            
            self.links[link.name] = (reader, writer)
            log.info(f"Connected to peer: {link.name} ({link.host}:{link.port})")
            
            # Start read loop
            asyncio.create_task(self.read_peer(link.name, reader, writer))
            
            # Aggressive sharing if 's' flag
            if 's' in link.flags:
                await self.share_data(writer)
                
        except Exception as e:
            log.error(f"Failed to connect to {link.name}: {e}")
    
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
            if name in self.links:
                del self.links[name]
            log.info(f"Peer {name} disconnected")
    
    async def handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming peer connection."""
        peer = writer.get_extra_info('peername')
        log.info(f"Incoming botnet connection from {peer}")
        
        try:
            # Read handshake
            data = await asyncio.wait_for(reader.readline(), timeout=30.0)
            line = data.decode('utf-8', errors='ignore').strip()
            
            if line.startswith('BOTLINK'):
                parts = line.split()
                if len(parts) >= 3:
                    peer_name = parts[1]
                    log.info(f"Peer identified: {peer_name}")
                    
                    # Send handshake response
                    response = f"BOTLINK {self.my_handle} {peer_name} 1 :WBS 6.0\n"
                    writer.write(response.encode())
                    await writer.drain()
                    
                    self.links[peer_name] = (reader, writer)
                    asyncio.create_task(self.read_peer(peer_name, reader, writer))
                    return
            
            # Not a bot link - close
            log.warning(f"Invalid handshake from {peer}: {line}")
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            log.warning(f"Handshake timeout from {peer}")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            log.error(f"Incoming connection error: {e}")
    
    # ===== Message Processing =====
    
    async def process_peer_line(self, line: str, from_bot: str, writer: asyncio.StreamWriter):
        """Process message from peer."""
        
        if line.startswith('.'):
            # Partyline command
            cmd = self.parse_command(line)
            await self.route_command(cmd, from_bot)
        
        elif line.startswith('CMD:'):
            # JSON command
            try:
                cmd = json.loads(line[4:])
                await self.route_command(cmd, from_bot)
            except json.JSONDecodeError as e:
                log.error(f"Invalid CMD from {from_bot}: {e}")
        
        elif line.startswith('CHAT:'):
            # Chat message
            parts = line.split(':', 2)
            if len(parts) == 3:
                chan = int(parts[1])
                msg = parts[2]
                self.party_q.put_nowait({
                    'type': 'botnet_chat',
                    'channel': chan,
                    'text': f"<{from_bot}> {msg}"
                })
        
        elif line.startswith('SHAREUSERS:'):
            await self.handle_share_users(line[11:], from_bot)
        
        elif line.startswith('SHARECHANS:'):
            await self.handle_share_channels(line[11:], from_bot)
        
        elif line.startswith('BOTLINK'):
            # Handshake confirmation
            log.debug(f"Handshake confirmed: {from_bot}")
        
        else:
            # Regular chat
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
    
    # ===== Broadcasting =====
    
    async def broadcast_chat(self, msg: str, chan: int, exclude: Optional[str] = None):
        """Broadcast chat to all peers."""
        line = f"CHAT:{chan}:{msg}\n"
        tasks = []
        for name, (_, writer) in self.links.items():
            if name != exclude:
                tasks.append(self._safe_send(writer, line))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def broadcast_all(self, cmd: Dict):
        """Broadcast command to all peers."""
        msg = f"CMD:{json.dumps(cmd)}\n"
        tasks = [self._safe_send(w, msg) for _, w in self.links.values()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def broadcast_subnet(self, cmd: Dict):
        """Broadcast to subnet peers only."""
        msg = f"CMD:{json.dumps(cmd)}\n"
        tasks = []
        for name, (_, writer) in self.links.items():
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
    
    # ===== Data Sharing =====
    
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
    
    # ===== Command Execution (from core) =====
    
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
                link = BotLink(**cmd_data['link'])
                self.peers[link.name] = link
                asyncio.run_coroutine_threadsafe(
                    self.connect_peer(link),
                    self.loop
                )
            
            elif cmd_type == 'unlink':
                name = cmd_data['name']
                if name in self.links:
                    _, writer = self.links[name]
                    writer.close()
                    del self.links[name]
                if name in self.peers:
                    del self.peers[name]
                log.info(f"Unlinked from {name}")
        
        except Exception as e:
            log.error(f"Execute command failed: {e}")
    
    def stop(self):
        """Shutdown."""
        self.running = False
        for _, writer in self.links.values():
            writer.close()

# ===== Process Entry Points =====

async def start_botnet_tasks(manager: BotnetManager):
    """Start all botnet tasks."""
    tasks = []
    
    # Start listener
    relay_port = manager.config.get('botnet', {}).get('relay_port')
    if relay_port:
        server = await asyncio.start_server(
            manager.handle_incoming,
            '0.0.0.0',
            relay_port
        )
        log.info(f"Botnet listening on port {relay_port}")
        tasks.append(asyncio.create_task(server.serve_forever()))
    
    # Connect to configured peers
    for link in manager.peers.values():
        tasks.append(asyncio.create_task(manager.connect_peer(link)))
    
    # Wait forever
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

def start_botnet_process(config, core_q, irc_q, botnet_q, party_q, db_path='db/wbs.db'):
    """Entry point for botnet process."""
    logger = logging.getLogger('botnet')
    
    manager = BotnetManager(config, core_q, irc_q, botnet_q, party_q, db_path)
    
    # Load peer bots from config
    for bot_cfg in config.get('botnet', {}).get('bots', []):
        link = BotLink(
            name=bot_cfg['name'],
            host=bot_cfg['host'],
            port=bot_cfg['port'],
            flags=bot_cfg.get('flags', ''),
            subnet_id=bot_cfg.get('subnet_id', 1)
        )
        manager.peers[link.name] = link
    
    def command_poller():
        """Poll botnet_q for commands."""
        throttle_interval = 0.1
        last_cmd_time = 0
        
        while manager.running:
            try:
                elapsed = time.time() - last_cmd_time
                if elapsed < throttle_interval:
                    time.sleep(throttle_interval - elapsed)
                
                cmd_data = botnet_q.get_nowait()
                logger.debug(f"Executing: {cmd_data}")
                
                manager.execute_command(cmd_data)
                last_cmd_time = time.time()
            
            except queue.Empty:
                time.sleep(0.1)
            
            except Exception as e:
                logger.error(f"Poller error: {e}")
                time.sleep(0.1)
    
    # Start poller thread
    poller = threading.Thread(target=command_poller, daemon=True)
    poller.start()
    
    logger.info(f"Botnet process started (pid={os.getpid()})")
    
    # Run async tasks
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    manager.loop = loop
    
    try:
        loop.run_until_complete(start_botnet_tasks(manager))
    except KeyboardInterrupt:
        logger.info("Botnet interrupted")
    finally:
        manager.stop()
        loop.close()

def botnet_process_launcher(config_path, core_q, irc_q, botnet_q, party_q, db_path='db/wbs.db'):
    """Launcher for multiprocessing.Process."""
    import json
    
    with open(config_path) as f:
        config = json.load(f)
    
    start_botnet_process(config, core_q, irc_q, botnet_q, party_q, db_path)
