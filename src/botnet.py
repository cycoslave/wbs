# src/botnet.py
"""
Botnet manager for WBS.
"""

import os
import time
import asyncio
import json
import logging
import socket
import queue
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

import aiosqlite

log = logging.getLogger(__name__)


@dataclass
class BotLink:
    """Active bot link config."""
    name: str
    host: str
    port: int
    relay_port: Optional[int] = None
    flags: str = ''  # 's'=aggressive, 'p'=passive, 'h'=hub, 'l'=leaf
    is_hub: bool = False
    fingerprint: Optional[str] = None
    subnet_id: Optional[int] = None


class BotnetManager:
    """Manages botnet links. Runs in separate process."""

    def __init__(self, config, core_q, irc_q, botnet_q, party_q, db_path='wbs.db'):
        self.config = config
        self.core_q = core_q
        self.irc_q = irc_q
        self.botnet_q = botnet_q
        self.party_q = party_q
        self.db_path = db_path
        self.links: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.peers: Dict[str, BotLink] = {}
        self.partyline_channels: Dict[int, List[str]] = {0: []}
        self.is_hub: bool = False
        self.subnet_id: int = 1
        self.my_handle: str = config.get('bot', {}).get('nick', 'WBS')
        self.my_port: Optional[int] = None
        self.running: bool = True
        self.server = None
        self.loop = None
        self.inbufs: Dict[str, bytearray] = {}
        self.outbufs: Dict[str, bytearray] = {}

    async def start_link(self, link: BotLink) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open TCP connection to peer (outgoing)."""
        try:
            reader, writer = await asyncio.open_connection(link.host, link.port)
            
            # TLS upgrade if fingerprint present (future)
            if link.fingerprint:
                # TODO: SSL context + fingerprint validation
                pass
            
            await self.send_handshake(writer, link.name)
            return reader, writer
        except Exception as e:
            log.error(f"Failed to connect to {link.name} ({link.host}:{link.port}): {e}")
            raise

    async def send_handshake(self, writer: asyncio.StreamWriter, target: str) -> None:
        """Send eggdrop-style handshake."""
        msg = f"BOTLINK {self.my_handle} {target} 1 :WBS Botnet\n"
        writer.write(msg.encode())
        await writer.drain()

    async def handle_peer(self, name: str) -> None:
        """Establish/maintain connection to peer."""
        link = self.peers[name]
        try:
            reader, writer = await self.start_link(link)
            self.links[name] = (reader, writer)
            
            # Start read loop
            asyncio.create_task(self.read_loop(reader, writer, name))
            
            # Aggressive sharing if 's' flag
            if 's' in link.flags:
                asyncio.create_task(self.share_userfile(writer))
                asyncio.create_task(self.share_channels(writer))
                
        except Exception as e:
            log.error(f"Link to {name} failed: {e}")

    async def read_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, name: str) -> None:
        """Read/process messages from peer."""
        self.inbufs.setdefault(name, bytearray())
        try:
            while self.running:
                data = await reader.read(4096)
                if not data: break
                self.inbufs[name].extend(data)
                while b'\n' in self.inbufs[name]:
                    line, rest = self.inbufs[name].split(b'\n', 1)
                    line = line.decode('utf-8', errors='ignore').rstrip('\r')
                    if line: await self.process_line(line, name, writer)
                    self.inbufs[name] = rest
        except Exception as e:
            log.error(f"Read loop {name} error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            if name in self.links:
                del self.links[name]

    async def process_line(self, line: str, from_bot: str, writer: asyncio.StreamWriter) -> None:
        """Process partyline/command from peer."""
        line = line.strip()
        
        if line.startswith('.'):  # Partyline command
            cmd = self.parse_command(line)
            await self.route_command(cmd, from_bot)
        elif line.startswith('BOTLINK'):  # Handshake response
            parts = line.split()
            if len(parts) >= 3:
                remote_handle = parts[1]
                log.info(f"Handshake confirmed from {remote_handle}")
                # Update links dict key if needed
                if from_bot.startswith('incoming_'):
                    self.links[remote_handle] = self.links.pop(from_bot)
        elif line.startswith('SHAREUSERS:'):
            await self.handle_share_users(line, from_bot)
        elif line.startswith('SHARECHANS:'):
            await self.handle_share_channels(line, from_bot)
        elif line.startswith('CHAT:'):
            # Relay to partyline
            parts = line.split(':', 2)
            if len(parts) == 3:
                chan, msg = int(parts[1]), parts[2]
                await self.relay_to_partyline(msg, chan)
        elif line.startswith('CMD:'):
            # Command from another bot
            try:
                cmd = json.loads(line.split(':', 1)[1])
                await self.route_command(cmd, from_bot)
            except Exception as e:
                log.error(f"Failed to parse CMD: {e}")
        else:  # Regular chat
            chan = 0
            await self.broadcast_chat(f"<{from_bot}> {line}", chan, exclude=from_bot)

    async def relay_to_partyline(self, msg: str, chan: int) -> None:
        """Send message to partyline (via queue to party process)."""
        try:
            self.party_q.put_nowait({
                'type': 'botnet_chat',
                'channel': chan,
                'text': msg
            })
        except Exception as e:
            log.error(f"Failed to relay to partyline: {e}")

    def parse_command(self, line: str) -> Dict[str, Any]:
        """Parse .cmd [target=subnet] args."""
        parts = line[1:].split(maxsplit=1)
        cmd_name = parts[0]
        args = parts[1] if len(parts) > 1 else ''
        
        target = 'me'
        if 'target=' in args:
            prefix, rest = args.split('=', 1)
            target_parts = rest.split(maxsplit=1)
            target = target_parts[0]
            args = target_parts[1] if len(target_parts) > 1 else ''
        
        return {'cmd': cmd_name, 'args': args, 'target': target}

    async def route_command(self, cmd: Dict, from_bot: str) -> None:
        """Route command to self/subnet/botnet."""
        target = cmd.get('target', 'me')
        
        if target in ('me', self.my_handle):
            self.core_q.put_nowait({
                'type': 'COMMAND',
                'text': f"{cmd['cmd']} {cmd.get('args', '')}",
                'nick': from_bot,
                'source': 'botnet'
            })
        elif target == 'subnet':
            await self.broadcast_subnet(cmd)
        elif target == 'botnet':
            await self.broadcast(cmd)

    async def share_userfile(self, writer: asyncio.StreamWriter) -> None:
        """Share user database (aggressive mode)."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute("SELECT * FROM users")
                rows = await cursor.fetchall()
                users = [dict(row) for row in rows]
            
            data = json.dumps(users)
            msg = f"SHAREUSERS:{data}\n"
            writer.write(msg.encode())
            await writer.drain()
        except Exception as e:
            log.error(f"Share userfile failed: {e}")

    async def share_channels(self, writer: asyncio.StreamWriter) -> None:
        """Share channel configs/bans."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute("SELECT * FROM channels")
                rows = await cursor.fetchall()
                chans = [dict(row) for row in rows]
            
            data = json.dumps(chans)
            msg = f"SHARECHANS:{data}\n"
            writer.write(msg.encode())
            await writer.drain()
        except Exception as e:
            log.error(f"Share channels failed: {e}")

    async def handle_share_users(self, line: str, from_bot: str) -> None:
        """Receive/merge shared users."""
        try:
            data = json.loads(line.split(':', 1)[1])
            log.info(f"Received {len(data)} users from {from_bot}")
            # TODO: Merge with conflict resolution
        except Exception as e:
            log.error(f"Handle share users error: {e}")

    async def handle_share_channels(self, line: str, from_bot: str) -> None:
        """Receive/merge shared channels."""
        try:
            data = json.loads(line.split(':', 1)[1])
            log.info(f"Received {len(data)} channels from {from_bot}")
        except Exception as e:
            log.error(f"Handle share channels error: {e}")

    async def broadcast_chat(self, msg: str, chan: int, exclude: Optional[str] = None) -> None:
        """Broadcast chat to all connected peers."""
        line = f"CHAT:{chan}:{msg}\n"
        for name, (_, writer) in self.links.items():
            if exclude and name == exclude:
                continue
            try:
                writer.write(line.encode())
                await writer.drain()
            except Exception as e:
                log.error(f"Broadcast to {name} failed: {e}")

    async def broadcast(self, cmd: Dict) -> None:
        """Broadcast command to entire botnet."""
        msg = f"CMD:{json.dumps(cmd)}\n"
        tasks = []
        for _, writer in self.links.values():
            tasks.append(self._safe_write(writer, msg))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_subnet(self, cmd: Dict) -> None:
        """Broadcast to subnet peers only."""
        subnet_peers = {k: v for k, v in self.peers.items() 
                       if getattr(v, 'subnet_id', self.subnet_id) == self.subnet_id}
        msg = f"CMD:{json.dumps(cmd)}\n"
        tasks = []
        for name in subnet_peers:
            if name in self.links:
                _, writer = self.links[name]
                tasks.append(self._safe_write(writer, msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_write(self, writer: asyncio.StreamWriter, msg: str) -> None:
        """Safe write with error handling."""
        self.outbufs.setdefault(name, bytearray()).extend(msg.encode('utf-8'))
        while self.outbufs[name]:
            try:
                wrote = writer.write(self.outbufs[name])
                del self.outbufs[name][:wrote]
                await writer.drain()
            except Exception as e:
                log.error(f"Partial write to {name}: {e}")
                break

    async def handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming: botlink vs partyline user → core Partyline (picklable data only)."""
        peeraddr = writer.get_extra_info('peername')
        clientip, clientport = peeraddr
        log.info(f"Incoming connection from {clientip}:{clientport}")
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=30.0)
            line = data.decode('utf-8', errors='ignore').strip()
            if line.startswith('BOTLINK'):
                # Bot link handshake
                parts = line.split()
                if len(parts) >= 3:
                    remotehandle = parts[1]
                    log.info(f"Bot link established from {remotehandle}")
                    await self.send_handshake(writer, remotehandle)
                    self.links[remotehandle] = (reader, writer)
                    asyncio.create_task(self.read_loop(reader, writer, remotehandle))
            else:
                # Partyline user: forward PICKLABLE data to core Partyline
                tempname = f"user_{clientip}_{clientport}"
                log.info(f"Partyline connection: {tempname}")
                self.core_q.put_nowait({
                    'type': 'PARTYLINE_NEWUSER',
                    'handle': tempname,
                    'peer': peeraddr,  # (ip, port) tuple - picklable
                    'firstline': line
                })
                # Close in botnet process; core spawns new session
        except asyncio.TimeoutError:
            log.warning(f"Handshake timeout from {clientip}:{clientport}")
        except Exception as e:
            log.error(f"Incoming connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    def execute_command(self, cmd_data: dict):
        """Execute command from botnet_q (called by poller thread)."""
        if not self.loop:
            log.error("Event loop not available")
            return
        
        try:
            cmd_type = cmd_data.get('type')
            
            if cmd_type == 'chat':
                # Broadcast chat message
                asyncio.run_coroutine_threadsafe(
                    self.broadcast_chat(
                        f"<{cmd_data.get('user', 'core')}> {cmd_data['text']}",
                        cmd_data.get('channel', 0)
                    ),
                    self.loop
                )
            
            elif cmd_type == 'cmd':
                # Parse and route command
                parsed = self.parse_command(f".{cmd_data['cmd']}")
                asyncio.run_coroutine_threadsafe(
                    self.route_command(parsed, cmd_data.get('user', 'core')),
                    self.loop
                )
            
            elif cmd_type == 'link':
                # Connect to new bot
                link = BotLink(**cmd_data['link'])
                self.peers[link.name] = link
                asyncio.run_coroutine_threadsafe(
                    self.handle_peer(link.name),
                    self.loop
                )
            
            elif cmd_type == 'unlink':
                # Disconnect from bot
                name = cmd_data['name']
                if name in self.links:
                    _, writer = self.links[name]
                    writer.close()
                    del self.links[name]
                if name in self.peers:
                    del self.peers[name]
            
            else:
                log.error(f"Unknown command type: {cmd_type}")
        
        except Exception as e:
            log.error(f"Execute command failed: {e}")

    def stop(self) -> None:
        """Graceful shutdown."""
        self.running = False
        if self.server:
            self.server.close()
        for _, writer in self.links.values():
            writer.close()


async def start_server_tasks(manager: BotnetManager):
    """Start all async tasks for botnet."""
    tasks = []
    
    # Connect to configured peer bots
    for name in manager.peers:
        tasks.append(asyncio.create_task(manager.handle_peer(name)))
    
    # Wait for all tasks
    await asyncio.gather(*tasks, return_exceptions=True)


def start_botnet_process(config, core_q, irc_q, botnet_q, party_q, db_path='db/wbs.db'):
    """
    Entry point for botnet process - matches IRC pattern.
    """
    logger = logging.getLogger('botnet')
    
    manager = BotnetManager(config, core_q, irc_q, botnet_q, party_q, db_path)
    
    # Load peer bots from config
    for bot_config in config.get('botnet', {}).get('bots', []):
        link = BotLink(
            name=bot_config['name'],
            host=bot_config['host'],
            port=bot_config['port'],
            flags=bot_config.get('flags', ''),
            subnet_id=bot_config.get('subnet_id', 1)
        )
        manager.peers[link.name] = link
    
    def command_poller():
        """Daemon thread: poll botnet_q for commands."""
        throttle_interval = 0.1  # 100ms between commands
        last_cmd_time = 0
        
        while manager.running:
            try:
                # Throttle check
                elapsed = time.time() - last_cmd_time
                if elapsed < throttle_interval:
                    time.sleep(throttle_interval - elapsed)
                
                # Non-blocking get from botnet_q
                cmd_data = botnet_q.get_nowait()
                logger.debug(f"Executing botnet command: {cmd_data}")
                
                manager.execute_command(cmd_data)
                last_cmd_time = time.time()
            
            except queue.Empty:
                time.sleep(0.1)  # Reduce CPU usage
            
            except Exception as e:
                logger.error(f"Botnet command poller error: {e}")
                time.sleep(0.1)
    
    # Start command poller thread (daemon=True)
    poller = threading.Thread(target=command_poller, daemon=True)
    poller.start()
    
    logger.info(f"Botnet process started (pid={os.getpid()})")
    
    # Get event loop and store in manager
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    manager.loop = loop
    
    # Start async server (blocking)
    try:
        loop.run_until_complete(start_server_tasks(manager))
    except KeyboardInterrupt:
        logger.info("Botnet process interrupted")
    finally:
        manager.stop()
        loop.close()


def botnet_process_launcher(config_path, core_q, irc_q, botnet_q, party_q, db_path='db/wbs.db'):
    """
    Launcher for multiprocessing.Process - matches irc_process_launcher.
    """
    import json
    
    # Load config from file path
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Start the actual process (blocking)
    start_botnet_process(config, core_q, irc_q, botnet_q, party_q, db_path)
