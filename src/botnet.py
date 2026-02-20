# src/botnet.py
"""
Botnet manager for WBS.
Handles hub/leaf linking, partyline relay, command routing (bot/subnet/botnet),
user/channel sharing. Multiprocessing IPC with core/IRC via queues.
Eggdrop-compatible: aggressive/passive sharing (s/p flags), partyline (./, /, '), TLS.
"""

import asyncio
import json
import logging
import multiprocessing as mp
import ssl
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

import aiosqlite

from .db import get_db, BotLinkRecord

log = logging.getLogger(__name__)


@dataclass
class BotLink:
    """Active bot link config (normalized from BotLinkRecord)."""
    name: str              # linked_bot_handle
    host: str              # Resolved from bots table
    port: int              # From bots table
    relay_port: Optional[int] = None
    flags: str = ''        # Eggdrop-style: 's'=aggressive, 'p'=passive, 'h'=hub, 'l'=leaf
    is_hub: bool = False
    fingerprint: Optional[str] = None  # TLS cert fingerprint (future)
    subnet_id: Optional[int] = None


class BotnetManager:
    """Manages botnet links in async event loop. Runs in separate process."""

    def __init__(self, config, core_q, irc_q, botnet_q, party_q):
        self.config = config
        self.core_q = core_q
        self.irc_q = irc_q
        self.botnet_q = botnet_q
        self.party_q = party_q
        self.links: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.peers: Dict[str, BotLink] = {}
        self.partyline_channels: Dict[int, List[str]] = {0: []}  # 0=global
        self.is_hub: bool = False
        self.subnet_id: int = 1
        self.my_handle: str = "WBS"
        self.my_port: Optional[int] = None
        self.running: bool = True

    async def load_config(self) -> None:
        """Load bot config, links, subnet from DB (corrected schema)."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            # Get self bot record (assumes handle is set via config)
            row = await db.execute_fetchone(
                "SELECT handle, subnet_id, is_hub FROM bots WHERE handle = ? LIMIT 1",
                (self.my_handle,)
            )
            if row:
                self.my_handle = row['handle']
                self.subnet_id = row['subnet_id'] or 1
                self.is_hub = bool(row['is_hub'])
            
            # Load bot links (relationships between bots)
            link_rows = await db.execute_fetchall(
                """SELECT bl.linked_bot_handle AS name, bl.flags, bl.link_type,
                          b.address AS host, b.port
                   FROM botlinks bl
                   JOIN bots b ON b.handle = bl.linked_bot_handle
                   WHERE bl.bot_handle = ?""",
                (self.my_handle,)
            )
            
            for link in link_rows:
                self.peers[link['name']] = BotLink(
                    name=link['name'],
                    host=link['host'] or '127.0.0.1',
                    port=link['port'] or 3333,
                    flags=link['flags'] or '',
                    is_hub='h' in (link['flags'] or '')
                )
        
        log.info(f"Botnet loaded: hub={self.is_hub}, subnet={self.subnet_id}, {len(self.peers)} peers")

    async def start_link(self, link: BotLink) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open TCP connection to peer (TLS placeholder)."""
        try:
            reader, writer = await asyncio.open_connection(link.host, link.port)
            
            # TLS upgrade if fingerprint present (future implementation)
            if link.fingerprint:
                # TODO: Wrap with SSL context + fingerprint validation
                pass
            
            await self.send_handshake(writer, link.name)
            return reader, writer
        except Exception as e:
            log.error(f"Failed to connect to {link.name} ({link.host}:{link.port}): {e}")
            raise

    async def send_handshake(self, writer: asyncio.StreamWriter, target: str) -> None:
        """Send Eggdrop-style handshake."""
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
        try:
            while self.running:
                data = await reader.read(4096)
                if not data:
                    break
                    
                lines = data.decode('utf-8', errors='ignore').splitlines()
                for line in lines:
                    if line.strip():
                        await self.process_line(line, name, writer)
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
        elif line.startswith(','):  # Bot owners channel (reserved)
            pass
        elif line.startswith("'"):  # Local-only (don't relay)
            pass
        elif line.startswith('SHAREUSERS:'):
            await self.handle_share_users(line, from_bot)
        elif line.startswith('SHARECHANS:'):
            await self.handle_share_channels(line, from_bot)
        else:  # Regular chat
            chan = 0  # Default global
            await self.broadcast_chat(f"<{from_bot}> {line}", chan, exclude=from_bot)
            # Also notify core for console display
            self.queue_to_core.put({
                'type': 'chat',
                'channel': chan,
                'user': from_bot,
                'text': line
            })

    def parse_command(self, line: str) -> Dict[str, Any]:
        """Parse .cmd [target=subnet] args."""
        # Format: .cmdname target=subnet arg1 arg2
        parts = line[1:].split(maxsplit=1)
        cmd_name = parts[0]
        args = parts[1] if len(parts) > 1 else ''
        
        # Check for target= prefix
        target = 'me'
        if '=' in args:
            prefix, rest = args.split('=', 1)
            if prefix.lower() == 'target':
                target_parts = rest.split(maxsplit=1)
                target = target_parts[0]
                args = target_parts[1] if len(target_parts) > 1 else ''
        
        return {'cmd': cmd_name, 'args': args, 'target': target}

    async def route_command(self, cmd: Dict, from_bot: str) -> None:
        """Route command to self/subnet/botnet."""
        target = cmd.get('target', 'me')
        
        if target in ('me', self.my_handle):
            # Execute locally - forward to core
            self.queue_to_core.put({
                'type': 'COMMAND',
                'text': cmd['cmd'] + ' ' + cmd.get('args', ''),
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
                rows = await db.execute_fetchall("SELECT * FROM users")
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
                rows = await db.execute_fetchall("SELECT * FROM channels")
                chans = [dict(row) for row in rows]
            
            data = json.dumps(chans)
            msg = f"SHARECHANS:{data}\n"
            writer.write(msg.encode())
            await writer.drain()
        except Exception as e:
            log.error(f"Share channels failed: {e}")

    async def handle_share_users(self, line: str, from_bot: str) -> None:
        """Receive/merge shared users (passive mode handles this)."""
        try:
            data = json.loads(line.split(':', 1)[1])
            # TODO: Merge logic with conflict resolution
            log.info(f"Received {len(data)} users from {from_bot}")
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
        try:
            writer.write(msg.encode())
            await writer.drain()
        except Exception as e:
            log.error(f"Write error: {e}")

    async def handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming connection (hub mode)."""
        peer_addr = writer.get_extra_info('peername')
        log.info(f"Incoming botnet link from {peer_addr}")
        
        # TODO: Read handshake, verify, create dynamic link
        temp_name = f"incoming_{peer_addr[0]}"
        asyncio.create_task(self.read_loop(reader, writer, temp_name))

    async def listen(self) -> None:
        """Listen for incoming bot connections."""
        if not self.my_port:
            log.warning("No listen port configured, hub mode disabled")
            return
        
        try:
            server = await asyncio.start_server(
                self.handle_incoming, 
                '0.0.0.0', 
                self.my_port
            )
            log.info(f"Botnet listening on port {self.my_port}")
            async with server:
                await server.serve_forever()
        except Exception as e:
            log.error(f"Listen failed: {e}")

    async def poll_core_queue(self) -> None:
        """Poll queue from core for partyline relays."""
        while self.running:
            try:
                msg = self.queue_from_core.get_nowait()
                
                if msg.get('type') == 'chat':
                    await self.broadcast_chat(
                        f"<{msg['user']}> {msg['text']}",
                        msg.get('channel', 0)
                    )
                elif msg.get('type') == 'cmd':
                    parsed = self.parse_command(f".{msg['cmd']}")
                    await self.route_command(parsed, msg.get('user', 'core'))
                    
            except Exception:
                pass
            await asyncio.sleep(0.05)

    async def run(self) -> None:
        """Main botnet event loop."""
        await self.load_config()
        
        tasks = []
        
        # Connect to configured peers
        for name in self.peers:
            tasks.append(self.handle_peer(name))
        
        # Listen if hub or port configured
        if self.is_hub or self.my_port:
            tasks.append(self.listen())
        
        # Queue poller
        tasks.append(self.poll_core_queue())
        
        await asyncio.gather(*tasks, return_exceptions=True)

    def stop(self) -> None:
        """Graceful shutdown."""
        self.running = False
        for _, writer in self.links.values():
            writer.close()


# Process entrypoint
def botnet_process(config, core_q, irc_q, botnet_q, party_q):
    """Run BotnetManager in dedicated process."""
    logging.basicConfig(level=logging.INFO)
    manager = BotnetManager(config, core_q, irc_q, botnet_q, party_q)
    try:
        asyncio.run(manager.run())
    except KeyboardInterrupt:
        log.info("Botnet process interrupted")
    finally:
        manager.stop()

def botnet_target(config_path, core_q, irc_q, botnet_q, party_q):
    """Stub - replace with real botnet."""
    import time, asyncio
    print("Botnet process starting (stub)")
    while True:
        time.sleep(1)