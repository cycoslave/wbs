"""
pydrop/botnet.py - Botnet manager for pydrop IRC bot.
Handles hub/leaf linking, partyline communication, command routing (bot/subnet/botnet),
user/channel sharing. Supports multiprocessing IPC with core/IRC processes.
Mimics Eggdrop: aggressive/passive sharing via flags (s/p), partyline cmds (./,/,'), TLS [web:1][web:2].
"""

import asyncio
import json
import logging
import multiprocessing as mp
import ssl
from typing import Dict, List, Optional, Tuple, AsyncGenerator

import aiosqlite
from dataclasses import dataclass, asdict

from .db import get_db, BotRecord, BotLinkRecord  # Assume BotLinkRecord dataclass exists in db.py
#from .core import BotEvent
from .user import sync_user
from .channel import sync_channel

log = logging.getLogger(__name__)


@dataclass
class BotLink:
    """Active bot link config."""
    name: str
    host: str
    port: int
    relay_port: Optional[int]
    flags: str  # Eggdrop-style: 'shpl' etc. [web:1]
    is_hub: bool = False
    fingerprint: Optional[str] = None  # TLS cert fingerprint


class BotnetManager:
    """Manages botnet links in async loop. Separate process via multiprocessing."""

    def __init__(self, queue_to_core: mp.Queue, queue_from_core: mp.Queue, db_path: str):
        self.queue_to_core = queue_to_core
        self.queue_from_core = queue_from_core
        self.db_path = db_path
        self.links: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.peers: Dict[str, BotLink] = {}
        self.partyline_channels: Dict[int, List[str]] = {0: []}  # 0=global partyline [web:2]
        self.is_hub: bool = False
        self.subnet_id: str = "default"
        self.my_name: str = "pydrop"
        self.my_port: Optional[int] = None  # Loaded from DB/config

    async def load_config(self) -> None:
        """Load bot record, links, subnet from DB."""
        async with get_db(self.db_path) as db:
            bot_rec: BotRecord = await db.get_bot_record(self.my_name)
            self.is_hub = bot_rec.is_hub
            self.subnet_id = bot_rec.subnet_id or "default"
            self.my_port = bot_rec.listen_port
            self.my_name = bot_rec.name
            bot_links = await db.get_bot_links()  # List[BotLinkRecord]
            self.peers = {link.name: BotLink(**asdict(link)) for link in bot_links}
        log.info(f"Botnet loaded: hub={self.is_hub}, subnet={self.subnet_id}, {len(self.peers)} peers [web:1]")

    async def start_link(self, link: BotLink) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open TCP/TLS connection to peer."""
        reader, writer = await asyncio.open_connection(link.host, link.port)
        if link.fingerprint:
            # TODO: Full TLS with fingerprint verify [web:8]
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            # ctx.check_hostname = False  # Customize
            # writer = asyncio.wrap_ssl(writer.transport, ctx)  # Proper TLS upgrade
            pass  # Placeholder for STARTTLS-like
        await self.send_handshake(writer, link.name)
        return reader, writer

    async def send_handshake(self, writer: asyncio.StreamWriter, target: str) -> None:
        """Send Eggdrop-style link handshake."""
        msg = f"PASS :randompw\nSERVER {target} 1 :Pydrop Botnet Link\n"
        writer.write(msg.encode())
        await writer.drain()

    async def handle_peer(self, name: str) -> None:
        """Start/maintain link to peer."""
        link = self.peers[name]
        try:
            reader, writer = await self.start_link(link)
            self.links[name] = (reader, writer)
            asyncio.create_task(self.read_loop(reader, writer, name))
            if 's' in link.flags:  # Aggressive share [web:1]
                asyncio.create_task(self.share_userfile(writer))
                asyncio.create_task(self.share_channels(writer))
        except Exception as e:
            log.error(f"Link to {name} failed: {e}")

    async def read_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, name: str) -> None:
        """Read/forward messages from peer."""
        try:
            while data := await reader.read(4096):
                lines = data.decode().splitlines()
                for line in lines:
                    if line.strip():
                        await self.process_line(line, name, writer)
        except Exception as e:
            log.error(f"Read loop {name} error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def process_line(self, line: str, from_bot: str, writer: asyncio.StreamWriter) -> None:
        """Process partyline/command line from peer [web:2]."""
        line = line.strip()
        if line.startswith('.'):  # Partyline command
            cmd = self.parse_command(line)
            await self.route_command(cmd, from_bot)
        elif line.startswith(','):  # Bot owners channel
            pass  # TODO: Handle
        elif line.startswith("'"):  # Local-only
            pass  # Ignore
        else:  # Chat
            chan = 0  # Default global
            await self.broadcast_chat(line, chan, exclude=from_bot)

    def parse_command(self, line: str) -> Dict:
        """Parse .cmd target=botnet args."""
        # Simple: split on spaces after first word
        parts = line[1:].split(maxsplit=1)
        cmd = {'cmd': parts[0], 'args': parts[1] if len(parts) > 1 else ''}
        # TODO: Parse target=subnet/botnet/me
        return cmd

    async def route_command(self, cmd: Dict, from_bot: str) -> None:
        """Route cmd to self/subnet/botnet."""
        target = cmd.get('target', 'me')
        if target in ('me', '*'):
            self.queue_to_core.put(BotEvent(cmd=cmd))
        if target == 'subnet':
            await self.broadcast_subnet(cmd)
        elif target == 'botnet':
            await self.broadcast(cmd)

    async def share_userfile(self, writer: asyncio.StreamWriter) -> None:
        """Aggressively share users."""
        async with get_db(self.db_path) as db:
            users = await db.get_all_users()
        data = json.dumps([asdict(u) for u in users])
        msg = f"SHAREUSERS :{data}\n"
        writer.write(msg.encode())
        await writer.drain()

    async def share_channels(self, writer: asyncio.StreamWriter) -> None:
        """Share channels/bans."""
        async with get_db(self.db_path) as db:
            chans = await db.get_all_channels()
        data = json.dumps([asdict(c) for c in chans])
        msg = f"SHARECHANS :{data}\n"
        writer.write(msg.encode())
        await writer.drain()

    async def broadcast_chat(self, msg: str, chan: int, exclude: Optional[str] = None) -> None:
        """Broadcast chat to partyline."""
        prefix = f"PRIVMSG #{chan} :" if chan else ""
        line = f"{prefix}{msg}\n"
        for name, (_, writer) in self.links.items():
            if exclude and name == exclude:
                continue
            writer.write(line.encode())

    async def broadcast(self, cmd: Dict) -> None:
        """Broadcast command to all links."""
        msg = json.dumps(cmd) + "\n"
        coros = [writer.write(msg.encode()) for _, writer in self.links.values()]
        await asyncio.gather(*coros, return_exceptions=True)

    async def broadcast_subnet(self, cmd: Dict) -> None:
        """Broadcast to subnet peers only."""
        subnet_peers = {k: v for k, v in self.peers.items() if getattr(v, 'subnet_id', self.subnet_id) == self.subnet_id}
        coros = []
        for name in subnet_peers:
            link = self.links.get(name)
            if link:
                reader, writer = link
                msg = json.dumps(cmd) + "\n"
                coros.append(writer.write(msg.encode()))
        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

    async def handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming link (hubs listen). Auth/handshake."""
        # TODO: Read handshake, verify, add dynamic link
        log.info("Incoming botnet link")
        asyncio.create_task(self.read_loop(reader, writer, "incoming"))

    async def listen(self) -> None:
        """Listen for incoming links."""
        if not self.my_port:
            return
        server = await asyncio.start_server(self.handle_incoming, '0.0.0.0', self.my_port)
        log.info(f"Listening on port {self.my_port}")
        async with server:
            await server.serve_forever()

    async def run(self) -> None:
        """Main botnet loop."""
        await self.load_config()
        # Outgoing links
        tasks = [self.handle_peer(name) for name in self.peers]
        # Incoming server
        if self.is_hub or True:  # Hubs/leaves can listen?
            tasks.append(self.listen())
        await asyncio.gather(*tasks, return_exceptions=True)

    def stop(self) -> None:
        """Close all links."""
        for _, writer in self.links.values():
            writer.close()


# Process entrypoint (called via multiprocessing)
def botnet_process(queue_to_core: mp.Queue, queue_from_core: mp.Queue, db_path: str):
    """Run BotnetManager in async event loop."""
    manager = BotnetManager(queue_to_core, queue_from_core, db_path)
    asyncio.run(manager.run())
