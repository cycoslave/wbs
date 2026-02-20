#!/usr/bin/env python3
"""
src/core.py - Main process: Core loop + spawns IRC/partyline/botnet children.
"""
import asyncio
import multiprocessing as mp
import threading
import time
import logging
from pathlib import Path
from typing import Dict, Any
from collections import deque

# Local modules
from .db import get_db, init_db
from .user import UserManager, SeenDB
from .channel import get_channel_mgr
from .irc import irc_target
from .partyline import partyline_target
from .botnet import botnet_target

logger = logging.getLogger("wbs.core")
BASE_DIR = Path(__file__).parent.parent

class Core:
    """Main process: Core event loop + child process manager."""
    
    def __init__(self, config):
        self.config = config
        self.db_path = config['db']['path'] or BASE_DIR / "wbs.db"
        
        # Queues (Core owns all communication)
        self.core_q = mp.Queue()     # Partyline/commands -> Core
        self.irc_q = mp.Queue()      # Core -> IRC
        self.botnet_q = mp.Queue() if config.get('botnet', {}).get('enabled') else None
        self.party_q = mp.Queue()    # Core -> Partyline
        
        # Event buffer (thread -> async)
        self._event_buffer = deque()
        self._buffer_lock = threading.Lock()
        self.quit_event = mp.Event()
        
        # Managers
        self.user_mgr = None
        self.seen = None
        self.channels = config.get('channels', [])
        self.children = []
        self.start_time = time.time()

    def spawn_children(self):
        """Spawn daemon children - config from env."""
        import os
        config_path = os.environ.get('WBS_CONFIG', 'config.json')
        
        # IRC
        irc_proc = mp.Process(
            target=irc_target,
            args=(config_path, self.core_q, self.irc_q, self.botnet_q, self.party_q),
            daemon=True, name="IRC"
        )
        irc_proc.start()
        self.children.append(irc_proc)
        
        # Partyline
        party_proc = mp.Process(
            target=partyline_target,
            args=(config_path, self.party_q, self.core_q, self.quit_event),
            daemon=True, name="Partyline"
        )
        party_proc.start()
        self.children.append(party_proc)
        
        # Botnet if enabled
        if self.botnet_q:
            botnet_proc = mp.Process(
                target=botnet_target,
                args=(config_path, self.core_q, self.irc_q, self.botnet_q, self.party_q),
                daemon=True, name="Botnet"
            )
            botnet_proc.start()
            self.children.append(botnet_proc)
        
        logger.info(f"Spawned: {[p.name for p in self.children]}")

    async def run(self):
        """Main async event loop - THIS IS THE CORE."""
        await self._async_init()
        self.spawn_children()
        
        # Start event poller thread
        poller_thread = threading.Thread(target=self.event_poller, daemon=True)
        poller_thread.start()
        
        logger.info("Core event loop running")
        await self._main_loop()

    def event_poller(self):
        """Thread: Poll core_q -> event buffer."""
        while not self.quit_event.is_set():
            try:
                msg = self.core_q.get(timeout=0.1)
                with self._buffer_lock:
                    self._event_buffer.append(msg)
            except mp.queues.Empty:
                pass

    async def _main_loop(self):
        """Core event loop: drain buffer, handle events, periodic tasks."""
        last_periodic = time.time()
        while not self.quit_event.is_set():
            # Drain events
            events = []
            with self._buffer_lock:
                while self._event_buffer:
                    events.append(self._event_buffer.popleft())
            
            for event in events:
                if event.get('cmd') == 'quit':
                    await self._shutdown(event.get('message', 'Quit'))
                    return
                await self.handle_event(event)
            
            # Periodic
            if time.time() - last_periodic >= 5.0:
                await self._periodic_tasks()
                last_periodic = time.time()
            
            await asyncio.sleep(0.05)

    async def _shutdown(self, message):
        """Graceful shutdown cascade."""
        self.quit_event.set()
        logger.info(f"Shutdown: {message}")
        
        # Notify children
        for q in (self.irc_q, self.party_q):
            try: q.put_nowait({'cmd': 'quit', 'message': message})
            except: pass
        if self.botnet_q:
            self.botnet_q.put_nowait({'cmd': 'quit', 'message': message})

        # Join children
        for child in self.children:
            if child.is_alive():
                child.join(timeout=5.0)
                if child.is_alive(): child.terminate()

    async def _async_init(self):
        """One-time async initialization: DB schema, user/seen managers, botnet."""
        logger.info(f"Initializing core with db_path={self.db_path}")
        
        # Initialize database schema
        await init_db(self.db_path)
        
        # User and seen managers
        self.user_mgr = UserManager()
        self.seen = SeenDB()
        
        # Botnet manager (conditional - only if enabled in config)
        botnet_cfg = self.config.get('botnet', {})
        if botnet_cfg.get('enabled', False):
            from .botnet import BotnetManager
            # Signature: BotnetManager(queue_to_core, queue_from_core, db_path)
            self.botnet_mgr = BotnetManager(self.event_q, self.cmd_q, self.db_path)
            await self.botnet_mgr.load_config()
            logger.info("Botnet manager initialized")
        else:
            logger.info("Botnet disabled")
        
        logger.info(f"Core initialized: channels={self.channels}")

    async def handle_event(self, event: Dict[str, Any]):
        """Dispatch events to appropriate handlers based on type."""
        etype = event.get('type', 'UNKNOWN')
        
        handlers = {
            'COMMAND': self.on_command,
            'PUBMSG': self.on_pubmsg,
            'PRIVMSG': self.on_privmsg,
            'JOIN': self.on_join,
            'PART': self.on_part,
            'KICK': self.on_kick,
            'QUIT': self.on_quit,
            'NICK': self.on_nick,
            'READY': self.on_ready,
            'ERROR': self.on_error,
        }
        
        handler = handlers.get(etype)
        if handler:
            await handler(event)
        else:
            logger.warning(f"Unhandled event type: {etype}")


    # === Event Handlers ===
    
    async def on_command(self, event: Dict[str, Any]):
        """
        Handle commands from authorized users (partyline/DCC or IRC privmsg).
        Delegates actual command logic to commands.py.
        """
        nick = event.get('nick', '')
        text = event.get('text', '').strip()
        
        # Check authorization via user manager
        handle = await self.user_mgr.match_user(f"{nick}!*@*")  # Simplified; use full hostmask
        if not handle:
            self.send_cmd('msg', nick, "You are not recognized. Contact bot owner.")
            return
        
        user = await self.user_mgr.get_user(handle)
        if not user or 'n' not in user.flags:  # Require at least basic flag
            self.send_cmd('msg', nick, "Access denied.")
            return
        
        # Parse command
        if not text:
            return
        
        parts = text.split(maxsplit=1)
        cmd = parts[0].lstrip('.').lower()
        arg = parts[1] if len(parts) > 1 else ""
        
        # Dispatch to commands.py registry
        if cmd in COMMANDS:
            # Create mock DCC session for IRC-based commands
            idx = hash(nick) % 10000  # Pseudo-idx for IRC commands
            if idx not in self.dcc_sessions:
                self.dcc_sessions[idx] = {'hand': handle, 'send': lambda msg: self.send_cmd('msg', nick, msg)}
            
            try:
                await COMMANDS[cmd](self.config, self.core_q, self.irc_q, self.botnet_q, self.party_q, handle, idx, arg)
            except Exception as e:
                logger.error(f"Command '{cmd}' error: {e}", exc_info=True)
                self.send_cmd('msg', nick, f"Error executing .{cmd}")
        else:
            self.send_cmd('msg', nick, f"Unknown command: .{cmd}")


    async def on_pubmsg(self, event: Dict[str, Any]):
        """Public message: update seen DB, flood protection checks (future)."""
        nick = event.get('nick', '')
        host = event.get('host', '')
        channel = event.get('channel', '')
        
        await self.seen.update_seen(nick, host, channel, 'PUBMSG')


    async def on_privmsg(self, event: Dict[str, Any]):
        """Private message: treat as potential command from authorized user."""
        # Transform to COMMAND event and re-dispatch
        event['type'] = 'COMMAND'
        await self.on_command(event)


    async def on_join(self, event: Dict[str, Any]):
        """User joined channel: update seen DB."""
        nick = event.get('nick', '')
        host = event.get('host', '')
        channel = event.get('channel', '')
        
        await self.seen.update_seen(nick, host, channel, 'JOIN')


    async def on_part(self, event: Dict[str, Any]):
        """User left channel: update seen DB."""
        nick = event.get('nick', '')
        host = event.get('host', '')
        channel = event.get('channel', '')
        
        await self.seen.update_seen(nick, host, channel, 'PART')


    async def on_kick(self, event: Dict[str, Any]):
        """User kicked from channel."""
        kicked_nick = event.get('kicked_nick', '')
        channel = event.get('channel', '')
        
        await self.seen.update_seen(kicked_nick, '', channel, 'KICK')


    async def on_quit(self, event: Dict[str, Any]):
        """User quit IRC."""
        nick = event.get('nick', '')
        await self.seen.update_seen(nick, '', '', 'QUIT')


    async def on_nick(self, event: Dict[str, Any]):
        """User changed nick."""
        old_nick = event.get('old_nick', '')
        new_nick = event.get('new_nick', '')
        
        await self.seen.update_seen(old_nick, '', '', f'NICK -> {new_nick}')


    async def on_ready(self, event: Dict[str, Any]):
        """IRC connection established: join channels."""
        logger.info("IRC READY - joining channels")
        for channel in self.channels:
            self.send_cmd('join', channel)


    async def on_error(self, event: Dict[str, Any]):
        """IRC error occurred."""
        error_msg = event.get('data', 'Unknown error')
        logger.error(f"IRC error: {error_msg}")


    # === Outbound Command Helpers ===
    def send_cmd(self, cmd_type: str, target: str, text: str = "", **kwargs):
        """Send to IRC queue."""
        cmd = {'cmd': cmd_type, 'target': target, 'text': text, **kwargs}  # Fixed: 'text': text
        try:
            self.irc_q.put_nowait(cmd)
            logger.debug(f"Sent: {cmd_type} -> {target}")
        except mp.queues.Full:
            logger.warning(f"IRC queue full, dropped: {cmd}")


    # === Periodic Tasks ===
    async def _periodic_tasks(self):
        """Periodic tasks."""
        # Fix: Check self.botnet_mgr exists first
        if hasattr(self, 'botnet_mgr') and self.botnet_mgr:
            await self.botnet_mgr.poll_links()
        # Add other tasks...

def start_core_process(config, core_q, irc_q, botnet_q, party_q):
    """
    Entry point for core process (called by main.py via multiprocessing).
    Sets up async runtime and starts CoreEventLoop.
    """
    # Configure logging for subprocess
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(name)s %(levelname)s: %(message)s'
    )
    
    logger.info(f"Core process started: PID={os.getpid()}")
    
    try:
        loop = CoreEventLoop(config, core_q, irc_q, botnet_q, party_q)
        asyncio.run(loop.run())
    except KeyboardInterrupt:
        logger.info("Core process interrupted")
    except Exception as e:
        logger.critical(f"Core process fatal error: {e}", exc_info=True)
        raise