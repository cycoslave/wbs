# src/core.py
"""
Main process: Core loop + spawns IRC/partyline/botnet children.
"""
import asyncio
import multiprocessing as mp
import threading
import time
import logging
import json
import os
import sys
import select
from pathlib import Path
from typing import Dict, Any
from collections import deque

from .db import init_db
from .user import UserManager
from .seen import Seen
from .irc import irc_target
from .botnet import botnet_target
from .commands import COMMANDS
from .partyline import PartylineHub
from .console import ConsoleTask

logger = logging.getLogger("wbs.core")
BASE_DIR = Path(__file__).parent.parent

class Core:
    """Main process: Core event loop + child process manager."""
    
    def __init__(self, args):
        self.config_path = getattr(args, 'config', 'config.json')
        db_path_override = getattr(args, 'db_path', None)
        with open(self.config_path) as f:
            self.config = json.load(f)
        if db_path_override:
            self.config['db']['path'] = db_path_override
        self.db_path = self.config['db']['path'] or BASE_DIR / "wbs.db"
        
        # Queues (Core owns all communication)
        self.core_q = mp.Queue()     # Core
        self.irc_q = mp.Queue()      # IRC
        self.botnet_q = mp.Queue() if self.config.get('botnet', {}).get('enabled') else None
        self.party_q = mp.Queue()    # Partyline
        
        # Async queues for console (main process only)
        self.command_queue = asyncio.Queue()  # Console -> Core
        self.console_queue = asyncio.Queue()  # Core -> Console
        
        # Event buffer (thread -> async)
        self._event_buffer = deque()
        self._buffer_lock = threading.Lock()
        self.quit_event = mp.Event()
        
        # Managers
        self.user_mgr = None
        self.partyline_hub = None
        self.seen = None

        # Runtime variables
        self.channels = self.config.get('channels', [])
        self.children = []
        self.start_time = time.time()
        self.running = True
        self.connected = False
        self.botname = None
        self.dcc_sessions = {}
        self.foreground = False

    def spawn_children(self, foreground=False):
        """Spawn daemon children - skip partyline in foreground mode."""
        config_path = self.config_path
        
        # IRC always
        irc_proc = mp.Process(
            target=irc_target,
            args=(config_path, self.core_q, self.irc_q, self.botnet_q, self.party_q),
            daemon=True, name="IRC"
        )
        irc_proc.start()
        self.children.append(irc_proc)
        
        # Partyline ONLY if not foreground
        if not foreground:
            party_proc = mp.Process(
                target=partyline_target,
                args=(config_path, self.party_q, self.core_q, self.quit_event),
                daemon=True, name="Partyline"
            )
            party_proc.start()
            self.children.append(party_proc)
            logger.info("Partyline process spawned")
        else:
            logger.info("Foreground mode: Using console (no partyline process)")
        
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

    async def run(self, foreground=False):
        """Main async event loop"""
        self.foreground = foreground
        
        logger.info(f"Initializing core with db_path={self.db_path}")
        await self._async_init()
        
        # Register console with partyline if foreground
        if foreground:
            self.console_session_id = self.partyline_hub.register_console(
                handle='console',
                output_callback=self._console_output
            )
        
        self.spawn_children(foreground=foreground)
        
        # Start event poller thread
        poller_thread = threading.Thread(target=self.event_poller, daemon=True)
        poller_thread.start()
        
        logger.info("Core event loop running")
        
        if foreground:
            await self._main_loop_with_console()
        else:
            await self._main_loop()

    def _console_output(self, message: str):
        """Callback for partyline messages to console"""
        print(message)            
    
    async def handle_event(self, event: Dict[str, Any]):
        """Handle events from children or internal"""
        if isinstance(event, tuple) and len(event) == 2 and event[0] == 'event':
            event = event[1]
        
        if not isinstance(event, dict):
            logger.error(f"Invalid event type received: {type(event)} - {event}")
            return
        
        etype = event.get('type', 'UNKNOWN')
        handlers = {
            'PARTYLINE_COMMAND': self.on_partyline_command,
            'PARTYLINE_CHAT': self.on_partyline_chat,
            'COMMAND': self.on_command,
            'PUBMSG': self.on_pubmsg,
            'PRIVMSG': self.on_privmsg,
            'JOIN': self.on_join,
            'PART': self.on_part,
            'KICK': self.on_kick,
            'QUIT': self.on_quit,
            'MODE': self.on_null,
            'NICK': self.on_nick,
            'READY': self.on_ready,
            'DISCONNECT': self.on_disconnect,
            'ERROR': self.on_error,
        }
        handler = handlers.get(etype)
        if handler:
            await handler(event)
        else:
            logger.warning(f"Unhandled event type: {etype}")
    
    async def on_partyline_command(self, event):
        """Forward partyline commands to partyline hub"""
        session_id = event.get('session_id')
        handle = event.get('handle')
        text = event.get('text')
        
        # AWAIT the async call
        await self.partyline_hub.handle_input(session_id, text)

    async def on_partyline_chat(self, event):
        """Handle chat from botnet partyline"""
        from_bot = event.get('from', 'unknown')
        text = event.get('text', '')
        
        # Broadcast to local partyline
        self.partyline_hub.broadcast(f"<{from_bot}@botnet> {text}")

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
            # Drain events from child processes
            events = []
            with self._buffer_lock:
                while self._event_buffer:
                    events.append(self._event_buffer.popleft())
            
            for event in events:
                if not isinstance(event, dict):
                    logger.error(f"Invalid event type received: {type(event)} - {event}")
                    continue
                    
                if event.get('cmd') == 'quit':
                    await self._shutdown(event.get('message', 'Quit'))
                    return
                await self.handle_event(event)
            
            # Periodic
            if time.time() - last_periodic >= 5.0:
                await self._periodic_tasks()
                last_periodic = time.time()
            
            await asyncio.sleep(0.05)

    async def _main_loop_with_console(self):
        """Foreground mode: handle console + child events."""
        
        # Create and start console task with partyline integration
        console = ConsoleTask(
            partyline_hub=self.partyline_hub,
            session_id=self.console_session_id,
            handle='console'
        )
        console_task = asyncio.create_task(console.run())
        
        last_periodic = time.time()
        try:
            while not self.quit_event.is_set() and console.running:
                # Drain child process events
                events = []
                with self._buffer_lock:
                    while self._event_buffer:
                        events.append(self._event_buffer.popleft())
                
                for event in events:
                    if not isinstance(event, dict):
                        logger.error(f"Invalid event: {type(event)} - {event}")
                        continue
                        
                    if event.get('cmd') == 'quit':
                        await self._shutdown(event.get('message', 'Quit'))
                        self.quit_event.set()
                        console.running = False
                        return
                    await self.handle_event(event)
                
                # Periodic
                if time.time() - last_periodic >= 5.0:
                    await self._periodic_tasks()
                    last_periodic = time.time()
                
                await asyncio.sleep(0.05)
                
        finally:
            console.running = False
            console_task.cancel()
            try:
                await console_task
            except asyncio.CancelledError:
                pass

    async def _shutdown(self, message):
        self.running = False
        self.quit_event.set()
        logger.info(f"Shutdown: {message}")
        
        # Send quit to children
        quit_msg = {'cmd': 'quit', 'message': message}
        for q in (self.irc_q, self.party_q):
            try:
                q.put_nowait(quit_msg)
            except:
                pass

        # Wait for children
        for child in self.children:
            if child.is_alive():
                child.join(timeout=3.0)
                if child.is_alive():
                    child.terminate()
                    child.join(timeout=1.0)

    async def _async_init(self):
        """One-time async initialization."""
        # Initialize database schema
        await init_db(self.db_path)
        
        # User and seen managers
        self.user_mgr = UserManager(self.db_path)
        self.seen = Seen(self.db_path)
        
        # Botnet manager
        botnet_cfg = self.config.get('botnet', {})
        if botnet_cfg.get('enabled', False):
            from .botnet import BotnetManager
            self.botnet_mgr = BotnetManager(
                self.config, self.core_q, self.irc_q, 
                self.botnet_q, self.party_q
            )
            await self.botnet_mgr.load_config()
            logger.info("Botnet manager initialized")
        else:
            logger.info("Botnet disabled")
        
        self.partyline_hub = PartylineHub(self)
        logger.info(f"Core initialized: channels={self.channels}")

    async def on_command(self, event):
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
        
        await self.seen.update_seen(old_nick, '', '', 'NICK')

    async def on_ready(self, event: Dict[str, Any]):
        """IRC connection established: join channels."""
        self.connected = True
        logger.info("IRC READY - joining channels")
        for channel in self.channels:
            self.send_cmd('join', channel)

    async def on_disconnect(self, event: Dict[str, Any]):
        """IRC connection dropped."""
        self.connected = False       

    async def on_null(self, event: Dict[str, Any]):
        """Just do nothing."""
        pass              

    async def on_error(self, event: Dict[str, Any]):
        """IRC error occurred."""
        error_msg = event.get('data', 'Unknown error')
        logger.error(f"IRC error: {error_msg}")

    def send_cmd(self, cmd_type: str, target: str, text: str = "", **kwargs):
        """Send to IRC queue."""
        cmd = {'cmd': cmd_type, 'target': target, 'text': text, **kwargs}
        try:
            self.irc_q.put_nowait(cmd)
        except mp.queues.Full:
            logger.warning(f"IRC queue full, dropped: {cmd}")

    async def _periodic_tasks(self):
        """Periodic tasks."""
        if hasattr(self, 'botnet_mgr') and self.botnet_mgr:
            await self.botnet_mgr.poll_links()