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
import socket
from pathlib import Path
from typing import Dict, Any
from collections import deque

from .db import init_db
from .user import UserManager
from .channel import ChannelManager
from .seen import Seen
from .irc import irc_process_launcher
from .botnet import botnet_process_launcher
from .commands import COMMANDS
from .partyline import Partyline
from .console import Console
from .session import Session
from .net import NetListener
from . import __version__

log = logging.getLogger("wbs.core")
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
        self.db_path = self.config['db']['path'] or BASE_DIR / "db/wbs.db"
        
        # Queues (Core owns all communication)
        self.core_q = mp.Queue()     # Core
        self.irc_q = mp.Queue()      # IRC
        self.botnet_q = mp.Queue() if self.config['settings']['botnet'] else None
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
        self.chan_mgr = None
        self.partyline = None
        self.seen = None
        self.net_listener = NetListener(self.core_q)

        # Runtime variables
        self.children = []
        self.start_time = time.time()
        self.running = True
        self.connected = False
        self.botname = self.config['bot']['nick']
        self.dcc_sessions = {}
        self.party_sessions = {}
        self.bot_sessions = {} 
        self.foreground = False

    def spawn_children(self, foreground=False):
        """Spawn daemon children - skip partyline in foreground mode."""
        config_path = self.config_path
        
        # IRC always
        irc_proc = mp.Process(
            target=irc_process_launcher,
            args=(config_path, self.core_q, self.irc_q, self.botnet_q, self.party_q),
            daemon=True, name="IRC"
        )
        irc_proc.start()
        self.children.append(irc_proc)
        
        # Partyline ONLY if not foreground
        if not foreground:
            log.info("Background mode")
        else:
            log.info("Foreground mode: Using console.")
        
        # Botnet if enabled
        if self.config['settings']['botnet']:
            botnet_proc = mp.Process(
                target=botnet_process_launcher,
                args=(config_path, self.core_q, self.irc_q, self.botnet_q, self.party_q),
                daemon=True, name="Botnet"
            )
            botnet_proc.start()
            self.children.append(botnet_proc)
        
        log.info(f"Spawned: {[p.name for p in self.children]}")

    async def run(self, foreground=False):
        """Main async event loop"""
        self.foreground = foreground
        log.info(f"Initializing core with db_path={self.db_path}")
        await self._async_init()
        
        if hasattr(self, 'net_listener'):
            asyncio.create_task(self.net_listener.listen(port=self.config['settings']['listen_port']))

        # Register console with partyline if foreground
        if foreground:
            self.console_session_id = self.partyline.register_console(
                handle='console',
                output_callback=self._console_output
            )
        
        self.spawn_children(foreground=foreground)
        
        # Start event poller thread
        poller_thread = threading.Thread(target=self.event_poller, daemon=True)
        poller_thread.start()
        
        log.info("Core event loop running")
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
            log.error(f"Invalid event type received: {type(event)} - {event}")
            return
        
        etype = event.get('type', 'UNKNOWN')
        handlers = {
            'PARTYLINE_INPUT': self.on_partyline_input,
            'PARTYLINE_CONNECT': self.on_partyline_connect,
            'PARTYLINE_DISCONNECT': self.on_partyline_disconnect,
            'BOTLINK_CONNECT': self.on_bot_connect,
            'BOT_DISCONNECT': self.on_bot_disconnect,
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
            log.warning(f"Unhandled event type: {etype}")
    
    async def on_partyline_input(self, event: dict):
        """Forward partyline input to Partyline manager."""
        session_id = event['session_id']
        text = event['text']
        await self.partyline.handle_input(session_id, text)

    async def on_bot_connect(self, event: dict):
        """Handle incoming bot connection - create bot session."""
        bot_name = event['handle']
        peer = event.get('peer', 'unknown')
        dup_fd = event.get('sockfd')
        
        log.info(f"New bot connection: {bot_name} fd={dup_fd}")
        
        if dup_fd is None:
            log.warning(f"No dup_fd for bot {bot_name}")
            return
        
        try:
            dup_sock = socket.socket(fileno=dup_fd)
            dup_sock.setblocking(False)
            
            reader, writer = await asyncio.open_connection(sock=dup_sock)
            
            # Generate session ID
            bot_id = len(self.bot_sessions) + 10000  # Offset to avoid collision
            
            response_q = mp.Queue()
            
            # Create bot session (same as telnet, just different type)
            bot_session = Session(
                session_id=bot_id,
                session_type='bot',
                handle=bot_name,
                reader=reader,
                writer=writer,
                core_q=self.core_q,
                response_q=response_q,
                subnet_id=1  # Get from config if needed
            )
            
            self.bot_sessions[bot_id] = bot_session
            
            # Send handshake response
            await bot_session.send(f"BOTLINK {self.botname} {bot_name} 1 :WBS {__version__}")
            asyncio.create_task(bot_session.run())
            
            log.info(f"Bot session {bot_id} created for {bot_name}")
            self.partyline.broadcast(f"*** {bot_name} linked to botnet")
            
        except Exception as e:
            log.error(f"Bot session {bot_name} failed: {e}")
            try:
                os.close(dup_fd)
            except:
                pass

    async def on_bot_disconnect(self, event: dict):
        """Handle bot disconnection."""
        session_id = event['session_id']
        bot_name = event['handle']
        
        if session_id in self.bot_sessions:
            del self.bot_sessions[session_id]
            log.info(f"Bot {bot_name} disconnected")
            self.partyline.broadcast(f"*** {bot_name} unlinked")

    async def on_partyline_connect(self, event: dict):
        """Recreate socket from DUP'd FD → reader/writer."""
        handle = event['handle']
        peer = event.get('peer', 'unknown')
        dup_fd = event.get('sockfd')
        
        log.info(f"Partyline newuser {handle} fd={dup_fd}")
        
        if dup_fd is None:
            log.warning(f"No dup_fd for {handle}")
            return
        
        try:
            dup_sock = socket.socket(fileno=dup_fd)
            dup_sock.setblocking(False)
            
            reader, writer = await asyncio.open_connection(sock=dup_sock)
            
            response_q = mp.Queue()
            session_id = self.partyline.register_remote('telnet', handle, response_q)
            
            #log.info(f"DEBUG creating Session: id={session_id}, reader={repr(reader)}, writer={repr(writer)}")
            session = Session(session_id, 'telnet', handle=handle,
                              reader=reader, writer=writer,
                              core_q=self.core_q, response_q=response_q)
            #log.info("DEBUG Session created OK")
            
            self.party_sessions[session_id] = session
            asyncio.create_task(session.run())
            
            #await session.send("Welcome to WBS partyline! Type .help")
            log.info(f"Remote session {session_id} (telnet) registered for {handle}")
            
        except Exception as e:
            log.error(f"Session dup_fd {dup_fd} failed: {e}")
            # Cleanup: close dup_fd IF socket creation failed
            try:
                os.close(dup_fd)
            except OSError:
                pass

    async def on_partyline_disconnect(self, event: dict):
        """Cleanup partyline session on disconnect."""
        session_id = event['session_id']
        
        if session_id in self.party_sessions:
            session = self.party_sessions.pop(session_id)
            try:
                if session.writer:
                    session.writer.close()
                    await session.writer.wait_closed()
                log.info(f"Party socket fd closed + session {session_id} ({getattr(session, 'handle', 'unknown')}) unregistered")
            except Exception as e:
                log.warning(f"Session {session_id} close failed: {e}")
        
        if hasattr(self, 'partyline') and self.partyline:
            if session_id in self.partyline.sessions:
                handle = self.partyline.sessions[session_id]['handle']
                del self.partyline.sessions[session_id]
                log.info(f"Partyline unregistered {handle}#{session_id}")
                self.partyline.broadcast(f"{handle} left the partyline", exclude_session=session_id)
        
        log.debug(f"Partyline disconnect complete: {session_id}")

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
                    log.error(f"Invalid event type received: {type(event)} - {event}")
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
        """Foreground: console + child events."""
        console_task = asyncio.create_task(
            Console(self.partyline, self.console_session_id, "console").run()
        )
        last_periodic = time.time()
        try:
            while not self.quit_event.is_set() and console_task.done() == False:
                # Drain event buffer
                events = []
                with self._buffer_lock:
                    while self._event_buffer:
                        events.append(self._event_buffer.popleft())
                for event in events:
                    if isinstance(event, dict) and event.get('cmd') == 'quit':
                        await self._shutdown(event.get('message', 'Quit'))
                        self.quit_event.set()
                        console_task.cancel()
                        return
                    await self.handle_event(event)
                # Periodic
                if time.time() - last_periodic >= 5.0:
                    await self._periodic_tasks()
                    last_periodic = time.time()
                await asyncio.sleep(0.05)
        finally:
            console_task.cancel()
            try:
                await console_task
            except asyncio.CancelledError:
                pass

    async def _shutdown(self, message):
        self.running = False
        self.quit_event.set()
        log.info(f"Shutdown: {message}")
        
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
        self.chan_mgr = ChannelManager(self.db_path)
        self.seen = Seen(self.db_path)
        
        self.partyline = Partyline(self)
        log.info(f"Core process started. (pid={os.getpid()})")

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
                log.error(f"Command '{cmd}' error: {e}", exc_info=True)
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
        log.info("IRC READY - joining channels..")
        channels = await self.chan_mgr.getchans()
        for channel in channels:
            if not None:
                log.info(f"Joining {channel}..")
                self.irc_q.put_nowait({'cmd': 'join', 'channel': channel})
                time.sleep(0.2)

    async def on_disconnect(self, event: Dict[str, Any]):
        """IRC connection dropped."""
        self.connected = False       

    async def on_null(self, event: Dict[str, Any]):
        """Just do nothing."""
        pass              

    async def on_error(self, event: Dict[str, Any]):
        """IRC error occurred."""
        error_msg = event.get('data', 'Unknown error')
        log.error(f"IRC error: {error_msg}")

    def send_cmd(self, cmd_type: str, target: str, text: str = "", **kwargs):
        """Send to IRC queue."""
        cmd = {'cmd': cmd_type, 'target': target, 'text': text, **kwargs}
        try:
            self.irc_q.put_nowait(cmd)
        except mp.queues.Full:
            log.warning(f"IRC queue full, dropped: {cmd}")

    async def _periodic_tasks(self):
        """Periodic tasks."""
        if hasattr(self, 'botnet_mgr') and self.botnet_mgr:
            await self.botnet_mgr.poll_queues()