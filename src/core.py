#!/usr/bin/env python3
"""
src/core.py - Core logic process.
"""
from __future__ import annotations
import asyncio
import multiprocessing as mp
import threading
import queue
import time
import logging
import os
from pathlib import Path
from typing import Dict, Any
from collections import deque

# Local modules
from .db import get_db, init_db
from .user import UserManager, SeenDB
from .channel import get_channel_mgr
from .commands import COMMANDS, handle_dcc_chat

logger = logging.getLogger("wbs.core")
BASE_DIR = Path(__file__).parent.parent

class CoreEventLoop:
    """
    Core bot process.
    """
    
    def __init__(self, config, core_q, irc_q, botnet_q, party_q):
        self.config = config
        self.core_q = core_q
        self.irc_q = irc_q
        self.botnet_q = botnet_q
        self.party_q = party_q
        
        # DB path resolution (prefer explicit config)
        self.db_path = config['db']['path'] or config.get('db', {}).get('path', BASE_DIR / "wbs.db")
        
        # Channel list
        self.channels = config.get('channels') or config.get('bot', {}).get('channels', [])
        
        # Managers (initialized in async_init)
        self.user_mgr = None
        self.seen = None
        self.botnet_mgr = None
        
        # Thread-safe event buffer (accessed by poller thread, consumed by async loop)
        self._event_buffer = deque()
        self._buffer_lock = threading.Lock()
        
        # Startup time for uptime tracking
        self.start_time = time.time()
        
        # DCC sessions (partyline support - for commands.py integration)
        self.dcc_sessions = {}  # idx: {'hand': str, 'writer': StreamWriter}


    def event_poller(self):
        """
        Threaded poller.
        """
        logger.info("Event poller thread started")
        while True:
            try:
                msg = self.core_q.get(timeout=0.1)
                with self._buffer_lock:
                    self._event_buffer.append(msg)
                logger.debug(f"Buffered event: {msg.get('type')}")
            except queue.Empty:
                pass
            except Exception as e:
                logger.error(f"Core poller error: {e}", exc_info=False)


    async def run(self):
        """
        Main async loop: initialize resources, drain event buffer, handle events,
        and run periodic tasks.
        """
        await self._async_init()
        logger.info("Core event loop running")
        
        # Start background poller thread
        poller_thread = threading.Thread(target=self.event_poller, daemon=True, name="EventPoller")
        poller_thread.start()
        
        last_periodic = time.time()
        
        while True:
            # Drain buffered events (thread-safe)
            events_to_process = []
            with self._buffer_lock:
                while self._event_buffer:
                    events_to_process.append(self._event_buffer.popleft())
            
            # Process all buffered events
            for event in events_to_process:
                try:
                    await self.handle_event(event)
                except Exception as e:
                    logger.error(f"Event handler error: {e}", exc_info=True)
            
            # Periodic tasks (every 5 seconds)
            now = time.time()
            if now - last_periodic >= 5.0:
                try:
                    await self._periodic_tasks()
                except Exception as e:
                    logger.error(f"Periodic task error: {e}", exc_info=True)
                last_periodic = now
            
            # Yield control (prevent CPU spin)
            await asyncio.sleep(0.05)


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
        """
        Send command to IRC process via cmd_q (thread-safe, sync).
        
        Args:
            cmd_type: 'msg', 'join', 'part', 'mode', 'raw', etc.
            target: channel or nick
            text: message content
            **kwargs: additional parameters (e.g., quick=True for fast mode)
        """
        cmd_data = {'cmd': cmd_type, 'target': target, **kwargs}
        if text:
            cmd_data['text'] = text
        
        try:
            self.cmd_q.put_nowait(cmd_data)
            logger.debug(f"Sent command: {cmd_type} -> {target}, qsize={self.cmd_q.qsize()}")
        except queue.Full:
            logger.warning(f"Command queue full, dropping: {cmd_data}")

    # === Periodic Tasks ===
    
    async def _periodic_tasks(self):
        """Run every ~5s: botnet link polling, cleanup, etc."""
        if self.botnet_mgr:
            # Botnet manager periodic maintenance
            try:
                await self.botnet_mgr.poll_links()
            except Exception as e:
                logger.error(f"Botnet poll error: {e}", exc_info=True)
        
        # Future: channel maintenance (limit checking, topic lock, etc.)


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