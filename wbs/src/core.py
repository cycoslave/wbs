# src/core.py
"""
Main process: Core loop + spawns IRC/partyline/botnet children.
"""
import asyncio
import multiprocessing as mp
import threading
import time
import logging
import os
import sys
import signal
from pathlib import Path
from typing import Dict, Any, Optional
from collections import deque

from .net import AccessGuard
from .net import NetListener
from .channel import ChannelManager, Channel, parse_mode_changes, USER_PREFIX_MODES
from .user import UserManager
from .bot import BotManager
from .botnet import BotnetManager
from .console import Console
from .partyline import Partyline, COMMAND_MIN_FLAGS
from .session import Session
from .plugins import PluginManager
from .games import GameManager
from .dcc import DCCManager, parse_chat_args
from .update import UpdateManager
from .db import init_db, get_db
from .commands import COMMANDS
from .helper import restore_terminal, gate_allows
from .subnet import local_subnet_id
from . import automode
from . import flood
from .logsafe import event_summary, irc_cmd_summary, command_error
from .tasks import TaskRegistry

log = logging.getLogger("wbs.core")

# SAST-001: events whose channel flood decision handle_event makes before
# plugins and games are dispatched (Core._public_flood_gate).
PUBLIC_TEXT_EVENTS = frozenset({'PUBMSG', 'ACTION', 'CHAN_ACTIVITY'})

BASE_DIR = Path(__file__).parent.parent
CLEAN_EXIT_CODE = 42
# Core exit code asking the supervisor for a fresh Core (.rehash, USR-16).
REHASH_EXIT_CODE = 43

class Core:
    """Main process: Core event loop + child process manager."""
    
    def __init__(self, config: dict, config_path: str, args, core_q=None, irc_q=None, sup_q=None):
        self.config      = config
        self.config_path = config_path
        self.args        = args
        db_path_override = getattr(args, 'db_path', None)
        if db_path_override:
            self.config.setdefault('db', {})['path'] = db_path_override
        self.db_path = self.config.get('db', {}).get('path', 'db/wbs.db')
        self.core_q = core_q if core_q is not None else mp.Queue()
        self.irc_q  = irc_q  if irc_q  is not None else mp.Queue()
        self.sup_q  = sup_q
        self._event_buffer = deque()
        self._buffer_lock = threading.Lock()
        self.quit_event = mp.Event()
        self._supervisor_ppid = os.getppid()
        
        # Managers
        self.guard = AccessGuard(db_path=self.db_path, config=self.config)
        self.user = UserManager(self.db_path)
        # One DB for admission control and partyline login (SAST-011).
        self.net_listener = NetListener(self.core_q, config=self.config, access_guard=self.guard,
                                        db_path=self.db_path, user_manager=self.user)
        self.bot = BotManager(self.db_path)
        self.botnet = BotnetManager(self)
        self.chan = ChannelManager(self.db_path)
        self.partyline = Partyline(self)
        self.dcc = DCCManager(self)
        self.plugin = PluginManager(self)
        self.game = GameManager(self)
        self.update = UpdateManager(self.config)

        # Runtime variables
        self.start_time = time.time()
        self.running = True
        self.connected = False
        self.connected_on = None
        self.botname = self.config['bot']['nick']
        self.channels: Dict[str, Channel] = {}
        self.dcc_sessions = {}
        self.party_sessions = {}
        self.bot_sessions = {} 
        self.event_handlers = {}  # type → [plugins]
        # Every periodic Core job, plugin core timers included (NET-9).
        self.tasks = TaskRegistry(self.db_path, spawn=lambda coro, name: self._create_safe_task(coro, name=name))
        self._console_task = None
        self.console: Optional[Console] = None
        self._detaching = False
        self._poller_thread: Optional[threading.Thread] = None
        self._main_task: Optional[asyncio.Task] = None
        self.foreground = False
        self._lag_ping_sent: float | None = None
        self._last_lag_ms: float = 0.0
        self._last_lag_ping: float = 0.0
        self.public_ip: Optional[str] = None
        self.botnet.guard = self.net_listener.guard
        if self.guard is not None:
            self.guard.live_peer_check = self.botnet.has_live_peer
        self.handlers = {
            'DCC_CHAT_REQUEST': self.on_dcc_chat_request, 
            'PARTYLINE_INPUT': self.on_partyline_input,
            'PARTYLINE_CONNECT': self.on_partyline_connect,
            'PARTYLINE_DISCONNECT': self.on_partyline_disconnect,
            'BOT_CONNECT': self.on_bot_connect,
            'BOT_DISCONNECT': self.on_bot_disconnect,
            'COMMAND': self.on_command,
            'PUBMSG': self.on_pubmsg,
            'PRIVMSG': self.on_privmsg,
            'NOTICE': self.on_notice,
            'ON_INVITE': self.on_invite,
            'NEWCHAN': self.on_newchan,
            'JOIN': self.on_join,
            'PART': self.on_part,
            'KICK': self.on_kick,
            'QUIT': self.on_quit,
            'MODE': self.on_mode,
            'NICK': self.on_nick,
            'WHO_REPLY': self.on_who_reply,
            'WHO_END': self.on_who_end,
            'NAMES_REPLY': self.on_names_reply,
            'NAMES_END': self.on_names_end,
            'IRC_STATE': self.on_irc_state,
            'READY': self.on_ready,
            'DISCONNECT': self.on_disconnect,
            'IRC_TIMER_FIRED': self.on_irc_timer_fired,
            'REQUEST_BOTLINKS': self.request_botlinks,
            'ERROR': self.on_error,
            'TOPIC': self.on_topic,
            'CHANNEL_TOPIC_META': self.on_333,
            'CHANNEL_TOPIC': self.on_332,
            'CHANNEL_MODES': self.on_324,
            'CHANNEL_CREATED': self.on_329,
            'BANLIST_ADD': self.on_367,
            'INVITELIST_ADD': self.on_346,
            'EXEMPTLIST_ADD': self.on_348,
            'ERR_CHANNELISFULL': self.on_471,
            'ERR_INVITEONLYCHAN': self.on_473,
            'ERR_BANNEDFROMCHAN': self.on_474,
            'BANLIST_END': self.on_null,
            'INVITELIST_END': self.on_null,
            'EXCEPTLIST_END': self.on_null,
            'IRC_PONG': self.on_irc_pong,
            'BOT_PUBLIC_IP': self.on_bot_public_ip,
            'CHAN_ACTIVITY': self.on_chan_activity,
            'FLOOD_IGNORE': self.on_flood_ignore,
            'IRC_NUMERIC': self.on_irc_numeric,
            'WHOIS_NUMERIC': self.on_whois_numeric,
            'IRC_TIMERS': self.on_irc_timers,
            # Plugin-only events (PLG-8): Core state comes from MODE/CHAN_ACTIVITY.
            **{t: self.on_null for t in ('ACTION', 'OP', 'DEOP', 'HALFOP', 'DEHALFOP',
                                          'VOICE', 'DEVOICE', 'BAN', 'UNBAN')},
        }

    async def _async_init(self):
        """One-time async initialization."""
        await init_db(self.db_path) 
        await self.guard.load()
        await self.botnet.subnet.load()
        await self._seed_and_autoload_modules()

    async def run(self, foreground=False):
        """Main async event loop"""
        self.foreground = foreground
        log.info(f"Core process started. (pid={os.getpid()})")
        # SYS-2: SIGTERM (the supervisor stopping the bot) is a graceful
        # shutdown: IRC QUIT, tasks stopped, state saved, then exit.
        self._install_signal_handlers()
        self._main_task = asyncio.current_task()
        log.info(f"Initializing core with db_path={self.db_path}")
        await self._async_init()
        # Configured plugins were seeded into loaded_modules and loaded by
        # _seed_and_autoload_modules; loading config['plugins'] again here
        # would bring back a plugin the operator `.unload`ed (PLG-4).

        if hasattr(self, 'net_listener'):
            self._create_safe_task(self.net_listener.listen())

        if foreground:
            log.info("Foreground mode: Using console.")
            self.console_session_id = self.partyline.register_console(
                handle='console',
                output_callback=self._console_output
            )
        else:
            log.info("Going to background..")

        await self.botnet.start()
        # Periodic jobs (NET-9): registered after the plugins (their
        # register_timer tasks wait for this start) and the botnet.
        await self._register_core_tasks()
        self.tasks.start()
        
        # Start event poller thread
        poller_thread = threading.Thread(target=self.event_poller, daemon=True)
        poller_thread.start()
        self._poller_thread = poller_thread
        # A Core that starts after the IRC process (relaunch, .rehash) gets
        # no READY or JOIN: ask IRC for its state and a channel resync.
        self.send_irc({'cmd': 'state'})
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
            log.error("Invalid event type received: %s", type(event).__name__)
            return
        
        etype = event.get('type', 'UNKNOWN')
        # IRC-fallback DCC (SAST-010) first: its login answers carry a
        # password and its session input belongs to the partyline, so neither
        # may reach the debug log, plugins, games or the IRC command layer.
        if etype == 'PRIVMSG' and self.dcc and await self.dcc.on_privmsg(event):
            return
        # IRC-7: the bot's own private-message flood limit; a flooding host
        # is dropped here (before plugins, games and commands) and ignored.
        # A private NOTICE (game input, GAM-6) counts the same way.
        if etype in ('PRIVMSG', 'NOTICE') and await flood.for_core(self).private(event):
            return
        # SAST-001: the channel flood decision for public text is made here,
        # before plugins (pubcom, url, ...) and games; a flooding host's
        # PUBMSG/ACTION/channel NOTICE never reaches any of them.
        if etype in PUBLIC_TEXT_EVENTS and await self._public_flood_gate(etype, event):
            return
        # SAST-002: metadata only (type, nick, channel/target, text length),
        # never the text: a PRIVMSG may be `identify <password>`.
        log.debug("Dispatching: %s", event_summary(etype, event))
        if etype == 'KICK' and 'kicked_uhost' not in event:
            # PLG-7: the victim's user@host, from the live member list
            # (looked up before on_kick removes the member).
            chan = self.get_chan(event.get('channel', '') or '')
            event['kicked_uhost'] = (chan.hosts.get((event.get('kicked') or '').lower(), '')
                                     if chan else '')
        await self.plugin.dispatch(etype, event)
        handler = self.handlers.get(etype)
        if handler:
            await handler(event)
        else:
            log.warning(f"Unhandled event type: {etype}")
    
    async def on_bot_public_ip(self, event: dict):
        ip = event['ip']
        self.public_ip = ip
        log.info(f"[Core] Public IP: {ip}")
        if self.dcc:
            self.dcc.set_detected_public_ip(ip)

    async def on_irc_pong(self, event: Dict[str, Any]):
        """Handle PONG reply to measure lag."""
        sent = self._lag_ping_sent
        if sent is not None:
            self._last_lag_ms = (time.time() * 1000) - sent
            self._lag_ping_sent = None
            log.debug(f"Lag: {self._last_lag_ms:.1f}ms")

    async def on_partyline_input(self, event: dict):
        """Forward partyline input to Partyline manager."""
        session_id = event['session_id']
        text = event['text']
        await self.partyline.handle_input(session_id, text)

    async def on_bot_connect(self, event: dict):
        bot_name = event['handle']
        conn_key = event.get('conn_id') or bot_name.lower()
        streams = self.net_listener.claim_stream(conn_key)
        if streams is None:
            log.warning(f"No pending streams for {bot_name}")
            return

        reader, writer = streams

        try:
            await self.botnet.process_incoming(bot_name, event['data'], reader, writer)
            self._create_safe_task(
                self.botnet.read_peer(bot_name, reader, writer),
                name=f"read_peer:{bot_name}"
            )
            log.debug(f"Bot connect handler complete for {bot_name}")

        except Exception as e:
            log.error(f"Bot connect failed for {bot_name}: {e}", exc_info=True)
            # read_peer never started, so this handler still owns the slot.
            if not writer.is_closing():
                writer.close()
            peer_ip = event.get('peer_ip')
            if self.guard and peer_ip:
                self.guard.release(peer_ip)

    async def on_bot_disconnect(self, event: dict):
        handle = event['handle']
        if handle in self.botnet.peers:
            link = self.botnet.peers.pop(handle)
            if not link.writer.is_closing():
                link.writer.close()
                await link.writer.wait_closed()
        key = handle.lower()
        if key in self.bot_sessions:
            del self.bot_sessions[key]
        log.info(f"Bot {handle} unlinked.")
        if hasattr(self, 'partyline'):
            self.partyline.broadcast(f"*** {handle} unlinked")
        # No guard.release() here (SAST-012): an inbound botlink's admission
        # slot is owned and released exactly once by BotnetManager.read_peer
        # (or by on_bot_connect when read_peer never started).  Releasing it
        # here as well would double-free the slot.

    async def on_partyline_connect(self, event: dict):
        """
        Adopt a telnet stream the listener authenticated (SAST-011).

        Ownership: claim_stream() transfers the connection and its admission
        slot to this handler; exactly one task then runs Session.run(), the
        only reader of the socket.  Session.run() always ends by queueing
        PARTYLINE_DISCONNECT, and on_partyline_disconnect() closes the
        writer and releases the slot once.
        """
        handle  = event['handle']
        peer_ip = event.get('peer_ip', 'unknown')
        conn_id = event.get('conn_id')
        streams = self.net_listener.claim_stream(conn_id)
        if not streams:
            log.error(f"No pending stream for {handle} (conn_id={conn_id})")
            return
        reader, writer = streams
        session_id = None
        try:
            response_q = asyncio.Queue()
            session_id = self.partyline.next_id
            self.partyline.next_id += 1
            session = Session(
                session_id=session_id,
                session_type='telnet',
                handle=handle,
                core_q=self.core_q,
                response_q=response_q,
                reader=reader,
                writer=writer,
                peer_ip=peer_ip,
            )
            self.party_sessions[session_id] = session
            self.partyline.sessions[session_id] = {
                'type': 'telnet',
                'handle': handle,
                'queue': response_q,
            }
            session.task = self._create_safe_task(session.run(), name=f"session:{handle}")
        except Exception as e:
            log.error(f"Partyline session setup failed for {handle} ({peer_ip}): {e}")
            if session_id is not None:
                self.party_sessions.pop(session_id, None)
                self.partyline.sessions.pop(session_id, None)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if self.guard:
                self.guard.release(peer_ip)
            return

        self.partyline.broadcast(
            f"*** {handle} joined the partyline (telnet)",
            exclude_session=session_id
        )
        log.info(f"Partyline session {session_id} created for {handle} from {peer_ip}")

    async def on_partyline_disconnect(self, event: dict):
        session_id = event["session_id"]
        session = self.party_sessions.pop(session_id, None)
        peer_ip = getattr(session, "peer_ip", None) if session else None

        if session:
            try:
                if session.writer:
                    session.writer.close()
                    await session.writer.wait_closed()
            except Exception as e:
                log.warning(f"Session {session_id} close failed: {e}")

        if self.partyline and session_id in self.partyline.sessions:
            handle = self.partyline.sessions[session_id]["handle"]
            del self.partyline.sessions[session_id]
            log.info(f"Partyline unregistered {handle}#{session_id}")
            self.partyline.broadcast(f"{handle} left the partyline",
                                    exclude_session=session_id)
        relay = getattr(self.partyline, "relay", None) if self.partyline else None
        if relay is not None:
            # Close any interactive relay owned by this session (SAST-017).
            relay.session_ended(session_id)

        if self.guard and peer_ip:
            self.guard.release(peer_ip)

        log.debug(f"Partyline disconnect complete: {session_id}")

    async def on_dcc_chat_request(self, event: Dict[str, Any]):
        """
        Route DCC CHAT CTCP from irc.py → DCCManager.  `host` is the sender's
        full nick!user@host; DCCManager authorizes it and validates any
        endpoint before any network access (SAST-009).
        """
        nick  = event.get('nick', '')
        host  = event.get('host', '')
        args  = event.get('args', [])
        ip, port, token = parse_chat_args(args)
        # Passive callbacks carry a 6th field (the token we sent; usually
        # numeric, so irc.py's passive_token may be None for them).
        token = event.get('passive_token') or token

        if token:
            # User's client is confirming a passive DCC offer we sent
            self._create_safe_task(
                self.dcc.on_passive_callback(nick, host, token, ip, port),
                name="dcc:passive_callback"
            )
        else:
            # New incoming DCC CHAT request
            self._create_safe_task(
                self.dcc.handle_request(nick, host, args),
                name="dcc:request"
            )

    def event_poller(self):
        """Thread: Poll core_q -> event buffer."""
        while not self.quit_event.is_set():
            try:
                msg = self.core_q.get(timeout=0.1)
                with self._buffer_lock:
                    self._event_buffer.append(msg)
            except mp.queues.Empty:
                pass
            except (OSError, EOFError):
                break

    async def _main_loop(self):
        """Core event loop: drain buffer, handle events, periodic tasks."""
        last_periodic = time.time()
        while not self.quit_event.is_set():
            now = time.time()
            last_periodic = await self._drain_and_dispatch_once(now, last_periodic)
            await asyncio.sleep(0.05)

    async def _main_loop_with_console(self):
        """Foreground: console + child events."""
        self.console = Console(self.partyline, self.console_session_id, "console")
        self._console_task = self._create_safe_task(self.console.run())
        last_periodic = time.time()
        try:
            while not self.quit_event.is_set():
                # Exit if console task ended (e.g. EOF / .die)
                if self._console_task.done():
                    if self._detaching:
                        break
                    if not self.quit_event.is_set():
                        await self._shutdown("Console exited")
                    break

                now = time.time()
                last_periodic = await self._drain_and_dispatch_once(now, last_periodic)
                await asyncio.sleep(0.05)
        finally:
            if self._console_task and not self._console_task.done():
                self._console_task.cancel()
            try:
                await self._console_task
            except (asyncio.CancelledError, Exception):
                pass
            #await self._shutdown("Console exited")
        if self._detaching and not self.quit_event.is_set():
            self._finish_detach()
            await self._main_loop()

    def can_detach(self) -> bool:
        """True if this Core runs the foreground console under a supervisor."""
        return bool(self.foreground and self.sup_q is not None
                    and getattr(self, 'console', None) is not None)

    def request_detach(self) -> None:
        """
        .detach (USR-9): end the console and go to the background.  The
        console loop stops after the current command; _finish_detach then
        moves this process, IRC and the supervisor off the terminal.
        """
        self._detaching = True
        if self.console is not None:
            self.console.running = False
            self.console._stop_event.set()

    def _logfile(self) -> str:
        override = getattr(self.args, 'logfile', None)
        return override or self.config.get('logging', {}).get('file', 'logs/wbs.log')

    def _finish_detach(self) -> None:
        """Release the terminal; telnet, DCC, IRC and the botnet keep running."""
        from .main import detach_stdio
        logfile = self._logfile()
        restore_terminal()
        self.send_irc({'cmd': 'detach_stdio', 'logfile': logfile})
        stdin = sys.stdin
        try:
            sys.stdin = open(os.devnull, 'r')
            if stdin is not None and stdin.fileno() > 2:
                stdin.close()      # the dup'ed tty fd handed over by the supervisor
        except Exception:
            pass
        detach_stdio(logfile, self.config)
        self.foreground = False
        self.console = None
        if self.sup_q is not None:
            try:
                self.sup_q.put_nowait({'cmd': 'detach'})
            except Exception as e:
                log.warning(f"[Core] Could not notify supervisor of detach: {e}")
        log.info("[Core] Detached from the terminal; running in background")

    def _install_signal_handlers(self) -> None:
        """SIGTERM -> graceful _shutdown on this loop (SYS-2)."""
        try:
            loop = asyncio.get_running_loop()
            loop.add_signal_handler(signal.SIGTERM, self._on_sigterm)
        except (NotImplementedError, RuntimeError, ValueError) as e:
            log.warning(f"[Core] Cannot install SIGTERM handler: {e}")

    def _on_sigterm(self) -> None:
        """Queue a quit for the main loop, which runs _shutdown in its own
        task (a separate task would be cancelled when run() returns)."""
        if not self.running:
            return              # already shutting down
        log.info("[Core] SIGTERM received — shutting down gracefully")
        with self._buffer_lock:
            self._event_buffer.appendleft({'cmd': 'quit', 'message': 'Shutting down'})

    async def _shutdown(self, message: str = "Shutting down") -> None:
        """
        Graceful shutdown. Sends IRC QUIT, stops the periodic tasks and
        game/plugin activity, saves game state and checkpoints the DB,
        notifies the supervisor, exits with CLEAN_EXIT_CODE (42) so the
        supervisor knows not to respawn Core.
        """
        if not self.running:
            return
        self.running = False
        self.quit_event.set()
        log.info(f"[Core] Shutdown: {message}")
        try:
            self.send_irc({'cmd': 'quit', 'message': message, 'reply': False})
        except Exception:
            pass
        t0 = time.monotonic()
        try:
            await asyncio.wait_for(self._stop_activity(), timeout=5.0)
        except Exception as e:
            log.warning(f"[Core] Shutdown cleanup incomplete: {e!r}")
        # Leave the IRC process time to put the QUIT on the wire.
        await asyncio.sleep(max(0.0, 1.5 - (time.monotonic() - t0)))
        if self.sup_q is not None:
            try:
                self.sup_q.put_nowait({'cmd': 'quit', 'message': message})
            except Exception:
                pass
        log.info("[Core] Shutdown complete")
        restore_terminal()
        os._exit(CLEAN_EXIT_CODE)

    async def _stop_activity(self) -> None:
        """Shutdown steps after the QUIT (SYS-2): stop tasks, save, close."""
        tasks = getattr(self, 'tasks', None)
        if tasks is not None:
            tasks.stop_all()
        game_mgr = getattr(self, 'game', None)
        for game in list(getattr(game_mgr, 'games', {}).values()):
            try:
                await game.flush_sessions()
            except Exception as e:
                log.error(f"[Core] Saving {getattr(game, 'name', game)} sessions failed: {e}")
        # Cancel everything else still running on this loop and let it end
        # (not the loop's main task, which is running this shutdown).
        current = asyncio.current_task()
        pending = [t for t in asyncio.all_tasks() if t is not current and not t.done()
                   and t is not self._main_task]
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.wait(pending, timeout=2.0)
        await self._close_db()

    async def _close_db(self) -> None:
        """Checkpoint the WAL into the main DB file (nothing left in -wal)."""
        try:
            async with get_db(self.db_path) as db:
                await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            log.info("[Core] Database closed")
        except Exception as e:
            log.warning(f"[Core] Database checkpoint failed: {e}")

    async def on_command(self, event):
        """
        IRC private-message command path (USR-13 / IRC-3 / IRC-15).

        * `identify` belongs to the pubcom plugin (dispatched before this
          handler) and gets no reply here, from anyone.
        * A sender whose hostmask matches no user is ignored silently.
        * F-01a: `settings.msg_commands` (default false) switches the whole
          path off: a recognised sender gets "Access denied.".
        * A recognised user needs +n (host-authenticated /msg commands are
          owner-only), AND a live pubcom `identify` session bound to the same
          handle and the sender's full hostmask (a hostmask match alone never
          runs a command), then the same COMMAND_MIN_FLAGS gate as the partyline;
          handlers get the partyline call shape with a `respond` that answers
          the nick by PRIVMSG.
        """
        nick = event.get('nick', '')
        host = event.get('host', '')
        ident = event.get('ident', '')
        text = event.get('text', '').strip()

        parts = text.split(maxsplit=1)
        if not parts:
            return
        cmd = parts[0].lstrip('.').lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == 'identify' or event.get('handled'):
            # `identify` belongs to the pubcom plugin (never echoed: it
            # carries a password); a plugin that marked the event handled
            # (PLG-9, e.g. seen) has already answered.  No second reply.
            return

        # irc.py sends the full nick!user@host as `host`.
        if '!' in host and '@' in host:
            full_hostmask = host
        else:
            full_hostmask = f"{nick}!{ident}@{host}" if ident else f"{nick}!*@{host}"

        handle = await self.user.match_user(full_hostmask)
        if not handle:
            log.debug("Ignoring private message from unrecognised %s", full_hostmask)
            return

        def reply(msg: str) -> None:
            self.send_cmd('msg', nick, msg)

        # F-01a: /msg commands are off unless the operator turns them on.
        # Strict `is True`: a string such as "false" must not enable them.
        settings = self.config.get('settings')
        if not (isinstance(settings, dict) and settings.get('msg_commands') is True):
            reply("Access denied.")
            return

        # Active (unlocked, not deleted) user holding +n on this bot's subnet
        # (global or local grant) — SAST-004 scope rules.
        if not await self.user.matchattr(handle, "+n", subnet_id=local_subnet_id(self.config)):
            reply("Access denied.")
            return

        # F-01a: a hostmask match is not authentication.  Require the pubcom
        # `identify` (password) session for this nick, bound to this exact
        # hostmask and to the handle the hostmask resolved to.  No second
        # password path here: pubcom owns identify and session binding.
        pubcom = self.plugin.plugins.get("pubcom")
        verify = getattr(pubcom, "verify_session", None)
        session_handle = await verify(nick, full_hostmask, event.get('account')) if verify else None
        if not session_handle or session_handle.lower() != str(handle).lower():
            reply("Access denied.")
            return

        if cmd not in COMMANDS or cmd not in COMMAND_MIN_FLAGS:
            reply(f"Unknown command: .{cmd}")
            return

        required_flag = COMMAND_MIN_FLAGS[cmd]
        if required_flag and not await gate_allows(self, handle, required_flag):
            reply(f"Access denied for .{cmd} (need +{required_flag}).")
            return

        async def respond(msg: str) -> None:
            # One PRIVMSG per line: irc.py flattens newlines into one line.
            for line in str(msg).split('\n'):
                if line.strip():
                    reply(line)

        # Not a partyline session id: session-bound commands (.quit, .relay,
        # .detach) see "no session", and the console bypass never applies.
        session_key = f"irc:{nick}"
        try:
            await COMMANDS[cmd](self, handle, session_key, arg, respond)
        except Exception as e:
            command_error(log, cmd, e)
            reply(f"Error executing .{cmd}")

    async def on_pubmsg(self, event: Dict[str, Any]):
        """Public message: games.  Flood protection (IRC-7) already ran in
        handle_event, before plugins (SAST-001)."""
        nick = event.get('nick', '')
        text = event.get('text', '')
        channel = event.get('channel', '')
        await self.game.dispatch_pubmsg(channel, nick, text, event=event)
        #await self.seen.update_seen(nick, host, channel, 'PUBMSG')

    async def _public_flood_gate(self, etype: str, event: Dict[str, Any]) -> bool:
        """Count channel text for flood protection (IRC-7) and decide it
        before any plugin or game runs (SAST-001).  True = drop the event.

        PUBMSG and CHAN_ACTIVITY(pub) (channel NOTICE/ACTION) are counted
        against flood_pub; an ACTION is not counted again (its CHAN_ACTIVITY
        was) but is dropped while its host is muted.  CHAN_ACTIVITY(ctcp)
        is counted against flood_ctcp and dropped when it triggered action."""
        fp = flood.for_core(self)
        channel = event.get('channel', '') or ''
        nick = event.get('nick', '') or ''
        host = event.get('host', '') or ''
        if etype == 'PUBMSG':
            return await fp.public(channel, nick, host)
        if etype == 'ACTION':
            return await fp.public(channel, nick, host, count=False)
        kind = event.get('kind', '') or ''
        if kind == 'pub':
            return await fp.public(channel, nick, host)
        return await fp.check(kind, channel, nick, host)

    async def on_chan_activity(self, event: Dict[str, Any]):
        """Channel ACTION/NOTICE/CTCP: counted for flood protection only,
        in handle_event's pre-dispatch gate (_public_flood_gate)."""

    async def on_flood_ignore(self, event: Dict[str, Any]):
        """The IRC process stopped a CTCP flood: put the host on the ignore
        list for flood.PRIVATE_IGNORE_SECONDS."""
        mask = event.get('mask', '')
        if mask:
            await flood.add_ignore(self, mask, event.get('source', ''),
                                   event.get('reason', 'flood'))

    async def on_privmsg(self, event: Dict[str, Any]):
        """Private message: treat as potential command from authorized user."""
        event['type'] = 'COMMAND'
        nick = event.get('nick', '')
        text = event.get('text', '')
        await self.game.dispatch_privmsg(nick, text, event=event)
        await self.on_command(event)

    async def on_notice(self, event: Dict[str, Any]):
        """NOTICE from a user to the bot: game input only (GAM-6, werewolf
        night actions).  Never a command, never answered by the core."""
        await self.game.dispatch_notice(event.get('nick', ''), event.get('text', ''),
                                        event=event)

    async def on_invite(self, event: dict):
        """Forward invite notice to partyline."""
        channel = event['channel']
        inviter_nick = event['inviter']
        self.partyline.broadcast(f"Invite to join {channel} by {inviter_nick}")

    async def on_mode(self, event: Dict[str, Any]):
        """
        Process MODE events — update channel tracking including limits.

        Argument consumption rules (target IRCd: UnrealIRCd / InspIRCd):
        +o / -o   op/deop           always takes arg (nick)
        +h / -h   halfop/dehalfop   always takes arg (nick)
        +v / -v   voice/devoice     always takes arg (nick)
        +b / -b   ban mask          always takes arg
        +e / -e   exempt mask       always takes arg
        +I / -I   invite mask       always takes arg
        +k        set key           takes arg (the key string)
        -k        unset key         takes NO arg
        +l        set limit         takes arg (integer)
        -l        unset limit       takes NO arg
        All other chars (+n +t +i +m +s +p etc.) take no arg.
        """
        channel = event.get('channel', '')
        # IRC-8: the bot's own MODE confirms a pending .mode/.op/... request.
        if self._is_me(event.get('nick', '')) and getattr(self, 'ircreq', None) is not None:
            confirmed = event.get('changes')
            if confirmed is None:
                confirmed = parse_mode_changes(event.get('modes', ''), event.get('args', []))
            await self.ircreq.on_mode(channel, [tuple(c) for c in confirmed])
        chan = self.get_chan(channel)
        if not chan:
            return

        changes = event.get('changes')
        if changes is None:
            changes = parse_mode_changes(event.get('modes', ''), event.get('args', []))
        had_op = chan.bot_op
        opped = []
        deopped = 0
        for sign, char, arg in changes:
            adding = sign == '+'
            if char in USER_PREFIX_MODES:
                # IRC-1: ~ & @ % + all tracked; q/a count as op level.
                if not arg:
                    continue
                if adding:
                    chan.add_user_mode(arg, char, self.botname)
                    if char == 'o' and not self._is_me(arg):
                        opped.append(arg)
                else:
                    chan.del_user_mode(arg, char, self.botname)
                    if char == 'o':
                        deopped += 1
            elif char == 'l':
                if adding and arg is not None:
                    try:
                        chan.limit = int(arg)
                    except (ValueError, TypeError):
                        chan.limit = 0
                elif not adding:
                    chan.limit = 0
            elif char == 'k':
                chan.key = (arg or '') if adding else ''
            elif char in 'beI':
                lst = {'b': chan.live_bans, 'e': chan.live_exempts,
                       'I': chan.live_invites}[char]
                if not arg:
                    continue
                if adding and arg not in lst:
                    lst.append(arg)
                elif not adding and arg in lst:
                    lst.remove(arg)
            elif char in 'ntpsim':
                setattr(chan, f'modes_{char}', adding)

        # IRC-6: the bot just got op on a synced channel -> enforce for
        # everyone present; +bitch deops ops nobody is entitled to.
        if chan.synced:
            if chan.bot_op and not had_op:
                await automode.sweep(self, chan)
            if opped:
                await automode.enforce_bitch(self, chan, opped, event.get('nick', ''))
        # IRC-7: deop flood by an op -> deop them (one count per -o).
        setter = event.get('nick', '')
        if deopped and setter and '!' in event.get('host', ''):
            fp = flood.for_core(self)
            for _ in range(deopped):
                if await fp.check('deop', channel, setter, event.get('host', '')):
                    break

    async def on_newchan(self, event: Dict[str, Any]):
        """The bot itself joined a channel: start a fresh live state (IRC-1).
        The IRC process asks the server for NAMES/WHO/MODE right after; the
        channel is marked synced when the WHO list ends."""
        nick = event.get('nick', '') or self.botname
        host = event.get('host', '')
        channel = event.get('channel', '')
        if nick and not self.botname:
            self.botname = nick
        chan = self._mark_joined(channel)
        chan.add_user(nick, host.partition('!')[2])

    async def on_join(self, event: Dict[str, Any]):
        nick    = event.get('nick', '')
        channel = event.get('channel', '')
        chan = self.get_chan(channel)
        if chan:
            chan.add_user(nick, event.get('host', '').partition('!')[2])
            # IRC-7: join flood (per host) before auto-modes.
            if await flood.for_core(self).check('join', channel, nick, event.get('host', '')):
                return
            # IRC-6: auto-op/voice/kick a recognised joiner.  Joins during
            # the bot's own sync are covered by the sweep at WHO end.
            if chan.synced:
                await automode.apply(self, chan, [nick])

    async def on_names_reply(self, event: Dict[str, Any]):
        """353 RPL_NAMREPLY: members as [nick, prefix_modes, user@host]."""
        chan = self.get_chan(event.get('channel', ''))
        if not chan:
            return
        for member in event.get('members', []):
            nick, modes, host = (list(member) + ['', '', ''])[:3]
            if not nick:
                continue
            chan.set_user_modes(nick, modes, self.botname)
            if host:
                chan.hosts[nick.lower()] = host

    async def on_names_end(self, event: Dict[str, Any]):
        chan = self.get_chan(event.get('channel', ''))
        if chan:
            log.debug(f"Channel {chan.name} NAMES: {len(chan.users)} users")

    async def on_irc_state(self, event: Dict[str, Any]):
        """IRC process state after a Core restart (.rehash): the IRC
        connection was kept, so READY does not come again."""
        if event.get('connected'):
            self.connected = True
            self.connected_on = self.connected_on or time.time()
        if event.get('botname'):
            self.botname = event['botname']
        if not event.get('connected'):
            return
        # The IRC process already requested NAMES/WHO/MODE for each one.
        for name in event.get('channels', []):
            self._mark_joined(name)

    def _mark_joined(self, channel: str) -> 'Channel':
        """Fresh live state for a channel the bot is in; synced comes later."""
        norm = self._normalize_chan(channel)
        chan = self.channels.get(norm)
        if chan is None:
            chan = Channel(name=norm)
            chan._chan_mgr = self.chan
            self.channels[norm] = chan
        chan.clear_state()
        chan.joined = True
        if self.botname:
            chan.add_user(self.botname)
        return chan

    def live_channel(self, channel: str) -> Optional['Channel']:
        """Live state of a channel the bot is in now, else None (IRC-2).
        Check `.synced` before trusting the member list."""
        chan = self.get_chan(channel)
        if chan is None or not self.connected or not chan.joined:
            return None
        return chan

    async def on_irc_numeric(self, event: Dict[str, Any]):
        """A server error numeric the IRC process forwards (IRC-8, IRC-11):
        fails the pending request it belongs to, with the server's reason.
        args by numeric: 401 [nick, text]; 441 [nick, chan, text]; 472
        [letter, text]; 432/433 [nick, text]; 696 [chan, mode, param, text];
        403/442/467/477/482 [chan, text]."""
        numeric = str(event.get('numeric', ''))
        args = list(event.get('args') or [])
        channel = nick = letter = ''
        text = args[-1] if len(args) > 1 else ''
        if numeric in ('401', '432', '433'):
            nick = args[0] if args else ''
        elif numeric == '441':
            nick, channel = (args + ['', ''])[:2]
        elif numeric == '472':
            letter = args[0] if args else ''
        elif args:
            channel = args[0]
        reqs = getattr(self, 'ircreq', None)
        if reqs is not None:
            if not await reqs.on_error(numeric, channel=channel, nick=nick, text=text, letter=letter) \
                    and numeric == '401':
                # "No such nick" for a .swhois/.swhowas (IRC-10)
                await reqs.on_whois_numeric('401', args)

    async def on_whois_numeric(self, event: Dict[str, Any]):
        """WHOIS/WHOWAS numerics for a pending .swhois/.swhowas (IRC-10)."""
        reqs = getattr(self, 'ircreq', None)
        if reqs is not None and reqs.pending:
            await reqs.on_whois_numeric(str(event.get('numeric', '')), event.get('args') or [])

    async def on_irc_timers(self, event: Dict[str, Any]):
        """The IRC process's answer to a `.timers` request (NET-9)."""
        reqs = getattr(self, 'ircreq', None)
        if reqs is not None and reqs.pending:
            await reqs.on_timers(event.get('req_id'), event.get('timers') or [])

    def _is_me(self, nick: str) -> bool:
        return bool(nick) and bool(self.botname) and nick.lower() == self.botname.lower()

    async def on_part(self, event: Dict[str, Any]):
        nick    = event.get('nick', '')
        channel = event.get('channel', '')
        if self._is_me(nick):
            if self.channels.pop(self._normalize_chan(channel), None) is not None:
                log.info(f"Bot parted {channel}")
            return
        chan = self.get_chan(channel)
        if chan:
            chan.remove_user(nick)

    async def on_kick(self, event: Dict[str, Any]):
        kicked_nick = event.get('kicked', '')
        channel     = event.get('channel', '')
        if self._is_me(kicked_nick):
            if self.channels.pop(self._normalize_chan(channel), None) is not None:
                log.info(f"Bot was kicked from {channel}")
            return
        chan = self.get_chan(channel)
        if chan:
            chan.remove_user(kicked_nick)
            # IRC-7: kick flood by an op -> deop.
            await flood.for_core(self).check('kick', channel, event.get('nick', ''),
                                             event.get('host', ''))

    async def on_quit(self, event: Dict[str, Any]):
        nick = event.get('nick', '')
        if self._is_me(nick):
            self.channels.clear()
            self.dcc.reset("bot quit IRC")
            return
        for chan in self.channels.values():
            chan.remove_user(nick)
        # A quit nick can be taken by anyone: its pending DCC offers expire.
        self.dcc.forget_nick(nick)

    async def on_nick(self, event: Dict[str, Any]):
        old_nick = event.get('old_nick', '')
        new_nick = event.get('new_nick', '')
        if self._is_me(old_nick):
            self.botname = new_nick
            log.info(f"Bot nick changed: {old_nick} → {new_nick}")
            if getattr(self, 'ircreq', None) is not None:
                await self.ircreq.on_nick(new_nick)
        for chan in self.channels.values():
            chan.rename_user(old_nick, new_nick)
        # IRC-7: nick flood, counted per host on every channel shared.
        if not self._is_me(new_nick):
            fp = flood.for_core(self)
            for chan in list(self.channels.values()):
                if new_nick.lower() in chan.users:
                    await fp.check('nick', chan.name, new_nick, event.get('host', ''))
        # Pending DCC offers are bound to the requesting nick (SAST-009).
        self.dcc.forget_nick(old_nick)
        self.dcc.forget_nick(new_nick)

    async def on_topic(self, event: Dict[str, Any]):
        channel = event.get('channel', '')
        chan = self.get_chan(channel)
        if chan:
            chan.topic = event.get('topic', '')
            log.debug(f"Topic changed on {channel}: {chan.topic}")

    async def on_who_reply(self, event: Dict[str, Any]):
        """
        One WHO reply line: member, user@host and prefix modes.
        These arrive after the bot joins and sends WHO #channel.
        """
        channel  = event.get('channel', '')
        nick     = event.get('nick', '')
        chan = self.get_chan(channel)
        if not chan or not nick:
            return

        modes = event.get('modes')
        if modes is None:   # older IRC process: booleans only
            modes = (('o' if event.get('is_op') else '')
                     + ('h' if event.get('is_halfop') else '')
                     + ('v' if event.get('is_voice') else ''))
        chan.set_user_modes(nick, modes, self.botname)
        if event.get('user') and event.get('host'):
            chan.hosts[nick.lower()] = f"{event['user']}@{event['host']}"

    async def on_who_end(self, event: Dict[str, Any]):
        """
        WHO response complete — mark channel as synced.
        """
        channel = event.get('channel', '')
        chan = self.get_chan(channel)
        if chan and chan.joined:
            first = not chan.synced
            chan.synced = True
            log.info(f"Channel {channel} WHO sync complete: "
                    f"{len(chan.users)} users, {len(chan.ops)} ops, "
                    f"{len(chan.halfops)} halfops, {len(chan.voiced)} voiced")
            # IRC-6: once per sync (join, reconnect, new Core), enforce
            # auto-modes for the users already in the channel.
            if first:
                await automode.sweep(self, chan)

    async def on_ready(self, event: Dict[str, Any]):
        """IRC connection established: join channels."""
        self.connected = True
        self.connected_on = time.time()
        self.botname = event.get('botname')
        self._irc_respawn_delay = 5.0
        self.dcc.reset("new IRC connection")
        # New connection: nothing from the old one is valid (IRC-1).  Each
        # channel resyncs when the bot's own JOIN comes back.
        for chan in self.channels.values():
            chan.clear_state()
        log.info("IRC READY - joining channels..")
        subnet_id = self.config.get('botnet', {}).get('subnet_id', None)
        channels = await self.chan.getchans(subnet_id=subnet_id)
        self._create_safe_task(self._join_channels(channels))
        await self._autoload_games()

    async def _join_channels(self, channels: list):
        """Throttled channel join sequence."""
        for channel in channels:
            if channel is not None:
                log.info(f"Joining {channel}..")
                self.send_irc({'cmd': 'join', 'channel': channel})
                await asyncio.sleep(0.2)

    async def on_disconnect(self, event: Dict[str, Any]):
        """IRC connection dropped."""
        self.connected = False
        self.dcc.reset("IRC disconnected")
        for chan in self.channels.values():
            chan.clear_state()   # mark all as unsynced; keeps Channel objects for rejoin
        log.info("IRC disconnected — channel live state cleared")


    async def on_332(self, event):  # CHANNEL_TOPIC
        """Update topic from RPL_TOPIC"""
        channel = event['channel']
        chan = self.get_chan(channel)
        self.get_chan(channel)
        if chan:
            chan.topic = event['topic']
            log.debug(f"Topic updated for {event['channel']}")

    async def on_333(self, event: Dict[str, Any]):
        chan = self.get_chan(event.get('channel', ''))
        if chan:
            chan.topic_set_by = event.get('setter', '')
            chan.topic_set_at = event.get('timestamp', 0)

    async def on_324(self, event):  # CHANNEL_MODES
        """Parse/set modes from RPL_CHANNELMODEIS"""
        channel = event['channel']
        chan = self.get_chan(channel)
        if chan:
            parts = (event.get('modes_str') or '').split()
            if parts:
                # Same parser as live MODE lines; 324 only lists set modes.
                await self.on_mode({'channel': channel, 'modes': parts[0],
                                    'args': parts[1:],
                                    'changes': event.get('changes')})
            log.debug(f"{channel} modes: n={chan.modes_n} t={chan.modes_t} l={chan.limit}")

    async def on_329(self, event):  # CHANNEL_CREATED
        """Set creation timestamp"""
        channel = event['channel']
        chan = self.get_chan(channel)
        self.get_chan(channel)
        if chan:
            chan.created = event['created']
            log.debug(f"{event['channel']} created: {event['created']}")

    async def on_367(self, event):  # BANLIST_ADD
        """Add ban to list"""
        channel = event['channel']
        chan = self.get_chan(channel)
        if chan and event.get('ban') and event['ban'] not in chan.live_bans:
            chan.live_bans.append(event['ban'])

    async def on_346(self, event):  # INVITELIST_ADD
        """Add invite to list"""
        channel = event['channel']
        chan = self.get_chan(channel)
        if chan and event.get('invite') and event['invite'] not in chan.live_invites:
            chan.live_invites.append(event['invite'])

    async def on_348(self, event):  # EXEMPTLIST_ADD
        """Add exempt to list"""
        channel = event['channel']
        chan = self.get_chan(channel)
        if chan and event.get('exempt') and event['exempt'] not in chan.live_exempts:
            chan.live_exempts.append(event['exempt'])       

    async def _request_botnet_action(self, cmd: str, channel: str) -> None:
        """Broadcast a single-channel request to all connected botnet peers."""
        if self.botnet and self.botnet.peers:
            await self.botnet.broadcast({
                'cmd':     cmd,
                'channel': channel,
                'target':  self.botname,
            })
            log.info(f"Broadcasted {cmd} for {channel} to botnet peers")  

    async def on_471(self, event: Dict[str, Any]):
        channel = event.get('channel', '')
        log.warning(f"Cannot join {channel}: channel is full (+l).")
        self.partyline.broadcast(
            f"*** Cannot join {channel}: channel full (+l) — "
            f"requesting a linked bot to raise the limit"
        )
        await self._request_botnet_action('REQUEST_LIMIT_RAISE', channel)

    async def on_473(self, event: Dict[str, Any]):
        channel = event.get('channel', '')
        log.warning(f"Cannot join {channel}: invite only (+i).")
        self.partyline.broadcast(
            f"*** Cannot join {channel}: invite only (+i) — "
            f"requesting a linked bot to send an invite"
        )
        await self._request_botnet_action('REQUEST_INVITE', channel)

    async def on_474(self, event: Dict[str, Any]):
        channel = event.get('channel', '')
        log.warning(f"Cannot join {channel}: I am banned.")
        self.partyline.broadcast(
            f"*** Cannot join {channel}: bot is banned — "
            f"requesting a linked bot to remove the ban"
        )
        await self._request_botnet_action('REQUEST_UNBAN', channel)                                     

    async def request_botlinks(self, event: dict):
        """Merge botnet.peers + user flags"""
        botnet_peers = self.botnet.peers  # Dict[BotLink]
        
        linked_bots = {}
        for link in botnet_peers.values():
            linked_bots[link.name] = link.nick
        self.send_irc({'cmd': 'UPDATE_BOTLINK', 'botlinks': linked_bots})

    async def on_null(self, event: Dict[str, Any]) -> None:
        """Intentional no-op handler for list/end numeric replies (BANLIST_END, INVITELIST_END, EXCEPTLIST_END)."""
        pass

    async def on_error(self, event: Dict[str, Any]):
        """IRC error occurred."""
        error_msg = event.get('data', 'Unknown error')
        if error_msg == "disconnect":
            pass
        else:
            log.error(f"IRC error: {error_msg}")

    def send_irc(self, payload: dict) -> None:
        """
        Single point of entry for all IRC queue writes.
        Always resolves self.irc_q at call time — safe across respawns.
        """
        try:
            self.irc_q.put_nowait(payload)
        except Exception as e:
            log.warning("[Core] IRC queue write dropped: %s — %s",
                        type(e).__name__, irc_cmd_summary(payload))

    def send_cmd(self, cmd_type: str, target: str, text: str = "", **kwargs) -> None:
        self.send_irc({'cmd': cmd_type, 'target': target, 'text': text, **kwargs})

    async def _periodic_tasks(self):
        """Every 5 s from the main loop: only the supervisor watchdog, which
        must never be switched off.  The other periodic jobs are registry
        tasks (see _register_core_tasks, `.tasks`)."""
        if hasattr(self, 'botnet') and self.botnet:
            if hasattr(self.botnet, 'poll_queues'):
                await self.botnet.poll_queues()

        current_ppid = os.getppid()
        if current_ppid != self._supervisor_ppid or current_ppid == 1:
            log.warning(f"Supervisor gone (ppid {self._supervisor_ppid} → {current_ppid}) — self-terminating")
            restore_terminal()
            await self._shutdown("Supervisor gone")

    async def _task_flood_expire(self):
        # IRC-7: lift temporary flood bans that are due.
        fp = getattr(self, 'flood', None)
        if fp is not None:
            fp.expire_bans()

    async def _task_ircreq_expire(self):
        # IRC-8/IRC-11: end .mode/.op/.nick/.timers requests never answered.
        reqs = getattr(self, 'ircreq', None)
        if reqs is not None and reqs.pending:
            await reqs.expire()

    async def _task_lag_check(self):
        if self.connected and self._lag_ping_sent is None:
            now = time.time()
            self._lag_ping_sent = time.time() * 1000
            self._last_lag_ping = now
            self.send_irc({'cmd': 'ping', 'token': f'LAG{int(now)}'})

    async def _task_autolink(self):
        if self.botnet is not None and self.botnet.running:
            await self.botnet.autolink._tick()

    async def _task_update_check(self):
        manifest = await self.update.check_update()
        err = getattr(self.update, 'last_error', None)
        if err:
            raise RuntimeError(err)
        if manifest:
            self.partyline.broadcast(
                f"*** Update available: {manifest.version_str} (use .update to install)")

    async def _register_core_tasks(self):
        """The Core's periodic jobs (NET-9), with their saved `.taskset`
        overrides applied."""
        reg = self.tasks
        await reg.load()
        reg.register('autolink', self._task_autolink, 5,
                     "connect autolink (+a) peers that are down, per-peer retry", first_delay=5)
        reg.register('ircreq_expire', self._task_ircreq_expire, 5,
                     "time out unanswered .mode/.op/.nick/.swhois/.timers requests",
                     can_disable=False)
        reg.register('flood_unban', self._task_flood_expire, 5,
                     "lift expired temporary flood bans")
        reg.register('lag_check', self._task_lag_check, 30,
                     "PING the IRC server to measure lag")
        # GAM-6: game timers (lottery daily draw); errors are logged by the
        # registry and by GameManager.tick, never fatal.
        reg.register('game_tick', self.game.tick, 2,
                     "run the loaded games' on_tick (lottery draw)", first_delay=2,
                     can_disable=False)
        has_host = bool((self.config.get('update') or {}).get('host'))
        reg.register('update_check', self._task_update_check, 6 * 3600,
                     "check the signed update manifest, announce new versions",
                     enabled=has_host)   # nothing to check without update.host

    async def register_timer(self, name: str, callback, interval: float, randomize: bool = False):
        """A plugin's Core timer: a registry task (listed by `.tasks`),
        first run at once, then every `interval` seconds (+/-30 s jitter
        with randomize)."""
        self.tasks.register(name, callback, interval, "plugin timer",
                            first_delay=0, jitter=30 if randomize else 0)

    def unregister_timer(self, name: str):
        self.tasks.unregister(name)
    
    async def call_later(self, delay: float, callback):
        """One-shot timer"""
        await asyncio.sleep(delay)
        await callback()

    async def on_irc_timer_fired(self, event):
        """Forward IRC timer + full context to plugins"""
        timer_name = event['timer_name']
        irc_data = event['irc_data']
        
        # Update core's IRC state
        self.connected = irc_data.get('connected', False)
        self.botname = irc_data.get('botname') or self.botname
        
        # Membership/modes come from live events (IRC-1); the snapshot only
        # reconciles which channels the bot is in.  A channel Core does not
        # know as joined gets a full resync instead of the library's
        # partial view (which has no hosts and would reset `synced`).
        channels_data = irc_data.get('channels', {})
        current = {self._normalize_chan(c): c for c in channels_data}
        if self.connected:
            for norm, raw in current.items():
                chan = self.channels.get(norm)
                if chan is None or not chan.joined:
                    self._mark_joined(raw)
                    self.send_irc({'cmd': 'resync', 'channel': raw})

        # Remove channels the IRC process is no longer in
        for chan_name in list(self.channels.keys()):
            if chan_name not in current:
                del self.channels[chan_name]
        
        log.debug(f"Core state: connected={self.connected}, "
                f"botname={self.botname}, channels={list(self.channels.keys())}")
        
        # Dispatch to plugins
        await self.plugin.dispatch(f"IRC_TIMER_{timer_name.upper()}", {
            'type': f"IRC_TIMER_{timer_name.upper()}",
            'irc_data': irc_data
        })

    def _normalize_chan(self, channel: str) -> str:
        """Ensure channel has # prefix and is lowercase."""
        if not channel.startswith(('#', '&', '!', '+')):
            channel = f'#{channel}'
        return channel.lower()

    def on_chan(self, channel: str) -> bool:
        """Check if the bot is on a channel."""
        return self._normalize_chan(channel) in self.channels

    def bot_isop(self, channel: str) -> bool:
        """Check if the bot has op status on a channel."""
        chan = self.channels.get(self._normalize_chan(channel))
        if not chan:
            return False
        return chan.bot_op  # use the dedicated bool, avoid scanning ops list

    def nick_isop(self, nick: str, channel: str) -> bool:
        """Check if a nick has op status on a channel."""
        chan = self.channels.get(self._normalize_chan(channel))
        if not chan:
            return False
        return chan.is_op(nick)  # uses lowercase-safe method

    def nick_isvoice(self, nick: str, channel: str) -> bool:
        """Check if a nick has voice status on a channel."""
        chan = self.channels.get(self._normalize_chan(channel))
        if not chan:
            return False
        return chan.is_voiced(nick)

    def chan_modes(self, channel: str) -> str:
        """Get current channel mode string (e.g. '+ntm')."""
        chan = self.channels.get(self._normalize_chan(channel))
        if not chan:
            return ''
        # Build mode string from the bool flags on the dataclass
        active = [m for m in 'ntpsim' if getattr(chan, f'modes_{m}', False)]
        mode_str = '+' + ''.join(active) if active else ''
        if chan.limit:
            mode_str += 'l'
        if chan.key:
            mode_str += 'k'
        return mode_str
    
    async def _autoload_modules(self):
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT name, type, scope, owner FROM loaded_modules WHERE autoload=1"
            ) as cursor:
                rows = await cursor.fetchall()

        for row in rows:
            try:
                if row["type"] == "plugin":
                    await self.plugin.load_plugin(row["name"])
                    #log.info("Autoloaded plugin: %s", row["name"])
                elif row["type"] == "game":
                    await self.game.load_game(row["name"])
                    #log.info("Autoloaded game: %s", row["name"])
            except Exception as e:
                log.error("Autoload failed for %s %s: %s", row["type"], row["name"], e)

    async def _seed_modules(self):
        async with get_db(self.db_path) as db:
            for plugin_name in self.config.get('plugins', []):
                await db.execute(
                    "INSERT INTO loaded_modules(name, type, scope, autoload) VALUES(?, 'plugin', NULL, 1) "
                    "ON CONFLICT(name, type) DO NOTHING",
                    (plugin_name,)
                )

    async def _autoload_games(self):
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT DISTINCT game_name FROM game_sessions WHERE state='running'"
            ) as cursor:
                game_rows = await cursor.fetchall()

            game_names = [row["game_name"] for row in game_rows]
            if not game_names:
                return

            placeholders = ",".join("?" * len(game_names))
            async with db.execute(
                f"SELECT game_name, scope, target, owner, data FROM game_sessions "
                f"WHERE game_name IN ({placeholders}) AND state='running'",
                game_names
            ) as cursor:
                session_rows = await cursor.fetchall()

        from collections import defaultdict
        sessions_by_game = defaultdict(list)
        for s in session_rows:
            sessions_by_game[s["game_name"]].append(s)

        for game_name in game_names:
            try:
                await self.game.load_game(game_name)
                for s in sessions_by_game[game_name]:
                    await self.game.start_game(
                        game_name, s["scope"], s["target"],
                        owner=s["owner"],
                        restore=True,
                    )
                    log.info(
                        "Restored game session: %s on %s:%s",
                        game_name, s["scope"], s["target"]
                    )
            except Exception as e:
                log.error("Failed to restore game %s: %s", game_name, e)

    async def do_rehash(self) -> None:
        """
        Soft rehash: replace Core only. IRC stays connected.
        Equivalent to Eggdrop's SIGHUP/.rehash — no IRC disconnect.

        Core exits with REHASH_EXIT_CODE; the supervisor re-reads the config
        and starts a fresh Core (freshly imported code) on the same queues,
        so the IRC process and its connection are kept (USR-16).  Core used
        to os.execv() the supervisor's argv, which handed `-f` to the Python
        interpreter ("Unknown option: -f") and fell back to a respawn.
        """
        log.info("[Core] Rehashing — restarting Core, IRC preserved")
        if self.sup_q is None:
            log.error("[Core] Rehash needs the supervisor; not running under one")
            return
        self.partyline.broadcast("*** Rehashing...")
        # Cancel plugin tasks, flush DB
        await self._pre_exec_cleanup()
        self._handoff_events()
        restore_terminal()
        os._exit(REHASH_EXIT_CODE)

    def _handoff_events(self) -> None:
        """Stop the core_q poller and put unhandled events back for the next Core."""
        self.quit_event.set()
        if self._poller_thread is not None:
            self._poller_thread.join(timeout=1.0)
        with self._buffer_lock:
            pending = list(self._event_buffer)
            self._event_buffer.clear()
        for event in pending:
            try:
                self.core_q.put_nowait(event)
            except Exception:
                break
        if pending:
            # Flush the queue's feeder thread before os._exit drops it.
            try:
                self.core_q.close()
                self.core_q.join_thread()
            except Exception:
                pass

    async def do_restart(self) -> None:
        """
        Full restart: gracefully quit IRC, then ask the supervisor to kill and
        respawn both Core and IRC with a fresh interpreter (new module imports).
        Core exits cleanly; supervisor sentinel loop detects the exit and acts.
        """
        log.info("[Core] Restart requested — notifying supervisor")
        self.partyline.broadcast("*** Restarting...")
        try:
            self.send_irc({'cmd': 'quit', 'message': 'Restarting...', 'reply': False})
        except Exception as e:
            log.warning(f"[Core] Could not send IRC QUIT: {e}")
        await asyncio.sleep(2.0)
        if self.sup_q is not None:
            try:
                self.sup_q.put_nowait({'cmd': 'restart', 'message': 'Operator requested restart'})
            except Exception as e:
                log.warning(f"[Core] Could not notify supervisor of restart: {e}")
        await self._pre_exec_cleanup()
        restore_terminal()
        os._exit(0)

    async def _pre_exec_cleanup(self) -> None:
        """Flush state before re-exec or exit."""
        self.running = False
        self.tasks.stop_all()
        await asyncio.sleep(0.3)

    async def _drain_and_dispatch_once(self, now: float, last_periodic: float) -> float:
        """Drain buffered events, dispatch them, and run periodic tasks."""
        events = []
        with self._buffer_lock:
            while self._event_buffer:
                events.append(self._event_buffer.popleft())

        for event in events:
            if isinstance(event, dict) and event.get('cmd') == 'quit':
                await self._shutdown(event.get('message', 'Quit'))
                return last_periodic
            if not isinstance(event, dict):
                log.error("Invalid event type received: %s", type(event).__name__)
                continue
            await self.handle_event(event)

        # Periodic tasks (5s)
        if now - last_periodic >= 5.0:
            await self._periodic_tasks()
            last_periodic = now

        return last_periodic

    def get_chan(self, channel: str) -> Optional['Channel']:
        """Normalized channel lookup. Always use this instead of self.channels.get(channel)."""
        return self.channels.get(self._normalize_chan(channel))

    def _create_safe_task(self, coro, *, name: str = "unnamed") -> asyncio.Task:
        """Schedule a coroutine as a tracked task; logs exceptions instead of swallowing them."""
        loop = asyncio.get_event_loop()
        task = loop.create_task(coro, name=name)

        def _on_done(t: asyncio.Task) -> None:
            if not t.cancelled() and t.exception() is not None:
                log.error("Task '%s' raised an exception", name, exc_info=t.exception())

        task.add_done_callback(_on_done)
        return task
    
    def _task_done_callback(self, task: asyncio.Task) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            self._logger.error("Task %s raised an exception: %s", task.get_name(), exc, exc_info=True)
    
    async def _seed_and_autoload_modules(self):
        """Seed configured plugins to DB, then autoload all flagged modules. Single connection."""
        async with get_db(self.db_path) as db:
            # Seed phase
            for plugin_name in self.config.get('plugins', []):
                await db.execute(
                    "INSERT INTO loaded_modules(name, type, scope, autoload) VALUES(?, 'plugin', NULL, 1) "
                    "ON CONFLICT(name, type) DO NOTHING",
                    (plugin_name,)
                )
            # Autoload phase
            async with db.execute(
                "SELECT name, type, scope, owner FROM loaded_modules WHERE autoload=1"
            ) as cursor:
                rows = await cursor.fetchall()

        for row in rows:
            try:
                if row["type"] == "plugin":
                    await self.plugin.load_plugin(row["name"])
                elif row["type"] == "game":
                    await self.game.load_game(row["name"])
            except Exception as e:
                log.error("Autoload failed for %s %s: %s", row["type"], row["name"], e)    

def core_process_launcher(config, config_path, args, core_q, irc_q, sup_q):
    """Entry point for Core as a supervised child process."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # SIGTERM keeps the default (die) until Core.run() installs its
    # graceful handler (SYS-2); an ignored SIGTERM always ended in SIGKILL.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)

    tty_fd = config.pop('_tty_fd', None)
    if tty_fd is not None:
        try:
            sys.stdin = os.fdopen(tty_fd, 'r')
        except Exception as e:
            log.warning(f"Could not restore TTY fd {tty_fd}: {e}")

    core = Core(config=config, config_path=config_path, args=args, core_q=core_q, irc_q=irc_q, sup_q=sup_q)
    asyncio.run(core.run(foreground=getattr(args, 'foreground', False)))