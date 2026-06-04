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
import random
import signal
from pathlib import Path
from typing import Dict, Any, Optional
from collections import deque

from .net import AccessGuard
from .net import NetListener
from .channel import ChannelManager, Channel
from .user import UserManager
from .bot import BotManager
from .botnet import BotnetManager
from .console import Console
from .partyline import Partyline
from .session import Session
from .plugins import PluginManager
from .games import GameManager
from .dcc import DCCManager
from .update import UpdateManager
from .db import init_db, get_db
from .commands import COMMANDS
from .helper import restore_terminal

log = logging.getLogger("wbs.core")
BASE_DIR = Path(__file__).parent.parent
_AUTH_TIMEOUT = 20
CLEAN_EXIT_CODE = 42

class Core:
    """Main process: Core event loop + child process manager."""
    
    def __init__(self, config: dict, config_path: str, args, core_q=None, irc_q=None, sup_q=None):
        self.config      = config
        self.config_path = config_path
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
        self.net_listener = NetListener(self.core_q, config=self.config, access_guard=self.guard)
        self.user = UserManager(self.db_path)
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
        self.channels = {} # chan_name -> Channel object
        self.dcc_sessions = {}
        self.party_sessions = {}
        self.bot_sessions = {} 
        self.event_handlers = {}  # type → [plugins]
        self.timers = {}  # name → task
        self._console_task = None
        self.foreground = False
        self._lag_ping_sent: float | None = None
        self._last_lag_ms: float = 0.0
        self._last_lag_ping: float = 0.0
        self.public_ip: Optional[str] = None
        self.botnet.guard = self.net_listener.guard
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
            'ON_INVITE': self.on_invite,
            'NEWCHAN': self.on_newchan,
            'JOIN': self.on_join,
            'PART': self.on_part,
            'KICK': self.on_kick,
            'QUIT': self.on_quit,
            'MODE': self.on_mode,
            'NICK': self.on_nick,
            'READY': self.on_ready,
            'DISCONNECT': self.on_disconnect,
            'IRC_TIMER_FIRED': self.on_irc_timer_fired,
            'REQUEST_BOTLINKS': self.request_botlinks,
            'ERROR': self.on_error,
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
        log.info(f"Initializing core with db_path={self.db_path}")
        await self._async_init()
        
        for plugin_name in self.config.get('plugins', []):
            try:
                await self.plugin.load_plugin(plugin_name)
                log.debug(f"Auto-loaded plugin: {plugin_name}")
            except Exception as e:
                log.error(f"Failed auto-load {plugin_name}: {e}")

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
        log.debug(f"Dispatching: {etype} - {event}")
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
            self.dcc.public_ip = ip

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
        streams = self.net_listener._pending_streams.pop(bot_name.lower(), None)
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
            if not writer.is_closing():
                writer.close()

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
        peer_ip = event.get('peer_ip', 'unknown')
        if self.guard and peer_ip != 'unknown':
            self.guard.release(peer_ip)    

    async def on_partyline_connect(self, event: dict):
        handle  = event['handle']
        peer_ip = event.get('peer_ip', 'unknown')
        conn_id = event.get('conn_id')
        streams = self.net.listener._pending_streams.pop(conn_id, None)
        if not streams:
            log.error(f"No pending stream for {handle} (conn_id={conn_id})")
            return
        reader, writer = streams
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
        )
        self.party_sessions[session_id] = session
        self.partyline.sessions[session_id] = {
            'type': 'telnet',
            'handle': handle,
            'queue': response_q,
        }
        self.partyline.broadcast(
            f"*** {handle} joined the partyline (telnet)",
            exclude_session=session_id
        )
        log.info(f"Partyline session {session_id} created for {handle} from {peer_ip}")
        asyncio.create_task(session.run())

        async def _run_with_timeout():
            try:
                async with asyncio.timeout(_AUTH_TIMEOUT):
                    await session.run()
                # Clean exit — on_partyline_disconnect fires and calls release there
            except asyncio.TimeoutError:
                log.warning(f"Auth timeout: {handle} ({peer_ip}) — evicting")
                if self.guard:
                    await self.guard.record_failure(peer_ip)
                    self.guard.release(peer_ip)       # ← direct call, no closure
                self.party_sessions.pop(session_id, None)
                self.partyline.sessions.pop(session_id, None)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        self._create_safe_task(_run_with_timeout(), name=f"session:{handle}")

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

        if self.guard and peer_ip:
            self.guard.release(peer_ip)

        log.debug(f"Partyline disconnect complete: {session_id}")

    async def on_dcc_chat_request(self, event: Dict[str, Any]):
        """Route DCC CHAT CTCP from irc.py → DCCManager."""
        nick  = event.get('nick', '')
        host  = event.get('host', '')
        args  = event.get('args', [])
        token = event.get('passive_token')   # None for new requests

        if token:
            # User's client is confirming a passive/reverse DCC offer we sent
            try:
                ip_int = int(args[-3]) if len(args) >= 4 else 0
                port   = int(args[-2]) if len(args) >= 4 else 0
            except (ValueError, IndexError):
                ip_int, port = 0, 0
            self._create_safe_task(
                self.dcc.on_passive_callback(nick, token, ip_int, port)
            )
        else:
            # New incoming DCC CHAT request
            self._create_safe_task(
                self.dcc.handle_request(nick, host, args)
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
        self._console_task = self._create_safe_task(
            Console(self.partyline, self.console_session_id, "console").run()
        )
        last_periodic = time.time()
        try:
            while not self.quit_event.is_set():
                # Exit if console task ended (e.g. EOF / .die)
                if self._console_task.done():
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

    async def _shutdown(self, message: str = "Shutting down") -> None:
        """
        Graceful shutdown. Sends IRC QUIT, notifies supervisor, exits with
        CLEAN_EXIT_CODE (42) so the supervisor knows not to respawn Core.
        """
        if not self.running:
            return
        self.running = False
        self.quit_event.set()
        log.info(f"[Core] Shutdown: {message}")
        try:
            self.send_irc({'cmd': 'quit', 'message': message})
        except Exception:
            pass
        await asyncio.sleep(1.5)
        if self.sup_q is not None:
            try:
                self.sup_q.put_nowait({'cmd': 'quit', 'message': message})
            except Exception:
                pass
        restore_terminal()
        os._exit(CLEAN_EXIT_CODE)

    async def on_command(self, event):
        """
        Handle commands from authorized users (partyline/DCC or IRC privmsg).
        Delegates actual command logic to commands.py.
        """
        nick = event.get('nick', '')
        host = event.get('host', '')
        ident = event.get('ident', '')
        text = event.get('text', '').strip()
        
        full_hostmask = f"{nick}!{ident}@{host}" if ident else f"{nick}!*@{host}"

        handle = await self.user.match_user(full_hostmask)
        if not handle:
            self.send_cmd('msg', nick, "You are not recognized. Contact bot owner.")
            return
        
        user = await self.user.get(handle)
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
            # Ephemeral IRC session: stable key, lambda binds nick at creation, cleaned up after
            session_key = f"irc:{nick}"
            self.dcc_sessions[session_key] = {
                'hand': handle,
                'send': lambda msg, n=nick: self.send_cmd('msg', n, msg)
            }
            try:
                await COMMANDS[cmd](self.config, self.core_q, self.irc_q, handle, session_key, arg)
            except Exception as e:
                log.error(f"Command '{cmd}' error: {e}", exc_info=True)
                self.send_cmd('msg', nick, f"Error executing .{cmd}")
            finally:
                self.dcc_sessions.pop(session_key, None)
        else:
            self.send_cmd('msg', nick, f"Unknown command: .{cmd}")

    async def on_pubmsg(self, event: Dict[str, Any]):
        """Public message: update seen DB, flood protection checks (future)."""
        nick = event.get('nick', '')
        host = event.get('host', '')
        text = event.get('text', '')
        channel = event.get('channel', '')
        await self.game.dispatch_pubmsg(channel, nick, text, event=event)
        #await self.seen.update_seen(nick, host, channel, 'PUBMSG')

    async def on_privmsg(self, event: Dict[str, Any]):
        """Private message: treat as potential command from authorized user."""
        event['type'] = 'COMMAND'
        nick = event.get('nick', '')
        text = event.get('text', '')
        await self.game.dispatch_privmsg(nick, text, event=event)
        await self.on_command(event)

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
        modes   = event.get('modes', '')
        args    = event.get('args', [])

        chan = self.get_chan(channel)
        if not chan:
            return

        arg_index = 0
        adding    = True

        for char in modes:
            if char == '+':
                adding = True
            elif char == '-':
                adding = False
            elif char in 'ovh':
                if arg_index < len(args):
                    target_nick = args[arg_index]
                    arg_index += 1
                    if char == 'o':
                        if target_nick.lower() == self.botname.lower():
                            chan.bot_op = adding
                        if adding and target_nick not in chan.ops:
                            chan.ops.append(target_nick)
                        elif not adding and target_nick in chan.ops:
                            chan.ops.remove(target_nick)
                    elif char == 'h':
                        if adding:
                            chan.set_halfop(target_nick, self.botname)
                        else:
                            chan.unset_halfop(target_nick, self.botname)
                    elif char == 'v':
                        if adding and target_nick not in chan.voiced:
                            chan.voiced.append(target_nick)
                        elif not adding and target_nick in chan.voiced:
                            chan.voiced.remove(target_nick)
            elif char == 'l':
                if adding and arg_index < len(args):
                    try:
                        chan.limit = int(args[arg_index])
                    except (ValueError, TypeError):
                        chan.limit = 0
                    arg_index += 1
                elif not adding:
                    chan.limit = 0
            elif char == 'k':
                if adding and arg_index < len(args):
                    chan.key = args[arg_index]
                    arg_index += 1
                elif not adding:
                    chan.key = ''
            elif char in 'beI':
                if arg_index < len(args):
                    arg_index += 1
        
    async def on_newchan(self, event: Dict[str, Any]):
        """User joined channel: update seen DB."""
        nick = event.get('nick', '')
        host = event.get('host', '')
        channel = event.get('channel', '')
        chan_data = event.get('irc_data', '')
        norm = self._normalize_chan(channel)
        if norm not in self.channels:
            chan = Channel(name=norm)
            chan._chan_mgr = self.chan
            self.channels[norm] = chan
        self.channels[channel].update_irc_state(chan_data)

    async def on_join(self, event: Dict[str, Any]):
        nick    = event.get('nick', '')
        channel = event.get('channel', '')
        chan = self.get_chan(channel)
        if chan:
            chan.add_user(nick)

    async def on_part(self, event: Dict[str, Any]):
        nick    = event.get('nick', '')
        channel = event.get('channel', '')
        if nick == self.botname:
            if channel in self.channels:
                del self.channels[channel]
                log.info(f"Bot parted {channel}")
            return
        chan = self.get_chan(channel)
        if chan:
            chan.remove_user(nick)

    async def on_kick(self, event: Dict[str, Any]):
        kicked_nick = event.get('kicked', '')
        channel     = event.get('channel', '')
        if kicked_nick == self.botname:
            if channel in self.channels:
                del self.channels[channel]
                log.info(f"Bot was kicked from {channel}")
            return
        chan = self.get_chan(channel)
        if chan:
            chan.remove_user(kicked_nick)

    async def on_quit(self, event: Dict[str, Any]):
        nick = event.get('nick', '')
        if nick == self.botname:
            self.channels.clear()
            return
        for chan in self.channels.values():
            chan.remove_user(nick)

    async def on_nick(self, event: Dict[str, Any]):
        old_nick = event.get('old_nick', '')
        new_nick = event.get('new_nick', '')
        if old_nick == self.botname:
            self.botname = new_nick
            log.info(f"Bot nick changed: {old_nick} → {new_nick}")
        for chan in self.channels.values():
            chan.rename_user(old_nick, new_nick)

    async def on_ready(self, event: Dict[str, Any]):
        """IRC connection established: join channels."""
        self.connected = True
        self.connected_on = time.time()
        self.botname = event.get('botname')
        self._irc_respawn_delay = 5.0
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

    async def on_332(self, event):  # CHANNEL_TOPIC
        """Update topic from RPL_TOPIC"""
        channel = event['channel']
        chan = self.get_chan(channel)
        self.get_chan(channel)
        if chan:
            chan.topic = event['topic']
            log.debug(f"Topic updated for {event['channel']}")

    async def on_324(self, event):  # CHANNEL_MODES
        """Parse/set modes from RPL_CHANNELMODEIS"""
        channel = event['channel']
        chan = self.get_chan(channel)
        self.get_chan(channel)
        if chan:
            chan._parse_and_set_modes(event['modes_str'])
            log.info(f"{event['channel']} modes: n={chan.modes_n} t={chan.modes_t} l={chan.limit}")

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
        self.get_chan(channel)
        if chan:
            chan.bans.append(event['ban'])
            log.debug(f"Ban added to {event['channel']}: {event['ban']}")

    async def on_346(self, event):  # INVITELIST_ADD
        """Add invite to list"""
        channel = event['channel']
        chan = self.get_chan(channel)
        self.get_chan(channel)
        if chan:
            chan.invites.append(event['invite'])

    async def on_348(self, event):  # EXEMPTLIST_ADD
        """Add exempt to list"""
        channel = event['channel']
        chan = self.get_chan(channel)
        self.get_chan(channel)
        if chan:
            chan.exempts.append(event['exempt'])       

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
        log.error(f"IRC error: {error_msg}")

    def send_irc(self, payload: dict) -> None:
        """
        Single point of entry for all IRC queue writes.
        Always resolves self.irc_q at call time — safe across respawns.
        """
        try:
            self.irc_q.put_nowait(payload)
        except Exception as e:
            log.warning(f"[Core] IRC queue write dropped: {e} — payload={payload}")

    def send_cmd(self, cmd_type: str, target: str, text: str = "", **kwargs) -> None:
        self.send_irc({'cmd': cmd_type, 'target': target, 'text': text, **kwargs})

    async def _periodic_tasks(self):
        """Periodic tasks."""
        if hasattr(self, 'botnet') and self.botnet:
            if hasattr(self.botnet, 'poll_queues'):
                await self.botnet.poll_queues()

        current_ppid = os.getppid()
        if current_ppid != self._supervisor_ppid or current_ppid == 1:
            log.warning(f"Supervisor gone (ppid {self._supervisor_ppid} → {current_ppid}) — self-terminating")
            restore_terminal()
            await self._shutdown("Supervisor gone")

        if self.connected and self._lag_ping_sent is None:
            now = time.time()
            if (now - self._last_lag_ping) >= 30.0:
                self._lag_ping_sent = time.time() * 1000
                self._last_lag_ping = now
                self.send_irc({'cmd': 'ping', 'token': f'LAG{int(now)}'})

    async def register_timer(self, name: str, callback, interval: float, randomize: bool = False):
        log.debug(f"Registered timer '{name}': {interval}s")   # ← once, at registration
        async def timer_loop():
            current_interval = interval
            while True:
                try:
                    await callback()
                except Exception as e:
                    log.error(f"Timer {name} error: {e}")
                if randomize:
                    current_interval = max(1.0, interval + random.randint(-30, 30))
                await asyncio.sleep(current_interval)
        self.timers[name] = self._create_safe_task(timer_loop())
    
    def unregister_timer(self, name: str):
        if name in self.timers:
            self.timers[name].cancel()
            del self.timers[name]
    
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
        
        # Update channel objects
        channels_data = irc_data.get('channels', {})
        for chan_name, chan_data in channels_data.items():
            chan = self.channels.get(chan_name)
            if chan:
                chan.update_irc_state(chan_data)

        # Remove channels the IRC process is no longer tracking
        current_chans = set(channels_data.keys())
        for chan_name in list(self.channels.keys()):
            if chan_name not in current_chans:
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

            # Fetch all sessions in the same connection, not one-per-game
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

        # Group sessions by game
        from collections import defaultdict
        sessions_by_game = defaultdict(list)
        for s in session_rows:
            sessions_by_game[s["game_name"]].append(s)

        for game_name in game_names:
            try:
                await self.game.load_game(game_name)
                for s in sessions_by_game[game_name]:
                    await self.game.start_game(
                        game_name, s["scope"], s["target"], owner=s["owner"]
                    )
                    log.info("Restored game session: %s on %s:%s", game_name, s["scope"], s["target"])
            except Exception as e:
                log.error("Failed to restore game %s: %s", game_name, e)

    async def do_rehash(self) -> None:
        """
        Soft rehash: re-exec Core only. IRC stays connected.
        Equivalent to Eggdrop's SIGHUP/.rehash — no IRC disconnect.
        Requires: 'm' flag (master).
        """
        log.info("[Core] Rehashing — re-execing Core, IRC preserved")
        self.partyline.broadcast("*** Rehashing...")
        # Cancel plugin tasks, flush DB
        await self._pre_exec_cleanup()
        # Replace this process image with a fresh Core
        os.execv(sys.executable, sys.argv)
        # os.execv does not return

    async def do_restart(self) -> None:
        """
        Full restart: gracefully quit IRC, then ask the supervisor to kill and
        respawn both Core and IRC with a fresh interpreter (new module imports).
        Core exits cleanly; supervisor sentinel loop detects the exit and acts.
        """
        log.info("[Core] Restart requested — notifying supervisor")
        self.partyline.broadcast("*** Restarting...")
        try:
            self.send_irc({'cmd': 'quit', 'message': 'Restarting...'})
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
        for name, task in list(self.timers.items()):
            task.cancel()
        self.timers.clear()
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
                log.error(f"Invalid event type received: {type(event)} - {event}")
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
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    tty_fd = config.pop('_tty_fd', None)
    if tty_fd is not None:
        try:
            sys.stdin = os.fdopen(tty_fd, 'r')
        except Exception as e:
            log.warning(f"Could not restore TTY fd {tty_fd}: {e}")

    core = Core(config=config, config_path=config_path, args=args, core_q=core_q, irc_q=irc_q, sup_q=sup_q)
    asyncio.run(core.run(foreground=getattr(args, 'foreground', False)))