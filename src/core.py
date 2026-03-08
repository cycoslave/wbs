# src/core.py
"""
Main process: Core loop + spawns IRC/partyline/botnet children.
"""
import asyncio
import multiprocessing as mp
import threading
import time
import datetime
import logging
import json
import os
import socket
import sys
from pathlib import Path
from typing import Dict, Any
from collections import deque

from . import __version__
from .db import init_db
from .net import NetListener
from .channel import ChannelManager, Channel
from .user import UserManager
from .bot import BotManager
from .botnet import BotnetManager
from .commands import COMMANDS
from .console import Console
from .partyline import Partyline
from .session import Session
from .plugins.seen import Seen
from .irc import irc_process_launcher
from .plugins import PluginManager


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
        self.core_q = mp.Queue()
        self.irc_q = mp.Queue()
        self._event_buffer = deque()
        self._buffer_lock = threading.Lock()
        self.quit_event = mp.Event()
        
        # Managers
        self.net_listener = NetListener(self.core_q)
        self.user = UserManager(self.db_path)
        self.bot = BotManager(self.db_path)
        self.botnet = BotnetManager(self)
        self.chan = ChannelManager(self.db_path)
        self.seen = Seen(self.db_path)
        self.partyline = Partyline(self)
        self.plugin = PluginManager(self)

        # Runtime variables
        self.children = []
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
        self.foreground = False
        log.info(f"Core process started. (pid={os.getpid()})")

    async def _async_init(self):
        """One-time async initialization."""
        # Initialize database schema
        await init_db(self.db_path)        

    def spawn_children(self):
        """Spawn daemon children - skip partyline in foreground mode."""
        config_path = self.config_path
        
        # IRC always
        irc_proc = mp.Process(
            target=irc_process_launcher,
            args=(config_path, self.core_q, self.irc_q),
            daemon=True, name="IRC"
        )
        irc_proc.start()
        self.children.append(irc_proc)
        log.info(f"Spawned: {[p.name for p in self.children]}")

    async def run(self, foreground=False):
        """Main async event loop"""
        self.foreground = foreground
        log.info(f"Initializing core with db_path={self.db_path}")
        await self._async_init()
        
        log.info("Loading configured plugins...")
        for plugin_name in self.config.get('plugins', []):
            try:
                await self.plugin.load_plugin(plugin_name)
                log.info(f"Auto-loaded plugin: {plugin_name}")
            except Exception as e:
                log.error(f"Failed auto-load {plugin_name}: {e}")

        if hasattr(self, 'net_listener'):
            asyncio.create_task(self.net_listener.listen(port=self.config['settings']['listen_port']))

        if foreground:
            log.info("Foreground mode: Using console.")
            self.console_session_id = self.partyline.register_console(
                handle='console',
                output_callback=self._console_output
            )
        else:
            log.info("Background mode")

        self.spawn_children()
        
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
        
        handlers = {
            'PARTYLINE_INPUT': self.on_partyline_input,
            'PARTYLINE_CONNECT': self.on_partyline_connect,
            'PARTYLINE_DISCONNECT': self.on_partyline_disconnect,
            'BOT_CONNECT': self.on_bot_connect,
            'BOT_DISCONNECT': self.on_bot_disconnect,
            #'BOT_COMMAND': self.on_bot_cmd,
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
            'BANLIST_END': self.on_null,
            'INVITELIST_END': self.on_null,
            'EXCEPTLIST_END': self.on_null,
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
        
        log.debug(f"New bot connection: {bot_name} fd={dup_fd}")
        
        if dup_fd is None:
            log.warning(f"No dup_fd for bot {bot_name}")
            return
        
        try:
            dup_sock = socket.socket(fileno=dup_fd)
            dup_sock.setblocking(False)
            
            reader, writer = await asyncio.open_connection(sock=dup_sock)
            
            # Generate session ID
            bot_id = len(self.bot_sessions)
            
            response_q = mp.Queue()
            
            # Create bot session
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
            
            await self.botnet.process_incoming(bot_name, event['data'], reader, writer)
            # Send handshake response
            #await bot_session.send(f"BOTLINK {self.botname} {bot_name} 1 :WBS {__version__}")
            #self.botnet_q.put_nowait({
            #    'type': 'botlink',
            #    'botname': bot_name,
            #    'line': event['line'],
            #    'request_id': request_id,
            #})
            #asyncio.create_task(bot_session.run())
            
            log.debug(f"Bot session {bot_id} created for {bot_name}")
            #self.partyline.broadcast(f"*** {bot_name} linked to botnet")
            
        except Exception as e:
            log.error(f"Bot session {bot_name} failed: {e}")
            try:
                os.close(dup_fd)
            except:
                pass

    async def on_bot_disconnect(self, event: dict):
        """Handle bot disconnection"""
        handle = event['handle']
        session_id = event.get('session_id', handle)
        
        if handle in self.botnet.peers:
            link = self.botnet.peers.pop(handle)
            if not link.writer.is_closing():
                link.writer.close()
                await link.writer.wait_closed()
        if session_id in self.bot_sessions:
            del self.bot_sessions[session_id]
        
        try:
            await self.bot.seen(handle, last_seen=datetime.now())
        except Exception as e:
            log.error(f"DB status {handle}: {e}")
        
        log.info(f"Bot {handle} unlinked.")
        self.party_q.put_nowait({
            'type': 'botnet_status',
            'text': f"*** {handle} unlinked",
            'bots': [{'name': h, 'online': h in self.botnet.peers} for h in await self.bot.list()]
        })
        self.core.irc_q.put({
            'type': 'BOTLINK_UNLINK', 
            'handle': handle
        })
        if hasattr(self, 'partyline'):
            self.partyline.broadcast(f"*** {handle} unlinked")

    async def on_bot_cmd(self, event: dict):
        """Handle bot disconnection"""
        handle = event['handle']
        if handle in self.botnet.peers:
            link = self.botnet.peers.pop(handle)
            await self.botnet.process_incoming(handle, event['data'], link.reader, link.writer)     

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
        
        # Send quit to irc child
        quit_msg = {'cmd': 'quit', 'message': message}
        try:
            self.irc_q.put_nowait(quit_msg)
        except:
            pass

        # Wait for children
        for child in self.children:
            if child.is_alive():
                child.join(timeout=3.0)
                if child.is_alive():
                    child.terminate()
                    child.join(timeout=1.0)
        sys.exit(1)

    async def on_command(self, event):
        """
        Handle commands from authorized users (partyline/DCC or IRC privmsg).
        Delegates actual command logic to commands.py.
        """
        nick = event.get('nick', '')
        text = event.get('text', '').strip()
        
        # Check authorization via user manager
        handle = await self.user.match_user(f"{nick}!*@*")  # Simplified; use full hostmask
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
            # Create mock DCC session for IRC-based commands
            idx = hash(nick) % 10000  # Pseudo-idx for IRC commands
            if idx not in self.dcc_sessions:
                self.dcc_sessions[idx] = {'hand': handle, 'send': lambda msg: self.send_cmd('msg', nick, msg)}
            
            try:
                await COMMANDS[cmd](self.config, self.core_q, self.irc_q, handle, idx, arg)
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

    async def on_invite(self, event: dict):
        """Forward invite notice to partyline."""
        channel = event['channel']
        inviter_nick = event['inviter_nick']
        solicitation = event['solicitation']
        self.partyline.broadcast(f"{solicitation} invite to join {channel} by {inviter_nick}")

    async def on_mode(self, event: Dict[str, Any]):
        """Process MODE events - update channel tracking including limits"""
        channel = event.get('channel', '')
        modes = event.get('modes', '')
        args = event.get('args', [])
        
        chan = self.channels.get(channel)
        if not chan:
            return
            
        mode_str = modes
        arg_index = 0
        adding = True
        
        for char in mode_str:
            if char == '+':
                adding = True
            elif char == '-':
                adding = False
            elif char == 'o':  # Op mode
                if arg_index < len(args):
                    target_nick = args[arg_index]
                    if target_nick.lower() == self.botname.lower():
                        chan.bot_op = adding
                    if adding and target_nick not in chan.ops:
                        chan.ops.append(target_nick)
                    elif not adding and target_nick in chan.ops:
                        chan.ops.remove(target_nick)
                    arg_index += 1
            elif char == 'v':  # Voice mode
                if arg_index < len(args):
                    target_nick = args[arg_index]
                    if adding and target_nick not in chan.voiced:
                        chan.voiced.append(target_nick)
                    elif not adding and target_nick in chan.voiced:
                        chan.voiced.remove(target_nick)
                    arg_index += 1
            elif char == 'l':  # Limit mode
                if adding and arg_index < len(args):
                    try:
                        chan.limit = int(args[arg_index])
                    except (ValueError, TypeError):
                        chan.limit = 0
                    arg_index += 1
                elif not adding:
                    # -l removes limit
                    chan.limit = 0
            elif char in 'kbeI':  # Other modes with parameters
                if adding or char in 'kbeI':
                    arg_index += 1
        
    async def on_newchan(self, event: Dict[str, Any]):
        """User joined channel: update seen DB."""
        nick = event.get('nick', '')
        host = event.get('host', '')
        channel = event.get('channel', '')
        chan_data = event.get('irc_data', '')
        await self.seen.update_seen(nick, host, channel, 'JOIN')
        # Update channel user list
        if channel not in self.channels:
            chan = Channel(name=channel)
            chan._chan_mgr = self.chan
            self.channels[channel] = chan
        
        self.channels[channel].update_irc_state(chan_data)

    async def on_join(self, event: Dict[str, Any]):
        """User joined channel: update seen DB."""
        nick = event.get('nick', '')
        host = event.get('host', '')
        channel = event.get('channel', '')
        await self.seen.update_seen(nick, host, channel, 'JOIN')
        # Update channel user list
        chan = self.channels.get(channel)
        if chan and nick not in chan.users:
            chan.users.append(nick)

    async def on_part(self, event: Dict[str, Any]):
        """User left channel: update seen DB."""
        nick = event.get('nick', '')
        host = event.get('host', '')
        channel = event.get('channel', '')
        await self.seen.update_seen(nick, host, channel, 'PART')
        if nick == self.botname:
            if channel in self.channels:
                del self.channels[channel]
                log.info(f"Bot parted {channel}, removed from channels database")
            return
        # Update channel user list
        chan = self.channels.get(channel)
        if chan and nick in chan.users:
            chan.users.remove(nick)
            # Remove from ops/voiced if present
            if nick in chan.ops:
                chan.ops.remove(nick)
            if nick in chan.voiced:
                chan.voiced.remove(nick)

    async def on_kick(self, event: Dict[str, Any]):
        """User kicked from channel."""
        kicked_nick = event.get('kicked_nick', '')
        channel = event.get('channel', '')
        await self.seen.update_seen(kicked_nick, '', channel, 'KICK')
        # If bot was kicked, remove channel entirely
        if kicked_nick == self.botname:
            if channel in self.channels:
                del self.channels[channel]
            return
        # Update channel user list
        chan = self.channels.get(channel)
        if chan and kicked_nick in chan.users:
            chan.users.remove(kicked_nick)
            # Remove from ops/voiced if present
            if kicked_nick in chan.ops:
                chan.ops.remove(kicked_nick)
            if kicked_nick in chan.voiced:
                chan.voiced.remove(kicked_nick)

    async def on_quit(self, event: Dict[str, Any]):
        """User quit IRC."""
        nick = event.get('nick', '')
        await self.seen.update_seen(nick, '', '', 'QUIT')
        if nick == self.botname:
            if channel in self.channels:
                del self.channels[channel]
            return
        for chan in self.channels.values():
            if nick in chan.users:
                chan.users.remove(nick)
            if nick in chan.ops:
                chan.ops.remove(nick)
            if nick in chan.voiced:
                chan.voiced.remove(nick)

    async def on_nick(self, event: Dict[str, Any]):
        """User changed nick."""
        old_nick = event.get('old_nick', '')
        new_nick = event.get('new_nick', '')
        await self.seen.update_seen(old_nick, '', '', 'NICK')
        # Update nick in all channels
        for chan in self.channels.values():
            if old_nick in chan.users:
                chan.users.remove(old_nick)
                chan.users.append(new_nick)
            if old_nick in chan.ops:
                chan.ops.remove(old_nick)
                chan.ops.append(new_nick)
            if old_nick in chan.voiced:
                chan.voiced.remove(old_nick)
                chan.voiced.append(new_nick)

    async def on_ready(self, event: Dict[str, Any]):
        """IRC connection established: join channels."""
        self.connected = True
        self.connected_on = time.time()
        self.botname = event.get('botname')
        log.info("IRC READY - joining channels..")
        channels = await self.chan.getchans()
        for channel in channels:
            if not None:
                log.info(f"Joining {channel}..")
                self.irc_q.put_nowait({'cmd': 'join', 'channel': channel})
                time.sleep(0.2)

    async def on_disconnect(self, event: Dict[str, Any]):
        """IRC connection dropped."""
        self.connected = False

    async def on_332(self, event):  # CHANNEL_TOPIC
        """Update topic from RPL_TOPIC"""
        chan = self.channels.get(event['channel'])
        if chan:
            chan.topic = event['topic']
            log.debug(f"Topic updated for {event['channel']}")

    async def on_324(self, event):  # CHANNEL_MODES
        """Parse/set modes from RPL_CHANNELMODEIS"""
        chan = self.channels.get(event['channel'])
        if chan:
            chan._parse_and_set_modes(event['modes_str'])
            log.info(f"{event['channel']} modes: n={chan.modes_n} t={chan.modes_t} l={chan.limit}")

    async def on_329(self, event):  # CHANNEL_CREATED
        """Set creation timestamp"""
        chan = self.channels.get(event['channel'])
        if chan:
            chan.created = event['created']
            log.debug(f"{event['channel']} created: {event['created']}")

    async def on_367(self, event):  # BANLIST_ADD
        """Add ban to list"""
        chan = self.channels.get(event['channel'])
        if chan:
            chan.bans.append(event['ban'])
            log.debug(f"Ban added to {event['channel']}: {event['ban']}")

    async def on_346(self, event):  # INVITELIST_ADD
        """Add invite to list"""
        chan = self.channels.get(event['channel'])
        if chan:
            chan.invites.append(event['invite'])

    async def on_348(self, event):  # EXEMPTLIST_ADD
        """Add exempt to list"""
        chan = self.channels.get(event['channel'])
        if chan:
            chan.exempts.append(event['exempt'])        

    async def request_botlinks(self, event: dict):
        """Merge botnet.peers + user flags"""
        botnet_peers = self.botnet.peers  # Dict[BotLink]
        
        linked_bots = {}
        for link in botnet_peers.values():
            linked_bots[link.name] = link.nick
        self.irc_q.put({'cmd': 'UPDATE_BOTLINK', 'botlinks': linked_bots})

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

    async def register_timer(self, name: str, callback, interval: float, random: bool = False):
        """Register repeating timer"""
        async def timer_loop():
            while True:
                try:
                    await callback()
                except Exception as e:
                    log.error(f"Timer {name} error: {e}")
                if random:
                    interval += random.randint(-30, 30)
                await asyncio.sleep(interval)
        
        self.timers[name] = asyncio.create_task(timer_loop())
        log.debug(f"Registered timer {name}: {interval}s")
    
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
        self.botname = irc_data.get('botname')
        
        # Update channel objects
        channels_data = irc_data.get('channels', {})
        for chan_name, chan_data in channels_data.items():
            if chan_name not in self.channels:
                chan = Channel(name=chan_name)
                chan._chan_mgr = self.chan
                self.channels[chan_name] = chan
            
            self.channels[chan_name].update_irc_state(chan_data)
        
        # Remove channels we're no longer in
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

    def on_chan(self, channel: str) -> bool:
        """Check if the bot is on a channel.
        
        Args:
            channel: Channel name (with or without # prefix)
        
        Returns:
            True if bot is on the channel, False otherwise
        """
        if not channel.startswith('#'):
            channel = f'#{channel}'
        return channel in self.channels

    def bot_isop(self, channel: str) -> bool:
        """Check if the bot has op status on a channel.
        
        Args:
            channel: Channel name (with or without # prefix)
        
        Returns:
            True if bot is opped, False otherwise
        """
        if not channel.startswith('#'):
            channel = f'#{channel}'
        
        chan = self.channels.get(channel)
        if not chan:
            return False
        
        return self.botname in chan.ops

    def nick_isop(self, nick: str, channel: str) -> bool:
        """Check if a nick has op status on a channel.
        
        Args:
            nick: Nickname to check
            channel: Channel name (with or without # prefix)
        
        Returns:
            True if nick is opped, False otherwise
        """
        if not channel.startswith('#'):
            channel = f'#{channel}'
        
        chan = self.channels.get(channel)
        if not chan:
            return False
        
        return nick in chan.ops

    def nick_isvoice(self, nick: str, channel: str) -> bool:
        """Check if a nick has voice status on a channel.
        
        Args:
            nick: Nickname to check
            channel: Channel name (with or without # prefix)
        
        Returns:
            True if nick has voice, False otherwise
        """
        if not channel.startswith('#'):
            channel = f'#{channel}'
        
        chan = self.channels.get(channel)
        if not chan:
            return False
        
        return nick in chan.voiced

    def chan_modes(self, channel: str) -> str:
        """Get current channel mode string.
        
        Args:
            channel: Channel name (with or without # prefix)
        
        Returns:
            Mode string (e.g., '+nt') or empty string if channel not found
        """
        if not channel.startswith('#'):
            channel = f'#{channel}'
        
        chan = self.channels.get(channel)
        if not chan:
            return ''
        
        return chan.mode