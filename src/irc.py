# src/irc.py
"""
IRC client process
"""
import os
import multiprocessing as mp
import queue
import threading
import time
import logging
import json
import asyncio
import irc.bot
from typing import Optional
from irc.client import ServerConnectionError

from .user import UserManager
from .channel import ChannelManager
from . import __version__

log = logging.getLogger(__name__)

# Event type constants
class EventType:
    PUBMSG = 'PUBMSG'
    PRIVMSG = 'PRIVMSG'
    JOIN = 'JOIN'
    PART = 'PART'
    NICK = 'NICK'
    MODE = 'MODE'
    KICK = 'KICK'
    QUIT = 'QUIT'
    COMMAND = 'COMMAND'
    READY = 'READY'
    DISCONNECT = 'DISCONNECT'
    ERROR = 'ERROR'
    WHOIS_USER = 'WHOIS_USER'
    WHOIS_END = 'WHOIS_END'


class WbsIrcBot(irc.bot.SingleServerIRCBot):
    """IRC bot instance - pure dispatcher, no business logic"""
    
    def __init__(self, config, core_q, irc_q):
        self.config = config
        self.chan = ChannelManager(self.config['db']['path'])
        self.core_q = core_q
        self.irc_q = irc_q
        self.config_id = config.get('id', 1)
        self.whois_trackers = {}  # Track pending WHOIS requests
        
        # Parse server list
        servers = self._parse_servers(config)
        bot_config = config.get('bot', {})
        
        super().__init__(
            servers,
            bot_config.get('nick', 'wbs'),
            bot_config.get('realname', 'WBS Bot')
        )
        
    def _parse_servers(self, config: dict) -> list[tuple[str, int]]:
        """Extract server list from config (supports multiple formats)"""
        try:
            # New format: config['bot']['servers'] = [{'host': ..., 'port': ...}]
            servers_list = config['bot']['servers']
            return [(s['host'], s['port']) for s in servers_list]
        except (KeyError, TypeError):
            # Legacy format: config['server'], config['port']
            host = config.get('server', 'irc.wcksoft.com')
            port = config.get('port', 6667)
            return [(host, port)]
    
    def _emit_event(self, event_data: dict):
        """Send event to core.py via queue"""
        event_data['config_id'] = self.config_id
        try:
            self.core_q.put(event_data, block=False)
        except queue.Full:
            log.error(f"Event queue full, dropping: {event_data['type']}")
    
    # === Connection Lifecycle ===
    
    def _connect(self):
        """Override to handle connection errors gracefully"""
        try:
            super()._connect()
        except ServerConnectionError as e:
            log.error(f"Connection failed: {e}")
            self._emit_event({
                'type': EventType.ERROR,
                'data': 'connect_fail',
                'error': str(e)
            })
    
    def on_welcome(self, conn, event):
        """Connected and registered - join channels"""
        log.info(f"Connected as {conn.get_nickname()}")
        self._emit_event({
            'type': EventType.READY,
            'botname': conn.get_nickname()
        })
    
    def on_disconnect(self, conn, event):
        """Connection lost"""
        log.warning("Disconnected from server")
        self._emit_event({
            'type': EventType.ERROR,
            'data': 'disconnect'
        })
        self._emit_event({'type': EventType.DISCONNECT})
    
    # === IRC Event Handlers ===
    
    def on_pubmsg(self, conn, event):
        """Public channel message"""
        text = event.arguments[0]
        self._emit_event({
            'type': EventType.PUBMSG,
            'channel': event.target,
            'nick': event.source.nick,
            'host': str(event.source),
            'text': text
        })
        
        # Detect bot-addressed commands (e.g., "wbs: .help")
        prefix = f"{conn.get_nickname()}:"
        if text.startswith(prefix):
            cmd_text = text[len(prefix):].strip()
            self._emit_event({
                'type': EventType.COMMAND,
                'channel': event.target,
                'nick': event.source.nick,
                'host': str(event.source),
                'text': cmd_text
            })
    
    def on_privmsg(self, conn, event):
        """Private message"""
        self._emit_event({
            'type': EventType.PRIVMSG,
            'target': event.target,
            'nick': event.source.nick,
            'host': str(event.source),
            'text': event.arguments[0]
        })
    
    def on_join(self, conn, event):
        self._emit_event({
            'type': EventType.JOIN,
            'channel': event.target,
            'nick': event.source.nick,
            'host': str(event.source)
        })
    
    def on_part(self, conn, event):
        reason = event.arguments[0] if event.arguments else ''
        self._emit_event({
            'type': EventType.PART,
            'channel': event.target,
            'nick': event.source.nick,
            'reason': reason
        })
    
    def on_kick(self, conn, event):
        kicked_nick = event.arguments[0]
        reason = event.arguments[1] if len(event.arguments) > 1 else ''
        channel = event.target
        if kicked_nick == conn.get_nickname():
            if self.chan.exist(channel):
                conn.join(channel)
        self._emit_event({
            'type': EventType.KICK,
            'channel': channel,
            'nick': event.source.nick,
            'kicked': kicked_nick,
            'reason': reason
        })
    
    def on_quit(self, conn, event):
        reason = event.arguments[0] if event.arguments else ''
        self._emit_event({
            'type': EventType.QUIT,
            'nick': event.source.nick,
            'reason': reason
        })
    
    def on_nick(self, conn, event):
        self._emit_event({
            'type': EventType.NICK,
            'old_nick': event.source.nick,
            'new_nick': event.target
        })
    
    def on_mode(self, conn, event):
        modes = event.arguments[0] if event.arguments else ''
        args = event.arguments[1:] if len(event.arguments) > 1 else []
        self._emit_event({
            'type': EventType.MODE,
            'target': event.target,
            'modes': modes,
            'args': args,
            'by': event.source.nick
        })
    
    def on_ctcp(self, conn, event):
        """Handle CTCP requests (PING, VERSION, etc)"""
        nick = event.source.nick
        ctcp_cmd = event.arguments[0].upper()
        
        if ctcp_cmd == 'PING':
            ts = event.arguments[1] if len(event.arguments) > 1 else ''
            conn.ctcp_reply(nick, f"PING {ts}")
        elif ctcp_cmd == 'VERSION':
            conn.ctcp_reply(nick, f"VERSION WBS {__version__}")
        else:
            super().on_ctcp(conn, event)
    
    def on_whoisuser(self, conn, event):
        """WHOIS response (311 numeric)"""
        # event.arguments = [mynick, nick, user, host, *, realname]
        nick = event.arguments[1]
        req_id = hash(nick)
        
        if req_id in self.whois_trackers:
            self._emit_event({
                'type': EventType.WHOIS_USER,
                'nick': nick,
                'user': event.arguments[2],
                'host': event.arguments[3],
                'realname': event.arguments[5]
            })
    
    def on_endofwhois(self, conn, event):
        """WHOIS complete (318 numeric)"""
        nick = event.arguments[1]
        req_id = hash(nick)
        
        if req_id in self.whois_trackers:
            del self.whois_trackers[req_id]
            self._emit_event({
                'type': EventType.WHOIS_END,
                'nick': nick
            })
    
    # === Command Execution ===
    
    def execute_command(self, cmd_data: dict):
        """Execute command from cmd_queue (called by poller thread)"""
        if not self.connection.is_connected():
            log.error(f"Not connected, dropping command: {cmd_data}")
            return
        
        cmd = cmd_data.get('cmd')
        
        try:
            if cmd == 'msg':
                self.connection.privmsg(cmd_data['target'], cmd_data['text'])
            
            elif cmd == 'notice':
                self.connection.notice(cmd_data['target'], cmd_data['text'])
            
            elif cmd == 'action':
                self.connection.action(cmd_data['target'], cmd_data['text'])
            
            elif cmd == 'join':
                self.connection.join(cmd_data['channel'])
            
            elif cmd == 'part':
                reason = cmd_data.get('reason', '')
                self.connection.part(cmd_data['channel'], reason)
            
            elif cmd == 'mode':
                self.connection.mode(cmd_data['channel'], cmd_data['modes'])

            elif cmd == 'quit':
                self.connection.quit(cmd_data['message'])
                time.sleep(2.0)
                self.core_q.put_nowait({'cmd': 'quit', 'message': cmd_data['message']})
            
            elif cmd == 'kick':
                reason = cmd_data.get('reason', 'Kicked')
                self.connection.kick(
                    cmd_data['channel'],
                    cmd_data['nick'],
                    reason
                )
            
            elif cmd == 'whois':
                nick = cmd_data['nick']
                req_id = hash(nick)
                self.whois_trackers[req_id] = {'nick': nick}
                self.connection.whois(nick)
            
            elif cmd == 'raw':
                self.connection.send_raw(cmd_data['line'])
            
            else:
                log.error(f"[IRC] Unknown command: {cmd}")
        
        except Exception as e:
            log.error(f"Command failed {cmd_data}: {e}")


def start_irc_process(config, core_q, irc_q):
    """
    Entry point for IRC process
    """
    irc = WbsIrcBot(config, core_q, irc_q)
    
    def command_poller():
        """Daemon thread: poll cmd_queue and execute commands"""
        throttle_interval = 0.1  # 100ms between commands (anti-flood)
        last_cmd_time = 0
        
        while True:
            try:
                elapsed = time.time() - last_cmd_time
                if elapsed < throttle_interval:
                    time.sleep(throttle_interval - elapsed)
                
                cmd_data = irc_q.get_nowait()
                log.debug(f"Executing: {cmd_data}")
                
                irc.execute_command(cmd_data)
                last_cmd_time = time.time()
            
            except queue.Empty:
                time.sleep(0.01) 
            
            except Exception as e:
                log.error(f"Command poller error: {e}")
                time.sleep(0.1)
    
    poller = threading.Thread(target=command_poller, daemon=True)
    poller.start()

    log.info(f"IRC process started. (pid={os.getpid()})")
    irc.start()

def irc_process_launcher(config_path, core_q, irc_q):
    """Launcher for IRC multiprocessing.Process."""
    config = json.load(open(config_path))
    asyncio.run(start_irc_process(config, core_q, irc_q))