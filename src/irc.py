#!/usr/bin/env python3
"""
src/irc.py - IRC process: jaraco/irc events -> event_queue; cmd_queue -> actions/msg/join/etc.
Pure dispatcher; no DB/commands here.
"""
import multiprocessing as mp
import queue
import threading
import janus
import irc.bot
import irc.strings
import time
import logging
from irc.client import ServerConnectionError

# Local imports (add to __init__.py or define inline)
from .db import get_bot_config  # DB func to load server/nick/channels

logger = logging.getLogger(__name__)

request_trackers = {}  # {req_id: {'type': 'whois', 'nick': 'foo'}}

# Event types as strings (no external types.py needed)
EventType = {
    'PUBMSG': 'PUBMSG', 'PRIVMSG': 'PRIVMSG', 'JOIN': 'JOIN', 'PART': 'PART',
    'NICK': 'NICK', 'MODE': 'MODE', 'COMMAND': 'COMMAND', 'READY': 'READY', 'ERROR': 'ERROR'
}

class WbsIrcBot(irc.bot.SingleServerIRCBot):
    @staticmethod
    def get_version():
        return "WBS 6.0.0"
    
    def __init__(self, config: dict, channels: list, event_queue: mp.Queue, cmd_queue: mp.Queue):
        self.config = config
        self.channels = channels
        self.event_queue = event_queue
        self.cmd_queue = cmd_queue
        self.config_id = config.get('id', 1)
        
        # Multi-server from bot.servers or legacy fallback
        try:
            bot_servers = config['bot']['servers']
            servers = [[s['host'], s['port']] for s in bot_servers]
        except (KeyError, TypeError):
            servers = [(config.get('server', 'irc.wcksoft.com'), 
                       config.get('port', 6667))]
        super().__init__(servers, config['bot']['nick'], config['bot']['realname'])

    def _connect(self):
        try:
            super()._connect()
        except ServerConnectionError:
            self.event_queue.put(('event', {'type': EventType['ERROR'], 'data': 'connect_fail', 'config_id': self.config_id}))

    def on_welcome(self, conn, event):
        print(f"[IRC] *** WELCOME: Registered as {conn.nickname}")
        print(f"[IRC] Configured for channels: {self.channels}")  # Debug
        conn.join("#tohands")
        time.sleep(1)
        for ch in self.channels:
            print(f"[IRC] Joining: {ch}")
            conn.join(ch)
            time.sleep(1)
        self.event_queue.put(('event', {'type': EventType['READY'], 'config_id': self.config_id}))

    def on_pubmsg(self, conn, event):
        msg = {
            'type': EventType['PUBMSG'],
            'channel': event.target,
            'nick': event.source.nick,
            'host': str(event.source),
            'text': event.arguments[0],
            'config_id': self.config_id
        }
        self.event_queue.put(('event', msg))
        # Bot-addressed commands
        prefix = f"{conn.get_nickname()}:"
        if msg['text'].startswith(prefix):
            cmd_msg = msg.copy()
            cmd_msg['text'] = msg['text'][len(prefix):].strip()
            cmd_msg['type'] = EventType['COMMAND']
            self.event_queue.put(('event', cmd_msg))

    def on_privmsg(self, conn, event):
        msg = {
            'type': EventType['PRIVMSG'],
            'target': event.target,
            'nick': event.source.nick,
            'host': str(event.source),
            'text': event.arguments[0],
            'config_id': self.config_id
        }
        self.event_queue.put(('event', msg))

    def on_join(self, conn, event):
        self.event_queue.put(('event', {
            'type': EventType['JOIN'],
            'channel': event.target,
            'nick': event.source.nick,
            'config_id': self.config_id
        }))

    def on_part(self, conn, event):
        self.event_queue.put(('event', {
            'type': EventType['PART'],
            'channel': event.target,
            'nick': event.source.nick,
            'config_id': self.config_id
        }))

    def on_nick(self, conn, event):
        self.event_queue.put(('event', {
            'type': EventType['NICK'],
            'old_nick': event.source.nick,
            'new_nick': event.target,
            'config_id': self.config_id
        }))

    def on_mode(self, conn, event):
        self.event_queue.put(('event', {
            'type': EventType['MODE'],
            'target': event.target,
            'modes': event.arguments[0] if event.arguments else '',
            'args': event.arguments[1:] if len(event.arguments) > 1 else [],
            'config_id': self.config_id
        }))

    # WHOIS numerics (simplified)
    def on_numeric(self, conn, event):
        if event.arguments[0] == '311':  # WHOIS user
            req_id = hash(event.arguments[1])  # Match whois(nick)
            if req_id in request_trackers:
                tracker = request_trackers[req_id]
                self.event_queue.put(('event', {
                    'type': 'WHOIS_USER', 'nick': tracker['nick'],
                    'user': event.arguments[2], 'host': event.arguments[3],
                    'config_id': self.config_id
                }))

    def send_msg(self, target: str, text: str):
        """Core-called via cmd_queue."""
        self.connection.privmsg(target, text)

    def send_action(self, target: str, action: str):
        self.connection.action(target, action)

    def send_mode(self, target: str, mode_str: str):
        self.connection.mode(target, mode_str)

    def do_cmd(self, cmd_data: dict):
        """Execute cmd from cmd_queue."""
        print(f"[IRC-Poller] CMD: {cmd_data}")  # Confirm receipt
        if not self.connection:
            print("[IRC] No connection")
            return
        if not self.connection.is_connected():
            print("[IRC] Not connected")
            return
        print(f"[IRC] {cmd_data['cmd'].upper()} {cmd_data.get('channel', '')}")
        cmd = cmd_data.get('cmd')
        if cmd == 'msg':
            self.send_msg(cmd_data['target'], cmd_data['text'])
        elif cmd == 'action':
            self.send_action(cmd_data['target'], cmd_data['text'])
        elif cmd == 'mode':
            self.send_mode(cmd_data['target'], cmd_data['mode'])
        elif cmd == 'join':
            self.connection.join(cmd_data['channel'])
        elif cmd == 'part':
            self.connection.part(cmd_data['channel'])
        elif cmd == 'whois':
            nick = cmd_data['nick']
            req_id = hash(nick)
            request_trackers[req_id] = {'type': 'whois', 'nick': nick}
            self.connection.whois(nick)

    def on_ctcp(self, conn, event):
        super().on_ctcp(conn, event)
        nick = event.source.nick
        ctcp_cmd = event.arguments[0]
        if ctcp_cmd == 'PING':
            ts = event.arguments[1] if len(event.arguments) > 1 else ''
            conn.ctcp_reply(nick, f"PING {ts}")

def startircprocess(config: dict, channels: list, eventq: mp.Queue, cmdq: mp.Queue):
    """mp.Process target: config from main.py, queues for IPC. Polls cmdq in daemon thread; reactor blocks."""
    bot = WbsIrcBot(config, channels, eventq, cmdq)  # Your bot init
    
    def cmdpoller():  # <- Add HERE: nested def (captures bot, cmdq)
        """Daemon thread: poll cmdq, execute bot.docmd()."""
        while True:
            try:
                cmddata = cmdq.get_nowait()
                logger.info(f"IRC cmd: {cmddata}, qsize={cmdq.qsize()}")
                bot.docmd(cmddata)  # Execute msg/join/etc.
            except queue.Empty:
                pass
            threading.Event().wait(0.1)  # Low CPU (~10Hz)
    
    poller_thread = threading.Thread(target=cmdpoller, daemon=True)
    poller_thread.start()
    
    logger.info("IRC process ready")
    bot.start()  # Blocks: reactor + auto-reconnect
