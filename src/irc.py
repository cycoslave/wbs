#!/usr/bin/env python3
"""
src/irc.py - IRC process: jaraco/irc events -> event_queue; cmd_queue -> actions/msg/join/etc.
Pure dispatcher; no DB/commands here.
"""
import multiprocessing as mp
import queue
import threading
import irc.bot
import irc.strings
from irc.client import ServerConnectionError

# Local imports (add to __init__.py or define inline)
from .db import get_bot_config  # DB func to load server/nick/channels

request_trackers = {}  # {req_id: {'type': 'whois', 'nick': 'foo'}}

# Event types as strings (no external types.py needed)
EventType = {
    'PUBMSG': 'PUBMSG', 'PRIVMSG': 'PRIVMSG', 'JOIN': 'JOIN', 'PART': 'PART',
    'NICK': 'NICK', 'MODE': 'MODE', 'COMMAND': 'COMMAND', 'READY': 'READY', 'ERROR': 'ERROR'
}

class WbsIrcBot(irc.bot.SingleServerIRCBot):
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
        
        print(f"[IRC] Configured for channels: {self.channels}")  # Debug
        super().__init__(servers, config['bot']['nick'], config['bot']['realname'])

    def _connect(self):
        try:
            super()._connect()
        except ServerConnectionError:
            self.event_queue.put(('event', {'type': EventType['ERROR'], 'data': 'connect_fail', 'config_id': self.config_id}))

    def on_welcome(self, conn, event):
        for ch in self.channels:
            conn.join(ch)
        print(f"[IRC] Joined: {self.channels}")
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

def start_irc_process(config: dict, channels: list, event_q: mp.Queue, cmd_q: mp.Queue):
    """
    mp.Process target: config from main.py, queues for IPC.
    Polls cmd_q in daemon thread (reactor blocks).
    """
    channels = config.get('bot', {}).get('channels', [])
    bot = WbsIrcBot(config, channels, event_q, cmd_q)
    
    def cmd_poller():
        while True:
            try:
                cmd_data = cmd_q.get_nowait()
                bot.do_cmd(cmd_data)
            except queue.Empty:
                pass
            threading.Event().wait(0.1)  # Low CPU poll
    
    poller_thread = threading.Thread(target=cmd_poller, daemon=True)
    poller_thread.start()
    
    bot.start()  # Blocks; auto-reconnect via base class
