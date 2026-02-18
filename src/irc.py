"""
IRC process using jaraco/irc for multiprocessing WBS bot.
Dispatches events to core via queues.
"""
import irc.bot
import irc.strings
from irc.client import ServerConnectionError

from . import core, db
from .types import EventType  # Assume defined in core.py or types.py


request_trackers = {}  # Global for now; {request_id: {'type': 'whois', 'nick': 'foo'}}


class WbsBot(irc.bot.SingleServerIRCBot):
    def __init__(self, config_id: int, event_queue: 'queue.Queue'):
        self.config_id = config_id
        self.event_queue = event_queue
        # Load from DB
        cfg = db.get_bot_config(config_id)
        servers = [(cfg['server'], cfg['port'])]
        self.channels = cfg.get('channels', [])
        super().__init__(servers, cfg['nickname'], cfg['realname'])

    def _connect(self):
        try:
            super()._connect()
        except ServerConnectionError:
            self.event_queue.put(('error', {'type': 'connect_fail', 'config_id': self.config_id}))

    def on_welcome(self, conn, event):
        for ch in self.channels:
            conn.join(ch)
        self.event_queue.put(('ready', {'config_id': self.config_id}))

    def on_pubmsg(self, conn, event):
        msg = {
            'type': EventType.PUBMSG,
            'channel': event.target,
            'nick': event.source.nick,
            'text': event.arguments[0],
            'config_id': self.config_id
        }
        self.event_queue.put(('event', msg))
        # Check for bot-addressed commands
        prefix = f"{conn.get_nickname()}:"
        if msg['text'].startswith(prefix):
            cmd = msg['text'][len(prefix):].strip()
            cmd_msg = msg.copy()
            cmd_msg['text'] = cmd
            cmd_msg['type'] = EventType.COMMAND
            self.event_queue.put(('event', cmd_msg))

    def on_privmsg(self, conn, event):
        msg = {
            'type': EventType.PRIVMSG,
            'target': event.target,
            'nick': event.source.nick,
            'text': event.arguments[0],
            'config_id': self.config_id
        }
        self.event_queue.put(('event', msg))

    def on_join(self, conn, event):
        self.event_queue.put(('event', {
            'type': EventType.JOIN,
            'channel': event.target,
            'nick': event.source.nick,
            'config_id': self.config_id
        }))

    def on_part(self, conn, event):
        self.event_queue.put(('event', {
            'type': EventType.PART,
            'channel': event.target,
            'nick': event.source.nick,
            'config_id': self.config_id
        }))

    def on_nick(self, conn, event):
        self.event_queue.put(('event', {
            'type': EventType.NICK,
            'old': event.source.nick,
            'new': event.target,
            'config_id': self.config_id
        }))

    def on_mode(self, conn, event):
        self.event_queue.put(('event', {
            'type': EventType.MODE,
            'target': event.target,
            'args': event.arguments,
            'config_id': self.config_id
        }))

    def send_msg(self, target: str, text: str):
        """Called from core via queue to send privmsg."""
        self.connection.privmsg(target, text)

    def send_action(self, target: str, action: str):
        """Send CTCP ACTION."""
        self.connection.action(target, action)

    def whois(self, nick: str):
        """Send WHOIS request; track for numeric replies."""
        request_id = id(nick)  # Simple unique ID
        request_trackers[request_id] = {'type': 'whois', 'nick': nick}
        self.connection.whois(nick)
        return request_id  # Return for potential tracking


def run_irc_process(config_id: int, event_queue, cmd_queue):
    """
    Entry for multiprocessing.Process(target=run_irc_process, args=(config_id, event_queue, cmd_queue))
    Loops handling cmds from core (e.g., join/leave) via cmd_queue.
    Note: cmd_queue handling not implemented yet; bot.start() blocks.
    """
    bot = WbsBot(config_id, event_queue)
    bot.start()  # Blocks until disconnect; base class handles recon
