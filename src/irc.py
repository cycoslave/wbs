# src/irc.py
"""
IRC client process
"""
import os
import queue
import threading
import time
import logging
import asyncio
import random
import string
import irc.bot
import irc.client
import ssl as ssl_lib
import socket as socket_module
from datetime import datetime, timedelta
from collections import defaultdict, deque
from jaraco.stream import buffer

from .helper import clean_message
from .user import UserManager
from .channel import ChannelManager
from . import __version__

log = logging.getLogger("wbs.irc")

class EventType:
    PUBMSG = 'PUBMSG'
    PRIVMSG = 'PRIVMSG'
    NEWCHAN = 'NEWCHAN'
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

class ServerCaps:
    """
    Parses RFC-documented IRC server capabilities from 005 RPL_ISUPPORT.
    Only known tokens are stored — unknown tokens are silently ignored.
    In-memory only, lives on WbsIrcBot, reset on disconnect.
    """

    # Integer-valued tokens
    _INT_TOKENS = {
        'NICKLEN', 'CHANNELLEN', 'TOPICLEN', 'KICKLEN',
        'AWAYLEN', 'MODES', 'MONITOR', 'MAXCHANNELS', 'ACCEPT'
    }

    # All RFC/ISUPPORT tokens we care about.
    # Value tokens expect '=<value>'; bool tokens are presence-only flags.
    _KNOWN_VALUE  = {
        'CHANTYPES', 'CHANMODES', 'CHANLIMIT', 'PREFIX', 'MAXLIST',
        'MODES', 'NETWORK', 'NICKLEN', 'CHANNELLEN', 'TOPICLEN',
        'KICKLEN', 'AWAYLEN', 'CASEMAPPING', 'CHARSET', 'MONITOR',
        'TARGMAX', 'MAXCHANNELS', 'ELIST', 'STATUSMSG', 'CALLERID',
        'DEAF', 'ACCEPT',
    }
    _KNOWN_BOOL = {
        'EXCEPTS', 'INVEX', 'SAFELIST', 'KNOCK', 'MAP', 'FNC',
        'ETRACE', 'CPRIVMSG', 'CNOTICE', 'WALLCHOPS', 'USERIP',
    }
    _KNOWN = _KNOWN_VALUE | _KNOWN_BOOL

    def __init__(self):
        self._raw: dict[str, str | bool] = {}
        self._parsed: dict[str, object] = {}

    def ingest(self, arguments: list[str]) -> None:
        """
        Feed one 005 line's argument list.
        Only whitelisted tokens are stored; everything else is ignored.
        Safe to call multiple times as the server sends several 005 lines.
        """
        for token in arguments:
            if '=' in token:
                key, _, raw_val = token.partition('=')
                if key not in self._KNOWN_VALUE:
                    continue
                self._raw[key] = raw_val
                self._parsed[key] = self._coerce(key, raw_val)
            else:
                if token not in self._KNOWN_BOOL:
                    continue
                self._raw[token] = True
                self._parsed[token] = True

    def _coerce(self, key: str, value: str) -> object:
        if key in self._INT_TOKENS:
            try:
                return int(value)
            except ValueError:
                return value
        return value

    def reset(self) -> None:
        """Clear on disconnect so stale caps don't survive a server change."""
        self._raw.clear()
        self._parsed.clear()

    @property
    def nicklen(self) -> int:
        return int(self._parsed.get('NICKLEN', 9))

    @property
    def channellen(self) -> int:
        return int(self._parsed.get('CHANNELLEN', 200))

    @property
    def topiclen(self) -> int:
        return int(self._parsed.get('TOPICLEN', 307))

    @property
    def kicklen(self) -> int:
        return int(self._parsed.get('KICKLEN', 255))

    @property
    def modes(self) -> int:
        return int(self._parsed.get('MODES', 3))

    @property
    def network(self) -> str:
        return str(self._parsed.get('NETWORK', ''))

    @property
    def chantypes(self) -> str:
        return str(self._parsed.get('CHANTYPES', '#&'))

    @property
    def casemapping(self) -> str:
        return str(self._parsed.get('CASEMAPPING', 'rfc1459'))

    @property
    def prefix(self) -> dict[str, str]:
        """{'o': '@', 'v': '+'} from PREFIX=(ov)@+"""
        raw = str(self._parsed.get('PREFIX', '(ov)@+'))
        try:
            modes_part, chars_part = raw[1:].split(')')
            return dict(zip(modes_part, chars_part))
        except (ValueError, IndexError):
            return {'o': '@', 'v': '+'}

    @property
    def chanmodes(self) -> dict[str, str]:
        """{'A': 'eIb', 'B': 'k', 'C': 'l', 'D': 'imnpst'}"""
        raw = str(self._parsed.get('CHANMODES', 'beI,k,l,imnpst'))
        labels = ['A', 'B', 'C', 'D']
        parts = raw.split(',')
        return dict(zip(labels, parts + [''] * (4 - len(parts))))

    @property
    def chanlimit(self) -> dict[str, int]:
        """{'#': 25, '&': 25} from CHANLIMIT=&#:25"""
        raw = str(self._parsed.get('CHANLIMIT', '#:25'))
        result = {}
        for part in raw.split(','):
            if ':' in part:
                prefixes, limit = part.split(':', 1)
                for ch in prefixes:
                    try:
                        result[ch] = int(limit)
                    except ValueError:
                        pass
        return result

    @property
    def maxlist(self) -> dict[str, int]:
        """{'b': 100, 'e': 100, 'I': 100} from MAXLIST=beI:100"""
        raw = str(self._parsed.get('MAXLIST', ''))
        result = {}
        for part in raw.split(','):
            if ':' in part:
                modes, limit = part.split(':', 1)
                for ch in modes:
                    try:
                        result[ch] = int(limit)
                    except ValueError:
                        pass
        return result

    @property
    def targmax(self) -> dict[str, int | None]:
        """{'PRIVMSG': 4, 'NOTICE': 4, 'NAMES': 1}"""
        raw = str(self._parsed.get('TARGMAX', ''))
        result = {}
        for part in raw.split(','):
            if ':' in part:
                cmd, limit = part.split(':', 1)
                result[cmd.upper()] = int(limit) if limit else None
        return result

    def supports(self, token: str) -> bool:
        """caps.supports('KNOCK'), caps.supports('EXCEPTS') etc."""
        return bool(self._parsed.get(token.upper(), False))

    def get(self, token: str, default=None):
        """Typed value for any known token not covered by a property."""
        return self._parsed.get(token.upper(), default)

    def __repr__(self) -> str:
        return (f"<ServerCaps network={self.network!r} nicklen={self.nicklen} "
                f"tokens={list(self._raw.keys())}>")

class WbsIrcBot(irc.bot.SingleServerIRCBot):
    """IRC bot instance - pure dispatcher, no business logic"""
    _IRC_MAX_BYTES = 510

    def __init__(self, config, core_q, irc_q):
        self.config = config
        self._supervisor_ppid = os.getppid()
        self._irc_ready = False
        self.chan = ChannelManager(self.config['db']['path'])
        self.user = UserManager(self.config['db']['path'])
        self.server_caps = ServerCaps()
        self._desired_nick: str = config.get('bot', {}).get('nick', 'wbs')
        self._nick_adjusted: str = self._desired_nick
        self.core_q = core_q
        self.irc_q = irc_q
        self.config_id = config.get('id', 1)
        self.whois_trackers = {}  # Track pending WHOIS requests
        self.maintenance_state = {
            'last_rejoin': {},
            'last_nick': 0,
            'linked_bots': {},
            'join_attempts': defaultdict(deque),
            'join_cooldown_until': {},
            'last_nick_attempt': datetime.min,
        }
        self.irc_timers = {}  # name → task
        self.last_connect_attempt = 0
        irc.client.ServerConnection.buffer_class = buffer.LenientDecodingLineBuffer
        irc.client.ServerConnection.buffer_class.errors = "replace"
        servers = self._parse_servers(config)
        bot_config = config.get('bot', {})
        super().__init__(
            servers,
            bot_config.get('nick', 'wbs'),
            bot_config.get('realname', 'WBS Bot')
        )
        self._emit_event({'type': 'REQUEST_BOTLINKS'})

    def _parse_servers(self, config: dict) -> list:
        try:
            servers_list = config['bot']['servers']
            result = []
            for s in servers_list:
                host = s['host']
                port = s['port']
                use_ssl = s.get('ssl', False)
                password = s.get('password', None)
                if use_ssl:
                    ssl_ctx = ssl_lib.create_default_context()
                    # Optional: allow self-signed certs for private servers
                    if s.get('ssl_verify', True) is False:
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = ssl_lib.CERT_NONE
                    result.append(irc.bot.ServerSpec(host, port, password, ssl_ctx))
                else:
                    result.append(irc.bot.ServerSpec(host, port, password))
            return result
        except (KeyError, TypeError):
            host = config.get('server', 'irc.wcksoft.com')
            port = config.get('port', 6667)
            return [irc.bot.ServerSpec(host, port)]
    
    def _emit_event(self, event_data: dict):
        """Send event to core.py via queue"""
        event_data['config_id'] = self.config_id
        try:
            self.core_q.put(event_data, block=False)
        except queue.Full:
            log.error(f"Event queue full, dropping: {event_data['type']}")
        
    def _connect(self):
        """Override to handle connection errors gracefully"""
        try:
            super()._connect()
        except irc.client.ServerConnectionError as e:
            log.error(f"Connection failed: {e}")
            self._emit_event({
                'type': EventType.ERROR,
                'data': 'connect_fail',
                'error': str(e)
            })

    def is_op(self, chan: str, nick: str) -> bool:
        """Check if nick is op on channel"""
        if chan in self.channels:
            return self.channels[chan].is_oper(nick)
        return False

    def on_chan(self, chan: str, nick: str) -> bool:
        """Check if nick is present in channel"""
        if chan in self.channels:
            return self.channels[chan].has_user(nick)
        return False

    def is_bot_op(self, chan: str) -> bool:
        """Check if bot is op on channel"""
        return self.is_op(chan, self.connection.get_nickname())
    
    def is_voice(self, chan: str, nick: str) -> bool:
        """Check if nick is voiced on channel"""
        if chan in self.channels:
            return self.channels[chan].is_voiced(nick)
        return False

    def is_online(self, nick: str) -> bool:
        """Check if nick is online anywhere (global users)"""
        return any(chan.has_user(nick) for chan in self.channels.values())

    @property 
    def is_connected(self) -> bool:
        """Connected to IRC server?"""
        return self._irc_ready

    def on_pong(self, conn, event):
        """Server PONG reply — emit to core for lag measurement."""
        token = event.arguments[0] if event.arguments else ''
        self._emit_event({
            'type': 'IRC_PONG',
            'token': token
        })

    def on_welcome(self, conn, event):
        """Connected and registered - join channels"""
        self._irc_ready = True
        log.info(f"Connected as {conn.get_nickname()}")
        conn.mode(conn.get_nickname(), "+i-ws")
        numerics = {
            '302': self.on_userhost, # RPL_USERHOST
            '332': self.on_332,    # RPL_TOPIC
            '333': self.on_333,    # RPL_TOPICWHOTIME
            '324': self.on_324,    # RPL_CHANNELMODEIS
            '329': self.on_329,    # RPL_CHANNELCREATETIME
            '367': self.on_367,    # RPL_BANLIST
            '346': self.on_346,    # RPL_INVITELIST
            '348': self.on_348,    # RPL_EXCEPTLIST
            '368': self.on_368,    # RPL_ENDOFBANLIST etc.
            '347': self.on_347,    # RPL_ENDOFINVITELIST
            '349': self.on_349,    # RPL_ENDOFEXCEPTLIST
            '352': self.on_352,    # RPL_WHOREPLY
            '315': self.on_315,    # RPL_ENDOFWHO
            '471': self.on_471,    # ERR_CHANNELISFULL
            '473': self.on_473,    # ERR_INVITEONLYCHAN
            '474': self.on_474,    # ERR_BANNEDFROMCHAN
            '433': self.on_nicknameinuse,    # ERR_NICKNAMEINUSE 
            '432': self.on_erroneusnickname, # ERR_ERRONEUSNICKNAME 
        }
        for numeric, handler in numerics.items():
            conn.add_global_handler(numeric, handler, -20)
        conn.send_raw(f"USERHOST {conn.get_nickname()}")
        self._emit_event({
            'type': EventType.READY,
            'botname': conn.get_nickname()
        })
    
    def on_disconnect(self, conn, event):
        """Connection lost"""
        self._irc_ready = False
        log.warning("Disconnected from server")
        self.server_caps.reset()
        self._nick_adjusted = self._desired_nick
        self._emit_event({
            'type': EventType.ERROR,
            'data': 'disconnect'
        })
        self._emit_event({'type': EventType.DISCONNECT})
        
    def on_pubmsg(self, conn, event):
        """Public channel message"""
        text = event.arguments[0]
        event_data = {
            'type': EventType.PUBMSG,
            'channel': event.target,
            'nick': event.source.nick,
            'host': str(event.source),
            'text': text
        }
        #log.debug(f"[IRC] Emitting PUBMSG: {event_data}")
        self._emit_event(event_data)
    
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
        nick = event.source.nick
        chan = event.target

        # Note linked bot joins for future reference — no action taken here
        #if nick in self.maintenance_state['linked_bots'].values():
        #    log.debug(f"[IRC] Linked bot '{nick}' joined {chan}")

        if nick.lower() == conn.get_nickname().lower():
            snapshot: dict = {}  # safe default — prevents UnboundLocalError if chan_obj is None
            chan_obj = self.channels.get(chan)

            if chan_obj:
                #log.info(f"Building snapshot for {chan}")
                try:
                    snapshot = {
                        'users': len(chan_obj.users()),
                        'user_list': list(chan_obj.users()),
                        'bot_op': self.is_bot_op(chan),
                        'ops': list(chan_obj.opers()),
                        'voiced': list(chan_obj.voiced()),
                        'mode': getattr(chan_obj, 'mode', ''),
                        'mode_params': getattr(chan_obj, 'mode_params', {})
                    }
                    log.debug(f"Successfully built snapshot for {chan}")
                except Exception as inner_e:
                    log.error(f"Error building snapshot for {chan}: {inner_e}", exc_info=True)
            else:
                log.warning(f"[IRC] on_join: channel object for '{chan}' not yet populated, emitting empty snapshot")

            self._emit_event({
                'type': EventType.NEWCHAN,
                'channel': chan,
                'nick': nick,
                'host': str(event.source),
                'irc_data': snapshot
            })
        else:
            self._emit_event({
                'type': EventType.JOIN,
                'channel': chan,
                'nick': nick,
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
            asyncio.run_coroutine_threadsafe(
                self._join_if_tracked(conn, channel),
                self.loop
            )
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
        channel = event.target
        modes = event.arguments[0] if event.arguments else ''
        mode_args = event.arguments[1:] if len(event.arguments) > 1 else []
        self._emit_event({
            'type': EventType.MODE,
            'channel': channel,
            'modes': modes,
            'args': mode_args,
            'nick': event.source.nick
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
        elif ctcp_cmd == 'DCC':
            # Log raw args so we can see exactly what jaraco delivers
            log.debug(f"[IRC] DCC raw arguments from {nick}: {event.arguments!r}")

            # jaraco may deliver as ['DCC', 'CHAT', 'chat', '<ip>', '<port>']
            # OR as ['DCC', 'CHAT chat <ip> <port>'] (one blob in [1])
            # Flatten and re-split to handle both
            parts = ' '.join(str(a) for a in event.arguments).split()
            # parts[0]='DCC', parts[1]='CHAT', parts[2]='chat', parts[3]=ip, parts[4]=port
            # passive: parts[5]=token

            subtype = parts[1].upper() if len(parts) > 1 else ''
            if subtype == 'CHAT':
                # Token is present only in passive DCC (6th field, non-numeric)
                token = parts[5] if len(parts) >= 6 and not parts[5].isdigit() else None
                log.info(f"[IRC] DCC CHAT from {nick} ip={parts[3] if len(parts)>3 else '?'} "
                        f"port={parts[4] if len(parts)>4 else '?'} token={token}")
                self._emit_event({
                    'type': 'DCC_CHAT_REQUEST',
                    'nick': nick,
                    'host': str(event.source),
                    'args': parts,
                    'passive_token': token
                })
            else:
                log.debug(f"[IRC] Unhandled DCC subtype {subtype!r} from {nick}")      
        else:
            super().on_ctcp(conn, event)
    
    def on_invite(self, conn, event):
        """Join channel on invite if tracked in DB"""
        inviter_nick = event.source.nick
        channel = event.arguments[0]
        log.info(f"Received channel invite on {channel} from {inviter_nick}")
        asyncio.run_coroutine_threadsafe(
            self._join_if_tracked(conn, channel),
            self.loop
        )
        self._emit_event({
            'type': 'ON_INVITE',
            'channel': channel,
            'inviter': inviter_nick
        })


    def on_userhost(self, conn, event):
        """302 RPL_USERHOST — extract our public IP from server's view."""
        # Response: :server 302 botnick :botnick=+user@1.2.3.4
        #log.debug(f"[IRC] USERHOST raw arguments: {event.arguments!r}")
        try:
            payload = event.arguments[0]  # e.g. "wbs=+~wbs@1.2.3.4"
            host = payload.split('@', 1)[1].strip()
            #log.info(f"[IRC] Public IP from USERHOST: {host}")
            self._emit_event({'type': 'BOT_PUBLIC_IP', 'ip': host})
        except (IndexError, ValueError):
            log.warning(f"[IRC] Could not parse USERHOST: {event.arguments!r}")

    def on_332(self, conn, event):  # RPL_TOPIC
        chan_name = event.arguments[1]
        topic = event.arguments[2]
        # source is the server on join, a nick!user@host on live change
        source = str(event.source) if event.source else ""
        nick = source.split("!")[0] if "!" in source else ""
        self._emit_event({
            'type': 'CHANNEL_TOPIC',
            'channel': chan_name,
            'topic': topic,
            'nick': nick,   # empty string if server-sent (join)
        })

    def on_333(self, conn, event):
        """RPL_TOPICWHOTIME — who set the topic and when."""
        try:
            channel   = event.arguments[1]
            setter    = event.arguments[2]   # nick!user@host
            timestamp = int(event.arguments[3])
        except (IndexError, ValueError):
            return
        self._emit_event({
            'type': 'CHANNEL_TOPIC_META',
            'channel': channel,
            'setter': setter,
            'timestamp': timestamp,
        })

    def on_324(self, conn, event):  # RPL_CHANNELMODEIS
        chan_name = event.arguments[1]
        modes_str = ' '.join(event.arguments[2:])
        self._emit_event({
            'type': 'CHANNEL_MODES',
            'channel': chan_name,
            'modes_str': modes_str
        })

    def on_329(self, conn, event):  # RPL_CHANNELCREATIONTIME
        chan_name = event.arguments[1]
        created_ts = int(event.arguments[2])
        self._emit_event({
            'type': 'CHANNEL_CREATED',
            'channel': chan_name,
            'created': created_ts
        })

    def on_367(self, conn, event):  # RPL_BANLIST
        chan_name, ban_mask = event.arguments[1:3]
        self._emit_event({
            'type': 'BANLIST_ADD',
            'channel': chan_name,
            'ban': ban_mask
        })

    def on_346(self, conn, event):  # RPL_INVITELIST
        chan_name, invite_mask = event.arguments[1:3]
        self._emit_event({
            'type': 'INVITELIST_ADD',
            'channel': chan_name,
            'invite': invite_mask
        })

    def on_348(self, conn, event):  # RPL_EXCEPTLIST
        chan_name, exempt_mask = event.arguments[1:3]
        self._emit_event({
            'type': 'EXEMPTLIST_ADD',
            'channel': chan_name,
            'exempt': exempt_mask
        })

    def on_368(self, conn, event):  # RPL_ENDOFBANLIST
        chan_name = event.arguments[1]
        self._emit_event({
            'type': 'BANLIST_END',
            'channel': chan_name
        })

    def on_347(self, conn, event):  # RPL_ENDOFINVITELIST
        chan_name = event.arguments[1]
        self._emit_event({
            'type': 'INVITELIST_END',
            'channel': chan_name
        })

    def on_349(self, conn, event):  # RPL_ENDOFEXCEPTLIST
        chan_name = event.arguments[1]
        self._emit_event({
            'type': 'EXCEPTLIST_END',
            'channel': chan_name
        })

    def on_352(self, conn, event):
        """
        RPL_WHOREPLY — one line per user in response to WHO #channel.
        Format: 352 botnick channel user host server nick flags :hopcount realname
        event.arguments = [botnick, channel, user, host, server, nick, flags, ':hopcount realname']
        """
        try:
            args      = event.arguments
            channel   = args[1]
            user      = args[2]   # ident
            host      = args[3]
            nick      = args[5]
            flags     = args[6]   # e.g. 'H@', 'G+', 'H%', 'H'
        except IndexError:
            log.warning("[IRC] Malformed 352: %r", event.arguments)
            return

        # flags: H=here G=gone(away), then mode prefixes: @=op %=halfop +=voice *=ircop
        is_op     = '@' in flags
        is_halfop = '%' in flags
        is_voice  = '+' in flags

        self._emit_event({
            'type': 'WHO_REPLY',
            'channel': channel,
            'nick': nick,
            'user': user,
            'host': host,
            'flags': flags,
            'is_op': is_op,
            'is_halfop': is_halfop,
            'is_voice': is_voice,
        })

    def on_315(self, conn, event):
        """
        RPL_ENDOFWHO — signals WHO response is complete for this channel.
        event.arguments = [botnick, channel, 'End of /WHO list']
        """
        try:
            channel = event.arguments[1]
        except IndexError:
            return
        self._emit_event({
            'type': 'WHO_END',
            'channel': channel,
        })

    def on_471(self, conn, event):  # ERR_CHANNELISFULL
        chan_name = event.arguments[1]
        self._emit_event({
            'type': 'ERR_CHANNELISFULL',
            'channel': chan_name
        }) 

    def on_473(self, conn, event):  # ERR_INVITEONLYCHAN
        chan_name = event.arguments[1]
        self._emit_event({
            'type': 'ERR_INVITEONLYCHAN',
            'channel': chan_name
        }) 

    def on_474(self, conn, event):  # ERR_BANNEDFROMCHAN
        chan_name = event.arguments[1]
        self._emit_event({
            'type': 'ERR_BANNEDFROMCHAN',
            'channel': chan_name
        })                         

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
        
    def on_topic(self, conn, event):
        """Live topic change during session."""
        self._emit_event({
            'type': 'TOPIC',
            'channel': event.target,
            'topic': event.arguments[0] if event.arguments else '',
            'nick': event.source.nick,
        })

    def on_featurelist(self, conn, event):
        """005 RPL_ISUPPORT — ingest capabilities."""
        self.server_caps.ingest(event.arguments)
        #log.info(f"[IRC] {self.server_caps}")

        # Enforce NICKLEN immediately if nick is too long
        nicklen = self.server_caps.nicklen
        if len(self._desired_nick) > nicklen:
            truncated = self._desired_nick[:nicklen]
            log.info(f"[IRC] Nick truncated to '{truncated}' (NICKLEN={nicklen})")
            self._nick_adjusted = truncated
            conn.nick(truncated)

    def on_nicknameinuse(self, conn, event):
        """
        433 ERR_NICKNAMEINUSE — pick an alternative nick per spec:

        • nick length > NICKLEN          → already handled in on_featurelist
        • len(nick) >= NICKLEN - 1       → truncate to NICKLEN-2, append 2 random digits
        • len(nick) <= NICKLEN - 2       → append 2 random digits directly
        """
        desired = self._nick_adjusted           # last attempted nick
        nicklen = int(self.server_caps.get('NICKLEN', 9))

        suffix = ''.join(random.choices(string.digits, k=2))

        if len(desired) >= nicklen - 1:
            # Need to carve room for 2 digits
            base = desired[:nicklen - 2]
        else:
            # Already have ≥2 chars of slack
            base = desired

        alt_nick = base + suffix
        log.warning(
            f"[IRC] Nick '{desired}' in use (NICKLEN={nicklen}), "
            f"trying '{alt_nick}'"
        )
        self._nick_adjusted = alt_nick
        conn.nick(alt_nick)

    def on_erroneusnickname(self, conn, event):
        """
        432 — nick is syntactically invalid or too long for this server.
        Same fallback strategy as 433.
        """
        log.warning(f"[IRC] Erroneous nick '{self._nick_adjusted}', applying fallback")
        self.on_nicknameinuse(conn, event)

    def _split_action(self, target: str, text: str) -> list[str]:
        """ACTION wraps text in CTCP: PRIVMSG target :\x01ACTION text\x01"""
        # \x01ACTION  = 8 bytes,  closing \x01 = 1 byte → 9 extra bytes consumed
        prefix = f"PRIVMSG {target} :\x01ACTION "
        suffix_len = 1  # closing \x01
        max_text_bytes = self._IRC_MAX_BYTES - len(prefix.encode("utf-8")) - suffix_len
        # Reuse the same chunking logic
        return self._split_privmsg(target, text, cmd_prefix=f"ACTION_WRAP_{target}")

    def _split_privmsg(self, target: str, text: str, cmd_prefix: str = "PRIVMSG") -> list[str]:
        """
        Split text into chunks that fit within IRC's 512-byte line limit.

        The prefix consumed by the command itself is:
            "PRIVMSG <target> :"   (or NOTICE/ACTION equivalent)
        Whatever remains of the 510-byte budget is available for text bytes.

        Text is split on UTF-8 byte boundaries so multi-byte characters are
        never truncated mid-sequence.
        """
        prefix = f"{cmd_prefix} {target} :"
        max_text_bytes = self._IRC_MAX_BYTES - len(prefix.encode("utf-8"))

        if max_text_bytes <= 0:
            log.warning("[IRC] Target name too long to fit in IRC line: %s", target)
            return []

        chunks: list[str] = []
        encoded = text.encode("utf-8")

        while encoded:
            chunk_bytes = encoded[:max_text_bytes]
            # Walk back until we have a valid UTF-8 sequence boundary
            while chunk_bytes:
                try:
                    chunk_str = chunk_bytes.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    chunk_bytes = chunk_bytes[:-1]
            else:
                # Pathological: no valid boundary found — skip this chunk
                log.error("[IRC] Could not decode chunk for %s, skipping", target)
                encoded = encoded[max_text_bytes:]
                continue

            chunks.append(chunk_str)
            encoded = encoded[len(chunk_bytes):]

        return chunks

    def execute_command(self, cmd_data: dict):
        """Execute command from cmd_queue (called by poller thread)"""
        cmd = cmd_data.get('cmd')
        
        try:
            if cmd == 'UPDATE_BOTLINK':
                self.maintenance_state['linked_bots'] = cmd_data['botlinks']   

            elif cmd == 'BOTLINK_LINK':
                handle = cmd_data['handle']
                nick = cmd_data['nick']
                self.maintenance_state['linked_bots'][handle] = nick

            elif cmd == 'BOTLINK_UNLINK':
                handle = cmd_data['handle']
                if handle in self.maintenance_state['linked_bots']:
                    del self.maintenance_state['linked_bots'][handle]

            elif cmd == 'REGISTER_IRC_TIMER':
                name = cmd_data['name']
                interval = cmd_data['interval']
                self.loop.call_soon_threadsafe(self._schedule_register_timer, name, interval)
            
            elif cmd == 'UNREGISTER_IRC_TIMER':
                name = cmd_data['name']
                self.loop.call_soon_threadsafe(self._schedule_unregister_timer, name)

            else:
                if not self.connection.is_connected():
                    log.error(f"Not connected, dropping command: {cmd}")
                    return
                
                if cmd == 'msg':
                    text = clean_message(cmd_data['text'])
                    for chunk in self._split_privmsg(cmd_data['target'], text, "PRIVMSG"):
                        self.connection.privmsg(cmd_data['target'], chunk)
                
                elif cmd == 'notice':
                    text = clean_message(cmd_data['text'])
                    for chunk in self._split_privmsg(cmd_data['target'], text, "PRIVMSG"):
                        self.connection.privmsg(cmd_data['target'], chunk)
                
                elif cmd == 'action':
                    text = clean_message(cmd_data['text'])
                    target = cmd_data['target']
                    # Account for 9 bytes of CTCP wrapping (\x01ACTION ...\x01)
                    prefix = f"PRIVMSG {target} :"
                    max_bytes = self._IRC_MAX_BYTES - len(prefix.encode("utf-8")) - 9
                    encoded = text.encode("utf-8")
                    while encoded:
                        chunk_bytes = encoded[:max_bytes]
                        while chunk_bytes:
                            try:
                                chunk = chunk_bytes.decode("utf-8")
                                break
                            except UnicodeDecodeError:
                                chunk_bytes = chunk_bytes[:-1]
                        else:
                            encoded = encoded[max_bytes:]
                            continue
                        self.connection.action(target, chunk)
                        encoded = encoded[len(chunk_bytes):]
                
                elif cmd == 'join':
                    self.connection.join(cmd_data['channel'])
                
                elif cmd == 'part':
                    reason = cmd_data.get('reason', '')
                    self.connection.part(cmd_data['channel'], clean_message(reason))
                
                elif cmd == 'mode':
                    self.connection.mode(cmd_data['channel'], cmd_data['modes'])

                elif cmd == 'quit':
                    self.connection.quit(cmd_data['message'])
                    time.sleep(2.0)
                    self.core_q.put_nowait({'cmd': 'quit', 'message': clean_message(cmd_data['message'])})
                
                elif cmd == 'kick':
                    reason = cmd_data.get('reason', 'Kicked')
                    self.connection.kick(
                        cmd_data['channel'],
                        cmd_data['nick'],
                        clean_message(reason)
                    )
                
                elif cmd == 'whois':
                    nick = cmd_data['nick']
                    req_id = hash(nick)
                    self.whois_trackers[req_id] = {'nick': nick}
                    self.connection.whois(nick)

                elif cmd == 'who':
                    self.connection.send_raw(f"WHO {cmd_data['channel']}")

                elif cmd == 'ping':
                    token = cmd_data.get('token', str(int(time.time())))
                    self.connection.ping(token)

                elif cmd == 'raw':
                    self.connection.send_raw(cmd_data['line'])
                
                else:
                    if cmd is not None:
                        log.error(f"[IRC] Unknown command: {cmd}")
        
        except Exception as e:
            log.error(f"Command failed {cmd_data}: {e}")

    async def maintenance_loop(self):
        """Maintenance every 15s"""
        while True:  # Add while True
            try:
                current_ppid = os.getppid()
                if current_ppid != self._supervisor_ppid or current_ppid == 1:
                    log.warning(f"Supervisor gone (ppid {self._supervisor_ppid} → {current_ppid}) — self-terminating")
                    os._exit(1)

                if self.is_connected:  # Check first
                    # Clean timers
                    for name, task in list(self.irc_timers.items()):
                        if task.done():
                            del self.irc_timers[name]
                    
                    await self._check_channels()
                    await self._check_nick()
                
                await asyncio.sleep(15)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Maintenance error: {e}")
                await asyncio.sleep(60) 

    async def _check_channels(self):
        """Rejoin active channels if missing, with flood protection/backoff."""
        try:
            if not self.is_connected:
                return
            active_chans = await self.chan.getchans() or []
            now = datetime.now()
            current_chans = {chan_name.lower(): chan for chan_name, chan in self.channels.items()}
            join_attempts = self.maintenance_state.get('join_attempts', {})
            join_cooldown_until = self.maintenance_state.get('join_cooldown_until', {})  # Fix: {} not 0

            log.debug(f"Active: {active_chans}, Current: {list(current_chans)}")

            for chan in active_chans:
                chan_lower = chan.lower()
                if chan_lower in current_chans:
                    continue

                cooldown_until = join_cooldown_until.get(chan_lower)
                if cooldown_until and now < cooldown_until:
                    log.debug(f"Join cooldown active for {chan} until {cooldown_until}")
                    continue

                attempts = join_attempts.setdefault(chan_lower, deque())  # Fix: safe default deque

                # Keep only attempts from the last 5 minutes
                cutoff = now - timedelta(minutes=5)
                while attempts and attempts[0] < cutoff:
                    attempts.popleft()

                # If we've already tried 3 times in the last 5 minutes, back off for 30 minutes
                if len(attempts) >= 3:
                    cooldown_until = now + timedelta(minutes=30)
                    join_cooldown_until[chan_lower] = cooldown_until
                    attempts.clear()
                    log.warning(f"Join backoff triggered for {chan}; pausing until {cooldown_until}")
                    continue

                self.connection.join(chan)
                attempts.append(now)
                log.info(f"Trying to join: {chan} (attempts in last 5m: {len(attempts)})")

            # Persist updated state back
            self.maintenance_state['join_attempts'] = join_attempts
            self.maintenance_state['join_cooldown_until'] = join_cooldown_until

        except Exception as e:
            log.error(f"_check_channels error: {e}", exc_info=True)

    async def _check_nick(self):
        """Periodically try to reclaim the desired nick if on a fallback."""
        if not self.is_connected:
            return

        current = self.connection.get_nickname()
        desired = self._desired_nick

        nicklen = self.server_caps.nicklen
        if len(desired) > nicklen:
            desired = desired[:nicklen]

        if current != desired:
            now = datetime.now()
            last = self.maintenance_state.get('last_nick_attempt', datetime.min)

            if now - last > timedelta(minutes=1):
                self.connection.nick(desired)
                self._nick_adjusted = desired
                self.maintenance_state['last_nick_attempt'] = now
                log.info(f"[IRC] Trying to reclaim nick: '{desired}'")

    def _schedule_register_timer(self, name: str, interval: float):
        """Schedule timer registration on the event loop."""
        asyncio.create_task(self._register_irc_timer(name, interval))

    def _schedule_unregister_timer(self, name: str):
        """Schedule timer cancellation on the event loop."""
        asyncio.create_task(self._unregister_irc_timer(name))

    async def _register_irc_timer(self, name: str, interval: float):
        """Register a repeating IRC timer."""
        if name in self.irc_timers:
            self.irc_timers[name].cancel()
        task = asyncio.create_task(self._irc_timer_loop(name, interval))
        self.irc_timers[name] = task
        #log.info(f"Registered IRC timer: {name} ({interval}s)")

    async def _unregister_irc_timer(self, name: str):
        """Cancel and remove a named IRC timer."""
        if name in self.irc_timers:
            self.irc_timers[name].cancel()
            del self.irc_timers[name]
            #log.info(f"Unregistered IRC timer: {name}") 

    def connect_now(self):
        """Force reconnect if throttled cooldown passed."""
        now = time.time()
        if now - self.last_connect_attempt < 300:
            log.debug(f"Connect throttled {int(now - self.last_connect_attempt)}s ago")
            return False
        self.last_connect_attempt = now
        if not self.is_connected:  # property, no ()
            self.jump_server("Timer reconnect")
            #log.info("Timer forced jump_server()")
            return True
        return False

    def _check_connection_health(self):
        """Detect stale conn: socket error or no PONG in 5min."""
        if self.is_connected:
            try:
                # Test socket
                sock = self.connection.socket
                sock.settimeout(3)
                sock.send(b'\n')  # minimal probe (no-op)
                return True
            except (socket_module.error, OSError, BrokenPipeError):
                log.warning("Socket probe failed")
                return False
        return False

    async def _join_if_tracked(self, conn, channel: str) -> None:
        """Async helper: rejoin channel if it exists in DB."""
        try:
            if await self.chan.exist(channel):
                conn.join(channel)
        except Exception as e:
            log.error(f"_rejoin_if_tracked failed for {channel}: {e}")

    async def _irc_timer_loop(self, name: str, interval: float):
        while True:
            await asyncio.sleep(interval)
            
            snapshot = {
                'connected': self.is_connected,
                'botname': self.connection.get_nickname() if self.connection else None,
                'channels': {}
            }
            
            for chan_name in list(self.channels.keys()):
                chan_obj = self.channels.get(chan_name)
                
                if chan_obj:
                    log.debug(f"Building snapshot for {chan_name}")
                    
                    try:
                        snapshot['channels'][chan_name] = {
                            'users': len(chan_obj.users()),
                            'user_list': list(chan_obj.users()),
                            'bot_op': self.is_bot_op(chan_name),
                            'ops': list(chan_obj.opers()),
                            'halfops': [n for n, m in chan_obj.users.items() if '%' in getattr(m, 'modes', '')],
                            'voiced': list(chan_obj.voiced()),
                            'mode': ''.join(f"{k}{v}" if v else k for k, v in chan_obj.modes.items()),
                            'mode_params': getattr(chan_obj, 'mode_params', {}),
                        }
                        log.debug(f"Successfully added {chan_name} to snapshot")
                        
                    except Exception as inner_e:
                        log.error(f"Error building snapshot for {chan_name}: {inner_e}", exc_info=True)

            if not self._check_connection_health():
                if self.connect_now():  # throttled
                    #log.info("Forced reconnect via timer")
                    pass

            # Sending event to core            
            event = {
                'type': 'IRC_TIMER_FIRED',
                'timer_name': name,
                'irc_data': snapshot
            }
            self._emit_event(event)                 

def start_irc_process(config, core_q, irc_q):
    """
    Entry point for IRC process
    """
    irc = WbsIrcBot(config, core_q, irc_q)

    # Start async maintenance
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    def command_poller():
        """Daemon thread: poll irc_q and execute commands with anti-flood throttle."""
        irc.loop = loop
        throttle_interval = 0.5  # 500ms between commands (anti-flood)
        last_cmd_time = 0

        while True:
            try:
                elapsed = time.time() - last_cmd_time
                if elapsed < throttle_interval:
                    time.sleep(throttle_interval - elapsed)

                cmd_data = irc_q.get(timeout=0.01)  # blocks up to 10ms, no exception spam
                log.debug(f"Executing: {cmd_data}")
                irc.execute_command(cmd_data)
                last_cmd_time = time.time()

            except queue.Empty:
                pass  # nothing pending, loop back

            except Exception as e:
                log.error(f"Command poller error: {e}")
                time.sleep(0.1)
    
    poller = threading.Thread(target=command_poller, daemon=True)
    poller.start()

    # Async maintenance in event loop thread
    def event_loop_thread():
        irc.maintenance_task = loop.create_task(irc.maintenance_loop())
        try:
            loop.run_forever()
        finally:
            irc.maintenance_task.cancel()
            loop.close()
    
    event_loop = threading.Thread(target=event_loop_thread, daemon=True)
    event_loop.start()

    log.info(f"IRC process started. (pid={os.getpid()})")
    irc.start()

def irc_process_launcher(config: dict, core_q, irc_q):
    """IRC subprocess entry point. core_pid/core_argv accepted but unused."""
    start_irc_process(config, core_q, irc_q)