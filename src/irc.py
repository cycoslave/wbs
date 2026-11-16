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
import functools
import irc.bot
import irc.client
import irc.connection
import irc.events
import ssl as ssl_lib
import socket as socket_module
from datetime import datetime, timedelta
from collections import defaultdict, deque
from jaraco.stream import buffer

from .helper import clean_message
from .user import UserManager
from .channel import ChannelManager, DEFAULT_PREFIX_CHARS, parse_mode_changes
from .ignore import IgnoreCache, IGNORED_EVENT_TYPES, irc_match
from .flood import (FloodGuard, config_rate, ban_mask, DEFAULT_CTCP_RATE,
                    PRIVATE_IGNORE_SECONDS)
from .subnet import local_subnet_id
from .idrules import valid_nick
from .ircreq import WHOIS_FORWARD
from .logsafe import event_summary, irc_cmd_summary, safe, guard_library_logs
from . import __version__

log = logging.getLogger("wbs.irc")
# SAST-002: the irc library traces every raw line (server PASS, PRIVMSG
# `identify <password>`, DCC chatauth) at DEBUG; never let that reach a log.
guard_library_logs()

SOURCE_URL = "https://github.com/cycoslave/wbs"
# CTCP requests the bot answers (IRC-9); DCC is handled separately.
CTCP_SUPPORTED = ("CLIENTINFO", "FINGER", "PING", "SOURCE", "TIME", "USERINFO", "VERSION")

class EventType:
    PUBMSG = 'PUBMSG'
    PRIVMSG = 'PRIVMSG'
    NOTICE = 'NOTICE'
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


# ---------------------------------------------------------------------------
# IRC server list / transport policy (SAST-005)
# ---------------------------------------------------------------------------
class IrcConfigError(ValueError):
    """Invalid IRC server configuration. Always fatal: never fall back."""


class IrcServerSpec(irc.bot.ServerSpec):
    """
    ServerSpec carrying its own transport policy.

    irc 20.x ServerSpec only knows host/port/password, and SingleServerIRCBot
    passes one set of connect params to every server. The per-server
    `connect_factory` here is what WbsIrcBot._connect hands to connect(), so
    each server gets exactly the transport it was configured with.
    """

    def __init__(self, host: str, port: int, password: str | None = None, *,
                 tls: bool = False, ssl_context: ssl_lib.SSLContext | None = None):
        super().__init__(host, port, password)
        if tls and ssl_context is None:
            raise IrcConfigError(f"{host}:{port}: TLS server without an SSL context")
        self.tls = bool(tls)
        self.ssl_context = ssl_context if tls else None
        if tls and ssl_context is not None:
            # server_hostname drives SNI and the hostname check.
            wrapper = functools.partial(ssl_context.wrap_socket,
                                        server_hostname=host)
            self.connect_factory = irc.connection.Factory(wrapper=wrapper)
        else:
            self.connect_factory = irc.connection.Factory()

    def __repr__(self):
        return (f"<IrcServerSpec {self.host}:{self.port} "
                f"{'tls' if self.tls else 'plaintext'} "
                f"{'with' if self.password else 'without'} password>")


_SERVER_KEYS = frozenset({'host', 'port', 'password', 'ssl', 'ssl_verify', 'ssl_ca_file'})
_TLS_ONLY_KEYS = ('ssl_verify', 'ssl_ca_file')


def _build_tls_context(label: str, ca_file: str | None) -> ssl_lib.SSLContext:
    """Verifying client context: CERT_REQUIRED + hostname check, TLS >= 1.2."""
    try:
        ctx = ssl_lib.create_default_context(cafile=ca_file)
    except (OSError, ssl_lib.SSLError) as exc:
        raise IrcConfigError(f"{label}: cannot load ssl_ca_file {ca_file!r}: {exc}") from exc
    ctx.minimum_version = ssl_lib.TLSVersion.TLSv1_2
    # create_default_context already sets these; assert so a future edit
    # cannot silently weaken them.
    if not ctx.check_hostname or ctx.verify_mode != ssl_lib.CERT_REQUIRED:
        raise IrcConfigError(f"{label}: TLS context is not verifying")
    return ctx


def _parse_server_entry(idx: int, s) -> IrcServerSpec:
    label = f"bot.servers[{idx}]"
    if not isinstance(s, dict):
        raise IrcConfigError(f"{label}: must be an object, got {type(s).__name__}")
    unknown = set(s) - _SERVER_KEYS
    if unknown:
        raise IrcConfigError(f"{label}: unknown key(s) {sorted(unknown)}; "
                             f"allowed: {sorted(_SERVER_KEYS)}")

    host = s.get('host')
    if not isinstance(host, str) or not host.strip() or any(c.isspace() for c in host):
        raise IrcConfigError(f"{label}: 'host' must be a non-empty hostname")

    port = s.get('port')
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise IrcConfigError(f"{label}: 'port' must be an integer 1-65535")

    password = s.get('password')
    if password is not None and not isinstance(password, str):
        raise IrcConfigError(f"{label}: 'password' must be a string or null")

    use_tls = s.get('ssl', False)
    if not isinstance(use_tls, bool):
        raise IrcConfigError(f"{label}: 'ssl' must be true or false")

    label = f"{label} ({host}:{port})"
    if not use_tls:
        stray = [k for k in _TLS_ONLY_KEYS if k in s]
        if stray:
            raise IrcConfigError(f"{label}: {stray} set but 'ssl' is not true; "
                                 f"refusing to guess the intended transport")
        return IrcServerSpec(host, port, password, tls=False)

    verify = s.get('ssl_verify', True)
    if not isinstance(verify, bool):
        raise IrcConfigError(f"{label}: 'ssl_verify' must be true or false")
    if verify is False:
        raise IrcConfigError(f"{label}: ssl_verify=false is not supported; for a "
                             f"self-signed/private CA set 'ssl_ca_file' to its PEM")
    ca_file = s.get('ssl_ca_file')
    if ca_file is not None and (not isinstance(ca_file, str) or not ca_file):
        raise IrcConfigError(f"{label}: 'ssl_ca_file' must be a file path")

    return IrcServerSpec(host, port, password, tls=True,
                         ssl_context=_build_tls_context(label, ca_file))


def build_server_specs(config: dict) -> list[IrcServerSpec]:
    """
    Validate the complete bot.servers list and return per-server specs.

    Fails closed: any malformed entry raises IrcConfigError; there is no
    default/legacy endpoint. A list mixing TLS and plaintext servers is
    rejected unless bot.allow_plaintext_fallback is explicitly true, because
    the reconnect rotation would otherwise hop from a TLS server to plaintext.
    """
    bot = config.get('bot') if isinstance(config, dict) else None
    if not isinstance(bot, dict):
        raise IrcConfigError("missing 'bot' section")
    servers = bot.get('servers')
    if not isinstance(servers, list) or not servers:
        raise IrcConfigError("'bot.servers' must be a non-empty list")

    specs = [_parse_server_entry(i, s) for i, s in enumerate(servers)]

    allow_mixed = bot.get('allow_plaintext_fallback', False)
    if not isinstance(allow_mixed, bool):
        raise IrcConfigError("'bot.allow_plaintext_fallback' must be true or false")
    kinds = {sp.tls for sp in specs}
    if len(kinds) > 1 and not allow_mixed:
        plain = [f"{sp.host}:{sp.port}" for sp in specs if not sp.tls]
        raise IrcConfigError(
            f"bot.servers mixes TLS and plaintext servers (plaintext: {plain}); "
            f"set 'ssl': true on every server, or set "
            f"bot.allow_plaintext_fallback=true to accept plaintext rotation")
    return specs


def _who(source) -> dict:
    """Sender fields every user event carries (PLG-7): `nick`, `host` (the
    full nick!user@host) and `uhost` (user@host; '' for a server source)."""
    src = irc.client.NickMask(str(source or ''))
    return {'nick': src.nick, 'host': str(src), 'uhost': src.userhost or ''}


# MODE letter -> (event for '+', event for '-') for plugins (PLG-8).
MODE_EVENTS = {
    'o': ('OP', 'DEOP'),
    'h': ('HALFOP', 'DEHALFOP'),
    'v': ('VOICE', 'DEVOICE'),
    'b': ('BAN', 'UNBAN'),
}


def _account_tag(event) -> str | None:
    """Services account from a server-set IRCv3 `account` message tag.

    Only the exact key `account` counts (client-only tags carry a `+`
    prefix and cannot spoof it).  None when absent, malformed or '*'.
    The tag is only present when the server has the account-tag capability
    enabled for this connection; consumers must treat None as "unknown".
    """
    for tag in getattr(event, 'tags', None) or ():
        if isinstance(tag, dict) and tag.get('key') == 'account':
            value = tag.get('value')
            if isinstance(value, str) and value and value != '*' \
                    and not any(c in value for c in ' \r\n\x00'):
                return value
            return None
    return None


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
    # Set once the bot is shutting down: no reconnects after the QUIT.
    _quitting = False

    def __init__(self, config, core_q, irc_q):
        self.config = config
        self._supervisor_ppid = os.getppid()
        self._irc_ready = False
        # Public IP seen in our own USERHOST reply; re-sent to a new Core (.rehash).
        self.public_ip = None
        self.chan = ChannelManager(self.config['db']['path'])
        self.user = UserManager(self.config['db']['path'])
        self.server_caps = ServerCaps()
        self._desired_nick: str = config.get('bot', {}).get('nick', 'wbs')
        self._nick_adjusted: str = self._desired_nick
        self._nick_attempt: str = self._desired_nick   # last nick asked for (IRC-11)
        self._nick_errors: int = 0
        self.core_q = core_q
        self.irc_q = irc_q
        self.config_id = config.get('id', 1)
        # FINGER idle time (IRC-9): seconds since the bot last spoke.
        self._last_activity = time.monotonic()
        self.maintenance_state = {
            'last_rejoin': {},
            'last_nick': 0,
            'linked_bots': {},
            'join_attempts': defaultdict(deque),
            'join_cooldown_until': {},
            'last_nick_attempt': datetime.min,
        }
        self.irc_timers = {}  # name → task
        # name → {'interval', 'last_run', 'next_run'} for `.timers` (NET-9)
        self.irc_timer_info = {}
        self.last_connect_attempt = 0
        irc.client.ServerConnection.buffer_class = buffer.LenientDecodingLineBuffer
        irc.client.ServerConnection.buffer_class.errors = "replace"
        bot_config = config.get('bot', {}) if isinstance(config.get('bot'), dict) else {}
        # IRC ident; library falls back to nick. Kept on self because our
        # _connect passes it explicitly (it does not read the library's
        # private connect params).
        self._username = bot_config.get('user') or None
        servers = self._parse_servers(config)
        super().__init__(
            servers,
            bot_config.get('nick', 'wbs'),
            bot_config.get('realname', 'WBS Bot'),
            username=self._username,
        )
        # Ignore list (USR-11): checked in the reactor before any on_* handler
        # (priority -30 runs ahead of the library's -20 and the -10
        # dispatcher), so an ignored sender's PRIVMSG/NOTICE/CTCP (DCC
        # included) never becomes an event for Core, commands, games or
        # plugins.
        self.ignores = IgnoreCache(self.config['db']['path'], local_subnet_id(config))
        for etype in IGNORED_EVENT_TYPES:
            self.connection.add_global_handler(etype, self._drop_ignored, -30)
        # The bot's own CTCP flood limit (IRC-7): checked here, before any
        # CTCP reply is sent.  A flooding host is dropped at once for
        # PRIVATE_IGNORE_SECONDS and Core puts it on the ignore list.
        self.ctcp_rate = config_rate(config, 'flood_ctcp', DEFAULT_CTCP_RATE)
        self.ctcp_guard = FloodGuard()
        self.flood_ignored: dict[str, float] = {}   # *!*@host -> until (monotonic)
        # Numeric replies (IRC-1).  The library names numeric events
        # ('352' -> 'whoreply'), so a handler registered under the bare
        # number never fires.  Registered once here, not per connect.
        # 302/432/433 are not listed: the dispatcher already calls
        # on_userhost / on_erroneusnickname / on_nicknameinuse by name.
        numerics = {
            '331': self.on_331,    # RPL_NOTOPIC
            '332': self.on_332,    # RPL_TOPIC
            '333': self.on_333,    # RPL_TOPICWHOTIME
            '324': self.on_324,    # RPL_CHANNELMODEIS
            '329': self.on_329,    # RPL_CHANNELCREATETIME
            '367': self.on_367,    # RPL_BANLIST
            '346': self.on_346,    # RPL_INVITELIST
            '348': self.on_348,    # RPL_EXCEPTLIST
            '368': self.on_368,    # RPL_ENDOFBANLIST
            '347': self.on_347,    # RPL_ENDOFINVITELIST
            '349': self.on_349,    # RPL_ENDOFEXCEPTLIST
            '352': self.on_352,    # RPL_WHOREPLY
            '315': self.on_315,    # RPL_ENDOFWHO
            '471': self.on_471,    # ERR_CHANNELISFULL
            '473': self.on_473,    # ERR_INVITEONLYCHAN
            '474': self.on_474,    # ERR_BANNEDFROMCHAN
            # Server errors for requests made on a caller's behalf (IRC-8):
            # Core matches them to the pending .mode/.op/... request.
            '401': self._numeric_error,    # ERR_NOSUCHNICK     [nick, text]
            '403': self._numeric_error,    # ERR_NOSUCHCHANNEL  [chan, text]
            '441': self._numeric_error,    # ERR_USERNOTINCHANNEL [nick, chan, text]
            '442': self._numeric_error,    # ERR_NOTONCHANNEL   [chan, text]
            '467': self._numeric_error,    # ERR_KEYSET         [chan, text]
            '472': self._numeric_error,    # ERR_UNKNOWNMODE    [letter, text]
            '477': self._numeric_error,    # ERR_NOCHANMODES    [chan, text]
            '482': self._numeric_error,    # ERR_CHANOPRIVSNEEDED [chan, text]
            '696': self._numeric_error,    # ERR_INVALIDMODEPARAM [chan, mode, param, text]
        }
        # .swhois / .swhowas output (IRC-10): Core collects these per request.
        for code in sorted(WHOIS_FORWARD):
            numerics[code] = self._whois_numeric
        for code, handler in numerics.items():
            self.connection.add_global_handler(
                irc.events.numeric.get(code, code), handler, -20)
        self._emit_event({'type': 'REQUEST_BOTLINKS'})

    def _drop_ignored(self, conn, event):
        """Reactor handler: stop processing of messages from ignored hosts."""
        source = event.source
        if not source or '!' not in str(source):
            return None   # server notices etc.
        if self._flood_ignored(str(source)):
            log.debug("[IRC] Dropped %s from %s (CTCP flood)", event.type, source)
            return "NO MORE"
        mask = self.ignores.match(str(source))
        if mask is None:
            return None
        log.debug("[IRC] Ignored %s from %s (matches %s)", event.type, source, mask)
        return "NO MORE"

    def _flood_ignored(self, source: str) -> bool:
        if not self.flood_ignored:
            return False
        now = time.monotonic()
        for mask, until in list(self.flood_ignored.items()):
            if until <= now:
                del self.flood_ignored[mask]
            elif irc_match(mask, source):
                return True
        return False

    def _ctcp_flooded(self, event) -> bool:
        """Count one CTCP request against the bot's own limit (IRC-7).
        True = drop it: the sender's host flooded and is now ignored."""
        source = str(event.source or '')
        mask = ban_mask(source.partition('!')[2])
        if mask is None or self.ctcp_rate is None:
            return False
        if not self.ctcp_guard.hit(mask.lower(), *self.ctcp_rate):
            return False
        self.ignores._fresh()
        if any(irc_match(p, source) for p in self.ignores.protected):
            log.info("[IRC] CTCP flood from %s not ignored (owner/admin)", source)
            return False
        self.flood_ignored[mask] = time.monotonic() + PRIVATE_IGNORE_SECONDS
        log.warning("[IRC] CTCP flood from %s: ignoring %s for %ds",
                    source, mask, PRIVATE_IGNORE_SECONDS)
        self._emit_event({'type': 'FLOOD_IGNORE', 'mask': mask, 'source': source,
                          'reason': 'CTCP flood'})
        return True

    def _chan_activity(self, kind: str, event) -> None:
        """Channel traffic Core counts for flood protection only (IRC-7)."""
        if event.target and irc.client.is_channel(event.target) and event.source:
            self._emit_event({'type': 'CHAN_ACTIVITY', 'kind': kind,
                              'channel': event.target, 'nick': event.source.nick,
                              'host': str(event.source)})

    def on_action(self, conn, event):
        """/me in a channel: counts as channel text (flood_pub) and is an
        ACTION event for plugins (PLG-8)."""
        self._chan_activity('pub', event)
        if event.target and irc.client.is_channel(event.target) and event.source:
            self._emit_event({
                'type': 'ACTION',
                'channel': event.target,
                **_who(event.source),
                'text': event.arguments[0] if event.arguments else '',
            })

    def on_pubnotice(self, conn, event):
        """A NOTICE to a channel counts as channel text (flood_pub)."""
        self._chan_activity('pub', event)

    def _parse_servers(self, config: dict) -> list[IrcServerSpec]:
        """Validated per-server specs. Invalid config is fatal (no fallback endpoint)."""
        try:
            return build_server_specs(config)
        except IrcConfigError as e:
            log.critical(f"Invalid IRC server config, refusing to connect: {e}")
            self._emit_event({
                'type': EventType.ERROR,
                'data': 'config_invalid',
                'error': str(e),
            })
            raise
    
    def _emit_event(self, event_data: dict):
        """Send event to core.py via queue"""
        event_data['config_id'] = self.config_id
        try:
            self.core_q.put(event_data, block=False)
        except queue.Full:
            log.error(f"Event queue full, dropping: {event_data['type']}")
        
    def _connect(self):
        """
        Connect to the server at the front of the rotation using THAT
        server's transport (TLS factory or plain), never a shared default.

        Replaces SingleServerIRCBot._connect, which applies one set of
        connect params to every server. TLS handshake / certificate /
        hostname failures surface as ServerConnectionError (ssl errors are
        OSError) and go through the normal disconnect -> reconnect path;
        they never retry the same server without TLS.
        """
        server = self.servers.peek()
        factory = getattr(server, 'connect_factory', None)
        if not isinstance(server, IrcServerSpec) or factory is None:
            # Only reachable if someone swaps self.servers; fail closed.
            raise IrcConfigError(f"refusing to connect to {server!r}: no transport policy")
        try:
            self.connect(
                server.host,
                server.port,
                self._nickname,
                server.password,
                username=self._username,
                ircname=self._realname,
                connect_factory=factory,
            )
        except irc.client.ServerConnectionError as e:
            log.error(f"Connection to {server.host}:{server.port} "
                      f"({'tls' if server.tls else 'plaintext'}) failed: {e}")
            self._emit_event({
                'type': EventType.ERROR,
                'data': 'connect_fail',
                'error': str(e)
            })
            # Same as the library: synthesize a disconnect so the reconnect
            # strategy schedules the next attempt.
            self.connection._handle_event(
                irc.client.Event("disconnect", self.connection.server, "", [""])
            )

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

    def _quit_server(self, message: str) -> None:
        """
        Send QUIT and close the connection in order (USR-20).

        ServerConnection.disconnect() writes the QUIT line, shuts the socket
        down for writing (the kernel delivers everything written before the
        FIN) and only then closes it.  _quitting stops the reconnect logic
        from bringing the bot back.  Called again once Core shuts down, the
        connection is already gone and nothing is sent.
        """
        self._quitting = True
        conn = self.connection
        if not conn.is_connected():
            log.info("[IRC] Quit: no server connection, nothing to send")
            return
        log.info(f"[IRC] Sending QUIT: {message}")
        conn.disconnect(message)

    def _on_disconnect(self, connection, event):
        """Library reconnect hook; no reconnect once the bot is quitting."""
        if self._quitting:
            self.channels = type(self.channels)()
            return
        super()._on_disconnect(connection, event)

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
        conn.send_raw(f"USERHOST {conn.get_nickname()}")
        self._emit_event({
            'type': EventType.READY,
            'botname': conn.get_nickname()
        })
    
    def on_disconnect(self, conn, event):
        """Connection lost"""
        self._irc_ready = False
        if getattr(self, '_quitting', False):
            log.info("Disconnected from server (quit)")
        else:
            log.warning("Disconnected from server")
        self.server_caps.reset()
        self._nick_adjusted = self._nick_attempt = self._desired_nick
        self._nick_errors = 0
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
            **_who(event.source),
            'account': _account_tag(event),
            'text': text
        }
        #log.debug(f"[IRC] Emitting PUBMSG: {event_data}")
        self._emit_event(event_data)
    
    def on_privmsg(self, conn, event):
        """Private message"""
        self._emit_event({
            'type': EventType.PRIVMSG,
            'target': event.target,
            **_who(event.source),
            'account': _account_tag(event),
            'text': event.arguments[0]
        })

    def on_privnotice(self, conn, event):
        """NOTICE from a user to the bot (GAM-6: werewolf night actions).
        Server notices (no nick!user@host source) are not forwarded."""
        if not event.source or '!' not in str(event.source):
            return
        self._emit_event({
            'type': EventType.NOTICE,
            'target': event.target,
            **_who(event.source),
            'account': _account_tag(event),
            'text': event.arguments[0] if event.arguments else ''
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
            # IRC-1: the server sends NAMES (353/366) on its own after our
            # JOIN; WHO and MODE give hosts, full prefixes and channel modes.
            self._request_sync(conn, chan, names=False)
        else:
            self._emit_event({
                'type': EventType.JOIN,
                'channel': chan,
                **_who(event.source),
            })

    def _request_sync(self, conn, chan: str, names: bool = True) -> None:
        """Ask the server for a channel's full live state (IRC-1).
        Core marks the channel synced when the WHO list ends (315)."""
        if names:
            conn.send_raw(f"NAMES {chan}")
        conn.send_raw(f"WHO {chan}")
        conn.send_raw(f"MODE {chan}")

    def _prefix_map(self) -> dict:
        """Prefix char -> mode letter, e.g. {'@': 'o', '+': 'v'}.  From the
        server's 005 PREFIX when it sent one, else ~ & @ % + (IRC-1)."""
        if self.server_caps.get('PREFIX'):
            return {c: m for m, c in self.server_caps.prefix.items()}
        return dict(DEFAULT_PREFIX_CHARS)

    @staticmethod
    def _split_member(entry: str, pmap: dict) -> tuple[str, str, str]:
        """'@+nick!user@host' -> ('nick', 'ov', 'user@host').  Handles
        multi-prefix and userhost-in-names forms."""
        i = 0
        modes = ''
        while i < len(entry) and entry[i] in pmap:
            modes += pmap[entry[i]]
            i += 1
        nick, _, host = entry[i:].partition('!')
        return nick, modes, host

    def on_namreply(self, conn, event):
        """353 RPL_NAMREPLY: arguments = [type, channel, 'nick @op +voice ...']."""
        try:
            channel, names = event.arguments[1], event.arguments[2]
        except IndexError:
            log.warning("[IRC] Malformed 353: %s",
                        event_summary("353", {"arguments": event.arguments}))
            return
        if channel == '*':
            return
        pmap = self._prefix_map()
        members = [list(self._split_member(e, pmap)) for e in names.split()]
        self._emit_event({
            'type': 'NAMES_REPLY',
            'channel': channel,
            'members': [m for m in members if m[0]],
        })

    def on_endofnames(self, conn, event):
        """366 RPL_ENDOFNAMES: arguments = [channel, 'End of /NAMES list.']."""
        if event.arguments:
            self._emit_event({'type': 'NAMES_END', 'channel': event.arguments[0]})
    
    # PART/QUIT/KICK carry the reason as `reason`; every user event carries
    # `nick`, `host` (nick!user@host) and `uhost` (user@host) (PLG-7).
    def on_part(self, conn, event):
        reason = event.arguments[0] if event.arguments else ''
        self._emit_event({
            'type': EventType.PART,
            'channel': event.target,
            **_who(event.source),
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
        # `kicked_uhost` is added by Core, which knows the members' hosts.
        self._emit_event({
            'type': EventType.KICK,
            'channel': channel,
            **_who(event.source),
            'kicked': kicked_nick,
            'reason': reason
        })
    
    def on_quit(self, conn, event):
        reason = event.arguments[0] if event.arguments else ''
        self._emit_event({
            'type': EventType.QUIT,
            **_who(event.source),
            'reason': reason
        })
    
    def on_nick(self, conn, event):
        who = _who(event.source)
        self._emit_event({
            'type': EventType.NICK,
            'old_nick': event.source.nick,
            'new_nick': event.target,
            'host': who['host'],
            'uhost': who['uhost'],
        })
    
    def on_mode(self, conn, event):
        channel = event.target
        modes = event.arguments[0] if event.arguments else ''
        mode_args = event.arguments[1:] if len(event.arguments) > 1 else []
        # IRC-1: split with this server's PREFIX/CHANMODES so Core applies
        # ~ & @ % + and list/key/limit arguments correctly.
        changes = parse_mode_changes(modes, mode_args,
                                     ''.join(self._prefix_map().values()),
                                     self.server_caps.chanmodes)
        who = _who(event.source)
        self._emit_event({
            'type': EventType.MODE,
            'channel': channel,
            'modes': modes,
            'args': mode_args,
            'changes': [list(c) for c in changes],
            **who,
        })
        # PLG-8: one OP/DEOP/HALFOP/DEHALFOP/VOICE/DEVOICE/BAN/UNBAN event
        # per change, with the setter (nick/host/uhost) and its target.
        if not irc.client.is_channel(channel or ''):
            return
        for sign, char, arg in changes:
            names = MODE_EVENTS.get(char)
            if names is None or not arg:
                continue
            etype = names[0] if sign == '+' else names[1]
            data = {'type': etype, 'channel': channel, **who, 'target': arg}
            if char == 'b':
                data['mask'] = arg
            self._emit_event(data)
    
    def _bot_realname(self) -> str:
        bot = self.config.get('bot')
        return (bot.get('realname') if isinstance(bot, dict) else None) or 'WBS Bot'

    def on_ctcp(self, conn, event):
        """Handle CTCP requests (PING, VERSION, etc)"""
        nick = event.source.nick
        ctcp_cmd = event.arguments[0].upper()
        # IRC-7: channel CTCPs count for the channel's flood_ctcp; every
        # CTCP counts for the bot's own limit (a flood gets no replies).
        self._chan_activity('ctcp', event)
        if self._ctcp_flooded(event):
            return

        if ctcp_cmd == 'PING':
            ts = event.arguments[1] if len(event.arguments) > 1 else ''
            conn.ctcp_reply(nick, f"PING {ts}")
        elif ctcp_cmd == 'VERSION':
            conn.ctcp_reply(nick, f"VERSION WBS {__version__}")
        elif ctcp_cmd == 'TIME':
            conn.ctcp_reply(nick, "TIME " + time.strftime("%a %b %d %H:%M:%S %Y %Z"))
        elif ctcp_cmd == 'FINGER':
            idle = int(time.monotonic() - self._last_activity)
            conn.ctcp_reply(nick, f"FINGER {conn.get_nickname()} ({self._bot_realname()}) "
                                  f"Idle {idle} seconds")
        elif ctcp_cmd == 'USERINFO':
            conn.ctcp_reply(nick, f"USERINFO {self._bot_realname()}")
        elif ctcp_cmd == 'CLIENTINFO':
            conn.ctcp_reply(nick, "CLIENTINFO " + " ".join(CTCP_SUPPORTED))
        elif ctcp_cmd == 'SOURCE':
            conn.ctcp_reply(nick, f"SOURCE {SOURCE_URL}")
        elif ctcp_cmd == 'DCC':
            # Log raw args so we can see exactly what jaraco delivers
            log.debug("[IRC] DCC raw arguments from %s: %s", safe(nick),
                      event_summary("DCC", {"arguments": event.arguments}))

            # jaraco may deliver as ['DCC', 'CHAT', 'chat', '<ip>', '<port>']
            # OR as ['DCC', 'CHAT chat <ip> <port>'] (one blob in [1])
            # Flatten and re-split to handle both
            parts = ' '.join(str(a) for a in event.arguments).split()
            # parts[0]='DCC', parts[1]='CHAT', parts[2]='chat', parts[3]=ip, parts[4]=port
            # passive: parts[5]=token

            subtype = parts[1].upper() if len(parts) > 1 else ''
            if subtype == 'CHAT':
                # Token is present only in passive DCC (6th field); it is
                # numeric for irssi/mIRC and for our own offers.
                token = parts[5] if len(parts) >= 6 else None
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
            self.public_ip = host
            self._emit_event({'type': 'BOT_PUBLIC_IP', 'ip': host})
        except (IndexError, ValueError):
            log.warning(f"[IRC] Could not parse USERHOST: {event.arguments!r}")

    # Numeric replies.  The library moves the first parameter (our own nick)
    # into event.target, so event.arguments starts at the channel (IRC-1:
    # these handlers used to index one too far and never fired anyway).
    @staticmethod
    def _arg(event, i: int, default=None):
        args = event.arguments or []
        return args[i] if len(args) > i else default

    def on_332(self, conn, event):  # RPL_TOPIC: [channel, topic]
        chan_name = self._arg(event, 0)
        if not chan_name:
            return
        self._emit_event({
            'type': 'CHANNEL_TOPIC',
            'channel': chan_name,
            'topic': self._arg(event, 1, ''),
            'nick': '',     # server-sent on join
        })

    def on_333(self, conn, event):
        """RPL_TOPICWHOTIME: [channel, setter, timestamp]."""
        try:
            channel   = event.arguments[0]
            setter    = event.arguments[1]   # nick!user@host
            timestamp = int(event.arguments[2])
        except (IndexError, ValueError):
            return
        self._emit_event({
            'type': 'CHANNEL_TOPIC_META',
            'channel': channel,
            'setter': setter,
            'timestamp': timestamp,
        })

    def on_324(self, conn, event):  # RPL_CHANNELMODEIS: [channel, modes, *params]
        chan_name = self._arg(event, 0)
        if not chan_name:
            return
        self._emit_event({
            'type': 'CHANNEL_MODES',
            'channel': chan_name,
            'modes_str': ' '.join(event.arguments[1:])
        })

    def on_329(self, conn, event):  # RPL_CHANNELCREATIONTIME: [channel, ts]
        try:
            chan_name = event.arguments[0]
            created_ts = int(event.arguments[1])
        except (IndexError, ValueError):
            return
        self._emit_event({
            'type': 'CHANNEL_CREATED',
            'channel': chan_name,
            'created': created_ts
        })

    def _list_entry(self, event, etype: str, key: str):
        chan_name, mask = self._arg(event, 0), self._arg(event, 1)
        if chan_name and mask:
            self._emit_event({'type': etype, 'channel': chan_name, key: mask})

    def on_367(self, conn, event):  # RPL_BANLIST: [channel, mask, ...]
        self._list_entry(event, 'BANLIST_ADD', 'ban')

    def on_346(self, conn, event):  # RPL_INVITELIST
        self._list_entry(event, 'INVITELIST_ADD', 'invite')

    def on_348(self, conn, event):  # RPL_EXCEPTLIST
        self._list_entry(event, 'EXEMPTLIST_ADD', 'exempt')

    def _list_end(self, event, etype: str):
        chan_name = self._arg(event, 0)
        if chan_name:
            self._emit_event({'type': etype, 'channel': chan_name})

    def on_368(self, conn, event):  # RPL_ENDOFBANLIST
        self._list_end(event, 'BANLIST_END')

    def on_347(self, conn, event):  # RPL_ENDOFINVITELIST
        self._list_end(event, 'INVITELIST_END')

    def on_349(self, conn, event):  # RPL_ENDOFEXCEPTLIST
        self._list_end(event, 'EXCEPTLIST_END')

    def on_352(self, conn, event):
        """
        RPL_WHOREPLY — one line per user in response to WHO #channel.
        Wire: 352 botnick channel user host server nick flags :hopcount realname
        event.arguments = [channel, user, host, server, nick, flags, 'hopcount realname']
        """
        try:
            args      = event.arguments
            channel   = args[0]
            user      = args[1]   # ident
            host      = args[2]
            nick      = args[4]
            flags     = args[5]   # e.g. 'H@', 'G+', 'H*~@', 'H'
        except IndexError:
            log.warning("[IRC] Malformed 352: %r", event.arguments)
            return

        # flags: H=here G=gone(away), *=ircop, then channel prefixes.
        pmap = self._prefix_map()
        user_modes = ''.join(pmap[c] for c in flags if c in pmap)

        self._emit_event({
            'type': 'WHO_REPLY',
            'channel': channel,
            'nick': nick,
            'user': user,
            'host': host,
            'flags': flags,
            'modes': user_modes,
            'is_op': any(m in 'qao' for m in user_modes),
            'is_halfop': 'h' in user_modes,
            'is_voice': 'v' in user_modes,
        })

    def on_315(self, conn, event):
        """
        RPL_ENDOFWHO — WHO response is complete for this channel.
        event.arguments = [channel, 'End of /WHO list']
        """
        channel = self._arg(event, 0)
        if not channel:
            return
        self._emit_event({
            'type': 'WHO_END',
            'channel': channel,
        })

    def on_471(self, conn, event):  # ERR_CHANNELISFULL: [channel, text]
        self._list_end(event, 'ERR_CHANNELISFULL')

    def on_473(self, conn, event):  # ERR_INVITEONLYCHAN
        self._list_end(event, 'ERR_INVITEONLYCHAN')

    def on_474(self, conn, event):  # ERR_BANNEDFROMCHAN
        self._list_end(event, 'ERR_BANNEDFROMCHAN')

    def _whois_numeric(self, conn, event):
        """WHOIS/WHOWAS numerics (311 312 313 314 317 318 319 330 369 406):
        forwarded to Core, which matches them to the `.swhois`/`.swhowas`
        request (IRC-10).  event.arguments = [nick, ...] (our own nick is
        the event target)."""
        code = irc.events.codes.get(event.type) or getattr(event.type, 'code', None) \
            or str(event.type)
        args = [str(a) for a in (event.arguments or [])]
        self._emit_event({'type': 'WHOIS_NUMERIC', 'numeric': str(code), 'args': args})

    def on_topic(self, conn, event):
        """Live topic change during session (TOPIC), with the setter."""
        self._emit_event({
            'type': 'TOPIC',
            'channel': event.target,
            'topic': event.arguments[0] if event.arguments else '',
            **_who(event.source),
        })

    def on_331(self, conn, event):  # RPL_NOTOPIC: [channel, text]
        """No topic set (sent instead of 332 on join): an empty
        CHANNEL_TOPIC, so topiclock can apply its locked topic (PLG-8b)."""
        chan_name = self._arg(event, 0)
        if chan_name:
            self._emit_event({'type': 'CHANNEL_TOPIC', 'channel': chan_name,
                              'topic': '', 'nick': ''})

    def on_featurelist(self, conn, event):
        """005 RPL_ISUPPORT — ingest capabilities."""
        self.server_caps.ingest(event.arguments)
        #log.info(f"[IRC] {self.server_caps}")

        # Enforce NICKLEN immediately if nick is too long
        nicklen = self.server_caps.nicklen
        if len(self._desired_nick) > nicklen:
            truncated = self._desired_nick[:nicklen]
            log.info(f"[IRC] Nick truncated to '{truncated}' (NICKLEN={nicklen})")
            self._nick_adjusted = self._nick_attempt = truncated
            conn.nick(truncated)

    # Nick-change fallback (IRC-11).  433 (in use) and 432 (erroneous) are
    # different problems: a taken nick is retried with two digits, a nick the
    # server calls syntactically invalid is never "fixed" by appending digits.
    # Once registered (001 seen) neither changes the bot's nick: it keeps the
    # one it has and Core tells the `.nick` caller.  `_nick_attempt` is the
    # nick last asked for, by the registration code or by `.nick`.
    _NICK_ERR_LIMIT = 5

    def _numeric_error(self, conn, event):
        """Server error numerics Core matches to pending requests (IRC-8)."""
        # event.type is the library's name for the numeric ('nosuchnick');
        # Core matches on the number.
        code = irc.events.codes.get(event.type) or getattr(event.type, 'code', None) \
            or str(event.type)
        self._emit_event({'type': 'IRC_NUMERIC', 'numeric': str(code),
                          'args': [str(a) for a in (event.arguments or [])]})

    def on_nicknameinuse(self, conn, event):
        """
        433 ERR_NICKNAMEINUSE.

        * registered: keep the current nick and tell Core (a `.nick` caller
          hears it; the reclaim timer just retries later)
        * registering: pick an alternative nick per spec:
            len(nick) >= NICKLEN - 1  -> cut to NICKLEN-2, append 2 digits
            len(nick) <= NICKLEN - 2  -> append 2 random digits directly
        """
        wanted = self._arg(event, 0) or self._nick_attempt
        if self._irc_ready:
            log.warning(f"[IRC] Nick '{wanted}' is in use; keeping '{conn.get_nickname()}'")
            self._nick_attempt = conn.get_nickname()
            self._emit_event({'type': 'IRC_NUMERIC', 'numeric': '433', 'args': [wanted]})
            return
        desired = self._nick_attempt            # last attempted nick
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
        self._nick_adjusted = self._nick_attempt = alt_nick
        conn.nick(alt_nick)

    def on_erroneusnickname(self, conn, event):
        """
        432 ERR_ERRONEUSNICKNAME - the server refuses the nick's syntax.

        * registered: keep the current nick and tell Core.  Nothing is sent,
          so a bad `.nick` can never leave the bot as 'wI157'.
        * registering: the configured nick is unusable; try it cleaned up
          (invalid characters dropped, cut to NICKLEN), else 'wbs' + 2
          digits.  Bounded: after _NICK_ERR_LIMIT refusals it stops trying.
        """
        bad = self._arg(event, 0) or self._nick_attempt
        if self._irc_ready:
            log.warning(f"[IRC] Server refused nick '{bad}' (432); "
                        f"keeping '{conn.get_nickname()}'")
            self._nick_attempt = conn.get_nickname()
            self._emit_event({'type': 'IRC_NUMERIC', 'numeric': '432', 'args': [bad]})
            return
        self._nick_errors += 1
        if self._nick_errors > self._NICK_ERR_LIMIT:
            log.error(f"[IRC] Nick '{bad}' refused (432) and no usable fallback; giving up")
            return
        nicklen = int(self.server_caps.get('NICKLEN', 9))
        cleaned = ''.join(c for c in bad if c.isascii() and (c.isalnum() or c in '[]\\`_^{|}-'))
        cleaned = cleaned.lstrip('-0123456789')[:nicklen]
        if not cleaned or cleaned == bad:
            cleaned = 'wbs' + ''.join(random.choices(string.digits, k=2))
        log.warning(f"[IRC] Erroneous nick '{bad}', trying '{cleaned}'")
        self._nick_adjusted = self._nick_attempt = cleaned
        conn.nick(cleaned)

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

    def mass_mode_lines(self, channel: str, sign: str, mode: str, nicks) -> list:
        """MODE lines setting `sign``mode` on each nick: at most 005 MODES
        changes per line (3 when the server did not say) and 510 bytes."""
        per_line = max(1, self.server_caps.modes)
        head = f"MODE {channel} "
        lines, batch = [], []

        def render(b):
            return f"{head}{sign}{mode * len(b)} {' '.join(b)}"

        for nick in nicks:
            trial = batch + [nick]
            if batch and (len(trial) > per_line
                          or len(render(trial).encode('utf-8')) > self._IRC_MAX_BYTES):
                lines.append(render(batch))
                batch = [nick]
            else:
                batch = trial
        if batch:
            lines.append(render(batch))
        return lines

    def execute_command(self, cmd_data: dict):
        """Execute command from cmd_queue (called by poller thread)"""
        cmd = cmd_data.get('cmd') if isinstance(cmd_data, dict) else None
        if not cmd:
            # A payload without a command can never run; it used to fall into
            # the connected check and log "Not connected, dropping command: None".
            log.debug("Ignoring IRC queue payload without a command: %s",
                      irc_cmd_summary(cmd_data))
            return

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

            elif cmd == 'timers':
                # `.timers` (NET-9): answer Core with this process's timers.
                self._emit_event({'type': 'IRC_TIMERS', 'req_id': cmd_data.get('req_id'),
                                  'timers': self.timers_snapshot()})

            elif cmd == 'quit':
                # Handled before the connected check: a second quit (Core's
                # shutdown after .die) must not log "Not connected" (USR-20).
                message = clean_message(cmd_data.get('message', ''))
                self._quit_server(message)
                # .die/.net die ask Core to shut down via this echo; Core's own
                # shutdown and .restart pass reply=False (they are already
                # exiting, and a stale quit must not stop the restarted bot).
                if cmd_data.get('reply', True):
                    self.core_q.put_nowait({'cmd': 'quit', 'message': message})

            elif cmd == 'state':
                # A new Core (.rehash) asks what this connection already has
                # (IRC-1): connected flag, nick and joined channels, each
                # resynced so the new Core's live state is complete.
                connected = self.connection.is_connected()
                chans = list(self.channels.keys()) if connected else []
                # The public IP is detected once, at registration: hand it to
                # the new Core, or DCC has no address to offer after .rehash.
                if self.public_ip:
                    self._emit_event({'type': 'BOT_PUBLIC_IP', 'ip': self.public_ip})
                self._emit_event({
                    'type': 'IRC_STATE',
                    'connected': connected,
                    'botname': self.connection.get_nickname() if connected else None,
                    'channels': chans,
                })
                for chan in chans:
                    self._request_sync(self.connection, chan)

            elif cmd == 'resync':
                if self.connection.is_connected():
                    self._request_sync(self.connection, cmd_data['channel'])

            elif cmd == 'mass_mode':
                # .mass (IRC-2): one mode letter for many nicks, batched by
                # this server's 005 MODES limit and the 510-byte line limit.
                if not self.connection.is_connected():
                    log.error("Not connected, dropping command: mass_mode")
                    return
                for line in self.mass_mode_lines(cmd_data['channel'], cmd_data['sign'],
                                                 cmd_data['mode'], cmd_data['nicks']):
                    self.connection.send_raw(line)

            elif cmd == 'reload_ignores':
                # Core changed the ignore list (USR-11); no connection needed.
                self.ignores.reload()

            elif cmd == 'detach_stdio':
                # Foreground .detach (USR-9): stop writing to the terminal.
                from .main import detach_stdio
                detach_stdio(cmd_data['logfile'], self.config)
                log.info("IRC process detached from the terminal")

            else:
                if not self.connection.is_connected():
                    log.error(f"Not connected, dropping command: {cmd}")
                    return
                
                if cmd in ('msg', 'notice', 'action'):
                    self._last_activity = time.monotonic()

                if cmd == 'msg':
                    text = clean_message(cmd_data['text'])
                    for chunk in self._split_privmsg(cmd_data['target'], text, "PRIVMSG"):
                        self.connection.privmsg(cmd_data['target'], chunk)
                
                elif cmd == 'notice':
                    # GAM-13: sent as a real NOTICE (it went out as PRIVMSG).
                    text = clean_message(cmd_data['text'])
                    for chunk in self._split_privmsg(cmd_data['target'], text, "NOTICE"):
                        self.connection.notice(cmd_data['target'], chunk)
                
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

                elif cmd == 'topic':
                    # topiclock (PLG-8b): one line, no CR/LF smuggling.
                    self.connection.topic(cmd_data['channel'],
                                          clean_message(cmd_data.get('topic', ''),
                                                        self.server_caps.topiclen))

                elif cmd == 'kick':
                    reason = cmd_data.get('reason', 'Kicked')
                    self.connection.kick(
                        cmd_data['channel'],
                        cmd_data['nick'],
                        clean_message(reason)
                    )
                
                elif cmd == 'whois':
                    self.connection.whois(cmd_data['nick'])

                elif cmd == 'whowas':
                    self.connection.whowas(cmd_data['nick'])

                elif cmd == 'who':
                    self.connection.send_raw(f"WHO {cmd_data['channel']}")

                elif cmd == 'ping':
                    token = cmd_data.get('token', str(int(time.time())))
                    self.connection.ping(token)

                elif cmd == 'nick':
                    # `.nick` (IRC-11): checked against this server's NICKLEN
                    # and the nick syntax before anything is sent.
                    nick = cmd_data['nick']
                    nicklen = self.server_caps.nicklen
                    if not valid_nick(nick, nicklen):
                        self._emit_event({'type': 'IRC_NUMERIC', 'numeric': '432',
                                          'args': [nick, f'invalid or longer than NICKLEN={nicklen}']})
                    else:
                        self._nick_attempt = nick
                        self.connection.nick(nick)

                elif cmd == 'raw':
                    self.connection.send_raw(cmd_data['line'])
                
                else:
                    if cmd is not None:
                        log.error(f"[IRC] Unknown command: {cmd}")
        
        except Exception as e:
            # SAST-002: metadata only; a `msg`/`raw` payload is never logged.
            log.error("Command failed (%s): %s: %s", irc_cmd_summary(cmd_data),
                      type(e).__name__, safe(e, 200))

    MAINTENANCE_INTERVAL = 15

    async def maintenance_loop(self):
        """Maintenance every 15s"""
        while True:  # Add while True
            try:
                current_ppid = os.getppid()
                if current_ppid != self._supervisor_ppid or current_ppid == 1:
                    log.warning(f"Supervisor gone (ppid {self._supervisor_ppid} → {current_ppid}) — self-terminating")
                    os._exit(1)

                self._timer_ran('maintenance', self.MAINTENANCE_INTERVAL)
                if self.is_connected:  # Check first
                    # Clean timers
                    for name, task in list(self.irc_timers.items()):
                        if task.done():
                            del self.irc_timers[name]
                            self.irc_timer_info.pop(name, None)
                    
                    await self._check_channels()
                    await self._check_nick()
                
                await asyncio.sleep(self.MAINTENANCE_INTERVAL)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Maintenance error: {e}")
                await asyncio.sleep(60) 

    async def _check_channels(self):
        """Rejoin active channels if missing, with flood protection/backoff."""
        try:
            if not self.is_connected or not self.connection.is_connected():
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

                if not self.connection.is_connected():
                    log.debug("[IRC] Lost connection during _check_channels, aborting")
                    return

                self.connection.join(chan)
                attempts.append(now)
                log.info(f"Trying to join: {chan} (attempts in last 5m: {len(attempts)})")

            # Persist updated state back
            self.maintenance_state['join_attempts'] = join_attempts
            self.maintenance_state['join_cooldown_until'] = join_cooldown_until

        except irc.client.ServerNotConnectedError:
            log.warning("[IRC] _check_channels: not connected, skipping")
        except Exception as e:
            log.error(f"_check_channels error: {e}", exc_info=True)

    async def _check_nick(self):
        """Periodically try to reclaim the desired nick if on a fallback."""
        if not self.is_connected or not self.connection.is_connected():
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
                self._nick_adjusted = self._nick_attempt = desired
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
        self.irc_timer_info[name] = {'interval': interval, 'last_run': None,
                                     'next_run': time.time() + interval}
        #log.info(f"Registered IRC timer: {name} ({interval}s)")

    async def _unregister_irc_timer(self, name: str):
        """Cancel and remove a named IRC timer."""
        self.irc_timer_info.pop(name, None)
        if name in self.irc_timers:
            self.irc_timers[name].cancel()
            del self.irc_timers[name]
            #log.info(f"Unregistered IRC timer: {name}") 

    def _timer_ran(self, name: str, interval: float) -> None:
        now = time.time()
        self.irc_timer_info[name] = {'interval': interval, 'last_run': now,
                                     'next_run': now + interval}

    def timers_snapshot(self) -> list:
        """`.timers` (NET-9): the timers that run in this process: the
        maintenance loop (join retry, nick reclaim) and every plugin IRC
        timer that is still live."""
        out = []
        for name, info in sorted(dict(self.irc_timer_info).items()):
            task = self.irc_timers.get(name)
            if name != 'maintenance' and (task is None or task.done()):
                continue
            desc = ("channel rejoin with backoff, nick reclaim" if name == 'maintenance'
                    else "plugin IRC timer")
            out.append({'name': name, 'interval': info.get('interval'),
                        'last_run': info.get('last_run'), 'next_run': info.get('next_run'),
                        'description': desc})
        return out

    def connect_now(self):
        """Force reconnect if throttled cooldown passed."""
        now = time.time()
        if self._quitting:
            return False
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
            if not self.connection.is_connected():
                return
            if await self.chan.exist(channel):
                conn.join(channel)
        except Exception as e:
            log.error(f"_rejoin_if_tracked failed for {channel}: {e}")

    async def _irc_timer_loop(self, name: str, interval: float):
        while True:
            await asyncio.sleep(interval)
            self._timer_ran(name, interval)
            
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
                            'halfops': list(chan_obj.halfops()),
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
                log.debug("Executing: %s", irc_cmd_summary(cmd_data))
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