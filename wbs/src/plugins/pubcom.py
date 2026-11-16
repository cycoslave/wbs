# src/plugins/pubcom.py
"""
WBS Plugin: pubcom.py 
version: 0.1.0
by: cyco
Description: Public commands in the channel.
"""
import asyncio
import re
import time
import json
import psutil
import feedparser
import random
import aiodns
import ipaddress
import whoisit
import aiohttp
import aiohttp.client_exceptions
import contextlib
import hashlib
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List
from bs4 import BeautifulSoup

from . import Plugin
from .. import __version__
from ..helper import clean_message, is_same_subnet_bot
from ..idrules import validate_mode_string, NICK_MODES
from ..net import AUTO_BAN_REASON
from ..safehttp import (
    FetchBlocked,
    FetchError,
    SafeFetchPolicy,
    SafeHttpClient,
    resolve_public,
)
from ..subnet import local_subnet_id

# ---------------------------------------------------------------------------
# Public-command authorization (SAST-006).
#
# Authentication (identify -> canonical handle bound to the caller's full
# nick!user@host), authorization (role checked per command, in this bot's
# subnet and the command's channel) and execution (typed, validated IRC
# payloads) are separate steps.  Nothing privileged runs on "is identified"
# alone.
#
# Channel enablement: commands are only answered in channels listed in
# config["pubcom"]["channels"] (case-insensitive) that are also active
# channels of this bot's subnet.  No list -> pubcom is disabled everywhere.
# ---------------------------------------------------------------------------
ROLE_CHANOP = "chanop"   # global +o/+A/+n, or channel +o on the command's channel
ROLE_ADMIN = "admin"     # +A (global or this subnet), as partyline .restart
PORTSCAN_COOLDOWN_SECONDS = 60

# Privileged public command -> required role.  Anything not listed here and
# not in the public map is an unknown command and is ignored.
PRIVILEGED_COMMANDS: dict[str, str] = {
    '!op': ROLE_CHANOP,
    '!deop': ROLE_CHANOP,
    '!voice': ROLE_CHANOP,
    '!devoice': ROLE_CHANOP,
    '!kick': ROLE_CHANOP,
    '!ban': ROLE_CHANOP,
    '!mode': ROLE_CHANOP,
    '!portscan': ROLE_CHANOP,
    '!rehash': ROLE_ADMIN,
    '!restart': ROLE_ADMIN,
}

# Public commands that need one argument; without it the bot prints usage
# instead of looking up an empty name (PLG-9).
_ARG_REQUIRED: dict[str, str] = {
    **{f'!{t}': '<domain>' for t in
       ('a', 'aaaa', 'ptr', 'mx', 'ns', 'dmarc', 'spf', 'dkim', 'soa', 'srv', 'caa', 'txt')},
    '!ptr6': '<ipv6>',
}

_CTRL = r'\x00-\x20\x7f'
CHANNEL_RE = re.compile(r'^[#&][^\x00-\x20\x07,:\x7f]{1,49}$')
NICK_RE = re.compile(r'^[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}-]{0,31}$')
MASK_RE = re.compile(rf'^[^{_CTRL},!@:][^{_CTRL},!@]{{0,63}}![^{_CTRL},!@]{{1,64}}@[^{_CTRL},!@]{{1,128}}$')
MODE_FLAGS_RE = re.compile(r'^[+-][A-Za-z+-]{1,15}$')
MODE_PARAM_RE = re.compile(rf'^[^{_CTRL},:][^{_CTRL},]{{0,127}}$')
MAX_MODE_PARAMS = 4
KICK_REASON_MAX = 200
_RFC1459_FOLD = str.maketrans('[]\\~', '{}|^')


def valid_channel(name: str) -> bool:
    return bool(name) and CHANNEL_RE.match(name) is not None


def valid_nick(nick: str) -> bool:
    return bool(nick) and NICK_RE.match(nick) is not None


def valid_mask(mask: str) -> bool:
    return bool(mask) and MASK_RE.match(mask) is not None


def parse_mode_args(arg: str) -> str | None:
    """Validate '!mode' input; return the normalized modes string or None.

    Shape: <[+-]flags> [param ...] with at most MAX_MODE_PARAMS params,
    no control characters, commas or ':'-prefixed (trailing) params.
    """
    if not arg or re.search(r'[\x00-\x08\x0a-\x1f\x7f]', arg):
        return None
    tokens = arg.split()
    if not tokens or not MODE_FLAGS_RE.match(tokens[0]):
        return None
    if not any(c.isalpha() for c in tokens[0]):
        return None
    params = tokens[1:]
    if len(params) > MAX_MODE_PARAMS:
        return None
    if not all(MODE_PARAM_RE.match(p) for p in params):
        return None
    return " ".join(tokens)


def clean_reason(reason: str) -> str:
    reason = re.sub(r'[\x00-\x1f\x7f]', ' ', reason or '').strip()
    return reason[:KICK_REASON_MAX]

# ---------------------------------------------------------------------------
# Outbound HTTP policy (SAST-008). Every request made by this plugin goes
# through one SafeHttpClient: redirects re-validated per hop, DNS pinned to
# the dialled address, internal destinations denied, bodies bounded.
# ---------------------------------------------------------------------------
# IRC-13: !whois uses whoisit (RDAP), which needs IANA bootstrap data first.
RDAP_BOOTSTRAP_TIMEOUT = 15.0   # seconds for the bootstrap download
RDAP_RETRY_SECONDS = 60.0       # wait after a failed bootstrap before retrying

PUBCOM_FETCH_POLICY = SafeFetchPolicy(
    schemes=frozenset({'http', 'https'}),
    ports=frozenset({80, 443, 8080, 8443}),
    max_redirects=3,
    max_bytes=4_194_304,        # hard ceiling for any single response
    total_timeout=30.0,         # hard ceiling; per-call budgets are lower
    connect_timeout=5.0,
    max_concurrency=4,
    max_waiters=8,
    user_agent=f"WBS/{__version__}",
)
PAGE_MAX_BYTES = 524_288        # !website / !youtube / !tech (truncated)
FEED_MAX_BYTES = 2_097_152      # RSS/Atom feeds (truncated)
API_MAX_BYTES = 4_194_304       # JSON APIs (strict: oversize is an error)

# Exact hostnames only: no substring/suffix matching.
CVE_HOSTS = frozenset({'cve.circl.lu'})
EPSS_HOSTS = frozenset({'api.first.org'})
COINGECKO_HOSTS = frozenset({'api.coingecko.com'})
TREND_HOSTS = frozenset({'intel.intruder.io'})
NEWS_FEEDS = (
    "https://news.ycombinator.com/rss",
    "https://techcrunch.com/feed/",
    "http://www.theregister.com/headlines.atom",
    "https://lifehacker.com/rss",  # Fixed: was /feed/rss
    "https://www.bleepingcomputer.com/feed/",
)
NEWS_HOSTS = frozenset(urllib.parse.urlsplit(u).hostname for u in NEWS_FEEDS)
YOUTUBE_HOSTS = frozenset({
    'youtube.com', 'www.youtube.com', 'm.youtube.com', 'music.youtube.com',
    'youtu.be', 'consent.youtube.com',
})
# Hosts a user may *submit* to !youtube (redirects may still reach
# consent.youtube.com, which is in YOUTUBE_HOSTS).
YOUTUBE_INPUT_HOSTS = YOUTUBE_HOSTS - {'consent.youtube.com'}


class PubcomFetchError(aiohttp.ClientError):
    """Safe-fetch failure surfaced through the existing ClientError paths."""

    def __init__(self, message: str, *, blocked: bool = False):
        super().__init__(message)
        self.blocked = blocked


class _FetchedResponse:
    """Minimal aiohttp-response lookalike over a bounded FetchResult."""

    def __init__(self, result):
        self._result = result
        self.status = result.status
        self.headers = result.headers
        self.url = result.url

    async def text(self) -> str:
        return self._result.text()

    async def json(self):
        return self._result.json()


class pubcomPlugin(Plugin):
    name    = "pubcom"
    version = "0.1.0"

    def __init__(self, core, http: SafeHttpClient | None = None):
        super().__init__(core)
        self.auth_sessions = {}
        self.auth_timeout = 43200
        self._epoch = 0     # bumped per IRC connection; sessions are bound to it
        self.http = http
        self._rdap_lock = asyncio.Lock()
        self._rdap_failed_at = None     # monotonic time of the last failed bootstrap
        self._rdap_error = ""
        self._rdap_task = None
        self._portscan_last_run: dict[str, float] = {}
    
    async def load(self):
        """Initialize plugin and register timers"""
        await super().load()
        if self.http is None:
            self.http = SafeHttpClient(PUBCOM_FETCH_POLICY)
        self.dns_resolver = aiodns.DNSResolver()
        # IRC-13: !whois needs whoisit's RDAP bootstrap data.  Fetched in the
        # background so a slow or offline IANA never delays startup; a failure
        # is retried on the next !whois (see _ensure_rdap).
        self._rdap_task = asyncio.create_task(self._ensure_rdap())
        self.log.info(f"Plugin {self.name} {self.version} loaded")
    
    async def unload(self):
        """Unload plugin and unregister timers"""
        self.auth_sessions.clear()
        self._portscan_last_run.clear()
        if self._rdap_task is not None:
            self._rdap_task.cancel()
            self._rdap_task = None
        if self.http is not None:
            await self.http.close()
            self.http = None
        await super().unload()
        self.log.info("Pubcom plugin unloaded")

    async def _ensure_rdap(self) -> str:
        """Make sure whoisit has its RDAP bootstrap data (IRC-13).

        Returns "" when ready, else a short reason for the channel.  The
        download has RDAP_BOOTSTRAP_TIMEOUT seconds; after a failure the next
        attempt waits RDAP_RETRY_SECONDS so a public command cannot hammer
        IANA while the bot is offline.
        """
        if whoisit.is_bootstrapped():
            return ""
        async with self._rdap_lock:
            if whoisit.is_bootstrapped():
                return ""
            now = time.monotonic()
            if self._rdap_failed_at is not None and now - self._rdap_failed_at < RDAP_RETRY_SECONDS:
                return self._rdap_error
            try:
                await asyncio.wait_for(whoisit.bootstrap_async(), RDAP_BOOTSTRAP_TIMEOUT)
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                self._rdap_error = (f"the RDAP bootstrap service did not answer within "
                                    f"{RDAP_BOOTSTRAP_TIMEOUT:g}s")
            except Exception as e:
                self._rdap_error = f"cannot load RDAP bootstrap data ({type(e).__name__}: {e})"
            else:
                self._rdap_failed_at = None
                self._rdap_error = ""
                self.log.info("pubcom: RDAP bootstrap data loaded")
                return ""
            self._rdap_failed_at = time.monotonic()
            self.log.warning("pubcom: %s", self._rdap_error)
            return self._rdap_error

    @contextlib.asynccontextmanager
    async def _http_get(self, url: str, *, hosts=None, timeout: float = 10,
                        max_bytes: int = API_MAX_BYTES, truncate: bool = False,
                        method: str = "GET"):
        """Policy-bound fetch; raises PubcomFetchError (an aiohttp.ClientError).

        ``hosts`` is an exact-hostname allowlist applied to every hop; None
        means any public destination.
        """
        if self.http is None:
            raise PubcomFetchError("HTTP client not initialised")
        try:
            result = await self.http.fetch(
                url, method=method, allowed_hosts=hosts, timeout=timeout,
                max_bytes=max_bytes, truncate=truncate,
            )
        except FetchError as e:
            raise PubcomFetchError(str(e), blocked=isinstance(e, FetchBlocked)) from None
        yield _FetchedResponse(result)

    # ------------------------------------------------------------------
    # Authentication / session binding (SAST-006, SAST-007).
    #
    # A nickname is never proof of identity.  `identify` binds a session to:
    #   * the canonical handle (stored spelling),
    #   * the caller's full nick!user@host (connection identity),
    #   * the services account from the IRCv3 account tag, when the server
    #     supplies one (None otherwise; must stay identical for the session),
    #   * a fingerprint of the stored credential at identify time,
    #   * the IRC connection epoch of this bot.
    #
    # Every privileged command re-verifies all of the above and re-reads the
    # user record, so a password change, delete or lock revokes the
    # session on the next command (a handle that no longer resolves is
    # treated as revoked).  Lifecycle events end sessions:
    #   * QUIT of the nick, or of the bot itself;
    #   * NICK: the session is NOT carried over to the new nick (intentional:
    #     a nick change cannot be tied to the same verified identity without
    #     account tracking, so the user re-identifies).  A nick changing *to*
    #     a session's nick also clears that stale entry;
    #   * PART/KICK that leaves the nick on no channel the bot can see (the
    #     bot would no longer observe its QUIT/NICK);
    #   * bot DISCONNECT and a new connection (READY);
    #   * expiry (auth_timeout) and any failed re-identify.
    # ------------------------------------------------------------------
    @staticmethod
    def irc_casefold(text: str) -> str:
        """RFC 1459 casemapping: A-Z/[]\\~ fold to a-z/{}|^."""
        return (text or '').lower().translate(_RFC1459_FOLD)

    def _key(self, nick: str) -> str:
        return self.irc_casefold(nick)

    def _norm_hostmask(self, hostmask: str) -> str:
        nick, sep, rest = (hostmask or '').partition('!')
        return f"{self.irc_casefold(nick)}{sep}{rest.lower()}"

    @staticmethod
    def _norm_account(account) -> str | None:
        """IRCv3 account tag value, or None when absent / logged out ('*')."""
        if not isinstance(account, str):
            return None
        account = account.strip()
        if not account or account == '*':
            return None
        return pubcomPlugin.irc_casefold(account)

    @staticmethod
    def _cred_fingerprint(stored_hash) -> str | None:
        if not stored_hash:
            return None
        return hashlib.sha256(str(stored_hash).encode()).hexdigest()

    async def _guard_blocked(self, guard, host: str) -> bool:
        """N-01: True while the guard holds an automatic auth_failure block for
        `host` (the address `record_failure` was keyed on).  Fails closed, like
        the DCC blocklist check."""
        try:
            entry = await guard.denied_by(ip=host, host=host)
        except Exception as exc:
            self.log.error("pubcom: blocklist check failed for %s: %s", host, exc)
            return True
        return entry is not None and entry.reason == AUTO_BAN_REASON

    def _drop(self, nick: str, why: str) -> bool:
        if self.auth_sessions.pop(self._key(nick), None) is not None:
            self.log.info("pubcom session for %s dropped: %s", nick, why)
            return True
        return False

    def _drop_all(self, why: str) -> None:
        if self.auth_sessions:
            self.log.info("pubcom: %d session(s) dropped: %s", len(self.auth_sessions), why)
        self.auth_sessions.clear()

    def _bind_session(self, nick: str, hostmask: str, handle: str,
                      account=None, cred: str | None = None) -> None:
        self.auth_sessions[self._key(nick)] = {
            'handle': handle,
            'hostmask': self._norm_hostmask(hostmask),
            'account': self._norm_account(account),
            'cred': cred,
            'epoch': self._epoch,
            'ts': time.time(),
        }

    def session_handle(self, nick: str, hostmask: str, account=None) -> str | None:
        """Canonical handle bound to this exact connection identity, else None.

        Synchronous identity check only (no DB); privileged dispatch uses
        verify_session(), which also re-verifies the user record.
        """
        if not nick or not hostmask:
            return None
        key = self._key(nick)
        sess = self.auth_sessions.get(key)
        if sess is None:
            return None
        if not isinstance(sess, dict) or not {'handle', 'hostmask', 'ts'} <= sess.keys():
            del self.auth_sessions[key]
            return None
        if time.time() - sess['ts'] >= self.auth_timeout:
            self._drop(nick, "expired")
            return None
        if sess.get('epoch', self._epoch) != self._epoch:
            self._drop(nick, "IRC connection changed")
            return None
        if sess['hostmask'] != self._norm_hostmask(hostmask):
            # Same nick, different connection identity: never inherit.
            self._drop(nick, "hostmask mismatch")
            return None
        if sess.get('account') != self._norm_account(account):
            # Account changed (logout, other account, or tag appeared/vanished).
            self._drop(nick, "account mismatch")
            return None
        return sess['handle']

    async def verify_session(self, nick: str, hostmask: str, account=None) -> str | None:
        """session_handle() plus revocation checks against the user record:
        the user must still exist under the bound handle, be unlocked, and
        hold the same credential that was verified at identify time."""
        handle = self.session_handle(nick, hostmask, account)
        if handle is None:
            return None
        sess = self.auth_sessions.get(self._key(nick)) or {}
        try:
            user = await self.core.user.get(handle)
        except Exception as e:
            self.log.error("pubcom: session re-verify failed for %s: %s", handle, e)
            return None   # fail closed, keep session for a transient error
        if user is None or getattr(user, 'is_locked', False):
            self._drop(nick, "user revoked")
            return None
        if self._cred_fingerprint(user.password) != sess.get('cred'):
            self._drop(nick, "credential changed")
            return None
        return handle

    def check_auth(self, nick: str, hostmask: str = '', account=None) -> bool:
        """True if nick has a live session bound to hostmask (no role check)."""
        return self.session_handle(nick, hostmask, account) is not None

    def _is_self(self, target: str) -> bool:
        botname = getattr(self.core, 'botname', None) or ''
        return bool(botname) and self.irc_casefold(target) == self.irc_casefold(botname)

    def _visible_nicks(self, exclude_channel: str | None = None) -> set[str] | None:
        """Casefolded nicks on the bot's tracked channels, or None if the
        core exposes no live channel state (visibility unknown)."""
        chans = getattr(self.core, 'channels', None)
        if not isinstance(chans, dict):
            return None
        skip = (exclude_channel or '').lower()
        seen: set[str] = set()
        for name, chan in chans.items():
            if str(name).lower() == skip:
                continue
            for n in getattr(chan, 'users', None) or ():
                seen.add(self.irc_casefold(n))
        return seen

    def _prune_unobservable(self, nicks, exclude_channel: str | None) -> None:
        visible = self._visible_nicks(exclude_channel)
        if visible is None:
            return
        for nick in list(nicks):
            if self._key(nick) not in visible:
                self._drop(nick, "no longer on a shared channel")

    async def on_NICK(self, event):
        old = event.get('old_nick') or ''
        new = event.get('new_nick') or ''
        if old:
            self._drop(old, "nick change (re-identify required)")
        if new:
            self._drop(new, "nick taken by another client")

    async def on_QUIT(self, event):
        nick = event.get('nick') or ''
        if nick and self._is_self(nick):
            self._drop_all("bot quit")
        elif nick:
            self._drop(nick, "quit")

    async def on_PART(self, event):
        nick = event.get('nick') or ''
        channel = event.get('channel') or ''
        if self._is_self(nick):
            self._prune_unobservable(list(self.auth_sessions), channel)
        elif nick and self._key(nick) in self.auth_sessions:
            self._prune_unobservable([nick], channel)

    async def on_KICK(self, event):
        nick = event.get('kicked') or ''
        channel = event.get('channel') or ''
        if self._is_self(nick):
            self._prune_unobservable(list(self.auth_sessions), channel)
        elif nick and self._key(nick) in self.auth_sessions:
            self._prune_unobservable([nick], channel)

    async def on_DISCONNECT(self, event):
        self._epoch += 1
        self._drop_all("IRC disconnect")

    async def on_READY(self, event):
        self._epoch += 1
        self._drop_all("new IRC connection")

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------
    def _subnet(self) -> int:
        return local_subnet_id(getattr(self.core, 'config', None))

    async def authorize(self, handle: str, role: str, channel: str) -> bool:
        """Does `handle` hold `role` for `channel` on this bot's subnet?

        Same policy as partyline: +o for channel-op actions (global grant, or
        a channel grant on exactly this channel; +A/+n imply op rights,
        IRC-14), +A for admin actions.  All
        checks go through UserManager.matchattr (active user, subnet scope).
        """
        if not handle:
            return False
        user = self.core.user
        sid = self._subnet()
        if role == ROLE_ADMIN:
            return await user.matchattr(handle, '+A', subnet_id=sid)
        if role == ROLE_CHANOP:
            # +A/+n imply channel op rights (operator decision, IRC-14).
            for spec in ('+o', '+A', '+n'):
                if await user.matchattr(handle, spec, subnet_id=sid):
                    return True
            for chan in dict.fromkeys((channel, channel.lower())):
                if await user.matchattr(handle, '*|o', chan, subnet_id=sid):
                    return True
            return False
        return False  # unknown role: deny

    def _enabled_channels(self) -> set[str]:
        cfg = (getattr(self.core, 'config', None) or {}).get('pubcom') or {}
        chans = cfg.get('channels') if isinstance(cfg, dict) else None
        if not isinstance(chans, (list, tuple)):
            return set()
        return {c.lower() for c in chans if isinstance(c, str) and valid_channel(c)}

    async def is_pubcom_enabled(self, channel: str) -> bool:
        """Pubcom answers only in channels listed in config pubcom.channels
        that are also active channels of this bot's subnet."""
        if not valid_channel(channel or ''):
            return False
        if channel.lower() not in self._enabled_channels():
            return False
        try:
            active = await self.core.chan.getchans(subnet_id=self._subnet())
        except Exception as e:
            self.log.error("pubcom: channel lookup failed for %s: %s", channel, e)
            return False
        return channel.lower() in {c.lower() for c in active or []}

    # Authentication handlers
    async def on_PRIVMSG(self, event):
        """Handle `/msg <bot> identify [handle] <password>`."""
        nick = event.get('nick') or ''
        hostmask = event.get('host') or ''
        parts = (event.get('text') or '').strip().split()

        if not parts or parts[0].lower() != 'identify':
            return
        # PLG-9: this plugin owns `identify`; the core must not also answer
        # "Unknown command" / "Access denied" to it.
        event['handled'] = True
        if not valid_nick(nick) or '!' not in hostmask:
            return

        if len(parts) == 2:
            handle, password = nick, parts[1]
        elif len(parts) == 3:
            handle, password = parts[1], parts[2]
        else:
            await self.send_notice(
                nick, f"Usage: /msg {self.core.botname} identify [handle] <password>")
            return

        # Any identify attempt drops the nick's current session first.
        self._drop(nick, "re-identify")

        canonical = await self.core.user.resolve_handle(handle)
        # F-04: failed identifies are counted per (host, target handle) in the
        # same AccessGuard the partyline/botlink listener uses.  A locked pair
        # is refused with the ordinary failure reply (no lock-state oracle) and
        # the password is not even checked.
        guard = getattr(self.core, 'guard', None)
        gkey = hostmask.rsplit('@', 1)[-1].lower() or 'unknown'
        gname = canonical or handle
        if guard is not None and (guard.handle_locked(gkey, gname)
                                  or await self._guard_blocked(guard, gkey)):
            self.log.warning("pubcom: identify for %r refused from %s (locked out)",
                             gname, hostmask)
            await self.send_notice(nick, "Invalid credentials!")
            return

        if canonical and await self.core.user.verify_password(canonical, password):
            record = await self.core.user.get(canonical)
            cred = self._cred_fingerprint(getattr(record, 'password', None))
            if record is None or cred is None:
                await self.send_notice(nick, "Invalid credentials!")
                return
            if guard is not None:
                guard.record_success(gkey, gname)
            self._bind_session(nick, hostmask, canonical,
                               account=event.get('account'), cred=cred)
            self.log.info("pubcom: %s identified as %s", hostmask, canonical)
            await self.send_notice(nick, "Logged in successfully!")
        else:
            self.log.info("pubcom: failed identify from %s", hostmask)
            if guard is not None:
                try:
                    await guard.record_failure(gkey, gname, peer=True)
                except Exception as exc:
                    self.log.error("pubcom: record_failure failed: %s", exc)
            await self.send_notice(nick, "Invalid credentials!")

    # Public message handlers
    def _public_commands(self) -> dict:
        return {
            '!info': self.cmd_info,
            '!identify': self.cmd_identify_help,
            '!version': self.cmd_version,
            '!uptime': self.cmd_uptime,
            '!time': self.cmd_time,
            '!news': self.cmd_news,
            '!cve': self.cmd_cve,
            '!lastcve': self.cmd_lastcve,
            '!epss': self.cmd_epss,
            '!whois': self.cmd_whois,
            '!youtube': self.cmd_youtube,
            '!a': self.cmd_a,
            '!aaaa': self.cmd_aaaa,
            '!ptr': self.cmd_ptr,
            '!ptr6': self.cmd_ptr6,
            '!mx': self.cmd_mx,
            '!ns': self.cmd_ns,
            '!dmarc': self.cmd_dmarc,
            '!spf': self.cmd_spf,
            '!dkim': self.cmd_dkim,
            '!soa': self.cmd_soa,
            '!srv': self.cmd_srv,
            '!caa': self.cmd_caa,
            '!txt': self.cmd_txt,
            '!website': self.cmd_website,
            '!waf': self.cmd_waf,
            '!tech': self.cmd_tech,
            '!geoip': self.cmd_geoip,
            '!asn': self.cmd_asn,
            '!trend': self.cmd_trend,
            '!crypto': self.cmd_crypto,
        }

    def _privileged_commands(self) -> dict:
        return {
            '!op': self.priv_op,
            '!deop': self.priv_deop,
            '!voice': self.priv_voice,
            '!devoice': self.priv_devoice,
            '!kick': self.priv_kick,
            '!ban': self.priv_ban,
            '!mode': self.priv_mode,
            '!portscan': self.cmd_portscan,
            '!rehash': self.priv_rehash,
            '!restart': self.priv_restart,
        }

    async def on_PUBMSG(self, event):
        """Handle public channel messages: enablement -> authn -> authz -> run."""
        text = (event.get('text') or '').strip()
        channel = event.get('channel') or ''
        nick = event.get('nick') or ''
        hostmask = event.get('host') or ''

        parts = text.split(maxsplit=1)
        if not parts:
            return
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        public = self._public_commands()
        privileged = self._privileged_commands()
        if cmd not in public and cmd not in privileged:
            return  # unknown commands are ignored

        if not await self.is_pubcom_enabled(channel):
            return

        if cmd in public:
            usage = _ARG_REQUIRED.get(cmd)
            if usage and not arg:       # PLG-9: usage instead of a lookup of ''
                await self.send_privmsg(channel, f"Usage: {cmd} {usage}")
                return
            await public[cmd](nick, hostmask, channel, arg)
            return

        await self._dispatch_privileged(cmd, privileged[cmd], nick, hostmask, channel, arg,
                                        account=event.get('account'))

    async def _dispatch_privileged(self, cmd, handler, nick, hostmask, channel, arg,
                                   account=None):
        role = PRIVILEGED_COMMANDS.get(cmd)
        if role is None:
            return
        handle = await self.verify_session(nick, hostmask, account)
        if handle is None:
            await self.send_notice(nick, "You must identify first")
            return
        if not await self.authorize(handle, role, channel):
            self.log.warning("pubcom: denied %s for %s (%s) in %s (need %s)",
                             cmd, handle, hostmask, channel, role)
            await self.send_notice(nick, f"Access denied for {cmd}.")
            return
        if cmd == '!portscan':
            key = channel.lower()
            now = time.monotonic()
            last_run = self._portscan_last_run.get(key)
            if last_run is not None and now - last_run < PORTSCAN_COOLDOWN_SECONDS:
                remaining = max(1, int(PORTSCAN_COOLDOWN_SECONDS - (now - last_run) + 0.999))
                await self.send_privmsg(
                    channel, f"Port scan cooldown active; try again in {remaining}s.")
                return
            # Reserve before awaiting the scan so concurrent calls cannot bypass
            # the per-channel cooldown.
            self._portscan_last_run[key] = now
        await handler(handle, nick, channel, arg)
    
    # Command implementations
    async def cmd_info(self, nick, uhost, channel, arg):
        """Display available commands"""
        commands = "!version !uptime !time !op !deop !voice !devoice !kick !ban !mode !crypto " \
                   "!rehash !restart !news !cve !epss !trend !lastcve !whois !portscan !youtube !dmarc !spf !dkim " \
                   "!srv !soa !txt !caa !a !aaaa !ptr !ptr6 !mx !ns"
        c2 = "!website !waf !tech !geoip !asn"
        await self.send_privmsg(channel, f"Valid commands are: {commands}")
        await self.send_privmsg(channel, f"{c2}")
        await self.send_privmsg(
            channel,
            "!portscan requires an identified operator and has a 60-second per-channel cooldown.",
        )
    
    async def cmd_identify_help(self, nick, uhost, channel, arg):
        """Show identify help"""
        await self.send_notice(nick, f"To identify: /msg {self.core.botname} identify [handle] <password>")
    
    async def cmd_version(self, nick, uhost, channel, arg):
        """Show bot version"""
        await self.send_privmsg(channel, f"I run Wicked Bot System {__version__}!")
    
    async def cmd_uptime(self, nick, uhost, channel, arg):
        """Show uptime"""
        uptime = time.time() - self.core.start_time
        uptime_str = self.format_duration(uptime)
        await self.send_privmsg(channel, f"Bot uptime: {uptime_str}")
        suptime = time.time() - self.core.connected_on
        suptime_str = self.format_duration(suptime)
        await self.send_privmsg(channel, f"Server uptime: {suptime_str}")
        muptime = time.time() -  psutil.boot_time()
        muptime_str = self.format_duration(muptime)
        await self.send_privmsg(channel, f"Machine uptime: {muptime_str}")
    
    async def cmd_time(self, nick, uhost, channel, arg):
        """Show current time"""
        now = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        await self.send_privmsg(channel, f"Current time is: {now}")
    
    async def cmd_cve(self, nick, uhost, channel, arg):
        """Lookup CVE details from CIRCL API"""
        cve_id = arg.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            await self.send_privmsg(channel, "Invalid CVE format. Use: !cve CVE-YYYY-XXXXX")
            return
        
        try:
            url = f'https://cve.circl.lu/api/cve/{cve_id}'
            async with self._http_get(url, hosts=CVE_HOSTS) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # Extract description - try containers.cna.descriptions first, then fallback to summary
                    summary = None
                    containers = data.get('containers', {})
                    if containers:
                        cna = containers.get('cna', {})
                        descriptions = cna.get('descriptions', [])
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                summary = desc.get('value')
                                break
                    
                    # Fallback to root-level summary
                    if not summary:
                        summary = data.get('summary', 'No description available')
                    
                    # Extract CVSS scores from CVE 5.1 format
                    score = 'N/A'
                    severity = ''
                    severity_str = ''

                    containers = data.get('containers', {})
                    if containers:
                        cna = containers.get('cna', {})

                        # Try to get CVSS from metrics (CVE 5.x format)
                        metrics = cna.get('metrics', [])
                        for metric in metrics:
                            # Check for CVSS v3.1
                            if 'cvssV3_1' in metric:
                                cvss_data = metric['cvssV3_1']
                                score = cvss_data.get('baseScore', score)
                                severity = cvss_data.get('baseSeverity', '').upper()
                                break
                            # Check for CVSS v3.0
                            elif 'cvssV3_0' in metric:
                                cvss_data = metric['cvssV3_0']
                                score = cvss_data.get('baseScore', score)
                                severity = cvss_data.get('baseSeverity', '').upper()
                                break
                            # Check for CVSS v2.0
                            elif 'cvssV2_0' in metric:
                                cvss_data = metric['cvssV2_0']
                                score = cvss_data.get('baseScore', score)
                                # Calculate severity for v2
                                if isinstance(score, (int, float)):
                                    if score >= 7.0:
                                        severity = 'HIGH'
                                    elif score >= 4.0:
                                        severity = 'MEDIUM'
                                    else:
                                        severity = 'LOW'
                                break
                        
                            # Fallback: try legacy v4 record if no metrics found
                            if score == 'N/A':
                                legacy = cna.get('x_legacyV4Record', {})
                                if legacy:
                                    # Try impact.baseMetricV3
                                    impact = legacy.get('impact', {})
                                    if 'baseMetricV3' in impact:
                                        cvss3 = impact['baseMetricV3'].get('cvssV3', {})
                                        score = cvss3.get('baseScore', score)
                                        severity = cvss3.get('baseSeverity', '').upper()
                                    # Fallback to baseMetricV2
                                    elif 'baseMetricV2' in impact:
                                        cvss2 = impact['baseMetricV2'].get('cvssV2', {})
                                        score = cvss2.get('baseScore', score)
                                        if isinstance(score, (int, float)):
                                            if score >= 7.0:
                                                severity = 'HIGH'
                                            elif score >= 4.0:
                                                severity = 'MEDIUM'
                                            else:
                                                severity = 'LOW'

                        severity_str = f" [{severity}]" if severity else ""

                    # Extract affected products
                    affected_products = []
                    if containers:
                        cna = containers.get('cna', {})
                        affected = cna.get('affected', [])
                        for item in affected[:3]:  # Limit to first 3 products
                            product = item.get('product', '')
                            vendor = item.get('vendor', '')
                            if vendor and vendor not in ('n/a', 'N/A') and product:
                                affected_products.append(f"{vendor} {product}")
                            elif product:
                                affected_products.append(product)
                    
                    # Fallback to vulnerable_product CPE parsing
                    if not affected_products:
                        vuln_products = data.get('vulnerable_product', [])
                        if vuln_products:
                            for cpe in vuln_products[:3]:
                                parts = cpe.split(':')
                                if len(parts) >= 5:
                                    vendor = parts[3].replace('_', ' ')
                                    product = parts[4].replace('_', ' ')
                                    affected_products.append(f"{vendor} {product}")
                    
                    products_str = f"{', '.join(affected_products)}" if affected_products else ""
                    
                    # Truncate summary for IRC (adjust based on product length)
                    max_summary_len = 180 - len(products_str)
                    if len(summary) > max_summary_len:
                        summary = summary[:max_summary_len-3] + "..."
                    
                    msg = f"{products_str} - CVSS: {score}{severity_str} | {summary}"
                    await self.send_privmsg(channel, msg)
                    
                elif resp.status == 404:
                    await self.send_privmsg(channel, f"{cve_id} not found")
                else:
                    await self.send_privmsg(channel, f"CVE lookup failed (status {resp.status})")
                    
        except aiohttp.client_exceptions.ClientError as e:
            self.log.error(f"CVE lookup error: {e}")
            await self.send_privmsg(channel, "Network error fetching CVE")
        except (KeyError, ValueError, TypeError) as e:
            self.log.error(f"CVE parsing error for {cve_id}: {e}")
            await self.send_privmsg(channel, "Error parsing CVE response")
    
    async def cmd_epss(self, nick, uhost, channel, arg):
        """Lookup EPSS score for CVE"""
        cve_id = arg.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            await self.send_privmsg(channel, "Invalid CVE format. Use: !epss CVE-YYYY-XXXXX")
            return
        
        try:
            # Use FIRST.org EPSS API
            url = f'https://api.first.org/data/v1/epss?cve={cve_id}'
            async with self._http_get(url, hosts=EPSS_HOSTS) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # Check if data exists
                    if data.get('status') == 'OK' and 'data' in data and len(data['data']) > 0:
                        epss_data = data['data'][0]
                        epss_score = float(epss_data.get('epss', 0))
                        percentile = float(epss_data.get('percentile', 0))
                        date = epss_data.get('date', 'N/A')
                        
                        # Convert to percentages for readability
                        epss_pct = epss_score * 100
                        percentile_pct = percentile * 100
                        
                        msg = f"{cve_id} | EPSS: {epss_pct:.2f}% (Top {100-percentile_pct:.1f}% risk) | Updated: {date}"
                        await self.send_privmsg(channel, msg)
                    else:
                        await self.send_privmsg(channel, f"{cve_id} - No EPSS data available")
                elif resp.status == 404:
                    await self.send_privmsg(channel, f"{cve_id} - No EPSS data found")
                else:
                    await self.send_privmsg(channel, f"EPSS lookup failed (status {resp.status})")
                    
        except aiohttp.client_exceptions.ClientError as e:
            self.log.error(f"EPSS lookup error: {e}")
            await self.send_privmsg(channel, "Network error fetching EPSS")
        except (KeyError, ValueError, TypeError) as e:
            self.log.error(f"EPSS parsing error for {cve_id}: {e}")
            await self.send_privmsg(channel, "Error parsing EPSS response")
    
    async def cmd_crypto(self, nick, uhost, channel, arg):
        """Crypto price lookup - matches original Tcl vwckcrypto"""
        
        parts = arg.lower().split()
        if not parts:
            await self.send_privmsg(channel, "Usage: !crypto <coin> [currency] [amount]")
            return
        
        coin_input = parts[0]
        currency_input = parts[1] if len(parts) > 1 else 'usd'
        amount_input = parts[2] if len(parts) > 2 else None
        
        # Coin mapping from Tcl (coin_id, symbol, fullname - fullname unused)
        coin_map = {
            'btc': ('bitcoin', 'BTC', 'Bitcoin'),
            'bitcoin': ('bitcoin', 'BTC', 'Bitcoin'),
            'ltc': ('litecoin', 'LTC', 'Litecoin'),
            'litecoin': ('litecoin', 'LTC', 'Litecoin'),
            'eth': ('ethereum', 'ETH', 'Ethereum'),
            'ethereum': ('ethereum', 'ETH', 'Ethereum'),
            'nmc': ('namecoin', 'NMC', 'Namecoin'),
            'namecoin': ('namecoin', 'NMC', 'Namecoin'),
            'doge': ('dogecoin', 'DOGE', 'Dogecoin'),
            'dogecoin': ('dogecoin', 'DOGE', 'Dogecoin'),
            'xmr': ('monero', 'XMR', 'Monero'),
            'monero': ('monero', 'XMR', 'Monero'),
            'sol': ('solana', 'SOL', 'Solana'),
            'solana': ('solana', 'SOL', 'Solana'),
            'gala': ('gala', 'GALA', 'Gala'),
            'ada': ('cardano', 'ADA', 'Cardano'),
            'dot': ('polkadot', 'DOT', 'Polkadot'),
            'avax': ('avalanche-2', 'AVAX', 'Avalanche'),
            'link': ('chainlink', 'LINK', 'Chainlink'),
            'matic': ('matic-network', 'MATIC', 'Polygon'),
            'bnb': ('binancecoin', 'BNB', 'Binance Coin'),
            'shib': ('shiba-inu', 'SHIB', 'Shiba Inu'),
            'usdt': ('tether', 'USDT', 'Tether'),
            'usdc': ('usd-coin', 'USDC', 'USD Coin'),
            'trx': ('tron', 'TRX', 'Tron'),
            'atom': ('cosmos', 'ATOM', 'Cosmos'),
            'etc': ('ethereum-classic', 'ETC', 'Ethereum Classic'),
            'xrp': ('ripple', 'XRP', 'XRP (Ripple)'),
            'vet': ('vechain', 'VET', 'VeChain'),
            'algo': ('algorand', 'ALGO', 'Algorand'),
            'hbar': ('hedera-hashgraph', 'HBAR', 'Hedera'),
            'xlm': ('stellar', 'XLM', 'Stellar'),
        }
        
        crypto_id, symbol, fullname = coin_map.get(coin_input, coin_map['btc'])
        
        # Fiat mapping from Tcl (fiat_id, symbol_str)
        fiat_map = {
            'usd': ('usd', '$USD'),
            'cad': ('cad', '$CAD'),
            'eur': ('eur', '€EUR'),
            'gbp': ('gbp', '£GBP'),
            'jpy': ('jpy', '¥JPY'),
            'aud': ('aud', '$AUD'),
            'chf': ('chf', 'CHF'),
            'cny': ('cny', '¥CNY'),
            'inr': ('inr', '₹INR'),
            'rub': ('rub', '₽RUB'),
            'nzd': ('nzd', '$NZD'),
            'hkd': ('hkd', '$HKD'),
            'krw': ('krw', '₩KRW'),
            'brl': ('brl', 'R$BRL'),
            'mxn': ('mxn', '$MXN'),
            'zar': ('zar', 'RZAR'),
            'sgd': ('sgd', '$SGD'),
            'try': ('try', '₺TRY'),
            'sek': ('sek', 'krSEK'),
            'nok': ('nok', 'krNOK'),
        }
        
        fiat_id, fsymbol = fiat_map.get(currency_input, fiat_map['usd'])
        
        try:
            url = f"https://api.coingecko.com/api/v3/simple/price?ids={crypto_id}&vs_currencies={fiat_id}"
            async with self._http_get(url, hosts=COINGECKO_HOSTS, timeout=10) as resp:
                if resp.status != 200:
                    await self.send_privmsg(channel, "Error fetching crypto data")
                    return
                data = await resp.json()
                if crypto_id not in data or fiat_id not in data[crypto_id]:
                    await self.send_privmsg(channel, "Error: Could not parse price.")
                    return
                
                price = data[crypto_id][fiat_id]
                if amount_input is None:
                    await self.send_privmsg(channel, f"Crypto price: {price}{fsymbol} per {symbol}")
                else:
                    try:
                        amount = float(amount_input)
                        total = price * amount
                        await self.send_privmsg(channel, f"Crypto price: {total}{fsymbol} for {amount} {symbol}")
                    except ValueError:
                        await self.send_privmsg(channel, "Invalid amount")
        except Exception as e:
            self.log.error(f"Crypto lookup error: {e}")
            await self.send_privmsg(channel, "Error fetching crypto price")
    
    # ------------------------------------------------------------------
    # Privileged channel/admin commands (SAST-006).
    #
    # Only reachable through _dispatch_privileged(), which has already
    # resolved the caller's bound canonical handle and checked the role in
    # PRIVILEGED_COMMANDS for this bot's subnet and this channel.  Every
    # argument is validated before anything is queued for IRC.
    # ------------------------------------------------------------------
    async def _priv_user_mode(self, handle, nick, channel, arg, mode):
        target = arg.split()[0] if arg.strip() else nick
        if not valid_nick(target):
            await self.send_notice(nick, "Invalid nick.")
            return
        if mode == '-o' and self._is_self(target):
            await self.send_notice(nick, "Refusing to deop myself.")
            return
        if not await self._may_mode_bot(handle, nick, channel, mode, target):
            return
        self.log.info("pubcom %s by %s (%s) on %s: %s", mode, handle, nick, channel, target)
        await self.send_mode(channel, mode, target)

    async def _may_mode_bot(self, handle, nick, channel, mode, target) -> bool:
        """NET-3: never op/mode a bot of another (or unknown) subnet."""
        if await is_same_subnet_bot(self.core, target) is not False:
            return True
        self.log.warning("Denied pubcom %s by %s (%s) on %s: target %r is a bot outside "
                         "the local subnet (or of unknown subnet scope)",
                         mode, handle, nick, channel, target)
        await self.send_notice(nick, f"Refused: {target} is a bot outside my subnet.")
        return False

    async def priv_op(self, handle, nick, channel, arg):
        """!op [nick] — give op (default: caller)"""
        await self._priv_user_mode(handle, nick, channel, arg, '+o')

    async def priv_deop(self, handle, nick, channel, arg):
        """!deop [nick] — remove op (default: caller)"""
        await self._priv_user_mode(handle, nick, channel, arg, '-o')

    async def priv_voice(self, handle, nick, channel, arg):
        """!voice [nick] — give voice (default: caller)"""
        await self._priv_user_mode(handle, nick, channel, arg, '+v')

    async def priv_devoice(self, handle, nick, channel, arg):
        """!devoice [nick] — remove voice (default: caller)"""
        await self._priv_user_mode(handle, nick, channel, arg, '-v')

    async def priv_kick(self, handle, nick, channel, arg):
        """!kick <nick> [reason]"""
        parts = arg.split(maxsplit=1)
        if not parts:
            await self.send_notice(nick, "Usage: !kick <nick> [reason]")
            return
        target = parts[0]
        if not valid_nick(target):
            await self.send_notice(nick, "Invalid nick.")
            return
        if self._is_self(target):
            await self.send_notice(nick, "Refusing to kick myself.")
            return
        reason = clean_reason(parts[1] if len(parts) > 1 else '') or f"Requested by {nick}"
        self.log.info("pubcom kick by %s (%s) on %s: %s", handle, nick, channel, target)
        await self.send_kick(channel, target, reason)

    async def priv_ban(self, handle, nick, channel, arg):
        """!ban <nick|nick!user@host> [reason] — ban, and kick when given a nick"""
        parts = arg.split(maxsplit=1)
        if not parts:
            await self.send_notice(nick, "Usage: !ban <nick|mask> [reason]")
            return
        target = parts[0]
        if valid_mask(target):
            mask, kick_nick = target, None
        elif valid_nick(target):
            mask, kick_nick = f"{target}!*@*", target
        else:
            await self.send_notice(nick, "Invalid nick or mask.")
            return
        if set(mask) <= set('*?!@.'):
            await self.send_notice(nick, "Refusing to ban everyone.")
            return
        if kick_nick and self._is_self(kick_nick):
            await self.send_notice(nick, "Refusing to ban myself.")
            return
        reason = clean_reason(parts[1] if len(parts) > 1 else '') or f"Banned by {nick}"
        self.log.info("pubcom ban by %s (%s) on %s: %s", handle, nick, channel, mask)
        await self.send_mode(channel, '+b', mask)
        if kick_nick:
            await self.send_kick(channel, kick_nick, reason)

    async def priv_mode(self, handle, nick, channel, arg):
        """!mode <[+-]modes> [params] — set modes on this channel only"""
        modes = parse_mode_args(arg)
        if modes is None:
            await self.send_notice(nick, "Usage: !mode <+/-modes> [params]")
            return
        self.log.info("pubcom mode by %s (%s) on %s: %s", handle, nick, channel, modes)
        err, changes = validate_mode_string(modes)
        targets = (modes.split()[1:] if err else
                   [t for _, letter, t in changes if letter in NICK_MODES and t])
        for target in targets:
            if not await self._may_mode_bot(handle, nick, channel, "mode", target):
                return
        await self.send_mode(channel, modes)

    async def priv_rehash(self, handle, nick, channel, arg):
        """!rehash — soft rehash (admin)"""
        self.log.info("pubcom rehash by %s (%s) in %s", handle, nick, channel)
        await self.send_privmsg(channel, "Rehashing...")
        await self.core.do_rehash()

    async def priv_restart(self, handle, nick, channel, arg):
        """!restart — full restart (admin)"""
        self.log.info("pubcom restart by %s (%s) in %s", handle, nick, channel)
        await self.send_privmsg(channel, "Restarting...")
        await self.core.do_restart()
    
    async def cmd_news(self, nick, uhost, channel, arg):
        """News from RSS feeds - matches original Tcl vwcknews"""
        
        num = 5
        if arg.strip() and arg.strip().isdigit():
            num = max(1, min(10, int(arg.strip())))
        
        rss_feeds = NEWS_FEEDS
        
        today_str = datetime.utcnow().strftime("%Y-%m-%d")
        
        async def fetch_feed(url):
            try:
                async with self._http_get(url, hosts=NEWS_HOSTS, timeout=10,
                                          max_bytes=FEED_MAX_BYTES, truncate=True) as resp:
                    if resp.status == 200:
                        data = await resp.text()
                        feed = feedparser.parse(data)
                        return feed.entries or []
            except Exception:
                pass
            return []
        
        # Concurrent fetch all feeds
        tasks = [fetch_feed(url) for url in rss_feeds]
        all_entries = []
        for entries in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(entries, list):
                all_entries.extend(entries)
        
        # Filter today's GMT articles (match Tcl logic)
        news_list = []
        for entry in all_entries:
            pubdate_str = entry.get('published') or entry.get('updated', '')
            try:
                pubdate = feedparser.parsedate_to_datetime(pubdate_str)
                if pubdate and pubdate.strftime("%Y-%m-%d") == today_str:
                    title = entry.get('title', '').strip()
                    link = entry.get('link', '').strip()
                    if title and link:
                        news_list.append(f"{title} - {link}")
            except Exception:
                pass
        
        if not news_list:
            await self.send_privmsg(channel, "No news available at the moment.")
            return
        
        # Shuffle (match Tcl rand shuffle)
        random.shuffle(news_list)
        news_list = news_list[:num]
        
        # Send one per line
        for item in news_list:
            await self.send_privmsg(channel, item)

    # MX - matches vwckdns_mx exactly
    async def cmd_mx(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'MX')
        if not records:
            await self.send_privmsg(channel, "No MX records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"MX records for {domain}: {display}")

    # A records
    async def cmd_a(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'A')
        if not records:
            await self.send_privmsg(channel, "No A records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"A records for {domain}: {display}")

    # AAAA records
    async def cmd_aaaa(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'AAAA')
        if not records:
            await self.send_privmsg(channel, "No AAAA records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"AAAA records for {domain}: {display}")

    # NS records
    async def cmd_ns(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'NS')
        if not records:
            await self.send_privmsg(channel, "No NS records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"NS records for {domain}: {display}")

    # PTR records (IPv4 reverse)
    async def cmd_ptr(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'PTR')
        if not records:
            await self.send_privmsg(channel, "No PTR records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"PTR records for {domain}: {display}")

    # PTR6 (IPv6 reverse lookup)
    async def cmd_ptr6(self, nick, uhost, channel, ip):
        ip = ip.strip()
        try:
            ipv6 = ipaddress.IPv6Address(ip)
            rev_domain = ipv6.reverse_pointer
        except ValueError:
            await self.send_privmsg(channel, "Invalid IPv6 address format.")
            return
        
        records = await self.get_dns_records(rev_domain, 'PTR')
        if not records:
            await self.send_privmsg(channel, f"No PTR6 records found for {ip}")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"PTR6 records for {ip} ({rev_domain}): {display}")

    # DMARC (_dmarc.domain.com TXT)
    async def cmd_dmarc(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        dmarc_domain = f"_dmarc.{domain}"
        records = await self.get_dns_records(dmarc_domain, 'TXT')
        if not records:
            await self.send_privmsg(channel, f"No DMARC record found for {domain}")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"DMARC record for {domain}: {display}")

    # SPF (TXT v=spf1 filtered)
    async def cmd_spf(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'TXT')
        spf_records = [r for r in records if r.startswith('v=spf')]
        if not spf_records:
            await self.send_privmsg(channel, f"No SPF record found for {domain}")
            return
        display = ', '.join(spf_records)
        await self.send_privmsg(channel, f"SPF record for {domain}: {display}")

    # DKIM (common selectors)
    async def cmd_dkim(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        selectors = ['google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2', 'mail', 'default']
        found = []
        for sel in selectors:
            records = await self.get_dns_records(f"{sel}._domainkey.{domain}", 'TXT')
            if records:  # records is now list[str]
                found.append(f"{sel}: {records[0][:80]}...")
        if not found:
            await self.send_privmsg(channel, f"No common DKIM selectors found for {domain}")
            return
        display = ', '.join(found)
        await self.send_privmsg(channel, f"DKIM selectors for {domain}: {display}")

    # SOA
    async def cmd_soa(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'SOA')
        if not records:
            await self.send_privmsg(channel, "No SOA records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"SOA records for {domain}: {display}")

    # SRV
    async def cmd_srv(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'SRV')
        if not records:
            await self.send_privmsg(channel, "No SRV records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"SRV records for {domain}: {display}")

    # CAA
    async def cmd_caa(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'CAA')
        if not records:
            await self.send_privmsg(channel, "No CAA records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"CAA records for {domain}: {display}")

    # TXT (all)
    async def cmd_txt(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'TXT')
        if not records:
            await self.send_privmsg(channel, "No TXT records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"TXT records for {domain}: {display}")
    
    async def cmd_trend(self, nick, uhost, channel, arg):
        """CVE Trends RSS - pure regex, matches Tcl vwcktrend"""        
        num = 5
        if arg.strip():
            try:
                n = float(arg.strip())
                num = max(1, min(10, n))
            except ValueError:
                pass
        
        url = "https://intel.intruder.io/rss/cvetrends/latest"
        
        try:
            async with self._http_get(url, hosts=TREND_HOSTS, timeout=10,
                                      max_bytes=FEED_MAX_BYTES, truncate=True) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                xml = await resp.text()
        except Exception as e:
            self.log.error(f"Trend fetch error: {e}")
            await self.send_privmsg(channel, f"Error fetching trend data: {e}")
            return
        
        if not xml.strip():
            await self.send_privmsg(channel, "Error: Failed to fetch data.")
            return
        
        # Pure regex - exact Tcl patterns
        item_pattern = r'<item>.*?</item>'
        items = re.findall(item_pattern, xml, re.DOTALL | re.IGNORECASE)
        
        count = 0
        for item in items:
            if count >= num:
                return
            
            # CVE from <title><![CDATA[CVE-...]]></title>
            cve_pattern = r'<title><!\[CDATA\[(.*?)\]\]></title>'
            cve_match = re.search(cve_pattern, item, re.IGNORECASE)
            cve = cve_match.group(1).strip() if cve_match else ""
            
            # Link from <link>URL</link>
            link_pattern = r'<link>(.*?)</link>'
            link_match = re.search(link_pattern, item, re.DOTALL | re.IGNORECASE)
            link = link_match.group(1).strip() if link_match else ""
            
            # Hype from <intruder:hypeScore>NN</intruder:hypeScore>
            hype_pattern = r'<intruder:hypeScore>(\d+)</intruder:hypeScore>'
            hype_match = re.search(hype_pattern, item, re.IGNORECASE)
            hype = hype_match.group(1) if hype_match else ""
            
            if cve and link and hype:
                await self.send_privmsg(channel, f"{cve} - Hype: {hype}/100, Link: {link}")
            count += 1
        
        return
    
    async def cmd_lastcve(self, nick, uhost, channel, arg):
        """Last CVEs - matches original Tcl vwcklastcve"""        
        num = 5
        if arg.strip() and arg.strip().lstrip('-').isdigit():
            n = float(arg.strip())
            num = max(1, min(10, n))
        
        url = f"https://cve.circl.lu/api/last/{int(num)}"
        
        try:
            async with self._http_get(url, hosts=CVE_HOSTS, timeout=30) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                data_text = await resp.text()
                cves: List[Dict[str, Any]] = json.loads(data_text)
        except Exception as e:
            self.log.error(f"CVE fetch error: {type(e).__name__}: {e!r}")
            await self.send_privmsg(channel, f"Error fetching CVEs: {type(e).__name__}")
            return
        
        count = 0
        for cve in cves:
            if count >= num:
                break
            
            # Extract CVE ID (match Tcl: cveMetadata or aliases regex CVE-*-*)
            cve_id = ""
            if cve.get('cveMetadata', {}).get('cveId'):
                cve_id = cve['cveMetadata']['cveId']
            elif 'aliases' in cve:
                for alias in cve['aliases']:
                    if isinstance(alias, str) and alias.startswith('CVE-') and '-' in alias[4:]:
                        cve_id = alias
                        break
            
            if not cve_id:
                continue
            
            # Extract first English desc/title (match Tcl priority)
            cve_title = "No description available"
            containers = cve.get('containers', {})
            cna = containers.get('cna', {})
            descriptions = cna.get('descriptions', [])
            for desc_dict in descriptions:
                if isinstance(desc_dict, dict) and desc_dict.get('lang') == 'en' and 'value' in desc_dict:
                    cve_title = desc_dict['value']
                    break
            else:
                # Fallback to details if no desc
                cve_title = cve.get('details', 'No description available')
            
            msg = f"{cve_id}: {cve_title}"
            await self.send_privmsg(channel, clean_message(msg))
            count += 1
        
        if count == 0:
            await self.send_privmsg(channel, "No recent CVEs found.")
    
    # Utility commands (simplified)
    def _normalize_user_url(self, arg: str) -> str:
        url = arg.strip().split()[0] if arg.strip() else ""
        if url and not re.match(r'^https?://', url, re.IGNORECASE):
            url = 'https://' + url
        return url

    async def _fetch_user_page(self, channel, url, *, hosts=None, method="GET",
                               label=None):
        """Fetch a user-supplied URL under the public-only policy.

        Returns the response lookalike, or None after reporting the error.
        The policy check runs before any DNS lookup or socket.
        """
        label = label or url
        try:
            async with self._http_get(url, hosts=hosts, method=method, timeout=10,
                                      max_bytes=PAGE_MAX_BYTES, truncate=True) as resp:
                return resp
        except PubcomFetchError as e:
            if e.blocked:
                self.log.warning("SSRF blocked %s in %s: %s", url, channel, e)
            await self.send_privmsg(channel, clean_message(f"Error fetching {label}: {e}"))
            return None

    async def cmd_website(self, nick, uhost, channel, arg):
        """Website title lookup"""
        url = self._normalize_user_url(arg)
        if not url:
            await self.send_privmsg(channel, "Usage: !website <url>")
            return
        
        resp = await self._fetch_user_page(channel, url)
        if resp is None:
            return
        if resp.status != 200:
            await self.send_privmsg(channel, f"Error: HTTP {resp.status}")
            return
        html = await resp.text()
        
        title = self._extract_title(html)
        if title:
            await self.send_privmsg(channel, clean_message(f"Title: {title}"))
        else:
            await self.send_privmsg(channel, clean_message(f"No title found for {url}"))

    async def cmd_youtube(self, nick, uhost, channel, arg):
        """YouTube title lookup"""  
        url = arg.strip()
        if not url:
            await self.send_privmsg(channel, "Usage: !youtube <url>")
            return
        
        # Exact host allowlist (no substring match): evil-youtube.com,
        # youtube.com.evil.net and user@youtube.com-style tricks are refused.
        try:
            parsed = urllib.parse.urlsplit(url)
            host = (parsed.hostname or '').lower().rstrip('.')
            bad = (parsed.scheme.lower() not in ('http', 'https')
                   or parsed.username is not None or '@' in parsed.netloc
                   or host not in YOUTUBE_INPUT_HOSTS)
        except ValueError:
            bad = True
        if bad:
            await self.send_privmsg(channel, "Invalid YouTube URL")
            return
        
        resp = await self._fetch_user_page(channel, url, hosts=YOUTUBE_HOSTS,
                                           label="YouTube")
        if resp is None:
            return
        if resp.status != 200:
            await self.send_privmsg(channel, f"Error: HTTP {resp.status}")
            return
        html = await resp.text()
        
        # YouTube meta title fallback
        title = (self._extract_title(html) or
                self._extract_meta_title(html) or
                "No title found")
        await self.send_privmsg(channel, clean_message(f"Title: {title}"))

    async def cmd_portscan(self, nick, uhost, channel, arg):
        """Port scan - your Tcl blocks + safe Python logic"""

        parts = arg.split()
        scanall = parts and parts[0] == '-all'
        if scanall:
            parts = parts[1:]
        target = ' '.join(parts).strip()
        
        if re.search(r'[^a-zA-Z0-9._-]', target):
            await self.send_privmsg(channel, "Invalid input. Please enter a valid IP or domain.")
            return
        
        # Your exact .gov block
        if re.search(r'\.gov$', target):
            await self.send_privmsg(channel, "Invalid input. Please enter a valid IP or domain.")
            return
        
        # Your exact private/special IP block
        private_regex = r'^(127\..*|10\..*|192\.168\..*|172\.(1[6-9]|2[0-9]|3[0-1])\..*|169\.254\..*|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\..*|224\..*|255\.255\.255\.255|0\.0\.0\.0)$'  # noqa: E501
        if re.match(private_regex, target):
            await self.send_privmsg(channel, f"Scan denied: {target} is a private or special IP.")
            return
        
        # Parse ports (default top 20 if missing)
        port_parts = target.split(':')
        ip = port_parts[0]
        ports_str = port_parts[1] if len(port_parts) > 1 else "21,22,23,25,53,80,110,143,443,993,995,1723,3306,3389,5432,5900,8080,8443"
        
        ports = [int(p) for p in ports_str.split(',') if p.strip().isdigit()]
        if len(ports) > 20:
            await self.send_privmsg(channel, "Max 20 ports (anti-abuse)")
            return
        if not ports:
            await self.send_privmsg(channel, "No valid ports specified")
            return
        
        # Resolve once under the shared fetch policy (SAST-008): hostnames
        # whose answers include any internal address, internal IP literals,
        # IPv4-mapped/6to4/NAT64 forms and numeric shorthands are refused.
        # Only the validated address is dialled, so DNS cannot rebind.
        try:
            addrs = await resolve_public(
                ip, self.http.policy if self.http is not None else PUBCOM_FETCH_POLICY,
                resolver=self.http.inner_resolver if self.http is not None else None)
        except FetchBlocked:
            await self.send_privmsg(channel, f"Scan denied: {ip} is a private or special IP.")
            return
        except FetchError:
            await self.send_privmsg(channel, f"Could not resolve {ip}.")
            return
        dial_addr = addrs[0]
        
        # Safe async TCP scan (max 10 concurrent)
        open_ports = []
        semaphore = asyncio.Semaphore(10)
        
        async def check_port(p):
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(dial_addr, p), timeout=2
                    )
                    writer.close()
                    await writer.wait_closed()
                    return p
                except Exception:
                    return None
        
        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        open_ports = sorted([p for p in results if p])
        
        if open_ports:
            scan_results = f"{ip} - Open Ports: {','.join(map(str, open_ports))}"
            # Split long output (your Tcl logic)
            max_length = 400
            max_messages = 5
            count = 0
            while len(scan_results) > max_length and count < max_messages:
                part = scan_results[:max_length]
                scan_results = scan_results[max_length + 1:]
                await self.send_privmsg(channel, part)
                count += 1
            if scan_results and count < max_messages:
                await self.send_privmsg(channel, scan_results)
            if count >= max_messages:
                await self.send_privmsg(channel, "Output too long. Some results may be missing.")
        else:
            await self.send_privmsg(channel, f"No open ports found on {ip}.")

    async def cmd_waf(self, nick, uhost, channel, arg):
        """WAF detection"""
        
        if not arg.strip():
            await self.send_privmsg(channel, "Usage: !waf <URL>")
            return
        
        url = self._normalize_user_url(arg)
        
        # HEAD only (-nobody equivalent)
        resp = await self._fetch_user_page(channel, url, method="HEAD")
        if resp is None:
            return
        headers = str(resp.headers).lower()
        
        waf_patterns = [
            # Your original (top tier)
            "cloudflare", "sucuri", "imperva", "akamai", "f5 big-ip", "incapsula",
            "barracuda", "fortiweb", "aws waf", "radware", "stackoverflow",
            
            # Cloud giants (2026 leaders)
            "azure", "google cloud", "fastly", "cloudfront", "gcp",
            
            # Enterprise heavyweights
            "modsecurity", "nginx", "nginx waf", "varnish", "litespeed",
            
            # Regional/niche from wafw00f
            "360waf", "alicloud", "aliyundun", "barracuda", "bitninja",
            "cloudbric", "ddos-guard", "fortigate", "imunify360", "palo alto",
            "wallarm", "watchguard", "webknight"
        ]
        
        for pattern in waf_patterns:
            if pattern.lower() in headers:
                await self.send_privmsg(channel, f"{url} is protected by a WAF: {pattern.title()}")
                return
        
        await self.send_privmsg(channel, f"No known WAF detected on {url}.")

    async def cmd_tech(self, nick, uhost, channel, arg):
        """Tech detection"""
        
        if not arg.strip():
            await self.send_privmsg(channel, "Usage: !tech <URL>")
            return
        
        url = self._normalize_user_url(arg)
        
        resp = await self._fetch_user_page(channel, url)
        if resp is None:
            return
        page_content = (await resp.text()).lower()
        
        tech_patterns = [
            # Your original CMS
            ("WordPress", '<meta name="generator" content="wordpress"'),
            ("Joomla", "com_content"),
            ("Drupal", "/sites/default/files/"),
            
            # Additional CMS
            ("Magento", "/magento_version"),
            ("Shopify", "shopify"),
            ("Squarespace", "squarespace"),
            ("Wix", "wix"),
            ("Ghost", "ghost"),
            ("Discourse", "/discourse"),
            
            # PHP Frameworks
            ("Laravel", "laravel_session"),
            ("CodeIgniter", "codeigniter"),
            ("Symfony", "symfony/"),
            
            # JS Frameworks (dev/prod)
            ("ReactJS", "react.development.js"),
            ("ReactJS", "__webpack_require__"),
            ("AngularJS", "angular.js"),
            ("VueJS", "vue.js"),
            ("Next.js", "/_next/"),
            ("Nuxt.js", "/nuxt/"),
            
            # Common libraries
            ("jQuery", "jquery.min.js"),
            ("Bootstrap", "bootstrap.min.css"),
            ("React", "react-dom"),
            
            # Servers/Hosting
            ("Apache", "apache"),
            ("Nginx", "nginx"),
            ("IIS", "iis"),
            ("cPanel", "cpanel"),
            
            # Analytics/Tracking
            ("Google Analytics", "_ga="),
            ("Matomo", "matomo"),
            
            # E-commerce
            ("WooCommerce", "woocommerce"),
            ("PrestaShop", "prestashop")
        ]
        
        found = []
        for tech, pattern in tech_patterns:
            if pattern.lower() in page_content:
                found.append(tech)
        
        if found:
            await self.send_privmsg(channel, f"{url} is using: {', '.join(found)}.")
        else:
            await self.send_privmsg(channel, f"No common technologies detected on {url}.")
        
    async def cmd_whois(self, nick, uhost, channel, arg):
        """WHOIS lookup (domain/IP/AS)"""
        if not await self.is_pubcom_enabled(channel):
            return
        arg = arg.strip()
        if not arg:
            await self.send_privmsg(channel, "Usage: !whois <domain|IP|ASN>")
            return
        err = await self._ensure_rdap()
        if err:
            await self.send_privmsg(channel, f"WHOIS unavailable: {err}. Try again later.")
            return
        try:
            if arg.isdigit():
                result = await whoisit.asn_async(arg)
                title = f"AS{result.get('asn', '')} {result.get('name', 'N/A')}"
            else:
                result = await whoisit.domain_async(arg)
                title = result.get('domain', arg)
            await self.send_privmsg(channel, f"WHOIS {arg}: {title}")
        except Exception as e:
            await self.send_privmsg(channel, f"WHOIS error: {e}")
    
    async def cmd_geoip(self, nick, uhost, channel, arg):
        """GeoIP via whois - matches Tcl vwckgeoip (free)"""
        if not await self.is_pubcom_enabled(channel):
            return
        
        if not arg.strip():
            await self.send_privmsg(channel, "Usage: !geoip <IP>")
            return
        
        ip = arg.strip()
        
        # Your exact IPv4 validation
        match = re.match(r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$', ip)
        if not match:
            await self.send_privmsg(channel, "Invalid IP address format.")
            return
        
        o1, o2, o3, o4 = map(int, match.groups())
        if any(o < 0 or o > 255 for o in [o1, o2, o3, o4]):
            await self.send_privmsg(channel, "Invalid IP address format.")
            return
        
        # Your exact 16 reserved ranges (subnet/mask)
        reserved_ips = [
            (0,0,0,0,8), (10,0,0,0,8), (100,64,0,0,10), (127,0,0,0,8),
            (169,254,0,0,16), (172,16,0,0,12), (192,0,0,0,24), (192,0,2,0,24),
            (192,88,99,0,24), (192,168,0,0,16), (198,18,0,0,15), (198,51,100,0,24),
            (203,0,113,0,24), (224,0,0,0,4), (240,0,0,0,4), (255,255,255,255,32)
        ]
        
        # Binary subnet match (your logic)
        ip_binary = f"{o1:08b}{o2:08b}{o3:08b}{o4:08b}"
        for s1, s2, s3, s4, mask in reserved_ips:
            subnet_binary = f"{s1:08b}{s2:08b}{s3:08b}{s4:08b}"
            if ip_binary[:mask] == subnet_binary[:mask]:
                await self.send_privmsg(channel, f"{ip} is a reserved/private IP address.")
                return
        
        # Your whois + Country: regex
        try:
            proc = await asyncio.create_subprocess_exec(
                'whois', ip, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            whois_result = stdout.decode('utf-8', errors='ignore')
            
            country_match = re.search(r'country:\s*(.+)', whois_result, re.IGNORECASE)
            if country_match:
                country = country_match.group(1).strip()
                await self.send_privmsg(channel, f"IP {ip} is registered in: {country}")
            else:
                await self.send_privmsg(channel, f"Could not determine location for IP {ip}.")
        except Exception:
            await self.send_privmsg(channel, "Whois lookup failed.")
    
    async def cmd_asn(self, nick, uhost, channel, arg):
        """ASN via whois - matches Tcl vwckasn (free)"""
        if not await self.is_pubcom_enabled(channel):
            return
        
        if not arg.strip():
            await self.send_privmsg(channel, "Usage: !asn <IP>")
            return
        
        ip = arg.strip()
        
        # Reuse geoip validation (IPv4 + reserved check)
        match = re.match(r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$', ip)
        if not match:
            await self.send_privmsg(channel, "Invalid IP address format.")
            return
        
        o1, o2, o3, o4 = map(int, match.groups())
        if any(o < 0 or o > 255 for o in [o1, o2, o3, o4]):
            await self.send_privmsg(channel, "Invalid IP address format.")
            return
        
        # Reserved IPs (reuse your geoip list)
        reserved_ips = [
            (0,0,0,0,8), (10,0,0,0,8), (100,64,0,0,10), (127,0,0,0,8),
            (169,254,0,0,16), (172,16,0,0,12), (192,0,0,0,24), (192,0,2,0,24),
            (192,88,99,0,24), (192,168,0,0,16), (198,18,0,0,15), (198,51,100,0,24),
            (203,0,113,0,24), (224,0,0,0,4), (240,0,0,0,4), (255,255,255,255,32)
        ]
        
        ip_binary = f"{o1:08b}{o2:08b}{o3:08b}{o4:08b}"
        for s1, s2, s3, s4, mask in reserved_ips:
            subnet_binary = f"{s1:08b}{s2:08b}{s3:08b}{s4:08b}"
            if ip_binary[:mask] == subnet_binary[:mask]:
                await self.send_privmsg(channel, f"{ip} is a reserved/private IP address.")
                return
        
        # Your exact whois + OriginAS: regex
        try:
            proc = await asyncio.create_subprocess_exec(
                'whois', ip, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            whois_result = stdout.decode('utf-8', errors='ignore')
            
            asn_match = re.search(r'OriginAS:\s*(AS\d+)', whois_result, re.IGNORECASE)
            if asn_match:
                asn = asn_match.group(1)
                await self.send_privmsg(channel, f"IP {ip} belongs to ASN: {asn}")
            else:
                await self.send_privmsg(channel, f"Could not determine ASN for IP {ip}.")
        except Exception:
            await self.send_privmsg(channel, "Whois lookup failed.")
    
    def format_duration(self, seconds):
        """Format duration in human readable form"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        parts = []
        if days: parts.append(f"{days}d")
        if hours: parts.append(f"{hours}h")
        if minutes: parts.append(f"{minutes}m")
        if secs: parts.append(f"{secs}s")
        
        return " ".join(parts) if parts else "0s"

    async def get_dns_records(self, domain: str, qtype: str) -> List[str]:
        """Helper: returns list[str] from aiodns results"""
        try:
            results = await self.dns_resolver.query(domain, qtype)
            if qtype == 'TXT':
                return [r.text for r in results if hasattr(r, 'text')]
            else:
                return [str(r.host) for r in results if hasattr(r, 'host')]
        except Exception:
            return []
        
    def _extract_title(self, html):
        """Extract <title> tag"""
        soup = BeautifulSoup(html, 'html.parser')
        title_tag = soup.find('title')
        return (title_tag.get_text().strip() if title_tag else None)

    def _extract_meta_title(self, html):
        """Fallback: og:title or twitter:title meta"""
        soup = BeautifulSoup(html, 'html.parser')
        metas = [
            soup.find('meta', property='og:title'),
            soup.find('meta', property='twitter:title'),
            soup.find('meta', attrs={'name': 'twitter:title'})
        ]
        for meta in metas:
            if meta and meta.get('content'):
                return meta.get('content').strip()
        return None        