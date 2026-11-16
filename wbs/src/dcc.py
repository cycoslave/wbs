"""
src/dcc.py

DCC CHAT manager — firewall-friendly implementation.

Three connection modes (auto-negotiated):
  1. Active DCC   — bot opens listening socket, advertises IP:port  (classic eggdrop)
  2. Passive DCC  — bot sends CTCP "DCC CHAT chat 0 0 <token>",
                    user's client calls back; bot never needs a public port for listen
                    (RFC-compatible with mIRC/HexChat passive DCC)
  3. IRC fallback — full partyline session over PRIVMSG/NOTICE for clients
                    behind symmetric NAT where DCC is simply impossible

Flow:
  - User sends  /ctcp botnick DCC CHAT chat <ip> <port>   → Reverse request (user listens, bot connects to them)
  - User sends  /dcc chat botnick                          → irc.py on_ctcp fires DCC_CHAT_REQUEST
  - Core routes DCC_CHAT_REQUEST → dcc.DCCManager.handle_request()
  - DCCManager picks mode, negotiates, registers session with partyline

Security model (SAST-009).  Every new request passes these gates, in this
order, before the bot touches the network (no dial, no listener, no CTCP
offer, no notice):
  1. per-source (host) and global request rate limits;
  2. the requester's full nick!user@host matches a known user whose account
     is active (not locked/deleted) and who holds +p on this bot's subnet;
  3. the session layer is available (see below);
  4. any peer endpoint is a public IPv4 address (or inside an explicitly
     configured dcc.allow_networks CIDR) on an allowed peer port;
  5. fixed capacity: one pending request per handle, at most max_pending
     pending negotiations, and pending + established <= max_sessions.
A passive callback must carry the single-use token of a pending offer, come
from the exact nick!user@host that requested it, still be authorized, and
name an allowed endpoint (gate 4) before the bot dials.

Every pending negotiation is owned by its verified requester (canonical
handle + full hostmask) and expires: on timeout, on NICK/QUIT of its nick,
and on IRC disconnect/reconnect.  Every outcome (refusal, failure, timeout,
cancellation, hand-off refused) closes the listener and the socket and
frees the slot.

Session contract (SAST-010).  Negotiation hands the session layer a
DCCRequest carrying the verified requester (canonical handle, normalized
full hostmask, nick).  Before anything is registered:
  * socket modes (active, passive, reverse): whoever is on the socket must
    answer a password challenge for the canonical handle (the listener of
    an active offer is reachable by anyone, so the socket is bound to the
    account by the challenge, not by who happened to connect);
  * IRC fallback: the password must arrive by private message from the
    exact nick!user@host that made the request; the session is then bound
    to that hostmask (and to the IRCv3 services account seen at login, when
    the server sends one) and ends on NICK/QUIT, identity mismatch or IRC
    reset;
  * the requester is re-authorized (same handle, active, +p on this subnet).
A session is then registered in the Partyline exactly once, under the
canonical handle (never the IRC nick), and is unregistered exactly once.
Users without a password cannot open DCC sessions.
"""
import asyncio
import ipaddress
import logging
import secrets
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Dict

from .safehttp import ip_denial_reason
from .subnet import local_subnet_id, DEFAULT_LISTEN_HOST

log = logging.getLogger("wbs.dcc")

ACTIVE_LISTEN_TIMEOUT   = 60   # seconds to wait for user to connect (active mode)
PASSIVE_CONNECT_TIMEOUT = 60   # seconds to wait for user's client to call back
CONNECT_TIMEOUT         = 15   # seconds for one outbound TCP connect
SESSION_IDLE_TIMEOUT    = 300  # seconds of silence before auto-disconnect
LISTEN_PORT_ATTEMPTS    = 50   # random ports tried for the active listener
AUTH_TIMEOUT            = 60   # seconds to answer the password challenge
AUTH_GRACE              = 5    # request expiry slack beyond the challenge timeout
AUTH_ATTEMPTS_MAX       = 3    # hard cap for dcc.auth_attempts
PASSWORD_MAX            = 256  # longer challenge answers are refused unchecked
SEND_TIMEOUT            = 30   # seconds for one socket write to drain
SESSION_QUEUE_MAX       = 200  # partyline -> session output backlog
END_CHAT_COMMANDS       = frozenset({'.endchat'})
IRC_AUTH_COMMAND        = 'chatauth'   # /msg <bot> chatauth <password> (IRC fallback)

_RFC1459_FOLD = str.maketrans('[]\\~', '{}|^')

#: Result of DCCManager._run_tracked when the owning request was released.
_RELEASED = object()


def _close_quietly(obj) -> None:
    """Close a StreamWriter / asyncio Server, ignoring errors."""
    if obj is None:
        return
    try:
        obj.close()
    except Exception:
        pass


def irc_casefold(text: str) -> str:
    """RFC 1459 casemapping: A-Z/[]\\~ fold to a-z/{}|^."""
    return (text or '').lower().translate(_RFC1459_FOLD)


def _norm_hostmask(hostmask: str) -> str:
    nick, sep, rest = (hostmask or '').partition('!')
    return f"{irc_casefold(nick)}{sep}{rest.lower()}"


def _norm_account(account) -> Optional[str]:
    """IRCv3 services account (casefolded), or None when absent / '*'."""
    if not isinstance(account, str):
        return None
    account = account.strip()
    if not account or account == '*':
        return None
    return irc_casefold(account)


def _ip_to_int(ip: str) -> int:
    """Convert dotted-decimal IP to 32-bit int for DCC CTCP."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def _int_to_ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))

def _random_token() -> str:
    """
    Unpredictable 9-digit passive-DCC token (numeric, always < 2**31).

    Real clients (irssi, mIRC, HexChat) hold the token in a 32-bit integer and
    echo it back truncated, so a longer token never matches its callback.
    """
    return str(10**8 + secrets.randbelow(9 * 10**8))


def _token_wire(token) -> Optional[str]:
    """
    Canonical form of a token echoed by a client: the decimal value modulo
    2**32 (what a 32-bit client echoes for a larger number), or None if it is
    not a plain decimal number.
    """
    token = str(token)
    if not token.isascii() or not token.isdigit() or len(token) > 20:
        return None
    return str(int(token) % 2**32)


def parse_chat_args(args) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Raw (ip, port, token) strings of a CTCP DCC CHAT.  Accepts the flattened
    irc.py form ['DCC', 'CHAT', 'chat', ip, port, (token)] and the same list
    without the leading 'DCC'.  Missing fields are None.
    """
    parts = [str(a) for a in (args or [])]
    upper = [p.upper() for p in parts]
    if 'CHAT' not in upper:
        return None, None, None
    rest = parts[upper.index('CHAT') + 2:]   # skip 'CHAT' and the protocol word
    ip = rest[0] if len(rest) > 0 else None
    port = rest[1] if len(rest) > 1 else None
    token = rest[2] if len(rest) > 2 else None
    return ip, port, token


class _RateLimiter:
    """Sliding window: at most `limit` accepted events per `window` s per key."""

    def __init__(self, limit: int, window: float, max_keys: int = 1024):
        self.limit = max(0, int(limit))
        self.window = float(window)
        self.max_keys = max_keys
        self._hits: Dict[str, deque] = {}

    def allow(self, key: str, now: Optional[float] = None) -> bool:
        now = time.monotonic() if now is None else now
        hits = self._hits.get(key)
        if hits is None:
            if len(self._hits) >= self.max_keys:
                self._prune(now)
                if len(self._hits) >= self.max_keys:
                    return False          # table full of live keys: fail closed
            hits = self._hits[key] = deque()
        while hits and now - hits[0] >= self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def _prune(self, now: float) -> None:
        stale = [k for k, h in self._hits.items() if not h or now - h[-1] >= self.window]
        for key in stale:
            del self._hits[key]


@dataclass(eq=False)
class DCCRequest:
    """
    One pending negotiation, owned by a verified requester.

    This is also the identity contract handed to the session layer
    (_open_session / _open_irc_fallback, SAST-010): `handle` is the
    canonical handle of the authorized user, `hostmask` the normalized full
    nick!user@host it was verified against, `nick` the requesting IRC nick.
    """
    rid: int
    handle: str
    nick: str
    hostmask: str
    kind: str                         # 'active' | 'passive' | 'client-passive' | 'reverse' | 'irc'
    created: float
    token: Optional[str] = None       # passive only; None once claimed/expired
    server: Optional[asyncio.AbstractServer] = None
    writer: Optional[asyncio.StreamWriter] = None
    tasks: set = field(default_factory=set)
    expiry: Optional[asyncio.Future] = None
    claimed: bool = False             # IRC fallback: login answer received
    done: bool = False

    @property
    def nick_key(self) -> str:
        return irc_casefold(self.nick)


class _BaseDCCSession:
    """
    Shared lifecycle of an established DCC session (SAST-010).

    The session is registered in the Partyline exactly once, under the
    canonical handle, before it is constructed; it owns its helper tasks.
    shutdown()/close() are idempotent: however many paths reach them (EOF,
    idle timeout, send error, .endchat, revocation, NICK/QUIT, IRC reset),
    the partyline entry is removed once, the manager forgets the session
    once and the transport is closed once.
    """

    kind = 'dcc'

    def __init__(self, session_id: int, handle: str, partyline, *,
                 nick: str = '', queue: Optional[asyncio.Queue] = None,
                 manager: Optional["DCCManager"] = None):
        self.session_id = session_id
        self.handle     = handle
        self.nick       = nick
        self.partyline  = partyline
        self.manager    = manager
        self._queue     = queue if queue is not None else asyncio.Queue(maxsize=SESSION_QUEUE_MAX)
        self._closed    = False
        self._tasks: set = set()
        self._last_activity = time.time()

    @property
    def closed(self) -> bool:
        return self._closed

    def _spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def start(self) -> None:
        self._spawn(self._drain_loop())

    async def send(self, text: str) -> None:          # pragma: no cover - abstract
        raise NotImplementedError

    async def _drain_loop(self):
        """Forward partyline output (session queue) to the user."""
        while not self._closed:
            msg = await self._queue.get()
            text = msg.get('text', '') if isinstance(msg, dict) else ''
            if text:
                await self.send(text)

    def _close_transport(self) -> None:
        pass

    def shutdown(self, reason: str = "closed") -> bool:
        """Synchronous, idempotent teardown.  False if already closed."""
        if self._closed:
            return False
        self._closed = True
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        for task in list(self._tasks):
            if task is not current and not task.done():
                task.cancel()
        self._close_transport()
        # No-op when the partyline already dropped it (revoke_session).
        self.partyline.unregister_session(self.session_id)
        if self.manager is not None:
            self.manager._session_closed(self)
        log.info("[DCC] %s session closed: %s (sid=%s): %s",
                 self.kind, self.handle, self.session_id, reason)
        return True

    def _send_now(self, text: str) -> None:
        """Best-effort synchronous write (no drain), for a last message."""

    def replace(self, notice: str) -> bool:
        """
        A newer session of the same handle takes over (DCC-8): tell the user
        why, then tear down through the one idempotent shutdown path.
        """
        if self._closed:
            return False
        self._send_now(notice)
        return self.shutdown("replaced by a new session")

    async def close(self, reason: str = "closed"):
        self.shutdown(reason)


class DCCSession(_BaseDCCSession):
    """One established DCC CHAT socket, a 'dcc' partyline session."""

    kind = 'dcc'

    def __init__(self, session_id: int, handle: str,
                 reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 partyline, **kw):
        super().__init__(session_id, handle, partyline, **kw)
        self.reader = reader
        self.writer = writer

    def start(self) -> None:
        super().start()
        self._spawn(self.recv_loop())

    async def send(self, text: str):
        """Send a line to the DCC peer."""
        if self._closed:
            return
        try:
            self.writer.write((text + "\r\n").encode("utf-8", errors="replace"))
            await asyncio.wait_for(self.writer.drain(), timeout=SEND_TIMEOUT)
            self._last_activity = time.time()
        except (ConnectionResetError, BrokenPipeError, OSError, asyncio.TimeoutError) as e:
            log.warning(f"[DCC] Send error to {self.handle}: {e!r}")
            await self.close("send error")

    async def recv_loop(self):
        """Read lines from peer and forward to partyline."""
        reason = "peer closed connection"
        try:
            while not self._closed:
                line = await asyncio.wait_for(
                    self.reader.readline(),
                    timeout=SESSION_IDLE_TIMEOUT
                )
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text or self._closed:
                    continue
                self._last_activity = time.time()
                if text.lower() in END_CHAT_COMMANDS:
                    reason = "ended by user"
                    break
                await self.partyline.handle_input(self.session_id, text)
        except asyncio.TimeoutError:
            reason = "idle timeout"
        except asyncio.CancelledError:
            raise
        except Exception as e:
            reason = f"receive error: {e!r}"
        finally:
            await self.close(reason)

    def _close_transport(self) -> None:
        _close_quietly(self.writer)

    def _send_now(self, text: str) -> None:
        try:
            self.writer.write((text + "\r\n").encode("utf-8", errors="replace"))
        except Exception:
            pass

    async def close(self, reason: str = "closed"):
        if self.shutdown(reason):
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout=5)
            except Exception:
                pass

class DCCManager:
    """
    Owned by Core.  Handles incoming DCC CHAT negotiations from irc.py events
    and manages active DCC sessions.

    Config keys (under config['dcc']):
        enabled           bool  — master switch (default: True)
        mode              str   — 'auto' | 'active' | 'passive' | 'irc'
                                  auto = active if public_ip is known AND the listener
                                  is bound to a non-loopback address, else passive
        public_ip         str   — override detected IP (useful behind NAT); this, never
                                  listen_host, is the address advertised in DCC offers
        port_min          int   — port range for active listen (default: 1024)
        port_max          int   — port range for active listen (default: 65535)
        max_sessions      int   — cap on pending + established DCC (default: 10)
        max_pending       int   — cap on pending negotiations (default: 5)
        rate_limit        int   — requests per source host per rate_window (default: 3)
        global_rate_limit int   — requests from all sources per rate_window (default: 20)
        rate_window       float — rate-limit window in seconds (default: 60)
        peer_port_min     int   — lowest peer port the bot will dial (default: 1024)
        peer_port_max     int   — highest peer port the bot will dial (default: 65535)
        allow_networks    list  — internal CIDRs the bot may dial anyway (default: none;
                                  only public IPv4 is dialled)
        connect_timeout   float — outbound connect timeout in seconds (default: 15)
        auth_timeout      float — seconds to answer the password challenge (default: 60)
        auth_attempts     int   — password tries per DCC socket (default/max: 3;
                                  the IRC fallback always allows exactly one)
        listen_host       str   — interface to bind the active DCC listener (default
                                  '127.0.0.1', loopback only; set '0.0.0.0' to accept
                                  remote DCC clients).  Independent of botnet.listen_host.
    """

    #: Kill switch for the whole session layer (SAST-009/010).  Deliberately
    #: not a config option; set False to refuse every authorized request.
    sessions_available: bool = True

    @property
    def public_ip(self):
        """Effective IP to advertise: configured override, else detected."""
        return self.configured_public_ip or self.detected_public_ip

    @property
    def listen_is_loopback(self) -> bool:
        """True if the active-DCC listener bind is only reachable from this host."""
        host = (self.listen_ip or '').strip().strip('[]')
        if host.lower() == 'localhost':
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def set_detected_public_ip(self, ip):
        """Record the IRC-detected IP; never displaces a configured override."""
        self.detected_public_ip = ip or None

    def __init__(self, core):
        self.core       = core
        self.cfg        = core.config.get('dcc', {}) or {}
        self.settings   = core.config.get('settings', {}) or {}
        self.enabled    = bool(self.cfg.get('enabled', True))
        self.mode       = self.cfg.get('mode', 'auto')
        # An operator-configured public_ip is authoritative; the IP detected
        # from IRC is kept apart and only used when nothing is configured.
        self.configured_public_ip = self.cfg.get('public_ip') or None
        self.detected_public_ip = None
        self.port_min   = int(self.cfg.get('port_min', 1024))
        self.port_max   = int(self.cfg.get('port_max', 65535))
        self.max_sessions = int(self.cfg.get('max_sessions', 10))
        self.max_pending  = int(self.cfg.get('max_pending', 5))
        self.peer_port_min = max(1, int(self.cfg.get('peer_port_min', 1024)))
        self.peer_port_max = min(65535, int(self.cfg.get('peer_port_max', 65535)))
        self.connect_timeout = float(self.cfg.get('connect_timeout', CONNECT_TIMEOUT))
        self.listen_ip  = str(self.cfg.get('listen_host') or DEFAULT_LISTEN_HOST).strip()
        self.auth_timeout = max(1.0, float(self.cfg.get('auth_timeout', AUTH_TIMEOUT)))
        self.auth_attempts = max(1, min(AUTH_ATTEMPTS_MAX,
                                        int(self.cfg.get('auth_attempts', AUTH_ATTEMPTS_MAX))))

        nets = []
        for raw in self.cfg.get('allow_networks', []) or []:
            try:
                net = ipaddress.ip_network(str(raw), strict=False)
            except ValueError:
                log.error("[DCC] Ignoring invalid dcc.allow_networks entry %r", raw)
                continue
            if net.version == 4:
                nets.append(net)
        self.allow_networks = tuple(nets)

        window = float(self.cfg.get('rate_window', 60))
        self._source_limiter = _RateLimiter(int(self.cfg.get('rate_limit', 3)), window)
        self._global_limiter = _RateLimiter(int(self.cfg.get('global_rate_limit', 20)), window)

        self._pending: Dict[int, DCCRequest] = {}
        self._next_rid = 1
        self._sessions: Dict[int, DCCSession] = {}
        self._bg_tasks: set = set()

    # ------------------------------------------------------------------
    # Gates
    # ------------------------------------------------------------------
    def _rate_ok(self, hostmask: str) -> bool:
        # Keyed by host only: nick and ident are free for the client to rotate.
        norm = _norm_hostmask(hostmask)
        source = norm.rpartition('@')[2] or norm
        if not self._source_limiter.allow(source):
            log.warning("[DCC] Request rate exceeded for %s; dropped", source)
            return False
        if not self._global_limiter.allow('*'):
            log.warning("[DCC] Global request rate exceeded; dropped request from %s", source)
            return False
        return True

    async def _authorize(self, nick: str, hostmask: str) -> Optional[str]:
        """
        Canonical handle of the requester, or None.  The full nick!user@host
        must belong to `nick`, match a known user's hostmask, and that user
        must be active (not locked/deleted) with +p on this bot's subnet.
        """
        return (await self._authorize_why(nick, hostmask))[0]

    async def _authorize_why(self, nick: str, hostmask: str) -> tuple[Optional[str], str]:
        """
        (handle, "") when authorized, else (None, reason).  The reason is for
        the log only; callers must never relay it to the IRC client.
        """
        if not nick or not hostmask or '!' not in hostmask or '@' not in hostmask:
            return None, "malformed requester"
        if irc_casefold(hostmask.partition('!')[0]) != irc_casefold(nick):
            return None, "hostmask does not belong to nick"
        # Denied host masks (USR-12) are refused before anything else.
        denial = await self._host_denial(host=hostmask.rpartition('@')[2], trusted=True)
        if denial:
            return None, denial
        try:
            user_mgr = self.core.user
            handle = await user_mgr.match_user(hostmask)
            if not handle:
                return None, "no matching user"
            if not await user_mgr.is_active(handle):
                return None, f"user {handle} locked or deleted"
            if not await user_mgr.matchattr(handle, '+p',
                                            subnet_id=local_subnet_id(self.core.config)):
                return None, f"user {handle} lacks +p"
            # A password-less account can never pass the challenge, so it is
            # refused before any dial-out, listener or prompt (DCC-7).
            account = await user_mgr.get(handle)
            if account is None or not account.password:
                return None, f"user {handle} has no password"
            return handle, ""
        except Exception as e:                      # fail closed
            log.error("[DCC] Authorization error for %s: %s", hostmask, e)
            return None, "authorization error"

    async def _host_denial(self, ip: Optional[str] = None, host: Optional[str] = None,
                           trusted: bool = True) -> Optional[str]:
        """
        None if the net blocklist (AccessGuard; .denyhost/.permithost and the
        automatic failure bans) admits this peer, else a log-only reason.
        `trusted`: `host` is the IRC server's view of the requester (may
        match a permit); a socket peer address is matched as an address.
        Fails closed.
        """
        guard = getattr(self.core, 'guard', None)
        if guard is None:
            return None
        try:
            entry = await guard.denied_by(ip=ip, host=host, host_trusted=trusted)
        except Exception as e:
            log.error("[DCC] Blocklist check failed for %s: %s", ip or host, e)
            return "blocklist check failed"
        if entry is None:
            return None
        return f"host {ip or host} denied by {entry.ip} ({entry.reason})"

    def endpoint_denial(self, ip, port) -> tuple[Optional[str], Optional[int], Optional[str]]:
        """
        Validate a peer-supplied DCC endpoint (decimal IPv4 integer + port).
        Returns (ip_str, port, None) when the bot may dial it, otherwise
        (None, None, reason).
        """
        try:
            ip_int = int(str(ip).strip())
            port_i = int(str(port).strip())
        except (TypeError, ValueError):
            return None, None, "malformed endpoint"
        if not 0 < ip_int <= 0xFFFFFFFF:
            return None, None, "address out of range"
        if not self.peer_port_min <= port_i <= self.peer_port_max:
            return None, None, f"port {port_i} not allowed"
        addr = ipaddress.IPv4Address(ip_int)
        if not any(addr in net for net in self.allow_networks):
            reason = ip_denial_reason(addr)
            if reason:
                return None, None, reason
        return str(addr), port_i, None

    def _capacity_denial(self, handle: str) -> Optional[str]:
        """None if a new pending request fits, else a user-facing reason."""
        if any(r.handle == handle for r in self._pending.values()):
            return "you already have a DCC request pending"
        if len(self._pending) >= self.max_pending:
            return "too many pending requests, try again later"
        # An established session of this handle is replaced on login, so it
        # does not take a slot from the new request.
        others = sum(1 for s in self._sessions.values() if not self._same_handle(s, handle))
        if len(self._pending) + others >= self.max_sessions:
            return "too many sessions, try again later"
        return None

    @staticmethod
    def _same_handle(session, handle: str) -> bool:
        return str(getattr(session, 'handle', '')).lower() == str(handle).lower()

    def _replace_sessions(self, req: DCCRequest) -> int:
        """
        One session per handle (DCC-8).  Called only once `req` is fully
        authenticated, right before its session registers: any established
        session of the same handle is told why and closed (one unregister
        each).  Sessions of other handles are untouched.
        """
        who = f"{req.nick}!{req.hostmask.partition('!')[2]}"
        old = [s for s in list(self._sessions.values()) if self._same_handle(s, req.handle)]
        return sum(1 for s in old if s.replace(f"*** Replaced by a new session from {who}"))

    # ------------------------------------------------------------------
    # Pending-request ownership and cleanup
    # ------------------------------------------------------------------
    def _new_request(self, handle: str, nick: str, hostmask: str, kind: str) -> DCCRequest:
        req = DCCRequest(rid=self._next_rid, handle=handle, nick=nick,
                         hostmask=_norm_hostmask(hostmask), kind=kind,
                         created=time.monotonic())
        self._next_rid += 1
        self._pending[req.rid] = req
        return req

    def _release(self, req: DCCRequest, reason: str, *, close_writer: bool = True) -> None:
        """Idempotent: drop ownership, close listener/socket, cancel helper tasks."""
        if req.done:
            return
        req.done = True
        req.token = None
        self._pending.pop(req.rid, None)
        _close_quietly(req.server)
        if close_writer:
            _close_quietly(req.writer)
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        for task in list(req.tasks):
            if task is not current and not task.done():
                task.cancel()
        req.tasks.clear()
        log.info("[DCC] Request #%d (%s, %s) closed: %s", req.rid, req.kind, req.handle, reason)

    def _track(self, req: DCCRequest, task: Optional[asyncio.Future]) -> None:
        if task is None:
            return
        if req.done:
            task.cancel()
            return
        req.tasks.add(task)
        task.add_done_callback(req.tasks.discard)

    def _expire_after(self, req: DCCRequest, timeout: float) -> None:
        """(Re)arm the request deadline; a previous deadline is cancelled."""
        async def _expire():
            await asyncio.sleep(timeout)
            self._release(req, "timed out")
        old = req.expiry
        if old is not None and not old.done() and old is not asyncio.current_task():
            old.cancel()
        req.expiry = asyncio.ensure_future(_expire())
        self._track(req, req.expiry)

    def _session_closed(self, session) -> None:
        """Called once by a session's shutdown(): forget it."""
        if self._sessions.get(session.session_id) is session:
            del self._sessions[session.session_id]

    def _irc_sessions(self, nick_key: Optional[str] = None) -> list:
        return [s for s in self._sessions.values()
                if isinstance(s, DCCIRCSession)
                and (nick_key is None or s.nick_key == nick_key)]

    def forget_nick(self, nick: str) -> int:
        """
        The nick quit or changed: its pending requests lose their owner and
        its IRC-fallback sessions (bound to that nick!user@host) end.
        Socket sessions are bound by their password challenge and survive.
        """
        key = irc_casefold(nick)
        reqs = [r for r in self._pending.values() if r.nick_key == key]
        for r in reqs:
            self._release(r, "requester nick changed or quit")
        sessions = self._irc_sessions(key)
        for s in sessions:
            s.shutdown("nick changed or quit")
        return len(reqs) + len(sessions)

    def reset(self, reason: str = "IRC connection reset") -> int:
        """
        Drop every pending negotiation and every IRC-fallback session
        (IRC disconnect / new connection: IRC identities are no longer
        verified).  Established socket sessions do not depend on IRC.
        """
        reqs = list(self._pending.values())
        for r in reqs:
            self._release(r, reason)
        sessions = self._irc_sessions()
        for s in sessions:
            s.shutdown(reason)
        return len(reqs) + len(sessions)

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------
    async def handle_request(self, nick: str, host: str, ctcp_args: list):
        """
        Called by Core when irc.py emits a DCC_CHAT event without a token.

        host is the requester's full nick!user@host.  ctcp_args is the
        flattened CTCP: ['DCC', 'CHAT', 'chat', '<ip>', '<port>'] for a
        reverse request, or ['DCC', 'CHAT'] / [..., '0', '0'] for a plain one.
        """
        if not self.enabled:
            log.debug("[DCC] DCC disabled, ignoring request.")
            return
        if not self._rate_ok(host):
            return

        handle, why = await self._authorize_why(nick, host)
        if not handle:
            log.warning("[DCC] Ignored DCC request from %s: %s", host, why)
            return

        if not self.sessions_available:
            log.info("[DCC] DCC request from %s (%s) refused: session layer disabled",
                     host, handle)
            await self._irc_notice(nick, "DCC CHAT is currently unavailable on this bot.")
            return

        # Optional reverse-DCC endpoint offered by the user's client.
        raw_ip, raw_port, _ = parse_chat_args(ctcp_args)
        reverse = raw_ip not in (None, '0') or raw_port not in (None, '0')
        ip = port = None
        if reverse:
            ip, port, why = self.endpoint_denial(raw_ip, raw_port)
            if why:
                log.warning("[DCC] Refused reverse-DCC endpoint from %s (%s): %s",
                            host, handle, why)
                await self._irc_notice(nick, "DCC: that address/port is not allowed.")
                return

        busy = self._capacity_denial(handle)
        if busy:
            await self._irc_notice(nick, f"DCC: {busy}.")
            return

        mode = self.mode
        if mode == 'auto':
            if self.public_ip and self.listen_is_loopback:
                log.info("[DCC] mode=auto: listener bound to %s (loopback), using passive DCC; "
                         "set dcc.listen_host to accept active DCC", self.listen_ip)
            mode = 'active' if self.public_ip and not self.listen_is_loopback else 'passive'

        # From here on, the request is registered before the first await, so
        # the capacity check above cannot be raced by concurrent requests.
        if reverse:
            req = self._new_request(handle, nick, host, 'reverse')
            self._expire_after(req, self.connect_timeout + 5)
            log.info(f"[DCC] Reverse-DCC: connecting to {nick} ({handle}) at {ip}:{port}")
            await self._dial(req, ip, port)
        elif mode == 'active':
            log.info(f"[DCC] Request from {nick} ({handle}) — negotiating mode=active")
            await self._negotiate_active(handle, nick, host)
        elif mode == 'passive':
            log.info(f"[DCC] Request from {nick} ({handle}) — negotiating mode=passive")
            await self._negotiate_passive(handle, nick, host)
        else:
            req = self._new_request(handle, nick, host, 'irc')
            try:
                ok = bool(await self._open_irc_fallback(req))
            except Exception as e:
                log.error("[DCC] IRC fallback failed for %s: %s", handle, e)
                ok = False
            if not ok:
                self._release(req, "IRC fallback refused")
            # else: stays pending until on_privmsg completes the login or it expires

    async def on_passive_callback(self, nick: str, host: str, token: str,
                                  user_ip_int, user_port):
        """
        Called by Core when user's client sends:
            CTCP DCC CHAT chat <ip> <port> <token>
        confirming a passive offer we sent.  host is the sender's full
        nick!user@host.  No work is done unless the token matches.
        """
        if not self.enabled or not token:
            return
        wire = _token_wire(token)
        if wire is None:
            log.warning(f"[DCC] Malformed passive token from {nick}")
            return
        req = next((r for r in list(self._pending.values())
                    if r.kind == 'passive' and r.token
                    and secrets.compare_digest(_token_wire(r.token) or "-", wire)), None)
        if req is None:
            if str(user_port).strip() == '0':
                # Not a callback to one of our offers: the client itself
                # started a passive handshake (irssi `/dcc chat -passive`)
                # and wants us to listen.
                await self._answer_client_passive(nick, host, str(token).strip())
                return
            log.warning(f"[DCC] Unknown passive token from {nick}")
            return
        if req.nick_key != irc_casefold(nick) or req.hostmask != _norm_hostmask(host):
            # Not the owner: leave the offer intact for its real owner.
            log.warning("[DCC] Passive token owner mismatch: expected %s, got %s",
                        req.hostmask, host)
            return
        req.token = None                      # single use, claimed before any await

        handle = await self._authorize(nick, host)
        if req.done:
            return
        if handle is None or handle != req.handle:
            self._release(req, "requester no longer authorized")
            return

        ip, port, why = self.endpoint_denial(user_ip_int, user_port)
        if why:
            log.warning("[DCC] Refused passive endpoint from %s (%s): %s", host, handle, why)
            self._release(req, f"endpoint refused ({why})")
            await self._irc_notice(nick, "DCC: that address/port is not allowed.")
            return

        log.info(f"[DCC] Passive callback from {nick} ({handle}) → {ip}:{port}")
        await self._dial(req, ip, port)

    async def _answer_client_passive(self, nick: str, host: str, token: str) -> None:
        """
        Client-initiated passive DCC (RFC reverse handshake):
            CTCP DCC CHAT chat <client_ip> 0 <token>     (token chosen by the client)
        We listen and answer with our endpoint and the same token:
            CTCP DCC CHAT chat <effective_ip> <port> <token>
        The client then connects and the normal password challenge runs on
        that socket.  Same gates as handle_request; unknown hosts get nothing.
        """
        if not self._rate_ok(host):
            return
        handle, why = await self._authorize_why(nick, host)
        if not handle:
            log.warning("[DCC] Ignored passive DCC request from %s: %s", host, why)
            return
        if not self.sessions_available:
            log.info("[DCC] Passive DCC request from %s (%s) refused: session layer disabled",
                     host, handle)
            await self._irc_notice(nick, "DCC CHAT is currently unavailable on this bot.")
            return
        if self.mode == 'irc':
            log.info("[DCC] Passive DCC request from %s (%s) ignored: mode=irc", host, handle)
            return
        if not self.public_ip:
            log.warning("[DCC] Passive DCC request from %s (%s): no public IP to advertise",
                        host, handle)
            await self._irc_notice(nick, "DCC: the bot has no address to offer.")
            return
        busy = self._capacity_denial(handle)
        if busy:
            await self._irc_notice(nick, f"DCC: {busy}.")
            return
        try:
            ip_int = _ip_to_int(self.public_ip)
        except OSError:
            log.error("[DCC] Invalid public_ip %r", self.public_ip)
            return

        req = self._new_request(handle, nick, host, 'client-passive')
        self._expire_after(req, ACTIVE_LISTEN_TIMEOUT)
        try:
            server, port = await self._start_listener(req)
        except Exception as e:
            log.error("[DCC] Listener setup failed: %s", e)
            server, port = None, None
        if req.done:                       # expired/revoked meanwhile
            _close_quietly(server)
            return
        if server is None:
            self._release(req, "no free port")
            await self._irc_notice(nick, "DCC: no free port available.")
            return
        req.server = server
        await self._irc_ctcp(nick, f"\x01DCC CHAT chat {ip_int} {port} {token}\x01")
        log.info("[DCC] Answered client-initiated passive request from %s (%s): %s:%d",
                 nick, handle, self.public_ip, port)

    # ------------------------------------------------------------------
    # Negotiation
    # ------------------------------------------------------------------
    async def _run_tracked(self, req: DCCRequest, coro):
        """
        Run `coro` as a task owned by `req`: releasing the request (expiry,
        NICK/QUIT, IRC reset) cancels it.  Returns _RELEASED in that case;
        a cancellation of the caller itself still propagates.
        """
        if req.done:
            coro.close()
            return _RELEASED
        task = asyncio.ensure_future(coro)
        self._track(req, task)
        try:
            return await task
        except asyncio.CancelledError:
            current = asyncio.current_task()
            if task.cancelled() and req.done and not (current and current.cancelling()):
                return _RELEASED
            raise

    async def _dial(self, req: DCCRequest, ip: str, port: int) -> None:
        """Connect to an already validated endpoint for `req`; always cleans up."""
        try:
            res = await self._run_tracked(req, asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.connect_timeout))
        except asyncio.CancelledError:
            self._release(req, "cancelled while connecting")
            raise
        except (OSError, asyncio.TimeoutError) as e:
            log.warning("[DCC] Connect to %s:%s for %s failed: %r", ip, port, req.handle, e)
            self._release(req, "connect failed")
            await self._irc_notice(req.nick, "DCC: connection failed.")
            return
        if res is _RELEASED:
            return
        reader, writer = res
        if req.done:                       # released right as the connect finished
            _close_quietly(writer)
            return
        await self._hand_off(req, reader, writer)

    async def _hand_off(self, req: DCCRequest, reader, writer) -> None:
        """Give an authorized request's socket to the session layer."""
        req.writer = writer
        try:
            ok = await self._run_tracked(req, self._open_session(req, reader, writer))
        except asyncio.CancelledError:
            self._release(req, "cancelled during session setup")
            raise
        except Exception as e:
            log.error("[DCC] Session setup failed for %s: %s", req.handle, e)
            ok = False
        if ok is _RELEASED:
            return                         # _release already closed the socket
        if ok is True:
            self._release(req, "session established", close_writer=False)
        else:
            self._release(req, "session refused")

    async def _start_listener(self, req: DCCRequest):
        """Bind the active-mode listener on a random port of the range."""
        if self.listen_is_loopback:
            log.warning("[DCC] Active listener bound to loopback (%s): remote DCC clients "
                        "cannot reach it. Set dcc.listen_host (e.g. 0.0.0.0) or use "
                        "mode=passive.", self.listen_ip)
        lo, hi = sorted((self.port_min, self.port_max))
        for _ in range(LISTEN_PORT_ATTEMPTS):
            port = lo + secrets.randbelow(hi - lo + 1)
            try:
                server = await asyncio.start_server(
                    lambda r, w: self._accept_active(req, r, w), self.listen_ip, port)
            except OSError:
                continue
            return server, port
        return None, None

    async def _negotiate_active(self, handle: str, nick: str, host: str):
        """Active DCC: bot opens a listening socket and advertises IP:port via CTCP."""
        if not self.public_ip:
            log.warning("[DCC] No public IP; falling back to passive.")
            await self._negotiate_passive(handle, nick, host)
            return

        req = self._new_request(handle, nick, host, 'active')
        self._expire_after(req, ACTIVE_LISTEN_TIMEOUT)
        try:
            server, port = await self._start_listener(req)
        except Exception as e:
            log.error("[DCC] Listener setup failed: %s", e)
            server, port = None, None
        if req.done:                       # expired/revoked meanwhile
            _close_quietly(server)
            return
        if server is None:
            self._release(req, "no free port")
            await self._irc_notice(nick, "DCC: no free port available.")
            return
        req.server = server

        try:
            ip_int = _ip_to_int(self.public_ip)
        except OSError:
            log.error("[DCC] Invalid public_ip %r", self.public_ip)
            self._release(req, "invalid public_ip")
            return
        await self._irc_ctcp(nick, f"\x01DCC CHAT chat {ip_int} {port}\x01")
        log.info(f"[DCC] Sent active offer to {nick}: {self.public_ip}:{port}")

    def _accept_active(self, req: DCCRequest, reader, writer) -> None:
        """Accept exactly one connection for `req`; anything else is closed."""
        if req.done or req.writer is not None:
            _close_quietly(writer)
            return
        req.writer = writer
        _close_quietly(req.server)
        peer = writer.get_extra_info('peername')
        log.info(f"[DCC] Active connection for {req.handle} ({peer})")
        task = asyncio.ensure_future(self._hand_off(req, reader, writer))
        self._bg_tasks.add(task)                 # strong ref; owns no resources itself
        task.add_done_callback(self._bg_tasks.discard)

    async def _negotiate_passive(self, handle: str, nick: str, host: str):
        """
        Passive/Reverse DCC (RFC extension):
        Bot sends: CTCP DCC CHAT chat 0 0 <token>
        User's client then opens a socket and sends back:
            CTCP DCC CHAT chat <real_ip_int> <real_port> <token>
        Bot connects outbound to the user, after on_passive_callback has
        re-checked ownership, authorization and the endpoint.
        """
        req = self._new_request(handle, nick, host, 'passive')
        req.token = _random_token()
        self._expire_after(req, PASSIVE_CONNECT_TIMEOUT)
        await self._irc_ctcp(nick, f"\x01DCC CHAT chat 0 0 {req.token}\x01")
        log.info(f"[DCC] Sent passive offer to {nick} ({handle})")

    # ------------------------------------------------------------------
    # Session layer (SAST-010)
    # ------------------------------------------------------------------
    async def _open_session(self, req: DCCRequest, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> bool:
        """
        Turn an authorized DCC socket into a partyline session (SAST-010).

        Contract: `req` carries the verified requester (canonical
        req.handle, req.hostmask, req.nick).  Return True only if the session
        layer took ownership of `writer`; on False or an exception the
        manager closes the socket and frees the slot.  May be cancelled when
        the request expires and then leaves no partial state (nothing is
        registered before the final, await-free step).

        The socket is bound to the account by a password challenge for
        req.handle: the peer on this socket is not otherwise known to be the
        IRC requester (an active listener accepts whoever connects first).
        """
        # The challenge gets its own deadline, replacing the negotiation one.
        self._expire_after(req, self.auth_timeout + AUTH_GRACE)
        # The socket's peer address is checked against the blocklist before
        # the password prompt (USR-12); the IRC host was checked already.
        peer = writer.get_extra_info('peername')
        denial = await self._host_denial(ip=peer[0] if peer else None, trusted=False)
        if req.done:
            return False
        if denial:
            log.warning("[DCC] Refused DCC socket for %s: %s", req.handle, denial)
            return False
        if not await self._socket_challenge(req, reader, writer):
            return False

        # Re-check the IRC requester right before registering.
        handle = await self._authorize(req.nick, req.hostmask)
        if req.done:
            return False
        if handle is None or handle != req.handle:
            log.warning("[DCC] %s no longer authorized after challenge", req.handle)
            await self._socket_line(writer, "Access denied.")
            return False

        # Await-free from here: register exactly once, under the canonical
        # handle, and hand the socket to the session.
        queue: asyncio.Queue = asyncio.Queue(maxsize=SESSION_QUEUE_MAX)
        replaced = self._replace_sessions(req)
        sid = self.core.partyline.register_remote('dcc', req.handle, queue)
        session = DCCSession(sid, req.handle, reader, writer, self.core.partyline,
                             nick=req.nick, queue=queue, manager=self)
        self._sessions[sid] = session
        req.writer = None                  # the session owns the socket now
        self._release(req, "session established", close_writer=False)
        queue.put_nowait({'type': 'MESSAGE', 'text':
                          f"Welcome to the WBS partyline, {req.handle}! "
                          f"Type .help for commands, .quit to leave."})
        if replaced:
            queue.put_nowait({'type': 'MESSAGE', 'text': "Replaced your previous session."})
        session.start()
        log.info("[DCC] Session %s established for %s (%s)", sid, req.handle, req.hostmask)
        return True

    async def _socket_line(self, writer, text: str) -> None:
        try:
            writer.write((text + "\r\n").encode("utf-8", errors="replace"))
            await asyncio.wait_for(writer.drain(), timeout=5)
        except Exception:
            pass

    # F-04b: DCC password failures are counted in the shared AccessGuard per
    # (requester host, handle) -- the key /msg identify uses (F-04) -- so they
    # add up across sockets and across the IRC-fallback path.
    @staticmethod
    def _auth_key(req: DCCRequest) -> tuple[str, str]:
        return (req.hostmask.rsplit('@', 1)[-1].lower() or 'unknown', req.handle)

    def _auth_locked(self, req: DCCRequest) -> bool:
        guard = getattr(self.core, 'guard', None)
        if guard is None or not guard.handle_locked(*self._auth_key(req)):
            return False
        log.warning("[DCC] login for %s from %s refused (locked out)",
                    req.handle, req.hostmask)
        return True

    async def _auth_failed(self, req: DCCRequest) -> None:
        guard = getattr(self.core, 'guard', None)
        if guard is None:
            return
        try:
            await guard.record_failure(*self._auth_key(req), peer=True)
        except Exception as exc:
            log.error("[DCC] record_failure failed: %s", exc)

    def _auth_succeeded(self, req: DCCRequest) -> None:
        guard = getattr(self.core, 'guard', None)
        if guard is not None:
            guard.record_success(*self._auth_key(req))

    async def _socket_challenge(self, req: DCCRequest, reader, writer) -> bool:
        """Password challenge for req.handle on the DCC socket."""
        for attempt in range(1, self.auth_attempts + 1):
            await self._socket_line(writer, "Enter your password.")
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=self.auth_timeout)
            except asyncio.TimeoutError:
                await self._socket_line(writer, "Login timeout.")
                log.warning("[DCC] Password challenge timed out for request #%d", req.rid)
                return False
            except (ValueError, asyncio.LimitOverrunError, OSError) as e:
                log.warning("[DCC] Bad challenge answer for request #%d: %r", req.rid, e)
                return False
            if not line:
                log.info("[DCC] Peer left during the challenge (request #%d)", req.rid)
                return False
            password = line.decode("utf-8", errors="replace").rstrip("\r\n")
            # F-04b: a locked (host, handle) pair gets the ordinary failure
            # reply without a password check (and adds nothing to the count).
            locked = self._auth_locked(req)
            ok = (not locked and 0 < len(password) <= PASSWORD_MAX
                  and await self.core.user.verify_password(req.handle, password))
            if not ok and not locked:
                await self._auth_failed(req)
            if req.done:
                return False
            if ok:
                self._auth_succeeded(req)
                return True
            log.warning("[DCC] Wrong password on DCC socket for %s (attempt %d/%d)",
                        req.handle, attempt, self.auth_attempts)
            await self._socket_line(writer, "Incorrect password.")
        return False

    # ------------------------------------------------------------------
    # IRC fallback (SAST-010)
    # ------------------------------------------------------------------
    async def _open_irc_fallback(self, req: DCCRequest) -> bool:
        """
        Start an IRC-fallback login for `req`: the requester has to send
        `/msg <bot> chatauth <password>` from the same nick!user@host
        within auth_timeout.  The request stays pending (owned by that
        hostmask) until then; on_privmsg completes it.  Returns True if the
        prompt was sent.
        """
        if self._irc_sessions(req.nick_key):
            await self._irc_notice(req.nick, "DCC: you already have an IRC chat session.")
            return False
        self._expire_after(req, self.auth_timeout)
        await self._irc_notice(
            req.nick,
            f"DCC: chat over IRC. Within {int(self.auth_timeout)}s send: "
            f"/msg {getattr(self.core, 'botname', 'bot')} {IRC_AUTH_COMMAND} <password>")
        return True

    async def on_privmsg(self, event: dict) -> bool:
        """
        Route a private message to the IRC-fallback layer.  Returns True if
        the message was consumed (a login answer, or input of an established
        IRC-fallback session) and must not be processed further.
        """
        nick = event.get('nick') or ''
        host = event.get('host') or ''
        text = (event.get('text') or '').strip()
        key = irc_casefold(nick)

        word, _, rest = text.partition(' ')
        if word.lower() == IRC_AUTH_COMMAND:
            # Always consumed: a password never reaches the command layer.
            await self._irc_login(nick, host, rest.strip(), event.get('account'))
            return True

        for session in self._irc_sessions(key):
            if not session.matches(nick, host, event.get('account')):
                session.shutdown("IRC identity changed")
                return False
            await session.handle_line(text)
            return True
        return False

    async def _irc_login(self, nick: str, host: str, password: str, account) -> None:
        key = irc_casefold(nick)
        req = next((r for r in self._pending.values()
                    if r.kind == 'irc' and not r.claimed and r.nick_key == key), None)
        if req is None:
            return
        if req.hostmask != _norm_hostmask(host):
            log.warning("[DCC] IRC login owner mismatch: expected %s, got %s",
                        req.hostmask, host)
            return
        req.claimed = True                 # single answer, claimed before any await
        locked = self._auth_locked(req)    # F-04b: no password check while locked
        ok = (not locked and 0 < len(password) <= PASSWORD_MAX
              and await self.core.user.verify_password(req.handle, password))
        if not ok and not locked:
            await self._auth_failed(req)
        if req.done:
            return
        if ok:
            self._auth_succeeded(req)
        if not ok:
            log.warning("[DCC] Wrong IRC-fallback password for %s from %s", req.handle, host)
            self._release(req, "IRC fallback: wrong password")
            await self._irc_notice(nick, "DCC: authentication failed.")
            return
        handle = await self._authorize(nick, host)
        if req.done:
            return
        if handle is None or handle != req.handle or self._irc_sessions(key):
            self._release(req, "IRC fallback: no longer authorized")
            await self._irc_notice(nick, "DCC: access denied.")
            return

        # Await-free: register exactly once, under the canonical handle.
        queue: asyncio.Queue = asyncio.Queue(maxsize=SESSION_QUEUE_MAX)
        replaced = self._replace_sessions(req)
        sid = self.core.partyline.register_remote('dcc', req.handle, queue)
        session = DCCIRCSession(sid, req.handle, self.core.partyline, nick=nick,
                                hostmask=req.hostmask, account=account,
                                core=self.core, queue=queue, manager=self)
        self._sessions[sid] = session
        self._release(req, "IRC fallback session established")
        queue.put_nowait({'type': 'MESSAGE', 'text':
                          f"Welcome to the WBS partyline, {req.handle}! "
                          f"Type .help for commands, .quit to leave."})
        if replaced:
            queue.put_nowait({'type': 'MESSAGE', 'text': "Replaced your previous session."})
        session.start()
        log.info("[DCC] IRC-fallback session %s established for %s (%s)",
                 sid, req.handle, req.hostmask)

    async def _irc_ctcp(self, nick: str, message: str):
        """Send raw CTCP — bypass clean_message which strips \x01."""
        self.core.send_irc({
            'cmd': 'raw',
            'line': f"PRIVMSG {nick} :{message}"
        })

    async def _irc_notice(self, nick: str, text: str):
        """Send a plain NOTICE to a nick."""
        self.core.send_irc({'cmd': 'notice', 'target': nick, 'text': text})

class DCCIRCSession(_BaseDCCSession):
    """
    A pseudo-DCC session that runs entirely over IRC PRIVMSG/NOTICE, for
    clients behind symmetric NAT where DCC is impossible.

    The Partyline sees it as a normal 'dcc' session of the canonical handle
    (session types are not relaxed for it).  It is bound to the exact
    nick!user@host that logged in and to the services account seen at login
    (None when the server sends no account tag): input from anything else is
    not accepted, and NICK/QUIT of the nick or an IRC reset ends it.
    """

    kind = 'dcc-irc'

    def __init__(self, session_id: int, handle: str, partyline, *, nick: str,
                 hostmask: str, account=None, core=None, **kw):
        super().__init__(session_id, handle, partyline, nick=nick, **kw)
        self.core = core
        self.hostmask = _norm_hostmask(hostmask)
        self.account = _norm_account(account)

    @property
    def nick_key(self) -> str:
        return irc_casefold(self.nick)

    def matches(self, nick: str, host: str, account=None) -> bool:
        return (irc_casefold(nick) == self.nick_key
                and _norm_hostmask(host) == self.hostmask
                and _norm_account(account) == self.account)

    def start(self) -> None:
        super().start()
        self._spawn(self._idle_watch())

    async def handle_line(self, text: str) -> None:
        if self._closed or not text:
            return
        self._last_activity = time.time()
        if text.lower() in END_CHAT_COMMANDS:
            await self.close("ended by user")
            return
        await self.partyline.handle_input(self.session_id, text)

    async def send(self, text: str) -> None:
        self._send_now(text)

    def _send_now(self, text: str) -> None:
        if self._closed or self.core is None:
            return
        self.core.send_irc({'cmd': 'notice', 'target': self.nick, 'text': text})

    async def _idle_watch(self):
        while not self._closed:
            remaining = SESSION_IDLE_TIMEOUT - (time.time() - self._last_activity)
            if remaining <= 0:
                await self.close("idle timeout")
                return
            await asyncio.sleep(remaining)

