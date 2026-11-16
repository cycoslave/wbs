# src/botnet.py
"""
Botnet peer manager for WBS.
Handles bot-to-bot linking, command routing, and data sharing.
"""
import asyncio
import json
import logging
import secrets
import hmac
import hashlib
import re
import time
import uuid
import ssl as ssl_lib
from datetime import datetime, timezone
from collections import OrderedDict
from typing import Dict, Optional, Literal, Callable
from dataclasses import dataclass

from . import __version__
from .bot import BotManager
from .user import UserManager
from .channel import ChannelManager
from .subnet import (SubnetManager, local_subnet_id, parse_subnet_id, valid_subnet_name,
                     bot_target_scope)
from .net import AccessGuard
from .share import ReplicationPolicy, normalize_share_level, SHARE_NONE
from .relay import RELAY_VERB
from .logsafe import line_summary, safe

log = logging.getLogger("wbs.botnet")
CLOCK_SKEW_WARN_SECONDS = 30
MAX_MSG_CACHE_SIZE = 2048
MSG_TTL = 30

# ---------------------------------------------------------------------------
# Botlink mutual authentication, protocol AUTH2 (SAST-001)
#
# Both bots must hold the same pre-shared link key (PSK), stored in the
# `bots.password` column of the *peer's* row on each side and provisioned by
# the operator with `.botattr <peer> pass=<key>` on both bots.  There is no
# key bootstrap: a peer with no provisioned key cannot link.
#
#   initiator -> responder  BOTLINK   <init> <resp> <subnet> WBS <ver> AUTH2 <nonce_i>
#   responder -> initiator  LINKACK   <resp> <init> AUTH2 <nonce_r> <ts_r> <proof_r>
#   initiator -> responder  LINKAUTH  <init> AUTH2 <ts_i> <proof_i>
#   responder -> initiator  LINKREADY <resp> AUTH2 <proof_ready>
#
# Every proof is HMAC-SHA256 under a key derived from the PSK over a
# length-unambiguous transcript carrying a role label, both identities, the
# hello subnet field, both fresh 256-bit nonces and every timestamp seen so
# far.  Each side contributes its own fresh nonce, so a recorded proof never
# verifies on a new connection (replay), a proof for one role/direction never
# verifies for another (reflection), and a changed timestamp breaks the MAC.
# Timestamps are mandatory and must be within CLOCK_SKEW_WARN_SECONDS.
#
# Per-connection state machine (BotLink.state):
#   out: await_ack -> await_ready -> ready
#   in :  (hello)  -> await_auth  -> ready
# Anything out of order, malformed, or failing verification aborts that
# connection only.  Messages are honoured only from the writer that owns the
# registered BotLink, and a live link is never replaced or inherited by a
# second connection claiming the same handle.
# ---------------------------------------------------------------------------
AUTH_PROTO = "AUTH2"
_AUTH_DOMAIN = "wbs-botlink-auth2"
_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
_PROOF_RE = re.compile(r"^[0-9a-f]{64}$")
_PEER_HANDLE_RE = re.compile(r"^[A-Za-z0-9_\-\[\]\\^`|{}]{1,32}$")
LEGACY_LINK_ERROR = (
    "botlink protocol AUTH2 required; upgrade both bots and set the same "
    "link key with .botattr <bot> pass=<key> on each side"
)


def _link_key(psk: str) -> bytes:
    """Derive the per-pair MAC key from the provisioned link PSK."""
    return hmac.new(psk.encode("utf-8"), f"{_AUTH_DOMAIN}:key".encode(), hashlib.sha256).digest()


def _auth_transcript(label: str, initiator: str, responder: str, subnet_field: str,
                     nonce_i: str, nonce_r: str, *timestamps: int) -> bytes:
    """Unambiguous (JSON-encoded) transcript for one handshake proof."""
    fields = [_AUTH_DOMAIN, label, initiator.lower(), responder.lower(),
              subnet_field, nonce_i, nonce_r, *[int(t) for t in timestamps]]
    return json.dumps(fields, separators=(",", ":")).encode("utf-8")


def _auth_proof(psk: str, label: str, initiator: str, responder: str, subnet_field: str,
                nonce_i: str, nonce_r: str, *timestamps: int) -> str:
    """HMAC-SHA256 proof of PSK possession bound to the full transcript."""
    msg = _auth_transcript(label, initiator, responder, subnet_field, nonce_i, nonce_r, *timestamps)
    return hmac.new(_link_key(psk), msg, hashlib.sha256).hexdigest()


def _derive_shared_password(partial_a: str, partial_b: str) -> str:
    """
    Removed (SAST-001): the old unauthenticated XOR key "exchange" derived the
    link key from two values sent in cleartext.  Kept only so stale imports
    fail loudly instead of silently re-enabling the bootstrap.
    """
    raise RuntimeError(
        "unauthenticated botlink key bootstrap was removed; provision a link "
        "key with .botattr <bot> pass=<key> on both bots"
    )

class AutoLinkManager:
    """
    Periodically attempts to connect to peers marked autolink=1 in the DB.
    Each peer has its own retry interval; connection attempts are jittered
    slightly to avoid thundering herd on startup.
    """

    # Hard floor: never retry faster than this regardless of DB setting
    MIN_RETRY_INTERVAL = 15   # seconds
    # Cap: don't let DB set absurdly long intervals that mask problems
    MAX_RETRY_INTERVAL = 600  # seconds

    def __init__(self, botnet_manager: "BotnetManager"):
        self._mgr = botnet_manager
        self._running = False
        self._task: asyncio.Task | None = None
        # Track next-attempt time per peer handle (epoch float)
        self._next_attempt: dict[str, float] = {}

    def start(self):
        """Launch the background loop."""
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="autolink-loop")
        log.info("AutoLinkManager started")

    def stop(self):
        """Cancel the background loop cleanly."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        log.info("AutoLinkManager stopped")

    async def _loop(self):
        """
        Main loop: polls DB for autolink peers, attempts connection
        for any that are due and not already connected.
        """
        # Short initial delay so botnet manager finishes init
        await asyncio.sleep(5)

        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("AutoLink loop error: %s", exc, exc_info=True)
            await asyncio.sleep(5)   # poll granularity

    async def _tick(self):
        """One pass: check all autolink peers and connect those that are due."""
        peers_cfg = await self._mgr.bot.get_autolink_peers()
        now = time.monotonic()

        for peer in peers_cfg:
            handle = peer["handle"].lower()

            # Already linked and authenticated — skip
            link = self._mgr.peers.get(handle)
            if link and link.connected and link.authed:
                # Reset the backoff counter since we're healthy
                self._next_attempt.pop(handle, None)
                continue

            # Not yet due for a retry?
            if now < self._next_attempt.get(handle, 0):
                continue

            # Clamp retry interval to safe bounds
            raw_interval = peer.get("autolink_retry_interval", 60)
            interval = max(
                self.MIN_RETRY_INTERVAL,
                min(raw_interval, self.MAX_RETRY_INTERVAL)
            )

            log.info("AutoLink: attempting connection to %s", handle)
            try:
                await self._mgr.connect_peer(peer["handle"])
            except Exception as exc:
                log.warning("AutoLink: connect to %s failed: %s", handle, exc)

            # Schedule next attempt regardless of success/failure.
            # On success, _tick will see authed=True next pass and skip.
            self._next_attempt[handle] = now + interval

@dataclass
class BotLink:
    """Represents a connected or pending botnet peer."""
    # Required fields — no default, must be supplied at construction
    name: str
    host: str
    port: int

    # Optional connection handles — set after the asyncio connection is established
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None

    # Optional identity/config fields
    nick:         str | None = None      # ← was: str = None (incorrect)
    # Authoritative peer scope, loaded from *our* DB (bots.subnet_id plus
    # bot_subnets), never from the peer's hello or payloads (SAST-002).
    # subnet_id is the primary subnet (local one when in scope); an empty
    # subnet_ids means unknown scope and every peer command is denied.
    subnet_id:    int | None = None
    subnet_ids:   frozenset[int] = frozenset()
    session_id:   int | None = None
    password:     str | None = None      # provisioned link PSK (never sent on the wire)

    # Settings with meaningful defaults.  share_level is loaded from the
    # peer's row in our DB (none|subnet|all, SAST-003); until then nothing
    # is replicated.
    share_level: str = SHARE_NONE
    role: Literal['hub', 'backup', 'leaf', 'none'] = 'none'

    # State flags
    authed:       bool = False
    connected:    bool = False
    connected_at: datetime | None = None

    # AUTH2 per-connection handshake state (see module header)
    direction:  Literal['in', 'out'] = 'out'
    state:      str = 'new'              # await_ack|await_auth|await_ready|ready|failed
    auth_initiator: str | None = None
    auth_responder: str | None = None
    subnet_field:   str = '1'            # hello subnet token, bound into every proof
    # Subnet the peer *announced* in its post-auth `SUBNET <id> [name]` line
    # (NET-7): (id, name or None).  Informational only: it is shown by
    # `.botattr` and can be accepted with `.botattr <bot> subnet=proposed`, but
    # it never becomes scope by itself (SAST-002).
    proposed_subnet: tuple[int, str | None] | None = None
    nonce_i:    str | None = None
    nonce_r:    str | None = None
    ts_r:       int | None = None
    ts_i:       int | None = None

@dataclass(frozen=True)
class BotCommand:
    """Minimal botnet command key."""
    name: str
    plugin: str = 'core'    

class BotnetManager:
    """Manages botnet peer connections and routing."""
    
    def __init__(self, core):
        self.core = core
        self.db_path = self.core.db_path
        self.config = self.core.config
        self.user = UserManager(self.db_path)
        self.chan = ChannelManager(self.db_path)
        self.bot = BotManager(self.db_path)
        self.subnet = SubnetManager(self.db_path)
        self.peers: Dict[str, BotLink] = {}
        self.topology: Dict[str, str] = {}   # handle → via_peer (indirect bots)
        self.cmds: Dict[BotCommand, Callable] = {}
        self._peer_skew: dict[str, int] = {}
        # In-flight AUTH2 handshakes, keyed by the owning connection (writer).
        self._handshakes: dict[asyncio.StreamWriter, BotLink] = {}
        
        # Settings
        self.subnet_id = self._local_subnet_id(self.config)
        self.my_handle = self.config.get('bot', {}).get('nick', 'WBS')
        # Deny-by-default replication policy for SHARE / UPDATE (SAST-003).
        self.policy = ReplicationPolicy(self.db_path, self.subnet_id, self.my_handle)
        self.autolink = AutoLinkManager(self)
        self._msg_cache: OrderedDict[str, float] = OrderedDict()
        self.guard: Optional["AccessGuard"] = None
        self.running = True
        self.loop = None
        
    def stop(self):
        """Shutdown."""
        self.running = False
        self.autolink.stop()
        for link in self.peers.values():
            if link.writer and not link.writer.is_closing():
                link.writer.close()
        for writer in list(self._handshakes):
            if self._writer_live(writer):
                writer.close()
        self._handshakes.clear()

    async def start(self):
        """Start background tasks. Must be called from inside a running event loop.
        The autolink retry loop is Core's 'autolink' registry task (NET-9),
        which calls self.autolink._tick(); it is not started here."""
        self._warn_tls_config()
        self._register_net_handlers()

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------
    def _handshake_timeout(self) -> float:
        try:
            return float(self.config.get('settings', {}).get('handshake_timeout', 30))
        except (TypeError, ValueError):
            return 30.0

    @staticmethod
    def _peer_ip(writer) -> str | None:
        try:
            info = writer.get_extra_info("peername")
            return info[0] if info else None
        except Exception:
            return None

    def has_live_peer(self, ip: str, handle: str | None = None) -> bool:
        """
        Is an authenticated botnet link up whose connection comes from `ip`
        (and, if given, that is `handle`)?  Used by the AccessGuard so failed
        BOTLINKs from a shared address never lock out linked peers (NET-13).
        """
        if not ip:
            return False
        if handle is not None:
            link = self._live_link(handle)
            links = [link] if link is not None else []
        else:
            links = [l for l in list(self.peers.values()) if self._live_link(l.name)]
        return any(self._peer_ip(l.writer) == ip for l in links)

    @staticmethod
    def _writer_live(writer) -> bool:
        try:
            return writer is not None and not writer.is_closing()
        except Exception:
            return False

    def _live_link(self, handle: str) -> BotLink | None:
        """Return the registered, fully authenticated link for handle, if still live."""
        link = self.peers.get(handle.lower())
        if link and link.state == 'ready' and link.authed and self._writer_live(link.writer):
            return link
        return None

    def _owns_link(self, handle: str, writer) -> BotLink | None:
        """Return the registered link only if `writer` is the connection that owns it."""
        link = self.peers.get(handle.lower())
        if link is not None and link.writer is writer and link.state == 'ready' and link.authed:
            return link
        return None

    def _pending_outbound(self, handle: str) -> bool:
        key = handle.lower()
        return any(
            hs.direction == 'out' and hs.name.lower() == key and self._writer_live(hs.writer)
            for hs in self._handshakes.values()
        )

    # ------------------------------------------------------------------
    # Peer scope and inbound authorization (SAST-002)
    #
    # Operator rule: bots of different subnets may share an IRC server and
    # may link, but channel ops, modes and botnet commands only ever flow
    # between bots of the *same* subnet.
    #
    #  * A peer's scope comes only from our own DB (bots.subnet_id plus
    #    bot_subnets), provisioned with `.botattr <bot> subnet=<id|name>`.
    #    The hello's subnet token and every payload field are peer-asserted
    #    and never become scope.  No stored subnet = unknown scope = denied.
    #  * authorize_peer_command() is the single deny-by-default gate in front
    #    of every inbound CMD, routed CMD_ROUTE and REQUEST_* effect.  It
    #    checks the sending link, the claimed routed origin and the intended
    #    target (channel scope, bot nicks named by op/mode/netop requests).
    #  * Routed messages are only relayed to peers sharing a subnet with the
    #    peer they came from, so a cross-subnet bot cannot launder a command
    #    through a hub by forging a same-subnet origin.
    # ------------------------------------------------------------------
    # Command -> index of its channel argument (channel must be in local scope).
    _CHANNEL_ARG: dict[str, int] = {
        'join': 0, 'part': 0, 'mode': 0, 'op': 1, 'deop': 1,
        'reqop': 1, 'sugop': 1,
        'request_invite': 0, 'request_unban': 0, 'request_limit_raise': 0,
    }
    # Command -> index of an argument that must name a same-subnet bot.
    _BOT_TARGET_ARG: dict[str, int] = {
        'reqop': 0, 'sugop': 0, 'request_invite': 1, 'request_unban': 1,
    }
    # Commands whose nick arguments must not name a bot outside the local subnet.
    _NICK_ARG_CMDS = frozenset({'op', 'deop', 'mode'})
    _CHAN_PREFIXES = ('#', '&', '+', '!')

    @staticmethod
    def _local_subnet_id(config: dict) -> int:
        """Local subnet: botnet.subnet_id, else subnet.id (what seed_db stores), else 1."""
        return local_subnet_id(config)

    async def load_peer_scope(self, handle: str) -> frozenset[int]:
        """Authoritative subnet scope of a peer from the local DB; empty = unknown."""
        try:
            scope = await self.bot.get_subnet_scope(handle)
        except Exception as exc:
            log.error("Could not load subnet scope for %s: %s", handle, exc)
            return frozenset()
        return scope or frozenset()

    def _apply_scope(self, link: BotLink, scope: frozenset[int]) -> None:
        link.subnet_ids = frozenset(scope)
        announced = link.proposed_subnet[0] if link.proposed_subnet else None
        if self.subnet_id in link.subnet_ids:
            link.subnet_id = self.subnet_id
        elif announced is not None and announced in link.subnet_ids:
            # The announcement only picks the primary subnet *inside* the
            # stored scope; it never widens it (NET-7 / SAST-002).
            link.subnet_id = announced
        elif link.subnet_ids:
            link.subnet_id = min(link.subnet_ids)
        else:
            link.subnet_id = None

    async def refresh_peer_scope(self, handle: str) -> BotLink | None:
        """Re-read a live peer's stored scope and share level (after .botattr changes)."""
        link = self.peers.get(handle.lower())
        if link is None:
            return None
        await self._reload_link_state(link)
        return link

    async def _reload_link_state(self, link: BotLink) -> str | None:
        """
        Re-read a link's stored scope and share level from our DB, looked up by
        the link's handle every time (NET-4): no cached row survives a
        `.-bot` / `.+bot` of the peer.  Returns None when the bots row was
        found, else the reason it could not be resolved (scope is then empty).
        """
        handle = (link.name or "").lower()
        bot, reason = None, f"no bots row for {handle!r} (deleted while linked?)"
        for key in dict.fromkeys((link.name or "", handle)):
            try:
                bot, reason = await self.bot.get(key), None
                break
            except ValueError:
                continue
            except Exception as exc:
                bot, reason = None, f"bots row lookup failed: {exc}"
                break
        if bot is not None and getattr(bot, "deleted_at", None):
            bot, reason = None, f"bots row for {handle!r} is deleted"
        if bot is None:
            scope, level = frozenset(), SHARE_NONE
        else:
            scope, level = await self.load_peer_scope(handle), normalize_share_level(bot.share_level)
        before = link.subnet_id
        self._apply_scope(link, scope)
        link.share_level = level
        if link.subnet_id != before or link.subnet_id is None:
            self.subnet.unregister_peer(handle)
            if link.subnet_id is not None:
                self.subnet.register_peer(handle, link.subnet_id)
        return reason

    async def _share_target_scope(self, link: BotLink | None, direction: str) -> frozenset[int]:
        """
        Share scope of a live link, resolved freshly from our DB by the link's
        handle (NET-4).  A link whose scope cannot be resolved logs a WARNING
        with the reason instead of being skipped silently.
        """
        name = link.name if link is not None else "?"
        if link is None or not link.authed or not link.connected or link.state != 'ready' \
                or not self._writer_live(link.writer):
            log.warning("replication %s: share target %s unresolved: link is not live",
                        direction, name)
            return frozenset()
        reason = await self._reload_link_state(link)
        if reason is not None:
            log.warning("replication %s: share target %s unresolved: %s", direction, name, reason)
            return frozenset()
        if not link.subnet_ids:
            log.warning("replication %s: share target %s unresolved: no stored subnet scope "
                        "(set it with .botattr %s subnet=<id|name>)", direction, name, name)
            return frozenset()
        scope = self.share_scope(link)
        if not scope:
            log.info("replication %s: nothing shared with %s (share=%s, subnets %s, "
                     "local subnet %s)", direction, name, link.share_level,
                     sorted(link.subnet_ids), self.subnet_id)
        return scope

    def share_scope(self, link: BotLink | None) -> frozenset[int]:
        """Subnets whose data may be replicated with this link (SAST-003); empty = nothing."""
        if link is None or not link.authed or not link.connected or link.state != 'ready':
            return frozenset()
        return self.policy.scope_for(link.share_level, link.subnet_ids)

    def link_in_local_subnet(self, link: BotLink | None) -> bool:
        return link is not None and self.subnet_id in link.subnet_ids

    def same_subnet_peer(self, handle: str | None) -> BotLink | None:
        """The registered, authenticated peer for handle if its stored scope includes our subnet."""
        if not handle:
            return None
        link = self.peers.get(handle.lower())
        if (link is not None and link.authed and link.connected and link.state == 'ready'
                and self.link_in_local_subnet(link)):
            return link
        return None

    def same_subnet_bot_nicks(self) -> dict[str, str]:
        """{nick_lower: handle} for authenticated, connected peers of the local subnet only."""
        return {
            (link.nick or link.name).lower(): handle
            for handle, link in self.peers.items()
            if (link.nick or link.name) and link.authed and link.connected
            and self.link_in_local_subnet(link)
        }

    async def _bot_target_scope(self, nick: str) -> bool | None:
        """
        True  -> nick is this bot or a bot whose stored scope includes our subnet.
        False -> nick is a bot outside our subnet, or of unknown scope.
        None  -> nick is not a known bot.

        Same rule as the local .op/.mode/.net path (subnet.bot_target_scope).
        """
        return await bot_target_scope(
            nick, local=self.subnet_id,
            own_names=(self.my_handle, getattr(self.core, 'botname', '')),
            peers=list(self.peers.values()), bots=self.bot)

    async def _channel_in_scope(self, channel: str) -> bool:
        """A channel bound to subnets must include ours; unbound channels are global."""
        if not channel or not channel.startswith(self._CHAN_PREFIXES):
            return False
        try:
            bound = await self.chan.get_subnet_ids(channel)
        except Exception as exc:
            log.error("Could not load subnet scope for channel %s: %s", channel, exc)
            return False
        return not bound or self.subnet_id in bound

    @staticmethod
    def _deny(from_bot: str, command: str, reason: str) -> bool:
        log.warning("Denied botnet command %r from %s: %s", command, from_bot, reason)
        return False

    async def authorize_peer_command(self, from_bot: str, command: str, args,
                                     source: str | None = None) -> bool:
        """
        Deny-by-default gate for every inbound peer command with local effects.

        from_bot: the authenticated peer the line arrived from.
        source:   the claimed origin of a routed (CMD_ROUTE) message, if any.
        """
        command = (command or '').lower()
        args = list(args) if isinstance(args, (list, tuple)) else str(args or '').split()

        link = self.same_subnet_peer(from_bot)
        if link is None:
            known = self.peers.get((from_bot or '').lower())
            scope = sorted(known.subnet_ids) if known else []
            return self._deny(from_bot, command,
                              f"sender is not a same-subnet peer (scope {scope or 'unknown'}, "
                              f"local subnet {self.subnet_id})")

        if source and source.lower() != from_bot.lower():
            if source.lower() == self.my_handle.lower():
                return self._deny(from_bot, command, "routed origin forged as this bot")
            if (await self._bot_target_scope(source)) is not True:
                return self._deny(from_bot, command,
                                  f"routed origin {source!r} is not a same-subnet bot")

        idx = self._CHANNEL_ARG.get(command)
        if idx is not None:
            chan = args[idx] if len(args) > idx else ''
            if not await self._channel_in_scope(chan):
                return self._deny(from_bot, command, f"channel {chan!r} outside local subnet")
        elif command in ('say', 'msg') and args and args[0].startswith(self._CHAN_PREFIXES):
            if not await self._channel_in_scope(args[0]):
                return self._deny(from_bot, command, f"channel {args[0]!r} outside local subnet")

        idx = self._BOT_TARGET_ARG.get(command)
        if idx is not None:
            target = args[idx] if len(args) > idx else ''
            if (await self._bot_target_scope(target)) is not True:
                return self._deny(from_bot, command,
                                  f"target {target!r} is not a same-subnet bot")

        if command in self._NICK_ARG_CMDS:
            if command == 'mode':
                nicks = [a for a in args[1:] if not a.startswith(('+', '-'))]
            else:
                nicks = args[:1]
            for nick in nicks:
                if (await self._bot_target_scope(nick)) is False:
                    return self._deny(from_bot, command,
                                      f"target {nick!r} is a bot outside the local subnet")
        return True

    def _may_relay(self, sender: BotLink | None, dest: BotLink) -> bool:
        """Relay routed traffic only between peers that share a stored subnet."""
        return sender is not None and bool(sender.subnet_ids & dest.subnet_ids)

    async def _abort_handshake(self, writer, handle: str, reason: str,
                               error: str | None = None, auth_failure: bool = False) -> None:
        """Fail one connection's handshake closed. Never touches another connection's link."""
        hs = self._handshakes.pop(writer, None)
        if hs is not None:
            hs.state = 'failed'
            hs.authed = False
            hs.connected = False
        log.error("Botlink handshake with %s rejected: %s", handle, reason)
        if error and self._writer_live(writer):
            await self._safe_send(writer, f"ERROR :{error}\n")
        if auth_failure and self.guard and (hs is None or hs.direction == 'in'):
            ip = self._peer_ip(writer)
            if ip:
                try:
                    await self.guard.record_failure(ip, handle, peer=True)
                except Exception as exc:
                    log.debug("record_failure for %s failed: %s", ip, exc)
        try:
            if self._writer_live(writer):
                writer.close()
        except Exception:
            pass

    @staticmethod
    def _normalize_fingerprint(value) -> str:
        """Lowercase 64-hex SHA-256 digest (colons/spaces optional) or ValueError."""
        if not isinstance(value, str):
            raise ValueError("ssl_fingerprint must be a string")
        fp = value.replace(':', '').replace(' ', '').lower()
        if not re.fullmatch(r'[0-9a-f]{64}', fp):
            raise ValueError("ssl_fingerprint must be a SHA-256 digest "
                             "(64 hex digits, colons optional)")
        return fp

    def _build_link_tls(self, handle: str, cfg: dict):
        """Build the client TLS context for an outgoing link.

        Returns ``(context, pin)``; ``pin`` is the normalized expected SHA-256
        of the peer certificate, or None.  Raises ValueError on bad config
        (fail closed: the link is not made).

        - default: full chain + hostname verification (system CAs);
        - ``ssl_ca_file``: same, additionally trusting that CA/cert file
          (verification stays on);
        - ``ssl_fingerprint``: the peer cert must match the pin (checked after
          the handshake).  Without ``ssl_ca_file`` the pin replaces chain
          verification, so a self-signed peer works;
        - ``ssl_verify=false`` (no pin): verification off, logged loudly.
        """
        ca_file = cfg.get('ssl_ca_file') or None
        raw_pin = cfg.get('ssl_fingerprint')
        pin = self._normalize_fingerprint(raw_pin) if raw_pin not in (None, '') else None
        if ca_file is not None and not isinstance(ca_file, str):
            raise ValueError("ssl_ca_file must be a path string")
        ssl_ctx = ssl_lib.create_default_context()
        if ca_file:
            try:
                ssl_ctx.load_verify_locations(cafile=ca_file)
            except (OSError, ssl_lib.SSLError) as exc:
                raise ValueError(f"cannot load ssl_ca_file {ca_file!r}: {exc}") from exc
        if pin is not None and not ca_file:
            # Pin-only: the pinned digest authenticates the peer.
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl_lib.CERT_NONE
        elif not cfg.get('ssl_verify', True):
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl_lib.CERT_NONE
            log.warning("TLS certificate verification is OFF for the link to bot %s "
                        "(settings.ssl_verify=false): the peer is NOT authenticated and "
                        "the link is open to man-in-the-middle; set ssl_ca_file or "
                        "ssl_fingerprint instead", handle)
        return ssl_ctx, pin

    def _peer_cert_matches_pin(self, handle: str, writer, pin: str) -> bool:
        try:
            sslobj = writer.get_extra_info('ssl_object')
            der = sslobj.getpeercert(binary_form=True) if sslobj else None
        except Exception as exc:
            log.warning("Dropping link to bot %s: cannot read peer certificate: %s",
                        handle, exc)
            return False
        if not der:
            log.warning("Dropping link to bot %s: peer presented no certificate", handle)
            return False
        got = hashlib.sha256(der).hexdigest()
        if not hmac.compare_digest(got, pin):
            log.warning("Dropping link to bot %s: peer certificate fingerprint does not "
                        "match ssl_fingerprint (got sha256 %s)", handle, got)
            return False
        return True

    def _warn_tls_config(self) -> None:
        cfg = self.config.get('settings', {})
        if (cfg.get('ssl', True) and not cfg.get('ssl_verify', True)
                and not cfg.get('ssl_fingerprint')):
            log.warning("Botnet links: settings.ssl_verify=false -- TLS certificate "
                        "verification is OFF for outgoing bot links (peers are "
                        "unauthenticated at the TLS layer; links are open to "
                        "man-in-the-middle). Use ssl_ca_file or ssl_fingerprint to "
                        "verify private/self-signed peers instead.")

    async def connect_peer(self, handle: str):
        """Establish an outgoing AUTH2 connection to a peer (we are the initiator)."""
        try:
            if self._live_link(handle):
                log.info("connect_peer %s: already linked", handle)
                return
            if self._pending_outbound(handle):
                log.info("connect_peer %s: handshake already in progress", handle)
                return

            bot = await self.bot.get(handle)
            if not bot.password:
                log.error(
                    "Refusing to link %s: no link key provisioned "
                    "(set the same key on both bots with .botattr %s pass=<key>)",
                    handle, handle,
                )
                return

            cfg = self.config.get('settings', {})
            use_ssl = cfg.get('ssl', True)

            if use_ssl:
                try:
                    ssl_ctx, pin = self._build_link_tls(handle, cfg)
                except ValueError as exc:
                    log.error("Refusing to link %s: %s", handle, exc)
                    return
                reader, writer = await asyncio.open_connection(bot.address, bot.port, ssl=ssl_ctx, limit=4096)
                if pin is not None and not self._peer_cert_matches_pin(handle, writer, pin):
                    writer.close()
                    return
            else:
                reader, writer = await asyncio.open_connection(bot.address, bot.port, limit=4096)

            scope = await self.load_peer_scope(handle)
            link = BotLink(
                name=handle,
                host=bot.address,
                port=bot.port,
                nick=handle,
                reader=reader,
                writer=writer,
                password=bot.password,
                share_level=normalize_share_level(bot.share_level),
                direction='out',
                state='await_ack',
                auth_initiator=self.my_handle,
                auth_responder=handle,
                # Our real subnet id (NET-7): informational for the peer,
                # bound into the proofs, never used for authorization.
                subnet_field=str(self.subnet_id),
                nonce_i=secrets.token_hex(32),
            )
            self._apply_scope(link, scope)
            # Pending handshakes are keyed by connection, never by handle, so an
            # unauthenticated connection can neither clobber nor inherit a link.
            self._handshakes[writer] = link

            hello = (f"BOTLINK {self.my_handle} {handle} {link.subnet_field} WBS "
                     f"{__version__} {AUTH_PROTO} {link.nonce_i}\n")
            writer.write(hello.encode())
            await writer.drain()

            asyncio.create_task(self.read_peer(handle, reader, writer, release_guard=False))
            log.info(f"Connecting to peer {handle} at {bot.address}:{bot.port} — awaiting auth")

        except Exception as e:
            log.debug("connect_peer %s: %s", handle, e)

    async def disconnect_peer(self, botname: str):
        link = self.peers.pop(botname.lower(), None)
        if not link:
            return
        if link.writer and not link.writer.is_closing():
            link.writer.close()
            try:
                await link.writer.wait_closed()
            except Exception as exc:
                log.debug("disconnect_peer %s: wait_closed: %s", botname, exc)
        link.connected = False
        link.authed = False
        link.state = 'closed'
        self.subnet.unregister_peer(botname)
        self.topology = {
            h: via for h, via in self.topology.items()
            if via != botname.lower()
        }
        self.core.bot_sessions.pop(botname.lower(), None)
        self._relay_peer_down(botname)
        try:
            self.core.send_irc({'cmd': 'BOTLINK_UNLINK', 'handle': link.name})
        except Exception as exc:
            log.debug("disconnect_peer %s: BOTLINK_UNLINK: %s", botname, exc)
        self.core.partyline.broadcast(f"*** {botname} unlinked from botnet", True)
        log.info(f"Peer {botname} disconnected.")

    async def unlink_peer(self, handle: str, reason: str = "unlinked") -> bool:
        """
        Fully drop a peer (NET-6): tell it why (BYE), close the connection,
        abort any pending handshake under that handle, and clear routing,
        `.bots` and IRC-side link state.  True if anything was dropped.
        """
        key = (handle or "").lower()
        dropped = False
        for writer, hs in list(self._handshakes.items()):
            if (hs.name or "").lower() == key:
                self._handshakes.pop(writer, None)
                hs.state = 'failed'
                if self._writer_live(writer):
                    writer.close()
                dropped = True
        link = self.peers.get(key)
        if link is not None:
            if link.writer is not None and self._writer_live(link.writer):
                await self._safe_send(link.writer, f"BYE :{reason}\n")
            await self.disconnect_peer(key)
            asyncio.create_task(self.broadcast_topology())
            log.info("Unlinked peer %s: %s", handle, reason)
            dropped = True
        return dropped

    def _relay_peer_down(self, handle: str) -> None:
        """Drop interactive relays bound to a link that is no longer live (SAST-017)."""
        relay = getattr(getattr(self.core, 'partyline', None), 'relay', None)
        if relay is not None:
            try:
                relay.peer_down(handle)
            except Exception as exc:
                log.error("Relay cleanup for %s failed: %s", handle, exc)

    async def read_peer(self, handle: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        release_guard: bool = True):
        """Continuously read messages from one peer connection (owns its own cleanup).

        release_guard: release the listener AccessGuard slot on exit. Only
        inbound connections hold one; outbound links pass False.
        """
        peer_ip = self._peer_ip(writer) if release_guard else None
        key = handle.lower()
        deadline = time.monotonic() + self._handshake_timeout()

        try:
            while self.running:
                authenticated = self._owns_link(handle, writer) is not None
                try:
                    if authenticated:
                        line = await reader.readline()
                    else:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or writer.is_closing():
                            raise asyncio.TimeoutError
                        line = await asyncio.wait_for(reader.readline(), remaining)
                except asyncio.TimeoutError:
                    if not writer.is_closing():
                        await self._abort_handshake(writer, handle, "handshake timeout",
                                                    error="handshake timeout")
                    break
                except (asyncio.LimitOverrunError, ValueError):
                    if not authenticated:
                        await self._abort_handshake(writer, handle, "oversized handshake line")
                        break
                    await reader.read(4096)
                    log.warning(f"Oversized line from {handle}, discarding")
                    continue
                if not line:
                    log.info(f"Connection closed by {handle}")
                    break
                decoded = line.decode(errors="replace").strip()
                if decoded:
                    await self.process_incoming(handle, decoded, reader, writer)

        except asyncio.CancelledError:
            log.info(f"Read task cancelled for {handle}")
        except Exception as e:
            log.error(f"Read error from {handle}: {e}")
        finally:
            # Connection-owned cleanup: only undo state that *this* socket owns.
            self._handshakes.pop(writer, None)
            registered = self.peers.get(key)
            owned = registered is not None and registered.writer is writer
            session = self.core.bot_sessions.get(key)
            owned_session = session is not None and getattr(session, 'writer', None) is writer
            if owned:
                self.peers.pop(key, None)
                try:
                    self.core.send_irc({'cmd': 'BOTLINK_UNLINK',
                                        'handle': getattr(registered, 'name', handle)})
                except Exception as exc:
                    log.debug("read_peer %s: BOTLINK_UNLINK: %s", handle, exc)
            if owned or owned_session:
                self.subnet.unregister_peer(handle)
                self.topology = {
                    h: via for h, via in self.topology.items()
                    if via != key
                }
                self.core.bot_sessions.pop(key, None)
            if not writer.is_closing():
                writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if self.guard and peer_ip:
                self.guard.release(peer_ip)
            # Relays bound to this connection's link die with it; relays of a
            # newer live link under the same handle are left alone.
            self._relay_peer_down(handle)
            log.info(f"Peer {handle} disconnected")

    # ------------------------------------------------------------------
    # AUTH2 handshake (see module header for the wire protocol)
    # ------------------------------------------------------------------
    async def _hs_botlink(self, from_bot: str, parts: list[str], reader, writer) -> None:
        """Responder: validate hello, send LINKACK with fresh nonce + proof."""
        if writer in self._handshakes or any(l.writer is writer for l in self.peers.values()):
            await self._abort_handshake(writer, from_bot, "duplicate BOTLINK on one connection")
            return
        if len(parts) < 7 or parts[6] != AUTH_PROTO:
            await self._abort_handshake(writer, from_bot, "legacy/unauthenticated botlink protocol",
                                        error=LEGACY_LINK_ERROR)
            return
        if len(parts) != 8:
            await self._abort_handshake(writer, from_bot, "malformed BOTLINK", error="malformed BOTLINK")
            return
        remote, local, subnet_field, nonce_i = parts[1], parts[2], parts[3], parts[7]
        if (remote.lower() != from_bot.lower() or local.lower() != self.my_handle.lower()
                or not _PEER_HANDLE_RE.match(remote) or remote.lower() == self.my_handle.lower()):
            await self._abort_handshake(writer, from_bot, "botlink identity mismatch",
                                        error="identity mismatch")
            return
        if not subnet_field.isdigit() or len(subnet_field) > 9 or not _NONCE_RE.match(nonce_i):
            await self._abort_handshake(writer, from_bot, "malformed BOTLINK", error="malformed BOTLINK")
            return
        if self._live_link(remote):
            await self._abort_handshake(writer, from_bot, "handle already linked on another connection",
                                        error="handle already linked")
            return
        try:
            bot = await self.bot.get(remote.lower())
        except ValueError:
            await self._abort_handshake(writer, from_bot, "unknown bot", error="unknown bot",
                                        auth_failure=True)
            return
        if getattr(bot, 'deleted_at', None) or not bot.password:
            await self._abort_handshake(writer, from_bot, "no link key provisioned for this bot",
                                        error="no link key provisioned")
            return

        scope = await self.load_peer_scope(remote)
        link = BotLink(
            name=remote,
            host=bot.address,
            port=bot.port,
            nick=remote,
            reader=reader,
            writer=writer,
            password=bot.password,
            share_level=normalize_share_level(bot.share_level),
            direction='in',
            state='await_auth',
            auth_initiator=remote,
            auth_responder=self.my_handle,
            subnet_field=subnet_field,
            nonce_i=nonce_i,
            nonce_r=secrets.token_hex(32),
            ts_r=int(time.time()),
        )
        # The hello's subnet token is peer-asserted: it is bound into the
        # proofs but never becomes the peer's scope (SAST-002).  It is not
        # even recorded as a proposal: pre-NET-7 peers always send '1'; only
        # the post-auth SUBNET line is.
        self._apply_scope(link, scope)
        proof_r = _auth_proof(link.password, "responder", link.auth_initiator, link.auth_responder,
                              link.subnet_field, link.nonce_i, link.nonce_r, link.ts_r)
        self._handshakes[writer] = link
        await self._safe_send(
            writer,
            f"LINKACK {self.my_handle} {remote} {AUTH_PROTO} {link.nonce_r} {link.ts_r} {proof_r}\n",
        )

    async def _hs_linkack(self, from_bot: str, parts: list[str], writer) -> None:
        """Initiator: verify responder proof, send LINKAUTH."""
        link = self._handshakes.get(writer)
        if link is None or link.direction != 'out' or link.state != 'await_ack':
            await self._abort_handshake(writer, from_bot, "unexpected LINKACK")
            return
        if len(parts) < 4 or parts[3] != AUTH_PROTO:
            await self._abort_handshake(writer, from_bot, "peer speaks legacy botlink protocol",
                                        error=LEGACY_LINK_ERROR)
            return
        if len(parts) != 7:
            await self._abort_handshake(writer, from_bot, "malformed LINKACK")
            return
        resp, init, nonce_r, ts_raw, proof_r = parts[1], parts[2], parts[4], parts[5], parts[6]
        if resp.lower() != link.auth_responder.lower() or init.lower() != self.my_handle.lower():
            await self._abort_handshake(writer, from_bot, "LINKACK identity mismatch")
            return
        if not _NONCE_RE.match(nonce_r) or nonce_r == link.nonce_i or not _PROOF_RE.match(proof_r):
            await self._abort_handshake(writer, from_bot, "malformed LINKACK")
            return
        try:
            ts_r = int(ts_raw)
        except ValueError:
            await self._abort_handshake(writer, from_bot, "invalid LINKACK timestamp",
                                        error="missing or invalid timestamp")
            return
        expected = _auth_proof(link.password, "responder", link.auth_initiator, link.auth_responder,
                               link.subnet_field, link.nonce_i, nonce_r, ts_r)
        if not hmac.compare_digest(proof_r, expected):
            await self._abort_handshake(writer, from_bot, "responder proof failed (wrong key or tampered)")
            return
        if not await self.check_clock_skew(ts_r, from_bot):
            await self._abort_handshake(writer, from_bot, "clock skew too large", error="clock skew too large")
            return

        link.nonce_r = nonce_r
        link.ts_r = ts_r
        link.ts_i = int(time.time())
        proof_i = _auth_proof(link.password, "initiator", link.auth_initiator, link.auth_responder,
                              link.subnet_field, link.nonce_i, link.nonce_r, link.ts_r, link.ts_i)
        link.state = 'await_ready'
        await self._safe_send(writer, f"LINKAUTH {self.my_handle} {AUTH_PROTO} {link.ts_i} {proof_i}\n")

    async def _hs_linkauth(self, from_bot: str, parts: list[str], writer) -> None:
        """Responder: verify initiator proof, send LINKREADY proof, activate link."""
        link = self._handshakes.get(writer)
        if link is None or link.direction != 'in' or link.state != 'await_auth':
            await self._abort_handshake(writer, from_bot, "unexpected LINKAUTH", error="unexpected LINKAUTH")
            return
        if len(parts) != 5 or parts[2] != AUTH_PROTO:
            await self._abort_handshake(writer, from_bot, "malformed LINKAUTH", error="malformed LINKAUTH",
                                        auth_failure=True)
            return
        init, ts_raw, proof_i = parts[1], parts[3], parts[4]
        if init.lower() != link.auth_initiator.lower() or not _PROOF_RE.match(proof_i):
            await self._abort_handshake(writer, from_bot, "LINKAUTH identity mismatch",
                                        error="auth failed", auth_failure=True)
            return
        try:
            ts_i = int(ts_raw)
        except ValueError:
            await self._abort_handshake(writer, from_bot, "invalid LINKAUTH timestamp",
                                        error="missing or invalid timestamp", auth_failure=True)
            return
        expected = _auth_proof(link.password, "initiator", link.auth_initiator, link.auth_responder,
                               link.subnet_field, link.nonce_i, link.nonce_r, link.ts_r, ts_i)
        if not hmac.compare_digest(proof_i, expected):
            await self._abort_handshake(writer, from_bot, "initiator proof failed (wrong key, replay or tampered)",
                                        error="auth failed", auth_failure=True)
            return
        if not await self.check_clock_skew(ts_i, from_bot):
            await self._abort_handshake(writer, from_bot, "clock skew too large", error="clock skew too large")
            return
        if self._live_link(from_bot):
            await self._abort_handshake(writer, from_bot, "handle already linked on another connection",
                                        error="handle already linked")
            return

        link.ts_i = ts_i
        proof_ready = _auth_proof(link.password, "ready", link.auth_initiator, link.auth_responder,
                                  link.subnet_field, link.nonce_i, link.nonce_r, link.ts_r, link.ts_i)
        await self._safe_send(writer, f"LINKREADY {self.my_handle} {AUTH_PROTO} {proof_ready}\n")
        if self.guard:
            ip = self._peer_ip(writer)
            if ip:
                try:
                    self.guard.record_success(ip, from_bot)
                except Exception as exc:
                    log.debug("record_success for %s failed: %s", ip, exc)
        self._activate_link(from_bot, link, writer)
        await self._announce_subnet(link)
        asyncio.create_task(self.share_all_data(from_bot))
        asyncio.create_task(self.broadcast_topology())

    async def _hs_linkready(self, from_bot: str, parts: list[str], writer) -> None:
        """Initiator: verify responder's final proof, activate link."""
        link = self._handshakes.get(writer)
        if link is None or link.direction != 'out' or link.state != 'await_ready':
            # READY before key proof (or on a connection we never initiated) is denied.
            await self._abort_handshake(writer, from_bot, "LINKREADY before mutual authentication",
                                        error="unexpected LINKREADY")
            return
        if len(parts) != 4 or parts[2] != AUTH_PROTO or not _PROOF_RE.match(parts[3]):
            await self._abort_handshake(writer, from_bot, "malformed LINKREADY")
            return
        if parts[1].lower() != link.auth_responder.lower():
            await self._abort_handshake(writer, from_bot, "LINKREADY identity mismatch")
            return
        expected = _auth_proof(link.password, "ready", link.auth_initiator, link.auth_responder,
                               link.subnet_field, link.nonce_i, link.nonce_r, link.ts_r, link.ts_i)
        if not hmac.compare_digest(parts[3], expected):
            await self._abort_handshake(writer, from_bot, "LINKREADY proof failed")
            return
        if self._live_link(from_bot):
            await self._abort_handshake(writer, from_bot, "handle already linked on another connection")
            return
        self._activate_link(from_bot, link, writer)
        await self._announce_subnet(link)
        asyncio.create_task(self.share_all_data(from_bot))

    async def _announce_subnet(self, link: BotLink) -> None:
        """Tell a freshly authenticated peer our subnet id and name (NET-7).

        `SUBNET <id> [name]`, sent once per link by both sides.  The peer only
        records it as a proposal; it is never authorization.
        """
        name = None
        try:
            local = await self.subnet.get(self.subnet_id)
            name = local.name if local and valid_subnet_name(local.name) else None
        except Exception as exc:
            log.debug("announce_subnet: cannot load local subnet name: %s", exc)
        line = f"SUBNET {self.subnet_id}" + (f" {name}" if name else "")
        await self._safe_send(link.writer, line + "\n")

    async def _on_subnet_announce(self, from_bot: str, link: BotLink, parts: list[str]) -> None:
        """Record a peer's announced subnet as a proposal; never trust it as scope."""
        announced = parse_subnet_id(parts[1]) if len(parts) > 1 else None
        name = parts[2] if len(parts) > 2 and valid_subnet_name(parts[2]) else None
        if announced is None or len(parts) > 3:
            log.warning("Malformed SUBNET announcement from %s ignored", from_bot)
            return
        link.proposed_subnet = (announced, name)
        label = f"{announced}" + (f" ({name})" if name else "")
        if not link.subnet_ids:
            log.warning(
                "Peer %s announces subnet %s; not trusted (SAST-002). Accept it with "
                ".botattr %s subnet=proposed%s", from_bot, label, from_bot,
                "" if await self.subnet.get(announced) else
                f" after creating it with .subnet add {name or '<name>'} {announced}")
        elif announced in link.subnet_ids:
            # Stored binding exists and covers the announcement: apply it.
            self._apply_scope(link, link.subnet_ids)
            self.subnet.unregister_peer(from_bot)
            if link.subnet_id is not None:
                self.subnet.register_peer(from_bot, link.subnet_id)
            log.info("Peer %s announces subnet %s, matching its stored scope %s",
                     from_bot, label, sorted(link.subnet_ids))
        else:
            log.warning("Peer %s announces subnet %s but its stored scope is %s; "
                        "keeping the stored scope", from_bot, label, sorted(link.subnet_ids))

    def _activate_link(self, from_bot: str, link: BotLink, writer) -> None:
        """Promote a verified handshake to the registered link for its handle."""
        self._handshakes.pop(writer, None)
        key = from_bot.lower()
        link.state = 'ready'
        link.authed = True
        link.connected = True
        link.connected_at = datetime.now(timezone.utc)
        # Handshake material is no longer needed once the link is live.
        link.nonce_i = link.nonce_r = None
        self.peers[key] = link
        if link.subnet_id is not None:
            self.subnet.register_peer(from_bot, link.subnet_id)
        if not self.link_in_local_subnet(link):
            log.warning(
                "Peer %s linked with subnet scope %s (local subnet %s): botnet commands, "
                "mode and op requests from it will be denied%s",
                from_bot, sorted(link.subnet_ids) or "unknown", self.subnet_id,
                "" if link.subnet_ids else
                f" until its subnet is set with .botattr {from_bot} subnet=<id|name|proposed>",
            )
        self.core.bot_sessions[key] = link
        self.core.partyline.broadcast(f"*** {from_bot} linked to botnet", True)
        self.core.send_irc({
            'cmd': 'BOTLINK_LINK',
            'handle': link.name,
            'nick': link.name
        })
        log.info("Peer %s mutually authenticated (%s, AUTH2)", from_bot,
                 "outbound" if link.direction == 'out' else "inbound")

    async def process_incoming(self, from_bot: str, line: str, reader, writer):
        """Process one message from a peer connection."""
        parts = line.split()
        if not parts:
            return
        cmd = parts[0].upper()

        link = self._owns_link(from_bot, writer)

        if cmd in ("BOTLINK", "LINKACK", "LINKAUTH", "LINKREADY"):
            if link is not None:
                log.warning("Ignoring %s from already-linked %s", cmd, from_bot)
                return
            if cmd == "BOTLINK":
                await self._hs_botlink(from_bot, parts, reader, writer)
            elif cmd == "LINKACK":
                await self._hs_linkack(from_bot, parts, writer)
            elif cmd == "LINKAUTH":
                await self._hs_linkauth(from_bot, parts, writer)
            else:
                await self._hs_linkready(from_bot, parts, writer)
            return

        # BLOCK UNAUTHED: only the connection that owns a mutually authenticated
        # link may issue commands; no other writer inherits its auth state.
        if link is None:
            if writer in self._handshakes:
                reason = f"peer error: {safe(line, 120)}" if cmd == "ERROR" else f"{safe(cmd, 24)} before authentication"
                await self._abort_handshake(writer, from_bot, reason)
            else:
                # SAST-002: never the payload (UPDATE/SHARE/CMD_ROUTE lines
                # carry user records and command arguments).
                log.warning(f"Unauthed from {from_bot}: {line_summary(line)}")
            return

        elif cmd == "SUBNET":
            # SUBNET <id> [name]: peer-announced subnet (NET-7), a proposal only.
            await self._on_subnet_announce(from_bot, link, parts)

        elif cmd == "BYE":
            # BYE :<reason>: the peer dropped this link (e.g. `.-bot`, NET-6).
            reason = line.split(None, 1)[1].lstrip(":") if len(parts) > 1 else ""
            log.info("Peer %s closed the link: %s", from_bot, reason[:120] or "no reason")
            await self.disconnect_peer(from_bot)
        
        elif cmd == "CHAT":
            if len(parts) < 3:
                log.warning("Malformed CHAT from %s: %s", from_bot, line_summary(line))
                return
            nick    = parts[1]
            message = ' '.join(parts[2:])
            self.core.partyline.broadcast(f"<{from_bot}@{nick.rstrip(':')}> {message}", True)

        elif cmd == "CMD":
            # Format: CMD <command> [args]
            if len(parts) < 2:
                return
            name = parts[1].lower()
            args = parts[2:]
            
            for pluginkey, handler in self.cmds.items():
                if pluginkey.name == name:
                    # SAST-002: same-subnet sender and in-scope target, or nothing happens.
                    if await self.authorize_peer_command(from_bot, name, args):
                        await handler(pluginkey, args, from_bot)
                    return
            log.warning(f"No handler for CMD {name}")
        
        elif cmd == RELAY_VERB:
            # Interactive partyline relay (SAST-017): typed JSON payload whose
            # origin is the authenticated link it arrived on, never a payload
            # field.  RelayManager enforces ownership and authorization.
            relay = getattr(getattr(self.core, 'partyline', None), 'relay', None)
            if relay is None:
                log.warning("RELAY from %s ignored: relay is not available", from_bot)
                return
            raw = line.split(None, 1)[1] if len(parts) > 1 else ""
            await relay.on_message(from_bot, link, raw)

        elif cmd in ('RELAY_OPEN', 'RELAY_INPUT', 'RELAY_CLOSE', 'RELAY_OUTPUT'):
            # Removed legacy relay verbs: they trusted payload-asserted
            # handle/origin/session ids (SAST-017).  Denied, never parsed.
            log.warning("Denied legacy %s from %s (use RELAY protocol v1)", cmd, from_bot)

        elif cmd == "CMD_ROUTE":
            # Format: CMD_ROUTE <routing> <msg_id> <source> <target_or_dash> [subnet_id] <command> [args...]
            # routing: broadcast | subnet | unicast
            if len(parts) < 6:
                log.warning(f"Malformed CMD_ROUTE from {from_bot}: {line_summary(line)}")
                return

            routing = parts[1].lower()
            source  = parts[3]
            subnet_id: int | None = None

            if routing == "subnet":
                # CMD_ROUTE subnet <msg_id> <source> - <subnet_id> <command> [args...]
                if len(parts) < 7:
                    log.warning(f"Malformed CMD_ROUTE subnet from {from_bot}: {line_summary(line)}")
                    return
                msg_id    = parts[2]
                try:
                    subnet_id = int(parts[5])
                except ValueError:
                    # Never guess a subnet for a routed command (SAST-002).
                    log.warning(f"Malformed CMD_ROUTE subnet from {from_bot} (bad subnet_id): {line_summary(line)}")
                    return
                command   = parts[6].lower()
                args      = " ".join(parts[7:])
                target    = None
            else:
                # CMD_ROUTE broadcast|unicast <msg_id> <source> <target_or_dash> <command> [args...]
                msg_id  = parts[2]
                target  = parts[4]
                command = parts[5].lower()
                args    = " ".join(parts[6:])

            if not self._register_message(msg_id):
                return  # duplicate — drop silently

            addressed_to_me = (
                routing == "broadcast"
                or (routing == "unicast" and target.lower() == self.my_handle.lower())
                or (routing == "subnet"  and self.subnet_id == subnet_id)
            )

            if addressed_to_me:
                for pluginkey, handler in self.cmds.items():
                    if pluginkey.name == command:
                        # SAST-002: routed target selection is not authorization.
                        if await self.authorize_peer_command(from_bot, command, args.split(),
                                                             source=source):
                            await handler(pluginkey, args.split(), from_bot)
                        break
                else:
                    log.warning(f"No handler for routed CMD_ROUTE command: {command}")

            # Relay logic: only between peers sharing a stored subnet with the
            # peer this came from, so cross-subnet traffic cannot be laundered.
            sender = self.peers.get(from_bot.lower())
            if routing == "broadcast":
                relay_peers = [
                    link for name, link in self.peers.items()
                    if link.authed and link.connected and link.writer
                    and name != from_bot.lower()
                    and self._may_relay(sender, link)
                ]
            elif routing == "subnet":
                relay_peers = [
                    link for name, link in self.peers.items()
                    if link.authed and link.connected and link.writer
                    and name != from_bot.lower()
                    and sender is not None and subnet_id in sender.subnet_ids
                    and subnet_id in link.subnet_ids
                ]
            elif routing == "unicast":
                # Relay if we're not the target; flood-fill reaches the target eventually
                relay_peers = [] if addressed_to_me else [
                    link for name, link in self.peers.items()
                    if link.authed and link.connected and link.writer
                    and name != from_bot.lower()
                    and self._may_relay(sender, link)
                ]
            else:
                relay_peers = []

            if relay_peers:
                tasks = [self._safe_send(link.writer, f"{line}\n") for link in relay_peers]
                await asyncio.gather(*tasks, return_exceptions=True)
        
        elif cmd == "CHAT_ROUTE":
            # Format: CHAT_ROUTE <msg_id> <source_bot> <nick> :<message text>
            if len(parts) < 4:
                log.warning(f"Malformed CHAT_ROUTE from {from_bot}: {line_summary(line)}")
                return

            msg_id     = parts[1]
            source_bot = parts[2]
            nick       = parts[3]
            # Colon-prefixed message body (IRC convention)
            msg        = " ".join(parts[4:]).lstrip(":")

            if not self._register_message(msg_id):
                return  # duplicate — drop silently

            # Display locally on the partyline
            self.core.partyline.broadcast(f"<{source_bot}@{nick}> {msg}", True)

            # Relay to all other authenticated peers except sender
            relay_line = f"CHAT_ROUTE {msg_id} {source_bot} {nick} :{msg}\n"
            tasks = [
                self._safe_send(link.writer, relay_line)
                for name, link in self.peers.items()
                if link.authed and link.connected and link.writer
                and name != from_bot.lower()
            ]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        elif cmd == "UPDATE":
            # Format: UPDATE <msg_id> <CHANNEL|USER|BOT> <ADD|DEL|UPDATE> <json>
            #         UPDATE <msg_id> <USERACCESS|BOTACCESS> <json>
            if len(parts) < 4:
                log.warning(f"Malformed UPDATE from {from_bot}: {line_summary(line)}")
                return
            msg_id = parts[1]
            wire = parts[2].upper()
            entity = self._WIRE_ENTITIES.get(wire)
            if entity is None:
                log.warning(f"Unknown UPDATE entity '{wire}' from {from_bot}")
                return
            if not self._register_message(msg_id):
                return  # duplicate — drop silently
            if wire in self._WIRE_ACTION_ENTITIES:
                if len(parts) < 5:
                    log.warning(f"Malformed UPDATE from {from_bot}: {line_summary(line)}")
                    return
                action = parts[3].upper()
                raw = line.split(None, 4)[4]
            else:
                action = "ADD"
                raw = line.split(None, 3)[3]
            if action == "UPDATE":
                action = "ADD"
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, ValueError) as exc:
                log.error(f"Malformed UPDATE {wire} JSON from {from_bot}: {exc}")
                return
            # SAST-003: validate against the sender's share scope *before* any
            # local effect or relay; a denied update is neither applied nor relayed.
            await self._receive_replication(from_bot, entity, action, [payload], msg_id=msg_id)

        elif cmd == "SHARE":
            if len(parts) < 3:
                log.warning(f"Malformed SHARE from {from_bot}: {line_summary(line)}")
                return
            entity = self._SHARE_ENTITIES.get(parts[1].upper())
            if entity is None:
                log.warning(f"Unknown SHARE entity '{parts[1]}' from {from_bot}")
                return
            try:
                records = json.loads(line.split(None, 2)[2])
            except (json.JSONDecodeError, ValueError) as exc:
                log.error(f"Malformed SHARE {parts[1]} JSON from {from_bot}: {exc}")
                return
            if not isinstance(records, list):
                log.warning(f"SHARE {parts[1]} from {from_bot} is not a list")
                return
            # Bulk shares are applied locally only, never relayed.
            await self._receive_replication(from_bot, entity, "ADD", records)

        elif cmd == "TOPOLOGY":
            # TOPOLOGY <msg_id> <source_bot> <peer1> [peer2 ...]
            if len(parts) < 3:
                log.warning("Malformed TOPOLOGY from %s: %s", from_bot, line_summary(line))
                return

            msg_id     = parts[1]
            source_bot = parts[2].lower()
            peers_seen = [p.lower() for p in parts[3:]]

            if not self._register_message(msg_id):
                return  # duplicate — drop silently

            # Register all peers the source bot can directly see as indirect for us,
            # but only if we don't already have a direct link to them.
            for handle in peers_seen:
                if handle == self.my_handle.lower():
                    continue   # that's us
                if handle not in self.peers:
                    self.topology[handle] = source_bot   # reachable via source_bot
                else:
                    self.topology.pop(handle, None)      # we have direct — clean up any stale indirect entry

            # Flood-fill to our other peers
            relay_line = f"TOPOLOGY {msg_id} {source_bot} {' '.join(parts[3:])}\n"
            tasks = [
                self._safe_send(link.writer, relay_line)
                for name, link in self.peers.items()
                if link.authed and link.connected and link.writer
                and name != from_bot.lower()
            ]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        elif cmd in ('REQUEST_INVITE', 'REQUEST_UNBAN', 'REQUEST_LIMIT_RAISE'):
            channel = parts[1] if len(parts) > 1 else ''
            target  = parts[2] if len(parts) > 2 else ''
            # SAST-002: only a same-subnet peer may ask us to act, only for an
            # in-scope channel, and only on behalf of a same-subnet bot.
            if not await self.authorize_peer_command(from_bot, cmd.lower(), parts[1:]):
                return
            if not self.core.bot_isop(channel):
                return
            if cmd == 'REQUEST_INVITE':
                self.core.send_irc({'cmd': 'invite', 'target': target, 'channel': channel})
                log.info(f"[Botnet] Sent INVITE {target} to {channel}")
            elif cmd == 'REQUEST_UNBAN':
                # TODO: scan chan.bans for a mask matching target's nick/host
                self.core.send_irc({'cmd': 'mode', 'channel': channel,
                                    'modes': '-b', 'args': target})
                log.info(f"[Botnet] Sent unban for {target} in {channel}")
            else:
                chan = self.core.channels.get(channel)
                new_limit = (chan.limit if chan else 0) + 10
                self.core.send_irc({'cmd': 'mode', 'channel': channel,
                                    'modes': '+l', 'args': str(new_limit)})
                log.info(f"[Botnet] Raised limit in {channel} to {new_limit}")

        else:
            log.error(f"Invalid command {cmd} from {from_bot}")
    
    async def _safe_send(self, writer: asyncio.StreamWriter, msg: str):
        """Send with error handling."""
        try:
            if writer is None or writer.is_closing():
                log.error("Send failed: writer already closing")
                return
            writer.write(msg.encode())
            await writer.drain()
        except Exception as e:
            log.error(f"Send failed: {e}")

    def register(self, plugin: str, name: str, handler: Callable):
        key = BotCommand(name.lower(), plugin.lower())
        if key in self.cmds:
            log.warning(f"Skipping duplicate {plugin}:{name} (existing)")
            return
        self.cmds[key] = handler
        #log.info(f"Registered {plugin}:{name}")

    async def dispatch(self, plugin: str, name: str, **kwargs):
        """Find handler, pass cmd_key + kwargs."""
        key = BotCommand(name.lower(), plugin.lower())
        handler = self.cmds.get(key)
        if handler:
            await handler(key, **kwargs)
        else:
            log.warning(f"No handler for {plugin}:{name}")

    def unregister(self, plugin: str, name: str):
        """Unregister handler."""
        key = BotCommand(plugin.lower(), name.lower())
        if key in self.cmds:
            del self.cmds[key]
            log.info(f"Unregistered {plugin}:{name}")
            return True
        log.warning(f"No handler for {plugin}:{name}")
        return False

    def unregister_plugin(self, plugin: str):
        """Unregister all handlers for plugin."""
        removed = 0
        to_remove = [k for k in self.cmds if k.plugin == plugin.lower()]
        for key in to_remove:
            del self.cmds[key]
            removed += 1
        log.info(f"Unregistered {removed} cmds for {plugin}")
        return removed            

    async def check_clock_skew(self, peer_timestamp: int, peer_name: str) -> bool:
        """
        Called during handshake. Returns False if skew is unacceptable.
        Caller must abort the link if False is returned.
        """
        skew = abs(int(time.time()) - peer_timestamp)
        self._peer_skew[peer_name] = skew
        if skew > CLOCK_SKEW_WARN_SECONDS:
            log.error(
                "Rejecting link from %s: clock skew is %ds (max %ds). "
                "Ensure NTP is running on both hosts.",
                peer_name, skew, CLOCK_SKEW_WARN_SECONDS
            )
            return False
        if skew > 0:
            log.debug("Clock skew with %s: %ds (acceptable)", peer_name, skew)
        return True

    async def broadcast_chat(self, nick: str, msg: str, exclude: set[str] | None = None) -> None:
        """
        Broadcast a partyline chat message to every bot in the network.

        Flood-fills via CHAT_ROUTE. Each hop relays to its own peers.
        Loop prevention via msg_id stops cycles.

        Args:
            nick:    The handle/nick of the user who sent the message.
            msg:     The chat message text.
            exclude: Peer handles to skip (e.g. the peer this came from).
        """
        msg_id = str(uuid.uuid4())
        line   = f"CHAT_ROUTE {msg_id} {self.my_handle} {nick} :{msg}\n"
        tasks  = [
            self._safe_send(link.writer, line)
            for name, link in self.peers.items()
            if link.authed and link.connected and link.writer
            and name not in (exclude or set())
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_all(self, command: str, args: str = "") -> None:
        """
        Send a command to every bot in the network, directly linked or not.

        Flood-fills via CMD_ROUTE broadcast. Each hop relays to its own
        peers. Loop prevention via msg_id stops cycles.

        Args:
            command: Command name.
            args:    Command arguments as a string.
        """
        msg_id = str(uuid.uuid4())
        line   = f"CMD_ROUTE broadcast {msg_id} {self.my_handle} - {command} {args}\n"
        tasks  = [
            self._safe_send(link.writer, line)
            for link in self.peers.values()
            if link.authed and link.connected and link.writer
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


    async def broadcast_subnet(self, command: str, args: str = "", subnet_id: int | None = None) -> None:
        """
        Send a command to all bots on a specific subnet, directly linked or not.

        Uses CMD_ROUTE with routing=subnet so intermediate bots only relay
        to peers that belong to the same subnet.

        Args:
            command:   Command name.
            args:      Command arguments as a string.
            subnet_id: Target subnet. Defaults to this bot's own subnet.
        """
        sid    = subnet_id if subnet_id is not None else self.subnet_id
        msg_id = str(uuid.uuid4())
        line   = f"CMD_ROUTE subnet {msg_id} {self.my_handle} - {sid} {command} {args}\n"
        tasks  = [
            self._safe_send(link.writer, line)
            for link in self.peers.values()
            if link.authed and link.connected and link.writer
            and sid in link.subnet_ids
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


    async def unicast(self, target: str, command: str, args: str = "") -> None:
        """
        Send a command to one specific bot anywhere in the network.

        Flood-fills via CMD_ROUTE unicast. Only the named target executes
        it; intermediate bots relay silently. No routing table required.

        Args:
            target:  Destination bot handle.
            command: Command name.
            args:    Command arguments as a string.
        """
        msg_id = str(uuid.uuid4())
        line   = f"CMD_ROUTE unicast {msg_id} {self.my_handle} {target} {command} {args}\n"
        tasks  = [
            self._safe_send(link.writer, line)
            for link in self.peers.values()
            if link.authed and link.connected and link.writer
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ------------------------------------------------------------------
    # Replication (SHARE on link-up, UPDATE for changes) — SAST-003
    #
    # Every record in either direction goes through self.policy
    # (share.ReplicationPolicy): the link's share scope comes from the peer's
    # stored share_level and stored subnet scope, never from the peer.
    # Inbound records are validated before they are applied or relayed, and
    # a relayed update is re-validated against each destination's own scope
    # and re-serialised from the sanitised record (never forwarded verbatim).
    # ------------------------------------------------------------------
    _WIRE_ENTITIES = {
        "CHANNEL": "channels", "USER": "users", "BOT": "bots",
        "USERACCESS": "useraccess", "BOTACCESS": "botaccess",
    }
    _WIRE_ACTION_ENTITIES = frozenset({"CHANNEL", "USER", "BOT"})
    _ENTITY_WIRE = {v: k for k, v in _WIRE_ENTITIES.items()}
    _SHARE_ENTITIES = {
        "SUBNETS": "subnets", "CHANNELS": "channels", "BOTS": "bots",
        "BOTACCESS": "botaccess", "USERS": "users", "USERACCESS": "useraccess",
    }
    # Dependency order for a full share: subnets and channels first (they
    # define ownership), then bots, access rows (which create inert users),
    # then user records.
    _SHARE_ORDER = (
        ("SUBNETS", "subnets"), ("CHANNELS", "channels"), ("BOTS", "bots"),
        ("BOTACCESS", "botaccess"), ("USERACCESS", "useraccess"), ("USERS", "users"),
    )

    def _replication_links(self, exclude: set[str] | None = None) -> list[tuple[str, BotLink]]:
        return [
            (name, link) for name, link in self.peers.items()
            if link.authed and link.connected and link.writer and link.state == 'ready'
            and name not in (exclude or set())
        ]

    async def _revoke_inactive_sessions(self, recs: list[dict]) -> None:
        """A replicated lock/delete ends the user's open local sessions (SAST-004)."""
        partyline = getattr(self.core, 'partyline', None)
        revoke = getattr(partyline, 'revoke_handle', None)
        if not callable(revoke):
            return
        for r in recs:
            handle = await self.user.resolve_handle(str(r.get("handle") or ""))
            if handle and not await self.user.is_active(handle):
                revoke(handle, "your account was locked or deleted")

    async def _apply_replication(self, entity: str, action: str, recs: list[dict],
                                 from_bot: str) -> None:
        if entity == "subnets":
            await self.subnet.merge_from_peer(recs, from_bot)
        elif entity == "channels":
            if action == "DEL":
                for r in recs:
                    await self.chan.delete_from_peer(r, from_bot)
            else:
                await self.chan.merge_from_peer(recs, from_bot)
        elif entity == "users":
            if action == "DEL":
                for r in recs:
                    await self.user.delete_from_peer(r, from_bot)
            else:
                await self.user.merge_from_peer(recs, from_bot)
            await self._revoke_inactive_sessions(recs)
        elif entity == "useraccess":
            await self.user.merge_access_from_peer(recs, from_bot)
        elif entity == "bots":
            if action == "DEL":
                for r in recs:
                    await self.bot.delete_from_peer(r, from_bot)
            else:
                await self.bot.merge_from_peer(recs, from_bot)
        elif entity == "botaccess":
            await self.bot.merge_access_from_peer(recs, from_bot)

    async def _receive_replication(self, from_bot: str, entity: str, action: str,
                                   records: list, msg_id: str | None = None) -> list[dict]:
        """Validate, apply and (for UPDATE, msg_id set) relay replicated records from a peer."""
        link = self._live_link(from_bot)
        scope = await self._share_target_scope(link, "in") if link is not None else frozenset()
        if not scope:
            log.warning("Denied %s %s from %s: no share scope (share=%s, subnets %s)",
                        entity, action, from_bot, link.share_level if link else None,
                        sorted(link.subnet_ids) if link else [])
            return []
        clean = await self.policy.inbound(entity, action, records, from_bot, scope)
        if not clean:
            return []
        relay: list[tuple[BotLink, list[dict]]] = []
        if msg_id is not None and action == "DEL":
            # Ownership must be resolved before the delete lands.
            relay = await self._relay_targets(entity, action, clean, {from_bot.lower()})
        try:
            await self._apply_replication(entity, action, clean, from_bot)
        except Exception as exc:
            log.error("Failed to apply %s %s from %s: %s", entity, action, from_bot, exc)
            return []
        if msg_id is not None:
            if action != "DEL":
                relay = await self._relay_targets(entity, action, clean, {from_bot.lower()})
            await self._send_updates(relay, entity, action, msg_id)
        return clean

    async def _relay_targets(self, entity: str, action: str, records: list[dict],
                             exclude: set[str]) -> list[tuple[BotLink, list[dict]]]:
        targets = []
        for name, link in self._replication_links(exclude):
            # Resolved by live link identity each time, never a cached row (NET-4).
            scope = await self._share_target_scope(link, "out")
            if not scope:
                continue
            out = await self.policy.outbound(entity, action, records, link.name, scope)
            if out:
                targets.append((link, out))
        return targets

    async def _send_updates(self, targets: list[tuple[BotLink, list[dict]]], entity: str,
                            action: str, msg_id: str) -> None:
        wire = self._ENTITY_WIRE[entity]
        head = f"UPDATE {msg_id} {wire} {action}" if wire in self._WIRE_ACTION_ENTITIES \
            else f"UPDATE {msg_id} {wire}"
        tasks = [
            self._safe_send(link.writer, f"{head} {json.dumps(rec)}\n")
            for link, recs in targets for rec in recs
        ]
        for link, recs in targets:
            log.info("replication out: %s %s to %s: %d record(s)",
                     entity, action, link.name, len(recs))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def replicate(self, entity: str, action: str, records: list[dict],
                        exclude: set[str] | None = None) -> None:
        """Send locally originated changes to every peer allowed to receive them."""
        msg_id = str(uuid.uuid4())
        self._register_message(msg_id)
        targets = await self._relay_targets(entity, action, records, exclude or set())
        await self._send_updates(targets, entity, action, msg_id)

    async def share_all_data(self, target_bot: str):
        """Full data share on link-up, limited to the link's share scope (SAST-003)."""
        link = self._live_link(target_bot)
        scope = await self._share_target_scope(link, "out")
        if not scope:
            return
        for wire, entity in self._SHARE_ORDER:
            await self._share_entity(link, wire, entity, scope)

    async def _share_candidates(self, entity: str, link: BotLink) -> list[dict]:
        if entity == "subnets":
            return await self.subnet.serialize_for_peer('full')
        if entity == "channels":
            return await self.chan.serialize_for_peer()
        if entity == "bots":
            return await self.bot.serialize_for_peer(link.name)
        if entity == "botaccess":
            return await self.bot.serialize_access_for_peer()
        if entity == "users":
            return await self.user.serialize_for_peer()
        if entity == "useraccess":
            return await self.user.serialize_access_for_peer()
        return []

    async def _share_entity(self, link: BotLink, wire: str, entity: str,
                            scope: frozenset[int]) -> None:
        records = await self.policy.outbound(
            entity, "ADD", await self._share_candidates(entity, link), link.name, scope)
        if records:
            await self._safe_send(link.writer, f"SHARE {wire} {json.dumps(records)}\n")

    # Per-entity share helpers kept for callers/plugins; all are scope-filtered.
    async def share_users(self, link: BotLink):
        await self._share_entity(link, "USERS", "users", self.share_scope(link))

    async def share_user_access(self, link: BotLink):
        await self._share_entity(link, "USERACCESS", "useraccess", self.share_scope(link))

    async def share_channels(self, link: BotLink):
        await self._share_entity(link, "CHANNELS", "channels", self.share_scope(link))

    async def share_bots(self, link: BotLink, exclude_bot: str | None = None):
        await self._share_entity(link, "BOTS", "bots", self.share_scope(link))

    async def share_bot_access(self, link: BotLink):
        await self._share_entity(link, "BOTACCESS", "botaccess", self.share_scope(link))

    async def share_subnets(self, link: BotLink):
        await self._share_entity(link, "SUBNETS", "subnets", self.share_scope(link))

    async def handle_share_subnets(self, data: str, from_bot: str):
        await self._receive_replication(from_bot, "subnets", "ADD", json.loads(data))

    async def handle_share_users(self, data: str, from_bot: str) -> None:
        await self._receive_replication(from_bot, "users", "ADD", json.loads(data))

    async def handle_share_user_access(self, data: str, from_bot: str) -> None:
        await self._receive_replication(from_bot, "useraccess", "ADD", json.loads(data))

    async def handle_share_bots(self, data: str, from_bot: str) -> None:
        await self._receive_replication(from_bot, "bots", "ADD", json.loads(data))

    async def handle_share_bot_access(self, data: str, from_bot: str) -> None:
        await self._receive_replication(from_bot, "botaccess", "ADD", json.loads(data))

    async def handle_share_channels(self, data: str, from_bot: str) -> None:
        await self._receive_replication(from_bot, "channels", "ADD", json.loads(data))

    # -- locally originated changes (called from commands.py) -------------
    # The command payloads only name the entity; the authoritative current
    # record is re-read from the local DB and then scope-filtered per peer.
    @staticmethod
    def _action(action: str) -> str:
        action = (action or "ADD").upper()
        return "ADD" if action == "UPDATE" else action

    async def sync_channel(self, action: str, channel_data: dict) -> None:
        """Replicate a channel add/update/delete to peers allowed to receive it."""
        name = str(channel_data.get("name") or "").lower()
        recs = [c for c in await self.chan.serialize_for_peer()
                if str(c.get("name", "")).lower() == name]
        if recs:
            await self.replicate("channels", self._action(action), recs)

    async def sync_user(self, action: str, user_data: dict) -> None:
        """Replicate a user add/update/delete (plus its in-scope access rows)."""
        handle = str(user_data.get("handle") or "").lower()
        action = self._action(action)
        if action == "ADD":
            await self.sync_user_access({"handle": handle})
        recs = [u for u in await self.user.serialize_for_peer()
                if str(u.get("handle", "")).lower() == handle]
        if recs:
            await self.replicate("users", action, recs)

    async def sync_bot(self, action: str, bot_data: dict) -> None:
        """Replicate a bot add/update to peers allowed to receive it.

        Locally deleted bots are hard-deleted (BotManager.delbot), so their
        ownership can no longer be proven and deletes are not replicated.
        """
        handle = str(bot_data.get("handle") or "").lower()
        action = self._action(action)
        if action == "DEL":
            log.info("sync_bot: bot deletes are not replicated (%s)", handle)
            return
        recs = [b for b in await self.bot.serialize_for_peer(self.my_handle)
                if str(b.get("handle", "")).lower() == handle]
        if recs:
            await self.replicate("bots", action, recs)

    async def sync_user_access(self, access_data: dict) -> None:
        """Replicate a user's access rows (optionally one channel) to allowed peers."""
        handle = str(access_data.get("handle") or "").lower()
        chan = access_data.get("channel")
        recs = [a for a in await self.user.serialize_access_for_peer()
                if str(a.get("handle", "")).lower() == handle
                and (chan is None or (a.get("channel") or "").lower() == str(chan).lower())]
        if recs:
            await self.replicate("useraccess", "ADD", recs)

    async def sync_bot_access(self, access_data: dict) -> None:
        """Replicate a bot's record and access rows to allowed peers (after .botattr)."""
        handle = str(access_data.get("handle") or "").lower()
        await self.sync_bot("ADD", {"handle": handle})
        recs = [a for a in await self.bot.serialize_access_for_peer()
                if str(a.get("handle", "")).lower() == handle]
        if recs:
            await self.replicate("botaccess", "ADD", recs)

    def _register_message(self, msg_id: str) -> bool:
        """
        Deduplication guard for flood-fill routing.

        Returns True if msg_id is new (caller should process + relay).
        Returns False if msg_id was already seen (caller should drop silently).

        Uses an OrderedDict as a bounded FIFO cache keyed by msg_id.
        Entries expire after MSG_TTL seconds; cache is also capped at
        MAX_MSG_CACHE_SIZE to bound memory under flood conditions.
        """
        now = time.monotonic()

        # Already seen — drop
        if msg_id in self._msg_cache:
            return False

        # Evict expired entries from the front (oldest inserted first)
        while self._msg_cache:
            oldest_id, oldest_ts = next(iter(self._msg_cache.items()))
            if now - oldest_ts > MSG_TTL:
                self._msg_cache.popitem(last=False)
            else:
                break  # remaining entries are newer

        # Hard cap: if still over limit, evict oldest regardless of age
        while len(self._msg_cache) >= MAX_MSG_CACHE_SIZE:
            self._msg_cache.popitem(last=False)

        # Register new message
        self._msg_cache[msg_id] = now
        return True
    
    async def broadcast_topology(self) -> None:
        """
        Announce our directly-linked peers to the network so all bots
        can build an indirect-link map for display and unicast routing.
        """
        direct = [
            name for name, link in self.peers.items()
            if link.authed and link.connected
        ]
        if not direct:
            return
        msg_id = str(uuid.uuid4())
        peer_list = " ".join(direct)
        line = f"TOPOLOGY {msg_id} {self.my_handle} {peer_list}\n"
        tasks = [
            self._safe_send(link.writer, line)
            for link in self.peers.values()
            if link.authed and link.connected and link.writer
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)    

    def _register_net_handlers(self) -> None:
        """
        Register handlers for commands dispatched via .net (CMD_ROUTE).
        Each handler receives (cmd_key, args_list, from_bot) and executes
        the action locally on this bot using the IRC queue.
        """
        net_cmds = {
            'join':    self._net_join,
            'part':    self._net_part,
            'say':     self._net_say,
            'msg':     self._net_say,
            'op':      self._net_op,
            'deop':    self._net_deop,
            'mode':    self._net_mode,
            'restart': self._net_restart,
            'die':     self._net_die,
        }
        for name, handler in net_cmds.items():
            self.register('net', name, handler)

    async def _net_join(self, cmd_key, args, from_bot):
        """CMD_ROUTE join #channel"""
        if not args:
            return
        channel = args[0] if isinstance(args, list) else args.split()[0]
        self.core.send_irc({'cmd': 'join', 'channel': channel})
        log.info("net join %s (from %s)", channel, from_bot)

    async def _net_part(self, cmd_key, args, from_bot):
        """CMD_ROUTE part #channel [reason]"""
        parts = args if isinstance(args, list) else args.split()
        if not parts:
            return
        channel = parts[0]
        reason  = ' '.join(parts[1:]) if len(parts) > 1 else ''
        self.core.send_irc({'cmd': 'part', 'channel': channel, 'reason': reason})
        log.info("net part %s (from %s)", channel, from_bot)

    async def _net_say(self, cmd_key, args, from_bot):
        """CMD_ROUTE say|msg #target message text"""
        parts = args if isinstance(args, list) else args.split()
        if len(parts) < 2:
            return
        target = parts[0]
        text   = ' '.join(parts[1:])
        self.core.send_irc({'cmd': 'msg', 'target': target, 'text': text})
        log.info("net say %s (from %s)", target, from_bot)

    async def _net_op(self, cmd_key, args, from_bot):
        """CMD_ROUTE op nick #channel"""
        parts = args if isinstance(args, list) else args.split()
        if len(parts) < 2:
            return
        nick, chan = parts[0], parts[1]
        self.core.send_irc({'cmd': 'mode', 'channel': chan, 'modes': f'+o {nick}'})
        log.info("net op %s on %s (from %s)", nick, chan, from_bot)

    async def _net_deop(self, cmd_key, args, from_bot):
        """CMD_ROUTE deop nick #channel"""
        parts = args if isinstance(args, list) else args.split()
        if len(parts) < 2:
            return
        nick, chan = parts[0], parts[1]
        self.core.send_irc({'cmd': 'mode', 'channel': chan, 'modes': f'-o {nick}'})
        log.info("net deop %s on %s (from %s)", nick, chan, from_bot)

    async def _net_mode(self, cmd_key, args, from_bot):
        """CMD_ROUTE mode #channel +modes"""
        parts = args if isinstance(args, list) else args.split()
        if len(parts) < 2:
            return
        chan  = parts[0]
        modes = ' '.join(parts[1:])
        self.core.send_irc({'cmd': 'mode', 'channel': chan, 'modes': modes})
        log.info("net mode %s %s (from %s)", chan, modes, from_bot)

    async def _net_restart(self, cmd_key, args, from_bot):
        """CMD_ROUTE restart"""
        log.info("net restart triggered by %s", from_bot)
        await self.core.shutdown("Restart via botnet")

    async def _net_die(self, cmd_key, args, from_bot):
        """CMD_ROUTE die [message]"""
        msg = ' '.join(args) if isinstance(args, list) else args
        log.info("net die triggered by %s: %s", from_bot, msg)
        self.core.send_irc({'cmd': 'quit', 'message': msg or 'Killed via botnet'})                 