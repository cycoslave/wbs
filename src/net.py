# src/net.py
"""
WBS network listener + connection admission control.
"""
import asyncio
import fnmatch
import ipaddress
import json
import logging
import multiprocessing as mp
import re
import socket
import ssl as ssl_lib
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from .db import get_db
from .logsafe import line_summary, safe
from .user import UserManager
from .subnet import local_subnet_id, botnet_listen

log = logging.getLogger("wbs.net")
PER_IP_MAX = 3
_HANDLE_MAX_LEN  = 64
_HANDLE_RE       = re.compile(r"^[A-Za-z0-9_\-\.]{1,64}$")
_LINE_MAX_BYTES  = 512
_PASSWORD_MAX    = 256        # longer answers are refused unchecked (as DCC)
_HTTP_METHODS    = ("GET ", "POST ", "HEAD ", "OPTIONS ", "PUT ", "DELETE ")


class _FramingError(Exception):
    """Handshake line was oversized, unterminated at EOF, or not UTF-8."""


async def _read_handshake_line(reader: asyncio.StreamReader, timeout: float,
                               max_bytes: int = _LINE_MAX_BYTES) -> str:
    """
    Read exactly one '\\n'-terminated handshake line (SAST-011).

    Framing is done by the StreamReader itself (readuntil), so a line split
    over several TCP segments is reassembled and anything the peer sent after
    the line (a coalesced password, the first botlink frame, early partyline
    input) stays buffered in `reader` for the next consumer instead of being
    discarded.  Lines longer than `max_bytes` are rejected; the StreamReader
    limit bounds memory while waiting for a separator.

    Raises asyncio.TimeoutError, or _FramingError on EOF / oversize / bad UTF-8.
    The returned line has its trailing CR/LF removed and nothing else.
    """
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\n"), timeout)
    except asyncio.IncompleteReadError as e:
        raise _FramingError("connection closed before end of line") from e
    except asyncio.LimitOverrunError as e:
        raise _FramingError("line exceeds stream limit") from e
    if len(data) > max_bytes:
        raise _FramingError(f"line too long ({len(data)} bytes)")
    try:
        return data.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as e:
        raise _FramingError("line is not valid UTF-8") from e


# ---------------------------------------------------------------------------
# Host masks of the net blocklist (USR-12)
#
# A net_blocklist row's `ip` column holds a host mask: an IP address, a CIDR
# network, or a case-insensitive glob (* and ?) over a hostname or IP
# (`*.example.net`, `10.0.*`).  `*!*@host` / `*@host` are accepted on input
# and stored as `host`.  reason='permit' rows are exceptions created by
# .permithost; reason='auth_failure' rows are AccessGuard's automatic
# failure bans, which a permit never overrides.
# ---------------------------------------------------------------------------
PERMIT_REASON    = "permit"
AUTO_BAN_REASON  = "auth_failure"
_HOST_MASK_MAX   = 255
_HOST_GLOB_RE    = re.compile(r"^[A-Za-z0-9.\-:_*?]+\Z", re.ASCII)
HOST_MASK_RULE_TEXT = ("Invalid host mask. Use an IP (1.2.3.4), a CIDR network "
                       "(10.0.0.0/8), or a host glob (*.example.net, 10.0.*); "
                       "*!*@host is accepted too.")


def _as_ip(text) -> Optional[ipaddress._BaseAddress]:
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _as_network(mask: str) -> Optional[ipaddress._BaseNetwork]:
    try:
        return ipaddress.ip_network(mask, strict=False)
    except ValueError:
        return None


def normalize_host_mask(text) -> Optional[str]:
    """Canonical blocklist mask for `text`, or None when it is not valid."""
    if not isinstance(text, str):
        return None
    mask = text.strip()
    if "@" in mask or "!" in mask:
        head, at, host = mask.rpartition("@")
        parts = head.split("!") if at else []
        # Only the host can be denied: nick/ident must be pure wildcards.
        if not at or len(parts) > 2 or any(not p or p.strip("*") for p in parts):
            return None
        mask = host
    if not mask or len(mask) > _HOST_MASK_MAX:
        return None
    addr = _as_ip(mask)
    if addr is not None:
        return str(addr)
    if "/" in mask:
        net = _as_network(mask)
        if net is None or net.prefixlen == 0:
            return None            # /0 would deny every address
        return str(net.network_address) if net.num_addresses == 1 else str(net)
    if not _HOST_GLOB_RE.match(mask) or not any(c.isalnum() for c in mask):
        return None                # also refuses all-wildcard masks (*, *.*)
    return mask.lower()


def _irc_glob(pattern: str, text: str) -> bool:
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, text, re.IGNORECASE | re.DOTALL) is not None


def host_mask_matches(mask: str, ip: Optional[str] = None,
                      host: Optional[str] = None) -> bool:
    """Does blocklist `mask` cover a peer with address `ip` / name `host`?"""
    net = _as_network(mask)
    if net is not None:
        addrs = [a for a in (_as_ip(ip), _as_ip(host)) if a is not None]
        return any(a.version == net.version and a in net for a in addrs)
    return any(_irc_glob(mask, v) for v in (ip, host) if v)


def host_masks_overlap(a: str, b: str) -> bool:
    """Can some peer be matched by both masks?  (Used by .permithost.)"""
    na, nb = _as_network(a), _as_network(b)
    if na is not None and nb is not None:
        return na.version == nb.version and na.overlaps(nb)
    if nb is not None and nb.num_addresses == 1:
        return host_mask_matches(a, ip=str(nb.network_address))
    if na is not None and na.num_addresses == 1:
        return host_mask_matches(b, ip=str(na.network_address))
    return _irc_glob(a, b) or _irc_glob(b, a)


def _is_name_glob(mask: str) -> bool:
    """A mask that can only match a reverse-DNS name (needs a PTR lookup)."""
    return _as_network(mask) is None and ":" not in mask and any(c.isalpha() for c in mask)


@dataclass
class _BlockEntry:
    ip:         str
    reason:     str  = "manual"
    added_by:   str  = "system"
    added_at:   int  = field(default_factory=lambda: int(time.time()))
    expires_at: int  = 0              # 0 = permanent
    note:       str  = ""

    def is_expired(self) -> bool:
        return self.expires_at != 0 and time.time() > self.expires_at

@dataclass
class _FailureRecord:
    count:    int   = 0
    first_at: float = field(default_factory=time.time)
    last_at:  float = field(default_factory=time.time)

class AccessGuard:
    """
    IP-level admission controller for the partyline / botlink listener.

    Modes (config['partyline']['access_mode']):

      blacklist (default)
        All IPs allowed unless explicitly blocked.
        Auto-blocks after max_failures failed auth attempts.
        Operators can manually add/remove entries via partyline commands.

      whitelist
        Only IPs that match a known hostmask (by IP or reverse-hostname)
        in the users or bots table are admitted.  Everything else is dropped
        at TCP accept time before any data is read.
        Auto-block on auth failure still applies.

    Blocklist entries are persisted to `net_blocklist` so bans
    survive restarts.  In-memory dict is the hot path for every decision.

    Auth failure counts are also persisted so counter survives restarts.
    """

    def __init__(self, db_path: str, config: dict) -> None:
        self.db_path = db_path
        cfg = config.get("settings", config)
        self.mode            = cfg.get("access_mode", "blacklist").lower()
        self.max_failures    = int(cfg.get("max_failures", 5))
        # NET-13: botlink failures are counted per (ip, claimed handle) and
        # lock that pair at max_failures; the address as a whole is auto-
        # blocked only at the higher max_failures_ip.  One rogue BOTLINK claim
        # from a shared address (127.0.0.1 hosts every local bot) therefore
        # cannot lock out the other bots there.
        self.max_failures_ip = max(self.max_failures,
                                   int(cfg.get("max_failures_ip", self.max_failures * 4)))
        self.lockout_seconds = int(cfg.get("lockout_seconds", 300))
        self.max_connections = int(cfg.get("max_connections", 50))
        self._blocklist: dict[str, _BlockEntry]    = {}   # ip → entry
        self._failures:  dict[str, _FailureRecord] = {}   # ip → record (per-IP total)
        self._handle_failures: dict[tuple[str, str], _FailureRecord] = {}   # (ip, handle) → record
        # Set by Core: live_peer_check(ip, handle=None) -> True while an
        # authenticated botnet link from that address (and handle) is up.
        self.live_peer_check: Optional[Callable[[str, Optional[str]], bool]] = None
        self._active:    dict[str, int]            = {}   # ip → open conn count
        self._loaded = False

    async def load(self) -> None:
        """Load persisted blocklist and failure counts from DB.  Call once at startup."""
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT ip, reason, added_by, added_at, expires_at, note "
                "FROM net_blocklist"
            )
        now   = int(time.time())
        count = 0
        for row in rows:
            entry = _BlockEntry(
                ip=row["ip"], reason=row["reason"],
                added_by=row["added_by"], added_at=row["added_at"],
                expires_at=row["expires_at"], note=row["note"],
            )
            if entry.expires_at == 0 or entry.expires_at > now:
                self._blocklist[row["ip"]] = entry
                count += 1

        async with get_db(self.db_path) as db:
            fail_rows = await db.execute_fetchall(
                "SELECT ip, count, first_at, last_at FROM net_auth_failures"
            )
        for row in fail_rows:
            self._failures[row["ip"]] = _FailureRecord(
                count=row["count"],
                first_at=row["first_at"],
                last_at=row["last_at"],
            )

        async with get_db(self.db_path) as db:
            hrows = await db.execute_fetchall(
                "SELECT ip, handle, count, first_at, last_at FROM net_handle_failures"
            )
        for row in hrows:
            self._handle_failures[(row["ip"], row["handle"])] = _FailureRecord(
                count=row["count"], first_at=row["first_at"], last_at=row["last_at"])

        self._loaded = True
        log.info(
            "AccessGuard: loaded %d blocklist entries, %d failure records (mode=%s)",
            count, len(self._failures), self.mode,
        )

    async def admit(self, ip: str) -> tuple[bool, str]:
        """
        Called at TCP accept time — before any data is read.
        Returns (allowed, reason_string).
        """
        if not self._loaded:
            await self.load()

        # Cheap early deny; repeated below after the awaits (SAST-012).
        if not self._has_capacity(ip):
            return False, "Connection refused"

        # Denied host masks / IPs (USR-12) and automatic failure bans, before
        # a single byte is read.  Name masks see the reverse-DNS name; a
        # permit is matched on the address only (PTR is attacker-controlled).
        ptr = await self._reverse_name(ip) if self._needs_ptr() else None
        entry = await self.denied_by(ip=ip, host=ptr, host_trusted=False)
        if (entry is not None and entry.reason == AUTO_BAN_REASON
                and self._has_live_peer(ip)):
            # An automatic failure ban never cuts off an address that
            # currently hosts an authenticated peer (NET-13).
            log.info("AccessGuard: ignoring failure ban %s for %s: an authenticated "
                     "botnet peer is linked from that address", entry.ip, ip)
            entry = None
        if entry is not None:
            log.warning("AccessGuard: DENY %s%s — blocklisted by %s (%s%s)",
                        ip, f" ({ptr})" if ptr else "", entry.ip, entry.reason,
                        f": {entry.note}" if entry.note else "")
            return False, "Connection refused"

        if self.mode == "whitelist":
            if not await self._whitelist_check(ip):
                log.warning("AccessGuard: DENY %s — not in whitelist", ip)
                return False, "Connection refused"

        # Check-and-take with no await in between: concurrent admits that
        # all passed the early check while blocklist/whitelist I/O was in
        # flight cannot together exceed the per-IP or global cap.
        if not self._has_capacity(ip):
            return False, "Connection refused"
        self._active[ip] = self._active.get(ip, 0) + 1
        return True, "ok"

    def _has_capacity(self, ip: str) -> bool:
        if self._active.get(ip, 0) >= PER_IP_MAX:
            log.warning("AccessGuard: DENY %s — per-IP limit (%d)", ip, PER_IP_MAX)
            return False
        if sum(self._active.values()) >= self.max_connections:
            log.warning("AccessGuard: DENY %s — global limit (%d)", ip, self.max_connections)
            return False
        return True

    def active_count(self, ip: Optional[str] = None) -> int:
        """Open admitted connections, for one IP or in total."""
        if ip is not None:
            return self._active.get(ip, 0)
        return sum(self._active.values())

    def release(self, ip: str) -> None:
        """Decrement active connection count.  Call when any connection closes."""
        if ip in self._active:
            self._active[ip] = max(0, self._active[ip] - 1)
            if self._active[ip] == 0:
                del self._active[ip]

    # -- botlink failure accounting (NET-13) -----------------------------
    _HANDLE_KEY_MAX   = 64          # longest claimed handle remembered
    _HANDLE_TABLE_MAX = 4096        # bound on remembered (ip, handle) pairs

    def _has_live_peer(self, ip: str, handle: Optional[str] = None) -> bool:
        check = self.live_peer_check
        if check is None:
            return False
        try:
            return bool(check(ip, handle))
        except Exception as exc:
            log.debug("AccessGuard: live_peer_check failed: %s", exc)
            return False

    @classmethod
    def _hkey(cls, ip: str, handle: str) -> tuple[str, str]:
        return ip, (handle or "").lower()[:cls._HANDLE_KEY_MAX]

    def _handle_rec_live(self, rec: Optional[_FailureRecord]) -> bool:
        """A (ip, handle) record counts while inside the lockout window."""
        if rec is None:
            return False
        return self.lockout_seconds <= 0 or time.time() - rec.last_at < self.lockout_seconds

    def handle_locked(self, ip: str, handle: str) -> bool:
        """
        True while (ip, handle) has failed botlink auth max_failures times
        within the lockout window.  Only that pair is refused: other handles
        from the same address are unaffected, and a currently linked,
        authenticated peer is never locked out.
        """
        rec = self._handle_failures.get(self._hkey(ip, handle))
        if rec is None or rec.count < self.max_failures or not self._handle_rec_live(rec):
            return False
        return not self._has_live_peer(ip, handle)

    def _trim_handle_table(self) -> None:
        if len(self._handle_failures) <= self._HANDLE_TABLE_MAX:
            return
        for k in [k for k, r in self._handle_failures.items() if not self._handle_rec_live(r)]:
            self._handle_failures.pop(k, None)
        while len(self._handle_failures) > self._HANDLE_TABLE_MAX:
            oldest = min(self._handle_failures, key=lambda k: self._handle_failures[k].last_at)
            self._handle_failures.pop(oldest, None)

    async def record_failure(self, ip: str, handle: str = "", *, peer: bool = False) -> None:
        """
        Record a failed auth attempt; auto-block after threshold.

        peer=True (a BOTLINK handshake claiming `handle`): counted under
        (ip, handle), which is locked at max_failures, and under the ip,
        which is auto-blocked only at the higher max_failures_ip.  A failure
        claiming a currently linked authenticated peer from its own address
        is ignored, and an address with a linked authenticated peer is never
        auto-blocked.  peer=False (partyline login): per-IP, max_failures.
        """
        now = time.time()
        if peer and handle and self._has_live_peer(ip, handle):
            log.warning("AccessGuard: failed botlink claim of linked peer %r from %s "
                        "ignored (live authenticated link)", handle, ip)
            return

        hrec = None
        if peer:
            key  = self._hkey(ip, handle)
            hrec = self._handle_failures.get(key)
            if hrec is None or not self._handle_rec_live(hrec):
                hrec = self._handle_failures[key] = _FailureRecord(count=0, first_at=now, last_at=now)
            hrec.count  += 1
            hrec.last_at = now
            self._trim_handle_table()

        rec         = self._failures.setdefault(ip, _FailureRecord())
        rec.count  += 1
        rec.last_at = now
        limit       = self.max_failures_ip if peer else self.max_failures
        log.warning(
            "AccessGuard: auth failure from %s%s [%d/%d%s]",
            ip,
            f" (handle={handle!r})" if handle else "",
            rec.count, limit,
            f"; this handle {hrec.count}/{self.max_failures}" if hrec else "",
        )
        if hrec is not None and hrec.count == self.max_failures:
            log.warning("AccessGuard: %s claiming handle %r refused for %ss",
                        ip, handle, self.lockout_seconds or "ever")

        await self._persist_failure(ip, rec)
        if hrec is not None:
            await self._persist_handle_failure(key, hrec)

        if rec.count >= limit:
            if self._has_live_peer(ip):
                log.warning("AccessGuard: %s reached %d failures but an authenticated "
                            "botnet peer is linked from it; not blocking the address",
                            ip, rec.count)
                return
            expires = (int(time.time()) + self.lockout_seconds
                       if self.lockout_seconds > 0 else 0)
            await self.block(
                ip=ip, reason="auth_failure", added_by="system",
                expires_at=expires,
                note=f"Auto-blocked after {rec.count} failures"
                     + (f"; last handle: {handle}" if handle else ""),
            )
            # Only the address counter restarts.  The (ip, handle) records
            # stay until their own window expires (N-01): wiping them here
            # would let failures against other handles clear a handle's lock.
            self._failures.pop(ip, None)
            await self._delete_failure_record(ip)

    def record_success(self, ip: str, handle: str = "") -> None:
        """
        Clear the failure counters on successful auth: the address's, and
        (botlink, handle given) the (ip, handle) pair's.
        """
        self._failures.pop(ip, None)
        loop = asyncio.get_event_loop()
        # DB cleanup is fire-and-forget; schedule as a task so we stay sync here
        loop.create_task(self._delete_failure_record(ip))
        if handle:
            key = self._hkey(ip, handle)
            self._handle_failures.pop(key, None)
            loop.create_task(self._delete_handle_failure(*key))

    async def block(
        self,
        ip:         str,
        reason:     str = "manual",
        added_by:   str = "operator",
        expires_at: int = 0,
        note:       str = "",
    ) -> Optional[str]:
        """
        Deny a host mask (IP, CIDR or host glob; see normalize_host_mask)
        and persist it.  Returns the stored mask, or None if `ip` is not a
        valid mask.  A row with the same mask (e.g. a permit) is replaced.
        """
        mask = normalize_host_mask(ip)
        if mask is None:
            log.error("AccessGuard.block: invalid host mask %r", ip)
            return None
        cur = self._blocklist.get(mask)
        if (reason == AUTO_BAN_REASON and cur is not None
                and cur.reason == PERMIT_REASON and _as_network(mask) is not None):
            # Keep the operator's permit: the failure ban gets its own row
            # (the same address in /32 or /128 form) and still wins.
            mask = str(ipaddress.ip_network(mask, strict=False))
        entry = _BlockEntry(
            ip=mask, reason=reason, added_by=added_by,
            added_at=int(time.time()), expires_at=expires_at, note=note,
        )
        self._blocklist[mask] = entry
        await self._persist(entry)
        log.info(
            "AccessGuard: BLOCKED %s reason=%s expires=%s by=%s",
            mask, reason, expires_at or "never", added_by,
        )
        return mask

    async def unblock(self, ip: str, removed_by: str = "operator") -> bool:
        """Remove the exact mask from the blocklist.  True if it was present."""
        mask = normalize_host_mask(ip) or ip
        if mask not in self._blocklist:
            return False
        await self._remove_from_blocklist(mask, reason=f"removed by {removed_by}")
        return True

    async def permit(self, ip: str, added_by: str = "operator",
                     note: str = "") -> tuple[Optional[str], bool, bool]:
        """
        `.permithost`: lift a deny.  The exact mask's deny row (manual or an
        automatic failure ban) is removed.  If a wider *manual* deny still
        covers the mask, a permit row is stored so the mask is admitted
        despite it.  Automatic failure bans are never overridden by a permit:
        a host that keeps failing auth is banned again.

        Returns (mask, removed_exact_deny, permit_stored); mask is None when
        `ip` is not a valid host mask.
        """
        mask = normalize_host_mask(ip)
        if mask is None:
            return None, False, False
        await self._purge_expired()
        removed = False
        cur = self._blocklist.get(mask)
        if cur is not None and cur.reason != PERMIT_REASON:
            await self._remove_from_blocklist(mask, reason=f"permitted by {added_by}")
            removed = True
        net = _as_network(mask)
        alt = str(net) if net is not None and net.num_addresses == 1 else None
        if alt and alt != mask and alt in self._blocklist:
            # A failure ban stored next to an existing permit (see block()).
            await self._remove_from_blocklist(alt, reason=f"permitted by {added_by}")
            removed = True
        # An address permit also overrides host-name denies: whether the
        # address's reverse-DNS name matches them is only known at connect.
        covering = [e for e in self._blocklist.values()
                    if e.reason not in (PERMIT_REASON, AUTO_BAN_REASON)
                    and (host_masks_overlap(e.ip, mask)
                         or (net is not None and _is_name_glob(e.ip)))]
        stored = False
        if covering:
            await self.block(mask, reason=PERMIT_REASON, added_by=added_by,
                             note=note or "overrides " + ", ".join(e.ip for e in covering))
            stored = True
        elif cur is not None and cur.reason == PERMIT_REASON:
            stored = True              # an existing permit stays in force
        return mask, removed, stored

    def list_blocked(self) -> list[_BlockEntry]:
        """Return all non-expired blocklist entries (denies and permits)."""
        return [e for e in self._blocklist.values() if not e.is_expired()]

    async def _purge_expired(self) -> None:
        for mask in [m for m, e in self._blocklist.items() if e.is_expired()]:
            await self._remove_from_blocklist(mask, reason="expired")

    def _needs_ptr(self) -> bool:
        return any(e.reason != PERMIT_REASON and _is_name_glob(e.ip)
                   for e in self._blocklist.values())

    async def _reverse_name(self, ip: str, timeout: float = 3.0) -> Optional[str]:
        """PTR name of `ip`, or None (lookup failed / timed out)."""
        try:
            loop = asyncio.get_running_loop()
            res = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout)
            return res[0]
        except Exception:
            return None

    async def denied_by(self, ip: Optional[str] = None, host: Optional[str] = None,
                        host_trusted: bool = True) -> Optional[_BlockEntry]:
        """
        The blocklist entry that refuses a peer with address `ip` and/or
        host name `host`, or None if it is allowed.

          * automatic failure bans (reason auth_failure) always apply;
          * a manual deny applies unless a permit row also matches the peer;
          * permits match `ip`, and `host` only when `host_trusted` (an IRC
            server's view of the host); a reverse-DNS name is never trusted
            to grant a permit.
        Expired entries are dropped on the way.
        """
        if not self._loaded:
            await self.load()
        await self._purge_expired()
        permit_host = host if host_trusted else None
        permitted = None
        deny = None
        for entry in self._blocklist.values():
            if entry.reason == PERMIT_REASON:
                if permitted is None and host_mask_matches(entry.ip, ip=ip, host=permit_host):
                    permitted = entry
            elif host_mask_matches(entry.ip, ip=ip, host=host):
                if entry.reason == AUTO_BAN_REASON:
                    return entry
                deny = deny or entry
        if deny is not None and permitted is not None:
            log.info("AccessGuard: %s matches deny %s but is permitted by %s",
                     ip or host, deny.ip, permitted.ip)
            return None
        return deny

    async def _whitelist_check(self, ip: str) -> bool:
        """
        Check IP against known hostmasks in users + bots tables.

        Two-pass strategy (Issue #6):
          1. Direct IP match against CIDR ranges extracted from masks.
          2. Reverse-DNS hostname fnmatch (informational — PTR is attacker-
             controlled, so this pass alone is not authoritative).

        A connection is admitted only if at least the IP-based pass matches,
        OR both passes agree.  Pure PTR-only matches are logged but rejected.
        """
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            resolved_host = result[0]
        except (socket.herror, socket.gaierror):
            resolved_host = ip

        async with get_db(self.db_path) as db:
            user_rows = await db.execute_fetchall(
                "SELECT hostmasks FROM users WHERE deleted_at IS NULL"
            )
            bot_rows = await db.execute_fetchall(
                "SELECT hostmasks FROM bots"
            )

        ip_matched  = False
        ptr_matched = False

        try:
            check_ip = ipaddress.ip_address(ip)
        except ValueError:
            check_ip = None

        for row in (*user_rows, *bot_rows):
            raw = row["hostmasks"]
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except (ValueError, TypeError):
                parsed = [raw]
            for mask in parsed:
                host_part = mask.split("@")[-1] if "@" in mask else mask

                if check_ip is not None:
                    try:
                        net = ipaddress.ip_network(host_part, strict=False)
                        if check_ip in net:
                            ip_matched = True
                    except ValueError:
                        pass  # not a CIDR — fall through to fnmatch

                # PTR / wildcard fnmatch
                if fnmatch.fnmatch(resolved_host, host_part) or fnmatch.fnmatch(ip, host_part):
                    ptr_matched = True

        if ip_matched:
            return True
        if ptr_matched and not ip_matched:
            log.warning(
                "AccessGuard: whitelist PTR-only match for %s (resolved=%s) — REJECTED "
                "(PTR records are attacker-controlled; add a CIDR mask to allow this host)",
                ip, resolved_host,
            )
        return False

    async def _persist(self, entry: _BlockEntry) -> None:
        async with get_db(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO net_blocklist
                    (ip, reason, added_by, added_at, expires_at, note)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason     = excluded.reason,
                    added_by   = excluded.added_by,
                    added_at   = excluded.added_at,
                    expires_at = excluded.expires_at,
                    note       = excluded.note
                """,
                (entry.ip, entry.reason, entry.added_by,
                 entry.added_at, entry.expires_at, entry.note),
            )

    async def _remove_from_blocklist(self, ip: str, reason: str = "") -> None:
        self._blocklist.pop(ip, None)
        async with get_db(self.db_path) as db:
            await db.execute(
                "DELETE FROM net_blocklist WHERE ip = ?", (ip,)
            )
        log.info("AccessGuard: UNBLOCKED %s (%s)", ip, reason)

    async def _persist_failure(self, ip: str, rec: _FailureRecord) -> None:
        async with get_db(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO net_auth_failures (ip, count, first_at, last_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    count    = excluded.count,
                    last_at  = excluded.last_at
                """,
                (ip, rec.count, rec.first_at, rec.last_at),
            )

    async def _persist_handle_failure(self, key: tuple[str, str], rec: _FailureRecord) -> None:
        async with get_db(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO net_handle_failures (ip, handle, count, first_at, last_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip, handle) DO UPDATE SET
                    count    = excluded.count,
                    first_at = excluded.first_at,
                    last_at  = excluded.last_at
                """,
                (key[0], key[1], rec.count, rec.first_at, rec.last_at),
            )

    async def _delete_handle_failure(self, ip: str, handle: str) -> None:
        async with get_db(self.db_path) as db:
            await db.execute(
                "DELETE FROM net_handle_failures WHERE ip = ? AND handle = ?", (ip, handle)
            )

    async def _delete_handle_failures(self, ip: str) -> None:
        async with get_db(self.db_path) as db:
            await db.execute("DELETE FROM net_handle_failures WHERE ip = ?", (ip,))

    async def _delete_failure_record(self, ip: str) -> None:
        async with get_db(self.db_path) as db:
            await db.execute(
                "DELETE FROM net_auth_failures WHERE ip = ?", (ip,)
            )

class NetListener:
    """
    Async TCP server for the partyline / botlink port.

    An AccessGuard MUST be provided in production.  Omitting it is only
    permitted when dev_mode=true is set in config — otherwise startup raises.
    """

    def __init__(
        self,
        core_q:       mp.Queue,
        config:       Optional[dict] = None,
        access_guard: Optional[AccessGuard] = None,
        *,
        db_path:      Optional[str] = None,
        user_manager: Optional[UserManager] = None,
    ) -> None:
        self._pending_streams: dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self._stream_timestamps: dict[str, float] = {}   # Issue #3: TTL tracking
        self._stream_peers: dict[str, str] = {}           # key → admitted peer IP
        self.core_q  = core_q
        self.config  = config or {}
        self.guard: Optional[AccessGuard] = access_guard
        self.server  = None

        # One explicit DB for partyline authentication (SAST-011).  Sources
        # must agree; with none the listener still serves botlinks but every
        # partyline login fails closed.
        paths = {p for p in (db_path,
                             getattr(user_manager, "db_path", None),
                             getattr(access_guard, "db_path", None)) if p}
        if len(paths) > 1:
            raise RuntimeError(f"NetListener: conflicting database paths {sorted(paths)}")
        self.db_path: Optional[str] = next(iter(paths), None)
        if user_manager is None and self.db_path:
            user_manager = UserManager(self.db_path)
        self.users: Optional[UserManager] = user_manager

        cfg = self.config.get("settings", {})
        if access_guard is None and not cfg.get("dev_mode", False):
            raise RuntimeError(
                "NetListener requires an AccessGuard in production. "
                "Pass access_guard=... or set dev_mode=true in config to bypass (unsafe)."
            )
        if access_guard is None:
            log.warning(
                "NetListener: no AccessGuard — running in dev_mode with NO admission control!"
            )

    def _build_ssl_context(self) -> ssl_lib.SSLContext | None:
        """Build server-side TLS context, or None if SSL is disabled.

        Raises RuntimeError at startup if ssl=true but cert/key files are
        missing or fail to load.

        plaintext requires explicit allow_plaintext=true override.
        A security-first bot must never silently serve credentials over cleartext.
        """
        cfg = self.config.get("settings", {})
        if not cfg.get("ssl", False):
            if not cfg.get("allow_plaintext", False):
                raise RuntimeError(
                    "SSL is disabled but allow_plaintext=true is not set. "
                    "Configure ssl=true with cert/key paths, or explicitly set "
                    "allow_plaintext=true to accept the security risk."
                )
            log.warning(
                "NetListener: TLS is DISABLED and allow_plaintext=true is set. "
                "Credentials will be transmitted in cleartext — DO NOT use in production!"
            )
            return None

        certfile = cfg.get("certfile")
        keyfile  = cfg.get("keyfile")
        if not certfile or not keyfile:
            raise RuntimeError(
                "SSL is enabled but certfile and/or keyfile are not configured. "
                "Set ssl=false or provide valid cert/key paths in config."
            )
        ctx = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl_lib.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        except (ssl_lib.SSLError, FileNotFoundError, PermissionError) as exc:
            raise RuntimeError(
                f"SSL is enabled but cert/key failed to load "
                f"(cert={certfile!r}, key={keyfile!r}): {exc}"
            ) from exc
        log.info("TLS enabled (cert=%s, min=TLSv1.2)", certfile)
        return ctx

    async def listen(self) -> None:
        """
        Bind and serve.
        listen_host: '' or absent → '127.0.0.1' (loopback only); set an explicit
        listen_host (e.g. '0.0.0.0') to accept remote bots.
        listen_port: default 3333.
        Read from config['botnet'] (listen_host/listen_port); the legacy
        config['settings'] keys of the same name are still honoured (NET-11).
        """
        host, port = botnet_listen(self.config)

        ssl_ctx = self._build_ssl_context()
        self.server = await asyncio.start_server(
            self.handle_connection, host, port, ssl=ssl_ctx
        )
        mode = "TLS" if ssl_ctx else "PLAINTEXT (allow_plaintext=true)"
        log.info("Net listening on %s:%d (%s)", host, port, mode)

        asyncio.get_running_loop().create_task(self._reap_pending_streams())

        async with self.server:
            await self.server.serve_forever()

    # ------------------------------------------------------------------
    # Pending-stream ownership (SAST-011 / SAST-012)
    #
    # A connection's admission slot is owned by exactly one party at a time:
    #   handle_connection   until a handler returns True (handoff), then
    #   the pending table   until core claims the stream (claim_stream), then
    #   the claimer         (partyline Session / botlink read_peer) until teardown.
    # Whoever owns a connection when it ends closes it and releases the slot,
    # exactly once; nobody else touches it.
    # ------------------------------------------------------------------
    def _add_pending(self, key: str, reader, writer, peer_ip: str) -> None:
        self._pending_streams[key]   = (reader, writer)
        self._stream_timestamps[key] = time.monotonic()
        self._stream_peers[key]      = peer_ip

    def claim_stream(self, key: Optional[str]):
        """
        Take ownership of a pending stream: (reader, writer), or None if it
        was never registered, was already claimed, or was reaped.  The caller
        now owns the connection and its admission slot.
        """
        if not key:
            return None
        self._stream_timestamps.pop(key, None)
        self._stream_peers.pop(key, None)
        return self._pending_streams.pop(key, None)

    async def _reap_stale(self, ttl: float, now: Optional[float] = None) -> int:
        """Close and release every pending stream older than ttl seconds."""
        now   = time.monotonic() if now is None else now
        stale = [k for k, ts in self._stream_timestamps.items() if now - ts > ttl]
        reaped = 0
        for key in stale:
            peer_ip = self._stream_peers.get(key)
            streams = self.claim_stream(key)
            if not streams:
                continue
            reaped += 1
            _, writer = streams
            log.warning("NetListener: reaping unclaimed stream key=%r", key)
            # The pending table owned this slot; it is released exactly once.
            await self._close_and_release(writer, peer_ip or "", admitted=bool(peer_ip))
        return reaped

    async def _reap_pending_streams(self) -> None:
        """
        Periodically close any _pending_streams entries that core never claimed.
        TTL: 60 seconds.  Prevents resource exhaustion from unanswered handshakes.
        One failed sweep must never stop reaping (SAST-012).
        """
        while True:
            await asyncio.sleep(30)
            try:
                await self._reap_stale(60.0)
            except Exception as e:
                log.error("NetListener: pending-stream reaper sweep failed: %s", e)

    async def _close_and_release(self, writer, peer_ip: str, admitted: bool) -> None:
        """
        Final cleanup for a connection the acceptor still owns: close the
        socket, then release its admission slot.  The slot is released before
        awaiting wait_closed() so a cancellation or a misbehaving transport
        can never leak it.
        """
        try:
            writer.close()
        except Exception:
            pass
        if admitted and self.guard:
            self.guard.release(peer_ip)
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Accept one connection.  Ownership (SAST-012): this coroutine owns the
        socket and its admission slot until a handler returns exactly True,
        meaning it registered the stream in the pending table.  Every other
        outcome (HTTP probe, bad handle, failed or timed-out auth, framing
        error, exception, cancellation) closes the socket and releases the
        slot here, exactly once.
        """
        peer    = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"
        admitted   = False
        handed_off = False

        if self.guard:
            try:
                allowed, _reason = await self.guard.admit(peer_ip)
            except Exception as e:
                log.error("AccessGuard admit error for %s: %s — refusing", peer_ip, e)
                allowed = False
            if not allowed:
                try:
                    writer.write(b"ERROR :Connection refused\r\n")
                    await writer.drain()
                except Exception:
                    pass
                finally:
                    # Nothing was admitted, so there is no slot to release.
                    await self._close_and_release(writer, peer_ip, admitted=False)
                return
            admitted = True

        try:
            cfg     = self.config.get("settings", {})
            timeout = float(cfg.get("handshake_timeout", 30))
            line = (await _read_handshake_line(reader, timeout)).strip()
            if not line:
                raise ValueError("Empty handshake line")

            # Handlers return True only when they transferred the connection
            # (and its admission slot) to the pending-stream table.  Any other
            # value, including a truthy non-bool, leaves ownership here.
            if line.startswith("BOTLINK"):
                result = await self._handle_botlink(line, peer, peer_ip, reader, writer)
            else:
                result = await self._handle_partyline(line, peer, peer_ip, reader, writer)
            handed_off = result is True

        except asyncio.TimeoutError:
            log.warning("Handshake timeout from %s", peer_ip)
        except _FramingError as e:
            log.warning("Bad handshake framing from %s: %s", peer_ip, e)
        except Exception as e:
            log.error("Connection error from %s: %s", peer_ip, e)

        finally:
            if not handed_off:
                # Defensive: if a handler registered the stream but then did
                # not report the handoff, take it back so the pending table
                # never holds a socket this coroutine is about to close.
                for key in [k for k, (_, w) in self._pending_streams.items() if w is writer]:
                    self.claim_stream(key)
                await self._close_and_release(writer, peer_ip, admitted)

    def _enqueue(self, key: str, reader, writer, peer_ip: str, event: dict) -> bool:
        """
        Register a pending stream and announce it to core; undo on failure.
        Returns True only when the pending table now owns the connection.
        Keys are per-connection UUIDs, so an existing entry is never replaced
        (and thereby orphaned without close/release).
        """
        if key in self._pending_streams:
            log.error("NetListener: pending key collision %r from %s — refusing", key, peer_ip)
            return False
        self._add_pending(key, reader, writer, peer_ip)
        try:
            self.core_q.put_nowait(event)
        except Exception as e:
            log.error("NetListener: could not queue %s for %s: %s",
                      event.get("type"), peer_ip, e)
            self.claim_stream(key)
            return False
        return True

    async def _handle_botlink(
        self,
        line:      str,
        peer:      tuple,
        peer_ip:   str,
        reader:    asyncio.StreamReader,
        writer:    asyncio.StreamWriter,
    ) -> bool:
        """Queue a botlink hello for BotnetManager.  True = stream handed off."""
        parts = line.split()
        if len(parts) < 4:
            log.warning("Invalid BOTLINK from %s: %s", safe(peer_ip), line_summary(line))
            return False
        remote_handle = parts[1]
        if self.guard and self.guard.handle_locked(peer_ip, remote_handle):
            # This (address, claimed handle) pair keeps failing auth; other
            # handles from the address are unaffected (NET-13).
            log.warning("Botlink from %s claiming %r refused: too many failed attempts",
                        peer_ip, remote_handle[:64])
            writer.write(b"ERROR :Connection refused\r\n")
            await writer.drain()
            return False
        try:
            subnet_id = int(parts[3])
        except ValueError:
            log.warning(
                "Invalid BOTLINK subnet_id from %s: %s — defaulting to subnet 1",
                safe(peer_ip), line_summary(line),
            )
            subnet_id = 1
        log.info("Botlink from %s (%s)", remote_handle, peer_ip)
        # Key by connection, not handle: a second socket claiming the same
        # handle must never overwrite (and orphan) another pending stream.
        # Authentication itself happens in BotnetManager (AUTH2 handshake).
        key = f"botlink:{uuid.uuid4()}"
        return self._enqueue(key, reader, writer, peer_ip, {
            "type":      "BOT_CONNECT",
            "handle":    remote_handle,
            "peer":      peer,
            "peer_ip":   peer_ip,
            "subnet_id": subnet_id,
            "conn_id":   key,
            "data":      line,
        })

    def _transport_is_secure(self, writer) -> bool:
        """TLS connection, or plaintext explicitly accepted by the operator."""
        if writer.get_extra_info("ssl_object") is not None:
            return True
        return bool(self.config.get("settings", {}).get("allow_plaintext", False))

    async def authenticate_partyline(self, handle: str, password: str) -> Optional[str]:
        """
        Canonical partyline login check (SAST-011).  Returns the stored
        handle when ALL of these hold, else None:
          * the handle names an existing user (case-insensitive lookup),
          * the awaited UserManager.authenticate(handle, password) passes:
            user not deleted, not locked, bcrypt check against the stored hash,
          * the user holds +p in this bot's subnet scope (SAST-004).
        Results must be exactly True (a stray coroutine or other truthy
        object never counts as success).  Any error fails closed.
        """
        if self.users is None:
            log.error("Partyline auth: no user database configured; refusing login")
            return None
        if not handle or not password or len(password) > _PASSWORD_MAX:
            return None
        try:
            canonical = await self.users.resolve_handle(handle)
            if not canonical:
                return None
            if await self.users.authenticate(canonical, password) is not True:
                return None
            if await self.users.matchattr(
                    canonical, "+p", subnet_id=local_subnet_id(self.config)) is not True:
                log.warning("Partyline auth: %r has no partyline access here", canonical)
                return None
            return canonical
        except Exception as e:
            log.error("Partyline auth error for %r: %s", handle, e)
            return None

    async def _handle_partyline(
        self,
        line:    str,
        peer:    tuple,
        peer_ip: str,
        reader:  asyncio.StreamReader,
        writer:  asyncio.StreamWriter,
    ) -> bool:
        """Telnet partyline login.  True = authenticated stream handed off."""
        if line.upper().startswith(_HTTP_METHODS):
            log.info("HTTP probe from %s — dropped silently", peer_ip)
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return False

        if not _HANDLE_RE.match(line):
            log.warning(
                "Partyline: invalid handle characters from %s (len=%d)",
                peer_ip, len(line),
            )
            writer.write(b"ERROR :Connection refused\r\n")
            await writer.drain()
            return False

        # Passwords never cross a plaintext socket unless the operator opted in.
        if not self._transport_is_secure(writer):
            log.warning("Partyline: refusing plaintext login from %s", peer_ip)
            writer.write(b"ERROR :TLS required\r\n")
            await writer.drain()
            return False

        cfg     = self.config.get("settings", {})
        timeout = float(cfg.get("auth_timeout", 60))
        handle  = line
        try:
            writer.write(b"Password: ")
            await writer.drain()
            password = await _read_handshake_line(reader, timeout)
        except asyncio.TimeoutError:
            log.warning("Auth timeout from %s", peer_ip)
            if self.guard:
                await self.guard.record_failure(peer_ip, handle)
            writer.write(b"ERROR :Login timeout\r\n")
            await writer.drain()
            return False
        except _FramingError as e:
            log.warning("Partyline: bad password line from %s: %s", peer_ip, e)
            if self.guard:
                await self.guard.record_failure(peer_ip, handle)
            return False

        canonical = await self.authenticate_partyline(handle, password)
        if canonical is None:
            if self.guard:
                await self.guard.record_failure(peer_ip, handle)
            log.warning("Failed partyline auth: handle=%r ip=%s", handle, peer_ip)
            writer.write(b"ERROR :Connection refused\r\n")
            await writer.drain()
            return False

        if self.guard:
            self.guard.record_success(peer_ip)

        conn_id = f"partyline:{uuid.uuid4()}"
        return self._enqueue(conn_id, reader, writer, peer_ip, {
            "type":    "PARTYLINE_CONNECT",
            "handle":  canonical,
            "peer":    peer,
            "peer_ip": peer_ip,
            "conn_id": conn_id,
        })
