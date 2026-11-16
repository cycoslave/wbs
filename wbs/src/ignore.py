# src/ignore.py
"""
Ignore list (USR-11): parsing, matching and the IRC-side enforcement cache.

Table `ignores` (db/schema.sql): one row per active ignore.  `flags` holds
the duration as given (`10m`, `1d2h`; empty = permanent) and the expiry is
`created_at + duration`, so no schema change is needed.  Expired rows are
deleted lazily (by the ignore commands); every reader also treats them as
inactive.

Owner/admin hostmasks are never ignorable: `+ignore` refuses a mask that
overlaps one, and the IRC layer never drops a sender whose hostmask matches
an owner/admin user, even if such a mask was added later.
"""
import json
import logging
import re
import sqlite3
import time
from datetime import datetime, timezone
from typing import Iterable, Optional

log = logging.getLogger("wbs.ignore")

_DURATION_RE = re.compile(r"^(?:(\d+)y)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?\Z", re.ASCII)
_UNIT_SECONDS = (365 * 86400, 86400, 3600, 60)
MAX_DURATION = 100 * 365 * 86400

# The IRC events an ignore drops (irc.client event types).
IGNORED_EVENT_TYPES = frozenset({
    "pubmsg", "privmsg", "pubnotice", "privnotice", "action", "ctcp", "ctcpreply",
})


def parse_duration(text: str) -> Optional[int]:
    """`10m`, `1h`, `2d12h`, `1y` -> seconds; `0` -> 0 (permanent);
    anything else -> None."""
    if not isinstance(text, str) or not text:
        return None
    if text == "0":
        return 0
    m = _DURATION_RE.match(text.lower())
    if not m or not any(m.groups()):
        return None
    total = sum(int(v) * mult for v, mult in zip(m.groups(), _UNIT_SECONDS) if v)
    if total > MAX_DURATION:
        return None
    return total


def format_duration(seconds: float) -> str:
    """Seconds -> `1d2h3m` (at least `0m`; seconds rounded up to a minute)."""
    seconds = max(0, int(seconds))
    minutes = -(-seconds // 60)
    days, rem = divmod(minutes, 1440)
    hours, mins = divmod(rem, 60)
    out = (f"{days}d" if days else "") + (f"{hours}h" if hours else "") + (f"{mins}m" if mins else "")
    return out or "0m"


def normalize_mask(mask: str) -> str:
    """Eggdrop-style completion: `nick` -> `nick!*@*`, `user@host` ->
    `*!user@host`; full masks are returned unchanged."""
    if "!" not in mask and "@" not in mask:
        return f"{mask}!*@*"
    if "!" not in mask:
        return f"*!{mask}"
    return mask


def irc_match(pattern: str, text: str) -> bool:
    """Case-insensitive IRC glob: only `*` and `?` are wildcards (`[` and
    `]` are ordinary nick characters, unlike fnmatch)."""
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, text, re.IGNORECASE | re.DOTALL) is not None


def masks_overlap(a: str, b: str) -> bool:
    """True when either mask matches the other (as text).  `*!*@*` overlaps
    every mask; `bob!x@h` overlaps `*!*x@*`."""
    return irc_match(a, b) or irc_match(b, a)


def created_epoch(value) -> Optional[int]:
    """`created_at` (CURRENT_TIMESTAMP text in UTC, or an epoch) -> epoch."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return int(datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    return None


def expires_at(row) -> int:
    """Expiry epoch of an ignore row; 0 = permanent."""
    seconds = parse_duration(row["flags"] or "") if row["flags"] else 0
    if not seconds:
        return 0
    start = created_epoch(row["created_at"])
    if start is None:
        # Unknown start: keep it until it is removed rather than guess.
        return 0
    return start + seconds


def is_expired(row, now: Optional[float] = None) -> bool:
    exp = expires_at(row)
    return bool(exp) and exp <= (time.time() if now is None else now)


# --- shared SQL --------------------------------------------------------------

_ROWS_SQL = ("SELECT id, hostmask, flags, comment, created_at, created_by "
             "FROM ignores WHERE deleted_at IS NULL")

# Hostmasks of live users holding +n or +A, granted globally or for this
# subnet (the same scope rule as UserManager.matchattr).
_PROTECTED_SQL = (
    "SELECT DISTINCT u.hostmasks FROM users u JOIN user_access a ON a.handle = u.handle "
    "WHERE u.deleted_at IS NULL AND a.deleted_at IS NULL "
    "AND (COALESCE(a.is_owner, 0) = 1 OR COALESCE(a.is_admin, 0) = 1) "
    "AND (a.subnet_id IS NULL OR a.subnet_id = ?)"
)


def _masks_of(values: Iterable) -> list[str]:
    out: list[str] = []
    for raw in values:
        try:
            masks = json.loads(raw) if isinstance(raw, str) and raw else (raw or [])
        except (json.JSONDecodeError, ValueError):
            log.warning("ignore: unreadable hostmasks value %r", raw)
            continue
        out.extend(m for m in masks if isinstance(m, str) and m)
    return out


async def protected_masks(db, subnet_id: int) -> list[str]:
    """Owner/admin hostmasks (aiosqlite connection)."""
    rows = await db.execute_fetchall(_PROTECTED_SQL, (subnet_id,))
    return _masks_of(r[0] for r in rows)


async def purge_expired(db, now: Optional[float] = None) -> list[str]:
    """Delete expired ignores (aiosqlite connection); returns their masks."""
    rows = await db.execute_fetchall(_ROWS_SQL)
    gone = [r for r in rows if is_expired(r, now)]
    for r in gone:
        await db.execute("DELETE FROM ignores WHERE id = ?", (r["id"],))
        log.info("ignore: %s expired", r["hostmask"])
    return [r["hostmask"] for r in gone]


async def active_ignores(db, now: Optional[float] = None) -> list:
    """Active (unexpired) ignore rows ordered by mask; expired rows are
    skipped here and deleted by purge_expired()."""
    rows = await db.execute_fetchall(_ROWS_SQL + " ORDER BY LOWER(hostmask)")
    return [r for r in rows if not is_expired(r, now)]


# --- IRC-side enforcement ----------------------------------------------------

class IgnoreCache:
    """
    Synchronous view of the ignore list for the IRC process (its reactor
    thread has no event loop to await on).  Loaded at start, reloaded when
    Core reports a change (`reload_ignores`) and at most `ttl` seconds
    after the previous load (picks up owner/admin host changes).
    """

    def __init__(self, db_path: str, subnet_id: int, ttl: float = 60.0):
        self.db_path = db_path
        self.subnet_id = subnet_id
        self.ttl = ttl
        self.entries: list[tuple[str, int]] = []   # (mask, expires_at or 0)
        self.protected: list[str] = []
        self.loaded_at: Optional[float] = None

    def reload(self) -> None:
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(_ROWS_SQL).fetchall()
            prot = conn.execute(_PROTECTED_SQL, (self.subnet_id,)).fetchall()
        finally:
            conn.close()
        self.entries = [(r["hostmask"], expires_at(r)) for r in rows]
        self.protected = _masks_of(r[0] for r in prot)
        self.loaded_at = time.monotonic()
        log.debug("ignore: %d active mask(s), %d protected", len(self.entries), len(self.protected))

    def _fresh(self) -> None:
        if self.loaded_at is None or time.monotonic() - self.loaded_at >= self.ttl:
            try:
                self.reload()
            except sqlite3.Error as e:
                # Keep the last good list; say so loudly instead of hiding it.
                log.error("ignore: cannot load the ignore list from %s: %s", self.db_path, e)
                self.loaded_at = time.monotonic()

    def match(self, hostmask: str, now: Optional[float] = None) -> Optional[str]:
        """The active ignore mask matching `hostmask` (nick!user@host), or
        None.  Owner/admin hostmasks never match."""
        if not hostmask:
            return None
        self._fresh()
        if not self.entries:
            return None
        now = time.time() if now is None else now
        hit = next((m for m, exp in self.entries
                    if (not exp or exp > now) and irc_match(m, hostmask)), None)
        if hit is None:
            return None
        if any(irc_match(p, hostmask) for p in self.protected):
            return None
        return hit
