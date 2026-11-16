# src/share.py
"""
Peer replication policy for WBS botnet data sharing (SAST-003).

Every record that crosses a botlink, inbound (SHARE / UPDATE from a peer) or
outbound (SHARE on link-up, UPDATE from local changes and relays), passes
through ReplicationPolicy.  Anything it does not explicitly allow is denied.

Share level (bots.share_level of the *peer's* row in our DB, set with
`.botattr <peer> share=none|subnet|all`; `full` is accepted as `all`; an
unknown, empty or NULL value is `none`):

    none    nothing is replicated with the peer in either direction.
    subnet  only data owned by the local subnet, and only if the peer's stored
            scope (SAST-002) includes the local subnet.
    all     data owned by any subnet in the peer's stored scope.

The share *scope* of a link is the resulting set of subnet ids; empty means
nothing is replicated.  Scope never exceeds the peer's stored scope, so data
owned by a subnet the peer is not in (foreign) never leaves and is never
accepted, at any level.

Entity ownership (which subnets an entity belongs to), always from local data:

    subnet       its id.
    user_access  {subnet_id} plus, for a channel row, the channel's bound
                 subnets.  A NULL subnet_id or an unbound (global) channel is
                 global.
    user         the union of its user_access rows (live or soft-deleted).  A
                 user with any global row, or any is_admin / is_owner flag, is
                 privileged/global and is never replicated.  Replicating a user
                 record (identity: hostmasks, lock, comment, deletion) needs
                 exclusive ownership inside the scope.
    channel      its channel_subnets bindings; unbound channels are global.
    bot          bots.subnet_id plus bot_subnets (BotManager.get_subnet_scope).
    bot_access   the bot's scope, plus the channel's bindings for a channel row.

An entity is replicable with a peer only if its ownership is non-empty, not
global and a subset of the link's share scope.  The same rule gates inbound
writes, inbound deletes and outbound serialization, and a relayed UPDATE is
re-checked against each destination link.

Field rules (default deny):

  * Credentials are never replicated: users.password and bots.password are
    stripped outbound and ignored inbound.
  * Global privileges are never replicated: user_access rows with a NULL
    subnet_id and rows or users carrying is_admin / is_owner are rejected, and
    those columns are never sent.
  * Local policy and scope are never replicated: bots.share_level, subnet_id,
    autolink and autolink_retry_interval.
  * Records about this bot or the sending/receiving peer itself are skipped.
    Bots we hold a link key for are operator-owned and never changed by a peer.
  * Timestamps must be integers no further than MAX_FUTURE_SKEW seconds in the
    future, so a peer cannot pin a last-write-wins override with a far-future
    updated_at / deleted_at.  Deletes are soft deletes and lose to a newer
    local update.
  * Unknown bots and unknown users are never created from a USERS / BOTS
    record (their ownership cannot be established).  An in-scope USERACCESS
    row may create an inert shell user: no password, no hostmasks, no global
    access.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Iterable

from .channel import _SYNC_ALLOWED_COLUMNS
from .db import get_db
from .user import ACCESS_FLAG_COLUMNS, PRIVILEGED_FLAG_COLUMNS

log = logging.getLogger("wbs.share")

SHARE_NONE, SHARE_SUBNET, SHARE_ALL = "none", "subnet", "all"
_LEVEL_ALIASES = {"none": SHARE_NONE, "subnet": SHARE_SUBNET, "all": SHARE_ALL, "full": SHARE_ALL}

# Seconds a replicated timestamp may lie in the future (matches the botlink
# clock-skew limit).
MAX_FUTURE_SKEW = 30

ENTITIES = frozenset({"subnets", "users", "useraccess", "bots", "botaccess", "channels"})

_HANDLE_RE = re.compile(r"^[A-Za-z0-9_\-\[\]\\^`|{}]{1,32}$")
_CHAN_PREFIXES = ("#", "&", "+", "!")
_BOT_ROLES = frozenset({"hub", "backup", "leaf", "none"})

PRIVILEGED_USER_FLAGS = PRIVILEGED_FLAG_COLUMNS
# Every other column of the one flag table (user.GLOBAL_FLAGS, USR-5).
USER_ACCESS_FLAGS = ACCESS_FLAG_COLUMNS
BOT_ACCESS_FLAGS = ("has_partyline", "is_op", "is_deop", "is_hop", "is_dehop",
                    "is_voice", "is_devoice", "is_friend")
_TS_FIELDS = ("created_at", "updated_at", "deleted_at")
_CHANNEL_LIST_COLUMNS = frozenset({"bans", "invites", "exempts"})


def normalize_share_level(raw) -> str:
    """Map a stored share_level to none|subnet|all; anything unrecognised is none."""
    if isinstance(raw, str):
        return _LEVEL_ALIASES.get(raw.strip().lower(), SHARE_NONE)
    return SHARE_NONE


@dataclass(frozen=True)
class UserOwnership:
    exists: bool
    local_handle: str | None = None
    subnets: frozenset[int] = frozenset()
    has_global: bool = False
    privileged: bool = False

    def exclusive_in(self, scope: frozenset[int]) -> bool:
        return (self.exists and bool(self.subnets) and not self.has_global
                and not self.privileged and self.subnets <= scope)


def _valid_handle(v) -> bool:
    return isinstance(v, str) and bool(_HANDLE_RE.match(v))


def _valid_channel(v) -> bool:
    return (isinstance(v, str) and 1 < len(v) <= 200 and v.startswith(_CHAN_PREFIXES)
            and not any(c in v for c in " ,\x07\r\n"))


def _flag(v) -> int | None:
    """0/1 for a boolean-ish flag, None if the value is not a flag."""
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int) and v in (0, 1):
        return v
    return None


def _hostmasks_json(v) -> str | None:
    """Normalise a hostmask list (list or JSON string) to a JSON string, or None if invalid."""
    if isinstance(v, str):
        try:
            v = json.loads(v) if v.strip() else []
        except (json.JSONDecodeError, ValueError):
            return None
    if not isinstance(v, list) or len(v) > 100:
        return None
    if not all(isinstance(m, str) and 0 < len(m) <= 255 and " " not in m for m in v):
        return None
    return json.dumps(v)


class ReplicationPolicy:
    """Deny-by-default authorization and sanitisation of replicated records."""

    def __init__(self, db_path: str, local_subnet_id: int, my_handle: str,
                 max_future_skew: int = MAX_FUTURE_SKEW):
        self.db_path = db_path
        self.local_subnet_id = local_subnet_id
        self.my_handle = my_handle
        self.max_future_skew = max_future_skew

    # ------------------------------------------------------------------
    # scope
    # ------------------------------------------------------------------
    def scope_for(self, share_level, peer_subnets: Iterable[int]) -> frozenset[int]:
        """Subnets whose data may be replicated with a peer; empty = nothing."""
        level = normalize_share_level(share_level)
        peer = frozenset(peer_subnets or ())
        if level == SHARE_ALL:
            return peer
        if level == SHARE_SUBNET and self.local_subnet_id in peer:
            return frozenset({self.local_subnet_id})
        return frozenset()

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    async def inbound(self, entity: str, action: str, records, peer: str,
                      scope: frozenset[int]) -> list[dict]:
        """Records from `peer` that may be applied locally, sanitised. Others are dropped and logged."""
        return await self._filter("in", entity, action, records, peer, scope)

    async def outbound(self, entity: str, action: str, records, peer: str,
                       scope: frozenset[int]) -> list[dict]:
        """Local records that may be sent to `peer`, sanitised. Others are dropped."""
        return await self._filter("out", entity, action, records, peer, scope)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    async def _filter(self, direction: str, entity: str, action: str, records,
                      peer: str, scope: frozenset[int]) -> list[dict]:
        action = (action or "ADD").upper()
        if action == "UPDATE":
            action = "ADD"
        if entity not in ENTITIES or action not in ("ADD", "DEL"):
            log.warning("replication %s: unsupported %s %s with %s", direction, entity, action, peer)
            return []
        if not scope or not isinstance(records, list):
            return []
        if action == "DEL" and entity not in ("users", "bots", "channels"):
            return []
        out: list[dict] = []
        denied = 0
        now = int(time.time())
        async with get_db(self.db_path) as db:
            for rec in records:
                if not isinstance(rec, dict):
                    denied += 1
                    continue
                reason = self._check_timestamps(rec, now)
                clean = None
                if reason is None:
                    check = getattr(self, f"_{entity}")
                    clean, reason = await check(db, direction, action, rec, peer, scope)
                if clean is None:
                    denied += 1
                    log.warning("replication %s: denied %s %s %r %s %s: %s",
                                direction, entity, action, self._key(rec),
                                "from" if direction == "in" else "to", peer, reason)
                else:
                    out.append(clean)
        if denied:
            log.info("replication %s: %s %s with %s: %d allowed, %d denied (scope %s)",
                     direction, entity, action, peer, len(out), denied, sorted(scope))
        return out

    @staticmethod
    def _key(rec: dict):
        for k in ("handle", "name", "id"):
            if k in rec:
                v = rec[k]
                return v if isinstance(v, (str, int)) else type(v).__name__
        return None

    def _check_timestamps(self, rec: dict, now: int) -> str | None:
        limit = now + self.max_future_skew
        for k in _TS_FIELDS:
            v = rec.get(k)
            if v is None:
                continue
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                return f"invalid {k}"
            if v > limit:
                return f"{k} {v} is in the future"
        return None

    @staticmethod
    def _copy_ts(src: dict, dst: dict, fields=_TS_FIELDS) -> None:
        for k in fields:
            if k in src:
                dst[k] = src[k]

    def _is_self_or_peer(self, handle: str, peer: str) -> bool:
        h = handle.lower()
        return h == (self.my_handle or "").lower() or h == (peer or "").lower()

    # -- lookups ---------------------------------------------------------
    @staticmethod
    async def _channel_bound(db, name: str) -> frozenset[int]:
        rows = await db.execute_fetchall(
            "SELECT subnet_id FROM channel_subnets WHERE LOWER(channel_name) = LOWER(?)", (name,))
        return frozenset(int(r["subnet_id"]) for r in rows if r["subnet_id"] is not None)

    async def _row_scope(self, db, subnet_id, channel) -> frozenset[int] | None:
        """Ownership of one access row; None = global."""
        if subnet_id is None:
            return None
        owned = {int(subnet_id)}
        if channel:
            bound = await self._channel_bound(db, channel)
            if not bound:
                return None
            owned |= bound
        return frozenset(owned)

    async def _user_ownership(self, db, handle: str) -> UserOwnership:
        async with db.execute(
            "SELECT handle FROM users WHERE LOWER(handle) = LOWER(?)", (handle,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return UserOwnership(exists=False)
        rows = await db.execute_fetchall(
            "SELECT channel, subnet_id, is_admin, is_owner FROM user_access "
            "WHERE LOWER(handle) = LOWER(?)", (handle,))
        subnets: set[int] = set()
        has_global = privileged = False
        for r in rows:
            if r["is_admin"] or r["is_owner"]:
                privileged = True
            owned = await self._row_scope(db, r["subnet_id"], r["channel"])
            if owned is None:
                has_global = True
            else:
                subnets |= owned
        return UserOwnership(True, row["handle"], frozenset(subnets), has_global, privileged)

    @staticmethod
    async def _bot_scope(db, handle: str) -> frozenset[int] | None:
        """Same rule as BotManager.get_subnet_scope: None = no such bot, empty = unknown."""
        async with db.execute(
            "SELECT subnet_id, deleted_at FROM bots WHERE LOWER(handle) = LOWER(?)", (handle,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        if row["deleted_at"] is not None:
            return frozenset()
        rows = await db.execute_fetchall(
            "SELECT subnet_id FROM bot_subnets WHERE LOWER(bot_handle) = LOWER(?) "
            "AND deleted_at IS NULL", (handle,))
        ids = {int(r["subnet_id"]) for r in rows if r["subnet_id"] is not None}
        if row["subnet_id"] is not None:
            ids.add(int(row["subnet_id"]))
        return frozenset(ids)

    @staticmethod
    async def _bot_keyed(db, handle: str) -> bool:
        """A bot we hold a link key for is linked directly and managed only locally."""
        async with db.execute(
            "SELECT 1 FROM bots WHERE LOWER(handle) = LOWER(?) "
            "AND password IS NOT NULL AND password != ''", (handle,)
        ) as cur:
            return await cur.fetchone() is not None

    # -- per-entity rules ------------------------------------------------
    # Each returns (sanitised_record, None) or (None, reason).

    async def _subnets(self, db, direction, action, rec, peer, scope):
        sid, name = rec.get("id"), rec.get("name")
        if isinstance(sid, bool) or not isinstance(sid, int):
            return None, "invalid subnet id"
        if not isinstance(name, str) or not name.strip() or len(name) > 64:
            return None, "invalid subnet name"
        if sid not in scope:
            return None, "subnet outside share scope"
        clean = {"id": sid, "name": name.strip()}
        self._copy_ts(rec, clean, ("created_at",))
        return clean, None

    async def _users(self, db, direction, action, rec, peer, scope):
        handle = rec.get("handle")
        if not _valid_handle(handle):
            return None, "invalid handle"
        own = await self._user_ownership(db, handle)
        if own.exists:
            if own.privileged:
                return None, "privileged user (is_admin/is_owner) is never replicated"
            if own.has_global:
                return None, "user has global access rows"
            if not own.exclusive_in(scope):
                return None, (f"user owned by subnets {sorted(own.subnets) or 'none'}, "
                              f"outside share scope")
        elif direction == "out":
            return None, "unknown user"
        else:
            # Ownership of an unknown user cannot be established; it is only
            # ever created (inert) by an in-scope access row.
            return None, "unknown user (no in-scope access rows yet)"
        clean: dict = {"handle": own.local_handle or handle}
        if action == "DEL":
            self._copy_ts(rec, clean, ("updated_at", "deleted_at"))
            return clean, None
        if "hostmasks" in rec:
            masks = _hostmasks_json(rec["hostmasks"])
            if masks is None:
                return None, "invalid hostmasks"
            clean["hostmasks"] = masks
        if "is_locked" in rec:
            locked = _flag(rec["is_locked"])
            if locked is None:
                return None, "invalid is_locked"
            clean["is_locked"] = locked
        if "comment" in rec:
            if rec["comment"] is not None and not isinstance(rec["comment"], str):
                return None, "invalid comment"
            clean["comment"] = (rec["comment"] or "")[:512]
        self._copy_ts(rec, clean)
        # password (credential) is never copied, in either direction.
        return clean, None

    async def _useraccess(self, db, direction, action, rec, peer, scope):
        handle = rec.get("handle")
        if not _valid_handle(handle):
            return None, "invalid handle"
        subnet_id, channel = rec.get("subnet_id"), rec.get("channel")
        if subnet_id is None:
            return None, "global access row (subnet_id NULL)"
        if isinstance(subnet_id, bool) or not isinstance(subnet_id, int):
            return None, "invalid subnet_id"
        if channel is not None and not _valid_channel(channel):
            return None, "invalid channel"
        for col in PRIVILEGED_USER_FLAGS:
            if rec.get(col):
                return None, f"{col} is a global privilege and is never replicated"
        owned = await self._row_scope(db, subnet_id, channel)
        if owned is None:
            return None, f"channel {channel!r} is global (no subnet binding)"
        if not owned <= scope:
            return None, f"row owned by subnets {sorted(owned)}, outside share scope"
        own = await self._user_ownership(db, handle)
        if own.privileged:
            return None, "privileged user (is_admin/is_owner) is never replicated"
        if own.has_global:
            return None, "user has global access rows (managed locally)"
        if direction == "out" and not own.exists:
            return None, "unknown user"
        if not own.exists and rec.get("deleted_at") is not None:
            return None, "tombstone for unknown user"
        clean: dict = {"handle": own.local_handle or handle, "channel": channel,
                       "subnet_id": subnet_id}
        for col in USER_ACCESS_FLAGS:
            if col in rec:
                v = _flag(rec[col])
                if v is None:
                    return None, f"invalid {col}"
                clean[col] = v
        self._copy_ts(rec, clean)
        return clean, None

    async def _bots(self, db, direction, action, rec, peer, scope):
        handle = rec.get("handle")
        if not _valid_handle(handle):
            return None, "invalid handle"
        if self._is_self_or_peer(handle, peer):
            return None, "record about this bot or the peer itself"
        bscope = await self._bot_scope(db, handle)
        if bscope is None:
            # Ownership of an unknown bot cannot be established; bots are
            # added locally by the operator (.+bot / .botattr subnet=).
            return None, "unknown bot"
        elif not bscope:
            return None, "bot has no stored subnet scope"
        elif not bscope <= scope:
            return None, f"bot owned by subnets {sorted(bscope)}, outside share scope"
        elif direction == "in" and await self._bot_keyed(db, handle):
            return None, "bot has a locally provisioned link key (operator-owned)"
        clean: dict = {"handle": handle.lower()}
        if action == "DEL":
            self._copy_ts(rec, clean, ("updated_at", "deleted_at"))
            return clean, None
        if "hostmasks" in rec:
            masks = _hostmasks_json(rec["hostmasks"])
            if masks is None:
                return None, "invalid hostmasks"
            clean["hostmasks"] = masks
        if "address" in rec:
            addr = rec["address"]
            if not isinstance(addr, str) or not addr or len(addr) > 255 or " " in addr:
                return None, "invalid address"
            clean["address"] = addr
        if "port" in rec:
            port = rec["port"]
            if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
                return None, "invalid port"
            clean["port"] = port
        if "role" in rec:
            if rec["role"] not in _BOT_ROLES:
                return None, "invalid role"
            clean["role"] = rec["role"]
        if "comment" in rec:
            if rec["comment"] is not None and not isinstance(rec["comment"], str):
                return None, "invalid comment"
            clean["comment"] = (rec["comment"] or "")[:512]
        self._copy_ts(rec, clean, ("created_at", "updated_at"))
        # password, share_level, subnet_id, autolink* are local-only.
        return clean, None

    async def _botaccess(self, db, direction, action, rec, peer, scope):
        handle = rec.get("handle")
        if not _valid_handle(handle):
            return None, "invalid handle"
        if self._is_self_or_peer(handle, peer):
            return None, "access row of this bot or the peer itself"
        bscope = await self._bot_scope(db, handle)
        if not bscope:
            return None, "unknown bot or bot without stored subnet scope"
        if not bscope <= scope:
            return None, f"bot owned by subnets {sorted(bscope)}, outside share scope"
        if direction == "in" and await self._bot_keyed(db, handle):
            return None, "bot has a locally provisioned link key (operator-owned)"
        channel = rec.get("channel")
        if channel is not None:
            if not _valid_channel(channel):
                return None, "invalid channel"
            bound = await self._channel_bound(db, channel)
            if not bound:
                return None, f"channel {channel!r} is global (no subnet binding)"
            if not bound <= scope:
                return None, f"channel {channel!r} bound outside share scope"
        clean: dict = {"handle": handle.lower(), "channel": channel}
        for col in BOT_ACCESS_FLAGS:
            if col in rec:
                v = _flag(rec[col])
                if v is None:
                    return None, f"invalid {col}"
                clean[col] = v
        self._copy_ts(rec, clean, ("created_at", "updated_at"))
        return clean, None

    async def _channels(self, db, direction, action, rec, peer, scope):
        name = rec.get("name")
        if not _valid_channel(name):
            return None, "invalid channel name"
        async with db.execute(
            "SELECT name FROM channels WHERE LOWER(name) = LOWER(?)", (name,)
        ) as cur:
            row = await cur.fetchone()
        bound = await self._channel_bound(db, name)
        if row is not None or bound:
            if not bound:
                return None, "global channel (no subnet binding)"
            if not bound <= scope:
                return None, f"channel bound to subnets {sorted(bound)}, outside share scope"
            local_name = row["name"] if row is not None else name
            subnet_ids = sorted(bound)
            if direction == "in":
                claimed = self._claimed_subnets(rec)
                if claimed is None:
                    return None, "invalid subnet_ids"
                # an in-scope peer may add bindings, but only inside its scope
                subnet_ids = sorted(bound | (claimed & scope))
        else:
            if direction == "out":
                return None, "unknown channel"
            if action == "DEL":
                return None, "delete of unknown channel"
            claimed = self._claimed_subnets(rec)
            if not claimed:
                return None, "new channel without subnet binding would be global"
            if not claimed <= scope:
                return None, f"new channel claims subnets {sorted(claimed)}, outside share scope"
            known = await db.execute_fetchall(
                f"SELECT id FROM subnets WHERE id IN ({','.join('?' * len(claimed))})",
                tuple(claimed))
            if len(known) != len(claimed):
                return None, "new channel claims an unknown subnet"
            local_name = name
            subnet_ids = sorted(claimed)
        clean: dict = {"name": local_name}
        if action == "DEL":
            self._copy_ts(rec, clean, ("updated_at", "deleted_at"))
            return clean, None
        for col in _SYNC_ALLOWED_COLUMNS:
            if col not in rec:
                continue
            v = rec[col]
            if col in _CHANNEL_LIST_COLUMNS:
                if isinstance(v, list):
                    v = json.dumps(v)
                if not isinstance(v, str):
                    return None, f"invalid {col}"
            elif v is not None and (isinstance(v, (dict, list, float))):
                return None, f"invalid {col}"
            clean[col] = v
        self._copy_ts(rec, clean)
        clean["subnet_ids"] = subnet_ids
        return clean, None

    @staticmethod
    def _claimed_subnets(rec: dict) -> frozenset[int] | None:
        if "subnet_ids" in rec:
            raw = rec["subnet_ids"]
        elif rec.get("subnet_id") is not None:
            raw = [rec["subnet_id"]]
        else:
            raw = []
        if not isinstance(raw, list):
            return None
        if any(isinstance(s, bool) or not isinstance(s, int) for s in raw):
            return None
        return frozenset(raw)
