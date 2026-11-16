# src/bot.py
"""
Handles bot management for WBS IRC bot.
"""
import json
import time
import logging
from typing import Optional, Literal
from dataclasses import dataclass, asdict, field

from . import crypto_exec
from .db import get_db 

log = logging.getLogger("wbs.bot")
_FLAG_MAP: dict[str, str] = {
    'p': 'has_partyline',
    'o': 'is_op',
    'd': 'is_deop',
    'v': 'is_voice',
    'q': 'is_devoice',
    'f': 'is_friend',
    'l': 'is_hop',
    'r': 'is_dehop',
}
_BOT_FLAG_COLUMNS: frozenset[str] = frozenset(_FLAG_MAP.values())

@dataclass
class Bot:
    """Maps to the 'bots' table. All fields mirror the schema exactly."""
    handle: str

    # Credentials & identity
    password: Optional[str] = None
    hostmasks: list[str] = field(default_factory=list)

    # Connection
    address: str = 'localhost'
    port: int = 3333

    # Botnet role
    role: Literal['hub', 'backup', 'leaf', 'none'] = 'none'
    share_level: str = 'subnet'
    autolink: bool = False
    autolink_retry_interval: int = 60
    subnet_id: Optional[int] = None

    # Metadata
    comment: str = ''
    created_at: int = field(default_factory=lambda: int(time.time()))
    created_by: Optional[str] = None
    updated_at: int = field(default_factory=lambda: int(time.time()))
    updated_by: Optional[str] = None
    deleted_at: Optional[int] = None
    deleted_by: Optional[str] = None

    def __post_init__(self):
        if isinstance(self.hostmasks, str):
            try:
                self.hostmasks = json.loads(self.hostmasks) if self.hostmasks.strip() else []
            except json.JSONDecodeError:
                log.warning(f"Invalid hostmasks JSON for {self.handle}: {self.hostmasks}")
                self.hostmasks = []

@dataclass
class BotAccess:
    """Maps to the 'bot_access' table — exactly mirrors the schema, no more."""
    handle: str
    channel: Optional[str] = None
    # Removed: subnet_id, is_admin, is_bot — none exist in bot_access schema
    has_partyline: bool = False
    is_op: bool = False
    is_deop: bool = False
    is_voice: bool = False
    is_devoice: bool = False
    is_friend: bool = False
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))
    created_by: Optional[str] = None
    updated_by: Optional[str] = None

class BotManager:

    def __init__(self, db_path):
        self.db_path = db_path

    async def set_password(self, handle: str, password: str) -> bool:
        """Hash and store a bot's password. Returns True if the bot was found and updated."""
        hashed = await crypto_exec.hash_password(password) if password else ''
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                "UPDATE bots SET password = ? WHERE LOWER(handle) = LOWER(?)",
                (hashed, handle)
            )
            await db.commit()
        
        if cursor.rowcount == 0:
            log.warning(f"set_password: bot '{handle}' not found — no rows updated")
            return False

        log.info(f"set_password: password updated for bot '{handle}'")
        return True

    async def matchattr(self, handle: str, flags: str, channel: Optional[str] = None) -> bool:
        """
        Check whether a bot has all flags in the flag string.

        flags format (eggdrop-style):
            '+opf'  → must have ALL of: is_op, has_partyline, is_friend
            '-opf'  → must have NONE of: is_op, has_partyline, is_friend
            'opf'   → same as '+opf' (positive assumed when no prefix)

        channel=None checks the global record (channel IS NULL).
        channel='#foo' checks the channel-scoped record for #foo.

        Returns False if the bot or access record doesn't exist,
        or if any unrecognised flag character is present.
        """
        if not flags:
            return False

        # Parse prefix
        if flags[0] in ('+', '-'):
            require_all = flags[0] == '+'
            flag_chars = flags[1:]
        else:
            require_all = True
            flag_chars = flags

        if not flag_chars:
            return False
        columns = [_FLAG_MAP[c] for c in flag_chars]

        # Validate all chars are known before hitting the DB
        unknown = [c for c in flag_chars if c not in _FLAG_MAP]
        if unknown:
            log.warning(
                f"matchattr: unknown flag chars {unknown!r} for bot '{handle}'"
            )
            return False

        for col in columns:
            if col not in _BOT_FLAG_COLUMNS:
                raise ValueError(f"matchattr: disallowed bot flag column: {col!r}")

        col_select = ", ".join(columns)
        async with get_db(self.db_path) as db:
            if channel is None:
                async with db.execute(
                    f"SELECT {col_select} FROM bot_access "
                    "WHERE LOWER(handle) = LOWER(?) AND channel IS NULL",
                    (handle,),
                ) as cur:
                    row = await cur.fetchone()
            else:
                async with db.execute(
                    f"SELECT {col_select} FROM bot_access "
                    "WHERE LOWER(handle) = LOWER(?) AND channel = ?",
                    (handle, channel),
                ) as cur:
                    row = await cur.fetchone()

        if row is None:
            return False  # No access record — bot has no flags here

        values = [bool(row[col]) for col in columns]

        if require_all:
            return all(values)      # '+opf' → must have every flag
        else:
            return not any(values)  # '-opf' → must have none

    async def addbot(self, handle: str, hostmask: Optional[str], address: Optional[str],
                    port: Optional[int], created_by: Optional[str] = None) -> bool:
        """Add bot. Returns True if created. Raises ValueError if handle already exists."""
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT 1 FROM bots WHERE LOWER(handle) = LOWER(?)", (handle,)
            ) as cursor:
                if await cursor.fetchone():
                    raise ValueError(f"Bot '{handle}' already exists")

            hostmasks_json = json.dumps([hostmask]) if hostmask else '[]'
            await db.execute(
                """INSERT INTO bots (handle, hostmasks, address, port, created_by)
                VALUES (?, ?, ?, ?, ?)""",
                (handle.lower(), hostmasks_json, address, port, created_by)
            )
        return True
            
    async def delbot(self, target_handle: str) -> bool:
        """Delete a bot by handle. Returns True if deleted, False if not found."""
        async with get_db(self.db_path) as db:
            # Check existence first (case-insensitive, like exist(); NET-6)
            async with db.execute(
                "SELECT 1 FROM bots WHERE LOWER(handle) = LOWER(?) AND deleted_at IS NULL",
                (target_handle,)
            ) as cursor:
                if not await cursor.fetchone():
                    return False 

            # Delete and capture rowcount before commit
            async with db.execute(
                "DELETE FROM bots WHERE LOWER(handle) = LOWER(?)",
                (target_handle,)
            ) as cursor:
                rowcount = cursor.rowcount

            await db.commit()
        return rowcount > 0
        
    async def exist(self, handle: str) -> bool:
        """Return True if a bot with this handle exists and is not deleted."""
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT 1 FROM bots WHERE LOWER(handle) = LOWER(?) AND deleted_at IS NULL",
                (handle,)
            ) as cur:
                row = await cur.fetchone()
        return row is not None

    async def get(self, handle: str) -> Bot:
        async with get_db(self.db_path) as db:
            async with db.execute(
                """SELECT handle, password, hostmasks, address, port,
                        role, share_level, autolink, autolink_retry_interval,
                        subnet_id, comment, created_at, created_by,
                        updated_at, updated_by, deleted_at, deleted_by
                FROM bots WHERE LOWER(handle) = LOWER(?)""",
                (handle,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    raise ValueError(f"Bot '{handle}' not found")

                return Bot(
                    handle=row['handle'],
                    password=row['password'],
                    hostmasks=json.loads(row['hostmasks'] or '[]'),
                    address=row['address'],
                    port=row['port'],
                    role=row['role'],
                    share_level=row['share_level'],
                    autolink=bool(row['autolink']),
                    autolink_retry_interval=row['autolink_retry_interval'],
                    subnet_id=row['subnet_id'],
                    comment=row['comment'] or '',
                    created_at=row['created_at'] or 0,
                    created_by=row['created_by'],
                    updated_at=row['updated_at'] or 0,
                    updated_by=row['updated_by'],
                    deleted_at=row['deleted_at'],
                    deleted_by=row['deleted_by'],
                )

    async def chpass(self, name: str, password: str):
        """Update botlink password in database."""
        try:
            async with get_db(self.db_path) as db:
                await db.execute(
                    "UPDATE bots SET password = ? WHERE LOWER(handle) = LOWER(?)",
                    (password, name)
                )
                await db.commit()
                log.info(f"Updated password for botlink {name}")
                
        except Exception as e:
            log.error(f"Failed to update botlink {name}: {e}")

    def to_dict(self, bot: Bot) -> dict:
        """Convert Bot to dict for DB operations."""
        data = asdict(bot)  # dataclasses.asdict(bot)
        data['hostmasks'] = json.dumps(data['hostmasks'])  # Convert list back to JSON
        return data

    async def save(self, bot: Bot, updated_by: Optional[str] = None) -> None:
        """Upsert a Bot into the database."""
        now = int(time.time())
        async with get_db(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO bots (handle, password, hostmasks, address, port,
                                role, share_level, autolink, autolink_retry_interval,
                                subnet_id, comment, created_at, created_by,
                                updated_at, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(handle) DO UPDATE SET
                    password                = excluded.password,
                    hostmasks               = excluded.hostmasks,
                    address                 = excluded.address,
                    port                    = excluded.port,
                    role                    = excluded.role,
                    share_level             = excluded.share_level,
                    autolink                = excluded.autolink,
                    autolink_retry_interval = excluded.autolink_retry_interval,
                    subnet_id               = excluded.subnet_id,
                    comment                 = excluded.comment,
                    updated_at              = ?,
                    updated_by              = ?
                """,
                (
                    bot.handle.lower(), bot.password,
                    json.dumps(bot.hostmasks),
                    bot.address, bot.port,
                    bot.role, bot.share_level,
                    int(bot.autolink), bot.autolink_retry_interval,
                    bot.subnet_id, bot.comment,
                    bot.created_at, bot.created_by,
                    now, updated_by,
                    # ON CONFLICT bindings
                    now, updated_by,
                )
            )

    async def get_subnet_ids(self, handle: str) -> list[int]:
        """Return all subnet_ids bound to this bot. Empty list = global."""
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT subnet_id FROM bot_subnets WHERE LOWER(bot_handle) = LOWER(?) ORDER BY subnet_id",
                (handle,)
            )
        return [row["subnet_id"] for row in rows]

    async def get_subnet_scope(self, handle: str) -> frozenset[int] | None:
        """
        Authoritative subnet scope of a bot, from local stored data only (SAST-002).

        Scope = bots.subnet_id plus every live bot_subnets binding.  Never taken
        from a peer's handshake or payload (bots.subnet_id and bot_subnets are
        not written by peer replication).

        Returns None when no bot row exists (the handle is not a bot), and an
        empty frozenset for a soft-deleted bot or one with no stored subnet:
        callers must treat an empty scope as *unknown* and deny.
        """
        key = (handle or "").lower()
        if not key:
            return None
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT subnet_id, deleted_at FROM bots WHERE LOWER(handle) = ?",
                (key,),
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                return None
            if row["deleted_at"] is not None:
                return frozenset()
            rows = await db.execute_fetchall(
                "SELECT subnet_id FROM bot_subnets "
                "WHERE LOWER(bot_handle) = ? AND deleted_at IS NULL",
                (key,),
            )
        ids = {int(r["subnet_id"]) for r in rows if r["subnet_id"] is not None}
        if row["subnet_id"] is not None:
            ids.add(int(row["subnet_id"]))
        return frozenset(ids)

    async def is_global(self, handle: str) -> bool:
        """A bot with no subnet bindings is active on all subnets."""
        return len(await self.get_subnet_ids(handle)) == 0

    async def bind_to_subnet(self, handle: str, subnet_id: int,
                              created_by: Optional[str] = None) -> bool:
        """Bind a bot to a specific subnet."""
        async with get_db(self.db_path) as db:
            async with db.execute(
                """INSERT OR IGNORE INTO bot_subnets (bot_handle, subnet_id, created_by)
                VALUES (?, ?, ?)""",
                (handle.lower(), subnet_id, created_by)
            ) as cursor:
                rowcount = cursor.rowcount
        return rowcount > 0

    async def unbind_from_subnet(self, handle: str, subnet_id: int) -> bool:
        """Remove a specific subnet binding from a bot."""
        async with get_db(self.db_path) as db:
            async with db.execute(
                "DELETE FROM bot_subnets WHERE LOWER(bot_handle) = LOWER(?) AND subnet_id = ?",
                (handle, subnet_id)
            ) as cursor:
                rowcount = cursor.rowcount
        return rowcount > 0

    async def make_global(self, handle: str) -> bool:
        """Remove all subnet bindings — bot becomes active on all subnets."""
        async with get_db(self.db_path) as db:
            async with db.execute(
                "DELETE FROM bot_subnets WHERE LOWER(bot_handle) = LOWER(?)",
                (handle,)
            ) as cursor:
                rowcount = cursor.rowcount
        return rowcount > 0

    async def get_bots_for_subnet(self, subnet_id: int) -> list[str]:
        """
        Return handles of all bots active on a given subnet:
        bots explicitly bound to it OR bots with no subnet binding (global).
        """
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                """
                SELECT b.handle FROM bots b
                WHERE b.deleted_at IS NULL
                  AND (
                    EXISTS (
                      SELECT 1 FROM bot_subnets bs
                      WHERE bs.bot_handle = b.handle AND bs.subnet_id = ?
                    )
                    OR NOT EXISTS (
                      SELECT 1 FROM bot_subnets bs2
                      WHERE bs2.bot_handle = b.handle
                    )
                  )
                ORDER BY b.handle
                """,
                (subnet_id,)
            )
        return [row["handle"] for row in rows]
    
    async def get_autolink_peers(self) -> list[dict]:
        """Return all bots configured for auto-linking."""
        async with get_db(self.db_path) as db:
            async with db.execute(
                """
                SELECT handle, address, port, autolink_retry_interval
                FROM bots
                WHERE autolink = 1
                AND deleted_at IS NULL
                """
            ) as cursor:
                rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # Bot fields a peer may replicate (SAST-003); everything else is local-only.
    _PEER_BOT_FIELDS = ("hostmasks", "address", "port", "role", "comment")
    _PEER_BOT_ACCESS_FLAGS = ("has_partyline", "is_op", "is_deop", "is_hop", "is_dehop",
                              "is_voice", "is_devoice", "is_friend")

    async def merge_from_peer(self, bots: list[dict], from_bot: str) -> None:
        """
        Merge bot records received from a botnet peer.
        - Never overwrites local password
        - Last-write-wins on updated_at
        - Skips self-reference
        """
        async with get_db(self.db_path) as db:
            for bot in bots:
                handle = bot['handle'].lower()

                if handle == from_bot.lower():
                    # Don't overwrite our own record with peer's copy
                    continue

                cur = await db.execute(
                    "SELECT password, updated_at FROM bots WHERE LOWER(handle) = ?", (handle,)
                )
                existing = await cur.fetchone()
                remote_updated = bot.get('updated_at') or 0

                if existing:
                    if remote_updated <= (existing[1] or 0):
                        continue  # Local is newer or equal
                    # Local-only (never from a peer, SAST-001/002/003): password,
                    # share_level, subnet_id, autolink*.  Only carried fields change.
                    fields = {k: bot[k] for k in self._PEER_BOT_FIELDS if k in bot}
                    if 'hostmasks' in fields and not isinstance(fields['hostmasks'], str):
                        fields['hostmasks'] = json.dumps(fields['hostmasks'])
                    fields.update(updated_at=remote_updated, updated_by=from_bot)
                    set_clause = ", ".join(f"{k} = ?" for k in fields)  # fixed allowlist
                    await db.execute(
                        f"UPDATE bots SET {set_clause} "
                        "WHERE LOWER(handle) = ? AND (updated_at IS NULL OR updated_at < ?)",
                        (*fields.values(), handle, remote_updated),
                    )
                else:
                    # New bots arrive inert: no key, no subnet scope, share=none.
                    masks = bot.get('hostmasks', '[]')
                    if not isinstance(masks, str):
                        masks = json.dumps(masks)
                    await db.execute(
                        """
                        INSERT INTO bots
                            (handle, hostmasks, address, port, role, share_level,
                            comment, created_at, updated_at, created_by)
                        VALUES (?, ?, ?, ?, ?, 'none', ?, ?, ?, ?)
                        """,
                        (
                            handle, masks,
                            bot.get('address', 'localhost'), bot.get('port', 3333),
                            bot.get('role', 'none'),
                            bot.get('comment', ''), bot.get('created_at', 0),
                            remote_updated, from_bot
                        )
                    )

            await db.commit()
        log.info(f"BotManager.merge_from_peer: merged {len(bots)} bots from {from_bot}")

    async def merge_access_from_peer(self, access_list: list[dict], from_bot: str) -> None:
        """
        Merge bot_access records from a peer.
        PK is (handle, channel). Last-write-wins.
        Skips own bot's access records.
        Only writes columns that exist in bot_access schema.
        """
        async with get_db(self.db_path) as db:
            for acc in access_list:
                handle = acc['handle'].lower()
                channel = acc.get('channel')  # May be NULL
                remote_updated = acc.get('updated_at') or 0

                if handle == from_bot.lower():
                    log.debug(f"merge_access_from_peer: skipping own record from {from_bot}")
                    continue

                cur = await db.execute(
                    """SELECT updated_at FROM bot_access
                    WHERE handle = ?
                        AND (channel = ? OR (channel IS NULL AND ? IS NULL))""",
                    (handle, channel, channel)
                )
                existing = await cur.fetchone()

                flags = {k: int(bool(acc[k])) for k in self._PEER_BOT_ACCESS_FLAGS if k in acc}
                if existing:
                    if remote_updated <= (existing[0] or 0):
                        continue
                    fields = dict(flags, updated_at=remote_updated, updated_by=from_bot)
                    set_clause = ", ".join(f"{k} = ?" for k in fields)  # fixed allowlist
                    await db.execute(
                        f"UPDATE bot_access SET {set_clause} WHERE handle = ? "
                        "AND (channel = ? OR (channel IS NULL AND ? IS NULL))",
                        (*fields.values(), handle, channel, channel),
                    )
                else:
                    cols = ["handle", "channel", *flags, "created_at", "updated_at", "created_by"]
                    vals = [handle, channel, *flags.values(),
                            acc.get('created_at', 0), remote_updated, from_bot]
                    await db.execute(
                        f"INSERT INTO bot_access ({', '.join(cols)}) "
                        f"VALUES ({', '.join('?' * len(cols))})",
                        vals,
                    )

            await db.commit()
        log.info(f"BotManager.merge_access_from_peer: merged {len(access_list)} rows from {from_bot}")

    async def serialize_for_peer(self, exclude_handle: str) -> list[dict]:
        """
        Return bots for botnet share — exclude self and soft-deleted bots.
        The password column holds botlink pre-shared keys (AUTH2, SAST-001)
        and is never sent to peers: a peer that learned another pair's key
        could impersonate either bot.  merge_from_peer() never stores a
        peer-supplied password either.
        """
        async with get_db(self.db_path) as db:
            async with db.execute(
                """SELECT handle, hostmasks, address, port, role,
                        share_level, autolink, autolink_retry_interval,
                        subnet_id, comment, created_at, updated_at
                FROM bots
                WHERE handle != ?
                AND deleted_at IS NULL""",
                (exclude_handle.lower(),)
            ) as cursor:
                rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def serialize_access_for_peer(self) -> list[dict]:
        """Return bot_access rows for botnet share."""
        async with get_db(self.db_path) as db:
            cursor = await db.execute("SELECT * FROM bot_access")
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def delete_from_peer(self, payload: dict, from_bot: str) -> None:
        """
        Soft-delete a bot received via botnet UPDATE BOT DEL (after
        ReplicationPolicy approval).  A delete older than the local record's
        last update loses; bots with a locally provisioned link key are never
        deleted by a peer; nothing is hard-deleted.
        """
        handle = (payload.get("handle") or "").strip().lower()
        if not handle:
            log.warning("delete_from_peer: missing handle in payload from %s", from_bot)
            return
        remote_ts = payload.get("deleted_at") or payload.get("updated_at")
        ts = remote_ts or int(time.time())
        async with get_db(self.db_path) as db:
            cur = await db.execute(
                "UPDATE bots SET deleted_at = ?, deleted_by = ?, updated_at = ?, updated_by = ? "
                "WHERE LOWER(handle) = ? AND deleted_at IS NULL "
                "AND (password IS NULL OR password = '') "
                "AND (? IS NULL OR updated_at IS NULL OR updated_at <= ?)",
                (ts, from_bot, ts, from_bot, handle, remote_ts, remote_ts))
            if cur.rowcount:
                await db.execute(
                    "UPDATE bot_access SET deleted_at = ?, deleted_by = ? "
                    "WHERE LOWER(handle) = ? AND deleted_at IS NULL", (ts, from_bot, handle))
        log.info("BotManager.delete_from_peer: %s bot '%s' from %s",
                 "deleted" if cur.rowcount else "kept", handle, from_bot)