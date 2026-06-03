# src/user.py
"""
Handles user management for WBS IRC bot.
"""
import json
import bcrypt
import time
import logging
import fnmatch
from typing import List, Optional
from dataclasses import dataclass, asdict, field

from .db import get_db 

log = logging.getLogger("wbs.user")
GLOBAL_FLAGS: dict[str, str] = {
    'p': 'has_partyline',
    'A': 'is_admin',
    'n': 'is_owner',
    'f': 'is_friend',
    'a': 'is_autoop',
    'o': 'is_op',
    'd': 'is_deop',
    'y': 'is_autohop',
    'l': 'is_hop',
    'r': 'is_dehop',
    'v': 'is_voice',
    'q': 'is_devoice',
    'k': 'is_autokick',
}
CHAN_FLAGS: dict[str, str] = dict(GLOBAL_FLAGS)
VALID_FLAG_COLUMNS: frozenset[str] = frozenset(GLOBAL_FLAGS.values())

@dataclass
class User:
    """Maps to the 'users' table."""
    handle: str
    password: Optional[str] = None      # bcrypt hash
    hostmasks: List[str] = field(default_factory=list)
    is_locked: bool = False
    comment: str = ''
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))
    deleted_at: Optional[int] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    deleted_by: Optional[str] = None

    def __post_init__(self):
        # Normalize hostmasks: DB stores as JSON string, dataclass expects list
        if isinstance(self.hostmasks, str):
            try:
                self.hostmasks = json.loads(self.hostmasks) if self.hostmasks else []
            except (json.JSONDecodeError, ValueError):
                self.hostmasks = []

@dataclass
class UserAccess:
    handle: str
    channel: Optional[str] = None
    subnet_id: Optional[int] = None
    has_partyline: bool = False
    is_admin: bool = False
    is_owner: bool = False
    is_friend: bool = False
    is_autoop: bool = False
    is_op: bool = False
    is_deop: bool = False
    is_autohop: bool = False
    is_hop: bool = False
    is_dehop: bool = False
    is_voice: bool = False
    is_devoice: bool = False
    is_autokick: bool = False
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    deleted_at: Optional[int] = None
    deleted_by: Optional[str] = None

class UserManager:
    def __init__(self, db_path):
        self.db_path = db_path

    async def adduser(self, handle: str, hostmask: str = None,
                      subnet_id: int = None, added_by: str = None) -> bool:
        """
        Add a user. subnet_id scopes their default access entry.
        None = global (partyline access on all subnets).
        Handles resurrection of soft-deleted users.
        """
        now = int(time.time())
        hostmasks = json.dumps([hostmask] if hostmask else [])

        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT handle, deleted_at FROM users WHERE handle = ?", (handle,)
            ) as cur:
                row = await cur.fetchone()

            if row:
                if row[1] is None:
                    return False
                await db.execute(
                    "UPDATE users SET deleted_at = NULL, updated_at = ?, updated_by = ?, "
                    "hostmasks = ? WHERE handle = ?",
                    (now, added_by, hostmasks, handle)
                )
            else:
                await db.execute(
                    "INSERT INTO users (handle, hostmasks, created_at, created_by, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (handle, hostmasks, now, added_by, now)
                )

            # Create a default access entry scoped to subnet (or global if None)
            await db.execute(
                """INSERT OR IGNORE INTO user_access
                   (handle, channel, subnet_id, created_by, updated_at)
                   VALUES (?, NULL, ?, ?, ?)""",
                (handle, subnet_id, added_by, now)
            )
            await db.commit()
            return True

    async def deluser(self, handle: str, deleted_by: str = None) -> bool:
        """Soft-delete a user and their access entries."""
        now = int(time.time())
        async with get_db(self.db_path) as db:
            cur = await db.execute(
                "UPDATE users SET deleted_at = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (now, now, deleted_by, handle)
            )
            if cur.rowcount == 0:
                return False
            await db.execute(
                "UPDATE user_access SET deleted_at = ?, updated_at = ? WHERE handle = ?",
                (now, now, handle)
            )
            await db.commit()
            return True

    async def listusers(self) -> str:
        """List active (non-deleted) users."""
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT handle, comment, is_locked FROM users "
                "WHERE deleted_at IS NULL ORDER BY handle"
            )
            if not rows:
                return "No users."
            lines = ["Users:"]
            for r in rows:
                lock = " [LOCKED]" if r["is_locked"] else ""
                lines.append(f"  {r['handle']}{lock} - {r['comment'] or ''}")
            return "\n".join(lines)

    async def showuser(self, target_handle: str) -> str:
        """Show detailed info for specific user."""
        async with get_db(self.db_path) as db:
            user_cursor = await db.execute("""
                SELECT handle,
                    password IS NOT NULL AS has_pass,
                    hostmasks,
                    is_locked,
                    comment,
                    created_at,
                    updated_at
                FROM users
                WHERE handle = ?
            """, (target_handle,))

            user = await user_cursor.fetchone()
            await user_cursor.close()

            if user is None:
                return f"User '{target_handle}' not found."

            access_cursor = await db.execute("""
                SELECT channel,
                    subnet_id,
                    has_partyline,
                    is_admin,
                    is_owner,
                    is_autoop,                                          
                    is_op,
                    is_deop,
                    is_autohop,
                    is_hop,
                    is_dehop,                                        
                    is_voice,
                    is_devoice,                         
                    is_friend,
                    is_autokick,
                    created_at
                FROM user_access
                WHERE handle = ?
                ORDER BY channel ASC, subnet_id ASC
            """, (target_handle,))

            result = [f"User: {user['handle']}"]
            result.append(f"  Comment: {user['comment'] or 'None'}")
            result.append(f"  Password: {'Set' if user['has_pass'] else 'None'}")
            result.append(f"  Locked: {'Yes' if user['is_locked'] else 'No'}")
            result.append(f"  Hostmasks: {user['hostmasks']}")
            result.append("  Access:")

            has_access = False
            async for row in access_cursor:
                has_access = True
                flags = []

                if row['has_partyline']:
                    flags.append('p')
                if row['is_admin']:
                    flags.append('A')
                if row['is_op']:
                    flags.append('o')
                if row['is_voice']:
                    flags.append('v')
                if row['is_friend']:
                    flags.append('f')
                if row['is_owner']:
                    flags.append('n')
                if row['is_autoop']:
                    flags.append('a')
                if row['is_deop']:
                    flags.append('d')
                if row['is_autohop']:
                    flags.append('y')
                if row['is_hop']:
                    flags.append('l')
                if row['is_dehop']:
                    flags.append('r')
                if row['is_devoice']:
                    flags.append('q')
                if row['is_autokick']:
                    flags.append('k')

                subnet = "all subnets" if row['subnet_id'] is None else f"subnet {row['subnet_id']}"
                flag_str = ''.join(flags) if flags else '-'

                result.append(f"    {row['channel'] or '*'} ({subnet}): +{flag_str}")

            await access_cursor.close()

            if not has_access:
                result.append("    No access granted")

            return "\n".join(result)

    async def match_user(self, hostmask: str) -> Optional[str]:
        """
        Match a full nick!ident@host against stored glob-style hostmasks.
        Hostmasks are stored as a JSON array per user, e.g. ["*!*@*.bar.com"].
        """
        hostmask = hostmask.lower()
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT handle, hostmasks FROM users WHERE deleted_at IS NULL"
            )
        for row in rows:
            masks = row['hostmasks']
            if isinstance(masks, str):
                try:
                    masks = json.loads(masks) if masks else []
                except (json.JSONDecodeError, ValueError):
                    masks = []
            for mask in masks:
                if fnmatch.fnmatch(hostmask, mask.lower()):
                    return row['handle']
        return None

    async def set_password(self, handle: str, password: str) -> bool:
        """Hash and store password for handle. Returns False if handle not found."""
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else None
        async with get_db(self.db_path) as db:
            cur = await db.execute(
                "UPDATE users SET password = ? WHERE handle = ? AND deleted_at IS NULL",
                (hashed, handle)
            )
            await db.commit()
        return cur.rowcount > 0

    async def verify_password(self, handle: str, password: str) -> bool:
        """Verify a plaintext password against the stored bcrypt hash."""
        try:
            async with get_db(self.db_path) as db:
                async with db.execute(
                    "SELECT password FROM users WHERE handle = ? AND is_locked = 0",
                    (handle,)
                ) as cur:
                    row = await cur.fetchone()

            if not row:
                return False

            stored_hash = row["password"]
            if not stored_hash:
                return False

            return bool(bcrypt.checkpw(password.encode(), stored_hash.encode()))
        except (ValueError, TypeError):
            return False

    async def change_handle(self, handle: str, new_handle: str):
        async with get_db(self.db_path) as db:
            await db.execute("UPDATE users SET handle = ? WHERE handle = ?", (new_handle, handle))
            await db.commit()        

    async def matchattr(self, handle: str, flags: str, channel: Optional[str] = None) -> bool:
        """
        Replicates Eggdrop's matchattr behavior exactly.

        flags format: [+/-]<global>[|/&<channel>]
        +oA        → user has global o AND A
        -k         → user does NOT have global k
        o|o        → user has global o AND channel o (channel arg required)
        *|o        → user has channel o only (skip global check)
        o&o        → same as o|o (& and | are interchangeable in this impl)
        +o|v       → has global o AND channel v

        Returns False if handle is unknown.
        """
        if not flags or not handle:
            return False

        # Parse +/- prefix
        positive = True
        if flags.startswith('-'):
            positive = False
            flags = flags[1:]
        elif flags.startswith('+'):
            flags = flags[1:]

        # Split on | or & (only one separator allowed per Eggdrop spec)
        if '|' in flags:
            global_part, chan_part = flags.split('|', 1)
        elif '&' in flags:
            global_part, chan_part = flags.split('&', 1)
        else:
            global_part = flags
            chan_part = None

        # '*' as global_part means "skip global check, only check channel flags"
        skip_global = (global_part == '*')

        async with get_db(self.db_path) as db:
            # --- Global flag check ---
            if not skip_global and global_part:
                for char in global_part:
                    col = GLOBAL_FLAGS.get(char)
                    if col is None:
                        log.warning(f"matchattr: unknown global flag '{char}'")
                        return False

                    col = GLOBAL_FLAGS.get(char)
                    if col is None:
                        log.warning(f"matchattr: unknown global flag '{char}'")
                        return False
                    assert col in VALID_FLAG_COLUMNS, f"matchattr: col {col!r} not in allowlist" 

                    async with db.execute(
                        f"SELECT 1 FROM user_access WHERE handle = ? AND channel IS NULL "
                        f"AND deleted_at IS NULL AND {col} = 1 LIMIT 1",
                        (handle,)
                    ) as cur:
                        row = await cur.fetchone()

                    # Apply the same assert before the channel query block too
                    col = CHAN_FLAGS.get(char)
                    if col is None:
                        log.warning(f"matchattr: unknown channel flag '{char}'")
                        return False
                    assert col in VALID_FLAG_COLUMNS, f"matchattr: col {col!r} not in allowlist"
                    has_flag = row is not None
                    if positive and not has_flag:
                        return False
                    if not positive and has_flag:
                        return False

            # --- Channel flag check ---
            if chan_part is not None:
                if not channel:
                    # Channel flags requested but no channel given → False
                    return False

                for char in chan_part:
                    col = CHAN_FLAGS.get(char)
                    if col is None:
                        log.warning(f"matchattr: unknown channel flag '{char}'")
                        return False

                    async with db.execute(
                        f"""
                        SELECT 1 FROM user_access
                        WHERE handle = ?
                        AND channel = ?
                        AND deleted_at IS NULL
                        AND {col} = 1
                        LIMIT 1
                        """,
                        (handle, channel)
                    ) as cur:
                        row = await cur.fetchone()
                    has_flag = row is not None
                    if positive and not has_flag:
                        return False
                    if not positive and has_flag:
                        return False

        return True

    async def list_users(self) -> List[User]:
        """Return all active users as User dataclasses."""
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                """
                SELECT handle, password, hostmasks, is_locked, comment,
                    created_at, updated_at, created_by, updated_by,
                    deleted_at, deleted_by
                FROM users
                WHERE deleted_at IS NULL
                ORDER BY handle
                """
            )
        return [User(**dict(r)) for r in rows]
    
    async def list_users_with_flag(self, flag: str) -> list[User]:
        """Return all active users who have the given flag set on any access row.

        Args:
            flag: A valid flag column name from VALID_FLAG_COLUMNS
                (e.g. 'is_admin', 'has_partyline').
        Raises:
            ValueError: If flag is not a recognized column name.
        """
        if flag not in VALID_FLAG_COLUMNS:
            raise ValueError(f"Invalid flag column: {flag!r}")

        # flag is allowlisted — safe to interpolate as column name
        query = f"""
            SELECT DISTINCT u.handle, u.password, u.hostmasks, u.is_locked, u.comment,
                u.created_at, u.updated_at, u.created_by, u.updated_by,
                u.deleted_at, u.deleted_by
            FROM users u
            JOIN user_access ua ON u.handle = ua.handle
            WHERE u.deleted_at IS NULL
            AND ua.deleted_at IS NULL
            AND ua.{flag} = 1
            ORDER BY u.handle
        """
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(query)
        return [User(**dict(r)) for r in rows] 
        
    async def exist(self, handle: str) -> bool:
        """Return True if a user with this handle exists and is not deleted."""
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT 1 FROM users WHERE handle = ? AND deleted_at IS NULL",
                (handle,)
            ) as cur:
                row = await cur.fetchone()
        return row is not None

    def to_dict(self, user: User) -> dict:
        """Convert User to dict for DB INSERT/UPDATE."""
        data = asdict(user)
        data['hostmasks'] = json.dumps(data['hostmasks'])  # List -> JSON string
        return data

    def access_to_dict(self, access: UserAccess) -> dict:
        """Convert UserAccess to dict for DB INSERT/UPDATE."""
        return asdict(access)

    async def get(self, handle: str) -> Optional[User]:
        """
        Fetch a single active user by handle.
        Returns None if not found or soft-deleted.
        """
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT handle, password, hostmasks, is_locked, comment,
                    created_at, updated_at, created_by, updated_by,
                    deleted_at, deleted_by
                FROM users
                WHERE handle = ?
                AND deleted_at IS NULL
                """,
                (handle,)
            )
            row = await cursor.fetchone()
            await cursor.close()

        if row is None:
            return None

        return User(**dict(row))
    
    async def get_deleted(self, handle: str) -> Optional[User]:
        """
        Fetch a user by handle regardless of deleted status.
        Use only for admin inspection — not for permission checks.
        """
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT handle, password, hostmasks, is_locked, comment,
                    created_at, updated_at, created_by, updated_by,
                    deleted_at, deleted_by
                FROM users
                WHERE handle = ?
                """,
                (handle,)
            )
            row = await cursor.fetchone()
            await cursor.close()

        if row is None:
            return None

        return User(**dict(row))

    async def merge_from_peer(self, users: list[dict], from_bot: str) -> None:
        """Merge user records from a botnet peer. Last-write-wins on updated_at."""
        async with get_db(self.db_path) as db:
            for user in users:
                handle = user['handle'].lower()
                remote_updated = user.get('updated_at') or 0
                remote_deleted = user.get('deleted_at')

                cur = await db.execute(
                    "SELECT updated_at, deleted_at FROM users WHERE handle = ?", (handle,)
                )
                existing = await cur.fetchone()

                if existing:
                    if remote_updated <= (existing[0] or 0):
                        continue
                    final_deleted = remote_deleted
                    if remote_deleted is None and existing[1] and existing[1] > remote_updated:
                        final_deleted = existing[1]  # Keep more-recent local delete

                    pw = user.get('password')
                    if pw is not None and not pw.startswith(('$2b$', '$2a$', '$2y$')):
                        log.warning("merge_from_peer: rejecting non-bcrypt password for %s from %s", handle, from_bot)
                        # Keep existing local password — fetch it
                        cur2 = await db.execute("SELECT password FROM users WHERE handle = ?", (handle,))
                        existing_pw = await cur2.fetchone()
                        pw = existing_pw[0] if existing_pw else None

                    await db.execute(
                        """UPDATE users SET
                            password = ?, hostmasks = ?, is_locked = ?, comment = ?,
                            updated_at = ?, updated_by = ?, deleted_at = ?
                        WHERE handle = ?""",
                        (
                            pw, user.get('hostmasks', '[]'),
                            user.get('is_locked', 0), user.get('comment', ''),
                            remote_updated, from_bot, final_deleted, handle
                        )
                    )
                else:
                    await db.execute(
                        """INSERT INTO users
                            (handle, password, hostmasks, is_locked, comment,
                            created_at, updated_at, created_by, deleted_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            handle, user.get('password'), user.get('hostmasks', '[]'),
                            user.get('is_locked', 0), user.get('comment', ''),
                            user.get('created_at', 0), remote_updated,
                            from_bot, remote_deleted
                        )
                    )
            await db.commit()
        log.info(f"UserManager.merge_from_peer: merged {len(users)} users from {from_bot}")

    async def merge_access_from_peer(self, access_list: list[dict], from_bot: str) -> None:
        """Merge user_access records from a botnet peer. Last-write-wins on updated_at."""
        async with get_db(self.db_path) as db:
            for acc in access_list:
                handle = acc['handle'].lower()
                channel = acc.get('channel')
                subnet_id = acc.get('subnet_id')
                remote_updated = acc.get('updated_at') or 0
                remote_deleted = acc.get('deleted_at')

                cur = await db.execute(
                    "SELECT 1 FROM users WHERE handle = ?", (handle,)
                )
                if not await cur.fetchone():
                    now = int(time.time())
                    await db.execute(
                        """INSERT OR IGNORE INTO users
                        (handle, hostmasks, created_at, updated_at, created_by)
                        VALUES (?, '[]', ?, ?, ?)""",
                        (handle, now, now, from_bot)
                    )

                cur = await db.execute(
                    """SELECT updated_at, deleted_at FROM user_access
                    WHERE handle = ?
                        AND (channel = ? OR (channel IS NULL AND ? IS NULL))
                        AND (subnet_id = ? OR (subnet_id IS NULL AND ? IS NULL))""",
                    (handle, channel, channel, subnet_id, subnet_id)
                )
                existing = await cur.fetchone()
                if existing:
                    if remote_updated <= (existing[0] or 0):
                        continue
                    final_deleted = remote_deleted
                    if remote_deleted is None and existing[1] and existing[1] > remote_updated:
                        final_deleted = existing[1]

                    await db.execute(
                        """UPDATE user_access SET
                            has_partyline=?, is_admin=?, is_owner=?, is_friend=?,
                            is_autoop=?, is_op=?, is_deop=?,
                            is_autohop=?, is_hop=?, is_dehop=?,
                            is_voice=?, is_devoice=?, is_autokick=?,
                            updated_at=?, updated_by=?, deleted_at=?
                        WHERE handle=?
                            AND (channel=? OR (channel IS NULL AND ? IS NULL))
                            AND (subnet_id=? OR (subnet_id IS NULL AND ? IS NULL))""",
                        (
                            acc.get('has_partyline', 0), acc.get('is_admin', 0),
                            acc.get('is_owner', 0), acc.get('is_friend', 0),
                            acc.get('is_autoop', 0), acc.get('is_op', 0), acc.get('is_deop', 0),
                            acc.get('is_autohop', 0), acc.get('is_hop', 0), acc.get('is_dehop', 0),
                            acc.get('is_voice', 0), acc.get('is_devoice', 0), acc.get('is_autokick', 0),
                            remote_updated, from_bot, final_deleted,
                            handle, channel, channel, subnet_id, subnet_id
                        )
                    )
                else:
                    await db.execute(
                        """INSERT INTO user_access (
                            handle, channel, subnet_id,
                            has_partyline, is_admin, is_owner, is_friend,
                            is_autoop, is_op, is_deop,
                            is_autohop, is_hop, is_dehop,
                            is_voice, is_devoice, is_autokick,
                            created_at, updated_at, created_by, deleted_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            handle, channel, subnet_id,
                            acc.get('has_partyline', 0), acc.get('is_admin', 0),
                            acc.get('is_owner', 0), acc.get('is_friend', 0),
                            acc.get('is_autoop', 0), acc.get('is_op', 0), acc.get('is_deop', 0),
                            acc.get('is_autohop', 0), acc.get('is_hop', 0), acc.get('is_dehop', 0),
                            acc.get('is_voice', 0), acc.get('is_devoice', 0), acc.get('is_autokick', 0),
                            acc.get('created_at', 0), remote_updated, from_bot, remote_deleted
                        )
                    )
            await db.commit()
        log.info(f"UserManager.merge_access_from_peer: merged {len(access_list)} rows from {from_bot}")

    async def serialize_for_peer(self) -> list[dict]:
        """Return all users (including soft-deleted) for botnet share. Passwords included."""
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                """SELECT handle, password, hostmasks, is_locked, comment,
                        created_at, updated_at, created_by, updated_by,
                        deleted_at, deleted_by
                FROM users"""
            )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def serialize_access_for_peer(self) -> list[dict]:
        """Return all user_access rows for botnet share."""
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                """SELECT handle, channel, subnet_id,
                        has_partyline, is_admin, is_owner, is_friend,
                        is_autoop, is_op, is_deop,
                        is_autohop, is_hop, is_dehop,
                        is_voice, is_devoice, is_autokick,
                        created_at, updated_at, created_by, deleted_at
                FROM user_access"""
            )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]     

    async def authenticate(self, handle: str, password: str) -> bool:
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT password_hash, locked FROM users "
                "WHERE handle = ? AND deleted_at IS NULL",
                (handle,)
            ) as cursor:
                row = await cursor.fetchone()
        if row is None or row[1]:
            return False
        return self.verify_password(password, row[0])      
    
    async def addhost(self, handle: str, hostmask: str, updated_by: str = None) -> str:
        """
        Add a hostmask to a user's hostmask list.

        Returns:
            "ok"           – hostmask added successfully
            "not_found"    – user does not exist or is deleted
            "duplicate"    – hostmask already present
            "invalid"      – hostmask format is wrong (missing ! or @)
        """
        if "!" not in hostmask or "@" not in hostmask:
            return "invalid"

        now = int(time.time())
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                "SELECT hostmasks FROM users WHERE handle = ? AND deleted_at IS NULL",
                (handle,),
            )
            row = await cursor.fetchone()
            if row is None:
                return "not_found"

            try:
                masks: list[str] = json.loads(row["hostmasks"]) if row["hostmasks"] else []
            except (json.JSONDecodeError, ValueError):
                masks = []

            if hostmask in masks:
                return "duplicate"

            masks.append(hostmask)
            await db.execute(
                "UPDATE users SET hostmasks = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (json.dumps(masks), now, updated_by, handle),
            )
            await db.commit()
        return "ok"


    async def delhost(self, handle: str, hostmask: str, updated_by: str = None) -> str:
        """
        Remove a hostmask from a user's hostmask list.

        Returns:
            "ok"           – hostmask removed successfully
            "not_found"    – user does not exist or is deleted
            "no_such_host" – hostmask not in user's list
            "invalid"      – hostmask format is wrong (missing ! or @)
        """
        if "!" not in hostmask or "@" not in hostmask:
            return "invalid"

        now = int(time.time())
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                "SELECT hostmasks FROM users WHERE handle = ? AND deleted_at IS NULL",
                (handle,),
            )
            row = await cursor.fetchone()
            if row is None:
                return "not_found"

            try:
                masks: list[str] = json.loads(row["hostmasks"]) if row["hostmasks"] else []
            except (json.JSONDecodeError, ValueError):
                masks = []

            if hostmask not in masks:
                return "no_such_host"

            masks.remove(hostmask)
            await db.execute(
                "UPDATE users SET hostmasks = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (json.dumps(masks), now, updated_by, handle),
            )
            await db.commit()
        return "ok"    