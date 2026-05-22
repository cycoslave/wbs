# src/user.py
"""
Handles user management for WBS IRC bot.
"""
import aiosqlite
import sqlite3
import json
import bcrypt
import time
import logging
import fnmatch
from typing import List, Optional, Dict
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
CHAN_FLAGS = GLOBAL_FLAGS 

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
    """Maps to the 'user_access' table."""
    handle: str
    channel: Optional[str] = None
    subnet_id: Optional[int] = None
    has_partyline: bool = False
    is_admin: bool = False
    is_bot: bool = False
    is_op: bool = False
    is_deop: bool = False
    is_voice: bool = False
    is_devoice: bool = False
    is_friend: bool = False
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))
    created_by: Optional[str] = None
    updated_by: Optional[str] = None


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
        import time
        now = int(time.time())
        hostmasks = json.dumps([hostmask] if hostmask else [])

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")
            async with db.execute(
                "SELECT handle, deleted_at FROM users WHERE handle = ?", (handle,)
            ) as cur:
                row = await cur.fetchone()

            if row:
                if row[1] is None:
                    return False  # Already exists and active
                # Resurrect
                await db.execute(
                    "UPDATE users SET deleted_at = NULL, updated_at = ?, updated_by = ?, "
                    "hostmasks = ? WHERE handle = ?",
                    (now, added_by, hostmasks, handle)
                )
            else:
                await db.execute(
                    "INSERT INTO users (handle, hostmasks, created_by, updated_at) "
                    "VALUES (?, ?, ?, ?)",
                    (handle, hostmasks, added_by, now)
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
        import time
        now = int(time.time())
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "UPDATE users SET deleted_at = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (now, now, deleted_by, handle)
            )
            if cur.rowcount == 0:
                await db.commit()
                return False
            # Soft-delete all access rows too
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

    async def set_password(self, handle: str, password: str):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else ''
        async with get_db(self.db_path) as db:
            await db.execute("UPDATE users SET password = ? WHERE handle = ?", (hashed, handle))
            await db.commit()

    async def verify_password(self, handle: str, password: str) -> bool:
        """Verify a plaintext password against the stored bcrypt hash."""
        try:
            async with get_db(self.db_path) as db:
                row = await db.execute_fetchone(
                    "SELECT password FROM users WHERE handle = ? AND is_locked = 0",
                    (handle,)
                )

            if not row:
                return False

            stored_hash = row["password"]
            if not stored_hash:
                return False

            return bool(bcrypt.checkpw(password.encode(), stored_hash.encode()))
        except Exception:
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

                    row = await db.execute_fetchone(
                        f"""
                        SELECT 1 FROM user_access
                        WHERE handle = ?
                        AND channel IS NULL
                        AND deleted_at IS NULL
                        AND {col} = 1
                        LIMIT 1
                        """,
                        (handle,)
                    )
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

                    row = await db.execute_fetchone(
                        f"""
                        SELECT 1 FROM user_access
                        WHERE handle = ?
                        AND channel = ?
                        AND deleted_at IS NULL
                        AND {col} = 1
                        LIMIT 1
                        """,
                        (handle, channel)
                    )
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
    
    async def list_users_with_flag(self, flag: str) -> List[User]:
        """
        Example: flag='is_admin' returns users who have at least one
        admin access row.  Extend as needed.
        """
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                f"""
                SELECT DISTINCT u.handle, u.password, u.hostmasks, u.is_locked,
                    u.comment, u.created_at, u.updated_at, u.created_by,
                    u.updated_by, u.deleted_at, u.deleted_by
                FROM users u
                JOIN user_access ua ON ua.handle = u.handle
                WHERE u.deleted_at IS NULL
                AND ua.deleted_at IS NULL
                AND ua.{flag} = 1
                ORDER BY u.handle
                """
            )
        return [User(**dict(r)) for r in rows]    
        
    def exist(self, user: str):
        """Check if user exists."""
        try:
            with sqlite3.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                cursor = db.execute("SELECT 1 FROM users WHERE handle = ?", (user.lower(),))
                return cursor.fetchone() is not None
        except sqlite3.Error:
            return False        

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

    async def sync_user(self, user: User, updated_by: Optional[str] = None) -> None:
        """
        Upsert a User into the database.

        - Inserts if handle doesn't exist
        - Updates real schema columns on conflict
        - Updates last_seen on the global user_access row (channel IS NULL)
        """
        now = int(time.time())
        hostmasks_json = json.dumps(user.hostmasks)

        async with get_db(self.db_path) as db:
            # Upsert the users row
            await db.execute(
                """
                INSERT INTO users (
                    handle, password, hostmasks, is_locked, comment,
                    created_at, updated_at, created_by, updated_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(handle) DO UPDATE SET
                    password    = excluded.password,
                    hostmasks   = excluded.hostmasks,
                    is_locked   = excluded.is_locked,
                    comment     = excluded.comment,
                    updated_at  = ?,
                    updated_by  = ?
                """,
                (
                    user.handle,
                    user.password,
                    hostmasks_json,
                    user.is_locked,
                    user.comment,
                    user.created_at,
                    now,
                    user.created_by,
                    updated_by,
                    # ON CONFLICT SET bindings
                    now,
                    updated_by,
                )
            )

            # Update last_seen on the global access row if it exists
            await db.execute(
                """
                UPDATE user_access
                SET last_seen = ?
                WHERE handle = ?
                AND channel IS NULL
                AND deleted_at IS NULL
                """,
                (now, user.handle)
            )

            await db.commit()