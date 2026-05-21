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
    created_by: Optional[str] = None
    updated_by: Optional[str] = None

    def __post_init__(self):
        # Normalize hostmasks if it comes from DB as JSON string
        if isinstance(self.hostmasks, str):
            self.hostmasks = json.loads(self.hostmasks) if self.hostmasks else []

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
                    last_seen,
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
                    is_op,
                    is_voice,
                    is_friend,
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
            result.append(f"  Last seen: {user['last_seen'] or 'Never'}")
            result.append("  Access:")

            has_access = False
            async for row in access_cursor:
                has_access = True
                flags = []

                if row['has_partyline']:
                    flags.append('P')
                if row['is_admin']:
                    flags.append('A')
                if row['is_op']:
                    flags.append('O')
                if row['is_voice']:
                    flags.append('V')
                if row['is_friend']:
                    flags.append('F')

                subnet = "all subnets" if row['subnet_id'] is None else f"subnet {row['subnet_id']}"
                flag_str = ''.join(flags) if flags else '-'

                result.append(f"    {row['channel']} ({subnet}): +{flag_str}")

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
        user = await self.get(handle)
        if not user:
            return False
        if channel:
            flags = user.chan_flags.get(channel, '')
        return all(f in flags for f in flags[1:]) if flags.startswith('+') else not any(f in flags for f in flags[1:])

    async def list_users(self, flag_filter: str = "") -> List[User]:
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT * FROM users WHERE flags LIKE ? OR chan_flags LIKE ?",
                (f"%{flag_filter}%", f"%{flag_filter}%")
            )
            return [User(**self._row_to_data(r)) for r in rows]
        
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

    async def get(self, handle: str) -> User:
        async with get_db(self.db_path) as db:
            row = await db.execute(
                "SELECT * FROM users WHERE handle = ?", (handle,)
            ).fetchone()
            
            if not row:
                raise ValueError(f"User '{handle}' not found")
            return User(**row)

    def _row_to_data(self, row: Dict) -> Dict:
        data = dict(row)
        data['hostmasks'] = (data.get('hostmasks', '') or '').split()
        data['chan_flags'] = json.loads(data.get('chan_flags', '{}'))
        data['xtra'] = json.loads(data.get('xtra', '{}'))
        return data

    async def sync_user(self, nick: str, host: str, channel: str = None, bot_id: int = None):
        async with get_db(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO users (handle, hostmasks, laston, chan_flags, xtra)
                VALUES (?, ?, strftime('%s','now'), ?, json_object('synced_by_bot', ?))
            """, (nick, host, json.dumps({channel: ''}) if channel else '{}', bot_id))
            await db.commit()
        # TODO: from .botnet import propagate_user_sync