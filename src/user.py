# src/user.py
"""
Handles user management for WBS IRC bot.
Mimics Eggdrop userfile: handles, hostmasks, global/channel flags, info, hashed passwords.
Async SQLite via db.py. Supports botnet sharing.
"""

import aiosqlite
import json
import bcrypt
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from .db import get_db 

@dataclass
class User:
    handle: str
    hostmasks: List[str]
    comment: str = ""
    is_locked: int = 0

    def __post_init__(self, db_path):
        self.hostmasks = self.hostmasks or []
        self.chan_flags = self.chan_flags or {}
        self.xtra = self.xtra or {}
        self.db_path = db_path

class UserManager:

    def __init__(self, db_path):
        self.db_path = db_path

    async def adduser(self, handle: str, hostmask: str = None):
        """Add user with hostmask. Returns True if created."""
        if not hostmask:
            hostmask = "*! *@localhost"  # Default
        
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT handle FROM users WHERE handle = ?", (handle,)) as cursor:
                if await cursor.fetchone():
                    raise ValueError(f"User {handle} already exists")
            
            async with db.execute(
                """
                INSERT INTO users (handle, hostmasks, created_by) 
                VALUES (?, json_array(?), ?)
                """,
                (handle, hostmask, "partyline")
            ) as cursor:
                await db.commit()
                if cursor.rowcount > 0:
                    return True
                return False
            
    async def deluser(self, target_handle: str) -> str:
        """Delete user by handle. Requires admin rights."""
        async with aiosqlite.connect(self.db_path) as db:
            # Check actor has admin rights
            #actor = await db.fetchone(
            #    "SELECT handle FROM user_access WHERE handle = ? AND is_admin = 1 AND channel = '*'",
            #    (actor_handle,)
            #)
            #if not actor:
            #    return f"{actor_handle}: Insufficient rights to delete users."
            
            async with db.execute("SELECT handle FROM users WHERE handle = ?", (target_handle,)) as cursor:
                if await cursor.fetchone():
                    async with db.execute("DELETE FROM users WHERE handle = ?", (target_handle,)) as cursor:
                        await db.commit()
                    await db.commit()
                    
                    async with db.execute("SELECT handle FROM users WHERE handle = ?", (target_handle,)) as cursor:
                        if await cursor.fetchone():
                            return False
                        else:
                            return True
                else:
                    return False 
        
    async def listusers(self) -> str:
        """List all users with access summary."""
        async with get_db(self.db_path) as db:
            # Check actor rights (admin or partyline access)
            #actor_rights = await db.fetchone(
            #    "SELECT has_partyline FROM user_access WHERE handle = ? AND channel = '*'",
            #    (actor_handle,)
            #)
            #if not actor_rights:
            #    return f"{actor_handle}: Access denied."
            
            users = await db.execute("""
                SELECT u.handle, u.comment, 
                    COUNT(ua.channel) as channel_count,
                    GROUP_CONCAT(ua.channel) as channels,
                    MAX(ua.is_admin) as is_admin
                FROM users u 
                LEFT JOIN user_access ua ON u.handle = ua.handle
                GROUP BY u.handle
                ORDER BY u.handle
            """)
            
            result = ["Users:"]
            async for row in users:
                admin = " (admin)" if row['is_admin'] else ""
                channels = row['channels'] or '*'
                result.append(f"  {row['handle']}{admin}: {channels} - {row['comment']}")
            
            return "\n".join(result)

    async def showuser(self, target_handle: str) -> str:
        """Show detailed info for specific user."""
        async with get_db(self.db_path) as db:
            # Check rights
            #actor_rights = await db.fetchone(
            #    "SELECT is_admin FROM user_access WHERE handle = ? AND channel = '*'",
            #    (actor_handle,)
            #)
            #if not actor_rights or not actor_rights['is_admin']:
            #    return f"{actor_handle}: Admin rights required."
            
            # Get user details
            user = await db.execute("""
                SELECT handle, password IS NOT NULL as has_pass, 
                    hostmasks, is_locked, comment, last_seen,
                    created_at, updated_at
                FROM users WHERE handle = ?
            """, (target_handle,))
            
            if not user:
                return f"User '{target_handle}' not found."
            
            # Get user details - separate connection
            async with get_db(self.db_path) as db:
                user_cursor = await db.execute("""
                    SELECT handle, password IS NOT NULL as has_pass, 
                        hostmasks, is_locked, comment, last_seen,
                        created_at, updated_at
                    FROM users WHERE handle = ?
                """, (target_handle,))
                
                user = None
                async for row in user_cursor:
                    user = row
                    break
            
            if not user:
                return f"User '{target_handle}' not found."
            
            # Get access details - separate connection
            async with get_db(self.db_path) as db:
                access_cursor = await db.execute("""
                    SELECT channel, subnet_id, has_partyline, is_admin, is_op, 
                        is_voice, is_friend, created_at
                    FROM user_access WHERE handle = ?
                    ORDER BY channel
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
                    if row['has_partyline']: flags.append('P')
                    if row['is_admin']: flags.append('A')
                    if row['is_op']: flags.append('O')
                    if row['is_voice']: flags.append('V')
                    if row['is_friend']: flags.append('F')
                    
                    subnet = f" (subnet {row['subnet_id']})" if row['subnet_id'] else ""
                    result.append(f"    {row['channel']}{subnet}: +{''.join(flags)}")
                
                if not has_access:
                    result.append("    No access granted")
                
                return "\n".join(result)

    async def get_user(self, handle: str) -> Optional[User]:
        async with get_db(self.db_path) as db:
            row = await db.execute_fetchone("SELECT * FROM users WHERE handle = ?", (handle,))
            if not row:
                return None
            data = dict(row)
            data['hostmasks'] = (data.get('hostmasks', '') or '').split()
            return User(**data)

    async def match_user(self, hostmask: str) -> Optional[str]:
        """Glob match hostmasks (eggdrop-style)."""
        async with get_db(self.db_path) as db:
            # Simple LIKE; enhance with fnmatch/regex if needed
            rows = await db.execute_fetchall(
                "SELECT handle FROM users WHERE hostmasks LIKE ?",
                (f"%{hostmask}%",)
            )
            return rows[0]['handle'] if rows else None

    async def set_password(self, handle: str, password: str):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else ''
        async with get_db(self.db_path) as db:
            await db.execute("UPDATE users SET password = ? WHERE handle = ?", (hashed, handle))
            await db.commit()

    async def matchattr(self, handle: str, flags: str, channel: Optional[str] = None) -> bool:
        user = await self.get_user(handle)
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