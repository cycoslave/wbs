# src/user.py
"""
Handles user management for WBS IRC bot.
Mimics Eggdrop userfile: handles, hostmasks, global/channel flags, info, hashed passwords.
Async SQLite via db.py. Supports botnet sharing.
Seen tracking for all users (like gseen.mod).
"""

import asyncio
import time
import json
import bcrypt
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from .db import get_db 

@dataclass
class User:
    handle: str
    hostmasks: List[str]
    flags: str = ""
    chan_flags: Dict[str, str] = None
    info: str = ""
    password: str = ""
    laston: int = 0
    xtra: Dict[str, str] = None

    def __post_init__(self, db_path):
        self.hostmasks = self.hostmasks or []
        self.chan_flags = self.chan_flags or {}
        self.xtra = self.xtra or {}
        self.db_path = db_path

class UserManager:
    FLAGS = {
        'n': 'owner', 'm': 'master', 'o': 'op', 'v': 'voice', 'p': 'prot', 
        'h': 'halfop', 'b': 'bot', 'k': 'kick', 'd': 'deop', 't': 'trust',
        'f': 'friend', 'i': 'info', 'g': 'gift', 'u': 'unban', 'a': 'autoop'
    }  # Eggdrop standard [web:22]

    def __init__(self, db_path):
        self.db_path = db_path

    async def add_user(self, handle: str, hostmask: str = "") -> bool:
        async with get_db(self.db_path) as db:
            await db.execute(
                "INSERT OR IGNORE INTO users (handle, hostmasks, flags) VALUES (?, ?, ?)",
                (handle, hostmask, "")
            )
            was_new = db.rowcount > 0
            if not was_new and hostmask:
                await db.execute(
                    "UPDATE users SET hostmasks = hostmasks || ' ' || ? WHERE handle = ?",
                    (hostmask, handle)
                )
            await db.commit()
            return was_new

    async def get_user(self, handle: str) -> Optional[User]:
        async with get_db(self.db_path) as db:
            row = await db.execute_fetchone("SELECT * FROM users WHERE handle = ?", (handle,))
            if not row:
                return None
            data = dict(row)
            data['hostmasks'] = (data.get('hostmasks', '') or '').split()
            data['chan_flags'] = json.loads(data.get('chan_flags', '{}'))
            data['xtra'] = json.loads(data.get('xtra', '{}'))
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

    async def chattr(self, handle: str, changes: str, channel: Optional[str] = None) -> str:
        user = await self.get_user(handle)
        if not user:
            return "*"
        if channel:
            flags = user.chan_flags.get(channel, "")
            new_flags = self._apply_changes(flags, changes)
            user.chan_flags[channel] = new_flags
            chan_json = json.dumps(user.chan_flags)
        else:
            new_flags = self._apply_changes(user.flags, changes)
            chan_json = None
        async with get_db(self.db_path) as db:
            if channel:
                await db.execute("UPDATE users SET chan_flags = ? WHERE handle = ?", (chan_json, handle))
            else:
                await db.execute("UPDATE users SET flags = ? WHERE handle = ?", (new_flags, handle))
            await db.commit()
        return f"{user.flags}|{new_flags}" if channel else new_flags

    def _apply_changes(self, current: str, changes: str) -> str:
        flags = set(c for c in current if c in self.FLAGS)
        i = 0
        while i < len(changes):
            if changes[i] in '+-':
                sign, i = changes[i], i + 1
                if i < len(changes):
                    flag = changes[i]
                    if flag in self.FLAGS:
                        if sign == '+':
                            flags.add(flag)
                        else:
                            flags.discard(flag)
                    i += 1
                else:
                    break
            else:
                i += 1
        return ''.join(sorted(flags))

    async def del_user(self, handle: str) -> bool:
        async with get_db(self.db_path) as db:
            await db.execute("DELETE FROM users WHERE handle = ?", (handle,))
            await db.commit()
            return db.rowcount > 0

    async def set_info(self, handle: str, info: str):
        async with get_db(self.db_path) as db:
            await db.execute("UPDATE users SET info = ? WHERE handle = ?", (info, handle))
            await db.commit()

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

class SeenDB:
    EXPIRE_DAYS = 60

    def __init__(self, db_path):
        self.rate_limits: Dict[str, List[float]] = {}
        self.db_path = db_path

    async def update_seen(self, nick: str, hostmask: str, channel: str, action: str = "seen"):
        if not self.check_rate_limit(nick):
            return
        async with get_db(self.db_path) as db:
            now = int(time.time())
            await db.execute("""
                INSERT OR REPLACE INTO seen (nick, last_seen, hostmask, channel, action)
                VALUES (?, ?, ?, ?, ?)
            """, (nick, now, hostmask, channel, action))
            await db.commit()

    async def get_seen(self, nick: str) -> Optional[Dict[str, Any]]:
        async with get_db(self.db_path) as db:
            row = await db.execute_fetchone("SELECT * FROM seen WHERE nick = ?", (nick,))
            if not row:
                return None
            data = dict(row)
            data['lastseen_str'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data['last_seen']))
            expire_ts = int(time.time()) - (86400 * self.EXPIRE_DAYS)
            if data['last_seen'] < expire_ts:
                await self.delete_seen(nick)
                return None
            return data

    async def delete_seen(self, nick: str):
        async with get_db(self.db_path) as db:
            await db.execute("DELETE FROM seen WHERE nick = ?", (nick,))
            await db.commit()

    def check_rate_limit(self, nick: str, max_per_min: int = 7) -> bool:
        now = time.time()
        timestamps = self.rate_limits.get(nick, [])
        timestamps = [t for t in timestamps if now - t < 60]
        if len(timestamps) >= max_per_min:
            return False
        timestamps.append(now)
        self.rate_limits[nick] = timestamps
        return True
