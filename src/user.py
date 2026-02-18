"""
src/user.py - Handles user management for WBS IRC bot.

Mimics Eggdrop userfile: handles, hostmasks, global/channel flags, info, hashed passwords.
Async SQLite via db.py. Supports botnet sharing.
Seen tracking for all users (like gseen.mod).
"""

import asyncio
import time
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from .db import get_db  # async context manager -> aiosqlite.Connection

async def sync_user(nick: str, host: str, channel: str = None, bot_id: int = None):
    """Sync user data to DB for botnet sharing."""
    async with get_db_connection() as conn:  # Or sync sqlite3 if not async yet
        # Upsert user
        await conn.execute("""
            INSERT OR REPLACE INTO users (nick, host, last_seen, channel, synced_by_bot)
            VALUES (?, ?, datetime('now'), ?, ?)
        """, (nick, host, channel, bot_id))
        await conn.commit()
    # Propagate to botnet if linked
    # from .botnet import propagate_user_sync  # Lazy if needed

@dataclass
class User:
    """Eggdrop-like user record."""
    handle: str
    hostmasks: List[str]
    flags: str = ""  # global flags e.g. "+nmo"
    chan_flags: Dict[str, str] = None  # {"#chan": "+o"}
    info: str = ""
    password: str = ""  # hashed
    laston: int = 0  # unix ts
    xtra: Dict[str, str] = None

    def __post_init__(self):
        self.hostmasks = self.hostmasks or []
        self.chan_flags = self.chan_flags or {}
        self.xtra = self.xtra or {}

class UserManager:
    """CRUD for users, flag matching, Eggdrop chattr logic."""
    
    FLAGS = {
        'n': 'owner', 'm': 'master', 'o': 'op', 'v': 'voice', 'h': 'halfop',
        'a': 'auto-op', 'f': 'friend', 'k': 'kick', 'd': 'deop', 't': 'botnet-master',
        # Add more per Eggdrop docs [web:24][page:2]
    }

    def __init__(self):
        pass

    async def add_user(self, handle: str, hostmask: str = "") -> bool:
        """Add user or hostmask. Return True if new user."""
        async with get_db() as db:
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
        """Fetch full User by handle."""
        async with get_db() as db:
            row = await db.execute_fetchone("SELECT * FROM users WHERE handle = ?", (handle,))
            if not row:
                return None
            data = dict(row)
            data['hostmasks'] = (data['hostmasks'] or '').split()
            data['chan_flags'] = self._parse_chan_flags(data.get('chan_flags', '{}'))
            data['xtra'] = self._parse_xtra(data.get('xtra', '{}'))
            return User(**data)

    async def match_user(self, hostmask: str) -> Optional[str]:
        """Find handle matching hostmask (exact or LIKE). Improve w/ regex."""
        async with get_db() as db:
            row = await db.execute_fetchone(
                "SELECT handle FROM users WHERE hostmasks LIKE ?", (f"%{hostmask}%",)
            )
            return row['handle'] if row else None

    async def chattr(self, handle: str, changes: str, channel: Optional[str] = None) -> str:
        """Eggdrop chattr: +mo or -k, global or chan."""
        user = await self.get_user(handle)
        if not user:
            return "*"
        if channel:
            flags = user.chan_flags.get(channel, "")
            new_chan_flags = self._apply_changes(flags, changes)
            user.chan_flags[channel] = new_chan_flags
            chan_flags_json = self._json_chan_flags(user.chan_flags)
            async with get_db() as db:
                await db.execute("UPDATE users SET chan_flags = ? WHERE handle = ?", (chan_flags_json, handle))
                await db.commit()
            return f"{user.flags}|{new_chan_flags}"
        else:
            new_flags = self._apply_changes(user.flags, changes)
            async with get_db() as db:
                await db.execute("UPDATE users SET flags = ? WHERE handle = ?", (new_flags, handle))
                await db.commit()
            return new_flags

    def _apply_changes(self, current: str, changes: str) -> str:
        """Apply +add / -remove flags."""
        flags = set(current.replace('|', ''))
        i = 0
        while i < len(changes):
            sign = changes[i]
            if sign in '+-':
                i += 1
                if i < len(changes):
                    flag = changes[i]
                    if sign == '+':
                        flags.add(flag)
                    else:
                        flags.discard(flag)
                    i += 1
            else:
                i += 1
        return ''.join(sorted(flags))  # or preserve order [web:6][page:1]

    async def set_info(self, handle: str, info: str):
        async with get_db() as db:
            await db.execute("UPDATE users SET info = ? WHERE handle = ?", (info, handle))
            await db.commit()

    async def set_password(self, handle: str, password: str):
        """Hash & set password (stub: use bcrypt/etc)."""
        hashed = password  # TODO: hash
        async with get_db() as db:
            await db.execute("UPDATE users SET password = ? WHERE handle = ?", (hashed, handle))
            await db.commit()

    async def list_users(self, flag_filter: str = "") -> List[User]:
        """List users matching flags (simple LIKE; TODO &/|)."""
        async with get_db() as db:
            rows = await db.execute_fetchall("SELECT * FROM users WHERE flags LIKE ? OR chan_flags LIKE ?", 
                                             (f"%{flag_filter}%", f"%{flag_filter}%"))
            return [User(**self._row_to_data(r)) for r in rows]

    async def matchattr(self, handle: str, flags: str, channel: Optional[str] = None) -> bool:
        """Eggdrop matchattr: check +flags."""
        user = await self.get_user(handle)
        if not user:
            return False
        # TODO: full +/- &/| logic [web:6]
        return flags[1:] in user.flags if flags.startswith('+') else False

    def _parse_chan_flags(self, json_str: str) -> Dict[str, str]:
        import json
        try:
            return json.loads(json_str)
        except:
            return {}

    def _json_chan_flags(self, d: Dict) -> str:
        import json
        return json.dumps(d)

    def _parse_xtra(self, json_str: str) -> Dict[str, str]:
        import json
        try:
            return json.loads(json_str)
        except:
            return {}

    def _row_to_data(self, row: Dict) -> Dict:
        data = dict(row)
        data['hostmasks'] = (data['hostmasks'] or '').split()
        data['chan_flags'] = self._parse_chan_flags(data.get('chan_flags', '{}'))
        data['xtra'] = self._parse_xtra(data.get('xtra', '{}'))
        return data

class SeenDB:
    """Global seen tracking (like gseen.mod [web:19])."""
    EXPIRE_DAYS = 60

    def __init__(self):
        self.rate_limits: Dict[str, List[float]] = {}  # nick: timestamps

    async def update_seen(self, nick: str, hostmask: str, channel: str, action: str = "seen"):
        async with get_db() as db:
            now = int(time.time())
            await db.execute("""
                INSERT OR REPLACE INTO seen (nick, lastseen, hostmask, channels, action)
                VALUES (?, ?, ?, ?, ?)
            """, (nick, now, hostmask, channel, action))
            await db.commit()

    async def get_seen(self, nick: str) -> Optional[Dict[str, Any]]:
        async with get_db() as db:
            row = await db.execute_fetchone("SELECT * FROM seen WHERE nick = ?", (nick,))
            if not row:
                return None
            data = dict(row)
            data['lastseen_str'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data['lastseen']))
            expire_ts = int(time.time()) - (86400 * self.EXPIRE_DAYS)
            if data['lastseen'] < expire_ts:
                await self.delete_seen(nick)
                return None
            return data

    async def delete_seen(self, nick: str):
        async with get_db() as db:
            await db.execute("DELETE FROM seen WHERE nick = ?", (nick,))
            await db.commit()

    def check_rate_limit(self, nick: str, max_per_min: int = 7) -> bool:
        """Prevent spam."""
        now = time.time()
        timestamps = self.rate_limits.get(nick, [])
        timestamps = [t for t in timestamps if now - t < 60]
        if len(timestamps) >= max_per_min:
            return False
        timestamps.append(now)
        self.rate_limits[nick] = timestamps
        return True

def get_user_info(userhost):
    # TODO: Implement DB lookup for user info
    return {"host": userhost, "flags": ""}

def get_user_flags(userhost):
    # TODO: Implement flag lookup
    return ""