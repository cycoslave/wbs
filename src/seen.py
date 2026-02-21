# src/seen.py
"""
Seen tracking for all users (like gseen.mod).
"""

import time
from typing import List, Optional, Dict, Any
from .db import get_db 

class Seen:
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
