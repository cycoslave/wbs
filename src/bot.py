# src/bot.py
"""
Handles bot management for WBS IRC bot.
"""

import aiosqlite
import sqlite3
import json
import bcrypt
import time
import logging
from typing import List, Optional, Literal, Dict, Any, Tuple
from dataclasses import dataclass, asdict, field

from .db import get_db 

log = logging.getLogger(__name__)

@dataclass
class Bot:
    """Maps to the 'bots' table."""
    handle: str
    password: Optional[str] = None
    hostmasks: list[str] = field(default_factory=list)
    address: str = 'localhost'
    port: int = 3333
    role: Literal['hub', 'backup', 'leaf', 'none'] = 'none'
    subnet_id: Optional[int] = None
    share_level: str = 'subnet'
    comment: str = ''
    created_at: int = field(default_factory=lambda: int(time.time()))

    def __post_init__(self):
        # Safe JSON parse
        if self.hostmasks and self.hostmasks.strip():
            try:
                self._hostmasks_list = json.loads(self.hostmasks)
            except json.JSONDecodeError:
                log.warning(f"Invalid hostmasks JSON for {self.handle}: {self.hostmasks}")
                self._hostmasks_list = []
        else:
            self._hostmasks_list = []
        
        # Property access
        self.hostmask = self._hostmasks_list[0] if self._hostmasks_list else None

@property
def hostmasks_list(self):
    return self._hostmasks_list

@dataclass
class BotAccess:
    """Maps to the 'bot_access' table."""
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


class BotManager:

    def __init__(self, db_path):
        self.db_path = db_path

    async def set_password(self, handle: str, password: str):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else ''
        async with get_db(self.db_path) as db:
            await db.execute("UPDATE users SET password = ? WHERE handle = ?", (hashed, handle))
            await db.commit()

    async def matchattr(self, handle: str, flags: str, channel: Optional[str] = None) -> bool:
        user = await self.get(handle)
        if not user:
            return False
        if channel:
            flags = user.chan_flags.get(channel, '')
        return all(f in flags for f in flags[1:]) if flags.startswith('+') else not any(f in flags for f in flags[1:])   

    async def addbot(self, handle: str, hostmask: Optional[str], address: Optional[str], port: Optional[int]):
        """Add bot. Returns True if created."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT handle FROM bots WHERE handle=?", (handle,)) as cursor:
                if await cursor.fetchone():
                    raise ValueError(f"Bot {handle} exists")
            
            hostmasks_json = json.dumps([hostmask]) if hostmask else None
            
            await db.execute(
                """
                INSERT OR IGNORE INTO bots (handle, hostmasks, address, port) 
                VALUES (?, ?, ?, ?)
                """,
                (handle, hostmasks_json, address, port)
            )
            await db.commit()
            
            # Verify creation
            async with db.execute("SELECT rowid FROM bots WHERE handle=?", (handle,)) as cursor:
                return (await cursor.fetchone()) is not None
            
    async def delbot(self, target_handle: str) -> str:
        """Delete user by handle. Requires admin rights."""
        async with aiosqlite.connect(self.db_path) as db:
            # Check actor has admin rights
            #actor = await db.fetchone(
            #    "SELECT handle FROM user_access WHERE handle = ? AND is_admin = 1 AND channel = '*'",
            #    (actor_handle,)
            #)
            #if not actor:
            #    return f"{actor_handle}: Insufficient rights to delete users."
            
            async with db.execute("SELECT handle FROM bots WHERE handle = ?", (target_handle,)) as cursor:
                if await cursor.fetchone():
                    async with db.execute("DELETE FROM bots WHERE handle = ?", (target_handle,)) as cursor:
                        await db.commit()                    
                    async with db.execute("SELECT handle FROM bots WHERE handle = ?", (target_handle,)) as cursor:
                        if await cursor.fetchone():
                            return False
                        else:
                            return True
                else:
                    return False 
        
    def exist(self, bot: str):
        try:
            with sqlite3.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                cursor = db.execute("SELECT 1 FROM bots WHERE handle = ?", (bot.lower(),))
                return cursor.fetchone() is not None
        except sqlite3.Error:
            return False 

    async def get(self, handle: str) -> Bot:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT handle, hostmasks, address, port FROM bots WHERE handle=?", (handle,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    raise ValueError(f"Bot '{handle}' not found")
                
                hostmasks_json = row[1]
                hostmasks_parsed = []
                if hostmasks_json:
                    try:
                        hostmasks_parsed = json.loads(hostmasks_json)
                    except json.JSONDecodeError as e:
                        log.warning(f"Invalid hostmasks JSON for {handle}: {hostmasks_json} ({e})")
                
                return Bot(
                    handle=row[0],
                    hostmasks=json.dumps(hostmasks_parsed),  # Always valid JSON array
                    address=row[2],
                    port=row[3]
                )

    def to_dict(self, bot: Bot) -> dict:
        """Convert Bot to dict for DB operations."""
        data = asdict(bot)  # dataclasses.asdict(bot)
        data['hostmasks'] = json.dumps(data['hostmasks'])  # Convert list back to JSON
        return data

    async def save(self, bot: Bot):
        data = to_dict(bot)
        async with get_db(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO bots (handle, password, hostmasks, address, port, 
                                        role, subnet_id, share_level, comment, created_at)
                VALUES (:handle, :password, :hostmasks, :address, :port,
                        :role, :subnet_id, :share_level, :comment, :created_at)
            """, data)

    def _row_to_data(self, row: Dict) -> Dict:
        data = dict(row)
        data['hostmasks'] = (data.get('hostmasks', '') or '').split()
        data['chan_flags'] = json.loads(data.get('chan_flags', '{}'))
        data['xtra'] = json.loads(data.get('xtra', '{}'))
        return data