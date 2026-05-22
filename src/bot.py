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
from typing import List, Optional, Literal, Dict
from dataclasses import dataclass, asdict, field

from .db import get_db 

log = logging.getLogger("wbs.bot")

@dataclass
class Bot:
    """Maps to the 'bots' table."""
    handle: str
    password: Optional[str] = None
    hostmasks: list[str] = field(default_factory=list)
    address: str = 'localhost'
    port: int = 3333
    role: Literal['hub', 'backup', 'leaf', 'none'] = 'none'
    share_level: str = 'subnet'
    comment: str = ''
    created_at: int = field(default_factory=lambda: int(time.time()))

    def __post_init__(self):
        if isinstance(self.hostmasks, str):
            try:
                self.hostmasks = json.loads(self.hostmasks) if self.hostmasks.strip() else []
            except json.JSONDecodeError:
                log.warning(f"Invalid hostmasks JSON for {self.handle}: {self.hostmasks}")
                self.hostmasks = []

    @property
    def hostmasks_list(self) -> list[str]:       # was orphaned outside the class
        return self.hostmasks

    @property
    def hostmask(self) -> Optional[str]:          # first mask or None
        return self.hostmasks[0] if self.hostmasks else None  

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
                "SELECT handle, hostmasks, address, port, password FROM bots WHERE handle=?", (handle,)
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
                    port=row[3],
                    password=row[4]
                )

    async def chpass(self, name: str, password: str):
        """Update botlink password in database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    "UPDATE bots SET password = ? WHERE handle = ?",
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
                                role, share_level, comment, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(handle) DO UPDATE SET
                    password     = excluded.password,
                    hostmasks    = excluded.hostmasks,
                    address      = excluded.address,
                    port         = excluded.port,
                    role         = excluded.role,
                    share_level  = excluded.share_level,
                    comment      = excluded.comment,
                    updated_at   = ?
                """,
                (
                    bot.handle, bot.password,
                    json.dumps(bot.hostmasks),
                    bot.address, bot.port,
                    bot.role, bot.share_level,
                    bot.comment, bot.created_at, now,
                    now,  # ON CONFLICT updated_at binding
                )
            )
            await db.commit()

    async def get_subnet_ids(self, handle: str) -> list[int]:
        """Return all subnet_ids bound to this bot. Empty list = global."""
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT subnet_id FROM bot_subnets WHERE bot_handle = ? ORDER BY subnet_id",
                (handle,)
            )
        return [row["subnet_id"] for row in rows]

    async def is_global(self, handle: str) -> bool:
        """A bot with no subnet bindings is active on all subnets."""
        return len(await self.get_subnet_ids(handle)) == 0

    async def bind_to_subnet(self, handle: str, subnet_id: int,
                              created_by: Optional[str] = None) -> bool:
        """Bind a bot to a specific subnet."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")
            cursor = await db.execute(
                """INSERT OR IGNORE INTO bot_subnets (bot_handle, subnet_id, created_by)
                   VALUES (?, ?, ?)""",
                (handle, subnet_id, created_by)
            )
            await db.commit()
        return cursor.rowcount > 0

    async def unbind_from_subnet(self, handle: str, subnet_id: int) -> bool:
        """Remove a specific subnet binding from a bot."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")
            cursor = await db.execute(
                "DELETE FROM bot_subnets WHERE bot_handle = ? AND subnet_id = ?",
                (handle, subnet_id)
            )
            await db.commit()
        return cursor.rowcount > 0

    async def make_global(self, handle: str) -> bool:
        """Remove all subnet bindings — bot becomes active on all subnets."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")
            cursor = await db.execute(
                "DELETE FROM bot_subnets WHERE bot_handle = ?",
                (handle,)
            )
            await db.commit()
        return cursor.rowcount > 0

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
    
    async def merge_from_peer(self, bots: list[dict], from_bot: str) -> None:
        """
        Merge bot records received from a botnet peer.
        - Never overwrites local password
        - Last-write-wins on updated_at
        - Skips self-reference
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")
            for bot in bots:
                handle = bot['handle'].lower()

                if handle == from_bot.lower():
                    # Don't overwrite our own record with peer's copy
                    continue

                cur = await db.execute(
                    "SELECT password, updated_at FROM bots WHERE handle = ?", (handle,)
                )
                existing = await cur.fetchone()
                remote_updated = bot.get('updated_at') or 0

                if existing:
                    if remote_updated <= (existing[1] or 0):
                        continue  # Local is newer or equal
                    # Keep local password — never accept it from a peer
                    await db.execute(
                        """
                        UPDATE bots SET
                            hostmasks = ?, address = ?, port = ?,
                            role = ?, share_level = ?, comment = ?,
                            updated_at = ?, updated_by = ?
                        WHERE handle = ? AND (updated_at IS NULL OR updated_at < ?)
                        """,
                        (
                            bot.get('hostmasks', '[]'), bot.get('address', 'localhost'),
                            bot.get('port', 3333), bot.get('role', 'none'),
                            bot.get('share_level', 'subnet'), bot.get('comment', ''),
                            remote_updated, from_bot,
                            handle, remote_updated
                        )
                    )
                else:
                    await db.execute(
                        """
                        INSERT INTO bots
                            (handle, hostmasks, address, port, role, share_level,
                            comment, created_at, updated_at, created_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            handle, bot.get('hostmasks', '[]'),
                            bot.get('address', 'localhost'), bot.get('port', 3333),
                            bot.get('role', 'none'), bot.get('share_level', 'subnet'),
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
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")

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

                if existing:
                    if remote_updated <= (existing[0] or 0):
                        continue
                    await db.execute(
                        """
                        UPDATE bot_access SET
                            has_partyline = ?, is_op = ?, is_deop = ?,
                            is_voice = ?, is_devoice = ?, is_friend = ?,
                            updated_at = ?, updated_by = ?
                        WHERE handle = ?
                        AND (channel = ? OR (channel IS NULL AND ? IS NULL))
                        """,
                        (
                            acc.get('has_partyline', 0), acc.get('is_op', 0),
                            acc.get('is_deop', 0), acc.get('is_voice', 0),
                            acc.get('is_devoice', 0), acc.get('is_friend', 0),
                            remote_updated, from_bot,
                            handle, channel, channel
                        )
                    )
                else:
                    await db.execute(
                        """
                        INSERT INTO bot_access
                            (handle, channel, has_partyline, is_op, is_deop,
                            is_voice, is_devoice, is_friend,
                            created_at, updated_at, created_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            handle, channel,
                            acc.get('has_partyline', 0), acc.get('is_op', 0),
                            acc.get('is_deop', 0), acc.get('is_voice', 0),
                            acc.get('is_devoice', 0), acc.get('is_friend', 0),
                            acc.get('created_at', 0), remote_updated, from_bot
                        )
                    )

            await db.commit()
        log.info(f"BotManager.merge_access_from_peer: merged {len(access_list)} rows from {from_bot}")

    async def serialize_for_peer(self, exclude_handle: str) -> list[dict]:
        """Return bots for botnet share — exclude self, strip passwords."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM bots WHERE handle != ?", (exclude_handle.lower(),)
            )
            rows = await cursor.fetchall()
        bots = [dict(row) for row in rows]
        for b in bots:
            b['password'] = None  # Never share passwords
        return bots

    async def serialize_access_for_peer(self) -> list[dict]:
        """Return bot_access rows for botnet share."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM bot_access")
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]    