# src/channel.py
"""
Handles IRC channel management for WBS.
"""

import aiosqlite
import sqlite3
import asyncio
import logging
import time
import json
from typing import Dict, Optional, Callable, List, Literal
from dataclasses import dataclass, field, asdict

from .db import get_db

log = logging.getLogger(__name__)

@dataclass
class Channel:
    """Maps to the 'channels' table."""
    name: str
    subnet_id: Optional[int] = None
    
    # Channel lists (JSON arrays in DB)
    modes: str = ''
    bans: List[str] = field(default_factory=list)
    invites: List[str] = field(default_factory=list)
    exempts: List[str] = field(default_factory=list)
    
    # Flood protection
    flood_pub: int = 15
    flood_pub_time: int = 60
    flood_ctcp: int = 3
    flood_ctcp_time: int = 60
    flood_join: int = 5
    flood_join_time: int = 60
    flood_kick: int = 3
    flood_kick_time: int = 10
    flood_deop: int = 3
    flood_deop_time: int = 10
    flood_nick: int = 5
    flood_nick_time: int = 60
    
    # Channel flags (booleans)
    is_bitch: bool = False
    is_autoop: bool = False
    is_autovoice: bool = False
    is_revenge: bool = False
    is_revengebots: bool = False
    is_protectfriends: bool = False
    is_protectops: bool = False
    is_dontkickops: bool = False
    is_inactive: bool = False
    is_enforcebans: bool = False
    is_dynamicbans: bool = False
    is_dynamicexempts: bool = False
    is_dynamicinvites: bool = False
    is_pubcom: bool = False
    is_news: bool = False
    is_url: bool = False
    is_stats: bool = False
    is_locked: bool = False
    is_topiclock: bool = False
    is_limit: bool = False
    
    # Lock state
    lock_by: Optional[str] = None
    lock_at: int = 0
    lock_reason: str = ''
    
    # Topic lock
    topiclock: str = ''
    topiclock_by: Optional[str] = None
    topiclock_at: int = 0
    topiclock_reason: str = ''
    
    # Channel limits
    limit_add: int = 15
    limit_rand: int = 200
    limit_tolerance: int = 2
    limit_delta: int = 300
    limit_at: int = 0
    
    # Metadata
    comment: str = ''
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))
    created_by: Optional[str] = None
    updated_by: Optional[str] = None

    def __post_init__(self):
        # Normalize JSON lists from DB
        for field_name in ['bans', 'invites', 'exempts']:
            field_value = getattr(self, field_name)
            if isinstance(field_value, str):
                setattr(self, field_name, json.loads(field_value) if field_value else [])

class ChannelManager:

    def __init__(self, db_path):
        self.db_path = db_path

    async def addchan(self, channel: str):
        """Add channel. Returns True if created."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT name FROM channels WHERE name = ?", (channel,)) as cursor:
                if await cursor.fetchone():
                    raise ValueError(f"Channel {channel} already exists")
            
            async with db.execute(
                """
                INSERT INTO channels (name) 
                VALUES (?)
                """,
                (channel,)
            ) as cursor:
                await db.commit()
                if cursor.rowcount > 0:
                    return True
                return False
            
    async def delchan(self, channel: str) -> str:
        """Delete channel."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT name FROM channels WHERE name = ?", (channel,)) as cursor:
                if await cursor.fetchone():
                    async with db.execute("DELETE FROM channels WHERE name = ?", (channel,)) as cursor:
                        await db.commit()
                    await db.commit()
                    
                    async with db.execute("SELECT name FROM channels WHERE name = ?", (channel,)) as cursor:
                        if await cursor.fetchone():
                            return False
                        else:
                            return True
                else:
                    return False 
        
    async def listchans(self) -> str:
        """List all channels."""
        async with get_db(self.db_path) as db:
            chans = await db.execute("""
                SELECT name,comment,is_inactive
                FROM channels
                ORDER BY name
            """)
            
            result = ["Channels:"]
            async for row in chans:
                active = " (inactive)" if row['is_inactive'] else ""
                result.append(f"  {row['name']}{active} - {row['comment']}")
            
            return "\n".join(result)

    async def showchan(self, channel: str) -> str:
        """Show detailed info for specific chan."""
        async with get_db(self.db_path) as db:
            # Get channel details
            chan = await db.execute("""
                SELECT * FROM channels WHERE name = ?
            """, (channel,))
            
            if not chan:
                return f"Channel '{channel}' not found."
            
            result = [f"Channel: {chan['name']}"]
            result.append(f"  Comment: {chan['comment'] or 'None'}")
            result.append(f"  Locked: {'Yes' if chan['is_locked'] else 'No'}")
            return "\n".join(result)

    async def getchans(self) -> str:
        """Get a list of all channels."""
        async with get_db(self.db_path) as db:
            chans = await db.execute("""
                SELECT name
                FROM channels
                WHERE is_inactive = 0
                ORDER BY name
            """)
            channels = []
            async for row in chans:
                channels.append(row['name'])
            return channels

    def exist(self, channel: str):
        try:
            with sqlite3.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                cursor = db.execute("SELECT 1 FROM channels WHERE name = ?", (channel.lower(),))
                return cursor.fetchone() is not None
        except sqlite3.Error:
            return False

    def channel_to_dict(self, channel: Channel) -> dict:
        """Convert Channel to dict for DB INSERT/UPDATE."""
        data = asdict(channel)
        # Convert lists back to JSON strings for DB
        data['bans'] = json.dumps(data['bans'])
        data['invites'] = json.dumps(data['invites'])
        data['exempts'] = json.dumps(data['exempts'])
        return data

    async def get_channel(self, name: str) -> Optional[Channel]:
        """Fetch channel from DB -> Channel dataclass."""
        async with get_db(self.db_path) as db:
            row = await db.execute(
                "SELECT * FROM channels WHERE name = ?",
                (name,)
            ).fetchone()
            
            if row:
                return Channel(**dict(row))
            return None

    async def get_all_channels(self) -> list[Channel]:
        """Get all channels."""
        async with get_db(self.db_path) as db:
            rows = await db.execute("SELECT * FROM channels ORDER BY name").fetchall()
            return [Channel(**dict(row)) for row in rows]

    async def create_channel(self, name: str, subnet_id: Optional[int] = None) -> Channel:
        """Create new channel."""
        channel = Channel(name=name, subnet_id=subnet_id)
        data = self.channel_to_dict(channel)
        
        async with get_db(self.db_path) as db:
            await db.execute("""
                INSERT INTO channels (
                    name, subnet_id, modes, bans, invites, exempts,
                    comment, created_at, updated_at
                ) VALUES (
                    :name, :subnet_id, :modes, :bans, :invites, :exempts,
                    :comment, :created_at, :updated_at
                )
            """, data)
            await db.commit()
            
        return channel

    async def sync_from_peer(self, channel_data: Dict):
        """
        Sync channel settings/bans/flags from botnet peer.
        
        Args:
            channel_data: Dict containing 'channel', 'settings', 'userflags', etc.
        """
        channel = channel_data.get('channel')
        if not channel:
            log.warning("sync_from_peer called without channel name")
            return
        
        try:
            async with get_db(self.db_path) as db:
                # Upsert channel settings
                settings = channel_data.get('settings', {})
                if settings:
                    columns = list(settings.keys())
                    placeholders = ', '.join(['?'] * len(columns))
                    values = list(settings.values())
                    
                    await db.execute(
                        f"INSERT OR REPLACE INTO channel_settings (channel, {', '.join(columns)}) VALUES (?, {placeholders})",
                        (channel.lower(), *values)
                    )
                
                # Sync user flags
                for user_flags in channel_data.get('userflags', []):
                    await db.execute(
                        "INSERT OR REPLACE INTO user_chan_flags (handle, channel, flags) VALUES (?, ?, ?)",
                        (user_flags['handle'], channel.lower(), user_flags['flags'])
                    )
            
            # Reload channel from DB
            await self._load_channels()
            log.info(f"Synced channel {channel} from botnet peer")
        except Exception as e:
            log.error(f"Failed to sync channel {channel}: {e}")