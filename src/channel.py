# src/channel.py
"""
Handles IRC channel management for WBS.
"""

import aiosqlite
import sqlite3
import asyncio
import logging
import json
from typing import Dict, Optional, Callable
from dataclasses import dataclass, field

from .db import get_db

log = logging.getLogger(__name__)

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