# src/channel.py
"""
Handles IRC channel management for WBS.
"""

import aiosqlite
import asyncio
import logging
import json
from typing import Dict, Optional, Callable
from dataclasses import dataclass, field

from .db import get_db

logger = logging.getLogger(__name__)

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
                return f"User '{channel}' not found."
            
            result = [f"Channel: {chan['name']}"]
            result.append(f"  Comment: {chan['comment'] or 'None'}")
            result.append(f"  Locked: {'Yes' if user['is_locked'] else 'No'}")
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

    async def add_ban(self, channel: str, banmask: str, creator: str = 'bot', lifetime: int = 0):
        """
        Add ban to channel state and send to IRC.
        
        Args:
            channel: Channel name
            banmask: Ban mask (e.g., '*!*@example.com')
            creator: Who created the ban
            lifetime: Ban duration in seconds (0 = permanent)
        """
        state = self.get_state(channel)
        if not state:
            logger.warning(f"Cannot add ban to unknown channel {channel}")
            return
        
        state.bans.add(banmask)
        
        if self._irc_send:
            self._irc_send(f"MODE {channel} +b {banmask}")
        
        logger.info(f"Banned {banmask} on {channel} by {creator} (lifetime: {lifetime}s)")
        
        # TODO: Store ban in DB with expiry if lifetime > 0

    async def remove_ban(self, channel: str, banmask: str):
        """Remove ban from channel."""
        state = self.get_state(channel)
        if state and banmask in state.bans:
            state.bans.discard(banmask)
            
            if self._irc_send:
                self._irc_send(f"MODE {channel} -b {banmask}")
            
            logger.info(f"Unbanned {banmask} on {channel}")

    async def enforce_modes(self, channel: str):
        """Enforce channel modes from settings."""
        settings = await self.get_settings(channel)
        if not settings or not settings.chanmode:
            return
        
        if self._irc_send:
            self._irc_send(f"MODE {channel} {settings.chanmode}")
            logger.debug(f"Enforcing modes {settings.chanmode} on {channel}")

    async def sync_from_peer(self, channel_data: Dict):
        """
        Sync channel settings/bans/flags from botnet peer.
        
        Args:
            channel_data: Dict containing 'channel', 'settings', 'userflags', etc.
        """
        channel = channel_data.get('channel')
        if not channel:
            logger.warning("sync_from_peer called without channel name")
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
            logger.info(f"Synced channel {channel} from botnet peer")
        except Exception as e:
            logger.error(f"Failed to sync channel {channel}: {e}")


# Global instance
_channel_mgr: Optional[ChannelManager] = None


async def init_channel_manager(db_path: str, irc_send_callback: Optional[Callable] = None):
    """Initialize global channel manager."""
    global _channel_mgr
    _channel_mgr = ChannelManager(db_path, irc_send_callback)
    await _channel_mgr.initialize()
    logger.info("Channel manager initialized")


def get_channel_mgr() -> ChannelManager:
    """Get the channel manager instance."""
    if _channel_mgr is None:
        raise RuntimeError("Channel manager not initialized - call init_channel_manager first")
    return _channel_mgr
