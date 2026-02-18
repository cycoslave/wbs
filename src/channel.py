"""
src/pydrop/channel.py - Handles IRC channel management for pydrop bot.

Manages channel state, settings, bans, user flags on channels, and DB interactions.
Inspired by Eggdrop channels module [web:1].
"""

import asyncio
import logging
from typing import Dict, Optional
from dataclasses import dataclass, asdict
from .db import get_db, ChannelSettingsRow, UserChanFlagsRow
from .user import get_user_info  # For handle resolution
#from .irc import send_raw  # Sends raw IRC commands


logger = logging.getLogger(__name__)


@dataclass
class ChannelState:
    """Runtime state of a channel."""
    users: Dict[str, Dict[str, str]]  # nick -> {'mode': 'op/voice/normal', 'account': str, 'host': str}
    modes: str = ''
    topic: str = ''
    bans: set[str] = None
    exempts: set[str] = None
    invites: set[str] = None

    def __post_init__(self):
        if self.bans is None:
            self.bans = set()
        if self.exempts is None:
            self.exempts = set()
        if self.invites is None:
            self.invites = set()


class ChannelManager:
    """Manages all channels the bot is on."""

    def __init__(self, db_path: str):
        self.channels: Dict[str, tuple[ChannelSettingsRow, ChannelState]] = {}
        self.db_path = db_path
        self._load_channels()

    async def _load_channels(self):
        """Load channel settings from DB."""
        async with get_db(self.db_path) as db:
            rows = await db.fetchall("SELECT * FROM channel_settings")
            for row in rows:
                settings = ChannelSettingsRow(**row)
                self.channels[settings.channel.lower()] = (settings, ChannelState({}))

    async def add_channel(self, channel: str, settings_dict: Optional[dict] = None) -> bool:
        """Add new channel with default or given settings."""
        channel_lower = channel.lower()
        if channel_lower in self.channels:
            return False

        defaults = {
            'chanmode': '+nt',  # Enforce common modes [web:1]
            'idle_kick': 0,
            'flood_chan': '15:60',
            # Extend with more Eggdrop defaults as needed [web:1]
        }
        if settings_dict:
            defaults.update(settings_dict)

        async with get_db(self.db_path) as db:
            await db.insert_ignore('channel_settings', channel=channel_lower, **{k: v for k, v in defaults.items() if k != 'channel'})
            row = await db.fetchone("SELECT * FROM channel_settings WHERE channel = ?", (channel_lower,))
            if row:
                settings = ChannelSettingsRow(**row)
                self.channels[channel_lower] = (settings, ChannelState({}))
                logger.info(f"Added channel {channel}")
                return True
        return False

    async def remove_channel(self, channel: str) -> bool:
        """Remove channel and related DB records."""
        channel_lower = channel.lower()
        if channel_lower not in self.channels:
            return False

        async with get_db(self.db_path) as db:
            await db.execute("DELETE FROM channel_settings WHERE channel = ?", (channel_lower,))
            await db.execute("DELETE FROM user_chan_flags WHERE channel = ?", (channel_lower,))
        if channel_lower in self.channels:
            del self.channels[channel_lower]
        logger.info(f"Removed channel {channel}")
        return True

    async def get_settings(self, channel: str) -> Optional[ChannelSettingsRow]:
        """Get channel settings."""
        return self.channels.get(channel.lower(), None)[0] if channel.lower() in self.channels else None

    async def set_setting(self, channel: str, key: str, value: str) -> bool:
        """Set a channel setting and update in-memory."""
        chan_lower = channel.lower()
        if chan_lower not in self.channels:
            return False
        async with get_db(self.db_path) as db:
            await db.execute(f"UPDATE channel_settings SET {key} = ? WHERE channel = ?", (value, chan_lower))
            row = await db.fetchone("SELECT * FROM channel_settings WHERE channel = ?", (chan_lower,))
            if row:
                self.channels[chan_lower] = (ChannelSettingsRow(**row), self.channels[chan_lower][1])
                return True
        return False

    async def get_user_flags(self, handle: str, channel: str) -> str:
        """Get channel-specific user flags."""
        chan_lower = channel.lower()
        async with get_db(self.db_path) as db:
            row = await db.fetchone("SELECT flags FROM user_chan_flags WHERE handle = ? AND channel = ?", (handle, chan_lower))
            return row['flags'] if row else ''

    async def set_user_flags(self, handle: str, channel: str, flags: str):
        """Set channel-specific user flags."""
        chan_lower = channel.lower()
        async with get_db(self.db_path) as db:
            await db.insert_or_replace('user_chan_flags', handle=handle, channel=chan_lower, flags=flags)
        logger.debug(f"Set flags '{flags}' for {handle} on {channel}")

    def get_state(self, channel: str) -> Optional[ChannelState]:
        """Get current channel state."""
        chan_lower = channel.lower()
        return self.channels.get(chan_lower, None)[1] if chan_lower in self.channels else None

    def update_user(self, channel: str, nick: str, mode: str, account: str = '', host: str = ''):
        """Update user presence/info on channel."""
        chan_lower = channel.lower()
        if chan_lower in self.channels:
            state = self.channels[chan_lower][1]
            state.users[nick] = {'mode': mode, 'account': account, 'host': host}

    async def add_ban(self, channel: str, banmask: str, creator: str = 'bot', lifetime: int = 60):
        """Add ban to channel state (extend to DB as needed)."""
        chan_lower = channel.lower()
        state = self.get_state(channel)
        if state:
            state.bans.add(banmask)
            send_raw(f"MODE {channel} +b {banmask}")
        logger.info(f"Banned {banmask} on {channel} by {creator} [web:1]")

    async def enforce_modes(self, channel: str):
        """Enforce channel modes from settings."""
        settings = await self.get_settings(channel)
        if settings and settings.chanmode:
            send_raw(f"MODE {channel} {settings.chanmode}")


# Global instance
channel_mgr: Optional[ChannelManager] = None


async def init_channel_manager(db_path: str):
    """Initialize global channel manager."""
    global channel_mgr
    channel_mgr = ChannelManager(db_path)


def get_channel_mgr() -> ChannelManager:
    """Get the channel manager instance."""
    if channel_mgr is None:
        raise RuntimeError("Channel manager not initialized")
    return channel_mgr

def get_channel_info(channel_name: str):
    """Retrieve channel information from DB or cache."""
    # Example: from pydrop.db import get_channel_by_name
    # return get_channel_by_name(channel_name)
    from .db import get_db_connection  # Use relative import
    conn = get_db_connection()
    # Query logic here, e.g.:
    # cursor = conn.execute("SELECT * FROM channels WHERE name=?", (channel_name,))
    # return cursor.fetchone()
    pass  # Replace with real implementation
