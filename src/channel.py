# src/channel.py
"""
Handles IRC channel management for WBS.

Manages channel state, settings, bans, user flags on channels, and DB interactions.
Inspired by Eggdrop channels module.
"""

import asyncio
import logging
import json
from typing import Dict, Optional, Callable
from dataclasses import dataclass, field

from .db import get_db, ChannelSettingsRow, UserChanFlagsRow

logger = logging.getLogger(__name__)


@dataclass
class ChannelState:
    """Runtime state of a channel."""
    users: Dict[str, Dict[str, str]] = field(default_factory=dict)  # nick -> {'mode': 'op/voice/normal', 'account': str, 'host': str}
    modes: str = ''
    topic: str = ''
    bans: set[str] = field(default_factory=set)
    exempts: set[str] = field(default_factory=set)
    invites: set[str] = field(default_factory=set)


class ChannelManager:
    """Manages all channels the bot is on."""

    def __init__(self, db_path: str, irc_send_callback: Optional[Callable] = None):
        """
        Args:
            db_path: Path to SQLite database
            irc_send_callback: Callback function to send raw IRC commands (injected by core.py)
        """
        self.channels: Dict[str, tuple[ChannelSettingsRow, ChannelState]] = {}
        self.db_path = db_path
        self._irc_send = irc_send_callback
        self._initialized = False

    async def initialize(self):
        """Async initialization - call this after construction."""
        if not self._initialized:
            await self._load_channels()
            self._initialized = True

    def set_irc_callback(self, callback: Callable):
        """Set IRC send callback after initialization."""
        self._irc_send = callback

    async def _load_channels(self):
        """Load channel settings from DB."""
        try:
            async with get_db(self.db_path) as db:
                rows = await db.fetchall("SELECT * FROM channel_settings")
                for row in rows:
                    settings = ChannelSettingsRow(**row)
                    self.channels[settings.channel.lower()] = (settings, ChannelState())
                logger.info(f"Loaded {len(rows)} channels from database")
        except Exception as e:
            logger.error(f"Failed to load channels: {e}")

    async def add_channel(self, channel: str, settings_dict: Optional[dict] = None) -> bool:
        """
        Add new channel with default or given settings.
        
        Args:
            channel: Channel name (e.g., '#main')
            settings_dict: Optional settings override
            
        Returns:
            True if added successfully, False if already exists
        """
        channel_lower = channel.lower()
        if channel_lower in self.channels:
            logger.warning(f"Channel {channel} already exists")
            return False

        defaults = {
            'chanmode': '+nt',
            'idle_kick': 0,
            'flood_chan': '15:60',
            'enforce_bans': 1,
            'cycle': 5,
            'dontkickops': 1,
            'statuslog': 1,
        }
        if settings_dict:
            defaults.update(settings_dict)

        try:
            async with get_db(self.db_path) as db:
                # Insert with defaults
                columns = ['channel'] + list(defaults.keys())
                placeholders = ', '.join(['?'] * len(columns))
                values = [channel_lower] + list(defaults.values())
                
                await db.execute(
                    f"INSERT OR IGNORE INTO channel_settings ({', '.join(columns)}) VALUES ({placeholders})",
                    tuple(values)
                )
                
                row = await db.fetchone("SELECT * FROM channel_settings WHERE channel = ?", (channel_lower,))
                if row:
                    settings = ChannelSettingsRow(**row)
                    self.channels[channel_lower] = (settings, ChannelState())
                    logger.info(f"Added channel {channel}")
                    return True
        except Exception as e:
            logger.error(f"Failed to add channel {channel}: {e}")
        
        return False

    async def remove_channel(self, channel: str) -> bool:
        """Remove channel and related DB records."""
        channel_lower = channel.lower()
        if channel_lower not in self.channels:
            logger.warning(f"Channel {channel} not found")
            return False

        try:
            async with get_db(self.db_path) as db:
                await db.execute("DELETE FROM channel_settings WHERE channel = ?", (channel_lower,))
                await db.execute("DELETE FROM user_chan_flags WHERE channel = ?", (channel_lower,))
            
            del self.channels[channel_lower]
            logger.info(f"Removed channel {channel}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove channel {channel}: {e}")
            return False

    async def get_settings(self, channel: str) -> Optional[ChannelSettingsRow]:
        """Get channel settings."""
        entry = self.channels.get(channel.lower())
        return entry[0] if entry else None

    async def set_setting(self, channel: str, key: str, value) -> bool:
        """
        Set a channel setting and update in-memory.
        
        Args:
            channel: Channel name
            key: Setting key (must be valid column in channel_settings)
            value: New value
        """
        chan_lower = channel.lower()
        if chan_lower not in self.channels:
            logger.warning(f"Cannot set setting for unknown channel {channel}")
            return False
        
        try:
            async with get_db(self.db_path) as db:
                await db.execute(
                    f"UPDATE channel_settings SET {key} = ? WHERE channel = ?",
                    (value, chan_lower)
                )
                row = await db.fetchone("SELECT * FROM channel_settings WHERE channel = ?", (chan_lower,))
                if row:
                    self.channels[chan_lower] = (ChannelSettingsRow(**row), self.channels[chan_lower][1])
                    logger.debug(f"Updated {channel} setting {key} = {value}")
                    return True
        except Exception as e:
            logger.error(f"Failed to set {key} for {channel}: {e}")
        
        return False

    async def get_user_flags(self, handle: str, channel: str) -> str:
        """Get channel-specific user flags (e.g., 'o' for op, 'v' for voice)."""
        chan_lower = channel.lower()
        try:
            async with get_db(self.db_path) as db:
                row = await db.fetchone(
                    "SELECT flags FROM user_chan_flags WHERE handle = ? AND channel = ?",
                    (handle, chan_lower)
                )
                return row['flags'] if row else ''
        except Exception as e:
            logger.error(f"Failed to get user flags for {handle} on {channel}: {e}")
            return ''

    async def set_user_flags(self, handle: str, channel: str, flags: str):
        """Set channel-specific user flags."""
        chan_lower = channel.lower()
        try:
            async with get_db(self.db_path) as db:
                await db.execute(
                    "INSERT OR REPLACE INTO user_chan_flags (handle, channel, flags) VALUES (?, ?, ?)",
                    (handle, chan_lower, flags)
                )
            logger.debug(f"Set flags '{flags}' for {handle} on {channel}")
        except Exception as e:
            logger.error(f"Failed to set user flags for {handle} on {channel}: {e}")

    def get_state(self, channel: str) -> Optional[ChannelState]:
        """Get current channel state."""
        entry = self.channels.get(channel.lower())
        return entry[1] if entry else None

    def update_user(self, channel: str, nick: str, mode: str, account: str = '', host: str = ''):
        """Update user presence/info on channel."""
        chan_lower = channel.lower()
        if chan_lower in self.channels:
            state = self.channels[chan_lower][1]
            state.users[nick] = {'mode': mode, 'account': account, 'host': host}
            logger.debug(f"Updated user {nick} on {channel}: mode={mode}")

    def remove_user(self, channel: str, nick: str):
        """Remove user from channel state (on PART/KICK/QUIT)."""
        chan_lower = channel.lower()
        if chan_lower in self.channels:
            state = self.channels[chan_lower][1]
            if nick in state.users:
                del state.users[nick]
                logger.debug(f"Removed user {nick} from {channel}")

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
