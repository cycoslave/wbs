# src/channel.py
"""
Handles IRC channel management for WBS.
"""
import aiosqlite
import sqlite3
import logging
import json
from typing import Dict, Optional, List
from dataclasses import dataclass, field, asdict

from .db import get_db

log = logging.getLogger(__name__)

@dataclass
class Channel:
    """Live IRC channel state + lazy-loaded DB config"""
    name: str
    
    users: List[str] = field(default_factory=list)
    ops: List[str] = field(default_factory=list)
    voiced: List[str] = field(default_factory=list)
    bot_op: bool = False
    # Bool modes (no param)
    modes_n: bool = False
    modes_t: bool = False
    modes_p: bool = False
    modes_s: bool = False
    modes_i: bool = False
    modes_m: bool = False
    # Param modes
    limit: Optional[int] = 0
    key: Optional[str] = ''
    bans: List[str] = field(default_factory=list)
    invites: List[str] = field(default_factory=list)
    exempts: List[str] = field(default_factory=list)
    topic: Optional[str] = ''
    created: Optional[int] = 0
    
    _chan_mgr = None
    
    def _parse_and_set_modes(self, modes_str: str):
        """Parse RPL_324 or MODE msg"""
        modes = irc.modes.parse_channel_modes(modes_str)
        for sign, mode, param in modes:
            setter = {'+': self._set_mode, '-': self._clear_mode}
            setter[sign](mode, param)

    def _set_mode(self, mode: str, param: Optional[str] = None):
        bool_modes = 'ntpsim'
        if mode in bool_modes:
            setattr(self, f'modes_{mode}', True)
        elif mode == 'l':
            self.limit = int(param) if param else None
        elif mode == 'k':
            self.key = param

    def _clear_mode(self, mode: str, param: Optional[str] = None):
        bool_modes = 'ntpsim'
        if mode in bool_modes:
            setattr(self, f'modes_{mode}', False)
        elif mode == 'l':
            self.limit = None
        elif mode == 'k':
            self.key = None

    def update_irc_state(self, irc_data: dict):
        self.users = irc_data.get('user_list', [])  # Use full list
        self.bot_op = irc_data.get('bot_op', False)
        self.ops = irc_data.get('ops', [])
        self.voiced = irc_data.get('voiced', [])
        # Bool/param now live-updated via handlers; no need for raw mode str
    
    async def _load_db_config(self):
        """Lazy load channel settings from DB"""
        if not self._db_loaded and self._chan_mgr:
            self._db_config = await self._chan_mgr.get_raw(self.name)
            self._db_loaded = True
    
    # Lazy-loaded DB properties
    async def get_subnet_id(self) -> Optional[int]:
        await self._load_db_config()
        return self._db_config.get('subnet_id') if self._db_config else None
    
    async def get_modes(self) -> str:
        await self._load_db_config()
        return self._db_config.get('modes', '') if self._db_config else ''
    
    async def get_bans(self) -> List[str]:
        await self._load_db_config()
        if self._db_config:
            bans = self._db_config.get('bans', '[]')
            return json.loads(bans) if isinstance(bans, str) else bans
        return []
    
    async def get_invites(self) -> List[str]:
        await self._load_db_config()
        if self._db_config:
            invites = self._db_config.get('invites', '[]')
            return json.loads(invites) if isinstance(invites, str) else invites
        return []
    
    async def get_exempts(self) -> List[str]:
        await self._load_db_config()
        if self._db_config:
            exempts = self._db_config.get('exempts', '[]')
            return json.loads(exempts) if isinstance(exempts, str) else exempts
        return []
    
    # Flood protection
    async def get_flood_pub(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_pub', 15) if self._db_config else 15
    
    async def get_flood_pub_time(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_pub_time', 60) if self._db_config else 60
    
    async def get_flood_ctcp(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_ctcp', 3) if self._db_config else 3
    
    async def get_flood_ctcp_time(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_ctcp_time', 60) if self._db_config else 60
    
    async def get_flood_join(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_join', 5) if self._db_config else 5
    
    async def get_flood_join_time(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_join_time', 60) if self._db_config else 60
    
    async def get_flood_kick(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_kick', 3) if self._db_config else 3
    
    async def get_flood_kick_time(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_kick_time', 10) if self._db_config else 10
    
    async def get_flood_deop(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_deop', 3) if self._db_config else 3
    
    async def get_flood_deop_time(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_deop_time', 10) if self._db_config else 10
    
    async def get_flood_nick(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_nick', 5) if self._db_config else 5
    
    async def get_flood_nick_time(self) -> int:
        await self._load_db_config()
        return self._db_config.get('flood_nick_time', 60) if self._db_config else 60
    
    # Channel flags
    async def is_bitch(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_bitch', False) if self._db_config else False
    
    async def is_autoop(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_autoop', False) if self._db_config else False
    
    async def is_autovoice(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_autovoice', False) if self._db_config else False
    
    async def is_revenge(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_revenge', False) if self._db_config else False
    
    async def is_revengebots(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_revengebots', False) if self._db_config else False
    
    async def is_protectfriends(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_protectfriends', False) if self._db_config else False
    
    async def is_protectops(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_protectops', False) if self._db_config else False
    
    async def is_dontkickops(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_dontkickops', False) if self._db_config else False
    
    async def is_inactive(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_inactive', False) if self._db_config else False
    
    async def is_enforcebans(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_enforcebans', False) if self._db_config else False
    
    async def is_dynamicbans(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_dynamicbans', False) if self._db_config else False
    
    async def is_dynamicexempts(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_dynamicexempts', False) if self._db_config else False
    
    async def is_dynamicinvites(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_dynamicinvites', False) if self._db_config else False
    
    async def is_pubcom(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_pubcom', False) if self._db_config else False
    
    async def is_news(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_news', False) if self._db_config else False
    
    async def is_url(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_url', False) if self._db_config else False
    
    async def is_stats(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_stats', False) if self._db_config else False
    
    async def is_locked(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_locked', False) if self._db_config else False
    
    async def is_topiclock(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_topiclock', False) if self._db_config else False
    
    async def is_limit(self) -> bool:
        await self._load_db_config()
        return self._db_config.get('is_limit', False) if self._db_config else False
    
    # Lock state
    async def get_lock_by(self) -> Optional[str]:
        await self._load_db_config()
        return self._db_config.get('lock_by') if self._db_config else None
    
    async def get_lock_at(self) -> int:
        await self._load_db_config()
        return self._db_config.get('lock_at', 0) if self._db_config else 0
    
    async def get_lock_reason(self) -> str:
        await self._load_db_config()
        return self._db_config.get('lock_reason', '') if self._db_config else ''
    
    # Topic lock
    async def get_topiclock(self) -> str:
        await self._load_db_config()
        return self._db_config.get('topiclock', '') if self._db_config else ''
    
    async def get_topiclock_by(self) -> Optional[str]:
        await self._load_db_config()
        return self._db_config.get('topiclock_by') if self._db_config else None
    
    async def get_topiclock_at(self) -> int:
        await self._load_db_config()
        return self._db_config.get('topiclock_at', 0) if self._db_config else 0
    
    async def get_topiclock_reason(self) -> str:
        await self._load_db_config()
        return self._db_config.get('topiclock_reason', '') if self._db_config else ''
    
    # Channel limits
    async def get_limit_add(self) -> int:
        await self._load_db_config()
        return self._db_config.get('limit_add', 15) if self._db_config else 15
    
    async def get_limit_rand(self) -> int:
        await self._load_db_config()
        return self._db_config.get('limit_rand', 200) if self._db_config else 200
    
    async def get_limit_tolerance(self) -> int:
        await self._load_db_config()
        return self._db_config.get('limit_tolerance', 2) if self._db_config else 2
    
    async def get_limit_delta(self) -> int:
        await self._load_db_config()
        return self._db_config.get('limit_delta', 300) if self._db_config else 300
    
    async def get_limit_at(self) -> int:
        await self._load_db_config()
        return self._db_config.get('limit_at', 0) if self._db_config else 0
    
    # Metadata
    async def get_comment(self) -> str:
        await self._load_db_config()
        return self._db_config.get('comment', '') if self._db_config else ''
    
    async def get_created_at(self) -> int:
        await self._load_db_config()
        return self._db_config.get('created_at', 0) if self._db_config else 0
    
    async def get_updated_at(self) -> int:
        await self._load_db_config()
        return self._db_config.get('updated_at', 0) if self._db_config else 0
    
    async def get_created_by(self) -> Optional[str]:
        await self._load_db_config()
        return self._db_config.get('created_by') if self._db_config else None
    
    async def get_updated_by(self) -> Optional[str]:
        await self._load_db_config()
        return self._db_config.get('updated_by') if self._db_config else None

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

    async def get_channel(self, name: str) -> Optional[dict]:
        """Fetch channel from DB -> dict."""
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT * FROM channels WHERE name = ?",
                (name,)
            ) as cursor:
                row = await cursor.fetchone()
            
            if row:
                return dict(row)
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