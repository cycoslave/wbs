# src/channel.py
"""
Handles IRC channel management for WBS.
"""
import logging
import json
from irc import modes
from typing import Dict, Optional, List
from dataclasses import dataclass, field, asdict

from .db import get_db

log = logging.getLogger("wbs.channel")
_SYNC_ALLOWED_COLUMNS = frozenset({
    'comment', 'is_inactive', 'is_bitch', 'is_autoop', 'is_autovoice',
    'is_revenge', 'is_revengebots', 'is_protectfriends', 'is_protectops',
    'is_dontkickops', 'is_enforcebans', 'is_dynamicbans', 'is_dynamicexempts',
    'is_dynamicinvites', 'is_pubcom', 'is_news', 'is_url', 'is_stats',
    'is_locked', 'lock_by', 'lock_at', 'lock_reason',
    'is_topiclock', 'topiclock', 'topiclock_by', 'topiclock_at', 'topiclock_reason',
    'is_limit', 'limit_add', 'limit_rand', 'limit_tolerance', 'limit_delta',
    'modes', 'bans', 'invites', 'exempts',
    'flood_pub', 'flood_pub_time', 'flood_ctcp', 'flood_ctcp_time',
    'flood_join', 'flood_join_time', 'flood_kick', 'flood_kick_time',
    'flood_deop', 'flood_deop_time', 'flood_nick', 'flood_nick_time',
})

@dataclass
class Channel:
    """Live IRC channel state + lazy-loaded DB config"""
    name: str

    # --- Live IRC state ---
    users: List[str] = field(default_factory=list)
    ops: List[str] = field(default_factory=list)
    voiced: List[str] = field(default_factory=list)
    bot_op: bool = False
    synced: bool = False
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

    # Private — initialized in __post_init__
    _chan_mgr: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        self._db_loaded: bool = False
        self._db_config: Optional[dict] = None
        self.name = self.name.lower()

    # Live IRC state — membership
    def add_user(self, nick: str):
        nick = nick.lower()
        if nick not in self.users:
            self.users.append(nick)

    def remove_user(self, nick: str):
        nick = nick.lower()
        self.users = [n for n in self.users if n != nick]
        self.unset_op(nick)
        self.voiced = [n for n in self.voiced if n != nick]

    def rename_user(self, old: str, new: str):
        old, new = old.lower(), new.lower()
        self.users  = [new if n == old else n for n in self.users]
        self.ops    = [new if n == old else n for n in self.ops]
        self.voiced = [new if n == old else n for n in self.voiced]

    def clear_state(self):
        """Reset all live IRC state (e.g. on bot PART or disconnect)."""
        self.users.clear()
        self.ops.clear()
        self.voiced.clear()
        self.bans.clear()
        self.invites.clear()
        self.exempts.clear()
        self.bot_op = False
        self.synced = False
        self.limit = 0
        self.key = ''
        self.topic = ''

    # Live IRC state — op/voice
    def is_op(self, nick: str) -> bool:
        return nick.lower() in self.ops

    def set_op(self, nick: str, botname: str = ''):
        nick = nick.lower()
        if nick not in self.ops:
            self.ops.append(nick)
        if botname and nick == botname.lower():
            self.bot_op = True

    def unset_op(self, nick: str, botname: str = ''):
        nick = nick.lower()
        self.ops = [n for n in self.ops if n != nick]
        if botname and nick == botname.lower():
            self.bot_op = False

    def is_voiced(self, nick: str) -> bool:
        return nick.lower() in self.voiced

    def set_voice(self, nick: str):
        nick = nick.lower()
        if nick not in self.voiced:
            self.voiced.append(nick)

    def unset_voice(self, nick: str):
        nick = nick.lower()
        self.voiced = [n for n in self.voiced if n != nick]

    # Live IRC state — modes
    def _parse_and_set_modes(self, modes_str: str):
        """Parse RPL_324 or MODE msg and apply to live state."""
        parsed = modes.parse_channel_modes(modes_str)
        for sign, mode, param in parsed:
            if sign == '+':
                self._set_mode(mode, param)
            else:
                self._clear_mode(mode, param)

    def _set_mode(self, mode: str, param: Optional[str] = None):
        if mode in 'ntpsim':
            setattr(self, f'modes_{mode}', True)
        elif mode == 'l':
            self.limit = int(param) if param else None
        elif mode == 'k':
            self.key = param

    def _clear_mode(self, mode: str, param: Optional[str] = None):
        if mode in 'ntpsim':
            setattr(self, f'modes_{mode}', False)
        elif mode == 'l':
            self.limit = None
        elif mode == 'k':
            self.key = None

    def update_irc_state(self, irc_data: dict):
        self.users   = irc_data.get('user_list', [])
        self.bot_op  = irc_data.get('bot_op', False)
        self.ops     = irc_data.get('ops', [])
        self.voiced  = irc_data.get('voiced', [])

    # DB — lazy load
    async def _load_db_config(self):
        if not self._db_loaded and self._chan_mgr:
            self._db_config = await self._chan_mgr.get_raw(self.name)
            self._db_loaded = True

    def invalidate_cache(self):
        """Force next DB access to reload from database."""
        self._db_loaded = False
        self._db_config = None

    # DB — subnet binding
    async def get_subnet_ids(self, channel: str) -> list[int]:
        """Return all subnet_ids bound to this channel. Empty = global."""
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT subnet_id FROM channel_subnets WHERE channel_name = ? ORDER BY subnet_id",
                (channel,)
            )
        return [row["subnet_id"] for row in rows]

    async def is_global(self, channel: str) -> bool:
        """A channel with no subnet bindings is active on all subnets."""
        return len(await self.get_subnet_ids(channel)) == 0

    async def bind_to_subnet(self, channel: str, subnet_id: int, created_by: Optional[str] = None) -> bool:
        """Bind a channel to a specific subnet."""
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                """INSERT OR IGNORE INTO channel_subnets
                (channel_name, subnet_id, created_by)
                VALUES (?, ?, ?)""",
                (channel, subnet_id, created_by)
            )
            await db.commit()
        return cursor.rowcount > 0

    async def unbind_from_subnet(self, channel: str, subnet_id: int) -> bool:
        """Remove a specific subnet binding."""
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                "DELETE FROM channel_subnets WHERE channel_name = ? AND subnet_id = ?",
                (channel, subnet_id)
            )
            await db.commit()
        return cursor.rowcount > 0

    async def make_global(self, channel: str) -> bool:
        """Remove all subnet bindings — channel becomes active on all subnets."""
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                "DELETE FROM channel_subnets WHERE channel_name = ?",
                (channel,)
            )
            await db.commit()
        return cursor.rowcount > 0

    async def get_channels_for_subnet(self, subnet_id: int) -> list[str]:
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                """
                SELECT name FROM channels
                WHERE is_inactive = 0
                AND deleted_at IS NULL
                AND (
                    EXISTS (
                    SELECT 1 FROM channel_subnets cs
                    WHERE cs.channel_name = channels.name AND cs.subnet_id = ?
                    )
                    OR NOT EXISTS (
                    SELECT 1 FROM channel_subnets cs2
                    WHERE cs2.channel_name = channels.name
                    )
                )
                ORDER BY name
                """,
                (subnet_id,)
            )
        return [row["name"] for row in rows]

    # DB — config properties (lazy)
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

    async def addchan(self, channel: str, subnet_id: int = None, created_by: str = None) -> bool:
        """
        Add a channel. If subnet_id is None the channel is global (joins on all subnets).
        Handles resurrection of soft-deleted channels.
        """
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT name, deleted_at FROM channels WHERE name = ?", (channel,)
            ) as cur:
                row = await cur.fetchone()

            now = int(__import__('time').time())

            if row:
                if row[1] is None:
                    raise ValueError(f"Channel {channel} already exists")
                # Resurrect soft-deleted channel
                await db.execute(
                    "UPDATE channels SET deleted_at = NULL, updated_at = ?, updated_by = ? WHERE name = ?",
                    (now, created_by, channel)
                )
            else:
                # No subnet_id column on channels — global/subnet scope
                # is handled exclusively via channel_subnets
                await db.execute(
                    "INSERT INTO channels (name, created_by, updated_at) VALUES (?, ?, ?)",
                    (channel, created_by, now)
                )

            if subnet_id is not None:
                # Schema uses created_by — not added_by
                await db.execute(
                    """INSERT OR IGNORE INTO channel_subnets
                    (channel_name, subnet_id, created_by)
                    VALUES (?, ?, ?)""",
                    (channel, subnet_id, created_by)
                )

            await db.commit()
            return True

    async def delchan(self, channel: str, deleted_by: str = None) -> bool:
        """Soft-delete a channel (sets deleted_at, keeps row for sync)."""
        async with get_db(self.db_path) as db:
            now = int(__import__('time').time())
            cur = await db.execute(
                "UPDATE channels SET deleted_at = ?, updated_at = ?, updated_by = ? "
                "WHERE name = ? AND deleted_at IS NULL",
                (now, now, deleted_by, channel)
            )
            await db.commit()
            return cur.rowcount > 0

    async def getchans(self, subnet_id: int = None) -> list:
        """
        Return active (non-deleted) channel names.
        If subnet_id is given, only return channels belonging to that subnet
        OR channels with no subnet binding (global channels).
        """
        async with get_db(self.db_path) as db:
            if subnet_id is not None:
                rows = await db.execute_fetchall(
                    """
                    SELECT c.name FROM channels c
                    WHERE c.deleted_at IS NULL
                      AND c.is_inactive = 0
                      AND (
                        EXISTS (
                          SELECT 1 FROM channel_subnets cs
                          WHERE cs.channel_name = c.name AND cs.subnet_id = ?
                        )
                        OR NOT EXISTS (
                          SELECT 1 FROM channel_subnets cs2
                          WHERE cs2.channel_name = c.name
                        )
                      )
                    ORDER BY c.name
                    """,
                    (subnet_id,)
                )
            else:
                rows = await db.execute_fetchall(
                    "SELECT name FROM channels WHERE deleted_at IS NULL AND is_inactive = 0 ORDER BY name"
                )
            return [r["name"] for r in rows]

    async def listchans(self) -> str:
        """List all channels including soft-deleted (for admin view)."""
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                """
                SELECT c.name, c.comment, c.is_inactive, c.deleted_at,
                       GROUP_CONCAT(cs.subnet_id) AS subnet_ids
                FROM channels c
                LEFT JOIN channel_subnets cs ON cs.channel_name = c.name
                GROUP BY c.name
                ORDER BY c.name
                """
            )
            result = ["Channels:"]
            for row in rows:
                if row["deleted_at"]:
                    status = " (deleted)"
                elif row["is_inactive"]:
                    status = " (inactive)"
                else:
                    status = ""
                scope = f"subnets [{row['subnet_ids']}]" if row["subnet_ids"] else "all subnets"
                result.append(f"  {row['name']}{status} [{scope}] - {row['comment']}")
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
            return "\n".join(result)

    async def exist(self, channel: str) -> bool:
        """Return True if a channel exists and is not deleted."""
        async with get_db(self.db_path) as db:
            row = await db.execute_fetchone(
                "SELECT 1 FROM channels WHERE name = ? AND deleted_at IS NULL",
                (channel.lower(),)
            )
        return row is not None

    def channel_to_dict(self, channel: Channel) -> dict:
        """Convert Channel to dict for DB INSERT/UPDATE."""
        data = asdict(channel)
        # Convert lists back to JSON strings for DB
        data['bans'] = json.dumps(data['bans'])
        data['invites'] = json.dumps(data['invites'])
        data['exempts'] = json.dumps(data['exempts'])
        return data

    async def get_channel(self, name: str) -> Optional[dict]:
        async with get_db(self.db_path) as db:
            async with db.execute("SELECT * FROM channels WHERE name = ?", (name,)) as cursor:
                row = await cursor.fetchone()

            if not row:
                return None

            data = dict(row)
            subnet_rows = await db.execute_fetchall(
                "SELECT subnet_id FROM channel_subnets WHERE channel_name = ? ORDER BY subnet_id",
                (name,)
            )
            data["subnet_ids"] = [r["subnet_id"] for r in subnet_rows]
            return data

    async def get_all_channels(self) -> list[Channel]:
        """Get all channels."""
        async with get_db(self.db_path) as db:
            rows = await db.execute("SELECT * FROM channels ORDER BY name").fetchall()
            return [Channel(**dict(row)) for row in rows]

    async def create_channel(self, name: str, subnet_id: Optional[int] = None,
                            created_by: Optional[str] = None) -> Channel:
        """
        Create a new channel row. Subnet binding goes to channel_subnets, not channels.
        """
        now = int(__import__('time').time())
        channel = Channel(name=name)

        async with get_db(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO channels (name, comment, created_at, updated_at, created_by)
                VALUES (?, '', ?, ?, ?)
                """,
                (channel.name, now, now, created_by)
            )

            if subnet_id is not None:
                await db.execute(
                    """INSERT OR IGNORE INTO channel_subnets
                    (channel_name, subnet_id, created_by)
                    VALUES (?, ?, ?)""",
                    (channel.name, subnet_id, created_by)
                )

            await db.commit()

        return channel

    async def merge_from_peer(self, channels: list[dict], from_bot: str) -> None:
        """
        Merge channel records from a botnet peer.
        Last-write-wins on updated_at. channel_subnets merged idempotently.
        """
        async with get_db(self.db_path) as db:
            for ch in channels:
                name = ch['name']
                remote_updated = ch.get('updated_at') or 0
                remote_deleted = ch.get('deleted_at')

                cur = await db.execute(
                    "SELECT updated_at, deleted_at FROM channels WHERE name = ?", (name,)
                )
                existing = await cur.fetchone()

                if existing:
                    local_updated = existing[0] or 0
                    local_deleted = existing[1]
                    if remote_updated <= local_updated:
                        pass  # Skip channel row but still sync subnets below
                    else:
                        final_deleted = remote_deleted
                        if remote_deleted is None and local_deleted and local_deleted > remote_updated:
                            final_deleted = local_deleted

                        # Use the allowlist — same safe columns as sync_channel_settings
                        safe = {k: ch.get(k) for k in _SYNC_ALLOWED_COLUMNS if k in ch}
                        if safe:
                            safe['updated_at'] = remote_updated
                            safe['updated_by'] = from_bot
                            safe['deleted_at'] = final_deleted
                            set_clause = ', '.join(f"{col} = ?" for col in safe)
                            await db.execute(
                                f"UPDATE channels SET {set_clause} WHERE name = ?",
                                (*safe.values(), name)
                            )
                else:
                    await db.execute(
                        """INSERT INTO channels
                            (name, comment, modes, bans, invites, exempts,
                            is_bitch, is_autoop, is_autovoice, is_revenge, is_revengebots,
                            is_protectfriends, is_protectops, is_dontkickops, is_inactive,
                            is_enforcebans, is_dynamicbans, is_dynamicexempts, is_dynamicinvites,
                            is_locked, lock_by, lock_at, lock_reason,
                            is_topiclock, topiclock, topiclock_by, topiclock_at, topiclock_reason,
                            is_limit, limit_add, limit_rand, limit_tolerance, limit_delta,
                            flood_pub, flood_pub_time, flood_ctcp, flood_ctcp_time,
                            flood_join, flood_join_time, flood_kick, flood_kick_time,
                            flood_deop, flood_deop_time, flood_nick, flood_nick_time,
                            created_at, updated_at, created_by, deleted_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            name, ch.get('comment', ''), ch.get('modes', ''),
                            ch.get('bans', '[]'), ch.get('invites', '[]'), ch.get('exempts', '[]'),
                            ch.get('is_bitch', 0), ch.get('is_autoop', 0), ch.get('is_autovoice', 0),
                            ch.get('is_revenge', 0), ch.get('is_revengebots', 0),
                            ch.get('is_protectfriends', 0), ch.get('is_protectops', 0),
                            ch.get('is_dontkickops', 0), ch.get('is_inactive', 0),
                            ch.get('is_enforcebans', 0), ch.get('is_dynamicbans', 0),
                            ch.get('is_dynamicexempts', 0), ch.get('is_dynamicinvites', 0),
                            ch.get('is_locked', 0), ch.get('lock_by'), ch.get('lock_at', 0),
                            ch.get('lock_reason', ''), ch.get('is_topiclock', 0),
                            ch.get('topiclock', ''), ch.get('topiclock_by'), ch.get('topiclock_at', 0),
                            ch.get('topiclock_reason', ''), ch.get('is_limit', 0),
                            ch.get('limit_add', 15), ch.get('limit_rand', 200),
                            ch.get('limit_tolerance', 2), ch.get('limit_delta', 300),
                            ch.get('flood_pub', 15), ch.get('flood_pub_time', 60),
                            ch.get('flood_ctcp', 3), ch.get('flood_ctcp_time', 60),
                            ch.get('flood_join', 5), ch.get('flood_join_time', 60),
                            ch.get('flood_kick', 3), ch.get('flood_kick_time', 10),
                            ch.get('flood_deop', 3), ch.get('flood_deop_time', 10),
                            ch.get('flood_nick', 5), ch.get('flood_nick_time', 60),
                            ch.get('created_at', 0), remote_updated, from_bot, remote_deleted
                        )
                    )

                # Merge channel_subnets — idempotent
                for sid in ch.get('subnet_ids', []):
                    await db.execute(
                        """INSERT OR IGNORE INTO channel_subnets
                        (channel_name, subnet_id, created_by)
                        VALUES (?, ?, ?)""",
                        (name, sid, from_bot)   # created_by — not added_by
                    )

            await db.commit()
        log.info(f"ChannelManager.merge_from_peer: merged {len(channels)} channels from {from_bot}")

    async def serialize_for_peer(self) -> list[dict]:
        """Return all channels with their subnet_ids for botnet share."""
        async with get_db(self.db_path) as db:
            cursor = await db.execute("SELECT * FROM channels")
            rows = await cursor.fetchall()
            channels = []
            for row in rows:
                ch = dict(row)
                # Attach subnet_ids so receiver can merge channel_subnets
                sub_cur = await db.execute(
                    "SELECT subnet_id FROM channel_subnets WHERE channel_name = ?",
                    (ch['name'],)
                )
                ch['subnet_ids'] = [r[0] for r in await sub_cur.fetchall()]
                channels.append(ch)
        return channels        