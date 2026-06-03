"""
WBS Plugin: stats.py
version: 0.1.0
by: cyco
Description: Track IRC events (join, part, quit, op, deop, voice, devoice, mode, nick)
             globally and per-channel. Keeps last 3 history entries per event type
             per scope, cleaned up hourly.
"""
import time

from . import Plugin
from ..db import get_db 

EVENT_TYPES = ['join', 'part', 'quit', 'op', 'deop', 'voice', 'devoice', 'mode', 'nick']
HISTORY_KEEP = 3

class statsPlugin(Plugin):
    name    = "stats"
    version = "0.1.0"

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS stats_global (
            event_type    TEXT    PRIMARY KEY,
            last_occurred INTEGER DEFAULT 0,
            count         INTEGER DEFAULT 0,
            last_actor    TEXT    DEFAULT '',
            last_data     TEXT    DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS stats_channel (
            channel       TEXT,
            event_type    TEXT,
            last_occurred INTEGER DEFAULT 0,
            count         INTEGER DEFAULT 0,
            last_actor    TEXT    DEFAULT '',
            last_data     TEXT    DEFAULT '',
            PRIMARY KEY (channel, event_type)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS stats_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scope       TEXT,
            event_type  TEXT,
            occurred_at INTEGER DEFAULT 0,
            actor       TEXT    DEFAULT '',
            target      TEXT    DEFAULT '',
            data        TEXT    DEFAULT ''
        )
        """
    ]

    def __init__(self, core):
        super().__init__(core)

    async def load(self):
        """Initialize tables, seed global event rows, register cleanup timer."""
        await super().load()
        async with get_db(self.core.db_path) as db:
            for sql in self.TABLE_SQL:
                await db.execute(sql)
            for etype in EVENT_TYPES:
                await db.execute(
                    "INSERT OR IGNORE INTO stats_global (event_type) VALUES (?)",
                    (etype,)
                )
            await db.commit()

        self.core.send_irc({
            'cmd': 'REGISTER_IRC_TIMER',
            'name': 'stats_cleanup',
            'interval': 3600
        })
        self.log.info(f"Plugin {self.name} {self.version} loaded")

    async def unload(self):
        """Unregister timer and drop plugin tables."""
        self.core.send_irc({
            'cmd': 'UNREGISTER_IRC_TIMER',
            'name': 'stats_cleanup'
        })
        await super().unload()
        self.log.info("Stats plugin unloaded")

    async def on_JOIN(self, event):
        await self._record(
            scope=event.get('channel', 'global'),
            etype='join',
            actor=event.get('nick', ''),
            target=event.get('channel', ''),
            data=''
        )

    async def on_PART(self, event):
        await self._record(
            scope=event.get('channel', 'global'),
            etype='part',
            actor=event.get('nick', ''),
            target=event.get('channel', ''),
            data=event.get('message', '')
        )

    async def on_QUIT(self, event):
        # QUIT is not channel-scoped — global only
        await self._record(
            scope='global',
            etype='quit',
            actor=event.get('nick', ''),
            target='',
            data=event.get('message', '')
        )

    async def on_OP(self, event):
        await self._record(
            scope=event.get('channel', 'global'),
            etype='op',
            actor=event.get('nick', ''),
            target=event.get('target', ''),
            data=f"+o {event.get('target', '')}"
        )

    async def on_DEOP(self, event):
        await self._record(
            scope=event.get('channel', 'global'),
            etype='deop',
            actor=event.get('nick', ''),
            target=event.get('target', ''),
            data=f"-o {event.get('target', '')}"
        )

    async def on_VOICE(self, event):
        await self._record(
            scope=event.get('channel', 'global'),
            etype='voice',
            actor=event.get('nick', ''),
            target=event.get('target', ''),
            data=f"+v {event.get('target', '')}"
        )

    async def on_DEVOICE(self, event):
        await self._record(
            scope=event.get('channel', 'global'),
            etype='devoice',
            actor=event.get('nick', ''),
            target=event.get('target', ''),
            data=f"-v {event.get('target', '')}"
        )

    async def on_MODE(self, event):
        await self._record(
            scope=event.get('channel', 'global'),
            etype='mode',
            actor=event.get('nick', ''),
            target=event.get('channel', ''),
            data=event.get('modes', '')
        )

    async def on_NICK(self, event):
        # NICK is not channel-scoped — global only
        await self._record(
            scope='global',
            etype='nick',
            actor=event.get('old_nick', ''),
            target='',
            data=event.get('new_nick', '')
        )

    async def on_IRC_TIMER_STATS_CLEANUP(self, event):
        """Keep only the last HISTORY_KEEP entries per scope + event_type."""
        async with get_db(self.core.db_path) as db:
            await db.execute(
                f"""
                DELETE FROM stats_history
                WHERE id NOT IN (
                    SELECT id FROM (
                        SELECT id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY scope, event_type
                                   ORDER BY occurred_at DESC
                               ) AS rn
                        FROM stats_history
                    ) ranked
                    WHERE rn <= {HISTORY_KEEP}
                )
                """
            )
            await db.commit()
        self.log.info("Stats history cleaned (kept last %d per scope/type)", HISTORY_KEEP)

    async def _record(self, scope: str, etype: str, actor: str, target: str, data: str):
        """Update aggregate stats and append a history row."""
        now = int(time.time())
        async with get_db(self.core.db_path) as db:
            # Global aggregate
            await db.execute(
                """
                INSERT INTO stats_global (event_type, last_occurred, count, last_actor, last_data)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(event_type) DO UPDATE SET
                    last_occurred = excluded.last_occurred,
                    count         = count + 1,
                    last_actor    = excluded.last_actor,
                    last_data     = excluded.last_data
                """,
                (etype, now, actor, data)
            )

            # Per-channel aggregate (skip for global-only events like QUIT, NICK)
            if scope != 'global':
                await db.execute(
                    """
                    INSERT INTO stats_channel (channel, event_type, last_occurred, count, last_actor, last_data)
                    VALUES (?, ?, ?, 1, ?, ?)
                    ON CONFLICT(channel, event_type) DO UPDATE SET
                        last_occurred = excluded.last_occurred,
                        count         = count + 1,
                        last_actor    = excluded.last_actor,
                        last_data     = excluded.last_data
                    """,
                    (scope, etype, now, actor, data)
                )

            # History row
            await db.execute(
                """
                INSERT INTO stats_history (scope, event_type, occurred_at, actor, target, data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scope, etype, now, actor, target, data)
            )
            await db.commit()
            
    async def get(self, scope: str, etype: str) -> dict | None:
        """
        .stats [#channel|global] <event_type>
        Returns count, last_occurred, last_actor, last_data + last 3 history rows.
        """
        async with get_db(self.core.db_path) as db:
            if scope == 'global':
                async with db.execute(
                    "SELECT * FROM stats_global WHERE event_type = ?", (etype,)
                ) as cur:
                    row = await cur.fetchone()
            else:
                async with db.execute(
                    "SELECT * FROM stats_channel WHERE channel = ? AND event_type = ?",
                    (scope, etype)
                ) as cur:
                    row = await cur.fetchone()

            if not row:
                return None

            async with db.execute(
                """
                SELECT occurred_at, actor, target, data
                FROM stats_history
                WHERE scope = ? AND event_type = ?
                ORDER BY occurred_at DESC
                LIMIT ?
                """,
                (scope, etype, HISTORY_KEEP)
            ) as cur:
                history = await cur.fetchall()

        return {
            'event_type':    etype,
            'scope':         scope,
            'count':         row['count'],
            'last_occurred': row['last_occurred'],
            'last_actor':    row['last_actor'],
            'last_data':     row['last_data'],
            'history':       [dict(h) for h in history]
        }
