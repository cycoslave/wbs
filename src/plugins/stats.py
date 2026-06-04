# src/plugins/stats.py
"""
WBS Plugin: stats.py
version: 0.2.0
by: cyco

Description:
    Comprehensive per-nick and per-channel IRC statistics tracker.
    Tracks: messages, actions (/me), emojis, URLs, characters, bytes,
    joins, parts, quits, nick changes, ops, deops, halfops, dehalfops,
    voice, devoice, kicks, bans, unbans, topic changes, channel mode
    changes, and unique victim counts.

    Stats are stored per-nick globally and per-nick-per-channel.

    Public commands (requires pubcom integration):
        !stats [nick]       — show stats for nick in current channel
        !topstats [n]       — top n nicks by messages in channel

    Partyline commands:
        .stats [#channel] [nick]    — show stats for nick
        .topstats [#channel] [n]    — top n nicks by messages
"""
from __future__ import annotations

import re
import time
from typing import Optional

from . import Plugin
from ..db import get_db

_EMOJI_RE = re.compile(
    "["
    "\U0001F600-\U0001F64F"
    "\U0001F300-\U0001F5FF"
    "\U0001F680-\U0001F6FF"
    "\U0001F1E0-\U0001F1FF"
    "\U00002600-\U000027BF"
    "\U0001F900-\U0001F9FF"
    "\U00002702-\U000027B0"
    "\U000024C2-\U0001F251"
    "]+",
    flags=re.UNICODE,
)
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_LITERAL_COLS = {"last_seen", "last_message"}
_HANDLED_MODE_CHARS = re.compile(r"[+\-ohvbeI]")
_SAFE_ORDER_COLS = frozenset({
    "messages", "actions", "characters", "bytes_total",
    "kicks_given", "bans_given", "ops_given", "voices_given",
    "victims", "topics_set", "emoji_count", "url_count",
})

def _count_emojis(text: str) -> int:
    return sum(len(m.group(0)) for m in _EMOJI_RE.finditer(text))

def _count_urls(text: str) -> int:
    return len(_URL_RE.findall(text))

class statsPlugin(Plugin):
    name    = "stats"
    version = "0.2.0"

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS stats_nick (
            nick            TEXT PRIMARY KEY,
            messages        INTEGER DEFAULT 0,
            actions         INTEGER DEFAULT 0,
            emoji_count     INTEGER DEFAULT 0,
            url_count       INTEGER DEFAULT 0,
            characters      INTEGER DEFAULT 0,
            bytes_total     INTEGER DEFAULT 0,
            joins           INTEGER DEFAULT 0,
            parts           INTEGER DEFAULT 0,
            quits           INTEGER DEFAULT 0,
            nick_changes    INTEGER DEFAULT 0,
            ops_given       INTEGER DEFAULT 0,
            deops_given     INTEGER DEFAULT 0,
            halfops_given   INTEGER DEFAULT 0,
            dehalfops_given INTEGER DEFAULT 0,
            voices_given    INTEGER DEFAULT 0,
            devoices_given  INTEGER DEFAULT 0,
            kicks_given     INTEGER DEFAULT 0,
            bans_given      INTEGER DEFAULT 0,
            unbans_given    INTEGER DEFAULT 0,
            topics_set      INTEGER DEFAULT 0,
            mode_changes    INTEGER DEFAULT 0,
            victims         INTEGER DEFAULT 0,
            last_seen       INTEGER DEFAULT 0,
            last_message    TEXT    DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS stats_nick_channel (
            nick            TEXT,
            channel         TEXT,
            messages        INTEGER DEFAULT 0,
            actions         INTEGER DEFAULT 0,
            emoji_count     INTEGER DEFAULT 0,
            url_count       INTEGER DEFAULT 0,
            characters      INTEGER DEFAULT 0,
            bytes_total     INTEGER DEFAULT 0,
            joins           INTEGER DEFAULT 0,
            parts           INTEGER DEFAULT 0,
            ops_given       INTEGER DEFAULT 0,
            deops_given     INTEGER DEFAULT 0,
            halfops_given   INTEGER DEFAULT 0,
            dehalfops_given INTEGER DEFAULT 0,
            voices_given    INTEGER DEFAULT 0,
            devoices_given  INTEGER DEFAULT 0,
            kicks_given     INTEGER DEFAULT 0,
            bans_given      INTEGER DEFAULT 0,
            unbans_given    INTEGER DEFAULT 0,
            topics_set      INTEGER DEFAULT 0,
            mode_changes    INTEGER DEFAULT 0,
            victims         INTEGER DEFAULT 0,
            last_seen       INTEGER DEFAULT 0,
            last_message    TEXT    DEFAULT '',
            PRIMARY KEY (nick, channel)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS stats_victims (
            actor   TEXT NOT NULL,
            victim  TEXT NOT NULL,
            scope   TEXT NOT NULL DEFAULT 'global',
            PRIMARY KEY (actor, victim, scope)
        )
        """,
    ]

    def __init__(self, core):
        super().__init__(core)

    async def load(self) -> None:
        await super().load()
        async with get_db(self.core.db_path) as db:
            await self._migrate(db)
            for sql in self.TABLE_SQL:
                await db.execute(sql)
            await db.commit()
        self.log.info("Plugin %s %s loaded", self.name, self.version)

    async def unload(self) -> None:
        self.log.info("Plugin %s unloading", self.name)
        await super().unload()

    async def _migrate(self, db) -> None:
        """Drop v0.1.0 tables if they exist (one-time, idempotent)."""
        for old_table in ("stats_global", "stats_channel", "stats_history"):
            await db.execute(f"DROP TABLE IF EXISTS {old_table}")
        self.log.debug("stats: migration check complete")

    async def _reply(self, channel: str, text: str) -> None:
        """Send a PRIVMSG to *channel* via the IRC layer."""
        irc = getattr(self.core, "irc", None)
        if irc and channel:
            await irc.privmsg(channel, text)

    async def _cmd_stats(self, channel: str, target: str, requester: str) -> None:
        """Handler for !stats [nick]"""
        row = await self.get_nick_stats(target, channel)
        if not row:
            await self._reply(channel, f"{requester}: No stats found for {target} in {channel}.")
            return
        import datetime
        last = datetime.datetime.fromtimestamp(row["last_seen"]).strftime("%Y-%m-%d %H:%M")
        await self._reply(
            channel,
            f"\x02{target}\x02 [{channel}] — "
            f"msgs: {row['messages']} | "
            f"actions: {row['actions']} | "
            f"chars: {row['characters']} | "
            f"urls: {row['url_count']} | "
            f"emoji: {row['emoji_count']} | "
            f"kicks: {row['kicks_given']} | "
            f"last: {last}",
        )

    async def _cmd_topstats(self, channel: str, n: int) -> None:
        """Handler for !topstats [n]"""
        rows = await self.get_top_nicks(channel=channel, limit=n)
        if not rows:
            await self._reply(channel, f"No stats recorded for {channel} yet.")
            return
        parts = [f"{i+1}. \x02{r['nick']}\x02 ({r['messages']} msgs)"
                for i, r in enumerate(rows)]
        await self._reply(channel, f"Top {n} in {channel}: " + " | ".join(parts))

    async def on_PUBMSG(self, event: dict) -> None:
        """Public channel message — also handles CTCP ACTION (/me)."""
        nick    = event.get("nick", "")
        channel = event.get("channel", "")
        text    = event.get("text", "") or event.get("message", "")

        is_action = text.startswith("\x01ACTION") and text.endswith("\x01")
        if is_action:
            text = text[len("\x01ACTION "):-1]

        if not is_action and text.startswith("!"):
            parts = text.split()
            cmd   = parts[0].lower()
            if cmd == "!stats":
                target = parts[1] if len(parts) > 1 else nick
                await self._cmd_stats(channel, target, nick)
            elif cmd == "!topstats":
                n = 5
                if len(parts) > 1:
                    try:
                        n = max(1, min(int(parts[1]), 10))
                    except ValueError:
                        pass
                await self._cmd_topstats(channel, n)
        nick    = event.get("nick", "")
        channel = event.get("channel", "")
        text    = event.get("text", "") or event.get("message", "")

        is_action = text.startswith("\x01ACTION") and text.endswith("\x01")
        if is_action:
            text = text[len("\x01ACTION "):-1]

        emojis = _count_emojis(text)
        urls   = _count_urls(text)
        chars  = len(text)
        byt    = len(text.encode("utf-8"))

        delta = {
            "messages":    0 if is_action else 1,
            "actions":     1 if is_action else 0,
            "emoji_count": emojis,
            "url_count":   urls,
            "characters":  chars,
            "bytes_total": byt,
            "last_seen":   int(time.time()),
            "last_message": text[:400],
        }

        await self._upsert_nick(nick, delta)
        if channel:
            await self._upsert_nick_channel(nick, channel, delta)

    async def on_ACTION(self, event: dict) -> None:
        """
        Handles ACTION if core dispatches it as a distinct event type.
        Guard flag prevents double-counting if core also delivers it as
        a CTCP PUBMSG (on_PUBMSG handles that case).
        """
        if event.get("_via_pubmsg"):
            return
        await self.on_PUBMSG({**event, "_via_pubmsg": True})

    async def on_JOIN(self, event: dict) -> None:
        nick    = event.get("nick", "")
        channel = event.get("channel", "")
        now     = int(time.time())
        await self._upsert_nick(nick, {"joins": 1, "last_seen": now})
        if channel:
            await self._upsert_nick_channel(nick, channel, {"joins": 1, "last_seen": now})

    async def on_PART(self, event: dict) -> None:
        nick    = event.get("nick", "")
        channel = event.get("channel", "")
        now     = int(time.time())
        await self._upsert_nick(nick, {"parts": 1, "last_seen": now})
        if channel:
            await self._upsert_nick_channel(nick, channel, {"parts": 1, "last_seen": now})

    async def on_QUIT(self, event: dict) -> None:
        nick = event.get("nick", "")
        await self._upsert_nick(nick, {"quits": 1, "last_seen": int(time.time())})

    async def on_NICK(self, event: dict) -> None:
        old_nick = event.get("old_nick", "") or event.get("nick", "")
        await self._upsert_nick(old_nick, {"nick_changes": 1, "last_seen": int(time.time())})

    async def on_KICK(self, event: dict) -> None:
        actor  = event.get("nick", "")
        channel = event.get("channel", "")
        victim  = event.get("target", "") or event.get("kicked", "")
        await self._record_action(
            actor=actor, channel=channel, victim=victim,
            global_delta={"kicks_given": 1},
            chan_delta={"kicks_given": 1},
        )

    async def on_BAN(self, event: dict) -> None:
        """Fired by core on MODE +b."""
        actor   = event.get("nick", "")
        channel = event.get("channel", "")
        mask    = event.get("mask", "") or event.get("target", "")
        await self._record_action(
            actor=actor, channel=channel, victim=mask,
            global_delta={"bans_given": 1},
            chan_delta={"bans_given": 1},
        )

    async def on_UNBAN(self, event: dict) -> None:
        """Fired by core on MODE -b."""
        actor   = event.get("nick", "")
        channel = event.get("channel", "")
        mask    = event.get("mask", "") or event.get("target", "")
        await self._record_action(
            actor=actor, channel=channel, victim=mask,
            global_delta={"unbans_given": 1},
            chan_delta={"unbans_given": 1},
        )

    async def on_OP(self, event: dict) -> None:
        actor   = event.get("nick", "")
        channel = event.get("channel", "")
        victim  = event.get("target", "")
        await self._record_action(
            actor=actor, channel=channel, victim=victim,
            global_delta={"ops_given": 1},
            chan_delta={"ops_given": 1},
        )

    async def on_DEOP(self, event: dict) -> None:
        actor   = event.get("nick", "")
        channel = event.get("channel", "")
        victim  = event.get("target", "")
        await self._record_action(
            actor=actor, channel=channel, victim=victim,
            global_delta={"deops_given": 1},
            chan_delta={"deops_given": 1},
        )

    async def on_HALFOP(self, event: dict) -> None:
        actor   = event.get("nick", "")
        channel = event.get("channel", "")
        victim  = event.get("target", "")
        await self._record_action(
            actor=actor, channel=channel, victim=victim,
            global_delta={"halfops_given": 1},
            chan_delta={"halfops_given": 1},
        )

    async def on_DEHALFOP(self, event: dict) -> None:
        actor   = event.get("nick", "")
        channel = event.get("channel", "")
        victim  = event.get("target", "")
        await self._record_action(
            actor=actor, channel=channel, victim=victim,
            global_delta={"dehalfops_given": 1},
            chan_delta={"dehalfops_given": 1},
        )

    async def on_VOICE(self, event: dict) -> None:
        actor   = event.get("nick", "")
        channel = event.get("channel", "")
        victim  = event.get("target", "")
        await self._record_action(
            actor=actor, channel=channel, victim=victim,
            global_delta={"voices_given": 1},
            chan_delta={"voices_given": 1},
        )

    async def on_DEVOICE(self, event: dict) -> None:
        actor   = event.get("nick", "")
        channel = event.get("channel", "")
        victim  = event.get("target", "")
        await self._record_action(
            actor=actor, channel=channel, victim=victim,
            global_delta={"devoices_given": 1},
            chan_delta={"devoices_given": 1},
        )

    async def on_TOPIC(self, event: dict) -> None:
        nick    = event.get("nick", "")
        channel = event.get("channel", "")
        now     = int(time.time())
        await self._upsert_nick(nick, {"topics_set": 1, "last_seen": now})
        if channel:
            await self._upsert_nick_channel(nick, channel, {"topics_set": 1, "last_seen": now})

    async def on_MODE(self, event: dict) -> None:
        """
        Generic mode change handler.
        Only increments mode_changes for mode chars NOT already handled
        by dedicated on_OP / on_BAN / on_VOICE / etc. handlers.
        """
        nick    = event.get("nick", "")
        channel = event.get("channel", "")
        modes   = event.get("modes", "") or event.get("mode", "")
        unhandled = _HANDLED_MODE_CHARS.sub("", modes)
        if not unhandled.strip():
            return
        now = int(time.time())
        await self._upsert_nick(nick, {"mode_changes": 1, "last_seen": now})
        if channel:
            await self._upsert_nick_channel(nick, channel, {"mode_changes": 1, "last_seen": now})

    async def get_nick_stats(
        self, nick: str, channel: Optional[str] = None
    ) -> Optional[dict]:
        """
        Return full stats dict for *nick*, scoped to *channel* if provided.
        Returns None if no stats recorded yet.
        """
        async with get_db(self.core.db_path) as db:
            if channel:
                async with db.execute(
                    "SELECT * FROM stats_nick_channel WHERE nick=? AND channel=?",
                    (nick, channel),
                ) as cur:
                    row = await cur.fetchone()
            else:
                async with db.execute(
                    "SELECT * FROM stats_nick WHERE nick=?", (nick,)
                ) as cur:
                    row = await cur.fetchone()
        return dict(row) if row else None

    async def get_top_nicks(
        self,
        channel: Optional[str] = None,
        limit: int = 5,
        order_by: str = "messages",
    ) -> list[dict]:
        """
        Return top *limit* nicks ordered by *order_by* column.
        Scoped to *channel* if provided, global otherwise.
        *order_by* is validated against a whitelist.
        """
        if order_by not in _SAFE_ORDER_COLS:
            order_by = "messages"

        async with get_db(self.core.db_path) as db:
            if channel:
                async with db.execute(
                    f"SELECT * FROM stats_nick_channel WHERE channel=? "
                    f"ORDER BY {order_by} DESC LIMIT ?",
                    (channel, limit),
                ) as cur:
                    rows = await cur.fetchall()
            else:
                async with db.execute(
                    f"SELECT * FROM stats_nick ORDER BY {order_by} DESC LIMIT ?",
                    (limit,),
                ) as cur:
                    rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def _upsert_nick(self, nick: str, delta: dict) -> None:
        """
        Insert or increment per-nick global stats.
        *delta* maps column_name → int (counter increment) or str/int
        for literal columns (last_seen, last_message).
        """
        if not nick:
            return

        counters = {k: v for k, v in delta.items() if k not in _LITERAL_COLS and isinstance(v, int)}
        literals = {k: v for k, v in delta.items() if k in _LITERAL_COLS}
        if not counters and not literals:
            return

        cols         = list(counters) + list(literals)
        values       = list(counters.values()) + list(literals.values())
        placeholders = ", ".join(["?"] * len(values))
        col_names    = ", ".join(cols)

        update_parts = (
            [f"{c} = {c} + excluded.{c}" for c in counters] +
            [f"{c} = excluded.{c}" for c in literals]
        )

        sql = (
            f"INSERT INTO stats_nick (nick, {col_names}) VALUES (?, {placeholders}) "
            f"ON CONFLICT(nick) DO UPDATE SET {', '.join(update_parts)}"
        )

        async with get_db(self.core.db_path) as db:
            await db.execute(sql, [nick] + values)
            await db.commit()

    async def _upsert_nick_channel(self, nick: str, channel: str, delta: dict) -> None:
        """Insert or increment per-nick per-channel stats."""
        if not nick or not channel:
            return

        counters = {k: v for k, v in delta.items() if k not in _LITERAL_COLS and isinstance(v, int)}
        literals = {k: v for k, v in delta.items() if k in _LITERAL_COLS}
        if not counters and not literals:
            return

        cols         = list(counters) + list(literals)
        values       = list(counters.values()) + list(literals.values())
        placeholders = ", ".join(["?"] * (len(values) + 2))  # +2 for nick, channel
        col_names    = "nick, channel, " + ", ".join(cols)

        update_parts = (
            [f"{c} = {c} + excluded.{c}" for c in counters] +
            [f"{c} = excluded.{c}" for c in literals]
        )

        sql = (
            f"INSERT INTO stats_nick_channel ({col_names}) VALUES ({placeholders}) "
            f"ON CONFLICT(nick, channel) DO UPDATE SET {', '.join(update_parts)}"
        )

        async with get_db(self.core.db_path) as db:
            await db.execute(sql, [nick, channel] + values)
            await db.commit()

    async def _record_action(
        self,
        actor: str,
        channel: str,
        victim: str,
        global_delta: dict,
        chan_delta: dict,
    ) -> None:
        """
        Record a mode/kick/ban/op action and track victim uniqueness.
        The 'victims' counter increments only once per distinct target
        per scope (dedup via stats_victims table).
        """
        now = int(time.time())
        global_delta["last_seen"] = now
        chan_delta["last_seen"]   = now

        if await self._register_victim(actor, victim, "global"):
            global_delta["victims"] = global_delta.get("victims", 0) + 1

        await self._upsert_nick(actor, global_delta)

        if channel:
            if await self._register_victim(actor, victim, channel):
                chan_delta["victims"] = chan_delta.get("victims", 0) + 1
            await self._upsert_nick_channel(actor, channel, chan_delta)

    async def _register_victim(self, actor: str, victim: str, scope: str) -> bool:
        """
        Insert (actor, victim, scope) into stats_victims.
        Returns True if new (victim not seen before for this actor+scope).
        Returns False if already recorded — prevents double-counting.
        """
        if not actor or not victim:
            return False
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT 1 FROM stats_victims WHERE actor=? AND victim=? AND scope=?",
                (actor, victim, scope),
            ) as cur:
                exists = await cur.fetchone()
            if not exists:
                await db.execute(
                    "INSERT OR IGNORE INTO stats_victims (actor, victim, scope) VALUES (?, ?, ?)",
                    (actor, victim, scope),
                )
                await db.commit()
                return True
        return False