# src/plugins/seen.py
"""
WBS Plugin: seen.py
version: 0.3.0
by: cyco

Description:
    Tracks all users in watched channels regardless of whether they are
    in the bot's userfile.

    Public / MSG commands
    ---------------------
    !seen <nick>            Last-seen lookup (channel or /msg)

    !seenstats              Database entry count

    Passive tracking
    ----------------
    PUBMSG  PRIVMSG  JOIN  PART  QUIT  NICK  KICK  MODE  TOPIC  ACTION

    Seen-notification (tell-seens)
    --------------------------------
    If user A asks "!seen B" and B is not found, notify B the next time
    B speaks or joins: "A was looking for you <ago>."

    Partyline commands
    ------------------
    .seen <nick>                — same as public !seen
    .seenstats                  — database entry count
    .purgeseens <YYYY-MM-DD>    — delete all records with last_seen strictly
                                  before that date (keep on/after).
                                  Also purges seen_notify entries > 7 days.
                                  Requires +m flag.

    Botnet forwarding
    -----------------
    If a local query returns nothing and botnet is enabled, the query is
    broadcast; the freshest reply wins.

    Rate limiting
    -------------
    MAX_SEENS_COUNT requests per MAX_SEENS_SECS seconds per nick.
    Excess requests are silently dropped.

    Schema migration
    ----------------
    Detects and upgrades the 0.2.x TEXT PRIMARY KEY schema on first load.

    TODO
    ----
    - max_seens constants are suitable for IRC scale; expose via DB
      plugin_settings post-MVP if operator tuning is needed.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from . import Plugin
from ..db import get_db

MAX_SEENS_COUNT: int = 5    # max !seen requests
MAX_SEENS_SECS:  int = 60   # per this many seconds
_SCHEMA = """
CREATE TABLE IF NOT EXISTS seen (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    nick       TEXT    NOT NULL COLLATE NOCASE,
    hostmask   TEXT    NOT NULL DEFAULT '',
    channel    TEXT    NOT NULL DEFAULT '',
    action     TEXT    NOT NULL DEFAULT 'was seen',
    last_seen  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    UNIQUE(nick)
);

CREATE INDEX IF NOT EXISTS idx_seen_nick       ON seen(nick COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_seen_last_seen  ON seen(last_seen);

CREATE TABLE IF NOT EXISTS seen_notify (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asker      TEXT    NOT NULL,
    target     TEXT    NOT NULL COLLATE NOCASE,
    channel    TEXT    NOT NULL DEFAULT '',
    asked_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_seen_notify_target ON seen_notify(target COLLATE NOCASE);
"""

class seenPlugin(Plugin):
    name    = "seen"
    version = "0.3.0"

    tell_seens:       bool  = True
    fuzzy_search:     bool  = True
    botnet_seens:     bool  = True
    BOTNET_TIMEOUT:   float = 3.0

    def __init__(self, core):
        super().__init__(core)
        # rate buckets keyed by requesting nick
        self._rate_buckets: Dict[str, List[float]] = defaultdict(list)
        self._botnet_pending: Dict[str, asyncio.Future] = {}

    async def load(self) -> None:
        await super().load()
        async with get_db(self.core.db_path) as db:
            await self._migrate(db)
            for stmt in _SCHEMA.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    await db.execute(stmt)
            await db.commit()
        self.log.info(f"Plugin {self.name} {self.version} loaded")

    async def unload(self) -> None:
        for fut in self._botnet_pending.values():
            fut.cancel()
        await super().unload()
        self.log.info(f"Plugin {self.name} unloaded")

    async def _migrate(self, db) -> None:
        """Upgrade 0.2.x TEXT PRIMARY KEY schema to 0.3.0."""
        try:
            async with db.execute("PRAGMA table_info(seen)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if cols and "id" not in cols:
                self.log.info("seen: migrating schema 0.2.x → 0.3.0")
                await db.execute("ALTER TABLE seen RENAME TO seen_old")
                await db.execute("""
                    CREATE TABLE seen (
                        id        INTEGER PRIMARY KEY AUTOINCREMENT,
                        nick      TEXT    NOT NULL COLLATE NOCASE,
                        hostmask  TEXT    NOT NULL DEFAULT '',
                        channel   TEXT    NOT NULL DEFAULT '',
                        action    TEXT    NOT NULL DEFAULT 'was seen',
                        last_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                        UNIQUE(nick)
                    )
                """)
                await db.execute("""
                    INSERT OR IGNORE INTO seen (nick, hostmask, channel, action, last_seen)
                    SELECT nick, hostmask, channel, action, last_seen FROM seen_old
                """)
                await db.execute("DROP TABLE seen_old")
                await db.commit()
                self.log.info("seen: migration complete")
        except Exception as exc:
            self.log.debug(f"seen: _migrate no-op ({exc})")

    async def on_PUBMSG(self, event: dict) -> None:
        nick    = event["nick"]
        uhost   = event.get("uhost", "")
        channel = event["channel"]
        text    = event["text"].strip()
        lower   = text.lower()

        if lower.startswith("!seen ") or lower == "!seen":
            if self._rate_ok(nick):
                arg = text[6:].strip()
                await self._cmd_seen(nick, channel, arg)
            return

        if lower.strip() == "!seenstats":
            if self._rate_ok(nick):
                await self._cmd_seenstats(nick, channel)
            return

        await self._update(nick, uhost, channel, "said something")

        if self.tell_seens:
            await self._deliver_notifications(nick, channel)

    async def on_PRIVMSG(self, event: dict) -> None:
        nick  = event["nick"]
        uhost = event.get("uhost", "")
        text  = event["text"].strip()
        lower = text.lower()

        if lower.startswith("seen "):
            reply = await self._query_seen(text[5:].strip())
            await self.send_notice(nick, reply)
            return

        if lower.strip() == "seenstats":
            await self.send_notice(nick, await self._stats_text())
            return

        await self._update(nick, uhost, "", "sent a private message")

    async def on_JOIN(self, event: dict) -> None:
        if event["nick"] == getattr(self.core, "botnick", ""):
            return
        channel = event["channel"]
        await self._update(
            event["nick"], event.get("uhost", ""),
            channel, f"joined {channel}"
        )
        if self.tell_seens:
            await self._deliver_notifications(event["nick"], channel)

    async def on_PART(self, event: dict) -> None:
        channel = event["channel"]
        msg     = event.get("message", "").strip()
        action  = f"parted {channel} ({msg})" if msg else f"parted {channel}"
        await self._update(event["nick"], event.get("uhost", ""), channel, action)

    async def on_QUIT(self, event: dict) -> None:
        """
        On QUIT we resolve which channels the nick was in using the live
        channel state held by core.  One _update call per channel so the
        record carries a real channel name.  If core exposes no channel
        map we fall back to a single record with channel=''.
        """
        nick    = event["nick"]
        uhost   = event.get("uhost", "")
        msg     = event.get("message", "").strip()
        action  = f"quit ({msg})" if msg else "quit"

        channels = self._channels_for_nick(nick)
        if channels:
            for chan in channels:
                await self._update(nick, uhost, chan, action)
        else:
            await self._update(nick, uhost, "", action)

    async def on_NICK(self, event: dict) -> None:
        new_nick = event["new_nick"]
        channel  = event.get("channel", "")
        await self._update(
            event["old_nick"], event.get("uhost", ""),
            channel, f"changed nick to {new_nick}"
        )
        await self._update(
            new_nick, event.get("uhost", ""),
            channel, f"is formerly known as {event['old_nick']}"
        )

    async def on_KICK(self, event: dict) -> None:
        channel = event["channel"]
        reason  = event.get("reason", "").strip()
        kicked  = event.get("kicked", event.get("target", ""))
        action  = (
            f"was kicked from {channel} by {event['nick']} ({reason})"
            if reason else
            f"was kicked from {channel} by {event['nick']}"
        )
        await self._update(kicked, event.get("kicked_uhost", ""), channel, action)

    async def on_MODE(self, event: dict) -> None:
        channel = event.get("channel", "")
        if not channel:
            return
        await self._update(
            event["nick"], event.get("uhost", ""),
            channel, f"set mode {event.get('modes', '')} on {channel}"
        )

    async def on_TOPIC(self, event: dict) -> None:
        channel = event["channel"]
        topic   = event.get("topic", "")[:80]
        await self._update(
            event["nick"], event.get("uhost", ""),
            channel, f"changed topic of {channel} to: {topic}"
        )

    async def on_ACTION(self, event: dict) -> None:
        channel = event.get("channel", "")
        await self._update(
            event["nick"], event.get("uhost", ""),
            channel, f"did an action: {event.get('text', '').strip()[:80]}"
        )

    async def on_BOTNET_SEEN_QUERY(self, event: dict) -> None:
        record = await self._get_exact(event.get("nick", ""))
        if record is None:
            return
        self.core.botnet_q.put_nowait({
            "cmd":      "SEEN_REPLY",
            "to_bot":   event["from_bot"],
            "query_id": event["query_id"],
            "record":   record,
            "bot":      getattr(self.core, "botnick", "wbs"),
        })

    async def on_BOTNET_SEEN_REPLY(self, event: dict) -> None:
        fut = self._botnet_pending.get(event.get("query_id", ""))
        if fut and not fut.done():
            fut.set_result({
                "last_seen": event["record"]["last_seen"],
                "record":    event["record"],
                "bot":       event.get("bot", "?"),
            })

    async def cmd_seen(self, caller: str, args: str) -> str:
        if not args.strip():
            return "Usage: .seen <nick>"
        return await self._query_seen(args.strip())

    async def cmd_seenstats(self, caller: str, args: str) -> str:
        return await self._stats_text()

    async def cmd_purgeseens(self, caller: str, args: str, flags: str = "") -> str:
        """
        .purgeseens <YYYY-MM-DD>
        Deletes seen records with last_seen strictly before midnight UTC on
        that date.  Records on or after the date are kept.
        Also purges seen_notify entries older than 7 days.
        Requires +m flag.
        """
        if "m" not in flags:
            return "Access denied. Requires +m flag."

        date_str = args.strip()
        if not date_str:
            return "Usage: .purgeseens <YYYY-MM-DD>"

        try:
            import datetime
            cutoff_dt = datetime.datetime.strptime(date_str, "%Y-%m-%d").replace(
                tzinfo=datetime.timezone.utc
            )
            cutoff_ts = int(cutoff_dt.timestamp())
        except ValueError:
            return f"Invalid date '{date_str}'. Use YYYY-MM-DD format."

        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "DELETE FROM seen WHERE last_seen < ?", (cutoff_ts,)
            ) as cur:
                seen_count = cur.rowcount
            notify_cutoff = int(time.time()) - (86400 * 7)
            async with db.execute(
                "DELETE FROM seen_notify WHERE asked_at < ?", (notify_cutoff,)
            ) as cur:
                notify_count = cur.rowcount
            await db.commit()

        return (
            f"Purged {seen_count} seen record(s) before {date_str} UTC"
            f" and {notify_count} stale notification(s)."
        )

    async def query(self, nick: str) -> str:
        """Query seen from another plugin."""
        return await self._query_seen(nick)
    
    async def _cmd_seen(self, asker: str, channel: str, target: str) -> None:
        if not target:
            await self.send_privmsg(channel, f"{asker}: Usage: !seen <nick>")
            return
        reply = await self._query_seen(target)
        if self.tell_seens and "haven't seen" in reply:
            await self._queue_notification(asker, target, channel)
        await self.send_privmsg(channel, f"{asker}: {reply}")

    async def _cmd_seenstats(self, asker: str, channel: str) -> None:
        await self.send_privmsg(channel, f"{asker}: {await self._stats_text()}")

    async def _query_seen(self, target: str) -> str:
        record = await self._get_exact(target)
        if record:
            return self._format(target, record)

        if self.fuzzy_search:
            chain = await self._follow_nick_chain(target)
            if chain:
                old_nick, old_record = chain
                return self._format(old_nick, old_record, via_nick=target)

        if self.botnet_seens and self._botnet_enabled():
            remote = await self._ask_botnet(target)
            if remote:
                return self._format(target, remote["record"], via_bot=remote["bot"])

        return f"I haven't seen {target}."

    async def _update(self, nick: str, hostmask: str, channel: str, action: str) -> None:
        if not nick:
            return
        async with get_db(self.core.db_path) as db:
            await db.execute(
                """
                INSERT INTO seen (nick, hostmask, channel, action, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(nick) DO UPDATE SET
                    hostmask  = excluded.hostmask,
                    channel   = excluded.channel,
                    action    = excluded.action,
                    last_seen = excluded.last_seen
                """,
                (nick, hostmask, channel, action, int(time.time())),
            )
            await db.commit()

    async def _get_exact(self, nick: str) -> Optional[dict]:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM seen WHERE nick = ? COLLATE NOCASE", (nick,)
            ) as cur:
                row = await cur.fetchone()
        return dict(row) if row else None

    async def _follow_nick_chain(self, nick: str) -> Optional[Tuple[str, dict]]:
        """Find a record that changed its nick to the searched nick."""
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM seen WHERE action LIKE ? COLLATE NOCASE LIMIT 1",
                (f"changed nick to {nick}",),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        record = dict(row)
        return (record["nick"], record)

    async def _stats_text(self) -> str:
        async with get_db(self.core.db_path) as db:
            async with db.execute("""
                SELECT
                    COUNT(*),
                    COALESCE(SUM(
                        LENGTH(nick) +
                        LENGTH(hostmask) +
                        LENGTH(channel) +
                        LENGTH(action)
                    ), 0)
                FROM seen
            """) as cur:
                row = await cur.fetchone()
        count = row[0] if row else 0
        size  = row[1] if row else 0
        return f"I'm currently tracking {count} nick(s) using {size} bytes."

    async def _queue_notification(self, asker: str, target: str, channel: str) -> None:
        async with get_db(self.core.db_path) as db:
            await db.execute(
                """
                INSERT INTO seen_notify (asker, target, channel, asked_at)
                VALUES (?, ?, ?, ?)
                """,
                (asker, target.lower(), channel, int(time.time())),
            )
            await db.commit()

    async def _deliver_notifications(self, nick: str, channel: str) -> None:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM seen_notify WHERE target = ? COLLATE NOCASE",
                (nick.lower(),),
            ) as cur:
                rows = await cur.fetchall()
            if not rows:
                return
            await db.execute(
                "DELETE FROM seen_notify WHERE target = ? COLLATE NOCASE",
                (nick.lower(),),
            )
            await db.commit()
        for row in rows:
            r   = dict(row)
            ago = self._ago(r["asked_at"])
            dest = channel or r["channel"]
            if dest:
                await self.send_privmsg(
                    dest, f"{nick}: {r['asker']} was looking for you {ago} ago."
                )

    def _botnet_enabled(self) -> bool:
        return (
            hasattr(self.core, "botnet")
            and self.core.botnet is not None
            and self.core.config.get("botnet", {}).get("enabled", False)
        )

    async def _ask_botnet(self, nick: str) -> Optional[dict]:
        query_id = str(uuid.uuid4())
        fut      = asyncio.get_event_loop().create_future()
        self._botnet_pending[query_id] = fut
        self.core.botnet_q.put_nowait({
            "cmd":      "BROADCAST",
            "type":     "SEEN_QUERY",
            "nick":     nick,
            "from_bot": getattr(self.core, "botnick", "wbs"),
            "query_id": query_id,
        })
        try:
            return await asyncio.wait_for(fut, timeout=self.BOTNET_TIMEOUT)
        except asyncio.TimeoutError:
            return None
        finally:
            self._botnet_pending.pop(query_id, None)

    def _rate_ok(self, nick: str) -> bool:
        now       = time.time()
        bucket    = self._rate_buckets[nick]
        bucket[:] = [t for t in bucket if now - t < MAX_SEENS_SECS]
        if len(bucket) >= MAX_SEENS_COUNT:
            return False
        bucket.append(now)
        return True

    def _channels_for_nick(self, nick: str) -> List[str]:
        """
        Return every channel the nick is currently in, using the live
        channel state map from core.  Returns an empty list if core does
        not expose it (graceful fallback).
        """
        try:
            chan_map = self.core.channel_manager.channels  # dict[str, Channel]
            nick_l   = nick.lower()
            return [
                name for name, obj in chan_map.items()
                if nick_l in obj.users
            ]
        except Exception:
            return []

    def _format(self, nick: str, record: dict,
                via_nick: str = "", via_bot: str = "") -> str:
        ts        = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(record["last_seen"]))
        ago       = self._ago(record["last_seen"])
        chan      = record.get("channel") or "unknown"
        act       = record.get("action", "was seen")
        host      = record.get("hostmask", "")
        host_part  = f" ({host})" if host else ""
        bot_part   = f" [via {via_bot}]" if via_bot else ""
        chain_part = f" [was looking for {via_nick}]" if via_nick else ""
        return (
            f"{nick}{host_part} was last seen on {chan} "
            f"{ago} ago ({ts}): {act}.{bot_part}{chain_part}"
        )

    @staticmethod
    def _ago(ts: int) -> str:
        delta = max(0, int(time.time()) - ts)
        parts = []
        for unit, label in (
            (604800, "week"),
            (86400,  "day"),
            (3600,   "hour"),
            (60,     "minute"),
            (1,      "second"),
        ):
            val = delta // unit
            if val:
                parts.append(f"{val} {label}{'s' if val != 1 else ''}")
                delta -= val * unit
        return " ".join(parts[:3]) if parts else "0 seconds"