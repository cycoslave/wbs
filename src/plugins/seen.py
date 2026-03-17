"""
WBS Plugin: seen.py
version: 0.1.0
by: cyco
Description: Track when users were last seen (like gseen.mod)
             Supports partyline, channel (!seen), privmsg, and botnet queries.
"""
import asyncio
import time
from typing import Dict, List, Optional
from . import Plugin, _db


class seenPlugin(Plugin):
    name    = "seen"
    version = "0.2.0"
    EXPIRE_DAYS      = 60
    BOTNET_TIMEOUT   = 3.0   # seconds to wait for botnet replies

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS seen (
            nick       TEXT    PRIMARY KEY,
            hostmask   TEXT,
            channel    TEXT,
            action     TEXT    DEFAULT 'seen',
            last_seen  INTEGER DEFAULT (strftime('%s','now'))
        )
        """
    ]

    def __init__(self, core):
        super().__init__(core)
        self._rate_limits: Dict[str, List[float]] = {}
        # pending botnet queries: nick -> asyncio.Future
        self._botnet_pending: Dict[str, asyncio.Future] = {}

    async def load(self):
        await super().load()
        async with _db(self.core.db_path) as db:
            await db.execute(self.TABLE_SQL[0])
            await db.commit()
        self.log.info(f"Plugin {self.name} {self.version} loaded")

    async def unload(self):
        # cancel any pending botnet queries
        for fut in self._botnet_pending.values():
            fut.cancel()
        async with _db(self.core.db_path) as db:
            await db.execute("DROP TABLE IF EXISTS seen")
            await db.commit()
        await super().unload()
        self.log.info("Seen plugin unloaded")

    async def on_PUBMSG(self, event):
        text    = event["text"].strip()
        channel = event["channel"]
        nick    = event["nick"]
        uhost   = event.get("uhost", "")

        # !seen command in channel
        if text.lower().startswith("!seen "):
            target = text.split(maxsplit=1)[1].strip()
            reply  = await self._query_seen(target, ask_botnet=True)
            await self.send_privmsg(channel, reply)
            return

        # passive tracking
        await self._update(nick, uhost, channel, "said something")

    async def on_PRIVMSG(self, event):
        """Handle /msg bot seen <nick>"""
        nick  = event["nick"]
        uhost = event.get("uhost", "")
        text  = event["text"].strip()

        if text.lower().startswith("seen "):
            target = text.split(maxsplit=1)[1].strip()
            reply  = await self._query_seen(target, ask_botnet=True)
            await self.send_notice(nick, reply)
            return

        # passive tracking for private messages too
        await self._update(nick, uhost, "", "sent a private message")

    async def on_JOIN(self, event):
        if event["nick"] == self.core.botnick:
            return
        await self._update(
            event["nick"], event.get("uhost", ""),
            event["channel"], "joined"
        )

    async def on_PART(self, event):
        msg    = event.get("message", "").strip()
        action = f"parted ({msg})" if msg else "parted"
        await self._update(event["nick"], event.get("uhost", ""),
                           event["channel"], action)

    async def on_QUIT(self, event):
        msg    = event.get("message", "").strip()
        action = f"quit ({msg})" if msg else "quit"
        await self._update(event["nick"], event.get("uhost", ""),
                           event.get("channel", ""), action)

    async def on_NICK(self, event):
        await self._update(
            event["nick"], event.get("uhost", ""),
            event.get("channel", ""),
            f"changed nick to {event['new_nick']}"
        )

    async def on_BOTNET_SEEN_REPLY(self, event):
        """
        Remote bot answered. Resolve the future immediately on first reply —
        subsequent replies are dropped since the future is already done.
        event: { 'query_id': str, 'record': dict, 'bot': str }
        """
        fut = self._botnet_pending.get(event.get("query_id", ""))
        if fut and not fut.done():
            fut.set_result({
                "last_seen": event["record"]["last_seen"],
                "record":    event["record"],
                "bot":       event["bot"],
            })

    async def on_BOTNET_SEEN_QUERY(self, event):
        """Reply with the full record dict so the caller can compare timestamps."""
        record = await self._get(event["nick"])
        if record is None:
            return
        self.core.botnet_q.put_nowait({
            "cmd":      "SEEN_REPLY",
            "to_bot":   event["from_bot"],
            "query_id": event["query_id"],
            "record":   record,          # full dict, not a pre-formatted string
            "bot":      self.core.botnick,
        })

    async def seen(self, nick: str) -> str:
        """Partyline: .seen <nick>"""
        return await self._query_seen(nick, ask_botnet=True)

    async def _query_seen(self, nick: str, ask_botnet: bool = False) -> str:
        local = await self._get(nick)

        if ask_botnet and self._botnet_enabled():
            remote = await self._ask_botnet(nick)
            if remote:
                # if we have local data, only use remote if it's more recent
                if local is None or remote["last_seen"] > local["last_seen"]:
                    return self._format_record(nick, remote["record"])

        if local:
            return self._format_record(nick, local)

        return f"[seen] I haven't seen {nick}."

    def _botnet_enabled(self) -> bool:
        return (
            hasattr(self.core, "botnet")
            and self.core.botnet is not None
            and self.core.config.get("botnet", {}).get("enabled", False)
        )

    async def _ask_botnet(self, nick: str) -> Optional[dict]:
        """
        Returns { 'last_seen': int, 'record': dict, 'bot': str } from
        the first bot that replies, or None on timeout.
        """
        import uuid
        query_id = str(uuid.uuid4())
        loop     = asyncio.get_event_loop()
        fut      = loop.create_future()
        self._botnet_pending[query_id] = fut

        self.core.botnet_q.put_nowait({
            "cmd":      "BROADCAST",
            "type":     "SEEN_QUERY",
            "nick":     nick,
            "from_bot": self.core.botnick,
            "query_id": query_id,
        })

        try:
            return await asyncio.wait_for(fut, timeout=self.BOTNET_TIMEOUT)
        except asyncio.TimeoutError:
            return None
        finally:
            self._botnet_pending.pop(query_id, None)

    def _check_rate_limit(self, nick: str, max_per_min: int = 7) -> bool:
        now        = time.time()
        timestamps = [t for t in self._rate_limits.get(nick, []) if now - t < 60]
        if len(timestamps) >= max_per_min:
            return False
        timestamps.append(now)
        self._rate_limits[nick] = timestamps
        return True

    async def _update(self, nick: str, hostmask: str, channel: str, action: str):
        if not self._check_rate_limit(nick):
            return
        now = int(time.time())
        async with _db(self.core.db_path) as db:
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
                (nick, hostmask, channel, action, now),
            )
            await db.commit()

    async def _get(self, nick: str) -> Optional[dict]:
        async with _db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM seen WHERE nick = ?", (nick,)
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        record = dict(row)
        # 0 = never expire
        if self.EXPIRE_DAYS > 0:
            expire_ts = int(time.time()) - (86400 * self.EXPIRE_DAYS)
            if record["last_seen"] < expire_ts:
                await self._delete(nick)
                return None
        return record

    async def _delete(self, nick: str):
        async with _db(self.core.db_path) as db:
            await db.execute("DELETE FROM seen WHERE nick = ?", (nick,))
            await db.commit()

    @staticmethod
    def _format_record(nick: str, record: dict) -> str:
        ts   = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(record["last_seen"]))
        ago  = seenPlugin._ago(record["last_seen"])
        chan = record["channel"] or "unknown"
        act  = record["action"]
        return f"[seen] {nick} was last seen on {chan} {ago} ago ({ts}): {act}."

    @staticmethod
    def _ago(ts: int) -> str:
        delta = int(time.time()) - ts
        if delta < 60:    return f"{delta}s"
        if delta < 3600:  return f"{delta // 60}m {delta % 60}s"
        if delta < 86400:
            h = delta // 3600
            return f"{h}h {(delta % 3600) // 60}m"
        d = delta // 86400
        return f"{d}d {(delta % 86400) // 3600}h"
