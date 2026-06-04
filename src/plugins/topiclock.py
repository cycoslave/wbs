# src/plugins/topiclock.py
"""
WBS Plugin: topiclock.py
version: 1.0.0
by: cyco
Description: Lock a channel's topic. Any user who changes the topic
             receives a NOTICE and the locked topic is immediately restored.
"""
import aiosqlite
import time

from . import Plugin
from ..db import get_db

class topicPlugin(Plugin):
    name    = "topiclock"
    version = "1.0.0"

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS topiclock (
            channel   TEXT    PRIMARY KEY,
            enabled   BOOLEAN NOT NULL DEFAULT 0,
            topic     TEXT    NOT NULL DEFAULT '',
            locked_by TEXT    NOT NULL DEFAULT '',
            locked_at INTEGER NOT NULL DEFAULT 0
        )
        """
    ]

    async def load(self) -> None:
        await super().load()
        async with get_db(self.core.db_path) as db:
            await db.execute(self.TABLE_SQL[0])
            await db.commit()
        self.log.info("Plugin %s %s loaded", self.name, self.version)

    async def unload(self) -> None:
        await super().unload()
        self.log.info("Plugin %s unloaded", self.name)

    async def on_CHANNEL_TOPIC(self, event: dict) -> None:
        """
        Fires on RPL_332 — both server-sent (on join) and user-changed.
        nick is populated only when a user changed the topic (not server).
        """
        chan  = event.get("channel", "")
        nick  = event.get("nick", "")
        topic = event.get("topic", "")

        if not chan:
            return

        cfg = await self._load_settings(chan)
        if not cfg["enabled"] or not cfg["topic"]:
            return

        # Nothing to do if topic already matches
        if topic == cfg["topic"]:
            return

        bot_nick = getattr(getattr(self.core, "irc", None), "nick", "")

        # A real user changed it — notify them
        if nick and nick != bot_nick:
            await self.send_notice(
                nick,
                f"[topiclock] The topic in {chan} is locked. "
                f"Your change has been reverted. "
                f"Contact a channel operator to change it."
            )
            self.log.info("topiclock: %s changed topic in %s — restoring.", nick, chan)

        # Restore locked topic
        self.core.send_irc({
            "cmd": "TOPIC",
            "channel": chan,
            "topic": cfg["topic"],
        })

    async def cmd_topiclock(self, chan: str, nick: str, args: str) -> str:
        """
        !topiclock           — toggle lock on/off
        !topiclock <topic>   — set and lock a new topic immediately
        Requires op flag (enforced by caller).
        """
        cfg = await self._load_settings(chan)

        if args:
            new_topic = args.strip()
            await self._save_setting(
                chan,
                enabled=1,
                topic=new_topic,
                locked_by=nick,
                locked_at=int(time.time()),
            )
            self.core.send_irc({"cmd": "TOPIC", "channel": chan, "topic": new_topic})
            return f"[topiclock] {chan} locked to: {new_topic}"

        # Toggle
        new_state = 0 if cfg["enabled"] else 1
        await self._save_setting(
            chan,
            enabled=new_state,
            locked_by=nick,
            locked_at=int(time.time()),
        )
        state_str = "enabled" if new_state else "disabled"

        # Re-enforce immediately when re-enabling
        if new_state and cfg["topic"]:
            self.core.send_irc({"cmd": "TOPIC", "channel": chan, "topic": cfg["topic"]})

        return f"[topiclock] {chan} topiclock {state_str}."

    async def _load_settings(self, chan: str) -> dict:
        defaults = {"enabled": 0, "topic": "", "locked_by": "", "locked_at": 0}
        async with get_db(self.core.db_path) as db:
            try:
                async with db.execute(
                    "SELECT * FROM topiclock WHERE channel = ?", (chan,)
                ) as cursor:
                    row = await cursor.fetchone()
                    return dict(row) if row else defaults
            except aiosqlite.OperationalError:
                self.log.warning("topiclock table missing for %s — using defaults", chan)
                return defaults

    async def _save_setting(self, channel: str, **kwargs) -> None:
        cols = ", ".join(f"{k}=?" for k in kwargs)
        async with get_db(self.core.db_path) as db:
            await db.execute(
                f"INSERT INTO topiclock(channel) VALUES(?) "
                f"ON CONFLICT(channel) DO UPDATE SET {cols}",
                (channel, *kwargs.values()),
            )
            await db.commit()