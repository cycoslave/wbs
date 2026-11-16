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
from ..helper import _valid_channel
from ..subnet import local_subnet_id

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
        self.register_command(      # PLG-6
            "topiclock", self._pl_topiclock, "A",
            "topiclock <#chan> [topic] - toggle the topic lock, or lock the channel to <topic>")
        self.log.info("Plugin %s %s loaded", self.name, self.version)

    async def unload(self) -> None:
        """Locked topics (topiclock table) persist across unload/load; only
        `.plugin purge topiclock` drops them."""
        await super().unload()
        self.log.info("Plugin %s unloaded", self.name)

    async def on_CHANNEL_TOPIC(self, event: dict) -> None:
        """332/331 on the bot's own join (PLG-8b): the server's current
        topic.  A different topic on a locked channel is replaced by the
        locked one."""
        chan  = event.get("channel", "")
        topic = event.get("topic", "")
        if not chan:
            return
        cfg = await self._load_settings(chan)
        if not cfg["enabled"] or not cfg["topic"] or topic == cfg["topic"]:
            return
        self.log.info("topiclock: %s has a different topic on join - applying the lock.", chan)
        self._set_topic(chan, cfg["topic"])

    async def on_TOPIC(self, event: dict) -> None:
        """A live topic change (PLG-8b).  On a locked channel a change by
        anyone but the bot itself or an owner/admin is reverted once and the
        setter gets a NOTICE.  The bot's own restore comes back as a TOPIC
        from the bot and is ignored, so there is no loop."""
        chan  = event.get("channel", "")
        nick  = event.get("nick", "")
        topic = event.get("topic", "")
        if not chan or not nick:
            return
        cfg = await self._load_settings(chan)
        if not cfg["enabled"] or not cfg["topic"] or topic == cfg["topic"]:
            return
        if self._is_bot(nick):
            return
        if await self._is_owner_or_admin(nick, event.get("host", "")):
            self.log.info("topiclock: %s (owner/admin) changed the locked topic of %s - kept.",
                          nick, chan)
            return
        self.log.info("topiclock: %s changed topic in %s - restoring.", nick, chan)
        await self.send_notice(
            nick,
            f"[topiclock] The topic in {chan} is locked. "
            f"Your change has been reverted. "
            f"Contact a channel operator to change it."
        )
        self._set_topic(chan, cfg["topic"])

    def _set_topic(self, chan: str, topic: str) -> None:
        self.core.send_irc({"cmd": "topic", "channel": chan, "topic": topic})

    def _is_bot(self, nick: str) -> bool:
        bot = getattr(self.core, "botname", "") or ""
        return bool(bot) and nick.lower() == bot.lower()

    async def _is_owner_or_admin(self, nick: str, host: str) -> bool:
        """The setter's hostmask belongs to a user with +n or +A (this bot's
        subnet scope)."""
        if "!" not in host:
            return False
        user = getattr(self.core, "user", None)
        if user is None:
            return False
        handle = await user.match_user(host)
        if not handle:
            return False
        sid = local_subnet_id(getattr(self.core, "config", None))
        return (await user.matchattr(handle, "n", subnet_id=sid)
                or await user.matchattr(handle, "A", subnet_id=sid))

    async def _pl_topiclock(self, handle: str, arg: str) -> str:
        """Partyline `.topiclock <#chan> [topic]` (gate: +A)."""
        parts = arg.split(maxsplit=1)
        if not parts:
            return "Usage: .topiclock <#chan> [topic]"
        chan = parts[0]
        if not _valid_channel(chan):
            return f"Invalid channel: {chan}"
        return await self.cmd_topiclock(chan, handle, parts[1].strip() if len(parts) > 1 else "")

    async def on_PUBMSG(self, event: dict) -> None:
        """Public `!topiclock [topic]`: channel operators only.

        Identity and the op check are pubcom's (identify session bound to the
        caller's hostmask; global +o/+A/+n or channel +o).  Without the pubcom
        plugin loaded nobody can be authenticated, so the command is ignored.
        """
        text = (event.get("text") or "").strip()
        head, _, rest = text.partition(" ")
        if head.lower() != "!topiclock":
            return
        chan, nick = event.get("channel", ""), event.get("nick", "")
        if not _valid_channel(chan) or not nick:
            return
        pubcom = self.core.plugin.plugins.get("pubcom")
        if pubcom is None:
            return
        if not await pubcom.is_pubcom_enabled(chan):
            return
        handle = await pubcom.verify_session(nick, event.get("host") or "",
                                             event.get("account"))
        if handle is None:
            await self.send_notice(nick, "You must identify first")
            return
        if not await pubcom.authorize(handle, "chanop", chan):
            await self.send_notice(nick, "Access denied for !topiclock.")
            return
        reply = await self.cmd_topiclock(chan, nick, rest.strip())
        await self.send_privmsg(chan, reply)

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
            self._set_topic(chan, new_topic)
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
            self._set_topic(chan, cfg["topic"])

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
        # Insert the supplied columns too: on a new channel the INSERT succeeds
        # and ON CONFLICT never runs, so values must not live only in UPDATE.
        col_names = "".join(f", {k}" for k in kwargs)
        placeholders = "".join(", ?" for _ in kwargs)
        cols = ", ".join(f"{k}=excluded.{k}" for k in kwargs)
        async with get_db(self.core.db_path) as db:
            await db.execute(
                f"INSERT INTO topiclock(channel{col_names}) "
                f"VALUES(?{placeholders}) "
                f"ON CONFLICT(channel) DO UPDATE SET {cols}",
                (channel, *kwargs.values()),
            )
            await db.commit()