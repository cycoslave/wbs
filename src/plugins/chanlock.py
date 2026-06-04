# src/plugins/chanlock.py
"""
WBS Plugin: chanlock.py
version: 0.1.0
by: cyco
Description: Channel lock enforcement — sets and holds +i on a channel.
             Optional +m (moderated) and +k (key) for hardened lockdown.
             Re-applies modes if stripped while lock is active.
"""

import time
import aiosqlite
from typing import Dict, Optional

from . import Plugin
from ..db import get_db

ALLOWED_SETTING_COLS = frozenset({"locked", "use_m", "key", "auto_unlock_secs", "locked_by", "locked_at"})

class chanlockPlugin(Plugin):
    name    = "chanlock"
    version = "0.1.0"

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS chanlock_settings (
            channel         TEXT    PRIMARY KEY,
            locked          BOOLEAN DEFAULT 0,
            use_m           BOOLEAN DEFAULT 0,
            key             TEXT    DEFAULT NULL,
            auto_unlock_secs INTEGER DEFAULT 0,
            locked_by       TEXT    DEFAULT NULL,
            locked_at       INTEGER DEFAULT NULL,
            updated_at      INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS chanlock_audit (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            channel   TEXT    NOT NULL,
            action    TEXT    NOT NULL,
            by_nick   TEXT,
            at_ts     INTEGER DEFAULT (strftime('%s','now'))
        )
        """
    ]

    def __init__(self, core):
        super().__init__(core)
        # In-memory state for channels we're actively watching
        self._locked_channels: Dict[str, dict] = {}

    async def load(self):
        """Initialize plugin: create tables and restore lock state from DB."""
        await super().load()
        async with get_db(self.core.db_path) as db:
            for sql in self.TABLE_SQL:
                await db.execute(sql)
            await db.commit()

        # Register a periodic timer to handle auto-unlock and re-enforce locks
        self.core.send_irc({
            'cmd': 'REGISTER_IRC_TIMER',
            'name': 'chanlock',
            'interval': 30
        })

        # Restore in-memory state from DB
        await self._restore_locked_state()
        self.log.info(f"Plugin {self.name} {self.version} loaded")

    async def unload(self):
        """Unload plugin and unregister timer. Lock state persists in DB."""
        self.core.send_irc({
            'cmd': 'UNREGISTER_IRC_TIMER',
            'name': 'chanlock'
        })
        await super().unload()
        self.log.info("Chanlock plugin unloaded")

    async def on_MODE(self, event: dict):
        """
        Watch for -i being set on a locked channel and immediately re-apply +i.
        Also watches for -m and -k if those modes are part of the lockdown config.
        """
        chan = event.get('channel')
        if not chan or chan not in self._locked_channels:
            return

        cfg = self._locked_channels[chan]
        modes: str = event.get('modes', '')

        # Someone removed invite-only — put it back immediately
        if '-i' in modes:
            self.log.warning(f"[chanlock] +i removed on locked channel {chan} — re-enforcing")
            await self._enforce_lock(chan, cfg)
            await self._audit(chan, "mode_reenforce", "bot")

        # Someone removed moderated while +m lock is active
        if cfg.get('use_m') and '-m' in modes:
            self.log.warning(f"[chanlock] +m removed on locked channel {chan} — re-enforcing")
            self.core.send_irc({'cmd': 'mode', 'channel': chan, 'modes': '+m'})

        # Someone removed the key while +k lock is active
        if cfg.get('key') and '-k' in modes:
            self.log.warning(f"[chanlock] +k removed on locked channel {chan} — re-enforcing")
            self.core.send_irc({'cmd': 'mode', 'channel': chan, 'modes': f"+k {cfg['key']}"})

    async def on_JOIN(self, event: dict):
        """
        Re-enforce lock when the bot joins a channel that is marked locked in DB.
        Handles reconnect scenarios.
        """
        nick = event.get('nick')
        chan = event.get('channel')

        # Only care about the bot's own JOIN
        if not self.core.irc or nick != self.core.irc.nick:
            return

        cfg = await self._load_settings(chan)
        if cfg['locked']:
            self.log.info(f"[chanlock] Bot joined {chan} — restoring lock")
            self._locked_channels[chan] = cfg
            await self._enforce_lock(chan, cfg)

    async def on_IRC_TIMER_CHANLOCK(self, event: dict):
        """
        Periodic enforcement:
        - Re-check locked channels still have +i
        - Handle auto-unlock expiry
        """
        irc_data = event.get('irc_data', {})
        if not irc_data.get('connected'):
            return

        now = time.time()
        to_unlock = []

        for chan, cfg in list(self._locked_channels.items()):
            if not irc_data['channels'].get(chan, {}).get('bot_op'):
                continue  # Can't enforce without ops

            # Auto-unlock check
            secs = cfg.get('auto_unlock_secs', 0)
            locked_at = cfg.get('locked_at') or 0
            if secs > 0 and locked_at and (now - locked_at) >= secs:
                to_unlock.append(chan)
                continue

            # Verify +i is still set; if not, re-apply
            chan_modes = irc_data['channels'].get(chan, {}).get('modes', '')
            if 'i' not in chan_modes:
                self.log.warning(f"[chanlock] Timer: {chan} missing +i — re-enforcing")
                await self._enforce_lock(chan, cfg)
                await self._audit(chan, "timer_reenforce", "bot")

        for chan in to_unlock:
            await self._do_unlock(chan, "auto-unlock")

    async def lock(self, chan: str, nick: str, use_m: bool = False,
                   key: Optional[str] = None, auto_unlock_secs: int = 0) -> str:
        """
        Lock a channel: set +i (and optionally +m, +k).

        Permission enforcement MUST be done upstream before calling this.

        Args:
            chan:              Channel to lock (e.g. #help)
            nick:             Nick triggering the lock (for audit log)
            use_m:            Also set +m (moderated)
            key:              Optional channel key for +k
            auto_unlock_secs: Auto-unlock after N seconds (0 = never)
        Returns:
            Human-readable status string for partyline output.
        """
        now = int(time.time())
        cfg = {
            'locked': 1,
            'use_m': int(use_m),
            'key': key,
            'auto_unlock_secs': auto_unlock_secs,
            'locked_by': nick,
            'locked_at': now,
        }
        await self._save_settings(chan, **cfg)
        self._locked_channels[chan] = cfg
        await self._enforce_lock(chan, cfg)
        await self._audit(chan, "lock", nick)

        parts = ["+i"]
        if use_m:
            parts.append("+m")
        if key:
            parts.append(f"+k {key}")
        mode_str = " ".join(parts)
        timer_note = f" (auto-unlock in {auto_unlock_secs}s)" if auto_unlock_secs else ""
        return f"[chanlock] {chan} locked ({mode_str}){timer_note} by {nick}."

    async def unlock(self, chan: str, nick: str) -> str:
        """
        Unlock a channel: remove +i (and +m/+k if they were set by lock).

        Permission enforcement MUST be done upstream before calling this.
        """
        await self._do_unlock(chan, nick)
        return f"[chanlock] {chan} unlocked by {nick}."

    async def status(self, chan: str) -> str:
        """Return lock status for a channel."""
        cfg = await self._load_settings(chan)
        if not cfg['locked']:
            return f"[chanlock] {chan} is NOT locked."
        parts = ["+i"]
        if cfg.get('use_m'):
            parts.append("+m")
        if cfg.get('key'):
            parts.append("+k")
        by = cfg.get('locked_by') or 'unknown'
        at = cfg.get('locked_at')
        ts = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(at)) if at else 'unknown'
        return f"[chanlock] {chan} LOCKED ({', '.join(parts)}) by {by} at {ts}."

    async def set(self, chan: str, param: str, value: str, nick: str) -> str:
        """
        Adjust a single chanlock setting via partyline.

        Usage: .chanlock set #chan <param> <value>
        Valid params: use_m (0|1), key (<word>|none), auto_unlock_secs (<int>)
        """
        valid = {
            "use_m":            ("Moderated (+m)",    lambda v: v in ("0", "1"),   lambda v: int(v)),
            "key":              ("Channel key (+k)",  lambda v: len(v) > 0,        lambda v: None if v.lower() == "none" else v),
            "auto_unlock_secs": ("Auto-unlock secs",  str.isdigit,                 lambda v: int(v)),
        }
        param = param.lower()
        if param not in valid:
            return f"Usage: .chanlock set <chan> <{'|'.join(valid)}> <value>"
        label, validate, cast = valid[param]
        if not validate(value):
            return f"{label}: invalid value '{value}'."
        cast_value = cast(value)
        await self._save_settings(chan, **{param: cast_value})
        # Refresh in-memory state if channel is currently locked
        if chan in self._locked_channels:
            self._locked_channels[chan][param] = cast_value
        return f"[chanlock] {chan} {label} set to {cast_value!r}."

    async def _enforce_lock(self, chan: str, cfg: dict):
        """Send the MODE commands to actually lock the channel."""
        modes = "+i"
        params = ""
        if cfg.get('use_m'):
            modes += "m"
        if cfg.get('key'):
            modes += "k"
            params = f" {cfg['key']}"
        self.core.send_irc({
            'cmd': 'mode',
            'channel': chan,
            'modes': f"{modes}{params}"
        })

    async def _do_unlock(self, chan: str, nick: str):
        """Remove lock modes and clear state."""
        cfg = self._locked_channels.pop(chan, await self._load_settings(chan))
        modes = "-i"
        if cfg.get('use_m'):
            modes += "m"
        if cfg.get('key'):
            modes += "k"
        self.core.send_irc({'cmd': 'mode', 'channel': chan, 'modes': modes})
        await self._save_settings(chan, locked=0, locked_by=None, locked_at=None)
        await self._audit(chan, "unlock", nick)
        self.log.info(f"[chanlock] {chan} unlocked by {nick}")

    async def _restore_locked_state(self):
        """Reload locked channels from DB into memory on plugin load."""
        async with get_db(self.core.db_path) as db:
            try:
                async with db.execute(
                    "SELECT * FROM chanlock_settings WHERE locked = 1"
                ) as cursor:
                    rows = await cursor.fetchall()
                    for row in rows:
                        d = dict(row)
                        self._locked_channels[d['channel']] = d
                        self.log.info(f"[chanlock] Restored lock state for {d['channel']}")
            except aiosqlite.OperationalError:
                self.log.warning("[chanlock] chanlock_settings not yet created — skipping restore")

    async def _load_settings(self, chan: str) -> dict:
        """Load channel settings from DB, returning defaults if not found."""
        defaults = {
            'locked': 0, 'use_m': 0, 'key': None,
            'auto_unlock_secs': 0, 'locked_by': None, 'locked_at': None
        }
        async with get_db(self.core.db_path) as db:
            try:
                async with db.execute(
                    "SELECT * FROM chanlock_settings WHERE channel = ?", (chan,)
                ) as cursor:
                    row = await cursor.fetchone()
                    return dict(row) if row else defaults
            except aiosqlite.OperationalError:
                self.log.warning("[chanlock] Table missing for %s — using defaults", chan)
                return defaults

    async def _save_settings(self, channel: str, **kwargs):
        """
        Persist settings for a channel.
        Validates kwargs keys against ALLOWED_SETTING_COLS to prevent injection.
        """
        invalid = kwargs.keys() - ALLOWED_SETTING_COLS
        if invalid:
            raise ValueError(f"Invalid setting column(s): {invalid}")

        cols = ", ".join(f"{k}=?" for k in kwargs)
        async with get_db(self.core.db_path) as db:
            await db.execute(
                f"INSERT INTO chanlock_settings(channel) VALUES(?) "
                f"ON CONFLICT(channel) DO UPDATE SET {cols}, "
                f"updated_at=strftime('%s','now')",
                (channel, *kwargs.values())
            )
            await db.commit()

    async def _audit(self, channel: str, action: str, by_nick: str):
        """Write an audit log entry for every lock/unlock/re-enforce event."""
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO chanlock_audit(channel, action, by_nick) VALUES(?, ?, ?)",
                (channel, action, by_nick)
            )
            await db.commit()