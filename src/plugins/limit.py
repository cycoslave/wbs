# src/plugins/limit.py
"""
WBS Plugin: limit.py 
version: 0.1.1
by: cyco
Description: Set and watch channel limit
"""
import aiosqlite
import time
from typing import Dict

from . import Plugin
from ..db import get_db 

class limitPlugin(Plugin):
    name       = "limit"
    version    = "0.1.1"
    LIMITADD   = 15
    LIMITTOL   = 2
    LIMITDELTA = 300
    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS limit_settings (
            channel    TEXT    PRIMARY KEY,
            enabled    BOOLEAN DEFAULT 1,
            limitadd   INTEGER DEFAULT 15,
            limittol   INTEGER DEFAULT 2,
            limitdelta INTEGER DEFAULT 300,
            updated_at INTEGER DEFAULT (strftime('%s','now'))
        )
        """
    ]

    def __init__(self, core):
        super().__init__(core)  # sets self.log
        self.limit_last_change: Dict[str, float] = {}
    
    async def load(self):
        """Initialize plugin and register timers"""
        await super().load()
        async with get_db(self.core.db_path) as db:
            await db.execute(self.TABLE_SQL[0])
            await db.commit() 
        self.core.send_irc({
            'cmd': 'REGISTER_IRC_TIMER',
            'name': 'limit',
            'interval': 300
        })
        self.log.info(f"Plugin {self.name} {self.version} loaded")
    
    async def unload(self):
        """Unload plugin and unregister timers"""
        self.core.send_irc({
            'cmd': 'UNREGISTER_IRC_TIMER',
            'name': 'limit'
        })
        async with get_db(self.core.db_path) as db:
            await db.execute("DROP TABLE IF EXISTS limit_settings")
            await db.commit() 
        await super().unload()
        self.log.info("Limit plugin unloaded")

    async def on_IRC_TIMER_LIMIT(self, event):
        """Periodic op enforcement - FULL IRC access via event"""
        irc_data = event['irc_data']
        #self.log.info(f"data: {irc_data}")
        
        if not irc_data['connected']:
            return
        
        for chan, chan_data in irc_data['channels'].items():
            bot_is_op = chan_data['bot_op']
            if not bot_is_op:
                continue

            cfg = await self._load_settings(chan)
            if not cfg["enabled"]:
                continue

            now = time.time()
            if chan not in self.limit_last_change:
                self.limit_last_change[chan] = now - cfg["limitdelta"]
            if self.limit_last_change[chan] + cfg["limitdelta"] > now:
                continue

            current_limit = self.core.channels[chan].limit
            newlimit = chan_data['users'] + cfg["limitadd"]
            if abs(current_limit - newlimit) <= cfg["limittol"]:
                continue

            self.log.info(f"Setting limit on {chan} from {current_limit} to {newlimit}")
            self.core.send_irc({
                'cmd': 'mode',
                'channel': chan,
                'modes': f"+l {newlimit}"
            })
            self.limit_last_change[chan] = now

    def _get_current_limit(self, chan_data: dict) -> int:
        """Extract current +l limit from mode string and params"""
        mode_str = chan_data.get('mode', '')
        mode_params = chan_data.get('mode_params', {})
        
        # Check if +l is active in modes
        if 'l' in mode_str and 'l' in mode_params:
            try:
                return int(mode_params['l'])
            except (ValueError, TypeError):
                pass
        
        # No limit set
        return 0
    
    async def on_MODE(self, event):
        """Track manual +l changes"""
        chan = event['channel']
        if 'l' in event['modes']:
            self.limit_last_change[chan] = time.time()

    async def set(self, chan: str, param: str, value: str, nick: str):
        """Called by partyline: .limitset #chan <param> <value>"""
        valid = {
            "enabled":    ("Enabled",     lambda v: v in ("0","1"), int),
            "limitadd":   ("Limit add",   str.isdigit,              int),
            "limittol":   ("Tolerance",   str.isdigit,              int),
            "limitdelta": ("Delta (secs)","".isdigit,               int),
        }
        param = param.lower()
        if param not in valid:
            return f"Usage: .limitset <chan> <{'|'.join(valid)}> <value>"
        label, validate, cast = valid[param]
        if not validate(value):
            return f"{label} must be a valid value."
        cast_value = cast(value)
        await self._save_setting(chan, **{param: cast_value})
        # invalidate cooldown so new delta takes effect immediately
        if param == "limitdelta":
            self.limit_last_change.pop(chan, None)
        return f"[limit] {chan} {label} set to {cast_value}."

    async def _load_settings(self, chan: str) -> dict:
        defaults = {"enabled": 0, "maxusers": 20, "kick_threshold": 5, "reset_interval": 60}
        async with get_db(self.core.db_path) as db:
            try:
                async with db.execute(
                    "SELECT * FROM limit_settings WHERE channel = ?", (chan,)
                ) as cursor:
                    row = await cursor.fetchone()
                    return dict(row) if row else defaults
            except aiosqlite.OperationalError as exc:
                self.log.warning("limit_settings missing for %s, using defaults", chan)
                return defaults

    async def _save_setting(self, channel: str, **kwargs):
        cols = ", ".join(f"{k}=?" for k in kwargs)
        async with get_db(self.core.db_path) as db:
            await db.execute(
                f"INSERT INTO limit_settings(channel) VALUES(?) "
                f"ON CONFLICT(channel) DO UPDATE SET {cols}, "
                f"updated_at=strftime('%s','now')",
                (channel, *kwargs.values())
            )