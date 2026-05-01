# src/games/duckhunt.py
"""
WBS Game: duckhunt.py 
version: 0.1.0
by: cyco
Description: Just a small duck hunting game.

Commands (in-channel):
  !bang                    - Shoot a duck.
  !duckstats               - Get the stats.
  !duckstatus              - Game status.
  !duckhelp                - Display DuckHunt's help.
"""
import asyncio
import random
import time
from typing import Optional

from . import Game, GameSession, _db

class DuckhuntGame(Game):
    name = "duckhunt"
    version = "0.1.0"
    scopes = {"channel"}
    allow_multiple_sessions = False
    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS duckhunt_settings (
            channel      TEXT  PRIMARY KEY,
            min_delay    INTEGER DEFAULT 180,
            max_delay    INTEGER DEFAULT 7200,
            duck_timeout INTEGER DEFAULT 7200,
            reload_time  REAL    DEFAULT 2.0,
            updated_at   INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS duckhunt_scores (
            channel    TEXT NOT NULL,
            nick       TEXT NOT NULL,
            score      INTEGER DEFAULT 0,
            misses     INTEGER DEFAULT 0,
            quickest   REAL    DEFAULT NULL,
            longest    REAL    DEFAULT NULL,
            updated_at INTEGER DEFAULT (strftime('%s','now')),
            PRIMARY KEY (channel, nick)
        )
        """,
    ]
    _UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)

    async def load(self):
        await super().load()
        db_path = self.core.db_path 
        async with _db(db_path) as db:
            await db.execute(self.TABLE_SQL[0])
            await db.commit() 
        async with _db(db_path) as db:
            await db.execute(self.TABLE_SQL[1])
            await db.commit() 
        self.log.info(f"Game {self.name} {self.version} loaded")

    async def unload(self):
        async with _db(self.core.db_path) as db:
            await db.execute("DROP TABLE IF EXISTS duckhunt_settings")
            await db.commit() 
        async with _db(self.core.db_path) as db:
            await db.execute("DROP TABLE IF EXISTS duckhunt_scores")
            await db.commit() 
        await super().unload()
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession):
        chan = session.target
        cfg  = await self._load_settings(chan)
        session.data["min_delay"]    = cfg["min_delay"]
        session.data["max_delay"]    = cfg["max_delay"]
        session.data["duck_timeout"] = cfg["duck_timeout"]
        session.data["reload_time"]  = cfg["reload_time"]
        session.data.setdefault("duck_up",            False)
        session.data.setdefault("duck_time",          0.0)
        session.data.setdefault("last_shot",          {})
        session.data.setdefault("consecutive_misses", 0)
        session.data.setdefault("lock",               asyncio.Lock())

        await super().start_session(session)

        await self.send_privmsg(
            session.target,
            "DuckHunt started. Wait for a duck, then use !bang",
        )

        session.task = asyncio.create_task(self._hunt_loop(session))

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.send_privmsg(session.target, "DuckHunt stopped.")
        await super().stop_session(key)

    async def handle_command(
        self,
        session: GameSession,
        nick: str,
        command: str,
        args: list[str],
        event: Optional[dict] = None,
    ):
        command = command.lower()

        if command == "bang":
            await self._bang(session, nick)
            return

        if command in {"duckstats", "duckscores"}:  # Instead of score,scores,stats
            await self._show_scores(session)
            return

        if command == "duckstatus":
            min_delay = session.data.get("min_delay", 20)
            max_delay = session.data.get("max_delay", 60)
            duck_up = session.data["duck_up"]
            misses = session.data.get("consecutive_misses", 0)
            
            status = "duck UP!" if duck_up else "no duck"
            quiet = " (quiet after 2 misses)" if misses >= 2 else f" ({misses} misses)"
            
            next_range = f"{min_delay/60:.0f}-{max_delay/3600:.1f}h"
            await self.send_privmsg(
                session.target, 
                f"Ducks: {status}{quiet}. Next possible in ~{next_range}"
            )
            return

        if command == "duckset" and args:
            valid = {"min_delay", "max_delay", "duck_timeout", "reload_time"}
            param = args[0].lower()
            if param not in valid or len(args) < 2:
                await self.send_privmsg(
                    session.target,
                    f"Usage: !duckset <{'|'.join(valid)}> <value>"
                )
                return
            try:
                value = float(args[1]) if param == "reload_time" else int(args[1])
            except ValueError:
                await self.send_notice(nick, "Value must be a number.")
                return
            session.data[param] = value
            await self._save_setting(session.target, **{param: value})
            await self.send_privmsg(session.target, f"DuckHunt {param} set to {value}.")
            return

        if command == "duckhelp":
            await self.send_privmsg(
                session.target,
                "DuckHunt: !bang (shoot), !duckstats (scores), !duckstatus (info), !duckhelp"
            )
            return

        await self.send_notice(nick, f"Unknown duckhunt command: {command}")

    async def _hunt_loop(self, session: GameSession):
        try:
            while True:
                delay = random.randint(
                    int(session.data["min_delay"]),
                    int(session.data["max_delay"]),
                )
                await asyncio.sleep(delay)

                if session.key not in self.sessions or session.state != "running":
                    return

                if session.data["duck_up"]:
                    continue

                session.data["duck_up"] = True
                session.data["duck_time"] = time.monotonic()

                duck_msg = random.choice([
                    "・゜゜・。。・゜゜\\_o< QUACK!",
                    "・゜゜・。。・゜゜\\_O< FLAP FLAP!",
                    "・゜゜・。。・゜゜\\_0< quack!",
                ])
                await self.send_privmsg(session.target, duck_msg)

                base_timeout = float(session.data["duck_timeout"])
                duck_timeout = random.uniform(base_timeout * 0.5, base_timeout * 1.5)
                await asyncio.sleep(float(session.data["duck_timeout"]))

                if session.key not in self.sessions or session.state != "running":
                    return

                if session.data["duck_up"]:
                    session.data["duck_up"] = False
                    session.data["consecutive_misses"] += 1  # Track miss
                    await self.send_privmsg(session.target, "Duck flew away after hours...")
                    
                    if session.data["consecutive_misses"] >= 2:
                        break_min = 8 * 3600   # 8 hours
                        break_max = 24 * 3600  # 24 hours
                        break_time = random.randint(break_min, break_max)
                        hours = break_time // 3600
                        mins = (break_time % 3600) // 60
                        #await self.send_privmsg(session.target, f"Ducks quiet after misses. Break ~{break_time//60} min.")
                        await asyncio.sleep(break_time)
                        session.data["consecutive_misses"] = 0  # Reset

                if session.key not in self.sessions or session.state != "running":
                    return

                if session.data["duck_up"]:
                    session.data["duck_up"] = False
                    await self.send_privmsg(session.target, "The duck got away...")
        except asyncio.CancelledError:
            raise

    async def _bang(self, session: GameSession, nick: str):
        async with session.data["lock"]:
            now = time.monotonic()
            last_shot = session.data["last_shot"].get(nick.lower(), 0.0)
            reload_time = float(session.data["reload_time"])

            if now - last_shot < reload_time:
                remain = reload_time - (now - last_shot)
                await self.send_notice(nick, f"Reloading... {remain:.1f}s left")
                return

            session.data["last_shot"][nick.lower()] = now
            if not session.data["duck_up"]:
                new_score = await self._update_score(session.target, nick, hit=False)
                await self.send_privmsg(
                    session.target,
                    f"{nick} fires wildly at nothing and loses a point. "
                    f"Score: {new_score}",
                )
                return

            reaction = now - float(session.data["duck_time"])
            session.data["duck_up"] = False
            session.data["consecutive_misses"] = 0

            new_score = await self._update_score(
                session.target, nick, hit=True, reaction=reaction
            )
            await self.send_privmsg(
                session.target,
                f"{nick} got the duck in {reaction:.3f}s! "
                f"Score: {new_score}",
            )

    async def _show_scores(self, session: GameSession):
        chan = session.target
        async with _db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, score, quickest, longest FROM duckhunt_scores "
                "WHERE channel=? ORDER BY score DESC LIMIT 5",
                (chan,)
            ) as cursor:
                rows = await cursor.fetchall()

            async with db.execute(
                "SELECT nick, quickest FROM duckhunt_scores "
                "WHERE channel=? AND quickest IS NOT NULL ORDER BY quickest ASC LIMIT 1",
                (chan,)
            ) as cursor:
                qrow = await cursor.fetchone()

            async with db.execute(
                "SELECT nick, longest FROM duckhunt_scores "
                "WHERE channel=? AND longest IS NOT NULL ORDER BY longest DESC LIMIT 1",
                (chan,)
            ) as cursor:
                lrow = await cursor.fetchone()

        if not rows:
            await self.send_privmsg(chan, "No duck scores yet.")
            return

        score_line = ", ".join(f"{r['nick']}:{r['score']}" for r in rows)
        extra = []
        if qrow:
            extra.append(f"quickest={qrow['nick']} {qrow['quickest']:.3f}s")
        if lrow:
            extra.append(f"longest={lrow['nick']} {lrow['longest']:.3f}s")

        suffix = f" ({', '.join(extra)})" if extra else ""
        await self.send_privmsg(chan, f"Duck scores: {score_line}{suffix}")

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        command = text.strip().lower()
        if command == '!bang':
            await self._bang(session, nick)
        elif command == '!duckstats':
            await self._show_scores(session)
        elif command == '!duckstatus':
            min_delay = session.data.get("min_delay", 20)
            max_delay = session.data.get("max_delay", 60)
            duck_up = session.data["duck_up"]
            misses = session.data.get("consecutive_misses", 0)
            
            status = "duck UP!" if duck_up else "no duck"
            quiet = " (quiet after 2 misses)" if misses >= 2 else f" ({misses} misses)"
            
            next_range = f"{min_delay/60:.0f}mins to {max_delay/3600:.1f}hours"
            await self.send_privmsg(
                session.target, 
                f"Ducks: {status}{quiet}. Next possible in ~{next_range}"
            )
            return
        elif command == '!duckhelp':
            await self.send_privmsg(session.target, "DuckHunt: !bang, !duckstats, !duckstatus, !duckhelp")

    async def _load_settings(self, channel: str) -> dict:
        async with _db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM duckhunt_settings WHERE channel=?", (channel,)
            ) as cursor:
                row = await cursor.fetchone()
        if row:
            return {
                "min_delay":    row["min_delay"],
                "max_delay":    row["max_delay"],
                "duck_timeout": row["duck_timeout"],
                "reload_time":  row["reload_time"],
            }
        return {
            "min_delay": 180, "max_delay": 7200,
            "duck_timeout": 7200, "reload_time": 2.0,
        }

    async def _save_setting(self, channel: str, **kwargs):
        cols = ", ".join(f"{k}=?" for k in kwargs)
        async with _db(self.core.db_path) as db:
            await db.execute(
                f"INSERT INTO duckhunt_settings(channel) VALUES(?) "
                f"ON CONFLICT(channel) DO UPDATE SET {cols}, "
                f"updated_at=strftime('%s','now')",
                (channel, *kwargs.values())
            )

    async def _update_score(
        self, channel: str, nick: str,
        hit: bool, reaction: float = 0.0
    ) -> int:
        async with _db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO duckhunt_scores(channel, nick, score, misses) VALUES(?,?,?,?) "
                "ON CONFLICT(channel, nick) DO UPDATE SET "
                "  score    = score + excluded.score, "
                "  misses   = misses + excluded.misses, "
                "  quickest = CASE WHEN ? IS NOT NULL AND "
                "    (quickest IS NULL OR ? < quickest) THEN ? ELSE quickest END, "
                "  longest  = CASE WHEN ? IS NOT NULL AND "
                "    (longest IS NULL OR ? > longest) THEN ? ELSE longest END, "
                "  updated_at = strftime('%s','now')",
                (
                    channel, nick,
                    1 if hit else -1,
                    0 if hit else 1,
                    reaction if hit else None,
                    reaction if hit else None,
                    reaction if hit else None,
                    reaction if hit else None,
                    reaction if hit else None,
                    reaction if hit else None,
                )
            )
            async with db.execute(
                "SELECT score FROM duckhunt_scores WHERE channel=? AND nick=?",
                (channel, nick)
            ) as cursor:
                row = await cursor.fetchone()
        return row["score"] if row else 0        