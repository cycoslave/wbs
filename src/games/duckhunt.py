# src/games/duckhunt.py
"""
WBS Game: duckhunt.py
version: 0.2.0
by: cyco
Description: Duck hunting game with miss chance, shoot penalties,
             reload delay, and anti-cheat script detection.

Commands (in-channel):
  !bang                    - Shoot at a duck.
  !duckstats               - Show top scores.
  !duckstatus              - Game status.
  !duckset <param> <value> - Adjust settings (chan-op only).
  !duckhelp                - Display DuckHunt help.

Anti-cheat:
  Shots within SUSPECT_WINDOW seconds of duck spawn trigger a
  probe sequence (2-3 rapid ducks). If the player hits all probes
  within SUSPECT_WINDOW each time, they are flagged and lose
  CHEAT_PENALTY points. Flags are stored per-nick per-channel.
"""
import asyncio
import random
import time
from typing import Optional

from . import Game, GameSession
from ..db import get_db

CMD_COOLDOWN_SECS  = 60      # !duckstats spam guard
SUSPECT_WINDOW     = 1.5     # seconds — reaction faster than this is suspicious
PROBE_COUNT        = 3       # number of rapid probe ducks to fire
PROBE_DELAY_MIN    = 15 * 60 # 15 min — min gap between probe ducks
PROBE_DELAY_MAX    = 30 * 60 # 30 min — max gap between probe ducks
CHEAT_PENALTY      = 20      # points deducted on confirmed cheat
MISS_CHANCE        = 0.15    # 15% chance a shot misses even when duck is up
RELOAD_SECS        = 3.0     # default reload time (can be overridden by duckset)

class DuckhuntGame(Game):
    name    = "duckhunt"
    version = "0.2.0"
    scopes  = {"channel"}
    allow_multiple_sessions = False

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS duckhunt_settings (
            channel      TEXT    PRIMARY KEY,
            min_delay    INTEGER DEFAULT 180,
            max_delay    INTEGER DEFAULT 7200,
            duck_timeout INTEGER DEFAULT 60,
            reload_time  REAL    DEFAULT 3.0,
            updated_at   INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS duckhunt_scores (
            channel    TEXT    NOT NULL,
            nick       TEXT    NOT NULL,
            score      INTEGER DEFAULT 0,
            misses     INTEGER DEFAULT 0,
            quickest   REAL    DEFAULT NULL,
            longest    REAL    DEFAULT NULL,
            cheat_flags INTEGER DEFAULT 0,
            updated_at INTEGER DEFAULT (strftime('%s','now')),
            PRIMARY KEY (channel, nick)
        )
        """,
    ]
    _UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)
    _cmd_cooldowns: dict[str, dict[str, float]] = {}

    async def load(self):
        await super().load()
        async with get_db(self.core.db_path) as db:
            await db.execute(self.TABLE_SQL[0])
            await db.commit()
        async with get_db(self.core.db_path) as db:
            await db.execute(self.TABLE_SQL[1])
            await db.commit()
        self.log.info(f"Game {self.name} {self.version} loaded")

    async def unload(self):
        await super().unload()
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession):
        chan = session.target
        cfg  = await self._load_settings(chan)
        session.data["min_delay"]          = cfg["min_delay"]
        session.data["max_delay"]          = cfg["max_delay"]
        session.data["duck_timeout"]       = cfg["duck_timeout"]
        session.data["reload_time"]        = cfg["reload_time"]
        session.data.setdefault("duck_up",             False)
        session.data.setdefault("duck_time",           0.0)
        session.data.setdefault("last_shot",           {})
        session.data.setdefault("consecutive_misses",  0)
        session.data.setdefault("lock",                asyncio.Lock())
        # Anti-cheat state per nick: {nick: [reaction_time, ...]}
        session.data.setdefault("suspect_hits",        {})
        # Probe mode: None | {"nick": str, "remaining": int, "hits": int}
        session.data["probe"]              = None
        session.data["probe_task"]         = None

        await super().start_session(session)
        await self.send_privmsg(
            session.target,
            "DuckHunt started. Wait for a duck, then use \x02!bang\x02",
        )
        session.task = asyncio.create_task(self._hunt_loop(session))

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            probe_task = session.data.get("probe_task")
            if probe_task and not probe_task.done():
                probe_task.cancel()
            await self.send_privmsg(session.target, "DuckHunt stopped.")
        await super().stop_session(key)

    async def _hunt_loop(self, session: GameSession):
        """Randomly spawns ducks. Probe ducks are handled by a separate task."""
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

                await self._spawn_duck(session)

                # Wait for duck to either be shot or time out
                base_timeout = float(session.data["duck_timeout"])
                duck_timeout = random.uniform(base_timeout * 0.5, base_timeout * 1.5)
                await asyncio.sleep(duck_timeout)

                if session.key not in self.sessions or session.state != "running":
                    return

                if session.data["duck_up"]:
                    session.data["duck_up"] = False
                    session.data["consecutive_misses"] += 1
                    await self.send_privmsg(session.target, "The duck got away!")

                    if session.data["consecutive_misses"] >= 2:
                        break_time = random.randint(8 * 3600, 24 * 3600)
                        hours = break_time // 3600
                        mins  = (break_time % 3600) // 60
                        await self.send_privmsg(
                            session.target,
                            f"Ducks have gone quiet for a while (~{hours}h {mins}m). Check back later!"
                        )
                        # Reset before sleep so a restart sees 0
                        session.data["consecutive_misses"] = 0
                        await asyncio.sleep(break_time)

                if session.key not in self.sessions or session.state != "running":
                    return

        except asyncio.CancelledError:
            raise

    async def _spawn_duck(self, session: GameSession, probe: bool = False):
        """Put a duck up in the channel."""
        session.data["duck_up"]   = True
        session.data["duck_time"] = time.monotonic()
        duck_msg = random.choice([
            "・゜゜・。。・゜゜\\_o< QUACK!",
            "・゜゜・。。・゜゜\\_O< FLAP FLAP!",
            "・゜゜・。。・゜゜\\_0< quack!",
        ])
        if probe:
            duck_msg += "  \x02(!\x02)"  # subtle visual tag on probe ducks (optional — remove if unwanted)
        await self.send_privmsg(session.target, duck_msg)

    async def _start_probe(self, session: GameSession, nick: str):
        """
        Fire PROBE_COUNT ducks spaced PROBE_DELAY_MIN–PROBE_DELAY_MAX seconds
        apart. Track how many the suspect hits within SUSPECT_WINDOW seconds.
        If they hit all of them that fast, flag and penalise.
        """
        session.data["probe"] = {
            "nick":      nick,
            "remaining": PROBE_COUNT,
            "hits":      0,
        }
        session.data["probe_task"] = asyncio.create_task(
            self._probe_loop(session, nick)
        )
        self.log.info(f"[duckhunt] Anti-cheat probe started for {nick} in {session.target}")

    async def _probe_loop(self, session: GameSession, nick: str):
        try:
            for i in range(PROBE_COUNT):
                delay = random.randint(PROBE_DELAY_MIN, PROBE_DELAY_MAX)
                await asyncio.sleep(delay)

                if session.key not in self.sessions or session.state != "running":
                    return
                if session.data["duck_up"]:
                    # Main loop already has a duck up — skip this probe duck
                    session.data["probe"]["remaining"] -= 1
                    continue

                await self._spawn_duck(session, probe=True)

                # Wait up to duck_timeout for a shot
                base_timeout = float(session.data["duck_timeout"])
                duck_timeout = random.uniform(base_timeout * 0.5, base_timeout * 1.5)
                await asyncio.sleep(duck_timeout)

                if session.data["duck_up"]:
                    # Probe duck not shot — take it down silently
                    session.data["duck_up"] = False

                session.data["probe"]["remaining"] -= 1

            # All probes fired — evaluate
            probe     = session.data["probe"]
            hit_ratio = probe["hits"] / PROBE_COUNT

            if hit_ratio >= 1.0:
                # Every probe duck hit within SUSPECT_WINDOW — very likely a script
                await self._flag_cheater(session, nick)
            else:
                self.log.info(
                    f"[duckhunt] Probe for {nick} inconclusive "
                    f"({probe['hits']}/{PROBE_COUNT} fast hits)"
                )

            session.data["probe"]      = None
            session.data["probe_task"] = None

        except asyncio.CancelledError:
            session.data["probe"]      = None
            session.data["probe_task"] = None
            raise

    async def _flag_cheater(self, session: GameSession, nick: str):
        chan = session.target
        new_score = await self._apply_penalty(chan, nick, CHEAT_PENALTY)
        await self.send_privmsg(
            chan,
            f"\x02[Anti-cheat]\x02 {nick} has been flagged for suspected scripting "
            f"and loses \x02{CHEAT_PENALTY} points\x02. Score: {new_score}"
        )
        self.log.warning(f"[duckhunt] Cheat flag: {nick} in {chan}. Score after penalty: {new_score}")

    async def _bang(self, session: GameSession, nick: str):
        async with session.data["lock"]:
            now         = time.monotonic()
            last_shot   = session.data["last_shot"].get(nick.lower(), 0.0)
            reload_time = float(session.data["reload_time"])
            if now - last_shot < reload_time:
                remain = reload_time - (now - last_shot)
                await self.send_notice(nick, f"Still reloading... {remain:.1f}s left")
                return

            session.data["last_shot"][nick.lower()] = now
            if not session.data["duck_up"]:
                # Penalty: lose 1 point for shooting at nothing
                new_score = await self._update_score(session.target, nick, delta=-1)
                await self.send_privmsg(
                    session.target,
                    f"{nick} fires wildly at nothing! \x02-1 point\x02. Score: {new_score}"
                )
                return

            reaction  = now - float(session.data["duck_time"])
            if random.random() < MISS_CHANCE:
                # Duck stays up — someone else can still shoot it
                await self.send_privmsg(
                    session.target,
                    f"{nick} fires but \x02misses\x02! The duck is still there..."
                )
                return

            session.data["duck_up"]              = False
            session.data["consecutive_misses"]   = 0

            new_score = await self._update_score(
                session.target, nick, delta=1, reaction=reaction
            )
            await self.send_privmsg(
                session.target,
                f"\x02{nick}\x02 got the duck in {reaction:.3f}s! Score: {new_score}"
            )

            # ── Anti-cheat: suspiciously fast reaction ────────────────────────
            if reaction < SUSPECT_WINDOW:
                # Check if this is a probe duck
                probe = session.data.get("probe")
                if probe and probe["nick"] == nick:
                    probe["hits"] += 1
                    self.log.info(
                        f"[duckhunt] Probe hit by {nick} in {reaction:.3f}s "
                        f"({probe['hits']}/{PROBE_COUNT})"
                    )
                else:
                    # First suspicious shot on a normal duck — start probe if not already running
                    probe_task = session.data.get("probe_task")
                    if probe_task is None or probe_task.done():
                        self.log.info(
                            f"[duckhunt] Suspicious reaction {reaction:.3f}s from {nick} — starting probe"
                        )
                        await self._start_probe(session, nick)

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return
        cmd  = parts[0].lower()
        args = parts[1:]
        chan = session.target

        if cmd == "!bang":
            await self._bang(session, nick)

        elif cmd in ("!duckstats", "!duckscores"):
            if not self._on_cooldown(chan, "duckstats"):
                await self._show_scores(session)

        elif cmd == "!duckstatus":
            duck_up = session.data["duck_up"]
            misses  = session.data.get("consecutive_misses", 0)
            min_d   = session.data.get("min_delay", 180)
            max_d   = session.data.get("max_delay", 7200)
            probe   = session.data.get("probe")
            status  = "\x02duck UP!\x02" if duck_up else "no duck"
            quiet   = " (ducks quiet — 2+ missed)" if misses >= 2 else f" ({misses} miss streak)"
            rng     = f"{min_d // 60}m–{max_d // 3600}h"
            probe_str = f"  \x02[probe active: {probe['nick']}]\x02" if probe else ""
            await self.send_privmsg(
                chan,
                f"DuckHunt: {status}{quiet}. Next duck window: ~{rng}{probe_str}"
            )

        elif cmd == "!duckset":
            if not self.core.nick_isop(nick, chan):
                return await self.send_notice(nick, "Only chan-ops can change DuckHunt settings.")
            valid = {"min_delay", "max_delay", "duck_timeout", "reload_time"}
            if not args or args[0].lower() not in valid or len(args) < 2:
                return await self.send_privmsg(
                    chan,
                    f"Usage: !duckset <{'|'.join(sorted(valid))}> <value>"
                )
            param = args[0].lower()
            try:
                value = float(args[1]) if param == "reload_time" else int(args[1])
            except ValueError:
                return await self.send_notice(nick, "Value must be a number.")
            session.data[param] = value
            await self._save_setting(chan, **{param: value})
            await self.send_privmsg(chan, f"DuckHunt {param} set to {value}.")

        elif cmd == "!duckhelp":
            await self.send_privmsg(
                chan,
                "DuckHunt: \x02!bang\x02 (shoot)  "
                "\x02!duckstats\x02 (scores)  "
                "\x02!duckstatus\x02 (info)  "
                "\x02!duckset\x02 (op only)  "
                "\x02!duckhelp\x02"
            )

    async def _show_scores(self, session: GameSession):
        chan = session.target
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, score, quickest, longest, cheat_flags "
                "FROM duckhunt_scores "
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

        score_line = "  ".join(
            f"{r['nick']}:{r['score']}"
            + (" \x02[flagged]\x02" if r["cheat_flags"] > 0 else "")
            for r in rows
        )
        extra = []
        if qrow:
            extra.append(f"fastest: {qrow['nick']} {qrow['quickest']:.3f}s")
        if lrow:
            extra.append(f"slowest: {lrow['nick']} {lrow['longest']:.3f}s")

        suffix = f"  ({', '.join(extra)})" if extra else ""
        await self.send_privmsg(chan, f"Duck scores: {score_line}{suffix}")

    async def _load_settings(self, channel: str) -> dict:
        async with get_db(self.core.db_path) as db:
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
            "duck_timeout": 60, "reload_time": RELOAD_SECS,
        }

    async def _save_setting(self, channel: str, **kwargs):
        cols = ", ".join(f"{k}=excluded.{k}" for k in kwargs)
        col_names = ", ".join(kwargs.keys())
        placeholders = ", ".join("?" * len(kwargs))
        async with get_db(self.core.db_path) as db:
            await db.execute(
                f"INSERT INTO duckhunt_settings(channel, {col_names}) "
                f"VALUES(?, {placeholders}) "
                f"ON CONFLICT(channel) DO UPDATE SET {cols}, "
                f"updated_at=strftime('%s','now')",
                (channel, *kwargs.values())
            )
            await db.commit()

    async def _update_score(
        self,
        channel: str,
        nick: str,
        delta: int,
        reaction: float = 0.0,
    ) -> int:
        """
        Apply a score delta. delta=+1 for a hit, delta=-1 for shooting at nothing.
        Score floor is 0 — cannot go below zero.
        Reaction times only recorded on hits (delta > 0).
        """
        hit = delta > 0
        async with get_db(self.core.db_path) as db:
            # Ensure row exists first
            await db.execute(
                "INSERT INTO duckhunt_scores(channel, nick) VALUES(?,?) "
                "ON CONFLICT(channel, nick) DO NOTHING",
                (channel, nick)
            )
            # Apply delta with floor at 0
            await db.execute(
                "UPDATE duckhunt_scores SET "
                "  score      = MAX(0, score + ?), "
                "  misses     = misses + ?, "
                "  quickest   = CASE WHEN ? AND (quickest IS NULL OR ? < quickest) THEN ? ELSE quickest END, "
                "  longest    = CASE WHEN ? AND (longest IS NULL OR ? > longest) THEN ? ELSE longest END, "
                "  updated_at = strftime('%s','now') "
                "WHERE channel=? AND nick=?",
                (
                    delta,
                    1 if not hit else 0,
                    hit, reaction if hit else 0, reaction if hit else 0,
                    hit, reaction if hit else 0, reaction if hit else 0,
                    channel, nick,
                )
            )
            await db.commit()
            async with db.execute(
                "SELECT score FROM duckhunt_scores WHERE channel=? AND nick=?",
                (channel, nick)
            ) as cursor:
                row = await cursor.fetchone()
        return row["score"] if row else 0

    async def _apply_penalty(self, channel: str, nick: str, points: int) -> int:
        """Deduct points and increment cheat_flags counter. Score floors at 0."""
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO duckhunt_scores(channel, nick) VALUES(?,?) "
                "ON CONFLICT(channel, nick) DO NOTHING",
                (channel, nick)
            )
            await db.execute(
                "UPDATE duckhunt_scores SET "
                "  score       = MAX(0, score - ?), "
                "  cheat_flags = cheat_flags + 1, "
                "  updated_at  = strftime('%s','now') "
                "WHERE channel=? AND nick=?",
                (points, channel, nick)
            )
            await db.commit()
            async with db.execute(
                "SELECT score FROM duckhunt_scores WHERE channel=? AND nick=?",
                (channel, nick)
            ) as cursor:
                row = await cursor.fetchone()
        return row["score"] if row else 0

    def _on_cooldown(self, chan: str, cmd: str) -> bool:
        now  = time.monotonic()
        last = self._cmd_cooldowns.setdefault(chan, {}).get(cmd, 0)
        if now - last < CMD_COOLDOWN_SECS:
            return True
        self._cmd_cooldowns[chan][cmd] = now
        return False