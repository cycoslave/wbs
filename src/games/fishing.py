# src/games/fishing.py
"""
WBS Game: fishing.py
version: 0.1.0
by: cyco
Description: IRC fishing game. Cast your line, wait for a bite, reel it in.
             Different fish award different points. Rare catches = big score.
             Miss the bite window and the fish gets away.

Flow:
  Partyline: .gstart fishing channel #chan  → makes game available (idle)
  In-channel:
    !fishcast           - Cast your line. One line per player at a time.
    !fishreel           - Reel in when you get a bite! Be quick.
    !fishstats [nick]   - Personal stats or another player's.
    !fishtop            - Top 5 anglers by score.
    !fishhelp           - Show commands.
    !fishing stop       - Chan-op ends the game.
"""
import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from . import Game, GameSession
from ..db import get_db

BITE_DELAY_MIN    = 10       # min seconds before a bite after casting
BITE_DELAY_MAX    = 45       # max seconds before a bite after casting
BITE_WINDOW_MIN   = 5        # min seconds to reel before fish escapes
BITE_WINDOW_MAX   = 12       # max seconds to reel before fish escapes
CMD_COOLDOWN_SECS = 60       # spam guard on !fishtop / !fishstats
FISH_TABLE = [
    # Common
    ("Boot",            (0.1,  0.5),   0,  40, "You pulled out an old boot. Classic."),
    ("Seaweed",         (0.0,  0.1),   0,  30, "Just a clump of seaweed. Not a fish."),
    ("Minnow",          (0.05, 0.2),   1,  80, "Tiny but it counts!"),
    ("Perch",           (0.2,  1.2),   2,  75, "A decent perch."),
    ("Bluegill",        (0.1,  0.8),   2,  70, "Scrappy little bluegill."),
    ("Carp",            (0.5,  4.0),   3,  60, "Heavy carp. Good fight."),
    ("Catfish",         (0.8,  5.0),   4,  55, "Big whiskered catfish."),
    # Uncommon
    ("Bass",            (0.5,  3.5),   6,  35, "Nice bass! The crowd approves."),
    ("Walleye",         (0.5,  4.0),   7,  30, "A walleye. Tasty one."),
    ("Pike",            (1.0,  8.0),   9,  25, "Long, mean pike. Watch the teeth."),
    ("Trout",           (0.3,  3.0),   8,  28, "Beautiful rainbow trout."),
    ("Salmon",          (2.0, 12.0),  12,  20, "A fat salmon! Well played."),
    # Rare
    ("Sturgeon",        (5.0, 40.0),  20,   8, "A massive sturgeon! Ancient fish."),
    ("Muskie",          (3.0, 20.0),  18,   7, "The fish of 10,000 casts. Muskie!"),
    ("Eel",             (0.5,  3.0),  10,   9, "A slithery eel. Spooky."),
    ("Swordfish",       (20., 120.),  30,   3, "A SWORDFISH?! How deep is this channel?"),
    # Legendary
    ("Golden Carp",     (1.0,  5.0),  50,   1, "\x02\x0307Golden Carp!\x03\x02 A legendary catch!"),
    ("Kraken Tentacle", (50.0, 999.0),75,   1, "\x02\x034A KRAKEN TENTACLE\x03\x02 drags your rod... you hold on!"),
    ("Rubber Duck",     (0.1,  0.1), 100,   1, "\x02A rubber duck?\x02 Worth 100pts for sheer mystery."),
]
FISH_NAMES    = [f[0] for f in FISH_TABLE]
FISH_WEIGHTS  = [f[3] for f in FISH_TABLE]

@dataclass
class ActiveLine:
    """Tracks one player's cast state."""
    nick:       str
    cast_time:  float                        # monotonic time of cast
    bite_time:  float  = 0.0                 # monotonic time of bite
    has_bite:   bool   = False
    fish_idx:   int    = -1                  # index into FISH_TABLE
    fish_kg:    float  = 0.0
    bite_task:  object = field(default=None) # asyncio.Task


class FishingGame(Game):
    name    = "fishing"
    version = "0.1.0"
    scopes  = {"channel"}
    allow_multiple_sessions = False

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS fishing_settings (
            channel        TEXT    PRIMARY KEY,
            bite_delay_min INTEGER DEFAULT 10,
            bite_delay_max INTEGER DEFAULT 45,
            bite_window_min INTEGER DEFAULT 5,
            bite_window_max INTEGER DEFAULT 12,
            updated_at     INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS fishing_scores (
            channel      TEXT    NOT NULL,
            nick         TEXT    NOT NULL,
            score        INTEGER DEFAULT 0,
            total_casts  INTEGER DEFAULT 0,
            total_caught INTEGER DEFAULT 0,
            biggest_fish TEXT    DEFAULT NULL,
            biggest_kg   REAL    DEFAULT NULL,
            rarest_fish  TEXT    DEFAULT NULL,
            rarest_pts   INTEGER DEFAULT 0,
            updated_at   INTEGER DEFAULT (strftime('%s','now')),
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
        # Tables intentionally preserved — scores survive plugin reload
        await super().unload()
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession, restore: bool = False):
        chan = session.target
        cfg  = await self._load_settings(chan)
        session.data["cfg"]   = cfg
        session.data["lines"] = {}   # nick.lower() -> ActiveLine
        session.data["lock"]  = asyncio.Lock()
        await super().start_session(session)
        if not restore:
            await self.say(chan,
                "\x02[Fishing]\x02 The lake is open! "
                "Type \x02!fishcast\x02 to drop your line."
            )

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            # Cancel all pending bite tasks
            for line in session.data.get("lines", {}).values():
                if line.bite_task and not line.bite_task.done():
                    line.bite_task.cancel()
            await self.say(session.target, "[Fishing] The lake is closed.")
        await super().stop_session(key)

    async def _bite_timer(self, session: GameSession, nick: str):
        """
        Wait a random delay, then announce a bite for nick.
        If the player doesn't reel within the bite window, the fish escapes.
        """
        cfg  = session.data["cfg"]
        nkey = nick.lower()

        try:
            delay = random.uniform(
                cfg["bite_delay_min"],
                cfg["bite_delay_max"],
            )
            await asyncio.sleep(delay)

            if session.key not in self.sessions or session.state != "running":
                return

            async with session.data["lock"]:
                line = session.data["lines"].get(nkey)
                if not line or line.has_bite:
                    return

                # Pick the fish now (hidden from player until reel)
                fish_idx  = random.choices(range(len(FISH_TABLE)), weights=FISH_WEIGHTS, k=1)[0]
                fish_info = FISH_TABLE[fish_idx]
                kg_min, kg_max = fish_info[1]
                fish_kg   = round(random.uniform(kg_min, kg_max), 2)

                line.has_bite  = True
                line.bite_time = time.monotonic()
                line.fish_idx  = fish_idx
                line.fish_kg   = fish_kg

            await self.say(session.target,
                f"\x02{nick}\x02 \x02\x0307!! BITE !!\x03\x02 — Quick, type \x02!reel\x02!"
            )

            # Bite window — wait, then check if they reeled
            window = random.uniform(cfg["bite_window_min"], cfg["bite_window_max"])
            await asyncio.sleep(window)

            if session.key not in self.sessions or session.state != "running":
                return

            async with session.data["lock"]:
                line = session.data["lines"].get(nkey)
                if line and line.has_bite:
                    # Still has bite — fish escaped
                    fish_name = FISH_TABLE[line.fish_idx][0]
                    del session.data["lines"][nkey]
                    await self.say(session.target,
                        f"  \x02{nick}\x02's \x02{fish_name}\x02 got away! "
                        f"Reel faster next time."
                    )

        except asyncio.CancelledError:
            raise

    async def _do_cast(self, session: GameSession, nick: str):
        async with session.data["lock"]:
            nkey = nick.lower()
            if nkey in session.data["lines"]:
                line = session.data["lines"][nkey]
                if line.has_bite:
                    await self.notice(nick, "You have a bite! Type \x02!reel\x02 now!")
                else:
                    await self.notice(nick, "Your line is already in the water. Be patient...")
                return

            line = ActiveLine(nick=nick, cast_time=time.monotonic())
            session.data["lines"][nkey] = line

        await self._update_cast_count(session.target, nick)
        await self.say(session.target,
            f"\x02{nick}\x02 casts their line... 🎣"
        )

        # Start bite timer outside the lock
        task = asyncio.create_task(self._bite_timer(session, nick))
        session.data["lines"][nick.lower()].bite_task = task

    async def _do_reel(self, session: GameSession, nick: str):
        async with session.data["lock"]:
            nkey = nick.lower()
            line = session.data["lines"].get(nkey)

            if line is None:
                await self.notice(nick, "You don't have a line in the water. Type \x02!fishcast\x02 first.")
                return

            if not line.has_bite:
                # Reeling with no bite yanks the line out
                if line.bite_task and not line.bite_task.done():
                    line.bite_task.cancel()
                del session.data["lines"][nkey]
                await self.say(session.target,
                    f"\x02{nick}\x02 reels in their line. No bite yet."
                )
                return

            # Successful catch
            reaction  = time.monotonic() - line.bite_time
            fish_info = FISH_TABLE[line.fish_idx]
            fish_name = fish_info[0]
            pts       = fish_info[2]
            flavour   = fish_info[4]
            kg        = line.fish_kg

            if line.bite_task and not line.bite_task.done():
                line.bite_task.cancel()
            del session.data["lines"][nkey]

        # Save and announce outside lock
        new_score = await self._record_catch(
            session.target, nick, fish_name, pts, kg
        )

        rarity_tag = ""
        if pts >= 50:
            rarity_tag = " \x02\x0307[LEGENDARY]\x03\x02"
        elif pts >= 18:
            rarity_tag = " \x02\x0304[RARE]\x03\x02"
        elif pts >= 6:
            rarity_tag = " \x02[uncommon]\x02"

        await self.say(session.target,
            f"\x02{nick}\x02 reels in a \x02{fish_name}\x02{rarity_tag} "
            f"({kg}kg, +{pts}pts) in {reaction:.2f}s!  {flavour}  "
            f"Score: {new_score}"
        )

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return
        cmd  = parts[0].lower()
        args = parts[1:]
        chan = session.target

        if cmd == "!fishcast":
            await self._do_cast(session, nick)

        elif cmd == "!fishreel":
            await self._do_reel(session, nick)

        elif cmd == "!fishstats":
            target = args[0] if args else nick
            await self._show_stats(chan, target)

        elif cmd == "!fishtop":
            if not self._on_cooldown(chan, "fishtop"):
                await self._show_top(chan)

        elif cmd == "!fishstop":
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only a chan-op can stop the game.")
            await self.stop_session(session.key)

        elif cmd == "!fishhelp":
            if not self._on_cooldown(chan, "fishhelp"):
                await self._show_help(chan)

    async def _show_stats(self, chan: str, nick: str):
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM fishing_scores WHERE channel=? AND nick=?",
                (chan, nick)
            ) as cursor:
                row = await cursor.fetchone()

        if not row:
            await self.say(chan, f"{nick} hasn't caught anything yet.")
            return

        pct = (
            f"{row['total_caught'] / row['total_casts'] * 100:.1f}%"
            if row["total_casts"] > 0 else "0%"
        )
        biggest  = f"{row['biggest_fish']} ({row['biggest_kg']}kg)" if row["biggest_fish"] else "none"
        rarest   = f"{row['rarest_fish']} ({row['rarest_pts']}pts)" if row["rarest_fish"] else "none"

        await self.say(chan,
            f"\x02{nick}\x02 — score: {row['score']}  "
            f"casts: {row['total_casts']}  "
            f"caught: {row['total_caught']} ({pct})  "
            f"biggest: {biggest}  "
            f"rarest: {rarest}"
        )

    async def _show_top(self, chan: str):
        self._set_cooldown(chan, "fishtop")
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, score, total_caught FROM fishing_scores "
                "WHERE channel=? ORDER BY score DESC LIMIT 5",
                (chan,)
            ) as cursor:
                rows = await cursor.fetchall()

        if not rows:
            return await self.say(chan, "[Fishing] No catches yet.")
        board = "  ".join(
            f"{i+1}. {r['nick']} {r['score']}pts ({r['total_caught']} fish)"
            for i, r in enumerate(rows)
        )
        await self.say(chan, f"[Fishing] Top anglers: {board}")

    async def _show_help(self, chan: str):
        self._set_cooldown(chan, "fishhelp")
        lines = [
            "[Fishing] commands:",
            "  !cast              - Drop your line in the water.",
            "  !reel              - Reel in when you get a bite!",
            "  !fishstats [nick]  - Show your (or another player's) stats.",
            "  !fishtop           - Top 5 anglers by score.",
            "  !fishing stop      - Chan-op ends the session.",
        ]
        for line in lines:
            await self.say(chan, line)

    async def _load_settings(self, channel: str) -> dict:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM fishing_settings WHERE channel=?", (channel,)
            ) as cursor:
                row = await cursor.fetchone()
        if row:
            return {
                "bite_delay_min":  row["bite_delay_min"],
                "bite_delay_max":  row["bite_delay_max"],
                "bite_window_min": row["bite_window_min"],
                "bite_window_max": row["bite_window_max"],
            }
        return {
            "bite_delay_min":  BITE_DELAY_MIN,
            "bite_delay_max":  BITE_DELAY_MAX,
            "bite_window_min": BITE_WINDOW_MIN,
            "bite_window_max": BITE_WINDOW_MAX,
        }

    async def _update_cast_count(self, channel: str, nick: str):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO fishing_scores(channel, nick, total_casts) VALUES(?,?,1) "
                "ON CONFLICT(channel, nick) DO UPDATE SET "
                "total_casts = total_casts + 1, "
                "updated_at  = strftime('%s','now')",
                (channel, nick)
            )
            await db.commit()

    async def _record_catch(
        self,
        channel: str,
        nick: str,
        fish_name: str,
        pts: int,
        kg: float,
    ) -> int:
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO fishing_scores("
                "  channel, nick, score, total_casts, total_caught, "
                "  biggest_fish, biggest_kg, rarest_fish, rarest_pts"
                ") VALUES(?,?,?,1,1,?,?,?,?) "
                "ON CONFLICT(channel, nick) DO UPDATE SET "
                "  score        = score + excluded.score, "
                "  total_caught = total_caught + 1, "
                "  biggest_fish = CASE WHEN excluded.biggest_kg > COALESCE(biggest_kg, -1) "
                "                 THEN excluded.biggest_fish ELSE biggest_fish END, "
                "  biggest_kg   = CASE WHEN excluded.biggest_kg > COALESCE(biggest_kg, -1) "
                "                 THEN excluded.biggest_kg   ELSE biggest_kg   END, "
                "  rarest_fish  = CASE WHEN excluded.rarest_pts > COALESCE(rarest_pts, -1) "
                "                 THEN excluded.rarest_fish  ELSE rarest_fish  END, "
                "  rarest_pts   = CASE WHEN excluded.rarest_pts > COALESCE(rarest_pts, -1) "
                "                 THEN excluded.rarest_pts   ELSE rarest_pts   END, "
                "  updated_at   = strftime('%s','now')",
                (channel, nick, pts, fish_name, kg, fish_name, pts)
            )
            await db.commit()
            async with db.execute(
                "SELECT score FROM fishing_scores WHERE channel=? AND nick=?",
                (channel, nick)
            ) as cursor:
                row = await cursor.fetchone()
        return row["score"] if row else 0

    async def say(self, target: str, msg: str):
        await self.send_privmsg(target, msg)

    async def notice(self, nick: str, msg: str):
        await self.send_notice(nick, msg)

    def _on_cooldown(self, chan: str, cmd: str) -> bool:
        now  = time.monotonic()
        last = self._cmd_cooldowns.setdefault(chan, {}).get(cmd, 0)
        if now - last < CMD_COOLDOWN_SECS:
            return True
        self._cmd_cooldowns[chan][cmd] = now
        return False

    def _set_cooldown(self, chan: str, cmd: str):
        self._cmd_cooldowns.setdefault(chan, {})[cmd] = time.monotonic()