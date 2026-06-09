# src/games/horseracing.py
"""
WBS Game: horseracing.py
version: 0.1.0
by: cyco
Description: Horse Racing for WBS.
             Bot announces a field of 4–6 horses with odds, players !bet <horse> <amount>,
             then the race plays out turn-by-turn with flavour commentary.
             Winners are paid out at posted odds. Bankrolls persist per nick.

Flow:
  Partyline: .gstart horseracing channel #chan    → makes game available (idle)
  In-channel:
    !horse                      - Open betting for next race.
    !horsebet <horse> <amount>  - Place a bet on a horse by number or name.
    !horses                     - Re-list the current field with odds.
    !horsestats [nick]          - Show nick's lifetime earnings and wins.
    !horsetop                   - Top 5 earners.
    !horsehelp                  - Show commands.
    !horsestop                  - Chan-op ends the game session.
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import Game, GameSession
from ..db import get_db

BET_SECS          = 60      # betting window
BET_WARN_SECS     = 15      # warning before close
RACE_STEP_SECS    = 2.5     # seconds between race update messages
CMD_COOLDOWN_SECS = 90
DEFAULT_STARTING_CASH = 1000
DEFAULT_MIN_BET       = 10
HORSE_POOL: List[Tuple[str, str, str]] = [
    ("Thunder Hooves",    "🐴", "a powerhouse from the northern stables"),
    ("Glue Factory",      "🐎", "somehow still running"),
    ("Disco Stallion",    "🦄", "moves to the beat of his own drum"),
    ("Mud Magnet",        "🐴", "loves the wet track a little too much"),
    ("Captain Carrot",    "🥕", "runs for snacks, not glory"),
    ("Nap Time",          "😴", "was found asleep in the paddock this morning"),
    ("Lady Lightfoot",    "🐎", "three-time regional champion, today she's just vibing"),
    ("Iron Stomach",      "🐴", "ate the race programme and still feels fine"),
    ("Buttercup",         "🌼", "gentle temperament, terrifying sprint"),
    ("The Accountant",    "💼", "methodical, calculating, surprisingly fast"),
    ("Sir Stumbles-Alot", "🤕", "a legend of almost-wins"),
    ("Phantom Menace",    "👻", "nobody saw him at the weigh-in either"),
]
EARLY_LEAD = [
    "{horse} bursts off the line like rent is due!",
    "{horse} takes an early lead, looking effortless.",
    "{horse} stumbles slightly but recovers — heart of a champion.",
    "{horse} is holding steady in the pack, biding time.",
    "{horse} nearly trips over their own hooves but pushes on.",
    "{horse} found a gap and is threading through the field!",
]
MID_RACE = [
    "{horse} is gaining ground fast — the crowd goes wild!",
    "{horse} pulls alongside the leader — this is anyone's race!",
    "{horse} appears to be napping mid-stride. Classic {horse}.",
    "{horse} cuts wide on the bend — questionable strategy.",
    "{horse} is putting on a clinic. Poetry in motion.",
    "{horse} has mysteriously picked up a second wind.",
    "{horse} bumped the rail but hasn't lost pace.",
    "{horse} is falling back — jockey looks concerned.",
    "{horse} and the pack are nose-to-nose heading into the final stretch!",
]
NEAR_FINISH = [
    "{horse} surges — nothing is going to stop them now!",
    "{horse} is digging deep — every stride matters.",
    "{horse} wobbles — oh no — recovers! The crowd is on their feet!",
    "{horse} has a clear lane and is FLYING.",
    "{horse} fades… this could cost them everything.",
    "{horse} makes a desperate lunge for the line!",
]
WINNER_LINES = [
    "🏆 {horse} crosses the line first! The crowd erupts!",
    "🏆 {horse} wins by a nose! Unbelievable scenes!",
    "🏆 {horse} — nobody saw that coming! What a race!",
    "🏆 {horse} storms home! The bookies are sweating!",
    "🏆 {horse} takes it! Pure determination from start to finish!",
]
DNF_LINES = [
    "{horse} veered into the hay bales. Incredible.",
    "{horse} stopped to greet a spectator. Race over.",
    "{horse} sat down at the 400m mark and refused to continue.",
]

@dataclass
class Horse:
    number: int
    name: str
    emoji: str
    blurb: str
    odds: float        # payout multiplier, e.g. 2.5 → $25 return on $10 bet
    position: int = 0  # lower = further ahead

@dataclass
class Bet:
    nick: str
    horse_number: int
    amount: int

class HorseRacingGame(Game):
    name    = "horseracing"
    version = "0.1.0"
    scopes  = {"channel"}

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS horseracing_settings (
            channel       TEXT    PRIMARY KEY,
            starting_cash INTEGER DEFAULT 1000,
            min_bet       INTEGER DEFAULT 10,
            updated_at    INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS horseracing_bank (
            nick          TEXT    PRIMARY KEY,
            cash          INTEGER NOT NULL DEFAULT 1000,
            updated_at    INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS horseracing_stats (
            channel       TEXT    NOT NULL,
            nick          TEXT    NOT NULL,
            total_won     INTEGER NOT NULL DEFAULT 0,
            total_lost    INTEGER NOT NULL DEFAULT 0,
            wins          INTEGER NOT NULL DEFAULT 0,
            races         INTEGER NOT NULL DEFAULT 0,
            updated_at    INTEGER DEFAULT (strftime('%s','now')),
            PRIMARY KEY (channel, nick)
        )
        """,
    ]

    _UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)
    _cmd_cooldowns: Dict[str, Dict[str, float]] = {}

    async def load(self):
        await super().load()
        async with get_db(self.core.db_path) as db:
            for sql in self.TABLE_SQL:
                await db.execute(sql)
            await db.commit()
        self.log.info("Game %s %s loaded", self.name, self.version)

    async def unload(self):
        await super().unload()
        self.log.info("Game %s %s unloaded", self.name, self.version)

    async def start_session(self, session: GameSession):
        chan = session.target
        session.data["cfg"]     = await self._load_settings(chan)
        session.data["phase"]   = "idle"
        session.data["horses"]  = []   # List[Horse]
        session.data["bets"]    = []   # List[Bet]
        await super().start_session(session)
        await self.say(
            chan,
            "\x02[Horse Racing]\x02 Track is open! "
            "Type \x02!horserace\x02 to open the next race."
        )

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.say(session.target, "[Horse Racing] Track closed. See you next time!")
        await super().stop_session(key)

    async def _open_betting(self, session: GameSession):
        """Build the field, post odds, run the countdown, then fire the race."""
        chan  = session.target
        cfg  = session.data["cfg"]

        # Build field: 4–6 randomly chosen horses
        count  = random.randint(4, 6)
        sample = random.sample(HORSE_POOL, count)
        horses = []
        for i, (name, emoji, blurb) in enumerate(sample, start=1):
            # Odds: range 1.5–6.0; lower number = shorter odds (favourite)
            odds = round(random.uniform(1.5, 6.0), 1)
            horses.append(Horse(number=i, name=name, emoji=emoji, blurb=blurb, odds=odds))

        # Sort loosely so lower odds = early-field favourite
        horses.sort(key=lambda h: h.odds)

        session.data["horses"] = horses
        session.data["bets"]   = []
        session.data["phase"]  = "betting"

        await self.say(chan, "\x02[Horse Racing]\x02 ── Today's Field ──")
        for h in horses:
            await self.say(
                chan,
                f"  \x02#{h.number}\x02 {h.emoji} \x02{h.name}\x02 "
                f"(odds: {h.odds}x) — {h.blurb}"
            )
        await self.say(
            chan,
            f"You have \x02{BET_SECS}s\x02 to bet! "
            f"Usage: \x02!horsebet <#> <amount>\x02  (min: ${cfg['min_bet']})"
        )

        # Countdown with a single warning
        try:
            await asyncio.sleep(BET_SECS - BET_WARN_SECS)
            await self.say(
                chan,
                f"[Horse Racing] \x02{BET_WARN_SECS}s left!\x02 "
                "Last chance — !horsebet <#> <amount>"
            )
            await asyncio.sleep(BET_WARN_SECS)
        except asyncio.CancelledError:
            return

        await self._run_race(session)

    async def _run_race(self, session: GameSession):
        chan    = session.target
        horses  = session.data["horses"]
        bets    = session.data["bets"]
        session.data["phase"] = "racing"

        if not bets:
            await self.say(chan, "[Horse Racing] No bets placed — race cancelled.")
            session.data["phase"] = "finished"
            session.task = None
            await self._post_round_prompt(session)
            return

        # Assign random starting positions (lower = ahead)
        for h in horses:
            h.position = random.randint(0, 100)

        await self.say(chan, "\x02[Horse Racing]\x02 ── AND THEY'RE OFF! ──")
        await asyncio.sleep(1)

        # ── Early phase (2 updates) ──
        for _ in range(2):
            h = random.choice(horses)
            await self.say(chan, "  " + random.choice(EARLY_LEAD).format(horse=h.name))
            h.position += random.randint(10, 30)
            await asyncio.sleep(RACE_STEP_SECS)

        # ── Mid-race phase (3 updates, sorted standings shown once) ──
        for _ in range(3):
            h = random.choice(horses)
            await self.say(chan, "  " + random.choice(MID_RACE).format(horse=h.name))
            h.position += random.randint(5, 25)
            await asyncio.sleep(RACE_STEP_SECS)

        # Post mid-race standings
        standings = sorted(horses, key=lambda x: x.position, reverse=True)
        order_str = "  →  ".join(
            f"{h.emoji}{h.name}" for h in standings
        )
        await self.say(chan, f"[Horse Racing] Mid-race order: {order_str}")
        await asyncio.sleep(RACE_STEP_SECS)

        # ── Final stretch (2 updates) ──
        for _ in range(2):
            h = random.choice(horses)
            await self.say(chan, "  " + random.choice(NEAR_FINISH).format(horse=h.name))
            h.position += random.randint(10, 40)
            await asyncio.sleep(RACE_STEP_SECS)

        # ── Determine winner ──
        # Small chance of a dramatic last-second overtake for the underdog
        if random.random() < 0.15:
            winner = max(horses, key=lambda h: h.odds)   # biggest underdog wins
        else:
            winner = max(horses, key=lambda h: h.position)

        await self.say(
            chan,
            random.choice(WINNER_LINES).format(horse=winner.name)
        )
        await asyncio.sleep(1)

        # Build final order (winner first, rest shuffled)
        rest = [h for h in horses if h.number != winner.number]
        random.shuffle(rest)
        final = [winner] + rest
        place_str = "  ".join(
            f"{i+1}. {h.emoji}{h.name}" for i, h in enumerate(final)
        )
        await self.say(chan, f"[Horse Racing] Final: {place_str}")

        await self._settle(session, winner)

    async def _settle(self, session: GameSession, winner: Horse):
        chan = session.target
        bets = session.data["bets"]
        cfg  = session.data["cfg"]

        await self.say(chan, "[Horse Racing] ── Payouts ──")

        # Group by nick for cleaner output
        by_nick: Dict[str, List[Bet]] = {}
        for b in bets:
            by_nick.setdefault(b.nick, []).append(b)

        for nick, nick_bets in by_nick.items():
            net = 0
            parts = []
            for b in nick_bets:
                if b.horse_number == winner.number:
                    payout = int(b.amount * winner.odds)
                    profit = payout - b.amount
                    net   += profit
                    parts.append(
                        f"#{b.horse_number} WON → +${profit} "
                        f"(returned ${payout} on ${b.amount})"
                    )
                else:
                    net -= b.amount
                    parts.append(f"#{b.horse_number} lost → -${b.amount}")

            cash = await self._load_cash(nick, cfg["starting_cash"])
            cash = max(0, cash + net)
            await self._save_cash(nick, cash)
            await self._record_stats(
                channel=session.target,
                nick=nick,
                won=max(0, net),
                lost=abs(min(0, net)),
                win=(net > 0),
            )

            tag = f"\x0303+${net}\x03" if net > 0 else f"\x0304-${abs(net)}\x03"
            await self.say(
                chan,
                f"  {nick}: {' | '.join(parts)}  [{tag}]  bank: ${cash}"
            )

            if cash == 0:
                await self.say(
                    chan,
                    f"  \x02{nick}\x02 is broke! "
                    f"Next !horsebet will give you ${cfg['starting_cash'] // 2} to get back in the race."
                )

        session.data["phase"] = "finished"
        session.task = None
        await self._post_round_prompt(session)

    async def _post_round_prompt(self, session: GameSession):
        await asyncio.sleep(2)
        await self.say(
            session.target,
            "[Horse Racing] Race complete. "
            "\x02!horserace\x02 to run another  |  \x02!horsestop\x02 to close the track."
        )

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return

        cmd   = parts[0].lower()
        chan  = session.target
        phase = session.data.get("phase", "idle")
        cfg   = session.data["cfg"]
        bets: List[Bet] = session.data["bets"]

        # !horserace — open a new round
        if cmd == "!horserace":
            sub = parts[1].lower() if len(parts) > 1 else ""

            if sub == "stop":
                if not self.core.nick_isop(nick, chan):
                    return await self.notice(nick, "Only a chan-op can close the track.")
                await self.stop_session(session.key)
                return

            if phase in ("idle", "finished"):
                if session.task and not session.task.done():
                    session.task.cancel()
                session.task = asyncio.create_task(self._open_betting(session))
                return

            if phase == "betting":
                return await self.notice(nick, "Betting is already open — !horsebet <#> <amount>")
            if phase == "racing":
                return await self.notice(nick, "Race in progress! Wait for the results.")
            return

        # !horses — re-list the current field
        elif cmd == "!horses":
            horses: List[Horse] = session.data.get("horses", [])
            if phase not in ("betting",) or not horses:
                return await self.notice(nick, "No race is currently open for betting.")
            await self.say(chan, "[Horse Racing] Current field:")
            for h in horses:
                await self.say(
                    chan,
                    f"  \x02#{h.number}\x02 {h.emoji} \x02{h.name}\x02 "
                    f"(odds: {h.odds}x) — {h.blurb}"
                )
            return

        # !horsebet <horse> <amount>
        elif cmd == "!horsebet":
            if phase != "betting":
                return await self.notice(nick, "Betting is not open right now.")

            horses: List[Horse] = session.data["horses"]

            if len(parts) < 3:
                return await self.notice(nick, "Usage: !horsebet <horse #> <amount>")

            # Accept horse number or partial name match
            horse_arg = parts[1].lstrip("#")
            picked: Optional[Horse] = None
            if horse_arg.isdigit():
                num = int(horse_arg)
                picked = next((h for h in horses if h.number == num), None)
            else:
                needle = horse_arg.lower()
                picked = next(
                    (h for h in horses if needle in h.name.lower()), None
                )

            if not picked:
                return await self.notice(
                    nick,
                    f"Horse '{parts[1]}' not found. "
                    "Use the number from !horses."
                )

            try:
                amount = int(parts[2])
            except ValueError:
                return await self.notice(nick, "Bet amount must be a whole number.")

            if amount < cfg["min_bet"]:
                return await self.notice(nick, f"Minimum bet is ${cfg['min_bet']}.")

            cash = await self._load_cash(nick, cfg["starting_cash"])
            # Total already committed this round
            committed = sum(b.amount for b in bets if b.nick == nick)
            if amount > cash - committed:
                avail = cash - committed
                return await self.notice(
                    nick,
                    f"Insufficient funds. Available this round: ${avail}."
                )

            bets.append(Bet(nick=nick, horse_number=picked.number, amount=amount))
            await self.say(
                chan,
                f"[Horse Racing] {nick} bets \x02${amount}\x02 on "
                f"\x02{picked.name}\x02 (odds {picked.odds}x) "
                f"— potential return: ${int(amount * picked.odds)}"
            )
            return

        # !horsestats [nick]
        elif cmd == "!horsestats":
            target = parts[1] if len(parts) > 1 else nick
            await self._show_stats(chan, target)
            return

        # !horsetop
        elif cmd == "!horsetop":
            if not self._on_cooldown(chan, "racetop"):
                await self._show_top(chan)
            return

        # !horsehelp
        elif cmd == "!horsehelp":
            if not self._on_cooldown(chan, "racehelp"):
                await self._show_help(chan, cfg)
            return

    async def _load_settings(self, channel: str) -> dict:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM horseracing_settings WHERE channel=?", (channel,)
            ) as cur:
                row = await cur.fetchone()
        if row:
            return {
                "starting_cash": row["starting_cash"],
                "min_bet":       row["min_bet"],
            }
        return {
            "starting_cash": DEFAULT_STARTING_CASH,
            "min_bet":       DEFAULT_MIN_BET,
        }

    async def _load_cash(self, nick: str, starting_cash: int) -> int:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT cash FROM horseracing_bank WHERE nick=?", (nick,)
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                await db.execute(
                    "INSERT INTO horseracing_bank(nick, cash) VALUES(?,?)",
                    (nick, starting_cash),
                )
                await db.commit()
        return row["cash"] if row else starting_cash

    async def _save_cash(self, nick: str, amount: int):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO horseracing_bank(nick, cash) VALUES(?,?) "
                "ON CONFLICT(nick) DO UPDATE SET "
                "cash=excluded.cash, updated_at=strftime('%s','now')",
                (nick, amount),
            )
            await db.commit()

    async def _record_stats(
        self, channel: str, nick: str, won: int, lost: int, win: bool
    ):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                """
                INSERT INTO horseracing_stats(channel, nick, total_won, total_lost, wins, races)
                VALUES(?,?,?,?,?,1)
                ON CONFLICT(channel, nick) DO UPDATE SET
                    total_won  = horseracing_stats.total_won  + excluded.total_won,
                    total_lost = horseracing_stats.total_lost + excluded.total_lost,
                    wins       = horseracing_stats.wins + excluded.wins,
                    races      = horseracing_stats.races + 1,
                    updated_at = strftime('%s','now')
                """,
                (channel, nick, won, lost, 1 if win else 0),
            )
            await db.commit()

    async def _show_stats(self, chan: str, nick: str):
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                """
                SELECT total_won, total_lost, wins, races
                FROM horseracing_stats WHERE channel=? AND nick=?
                """,
                (chan, nick),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return await self.say(chan, f"[Horse Racing] No stats yet for {nick}.")
        net = row["total_won"] - row["total_lost"]
        tag = f"+${net}" if net >= 0 else f"-${abs(net)}"
        await self.say(
            chan,
            f"[Horse Racing] {nick}: {row['races']} races, "
            f"{row['wins']} wins, net {tag} "
            f"(won ${row['total_won']}, lost ${row['total_lost']})"
        )

    async def _show_top(self, chan: str):
        self._set_cooldown(chan, "racetop")
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                """
                SELECT nick,
                       (total_won - total_lost) AS net,
                       wins, races
                FROM horseracing_stats
                WHERE channel=?
                ORDER BY net DESC, wins DESC
                LIMIT 5
                """,
                (chan,),
            ) as cur:
                rows = await cur.fetchall()
        if not rows:
            return await self.say(chan, "[Horse Racing] No leaderboard data yet.")
        board = "  ".join(
            f"{i+1}. {r['nick']} "
            f"({'+'if r['net']>=0 else ''}{r['net']})"
            for i, r in enumerate(rows)
        )
        await self.say(chan, f"[Horse Racing] Top earners: {board}")

    async def _show_help(self, chan: str, cfg: dict):
        self._set_cooldown(chan, "racehelp")
        await self.say(chan, "[Horse Racing] commands:")
        await self.say(chan, f"    !horserace                - Open the next race (betting: {BET_SECS}s).")
        await self.say(chan, "    !horses                   - Re-list the current field with odds.")
        await self.say(chan, f"    !horsebet <#> <amount>    - Bet on a horse (min: ${cfg['min_bet']}).")
        await self.say(chan, "    !horsestats [nick]        - Show career stats.")
        await self.say(chan, "    !horsetop                 - Top 5 earners.")
        await self.say(chan, "    !horsestop                - Close the track (chan-op only).")

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