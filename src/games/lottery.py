# src/games/lottery.py
"""
WBS Game: lottery.py
version: 0.2.0
by: cyco
Description: Daily IRC 6/49 lottery. Players pick 6 numbers (1-49) once per day.
             Bot draws 6 winning numbers at a configured UTC hour.
             Jackpot rolls over (full pot) if no 6-match winner.
             Uses on_tick() (called by GameManager.tick()) for the daily draw.

Flow:
  Partyline: .gstart lottery channel #chan  → activates daily lottery on channel
  In-channel:
    !lotto 7 14 21 28 35 42  - Pick your 6 numbers (once per calendar day UTC).
    !lotto                   - Show your current picks + time until draw.
    !lottojackpot            - Show current jackpot amount + ticket count.
    !lottotop                - Top 5 all-time winners by total winnings.
    !lottohelp               - Show commands and prize tiers.
    !lottostop               - Chan-op ends the lottery.

Draw mechanics:
    - 6 winning numbers drawn from 1-49 (no duplicates).
    - Match 3 → ticket price refunded (PRIZE_MATCH3).
    - Match 4 → PRIZE_MATCH4 chips.
    - Match 5 → PRIZE_MATCH5 chips.
    - Match 6 → jackpot split equally among all 6-match winners.
    - No 6-match winner → jackpot rolls over (full pot, unchanged).
    - Jackpot grows: each ticket sold adds TICKET_PRICE to the pot.
    - Draw time    → configurable UTC hour (default 20:00 UTC).
    - Jackpot seed → JACKPOT_SEED on first draw, rolls over fully each miss.
"""
import asyncio
import random
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from . import Game, GameSession
from ..db import get_db

PICK_MIN          = 1
PICK_MAX          = 49
PICK_COUNT        = 6             # numbers per ticket
JACKPOT_SEED      = 1000          # starting jackpot chips
TICKET_PRICE      = 50            # chips added to jackpot per ticket sold
PRIZE_MATCH3      = TICKET_PRICE  # match 3 → get ticket cost back
PRIZE_MATCH4      = 300           # match 4 → fixed prize
PRIZE_MATCH5      = 800           # match 5 → fixed prize
# match 6 → jackpot (split if tied)
DEFAULT_DRAW_HOUR = 20            # UTC hour for daily draw (20:00 UTC)
CMD_COOLDOWN_SECS = 60


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _today_str() -> str:
    """YYYY-MM-DD in UTC — used as the daily pick key."""
    return _utc_now().strftime("%Y-%m-%d")


def _seconds_until_hour(hour: int) -> float:
    """Seconds until next occurrence of `hour`:00:00 UTC."""
    from datetime import timedelta
    now    = _utc_now()
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


def _fmt_countdown(secs: float) -> str:
    secs = int(secs)
    h, rem = divmod(secs, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    return f"{m}m {s}s"


def _fmt_picks(numbers: List[int]) -> str:
    """Return sorted numbers as a bold space-separated string."""
    return " ".join(f"\x02{n}\x02" for n in sorted(numbers))


def _count_matches(ticket: Set[int], winning: Set[int]) -> int:
    return len(ticket & winning)


class LotteryGame(Game):
    name    = "lottery"
    version = "0.3.0"
    scopes  = {"channel"}

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS lottery_settings (
            channel    TEXT    PRIMARY KEY,
            draw_hour  INTEGER DEFAULT 20,
            jackpot    INTEGER DEFAULT 1000,
            last_draw  TEXT    DEFAULT NULL,
            updated_at INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS lottery_picks (
            channel    TEXT    NOT NULL,
            nick       TEXT    NOT NULL,
            picks      TEXT    NOT NULL,
            pick_date  TEXT    NOT NULL,
            updated_at INTEGER DEFAULT (strftime('%s','now')),
            PRIMARY KEY (channel, nick, pick_date)
        )
        """,
        # picks stored as comma-separated integers e.g. "7,14,21,28,35,42"
        """
        CREATE TABLE IF NOT EXISTS lottery_winners (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            channel      TEXT    NOT NULL,
            nick         TEXT    NOT NULL,
            winning_nums TEXT    NOT NULL,
            matched      INTEGER NOT NULL,
            prize_won    INTEGER NOT NULL,
            draw_date    TEXT    NOT NULL,
            won_at       INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
    ]
    _UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)
    _cmd_cooldowns: Dict[str, Dict[str, float]] = {}

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def load(self):
        await super().load()
        for sql in self.TABLE_SQL:
            async with get_db(self.core.db_path) as db:
                await db.execute(sql)
                await db.commit()
        self.log.info(f"Game {self.name} {self.version} loaded")

    async def unload(self):
        # Tables preserved — history and jackpot survive reloads
        await super().unload()
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession, restore: bool = False):
        chan = session.target
        cfg  = await self._load_settings(chan)
        session.data["cfg"]        = cfg
        session.data["draw_fired"] = False   # guard: only one draw per UTC day
        await super().start_session(session)
        jackpot   = cfg["jackpot"]
        draw_hour = cfg["draw_hour"]
        secs      = _seconds_until_hour(draw_hour)
        if not restore:
            await self.say(chan,
                f"\x02[Lottery]\x02 Daily 6/49 lottery active! "
                f"Pick {PICK_COUNT} numbers (1-{PICK_MAX}) with "
                f"\x02!lotto n1 n2 n3 n4 n5 n6\x02. "
                f"Draw at \x02{draw_hour:02d}:00 UTC\x02 "
                f"(in {_fmt_countdown(secs)}). "
                f"Current jackpot: \x02${jackpot}\x02."
            )

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.say(session.target, "[Lottery] Lottery deactivated.")
        await super().stop_session(key)

    # ── Tick / Draw ───────────────────────────────────────────────────────────

    async def on_tick(self):
        """Check every active session — fire draw if we've hit the draw hour."""
        for session in list(self.sessions.values()):
            if session.state != "running":
                continue
            cfg       = session.data.get("cfg", {})
            draw_hour = cfg.get("draw_hour", DEFAULT_DRAW_HOUR)
            today     = _today_str()
            now_hour  = _utc_now().hour

            # Already drew today
            if cfg.get("last_draw") == today:
                session.data["draw_fired"] = False   # reset for tomorrow
                continue

            # Not yet draw time
            if now_hour < draw_hour:
                session.data["draw_fired"] = False
                continue

            # Guard: fire only once per day even if tick runs multiple times
            if session.data.get("draw_fired"):
                continue

            session.data["draw_fired"] = True
            await self._do_draw(session, today)

    async def _do_draw(self, session: GameSession, draw_date: str):
        chan    = session.target
        cfg     = session.data["cfg"]
        jackpot = cfg["jackpot"]

        # Fetch all picks for today on this channel
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, picks FROM lottery_picks "
                "WHERE channel=? AND pick_date=?",
                (chan, draw_date),
            ) as cur:
                rows = await cur.fetchall()

        total_tickets = len(rows)

        # Draw 6 unique winning numbers
        winning_nums: List[int] = sorted(
            random.sample(range(PICK_MIN, PICK_MAX + 1), PICK_COUNT)
        )
        winning_set = set(winning_nums)

        await self.say(chan,
            f"\x02[Lottery]\x02 🎰 Daily 6/49 draw! "
            f"{total_tickets} ticket(s) entered. "
            f"Winning numbers: {_fmt_picks(winning_nums)}"
        )

        # Tally results per tier
        # tier buckets: {matched: [(nick, ticket_set)]}
        tier_winners: Dict[int, List[str]] = {3: [], 4: [], 5: [], 6: []}
        winning_str = ",".join(str(n) for n in winning_nums)

        for row in rows:
            ticket_set = set(int(x) for x in row["picks"].split(","))
            matched    = _count_matches(ticket_set, winning_set)
            if matched >= 3:
                tier_winners[matched].append(row["nick"])

        # ── Announce tier 3/4/5 winners ──────────────────────────────────────
        for matched, prize in ((3, PRIZE_MATCH3), (4, PRIZE_MATCH4), (5, PRIZE_MATCH5)):
            nicks = tier_winners[matched]
            if not nicks:
                continue
            label = f"match-{matched}"
            await self.say(chan,
                f"  \x02{label}\x02 ({len(nicks)} winner{'s' if len(nicks) != 1 else ''}): "
                f"{', '.join(nicks)} each win \x02${prize}\x02!"
            )
            for nick in nicks:
                await self._record_win(chan, nick, winning_str, matched, prize, draw_date)

        # ── Jackpot (match 6) ─────────────────────────────────────────────────
        jackpot_winners = tier_winners[6]

        if jackpot_winners:
            share = jackpot // len(jackpot_winners)
            await self.say(chan,
                f"\x02\x0307🎉 JACKPOT WINNER{'S' if len(jackpot_winners) > 1 else ''}!\x03\x02 "
                f"{', '.join(jackpot_winners)} matched all 6! "
                f"Each wins \x02${share}\x02 chips!"
            )
            for nick in jackpot_winners:
                await self._record_win(chan, nick, winning_str, 6, share, draw_date)

            new_jackpot = JACKPOT_SEED   # reset after jackpot is won
        else:
            # No 6-match — full pot rolls over unchanged
            new_jackpot = jackpot
            await self.say(chan,
                f"  No jackpot winner today. "
                f"Jackpot rolls over! Pot remains \x02${jackpot}\x02."
            )

        if not any(tier_winners[m] for m in (3, 4, 5, 6)):
            await self.say(chan, "  No winners today. Better luck tomorrow!")

        # Persist updated jackpot + last_draw date
        cfg["jackpot"]   = new_jackpot
        cfg["last_draw"] = draw_date
        await self._save_settings(chan, cfg)

        await self.say(chan,
            f"[Lottery] Next draw at \x02{cfg['draw_hour']:02d}:00 UTC\x02 tomorrow. "
            f"Jackpot: \x02${new_jackpot}\x02. "
            f"Pick with \x02!lotto n1 n2 n3 n4 n5 n6\x02."
        )

    # ── Commands ──────────────────────────────────────────────────────────────

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return
        cmd  = parts[0].lower()
        cfg  = session.data["cfg"]
        chan = session.target

        # ── !lotto [n1 n2 n3 n4 n5 n6] ───────────────────────────────────────
        if cmd == "!lotto":
            today = _today_str()

            # No argument → show current picks + countdown
            if len(parts) == 1:
                picks = await self._get_picks(chan, nick, today)
                secs  = _seconds_until_hour(cfg["draw_hour"])
                if picks:
                    await self.say(chan,
                        f"[Lottery] \x02{nick}\x02 has picked "
                        f"{_fmt_picks(picks)} for today. "
                        f"Draw in {_fmt_countdown(secs)}. "
                        f"Jackpot: \x02${cfg['jackpot']}\x02."
                    )
                else:
                    await self.say(chan,
                        f"[Lottery] \x02{nick}\x02 hasn't picked yet today! "
                        f"Type \x02!lotto n1 n2 n3 n4 n5 n6\x02 "
                        f"({PICK_COUNT} unique numbers, {PICK_MIN}-{PICK_MAX}). "
                        f"Draw in {_fmt_countdown(secs)}."
                    )
                return

            # Parse 6 numbers
            raw = parts[1:]
            if len(raw) != PICK_COUNT:
                return await self.notice(nick,
                    f"Pick exactly {PICK_COUNT} numbers. "
                    f"Usage: !lotto n1 n2 n3 n4 n5 n6"
                )

            try:
                numbers = [int(x) for x in raw]
            except ValueError:
                return await self.notice(nick,
                    f"All picks must be integers between {PICK_MIN} and {PICK_MAX}."
                )

            # Range check
            if not all(PICK_MIN <= n <= PICK_MAX for n in numbers):
                return await self.notice(nick,
                    f"All numbers must be between {PICK_MIN} and {PICK_MAX}."
                )

            # Duplicate check
            if len(set(numbers)) != PICK_COUNT:
                return await self.notice(nick, "All 6 numbers must be unique.")

            # Already drew today? Reject new picks until tomorrow
            if cfg.get("last_draw") == today:
                secs = _seconds_until_hour(cfg["draw_hour"])
                return await self.notice(nick,
                    f"Today's draw is done! Next draw in {_fmt_countdown(secs)}."
                )

            # One entry per day
            existing = await self._get_picks(chan, nick, today)
            if existing:
                return await self.notice(nick,
                    f"You already entered {_fmt_picks(existing)} today. "
                    "One ticket per day — good luck!"
                )

            # Save pick and add ticket price to jackpot
            await self._save_picks(chan, nick, numbers, today)
            cfg["jackpot"] += TICKET_PRICE
            secs = _seconds_until_hour(cfg["draw_hour"])
            await self.say(chan,
                f"[Lottery] \x02{nick}\x02 enters {_fmt_picks(numbers)}. "
                f"Draw in {_fmt_countdown(secs)}. "
                f"Jackpot: \x02${cfg['jackpot']}\x02. Good luck! 🍀"
            )

        # ── !lottojackpot ─────────────────────────────────────────────────────
        elif cmd == "!lottojackpot":
            secs  = _seconds_until_hour(cfg["draw_hour"])
            today = _today_str()
            async with get_db(self.core.db_path) as db:
                async with db.execute(
                    "SELECT COUNT(*) AS cnt FROM lottery_picks "
                    "WHERE channel=? AND pick_date=?",
                    (chan, today),
                ) as cur:
                    row = await cur.fetchone()
            tickets = row["cnt"] if row else 0
            await self.say(chan,
                f"[Lottery] Jackpot: \x02${cfg['jackpot']}\x02  |  "
                f"Tickets today: \x02{tickets}\x02  |  "
                f"Draw: \x02{cfg['draw_hour']:02d}:00 UTC\x02 "
                f"(in {_fmt_countdown(secs)})"
            )

        # ── !lottotop ─────────────────────────────────────────────────────────
        elif cmd == "!lottotop":
            if not self._on_cooldown(chan, "lottotop"):
                await self._show_top(chan)

        # ── !lottohelp ────────────────────────────────────────────────────────
        elif cmd == "!lottohelp":
            if not self._on_cooldown(chan, "lottohelp"):
                await self._show_help(chan, cfg)

        # ── !lottostop ────────────────────────────────────────────────────────
        elif cmd == "!lottostop":
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only a chan-op can stop the lottery.")
            await self.stop_session(session.key)

    # ── DB helpers ────────────────────────────────────────────────────────────

    async def _load_settings(self, channel: str) -> dict:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM lottery_settings WHERE channel=?", (channel,)
            ) as cur:
                row = await cur.fetchone()
        if row:
            return {
                "draw_hour": row["draw_hour"],
                "jackpot":   row["jackpot"],
                "last_draw": row["last_draw"],
            }
        # Insert defaults for this channel
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT OR IGNORE INTO lottery_settings(channel) VALUES(?)",
                (channel,),
            )
            await db.commit()
        return {
            "draw_hour": DEFAULT_DRAW_HOUR,
            "jackpot":   JACKPOT_SEED,
            "last_draw": None,
        }

    async def _save_settings(self, channel: str, cfg: dict):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO lottery_settings(channel, draw_hour, jackpot, last_draw) "
                "VALUES(?,?,?,?) "
                "ON CONFLICT(channel) DO UPDATE SET "
                "draw_hour=excluded.draw_hour, "
                "jackpot=excluded.jackpot, "
                "last_draw=excluded.last_draw, "
                "updated_at=strftime('%s','now')",
                (channel, cfg["draw_hour"], cfg["jackpot"], cfg["last_draw"]),
            )
            await db.commit()

    async def _get_picks(self, channel: str, nick: str, date: str) -> Optional[List[int]]:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT picks FROM lottery_picks "
                "WHERE channel=? AND nick=? AND pick_date=?",
                (channel, nick, date),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        return [int(x) for x in row["picks"].split(",")]

    async def _save_picks(self, channel: str, nick: str, numbers: List[int], date: str):
        picks_str = ",".join(str(n) for n in sorted(numbers))
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO lottery_picks(channel, nick, picks, pick_date) "
                "VALUES(?,?,?,?) "
                "ON CONFLICT(channel, nick, pick_date) DO UPDATE SET "
                "picks=excluded.picks, "
                "updated_at=strftime('%s','now')",
                (channel, nick, picks_str, date),
            )
            # Ticket price added to jackpot in DB
            await db.execute(
                "UPDATE lottery_settings SET jackpot = jackpot + ? "
                "WHERE channel=?",
                (TICKET_PRICE, channel),
            )
            await db.commit()

    async def _record_win(
        self,
        channel: str,
        nick: str,
        winning_nums: str,
        matched: int,
        prize: int,
        date: str,
    ):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO lottery_winners"
                "(channel, nick, winning_nums, matched, prize_won, draw_date) "
                "VALUES(?,?,?,?,?,?)",
                (channel, nick, winning_nums, matched, prize, date),
            )
            await db.commit()

    # ── Display helpers ───────────────────────────────────────────────────────

    async def _show_top(self, chan: str):
        self._set_cooldown(chan, "lottotop")
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, SUM(prize_won) AS total, COUNT(*) AS wins "
                "FROM lottery_winners WHERE channel=? "
                "GROUP BY nick ORDER BY total DESC LIMIT 5",
                (chan,),
            ) as cur:
                rows = await cur.fetchall()
        if not rows:
            return await self.say(chan, "[Lottery] No winners yet. Be the first!")
        board = "  ".join(
            f"{i + 1}. {r['nick']} ${r['total']} "
            f"({r['wins']} win{'s' if r['wins'] != 1 else ''})"
            for i, r in enumerate(rows)
        )
        await self.say(chan, f"[Lottery] All-time winners: {board}")

    async def _show_help(self, chan: str, cfg: dict):
        self._set_cooldown(chan, "lottohelp")
        await self.say(chan, "\x02[Lottery 6/49]\x02 commands:")
        await self.say(chan,
            f"    !lotto n1 n2 n3 n4 n5 n6  - Pick {PICK_COUNT} unique numbers "
            f"({PICK_MIN}-{PICK_MAX}), once per day."
        )
        await self.say(chan, "    !lotto                    - Show your current picks + countdown.")
        await self.say(chan, "    !lottojackpot             - Show jackpot, ticket count, and draw time.")
        await self.say(chan, "    !lottotop                 - All-time top winners.")
        await self.say(chan, "    !lottohelp                - This help text.")
        await self.say(chan, "    !lottostop                - (op) Deactivate lottery.")
        await self.say(chan, "\x02Prize tiers:\x02")
        await self.say(chan, f"    Match 3 → \x02${PRIZE_MATCH3}\x02  (ticket refund)")
        await self.say(chan, f"    Match 4 → \x02${PRIZE_MATCH4}\x02")
        await self.say(chan, f"    Match 5 → \x02${PRIZE_MATCH5}\x02")
        await self.say(chan,
            f"    Match 6 → \x02Jackpot\x02 (currently ${cfg['jackpot']}, "
            "split if tied)"
        )
        await self.say(chan,
            f"    Ticket cost: ${TICKET_PRICE} (added to jackpot). "
            f"Draw: daily at {cfg['draw_hour']:02d}:00 UTC."
        )

    # ── Util ──────────────────────────────────────────────────────────────────

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