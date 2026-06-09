# src/games/lottery.py
"""
WBS Game: lottery.py
version: 0.1.0
by: cyco
Description: Daily IRC lottery. Players pick a number once per day.
             Bot draws at a configured UTC hour. Jackpot rolls over if no winner.
             Uses on_tick() (called by GameManager.tick()) for the daily draw.

Flow:
  Partyline: .gstart lottery channel #chan  → activates daily lottery on channel
  In-channel:
    !lotto <1-49>           - Pick your number (once per calendar day UTC).
    !lotto                  - Show your current pick + time until draw.
    !lottojackpot                - Show current jackpot amount.
    !lottotop               - Top 5 all-time winners by total winnings.
    !lottohelp              - Show commands.
    !lottostop           - Chan-op ends the lottery.

Draw mechanics:
    - Winning number drawn: random 1-49.
    - Exact match → wins the full jackpot + PRIZE_BASE bonus.
    - No winner    → jackpot rolls over (adds ROLLOVER_ADD per day).
    - Draw time    → configurable UTC hour (default 20:00 UTC).
    - Jackpot seed → JACKPOT_SEED on first draw, rolls over each miss.
"""
import asyncio
import random
import time
from datetime import datetime, timezone
from typing import Dict, Optional

from . import Game, GameSession
from ..db import get_db

PICK_MIN        = 1
PICK_MAX        = 49
JACKPOT_SEED    = 1000        # starting jackpot chips
ROLLOVER_ADD    = 500         # chips added to jackpot each no-winner day
PRIZE_BASE      = 200         # bonus chips on top of jackpot for winner
DEFAULT_DRAW_HOUR = 20        # UTC hour for daily draw (20:00 UTC)
CMD_COOLDOWN_SECS = 60

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _today_str() -> str:
    """YYYY-MM-DD in UTC — used as the daily pick key."""
    return _utc_now().strftime("%Y-%m-%d")

def _seconds_until_hour(hour: int) -> float:
    """Seconds until next occurrence of `hour`:00:00 UTC."""
    now = _utc_now()
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if target <= now:
        # already past today's draw time — next one is tomorrow
        from datetime import timedelta
        target += timedelta(days=1)
    return (target - now).total_seconds()

def _fmt_countdown(secs: float) -> str:
    secs = int(secs)
    h, rem = divmod(secs, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    return f"{m}m {s}s"

class LotteryGame(Game):
    name    = "lottery"
    version = "0.1.0"
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
            pick       INTEGER NOT NULL,
            pick_date  TEXT    NOT NULL,
            updated_at INTEGER DEFAULT (strftime('%s','now')),
            PRIMARY KEY (channel, nick, pick_date)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS lottery_winners (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            channel      TEXT    NOT NULL,
            nick         TEXT    NOT NULL,
            winning_num  INTEGER NOT NULL,
            jackpot_won  INTEGER NOT NULL,
            draw_date    TEXT    NOT NULL,
            won_at       INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
    ]
    _UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)
    _cmd_cooldowns: Dict[str, Dict[str, float]] = {}

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

    async def start_session(self, session: GameSession):
        chan = session.target
        cfg  = await self._load_settings(chan)
        session.data["cfg"]        = cfg
        session.data["draw_fired"] = False   # guard: only one draw per UTC day
        await super().start_session(session)
        jackpot   = cfg["jackpot"]
        draw_hour = cfg["draw_hour"]
        secs      = _seconds_until_hour(draw_hour)
        await self.say(chan,
            f"\x02[Lottery]\x02 Daily lottery active! "
            f"Pick a number 1-{PICK_MAX} with \x02!lotto <number>\x02. "
            f"Draw at \x02{draw_hour:02d}:00 UTC\x02 "
            f"(in {_fmt_countdown(secs)}). "
            f"Current jackpot: \x02${jackpot}\x02."
        )

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.say(session.target, "[Lottery] Lottery deactivated.")
        await super().stop_session(key)

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
        chan = session.target
        cfg  = session.data["cfg"]

        # Fetch all picks for today on this channel
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, pick FROM lottery_picks "
                "WHERE channel=? AND pick_date=?",
                (chan, draw_date),
            ) as cur:
                rows = await cur.fetchall()

        total_picks = len(rows)
        winning_num = random.randint(PICK_MIN, PICK_MAX)
        jackpot     = cfg["jackpot"]

        await self.say(chan,
            f"\x02[Lottery]\x02 🎰 Today's draw! "
            f"{total_picks} ticket(s) sold. "
            f"Winning number: \x02{winning_num}\x02!"
        )

        winners = [r["nick"] for r in rows if r["pick"] == winning_num]

        if winners:
            # Split jackpot evenly if multiple winners (extremely rare but possible)
            share    = jackpot // len(winners)
            total_win = share + PRIZE_BASE

            await self.say(chan,
                f"\x02\x0307🎉 WINNER{'S' if len(winners) > 1 else ''}!\x03\x02 "
                f"{', '.join(winners)} picked \x02{winning_num}\x02! "
                f"Each wins \x02${total_win}\x02 chips!"
            )

            for nick in winners:
                await self._record_win(chan, nick, winning_num, total_win, draw_date)

            # Reset jackpot to seed
            new_jackpot = JACKPOT_SEED
        else:
            await self.say(chan,
                f"  No winner today. Jackpot rolls over! "
                f"New jackpot: \x02${jackpot + ROLLOVER_ADD}\x02."
            )
            new_jackpot = jackpot + ROLLOVER_ADD

        # Persist updated jackpot + last_draw date
        cfg["jackpot"]   = new_jackpot
        cfg["last_draw"] = draw_date
        await self._save_settings(chan, cfg)

        await self.say(chan,
            f"[Lottery] Next draw at \x02{cfg['draw_hour']:02d}:00 UTC\x02 tomorrow. "
            f"Jackpot: \x02${new_jackpot}\x02. Pick with \x02!lotto <1-{PICK_MAX}>\x02."
        )

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return
        cmd  = parts[0].lower()
        cfg  = session.data["cfg"]
        chan = session.target

        # ── !lotto [number] ───────────────────────────────────────────────────
        if cmd == "!lotto":
            today = _today_str()

            # No argument → show current pick + countdown
            if len(parts) == 1:
                pick = await self._get_pick(chan, nick, today)
                secs = _seconds_until_hour(cfg["draw_hour"])
                if pick:
                    await self.say(chan,
                        f"[Lottery] \x02{nick}\x02 has picked \x02{pick}\x02 for today. "
                        f"Draw in {_fmt_countdown(secs)}. Jackpot: \x02${cfg['jackpot']}\x02."
                    )
                else:
                    await self.say(chan,
                        f"[Lottery] \x02{nick}\x02 hasn't picked yet today! "
                        f"Type \x02!lotto <1-{PICK_MAX}>\x02. "
                        f"Draw in {_fmt_countdown(secs)}."
                    )
                return

            # Parse number
            try:
                number = int(parts[1])
            except ValueError:
                return await self.notice(nick, f"Usage: !lotto <{PICK_MIN}-{PICK_MAX}>")

            if not (PICK_MIN <= number <= PICK_MAX):
                return await self.notice(nick, f"Pick a number between {PICK_MIN} and {PICK_MAX}.")

            # Already drew today? Reject new picks until tomorrow
            if cfg.get("last_draw") == today:
                secs = _seconds_until_hour(cfg["draw_hour"])
                return await self.notice(nick,
                    f"Today's draw is done! Next draw in {_fmt_countdown(secs)}."
                )

            # One pick per day — check if already picked
            existing = await self._get_pick(chan, nick, today)
            if existing:
                return await self.notice(nick,
                    f"You already picked \x02{existing}\x02 today. "
                    "One pick per day — good luck!"
                )

            # Save pick
            await self._save_pick(chan, nick, number, today)
            secs = _seconds_until_hour(cfg["draw_hour"])
            await self.say(chan,
                f"[Lottery] \x02{nick}\x02 picks \x02{number}\x02. "
                f"Draw in {_fmt_countdown(secs)}. Jackpot: \x02${cfg['jackpot']}\x02. Good luck! 🍀"
            )

        # ── !lottojackpot ──────────────────────────────────────────────────────────
        elif cmd == "!lottojackpot":
            secs = _seconds_until_hour(cfg["draw_hour"])
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

        # ── !lottostop ─────────────────────────────────────────────────────
        elif cmd == "!lottostop":
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only a chan-op can stop the lottery.")
            await self.stop_session(session.key)

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

    async def _get_pick(self, channel: str, nick: str, date: str) -> Optional[int]:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT pick FROM lottery_picks "
                "WHERE channel=? AND nick=? AND pick_date=?",
                (channel, nick, date),
            ) as cur:
                row = await cur.fetchone()
        return row["pick"] if row else None

    async def _save_pick(self, channel: str, nick: str, number: int, date: str):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO lottery_picks(channel, nick, pick, pick_date) "
                "VALUES(?,?,?,?) "
                "ON CONFLICT(channel, nick, pick_date) DO UPDATE SET "
                "pick=excluded.pick, "
                "updated_at=strftime('%s','now')",
                (channel, nick, number, date),
            )
            await db.commit()

    async def _record_win(self, channel: str, nick: str, number: int, amount: int, date: str):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO lottery_winners(channel, nick, winning_num, jackpot_won, draw_date) "
                "VALUES(?,?,?,?,?)",
                (channel, nick, number, amount, date),
            )
            await db.commit()

    async def _show_top(self, chan: str):
        self._set_cooldown(chan, "lottotop")
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, SUM(jackpot_won) AS total, COUNT(*) AS wins "
                "FROM lottery_winners WHERE channel=? "
                "GROUP BY nick ORDER BY total DESC LIMIT 5",
                (chan,),
            ) as cur:
                rows = await cur.fetchall()
        if not rows:
            return await self.say(chan, "[Lottery] No winners yet. Be the first!")
        board = "  ".join(
            f"{i + 1}. {r['nick']} ${r['total']} ({r['wins']} win{'s' if r['wins'] != 1 else ''})"
            for i, r in enumerate(rows)
        )
        await self.say(chan, f"[Lottery] All-time winners: {board}")

    async def _show_help(self, chan: str, cfg: dict):
        self._set_cooldown(chan, "lottohelp")
        await self.say(chan, "\x02[Lottery]\x02 commands:")
        await self.say(chan, f"    !lotto <1-{PICK_MAX}>   - Pick your number (once per day).")
        await self.say(chan,  "    !lotto                 - Show your current pick + countdown.")
        await self.say(chan,  "    !lottojackpot          - Show jackpot, ticket count, and draw time.")
        await self.say(chan,  "    !lottotop              - All-time top winners.")
        await self.say(chan,  "    !lottohelp             - This help text.")
        await self.say(chan,  "    !lottostop             - (op) Deactivate lottery.")
        await self.say(chan,
            f"    Draw: daily at {cfg['draw_hour']:02d}:00 UTC. "
            f"Jackpot starts at ${JACKPOT_SEED}, rolls over by ${ROLLOVER_ADD}/day with no winner."
        )

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