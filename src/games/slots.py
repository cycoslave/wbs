# src/games/slots.py
"""
WBS Game: slots.py
version: 0.1.0
by: cyco
Description: IRC slot machine. Instant, no turns.
             !slot <bet> spins 3 reels and pays out immediately.
             Shares a chip wallet with Blackjack (slots_cash table mirrors
             blackjack_cash structure so ops can choose to link them).

Flow:
  Partyline: .gstart slots channel #chan  → makes machine available
  In-channel:
    !slot [bet]         - Spin! Default bet if omitted.
    !slotcash [nick]    - Check chip balance.
    !slottop            - Top 5 by chip count.
    !slothelp           - Show commands.
    !slots stop         - Chan-op ends the game.
"""
import asyncio
import time
from typing import Dict

from . import Game, GameSession
from ..db import get_db

DEFAULT_STARTING_CASH = 1500
DEFAULT_MIN_BET       = 5
DEFAULT_MAX_BET       = 500
DEFAULT_DEFAULT_BET   = 25
CMD_COOLDOWN_SECS     = 120
SPIN_COOLDOWN_SECS    = 3
SYMBOLS = [
    ("🍒", 30),   # Cherry    — most common
    ("🍋", 25),   # Lemon
    ("🍊", 20),   # Orange
    ("🍇", 15),   # Grapes
    ("🔔", 10),   # Bell
    ("⭐", 6),    # Star
    ("💎", 3),    # Diamond
    ("7️⃣",  1),   # Seven     — rarest
]
SYMBOL_NAMES    = [s[0] for s in SYMBOLS]
SYMBOL_WEIGHTS  = [s[1] for s in SYMBOLS]
PAYTABLE_3OAK: Dict[str, float] = {
    "🍒": 2.0,    # 2× bet
    "🍋": 2.5,
    "🍊": 3.0,
    "🍇": 4.0,
    "🔔": 6.0,
    "⭐": 10.0,
    "💎": 25.0,
    "7️⃣": 50.0,   # jackpot
}
PAYTABLE_2OAK_PUSH = {"🍒", "🍋"}  # Any two matching symbols (any combo) → return bet (push)
FRUIT_SYMBOLS = {"🍒", "🍋", "🍊", "🍇"}    # Mixed win: all 3 different fruit (cherry/lemon/orange/grape) → small win

def _spin() -> list[str]:
    """Draw one symbol per reel, weighted."""
    import random
    return random.choices(SYMBOL_NAMES, weights=SYMBOL_WEIGHTS, k=3)

def _evaluate(reels: list[str], bet: int) -> tuple[int, str]:
    """
    Return (delta, label).
    delta > 0 = win, delta < 0 = loss, delta == 0 = push.
    """
    a, b, c = reels

    # 3-of-a-kind
    if a == b == c:
        mult  = PAYTABLE_3OAK.get(a, 2.0)
        delta = int(bet * mult)
        if a == "7️⃣":
            label = f"\x02\x0307JACKPOT! 7 7 7\x03\x02  +${delta}"
        elif a == "💎":
            label = f"\x02DIAMOND TRIPLE!\x02  +${delta}"
        else:
            label = f"THREE {a}!  +${delta}"
        return delta, label

    # Two-of-a-kind consolation (cherry or lemon only)
    counts = {s: reels.count(s) for s in set(reels)}
    for sym, cnt in counts.items():
        if cnt == 2 and sym in PAYTABLE_2OAK_PUSH:
            return 0, f"Two {sym}  — push."

    # All three are different fruit → small win (1.5×)
    if set(reels) <= FRUIT_SYMBOLS and len(set(reels)) == 3:
        delta = int(bet * 1.5)
        return delta, f"Fruit mix!  +${delta}"

    # Loss
    return -bet, f"-${bet}"

class SlotsGame(Game):
    name    = "slots"
    version = "0.1.0"
    scopes  = {"channel"}

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS slots_settings (
            channel       TEXT    PRIMARY KEY,
            starting_cash INTEGER DEFAULT 1500,
            min_bet       INTEGER DEFAULT 5,
            max_bet       INTEGER DEFAULT 500,
            default_bet   INTEGER DEFAULT 25,
            updated_at    INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS slots_cash (
            nick       TEXT    PRIMARY KEY,
            cash       INTEGER NOT NULL DEFAULT 1500,
            updated_at INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
    ]
    _UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)
    _cmd_cooldowns:  Dict[str, Dict[str, float]] = {}   # chan → cmd → last_used
    _spin_cooldowns: Dict[str, float]            = {}   # nick.lower() → last_spin

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
        # Tables preserved — cash survives reloads
        await super().unload()
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession):
        chan = session.target
        session.data["cfg"] = await self._load_settings(chan)
        await super().start_session(session)
        cfg = session.data["cfg"]
        await self.say(chan,
            f"\x02[Slots]\x02 Machine is live! "
            f"Type \x02!slot\x02 to spin "
            f"(default bet: ${cfg['default_bet']}, "
            f"min: ${cfg['min_bet']}, max: ${cfg['max_bet']})."
        )

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.say(session.target, "[Slots] Machine powered down.")
        await super().stop_session(key)

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return
        cmd  = parts[0].lower()
        cfg  = session.data["cfg"]
        chan = session.target

        # ── !slot [bet] ───────────────────────────────────────────────────────
        if cmd == "!slot":
            # Per-nick spin cooldown (anti-spam)
            nkey = nick.lower()
            now  = time.monotonic()
            last = self._spin_cooldowns.get(nkey, 0)
            if now - last < SPIN_COOLDOWN_SECS:
                remaining = int(SPIN_COOLDOWN_SECS - (now - last)) + 1
                return await self.notice(nick, f"Slow down! Wait {remaining}s before spinning again.")
            self._spin_cooldowns[nkey] = now

            # Parse bet
            if len(parts) > 1:
                try:
                    bet = int(parts[1])
                except ValueError:
                    return await self.notice(nick, "Usage: !slot [bet amount]")
            else:
                bet = cfg["default_bet"]

            if bet < cfg["min_bet"]:
                return await self.notice(nick, f"Minimum bet is ${cfg['min_bet']}.")
            if bet > cfg["max_bet"]:
                return await self.notice(nick, f"Maximum bet is ${cfg['max_bet']}.")

            # Load wallet
            cash = await self._load_cash(nick, cfg["starting_cash"])
            if cash == 0:
                cash = cfg["starting_cash"] // 2
                await self._save_cash(nick, cash)
                await self.notice(nick, f"You were broke — here's a ${cash} top-up to get back in.")

            if bet > cash:
                return await self.notice(nick, f"Not enough chips! You have ${cash}.")

            # Spin
            reels = _spin()
            delta, label = _evaluate(reels, bet)
            new_cash = max(0, cash + delta)
            await self._save_cash(nick, new_cash)

            reel_str = " | ".join(reels)
            await self.say(chan,
                f"\x02{nick}\x02 spins ${bet} → [ {reel_str} ]  {label}  "
                f"(chips: ${new_cash})"
            )

            # Jackpot fanfare
            if reels[0] == reels[1] == reels[2] == "7️⃣":
                await self.say(chan,
                    f"\x02\x0307🎉 JACKPOT! {nick} hit the 7s for ${delta}! 🎉\x03\x02"
                )

        # ── !slotcash [nick] ──────────────────────────────────────────────────
        elif cmd == "!slotcash":
            target = parts[1] if len(parts) > 1 else nick
            cash   = await self._load_cash(target, cfg["starting_cash"])
            await self.say(chan, f"[Slots] {target} has \x02${cash}\x02 in chips.")

        # ── !slottop ──────────────────────────────────────────────────────────
        elif cmd == "!slottop":
            if not self._on_cooldown(chan, "slottop"):
                await self._show_top(chan)

        # ── !slothelp ─────────────────────────────────────────────────────────
        elif cmd == "!slothelp":
            if not self._on_cooldown(chan, "slothelp"):
                await self._show_help(chan, cfg)

        # ── !slots stop ───────────────────────────────────────────────────────
        elif cmd == "!slots" and len(parts) > 1 and parts[1].lower() == "stop":
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only a chan-op can stop the machine.")
            await self.stop_session(session.key)

    async def _show_top(self, chan: str):
        self._set_cooldown(chan, "slottop")
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, cash FROM slots_cash ORDER BY cash DESC LIMIT 5"
            ) as cur:
                rows = await cur.fetchall()
        if not rows:
            return await self.say(chan, "[Slots] No records yet.")
        board = "  ".join(
            f"{i + 1}. {r['nick']} ${r['cash']}" for i, r in enumerate(rows)
        )
        await self.say(chan, f"[Slots] Top chips: {board}")

    async def _show_help(self, chan: str, cfg: dict):
        self._set_cooldown(chan, "slothelp")
        await self.say(chan, "[Slots] commands:")
        await self.say(chan, f"    !slot [bet]         - Spin! (default: ${cfg['default_bet']}, min: ${cfg['min_bet']}, max: ${cfg['max_bet']})")
        await self.say(chan,  "    !slotcash [nick]    - Check chip balance.")
        await self.say(chan,  "    !slottop            - Top 5 chip leaders.")
        await self.say(chan,  "    !slothelp           - This help text.")
        await self.say(chan,  "    !slots stop         - (op) Shut down the machine.")
        await self.say(chan,  "[Slots] Pay table: 🍒×3=2× | 🍋×3=2.5× | 🍊×3=3× | 🍇×3=4× | 🔔×3=6× | ⭐×3=10× | 💎×3=25× | 7️⃣×3=50× JACKPOT")
        await self.say(chan,  "        Fruit mix (🍒🍋🍊🍇 all different) = 1.5×  |  Two 🍒/🍋 = push")

    async def _load_settings(self, channel: str) -> dict:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM slots_settings WHERE channel=?", (channel,)
            ) as cur:
                row = await cur.fetchone()
        if row:
            return {
                "starting_cash": row["starting_cash"],
                "min_bet":       row["min_bet"],
                "max_bet":       row["max_bet"],
                "default_bet":   row["default_bet"],
            }
        return {
            "starting_cash": DEFAULT_STARTING_CASH,
            "min_bet":       DEFAULT_MIN_BET,
            "max_bet":       DEFAULT_MAX_BET,
            "default_bet":   DEFAULT_DEFAULT_BET,
        }

    async def _load_cash(self, nick: str, starting_cash: int) -> int:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT cash FROM slots_cash WHERE nick=?", (nick,)
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                await db.execute(
                    "INSERT INTO slots_cash(nick, cash) VALUES(?,?)",
                    (nick, starting_cash),
                )
                await db.commit()
        return row["cash"] if row else starting_cash

    async def _save_cash(self, nick: str, amount: int):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO slots_cash(nick, cash) VALUES(?,?) "
                "ON CONFLICT(nick) DO UPDATE SET cash=excluded.cash, "
                "updated_at=strftime('%s','now')",
                (nick, amount),
            )
            await db.commit()

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