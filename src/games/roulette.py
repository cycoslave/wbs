# src/games/roulette.py
"""
WBS Game: roulette.py
version: 0.1.0
by: cyco
Description: IRC Roulette. Fixed betting window, then the wheel spins.
             Multiple players bet simultaneously. European single-zero wheel (0-36).

Flow:
  Partyline: .gstart roulette channel #chan  → makes table available (idle)
  In-channel:
    !roulette                       - Open a betting round.
    !roulettebet <type> <amount>    - Place a bet during the window.
    !roulettecash [nick]            - Check chip balance.
    !roulettetop                    - Top 5 by chip count.
    !roulettehelp                   - Show bet types and commands.
    !roulettestop                   - Chan-op ends the game.

Bet types:
    Straight  : !roulettebet 17 100          Single number 0-36        pays 35:1
    Red/Black : !roulettebet red 50          Colour                     pays 1:1
    Odd/Even  : !roulettebet odd 50                                     pays 1:1
    High/Low  : !roulettebet high 50         19-36 / 1-18               pays 1:1
    Dozen     : !roulettebet dozen1 50       1-12 / dozen2 13-24 / dozen3 25-36  pays 2:1
    Column    : !roulettebet col1 50         cols 1/2/3 (every 3rd num) pays 2:1
    Split     : !roulettebet split 14-17 50  Two adjacent numbers       pays 17:1
    Street    : !roulettebet street 13 50    3-num row (13,14,15)       pays 11:1
    Corner    : !roulettebet corner 1 50     4-num square (1,2,4,5)     pays 8:1
"""
import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import Game, GameSession
from ..db import get_db

BETTING_SECS      = 45
BETTING_WARN_SECS = 15
CMD_COOLDOWN_SECS = 120
DEFAULT_STARTING_CASH = 1500
DEFAULT_MIN_BET       = 5
DEFAULT_MAX_BET       = 1000
DEFAULT_DEFAULT_BET   = 50
RED_NUMBERS = {1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36}
BLACK_NUMBERS = {2,4,6,8,10,11,13,15,17,20,22,24,26,28,29,31,33,35}
# 0 is neither red nor black (green)

def _spin_wheel() -> int:
    return random.randint(0, 36)

def _colour(n: int) -> str:
    if n == 0:
        return "green"
    return "red" if n in RED_NUMBERS else "black"

def _colour_irc(n: int) -> str:
    """Colour-coded mIRC string for the winning number."""
    c = _colour(n)
    code = {"red": "\x0304", "black": "\x0301", "green": "\x0303"}[c]
    return f"{code}{n}\x03"

@dataclass
class Bet:
    nick:   str
    kind:   str          # canonical bet type string
    amount: int
    params: object = None  # extra data depending on kind (number, pair, etc.)

def _resolve(bet: Bet, winner: int) -> Tuple[int, str]:
    """
    Return (delta, description).
    delta > 0 = net win (not including stake return),
    delta < 0 = loss.
    """
    k  = bet.kind
    w  = winner
    am = bet.amount

    if k == "straight":
        if w == bet.params:
            return am * 35, f"hit {w}! +${am * 35}"
        return -am, f"missed ({w})  -${am}"

    if k in ("red", "black"):
        if w == 0:
            return -am, f"zero  -${am}"
        if _colour(w) == k:
            return am, f"{k} wins ({w})  +${am}"
        return -am, f"{_colour(w)} ({w})  -${am}"

    if k in ("odd", "even"):
        if w == 0:
            return -am, f"zero  -${am}"
        hit = (w % 2 == 1) if k == "odd" else (w % 2 == 0)
        if hit:
            return am, f"{k} wins ({w})  +${am}"
        return -am, f"{'even' if k == 'odd' else 'odd'} ({w})  -${am}"

    if k in ("high", "low"):
        if w == 0:
            return -am, f"zero  -${am}"
        hit = (w >= 19) if k == "high" else (w <= 18)
        if hit:
            return am, f"{k} wins ({w})  +${am}"
        return -am, f"missed ({w})  -${am}"

    if k in ("dozen1", "dozen2", "dozen3"):
        ranges = {"dozen1": range(1, 13), "dozen2": range(13, 25), "dozen3": range(25, 37)}
        if w in ranges[k]:
            return am * 2, f"{k} wins ({w})  +${am * 2}"
        return -am, f"missed ({w})  -${am}"

    if k in ("col1", "col2", "col3"):
        col_map = {"col1": 1, "col2": 2, "col3": 3}
        if w != 0 and w % 3 == col_map[k] % 3:
            return am * 2, f"{k} wins ({w})  +${am * 2}"
        return -am, f"missed ({w})  -${am}"

    if k == "split":
        a, b = bet.params
        if w in (a, b):
            return am * 17, f"split {a}-{b} hits {w}!  +${am * 17}"
        return -am, f"missed ({w})  -${am}"

    if k == "street":
        base = bet.params   # lowest number of the row (must be 1,4,7,...34)
        if w in (base, base + 1, base + 2):
            return am * 11, f"street {base}-{base+2} hits {w}!  +${am * 11}"
        return -am, f"missed ({w})  -${am}"

    if k == "corner":
        n = bet.params   # top-left of the square
        nums = {n, n + 1, n + 3, n + 4}
        if w in nums:
            return am * 8, f"corner {n}/{n+1}/{n+3}/{n+4} hits {w}!  +${am * 8}"
        return -am, f"missed ({w})  -${am}"

    return -am, f"unknown bet  -${am}"


def _parse_bet(parts: List[str], cfg: dict) -> Tuple[Optional[Bet], Optional[str]]:
    """
    Parse   !roulettebet <type_and_params...> <amount>
    Returns (Bet, None) on success or (None, error_string) on failure.

    Grammar:
        !roulettebet <number 0-36> <amount>
        !roulettebet red|black|odd|even|high|low <amount>
        !roulettebet dozen1|dozen2|dozen3 <amount>
        !roulettebet col1|col2|col3 <amount>
        !roulettebet split <n1>-<n2> <amount>
        !roulettebet street <base> <amount>
        !roulettebet corner <n> <amount>
    """
    # parts already stripped of "!roulettebet"
    if len(parts) < 2:
        return None, "Usage: !roulettebet <type> [params] <amount>  — try !roulettehelp"

    # Amount is always the last token
    try:
        amount = int(parts[-1])
    except ValueError:
        return None, "Bet amount must be a whole number."

    if amount < cfg["min_bet"]:
        return None, f"Minimum bet is ${cfg['min_bet']}."
    if amount > cfg["max_bet"]:
        return None, f"Maximum bet is ${cfg['max_bet']}."

    kind_token = parts[0].lower()
    params_tokens = parts[1:-1]   # anything between type and amount

    try:
        num = int(kind_token)
        if 0 <= num <= 36:
            return Bet(nick="", kind="straight", amount=amount, params=num), None
        return None, "Straight bet: number must be 0-36."
    except ValueError:
        pass

    simple = {"red", "black", "odd", "even", "high", "low",
              "dozen1", "dozen2", "dozen3", "col1", "col2", "col3"}
    if kind_token in simple:
        return Bet(nick="", kind=kind_token, amount=amount), None

    if kind_token == "split":
        if not params_tokens:
            return None, "Split bet: !roulettebet split <n1>-<n2> <amount>"
        try:
            a, b = map(int, params_tokens[0].split("-"))
            if not (0 <= a <= 36 and 0 <= b <= 36 and a != b):
                raise ValueError
        except ValueError:
            return None, "Split: !roulettebet split <n1>-<n2> <amount>  e.g. !roulettebet split 14-17 50"
        return Bet(nick="", kind="split", amount=amount, params=(a, b)), None

    if kind_token == "street":
        if not params_tokens:
            return None, "Street bet: !roulettebet street <base> <amount>  (base = 1,4,7,...34)"
        try:
            base = int(params_tokens[0])
            if base < 1 or base > 34 or (base - 1) % 3 != 0:
                raise ValueError
        except ValueError:
            return None, "Street base must be 1, 4, 7, 10 ... 34."
        return Bet(nick="", kind="street", amount=amount, params=base), None

    if kind_token == "corner":
        if not params_tokens:
            return None, "Corner bet: !roulettebet corner <top-left-num> <amount>"
        try:
            n = int(params_tokens[0])
            # top-left must not be in columns 3 (3,6,9,...) and not row 12
            col = ((n - 1) % 3) + 1
            if n < 1 or n > 32 or col == 3:
                raise ValueError
        except ValueError:
            return None, "Corner: top-left number invalid (col 3 or >32 not allowed)."
        return Bet(nick="", kind="corner", amount=amount, params=n), None

    return None, f"Unknown bet type '{kind_token}'. Try !roulettehelp"

class RouletteGame(Game):
    name    = "roulette"
    version = "0.1.0"
    scopes  = {"channel"}

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS roulette_settings (
            channel       TEXT    PRIMARY KEY,
            starting_cash INTEGER DEFAULT 1500,
            min_bet       INTEGER DEFAULT 5,
            max_bet       INTEGER DEFAULT 1000,
            default_bet   INTEGER DEFAULT 50,
            updated_at    INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS roulette_cash (
            nick       TEXT    PRIMARY KEY,
            cash       INTEGER NOT NULL DEFAULT 1500,
            updated_at INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
    ]
    _UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)
    _cmd_cooldowns: Dict[str, Dict[str, float]] = {}

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
        # Tables preserved — wallets survive reloads
        await super().unload()
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession):
        """Called by .gstart — table is available, waiting for !roulette to open a round."""
        chan = session.target
        session.data["cfg"]   = await self._load_settings(chan)
        session.data["phase"] = "idle"
        session.data["bets"]  = {}   # nick.lower() -> List[Bet]
        await super().start_session(session)
        await self.say(chan,
            "\x02[Roulette]\x02 Table is open! "
            "Type \x02!roulette\x02 to start a betting round."
        )

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            if session.task and not session.task.done():
                session.task.cancel()
            await self.say(session.target, "[Roulette] Table closed.")
        await super().stop_session(key)

    async def _betting_phase(self, session: GameSession):
        """Sleep through the betting window, warn at BETTING_WARN_SECS, then spin."""
        try:
            await asyncio.sleep(BETTING_SECS - BETTING_WARN_SECS)
            # Warn if anyone has bet; quiet warning if table is empty
            if session.data["bets"]:
                await self.say(session.target,
                    f"[Roulette] \x02{BETTING_WARN_SECS}s left!\x02 "
                    "Last chance — \x02!roulettebet <type> <amount>\x02"
                )
            await asyncio.sleep(BETTING_WARN_SECS)
        except asyncio.CancelledError:
            return
        await self._spin(session)

    async def _spin(self, session: GameSession):
        chan  = session.target
        bets: Dict[str, List[Bet]] = session.data["bets"]
        cfg  = session.data["cfg"]

        # No bets placed — cancel quietly, return to idle
        if not bets:
            await self.say(chan, "[Roulette] No bets placed. Round cancelled.")
            session.data["phase"] = "idle"
            session.task          = None
            return

        session.data["phase"] = "spinning"
        await self.say(chan, "[Roulette] No more bets! The wheel is spinning... 🎡")
        await asyncio.sleep(2)

        winner = _spin_wheel()
        await self.say(chan,
            f"[Roulette] 🎯 The ball lands on \x02{_colour_irc(winner)}\x02 "
            f"({_colour(winner).upper()})!"
        )
        await asyncio.sleep(1)

        # Settle all bets
        totals: Dict[str, int] = {}   # nick -> net delta this round
        for nick_key, player_bets in bets.items():
            net = 0
            for b in player_bets:
                delta, _ = _resolve(b, winner)
                net += delta
            totals[nick_key] = net

        # Load all wallets, apply deltas, report
        await self.say(chan, "[Roulette] ── Results ──")
        for nick_key, player_bets in bets.items():
            display_nick = player_bets[0].nick   # preserve original case
            cash = await self._load_cash(display_nick, cfg["starting_cash"])
            net  = totals[nick_key]

            # Per-bet detail (only if player placed >1 bet)
            if len(player_bets) > 1:
                details = []
                for b in player_bets:
                    delta, desc = _resolve(b, winner)
                    sign = "+" if delta >= 0 else ""
                    details.append(f"{b.kind}:{sign}{delta}")
                detail_str = "  [" + "  ".join(details) + "]"
            else:
                _, desc = _resolve(player_bets[0], winner)
                detail_str = f"  [{desc}]"

            new_cash = max(0, cash + net)
            sign = "+" if net >= 0 else ""
            await self.say(chan,
                f"  \x02{display_nick}\x02:{detail_str}  "
                f"net: {sign}${net}  chips: ${new_cash}"
            )
            await self._save_cash(display_nick, new_cash)

            if new_cash == 0:
                await self.say(chan,
                    f"  \x02{display_nick}\x02 is broke! "
                    f"Next round they'll get ${cfg['starting_cash'] // 2} back."
                )

        await asyncio.sleep(3)
        session.data["bets"]  = {}
        session.data["phase"] = "finished"
        session.task          = None
        await self.say(chan,
            "[Roulette] Round over. "
            "\x02!roulette\x02 to spin again  |  "
            "\x02!roulette stop\x02 to close the table."
        )

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return
        cmd  = parts[0].lower()
        phase = session.data.get("phase", "idle")
        cfg  = session.data["cfg"]
        chan = session.target

        if cmd == "!roulettestop":
                if not self.core.nick_isop(nick, chan):
                    return await self.notice(nick, "Only a chan-op can close the table.")
                await self.stop_session(session.key)
                return

        if cmd == "!roulette":
            # Open a new betting round
            if phase in ("idle", "finished"):
                session.data["bets"]  = {}
                session.data["phase"] = "betting"
                await self.say(chan,
                    f"\x02[Roulette]\x02 Betting is open for \x02{BETTING_SECS}s\x02! "
                    f"Type \x02!roulettebet <type> <amount>\x02 to place a bet. "
                    f"(min: ${cfg['min_bet']}, max: ${cfg['max_bet']})  "
                    f"Try \x02!roulettehelp\x02 for bet types."
                )
                session.task = asyncio.create_task(self._betting_phase(session))
                return

            if phase == "betting":
                return await self.notice(nick, "Betting is already open! Place your bet with !roulettebet")

            if phase == "spinning":
                return await self.notice(nick, "Wheel is spinning — wait for results.")

        elif cmd == "!roulettebet":
            if phase != "betting":
                return await self.notice(nick,
                    "No round is open. Type \x02!roulette\x02 to start one."
                )

            bet, err = _parse_bet(parts[1:], cfg)
            if err:
                return await self.notice(nick, err)

            # Wallet check — total of all pending bets + this one
            nkey        = nick.lower()
            cash        = await self._load_cash(nick, cfg["starting_cash"])
            if cash == 0:
                cash = cfg["starting_cash"] // 2
                await self._save_cash(nick, cash)
                await self.notice(nick,
                    f"You were broke — here's ${cash} back to play with."
                )

            existing_bets = session.data["bets"].get(nkey, [])
            already_staked = sum(b.amount for b in existing_bets)
            if already_staked + bet.amount > cash:
                return await self.notice(nick,
                    f"Not enough chips! You have ${cash}, already staked ${already_staked}."
                )

            # Max bets per player per round: 5 (prevent spam)
            if len(existing_bets) >= 5:
                return await self.notice(nick, "Maximum 5 bets per round.")

            bet.nick = nick
            session.data["bets"].setdefault(nkey, []).append(bet)

            # Confirm in channel
            total_staked = already_staked + bet.amount
            await self.say(chan,
                f"  \x02{nick}\x02 bets \x02${bet.amount}\x02 on "
                f"\x02{bet.kind}{(' ' + str(bet.params)) if bet.params is not None else ''}\x02  "
                f"(total staked: ${total_staked})"
            )

        elif cmd == "!roulettecash":
            target = parts[1] if len(parts) > 1 else nick
            cash   = await self._load_cash(target, cfg["starting_cash"])
            await self.say(chan, f"[Roulette] {target} has \x02${cash}\x02 in chips.")

        elif cmd == "!roulettetop":
            if not self._on_cooldown(chan, "roulettetop"):
                await self._show_top(chan)

        elif cmd == "!roulettehelp":
            if not self._on_cooldown(chan, "roulettehelp"):
                await self._show_help(chan, cfg)

    async def _show_top(self, chan: str):
        self._set_cooldown(chan, "roulettetop")
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, cash FROM roulette_cash ORDER BY cash DESC LIMIT 5"
            ) as cur:
                rows = await cur.fetchall()
        if not rows:
            return await self.say(chan, "[Roulette] No records yet.")
        board = "  ".join(
            f"{i + 1}. {r['nick']} ${r['cash']}" for i, r in enumerate(rows)
        )
        await self.say(chan, f"[Roulette] Top chips: {board}")

    async def _show_help(self, chan: str, cfg: dict):
        self._set_cooldown(chan, "roulettehelp")
        await self.say(chan, "\x02[Roulette]\x02 commands:")
        await self.say(chan, "    !roulette                   - Open a betting round.")
        await self.say(chan, f"   !roulettebet <type> <amount> - Place a bet (min ${cfg['min_bet']}, max ${cfg['max_bet']}, up to 5/round).")
        await self.say(chan, "    !roulettecash [nick]        - Check chip balance.")
        await self.say(chan, "    !roulettetop                - Top 5 chip leaders.")
        await self.say(chan, "    !roulettestop               - (op) Close the table.")
        await self.say(chan, "\x02Bet types:\x02")
        await self.say(chan, "    !roulettebet 17 100          Straight  35:1")
        await self.say(chan, "    !roulettebet red 50          Red/Black  1:1")
        await self.say(chan, "    !roulettebet odd 50          Odd/Even   1:1")
        await self.say(chan, "    !roulettebet high 50         High(19-36)/Low(1-18)  1:1")
        await self.say(chan, "    !roulettebet dozen1 50       Dozens (1-12/13-24/25-36)  2:1")
        await self.say(chan, "    !roulettebet col1 50         Columns (col1/col2/col3)   2:1")
        await self.say(chan, "    !roulettebet split 14-17 50  Split two numbers  17:1")
        await self.say(chan, "    !roulettebet street 13 50    Street (row of 3)  11:1")
        await self.say(chan, "    !roulettebet corner 1 50     Corner (4 nums)     8:1")
        await self.say(chan, "    Zero (0) wins only straight bets on 0. All others lose.")

    async def _load_settings(self, channel: str) -> dict:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM roulette_settings WHERE channel=?", (channel,)
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
                "SELECT cash FROM roulette_cash WHERE nick=?", (nick,)
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                await db.execute(
                    "INSERT INTO roulette_cash(nick, cash) VALUES(?,?)",
                    (nick, starting_cash),
                )
                await db.commit()
        return row["cash"] if row else starting_cash

    async def _save_cash(self, nick: str, amount: int):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO roulette_cash(nick, cash) VALUES(?,?) "
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