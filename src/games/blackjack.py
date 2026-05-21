# src/games/blackjack.py
"""
WBS Game: blackjack.py 
version: 0.1.0
by: cyco
Description: Blackjack game for WBS.

Commands (in-channel):
  !blackjack          - Start a game. Opens 5-min registration window.
  !bjjoin               - Join during registration or between rounds.
  !bjstart              - Owner skips the registration countdown.
  !bjbet <amount>       - Place bet during betting phase (45s window).
  !bjhit                - Draw a card on your turn.
  !bjstand              - Hold your hand on your turn.
  !blackjack stop     - Owner or chan-op ends the game.
  !bjset <param> <v>  - Owner configures per-channel settings.
  !bjcash [nick]        - Check chip balance.
  !bjtop              - Top 5 chip leaders.
"""
import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import Game, GameSession, _db

DEFAULT_STARTING_CASH = 1500
DEFAULT_MIN_BET = 10
DEFAULT_DEFAULT_BET = 50
DEFAULT_TURN_SECS = 60
REGISTRATION_SECS = 60
REGISTRATION_WARN = 30
CMD_COOLDOWN_SECS = 300
BET_SECS = 45
SUITS = ["♠", "♥", "♦", "♣"]
RANKS = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"]

def new_deck() -> List[str]:
    return [f"{r}{s}" for s in SUITS for r in RANKS]

def card_value(card: str) -> int:
    rank = card[:-1]
    if rank in ("J", "Q", "K"):
        return 10
    if rank == "A":
        return 11
    return int(rank)

def hand_value(hand: List[str]) -> int:
    total = sum(card_value(c) for c in hand)
    aces  = sum(1 for c in hand if c[:-1] == "A")
    while total > 21 and aces:
        total -= 10
        aces  -= 1
    return total

def hand_str(hand: List[str]) -> str:
    return " ".join(hand)

@dataclass
class PlayerState:
    nick:  str
    cash:  int
    bet:   int       = 0
    hand:  List[str] = field(default_factory=list)
    stood: bool      = False
    bust:  bool      = False
    done:  bool      = False

class BlackjackGame(Game):
    name   = "blackjack"
    version = "0.1.0"
    scopes = {"channel"}

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS blackjack_settings (
            channel       TEXT    PRIMARY KEY,
            starting_cash INTEGER DEFAULT 1500,
            min_bet       INTEGER DEFAULT 10,
            default_bet   INTEGER DEFAULT 50,
            turn_secs     INTEGER DEFAULT 60,
            updated_at    INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS blackjack_cash (
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
            await db.execute("DROP TABLE IF EXISTS blackjack_settings")
            await db.commit() 
        async with _db(self.core.db_path) as db:
            await db.execute("DROP TABLE IF EXISTS blackjack_cash")
            await db.commit() 
        await super().unload() 
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession):
        chan = session.target
        session.data["cfg"]            = await self._load_settings(chan)
        session.data["players"]        = {}   # nick -> PlayerState
        session.data["deck"]           = []
        session.data["dealer"]         = []
        session.data["phase"]          = "registering"
        session.data["current_player"] = None
        await super().start_session(session)
        await self._open_registration(session)

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.say(session.target, "[Blackjack] Game over.")
        await super().stop_session(key)  # cancels task + clears session snapshot

    async def _registration_phase(self, session: GameSession):
        """Wait REGISTRATION_SECS, emit a warning at REGISTRATION_WARN seconds remaining."""
        try:
            # sleep until the warning point
            await asyncio.sleep(REGISTRATION_SECS - REGISTRATION_WARN)
            await self.say(session.target, f"[Blackjack] \x0230s left\x02 to join! Type \x02!bjjoin\x02 to get in.")
            await asyncio.sleep(REGISTRATION_WARN)
        except asyncio.CancelledError:
            return
        await self._begin_round(session)

    async def _begin_round(self, session: GameSession):
        chan    = session.target
        players = session.data["players"]
        cfg    = session.data["cfg"]

        if not players:
            await self.say(chan, "[Blackjack] No players joined. Game cancelled.")
            await self.stop_session(session.key)
            return

        session.data["phase"] = "betting"
        await self.say(chan,
            f"[Blackjack] {len(players)} player(s): {', '.join(players)} — "
            f"You have {BET_SECS}s to \x02!bjbet <amount>\x02 "
            f"(default: ${cfg['default_bet']}, min: ${cfg['min_bet']})."
        )

        try:
            await asyncio.sleep(BET_SECS)
        except asyncio.CancelledError:
            return

        # assign default bet to anyone who didn't bet
        for p in players.values():
            if p.bet == 0:
                p.bet = min(cfg["default_bet"], p.cash)

        # deal two cards each
        deck = new_deck()
        random.shuffle(deck)
        session.data["deck"]   = deck
        session.data["dealer"] = [deck.pop(), deck.pop()]
        for p in players.values():
            p.hand = [deck.pop(), deck.pop()]

        await self.say(chan, f"[Blackjack] Dealer shows: {session.data['dealer'][0]}")
        for p in players.values():
            await self.say(chan,
                f"  {p.nick}: {hand_str(p.hand)} "
                f"(value: {hand_value(p.hand)})  bet: ${p.bet}"
            )

        session.data["phase"] = "playing"
        await self._play_all_turns(session)

    async def _play_all_turns(self, session: GameSession):
        chan    = session.target
        players = session.data["players"]
        cfg    = session.data["cfg"]

        for nick, p in list(players.items()):
            if p.done:
                continue

            # natural 21 on deal — auto-stand
            if hand_value(p.hand) == 21:
                await self.say(chan, f"  {nick}: Natural 21 — auto-stand!")
                p.done = True
                continue

            await self.say(chan,
                f"[Blackjack] {nick}'s turn: {hand_str(p.hand)} "
                f"({hand_value(p.hand)}) — \x02!bjhit\x02 or \x02!bjstand\x02 "
                f"(timeout: {cfg['turn_secs']}s)"
            )
            session.data["current_player"] = nick
            done_flag = asyncio.Event()
            session.data["turn_done"] = done_flag

            try:
                await asyncio.wait_for(done_flag.wait(), timeout=cfg["turn_secs"])
            except asyncio.TimeoutError:
                await self.say(chan,
                    f"  {nick} timed out — auto-stand with "
                    f"{hand_str(p.hand)} ({hand_value(p.hand)})."
                )
                p.stood = True
                p.done  = True

        session.data["current_player"] = None
        await self._dealer_play(session)

    async def _dealer_play(self, session: GameSession):
        chan   = session.target
        deck  = session.data["deck"]
        dealer = session.data["dealer"]

        await self.say(chan,
            f"[Blackjack] Dealer's hand: {hand_str(dealer)} ({hand_value(dealer)})"
        )
        while hand_value(dealer) < 17 and deck:
            dealer.append(deck.pop())
            await asyncio.sleep(1)
            await self.say(chan,
                f"  Dealer hits: {hand_str(dealer)} ({hand_value(dealer)})"
            )

        dval = hand_value(dealer)
        await self.say(chan,
            f"  Dealer {'busts at' if dval > 21 else 'stands at'} {dval}."
        )
        await self._settle(session, dval)

    async def _settle(self, session: GameSession, dealer_val: int):
        chan    = session.target
        players = session.data["players"]
        cfg    = session.data["cfg"]

        await self.say(chan, "[Blackjack] ── Results ──")
        for p in players.values():
            pval = hand_value(p.hand)
            nat  = (pval == 21 and len(p.hand) == 2)

            if p.bust or pval > 21:
                delta  = -p.bet
                result = f"BUST  -${p.bet}"
            elif dealer_val > 21:
                delta  = int(p.bet * (1.5 if nat else 1))
                result = f"WIN (dealer bust)  +${delta}"
            elif nat and dealer_val != 21:
                delta  = int(p.bet * 1.5)
                result = f"BLACKJACK  +${delta}"
            elif pval > dealer_val:
                delta  = p.bet
                result = f"WIN  +${delta}"
            elif pval == dealer_val:
                delta  = 0
                result = "PUSH"
            else:
                delta  = -p.bet
                result = f"LOSE  -${p.bet}"

            p.cash = max(0, p.cash + delta)
            await self.say(chan,
                f"  {p.nick}: {hand_str(p.hand)} ({pval}) → {result}  "
                f"cash: ${p.cash}"
            )
            await self._save_cash(p.nick, p.cash)

            if p.cash == 0:
                await self.say(chan,
                    f"  \x02{p.nick}\x02 is broke! Rejoin next round for "
                    f"${cfg['starting_cash'] // 2} consolation chips."
                )

        await asyncio.sleep(3)
        await self._round_finished(session)

    async def _round_finished(self, session: GameSession):
        session.data["players"]        = {}
        session.data["deck"]           = []
        session.data["dealer"]         = []
        session.data["current_player"] = None
        session.data["phase"]          = "finished"
        session.task                   = None
        await self.say(session.target,
            "[Blackjack] Round over. "
            "\x02!bjstart\x02 to play again  |  "
            "\x02!blackjack stop\x02 to end."
        )

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return
        cmd    = parts[0].lower()
        phase  = session.data.get("phase", "")
        players: Dict[str, PlayerState] = session.data["players"]
        cfg    = session.data["cfg"]
        chan   = session.target

        if cmd == "!bjjoin":
            if phase != "registering":
                return await self.notice(nick, "Registration is closed. Wait for the next round.")
            if nick in players:
                return await self.notice(nick, "You're already in the game.")
            cash = await self._load_cash(nick, cfg["starting_cash"])
            if cash == 0:
                cash = cfg["starting_cash"] // 2
            players[nick] = PlayerState(nick=nick, cash=cash)
            await self.say(chan, f"[Blackjack] {nick} joined with ${cash}.")

        elif cmd == "!bjstart" and phase == "finished":
            session.data["phase"] = "registering"
            await self._open_registration(session)

        elif cmd == "!bjbet" and phase == "betting":
            if nick not in players:
                return await self.notice(nick, "You're not in this game.")
            p = players[nick]
            if p.bet > 0:
                return await self.notice(nick, f"Bet already set: ${p.bet}.")
            try:
                amount = int(parts[1]) if len(parts) > 1 else cfg["default_bet"]
            except (ValueError, IndexError):
                return await self.notice(nick, "Usage: !bjbet <amount>")
            if amount < cfg["min_bet"]:
                return await self.notice(nick, f"Minimum bet is ${cfg['min_bet']}.")
            if amount > p.cash:
                return await self.notice(nick, f"You only have ${p.cash}.")
            p.bet = amount
            await self.say(chan, f"[Blackjack] {nick} bets ${amount}.")

        elif cmd == "!bjhit" and phase == "playing":
            if session.data.get("current_player") != nick:
                return
            p = players[nick]
            p.hand.append(session.data["deck"].pop())
            val = hand_value(p.hand)
            await self.say(chan, f"  {nick} hits: {hand_str(p.hand)} ({val})")
            if val > 21:
                await self.say(chan, f"  {nick} busts!")
                p.bust = p.done = True
                session.data["turn_done"].set()
            elif val == 21:
                await self.say(chan, f"  {nick} hits 21 — auto-stand.")
                p.stood = p.done = True
                session.data["turn_done"].set()

        elif cmd == "!bjstand" and phase == "playing":
            if session.data.get("current_player") != nick:
                return
            p = players[nick]
            await self.say(chan, f"  {nick} stands at {hand_value(p.hand)}.")
            p.stood = p.done = True
            session.data["turn_done"].set()

        elif cmd == "!blackjack" and len(parts) > 1 and parts[1].lower() == "stop":
            #if nick != session.owner and not self.core.nick_isop(nick, chan):
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only the game owner or a chan-op can stop the game.")
            await self.stop_session(session.key)
            return

        #elif cmd == "!bjset":
        #    if nick != session.owner and not self.core.nick_isop(nick, chan):
        #        return await self.notice(nick, "Only the game owner or a chan-op can change settings.")
        #    await self._handle_set(session, nick, parts[1:])

        elif cmd == "!bjcash":
            target = parts[1] if len(parts) > 1 else nick
            if target in players:
                await self.say(chan, f"{target} has ${players[target].cash} in chips.")
            else:
                cash = await self._load_cash(target, cfg["starting_cash"])
                await self.say(chan, f"{target} has ${cash} in chips (not in current game).")

        elif cmd == "!bjtop":
            if not self._on_cooldown(chan, "bjtop"):
                await self._show_top(chan)
            return

        elif cmd == "!bjhelp":
            if not self._on_cooldown(chan, "bjhelp"):
                await self._show_help(chan)
            return

    async def _handle_set(self, session: GameSession, nick: str, args: list):
        chan = session.target
        cfg  = session.data["cfg"]
        valid = {
            "starting_cash": ("Starting cash", int),
            "min_bet":       ("Minimum bet",   int),
            "default_bet":   ("Default bet",   int),
            "turn_secs":     ("Turn timeout",  int),
        }
        if len(args) < 2 or args[0].lower() not in valid:
            return await self.notice(nick,
                f"Usage: !bjset <{'|'.join(valid)}> <value>"
            )
        key         = args[0].lower()
        label, cast = valid[key]
        try:
            value = cast(args[1])
        except ValueError:
            return await self.notice(nick, f"{label} must be a number.")

        cfg[key] = value
        async with _db(self.core.db_path) as db:
            await db.execute(
                f"INSERT INTO blackjack_settings(channel, {key}) VALUES(?,?) "
                f"ON CONFLICT(channel) DO UPDATE SET {key}=excluded.{key}, "
                f"updated_at=strftime('%s','now')",
                (chan, value)
            )
        await self.say(chan, f"[Blackjack] {label} set to {value}.")

    async def _show_top(self, chan: str):
        self._set_cooldown(chan, "bjtop")
        async with _db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, cash FROM blackjack_cash ORDER BY cash DESC LIMIT 5"
            ) as cursor:
                rows = await cursor.fetchall()
        if not rows:
            return await self.say(chan, "[Blackjack] No chip records yet.")
        board = "  ".join(
            f"{i + 1}. {r['nick']} ${r['cash']}" for i, r in enumerate(rows)
        )
        await self.say(chan, f"[Blackjack] Top chips: {board}")

    async def _show_help(self, chan: str):
        self._set_cooldown(chan, "bjhelp")
        await self.say(chan, f"[Blackjack] commands:")
        await self.say(chan, f"    !blackjack            - Start a game. Opens 5-min registration window.")
        await self.say(chan, f"    !bjjoin               - Join during registration or between rounds.")
        await self.say(chan, f"    !bjstart              - Owner skips the registration countdown.")
        await self.say(chan, f"    !bjbet <amount>       - Place bet during betting phase (45s window).")
        await self.say(chan, f"    !bjhit                - Draw a card on your turn.")
        await self.say(chan, f"    !bjstand              - Hold your hand on your turn.")
        await self.say(chan, f"    !blackjack stop       - Owner or chan-op ends the game.")
        #await self.say(chan, f"    !bjset <param> <v>    - Owner configures per-channel settings.")
        await self.say(chan, f"    !bjcash [nick]        - Check chip balance.")
        await self.say(chan, f"    !bjtop                - Top 5 chip leaders.")

    async def _load_settings(self, channel: str) -> dict:
        async with _db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM blackjack_settings WHERE channel=?", (channel,)
            ) as cursor:
                row = await cursor.fetchone()
        if row:
            return {
                "starting_cash": row["starting_cash"],
                "min_bet":       row["min_bet"],
                "default_bet":   row["default_bet"],
                "turn_secs":     row["turn_secs"],
            }
        return {
            "starting_cash": DEFAULT_STARTING_CASH,
            "min_bet":       DEFAULT_MIN_BET,
            "default_bet":   DEFAULT_DEFAULT_BET,
            "turn_secs":     DEFAULT_TURN_SECS,
        }

    async def _load_cash(self, nick: str, starting_cash: int) -> int:
        async with _db(self.core.db_path) as db:
            async with db.execute(
                "SELECT cash FROM blackjack_cash WHERE nick=?", (nick,)
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                await db.execute(
                    "INSERT INTO blackjack_cash(nick, cash) VALUES(?,?)",
                    (nick, starting_cash)
                )
                await db.commit()
        return row["cash"] if row else starting_cash

    async def _save_cash(self, nick: str, amount: int):
        async with _db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO blackjack_cash(nick, cash) VALUES(?,?) "
                "ON CONFLICT(nick) DO UPDATE SET cash=excluded.cash, "
                "updated_at=strftime('%s','now')",
                (nick, amount)
            )

    async def say(self, target: str, msg: str):
        await self.send_privmsg(target, msg)

    async def notice(self, nick: str, msg: str):
        await self.send_notice(nick, msg)

    async def _open_registration(self, session: GameSession):
        """Announce join window and start the registration countdown."""
        chan = session.target
        await self.say(chan,
            f"\x02[Blackjack]\x02 New round! "
            f"Type \x02!bjjoin\x02 to play. "
            f"Starting in {REGISTRATION_SECS}s "
            f"(or type \x02!bjstart\x02 to begin now)."
        )
        session.task = asyncio.create_task(self._registration_phase(session))

    def _on_cooldown(self, chan: str, cmd: str) -> bool:
        """Returns True and stays silent if cmd is still on cooldown for this channel."""
        now = time.monotonic()
        last = self._cmd_cooldowns.setdefault(chan, {}).get(cmd, 0)
        if now - last < CMD_COOLDOWN_SECS:
            return True
        self._cmd_cooldowns[chan][cmd] = now
        return False
    
    def _set_cooldown(self, chan: str, cmd: str):
        self._cmd_cooldowns.setdefault(chan, {})[cmd] = time.monotonic()    