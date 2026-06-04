# src/games/poker.py
"""
WBS Game: poker.py
version: 0.2.0
by: cyco
Description: Texas Hold'em Poker game for WBS.

Flow:
  Partyline: .gstart poker channel #chan  → makes game available (idle)
  In-channel:
    !pkstart            - Start a hand. Starter is auto-joined.
    !pkjoin             - Join during registration window or between hands.
    !pkbet <amount>     - Bet/raise during betting phase.
    !pkcall             - Call the current bet.
    !pkcheck            - Check (if no bet to call).
    !pkfold             - Fold your hand.
    !pkallin            - Go all-in.
    !poker stop         - Owner or chan-op ends the game.
    !pkcash [nick]      - Check chip balance.
    !pktop              - Top 5 chip leaders.
    !pkhelp             - Show commands.
"""
import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from itertools import combinations

from . import Game, GameSession
from ..db import get_db

DEFAULT_STARTING_CASH = 1500
DEFAULT_SMALL_BLIND = 10
DEFAULT_BIG_BLIND = 20
DEFAULT_TURN_SECS = 60
REGISTRATION_SECS = 60
REGISTRATION_WARN = 30
CMD_COOLDOWN_SECS = 300
MIN_PLAYERS = 2
SUITS = ["♠", "♥", "♦", "♣"]
RANKS = ["2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"]
RANK_VAL = {r: i for i, r in enumerate(RANKS, 2)}  # 2=2 .. A=14
HAND_NAMES = [
    "High Card", "One Pair", "Two Pair", "Three of a Kind",
    "Straight", "Flush", "Full House", "Four of a Kind",
    "Straight Flush", "Royal Flush"
]

def new_deck() -> List[str]:
    return [f"{r}{s}" for s in SUITS for r in RANKS]

def card_rank(card: str) -> str:
    return card[:-1]

def card_suit(card: str) -> str:
    return card[-1]

def rank_val(card: str) -> int:
    return RANK_VAL[card_rank(card)]

def hand_str(hand: List[str]) -> str:
    return " ".join(hand)

def evaluate_5(cards: List[str]):
    """Evaluate exactly 5 cards. Returns (rank_idx, tiebreakers)."""
    vals = sorted([rank_val(c) for c in cards], reverse=True)
    suits = [card_suit(c) for c in cards]
    is_flush = len(set(suits)) == 1
    is_straight = (len(set(vals)) == 5) and (vals[0] - vals[4] == 4)
    # Ace-low straight: A-2-3-4-5
    if set(vals) == {14, 2, 3, 4, 5}:
        is_straight = True
        vals = [5, 4, 3, 2, 1]  # treat ace as 1 for tiebreak

    from collections import Counter
    ctr = Counter(vals)
    groups = sorted(ctr.items(), key=lambda x: (x[1], x[0]), reverse=True)
    counts = [g[1] for g in groups]
    ranked_vals = [g[0] for g in groups]

    if is_straight and is_flush:
        if vals[0] == 14:
            return (9, vals)  # Royal Flush
        return (8, vals)      # Straight Flush
    if counts[0] == 4:
        return (7, ranked_vals)  # Four of a Kind
    if counts[:2] == [3, 2]:
        return (6, ranked_vals)  # Full House
    if is_flush:
        return (5, vals)         # Flush
    if is_straight:
        return (4, vals)         # Straight
    if counts[0] == 3:
        return (3, ranked_vals)  # Three of a Kind
    if counts[:2] == [2, 2]:
        return (2, ranked_vals)  # Two Pair
    if counts[0] == 2:
        return (1, ranked_vals)  # One Pair
    return (0, vals)             # High Card

def best_hand(hole: List[str], community: List[str]):
    """Best 5-card hand from hole + community (up to 7 cards)."""
    all_cards = hole + community
    if len(all_cards) < 5:
        return evaluate_5(all_cards + ["2♠"] * (5 - len(all_cards)))
    best = None
    for combo in combinations(all_cards, 5):
        score = evaluate_5(list(combo))
        if best is None or score > best:
            best = score
    return best

def hand_name(score) -> str:
    return HAND_NAMES[score[0]]

@dataclass
class PokerPlayer:
    nick: str
    cash: int
    hole: List[str] = field(default_factory=list)
    bet_total: int = 0    # total committed this hand
    street_bet: int = 0   # committed this betting street
    folded: bool = False
    all_in: bool = False
    acted: bool = False   # has acted this street

class PokerGame(Game):
    name = "poker"
    version = "0.2.0"
    scopes = {"channel"}

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS poker_settings (
            channel       TEXT    PRIMARY KEY,
            starting_cash INTEGER DEFAULT 1500,
            small_blind   INTEGER DEFAULT 10,
            big_blind     INTEGER DEFAULT 20,
            turn_secs     INTEGER DEFAULT 60,
            updated_at    INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS poker_cash (
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
        await super().unload()
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession):
        """Called by .gstart — makes the game available but does NOT start a hand."""
        chan = session.target
        session.data["cfg"] = await self._load_settings(chan)
        session.data["players"] = {}
        session.data["order"] = []
        session.data["deck"] = []
        session.data["community"] = []
        session.data["pot"] = 0
        session.data["phase"] = "idle"
        session.data["street"] = None
        session.data["current_idx"] = 0
        session.data["current_bet"] = 0
        session.data["dealer_idx"] = 0
        session.data["action_player"] = None
        await super().start_session(session)
        await self.say(chan,
            "\x02[Poker]\x02 Texas Hold'em is now available! "
            "Type \x02!pkstart\x02 to start a hand."
        )

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.say(session.target, "[Poker] Game over.")
        await super().stop_session(key)

    async def _open_registration(self, session: GameSession):
        chan = session.target
        await self.say(chan,
            f"\x02[Poker]\x02 Registration open! "
            f"Type \x02!pkjoin\x02 to play. "
            f"Starting in {REGISTRATION_SECS}s "
            f"(chan-ops: type \x02!pkstart\x02 again to begin immediately)."
        )
        session.task = asyncio.create_task(self._registration_phase(session))

    async def _registration_phase(self, session: GameSession):
        try:
            await asyncio.sleep(REGISTRATION_SECS - REGISTRATION_WARN)
            await self.say(session.target,
                f"[Poker] \x0230s left\x02 to join! Type \x02!pkjoin\x02."
            )
            await asyncio.sleep(REGISTRATION_WARN)
        except asyncio.CancelledError:
            return
        await self._begin_hand(session)

    async def _begin_hand(self, session: GameSession):
        chan = session.target
        players = session.data["players"]

        if len(players) < MIN_PLAYERS:
            await self.say(chan,
                f"[Poker] Need at least {MIN_PLAYERS} players. "
                f"Type \x02!pkjoin\x02 then \x02!pkstart\x02."
            )
            session.data["phase"] = "idle"
            return

        cfg = session.data["cfg"]
        order = list(players.keys())
        random.shuffle(order)
        session.data["order"] = order

        # Reset per-hand state
        for p in players.values():
            p.hole = []
            p.bet_total = 0
            p.street_bet = 0
            p.folded = False
            p.all_in = False
            p.acted = False

        deck = new_deck()
        random.shuffle(deck)
        session.data["deck"] = deck
        session.data["community"] = []
        session.data["pot"] = 0
        session.data["current_bet"] = 0
        session.data["phase"] = "playing"
        session.data["street"] = "preflop"

        # Dealer / SB / BB positions
        d_idx = session.data["dealer_idx"] % len(order)
        sb_idx = (d_idx + 1) % len(order)
        bb_idx = (d_idx + 2) % len(order)
        session.data["dealer_idx"] = (d_idx + 1) % len(order)  # rotate next hand

        dealer_nick = order[d_idx]
        sb_nick = order[sb_idx]
        bb_nick = order[bb_idx]

        # Post blinds
        sb = cfg["small_blind"]
        bb = cfg["big_blind"]
        self._post_blind(session, sb_nick, sb)
        self._post_blind(session, bb_nick, bb)
        session.data["current_bet"] = bb

        await self.say(chan,
            f"[Poker] New hand! Dealer: {dealer_nick}  "
            f"SB: {sb_nick} (${sb})  BB: {bb_nick} (${bb})  "
            f"Pot: ${session.data['pot']}"
        )

        # Deal 2 hole cards each
        for nick in order:
            p = players[nick]
            p.hole = [deck.pop(), deck.pop()]

        # Notify each player privately
        for nick in order:
            p = players[nick]
            await self.notice(nick, f"[Poker] Your hole cards: {hand_str(p.hole)}")

        await self.say(chan, f"[Poker] Hole cards dealt. Pre-flop betting begins.")

        # Pre-flop action starts left of BB
        start_idx = (bb_idx + 1) % len(order)
        await self._betting_street(session, start_idx)

    def _post_blind(self, session: GameSession, nick: str, amount: int):
        players = session.data["players"]
        p = players[nick]
        actual = min(amount, p.cash)
        p.cash -= actual
        p.bet_total += actual
        p.street_bet += actual
        session.data["pot"] += actual
        if p.cash == 0:
            p.all_in = True

    async def _betting_street(self, session: GameSession, start_idx: int):
        """Run one complete betting street starting at start_idx."""
        players = session.data["players"]

        # Reset street bets and acted flags for new street
        for p in players.values():
            p.street_bet = 0
            p.acted = False

        session.data["current_idx"] = start_idx
        await self._next_action(session)

    async def _next_action(self, session: GameSession):
        """Find next player who needs to act and prompt them."""
        order = session.data["order"]
        players = session.data["players"]
        chan = session.target
        cfg = session.data["cfg"]

        # Walk through order to find who needs to act
        checked = 0
        idx = session.data["current_idx"]
        while checked < len(order):
            nick = order[idx % len(order)]
            p = players[nick]
            if not p.folded and not p.all_in:
                to_call = session.data["current_bet"] - p.street_bet
                if not p.acted or to_call > 0:
                    break
            idx += 1
            checked += 1
        else:
            # All players done — advance to next street
            await self._advance_street(session)
            return

        nick = order[idx % len(order)]
        session.data["current_idx"] = idx % len(order)
        p = players[nick]
        to_call = session.data["current_bet"] - p.street_bet
        pot = session.data["pot"]
        community_str = hand_str(session.data["community"]) if session.data["community"] else "(none yet)"

        action_opts = []
        if to_call == 0:
            action_opts.append("\x02!pkcheck\x02")
        else:
            action_opts.append(f"\x02!pkcall\x02 (${to_call})")
        action_opts.append("\x02!pkbet <amount>\x02")
        action_opts.append("\x02!pkallin\x02")
        action_opts.append("\x02!pkfold\x02")

        await self.say(chan,
            f"[Poker] {nick}'s turn | Pot: ${pot} | Board: {community_str} | "
            f"To call: ${to_call} | Cash: ${p.cash} | "
            + "  ".join(action_opts)
        )
        await self.notice(nick, f"[Poker] Your hole cards: {hand_str(p.hole)}")

        session.data["action_player"] = nick
        done_flag = asyncio.Event()
        session.data["turn_done"] = done_flag

        try:
            await asyncio.wait_for(done_flag.wait(), timeout=cfg["turn_secs"])
        except asyncio.TimeoutError:
            p.folded = True
            p.acted = True
            await self.say(chan, f"  {nick} timed out — auto-fold.")
            if await self._check_one_left(session):
                return
            session.data["current_idx"] = (session.data["current_idx"] + 1) % len(order)
            await self._next_action(session)

    async def _check_one_left(self, session: GameSession) -> bool:
        """If only one active player remains, award pot and end hand."""
        players = session.data["players"]
        active = [n for n, p in players.items() if not p.folded]
        if len(active) == 1:
            winner = active[0]
            pot = session.data["pot"]
            players[winner].cash += pot
            await self.say(session.target,
                f"[Poker] Everyone else folded. {winner} wins the pot of ${pot}!"
            )
            await self._save_cash(winner, players[winner].cash)
            await self._round_finished(session)
            return True
        return False

    async def _advance_street(self, session: GameSession):
        street = session.data["street"]
        deck = session.data["deck"]
        community = session.data["community"]
        chan = session.target

        # Reset for new street
        session.data["current_bet"] = 0
        for p in session.data["players"].values():
            p.street_bet = 0
            p.acted = False

        if street == "preflop":
            deck.pop()  # burn
            flop = [deck.pop(), deck.pop(), deck.pop()]
            community.extend(flop)
            session.data["street"] = "flop"
            await self.say(chan, f"[Poker] *** FLOP *** {hand_str(community)}")
        elif street == "flop":
            deck.pop()  # burn
            community.append(deck.pop())
            session.data["street"] = "turn"
            await self.say(chan, f"[Poker] *** TURN *** {hand_str(community)}")
        elif street == "turn":
            deck.pop()  # burn
            community.append(deck.pop())
            session.data["street"] = "river"
            await self.say(chan, f"[Poker] *** RIVER *** {hand_str(community)}")
        elif street == "river":
            await self._showdown(session)
            return

        # Start betting from first active player left of dealer
        order = session.data["order"]
        players = session.data["players"]
        dealer_idx = (session.data["dealer_idx"] - 1) % len(order)
        start_idx = (dealer_idx + 1) % len(order)
        for i in range(len(order)):
            nick = order[(start_idx + i) % len(order)]
            if not players[nick].folded and not players[nick].all_in:
                start_idx = (start_idx + i) % len(order)
                break
        await self._betting_street(session, start_idx)

    async def _showdown(self, session: GameSession):
        chan = session.target
        players = session.data["players"]
        community = session.data["community"]
        pot = session.data["pot"]

        active = {n: p for n, p in players.items() if not p.folded}
        await self.say(chan, f"[Poker] *** SHOWDOWN *** | Board: {hand_str(community)} | Pot: ${pot}")

        scores = {}
        for nick, p in active.items():
            score = best_hand(p.hole, community)
            scores[nick] = score
            await self.say(chan,
                f"  {nick}: {hand_str(p.hole)} → \x02{hand_name(score)}\x02"
            )

        best_score = max(scores.values())
        winners = [n for n, s in scores.items() if s == best_score]

        share = pot // len(winners)
        remainder = pot % len(winners)
        for i, nick in enumerate(winners):
            amount = share + (remainder if i == 0 else 0)
            players[nick].cash += amount
            await self._save_cash(nick, players[nick].cash)

        if len(winners) == 1:
            await self.say(chan,
                f"[Poker] \x02{winners[0]}\x02 wins ${pot} with "
                f"\x02{hand_name(best_score)}\x02! Cash: ${players[winners[0]].cash}"
            )
        else:
            win_str = ", ".join(winners)
            await self.say(chan,
                f"[Poker] Split pot! {win_str} each win ${share} "
                f"with \x02{hand_name(best_score)}\x02."
            )

        for nick, p in players.items():
            if p.cash == 0:
                cfg = session.data["cfg"]
                await self.say(chan,
                    f"  \x02{nick}\x02 is out of chips! "
                    f"Rejoin next round for ${cfg['starting_cash'] // 2} consolation chips."
                )

        await asyncio.sleep(3)
        await self._round_finished(session)

    async def _round_finished(self, session: GameSession):
        players = session.data["players"]
        busted = [n for n, p in players.items() if p.cash == 0]
        for n in busted:
            del players[n]

        session.data["community"] = []
        session.data["deck"] = []
        session.data["pot"] = 0
        session.data["current_bet"] = 0
        session.data["action_player"] = None
        session.data["phase"] = "finished"
        session.task = None
        await self.say(session.target,
            "[Poker] Hand over. "
            "\x02!pkstart\x02 for next hand  |  "
            "\x02!pkjoin\x02 to join  |  "
            "\x02!poker stop\x02 to end."
        )

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return
        cmd = parts[0].lower()
        phase = session.data.get("phase", "")
        players: Dict[str, PokerPlayer] = session.data["players"]
        cfg = session.data["cfg"]
        chan = session.target

        if cmd == "!pkstart" and phase in ("idle", "finished"):
            if nick not in players:
                cash = await self._load_cash(nick, cfg["starting_cash"])
                if cash == 0:
                    cash = cfg["starting_cash"] // 2
                players[nick] = PokerPlayer(nick=nick, cash=cash)
                await self.say(chan, f"[Poker] {nick} started the game and joined with ${cash}.")
            session.data["phase"] = "registering"
            await self._open_registration(session)
            return

        elif cmd == "!pkstart" and phase == "registering":
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only a chan-op can skip the registration countdown.")
            if session.task and not session.task.done():
                session.task.cancel()
            await self._begin_hand(session)
            return

        elif cmd == "!pkjoin":
            if phase not in ("registering", "finished"):
                return await self.notice(nick, "Can only join between hands. Wait for the next round.")
            if nick in players:
                return await self.notice(nick, "You're already in the game.")
            cash = await self._load_cash(nick, cfg["starting_cash"])
            if cash == 0:
                cash = cfg["starting_cash"] // 2
            players[nick] = PokerPlayer(nick=nick, cash=cash)
            await self.say(chan, f"[Poker] {nick} joined with ${cash}.")

        elif cmd == "!pkfold" and phase == "playing":
            if session.data.get("action_player") != nick:
                return
            p = players[nick]
            p.folded = True
            p.acted = True
            await self.say(chan, f"  {nick} folds.")
            session.data["turn_done"].set()
            if await self._check_one_left(session):
                return
            session.data["current_idx"] = (session.data["current_idx"] + 1) % len(session.data["order"])

        elif cmd == "!pkcheck" and phase == "playing":
            if session.data.get("action_player") != nick:
                return
            p = players[nick]
            to_call = session.data["current_bet"] - p.street_bet
            if to_call > 0:
                return await self.notice(nick, f"You must call ${to_call}, raise, or fold.")
            p.acted = True
            await self.say(chan, f"  {nick} checks.")
            session.data["turn_done"].set()
            session.data["current_idx"] = (session.data["current_idx"] + 1) % len(session.data["order"])

        elif cmd == "!pkcall" and phase == "playing":
            if session.data.get("action_player") != nick:
                return
            p = players[nick]
            to_call = min(session.data["current_bet"] - p.street_bet, p.cash)
            if to_call <= 0:
                return await self.notice(nick, "Nothing to call. Use !pkcheck.")
            p.cash -= to_call
            p.street_bet += to_call
            p.bet_total += to_call
            session.data["pot"] += to_call
            p.acted = True
            if p.cash == 0:
                p.all_in = True
                await self.say(chan, f"  {nick} calls ${to_call} and is \x02ALL IN\x02! Pot: ${session.data['pot']}")
            else:
                await self.say(chan, f"  {nick} calls ${to_call}. Pot: ${session.data['pot']}")
            session.data["turn_done"].set()
            session.data["current_idx"] = (session.data["current_idx"] + 1) % len(session.data["order"])

        elif cmd == "!pkbet" and phase == "playing":
            if session.data.get("action_player") != nick:
                return
            p = players[nick]
            if len(parts) < 2:
                return await self.notice(nick, "Usage: !pkbet <amount>")
            try:
                amount = int(parts[1])
            except ValueError:
                return await self.notice(nick, "Usage: !pkbet <amount>")
            to_call = session.data["current_bet"] - p.street_bet
            total_needed = to_call + amount
            if total_needed > p.cash:
                return await self.notice(nick, f"Not enough chips (${p.cash}). Use !pkallin.")
            if amount < cfg["big_blind"]:
                return await self.notice(nick, f"Minimum raise is ${cfg['big_blind']}.")
            p.cash -= total_needed
            p.street_bet += total_needed
            p.bet_total += total_needed
            session.data["pot"] += total_needed
            session.data["current_bet"] = p.street_bet
            # Raise re-opens action for all others
            for other_nick, other_p in players.items():
                if other_nick != nick and not other_p.folded and not other_p.all_in:
                    other_p.acted = False
            p.acted = True
            await self.say(chan, f"  {nick} raises to ${p.street_bet}. Pot: ${session.data['pot']}")
            session.data["turn_done"].set()
            session.data["current_idx"] = (session.data["current_idx"] + 1) % len(session.data["order"])

        elif cmd == "!pkallin" and phase == "playing":
            if session.data.get("action_player") != nick:
                return
            p = players[nick]
            amount = p.cash
            p.street_bet += amount
            p.bet_total += amount
            session.data["pot"] += amount
            p.cash = 0
            p.all_in = True
            p.acted = True
            if p.street_bet > session.data["current_bet"]:
                session.data["current_bet"] = p.street_bet
                for other_nick, other_p in players.items():
                    if other_nick != nick and not other_p.folded and not other_p.all_in:
                        other_p.acted = False
            await self.say(chan, f"  {nick} goes \x02ALL IN\x02 with ${amount}! Pot: ${session.data['pot']}")
            session.data["turn_done"].set()
            session.data["current_idx"] = (session.data["current_idx"] + 1) % len(session.data["order"])

        elif cmd == "!poker" and len(parts) > 1 and parts[1].lower() == "stop":
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only a chan-op can stop the game.")
            await self.stop_session(session.key)
            return

        elif cmd == "!pkcash":
            target = parts[1] if len(parts) > 1 else nick
            if target in players:
                await self.say(chan, f"{target} has ${players[target].cash} in chips.")
            else:
                cash = await self._load_cash(target, cfg["starting_cash"])
                await self.say(chan, f"{target} has ${cash} in chips (not in current game).")

        elif cmd == "!pktop":
            if not self._on_cooldown(chan, "pktop"):
                await self._show_top(chan)

        elif cmd == "!pkhelp":
            if not self._on_cooldown(chan, "pkhelp"):
                await self._show_help(chan)

    async def _load_settings(self, channel: str) -> dict:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM poker_settings WHERE channel=?", (channel,)
            ) as cursor:
                row = await cursor.fetchone()
        if row:
            return {
                "starting_cash": row["starting_cash"],
                "small_blind":   row["small_blind"],
                "big_blind":     row["big_blind"],
                "turn_secs":     row["turn_secs"],
            }
        return {
            "starting_cash": DEFAULT_STARTING_CASH,
            "small_blind":   DEFAULT_SMALL_BLIND,
            "big_blind":     DEFAULT_BIG_BLIND,
            "turn_secs":     DEFAULT_TURN_SECS,
        }

    async def _load_cash(self, nick: str, starting_cash: int) -> int:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT cash FROM poker_cash WHERE nick=?", (nick,)
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                await db.execute(
                    "INSERT INTO poker_cash(nick, cash) VALUES(?,?)",
                    (nick, starting_cash)
                )
                await db.commit()
        return row["cash"] if row else starting_cash

    async def _save_cash(self, nick: str, amount: int):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO poker_cash(nick, cash) VALUES(?,?) "
                "ON CONFLICT(nick) DO UPDATE SET cash=excluded.cash, "
                "updated_at=strftime('%s','now')",
                (nick, amount)
            )
            await db.commit()

    async def _show_top(self, chan: str):
        self._set_cooldown(chan, "pktop")
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT nick, cash FROM poker_cash ORDER BY cash DESC LIMIT 5"
            ) as cursor:
                rows = await cursor.fetchall()
        if not rows:
            return await self.say(chan, "[Poker] No chip records yet.")
        board = "  ".join(f"{i+1}. {r['nick']} ${r['cash']}" for i, r in enumerate(rows))
        await self.say(chan, f"[Poker] Top chips: {board}")

    async def _show_help(self, chan: str):
        self._set_cooldown(chan, "pkhelp")
        lines = [
            "[Poker] Texas Hold'em commands:",
            "  !pkstart            - Start a hand. You are auto-joined.",
            "  !pkjoin             - Join during registration or between hands.",
            "  !pkbet <amount>     - Bet or raise.",
            "  !pkcall             - Call the current bet.",
            "  !pkcheck            - Check (when no bet to call).",
            "  !pkfold             - Fold your hand.",
            "  !pkallin            - Go all-in.",
            "  !poker stop         - Chan-op ends the game.",
            "  !pkcash [nick]      - Check chip balance.",
            "  !pktop              - Top 5 chip leaders.",
        ]
        for line in lines:
            await self.say(chan, line)

    async def say(self, target: str, msg: str):
        await self.send_privmsg(target, msg)

    async def notice(self, nick: str, msg: str):
        await self.send_notice(nick, msg)

    def _on_cooldown(self, chan: str, cmd: str) -> bool:
        now = time.monotonic()
        last = self._cmd_cooldowns.setdefault(chan, {}).get(cmd, 0)
        if now - last < CMD_COOLDOWN_SECS:
            return True
        self._cmd_cooldowns[chan][cmd] = now
        return False

    def _set_cooldown(self, chan: str, cmd: str):
        self._cmd_cooldowns.setdefault(chan, {})[cmd] = time.monotonic()