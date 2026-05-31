"""
WBS Game: werewolf.py
version: 0.1.0
by: cyco
Description: Social deduction Werewolf (Mafia) game for WBS.

Roles: Werewolf, Seer, Doctor, Villager
Minimum players: 4

Commands (in-channel):
  !werewolf           - Start a game. Opens join window.
  !wjoin              - Join during registration.
  !wstart             - Owner/op skips the join countdown.
  !werewolf stop      - Owner or chan-op ends the game.
  !wvote <nick>       - Vote to lynch a player (day phase).
  !wunvote            - Remove your vote.
  !wstats             - Show current game state (alive players, day/night).
  !whelp              - Show commands.

Night actions (via NOTICE to bot):
  !wkill <nick>       - Werewolf: choose a kill target.
  !wsee  <nick>       - Seer: investigate a player.
  !wsave <nick>       - Doctor: protect a player.
"""
import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from . import Game, GameSession
from ..db import get_db

REGISTRATION_SECS = 60
REGISTRATION_WARN = 30
DAY_SECS          = 120   # voting window
NIGHT_SECS        = 60    # night-action window
CMD_COOLDOWN_SECS = 30
MIN_PLAYERS       = 4
WEREWOLF  = "werewolf"
SEER      = "seer"
DOCTOR    = "doctor"
VILLAGER  = "villager"
ROLE_LABELS = {
    WEREWOLF: "\x034Werewolf\x03",
    SEER:     "\x033Seer\x03",
    DOCTOR:   "\x032Doctor\x03",
    VILLAGER: "\x0314Villager\x03",
}

def _assign_roles(players: List[str]) -> Dict[str, str]:
    """
    Scale role counts by player count:
      4-5  → 1 wolf, 1 seer, 1 doctor, rest villagers
      6-8  → 2 wolves, 1 seer, 1 doctor, rest villagers
      9+   → 3 wolves, 1 seer, 1 doctor, rest villagers
    """
    n = len(players)
    wolves = 1 if n < 6 else (2 if n < 9 else 3)
    pool = (
        [WEREWOLF] * wolves
        + [SEER]
        + [DOCTOR]
        + [VILLAGER] * (n - wolves - 2)
    )
    random.shuffle(pool)
    return dict(zip(players, pool))

@dataclass
class WPlayer:
    nick:      str
    role:      str
    alive:     bool = True
    protected: bool = False   # doctor saved this night

class WerewolfGame(Game):
    name    = "werewolf"
    version = "0.1.0"
    scopes  = {"channel"}

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS werewolf_stats (
            nick         TEXT    PRIMARY KEY,
            games_played INTEGER DEFAULT 0,
            wins         INTEGER DEFAULT 0,
            updated_at   INTEGER DEFAULT (strftime('%s','now'))
        )
        """
    ]
    _UNSERIALIZABLE = (asyncio.Lock, asyncio.Event, asyncio.Task, asyncio.Semaphore)
    _cmd_cooldowns: Dict[str, Dict[str, float]] = {}

    async def load(self):
        await super().load()
        async with get_db(self.core.db_path) as db:
            await db.execute(self.TABLE_SQL[0])
            await db.commit()
        self.log.info(f"Game {self.name} {self.version} loaded")

    async def unload(self):
        await super().unload()
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession):
        session.data["players"]      = {}   # nick -> WPlayer
        session.data["phase"]        = "registering"
        session.data["day"]          = 0
        session.data["votes"]        = {}   # voter -> target
        session.data["night_kill"]   = None
        session.data["night_save"]   = None
        session.data["night_see"]    = None
        session.data["wolves"]       = []
        session.data["actions_done"] = set()
        session.data["vote_event"]   = asyncio.Event()
        await super().start_session(session)
        await self._open_registration(session)

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.say(session.target, "[Werewolf] Game ended.")
        await super().stop_session(key)

    async def _open_registration(self, session: GameSession):
        chan = session.target
        await self.say(chan,
            f"\x02[Werewolf]\x02 A new game is starting! "
            f"Type \x02!wjoin\x02 to join. "
            f"Game begins in {REGISTRATION_SECS}s or when \x02!wstart\x02 is used. "
            f"(min {MIN_PLAYERS} players)"
        )
        session.task = asyncio.create_task(self._registration_phase(session))

    async def _registration_phase(self, session: GameSession):
        try:
            await asyncio.sleep(REGISTRATION_SECS - REGISTRATION_WARN)
            await self.say(session.target,
                f"[Werewolf] \x0230s left\x02 to join! Type \x02!wjoin\x02."
            )
            await asyncio.sleep(REGISTRATION_WARN)
        except asyncio.CancelledError:
            return
        await self._begin_game(session)

    async def _begin_game(self, session: GameSession):
        chan     = session.target
        players  = session.data["players"]

        if len(players) < MIN_PLAYERS:
            await self.say(chan,
                f"[Werewolf] Not enough players ({len(players)}/{MIN_PLAYERS}). Game cancelled."
            )
            await self.stop_session(session.key)
            return

        # Assign roles
        roles = _assign_roles(list(players.keys()))
        for nick, role in roles.items():
            players[nick].role = role

        session.data["wolves"] = [n for n, p in players.items() if p.role == WEREWOLF]
        session.data["phase"]  = "night"
        session.data["day"]    = 1

        await self.say(chan,
            f"[Werewolf] {len(players)} players locked in: {', '.join(players)}. "
            "Roles have been sent via notice. \x02Night falls…\x02"
        )

        # Send each player their role privately
        for nick, p in players.items():
            role_line = f"[Werewolf] Your role: {ROLE_LABELS[p.role]}"
            if p.role == WEREWOLF:
                teammates = [n for n in session.data["wolves"] if n != nick]
                if teammates:
                    role_line += f"  |  Pack: {', '.join(teammates)}"
            await self.notice(nick, role_line)

        await self._run_night(session)

    async def _run_night(self, session: GameSession):
        chan    = session.target
        players = session.data["players"]
        day    = session.data["day"]

        # Reset night state
        session.data["night_kill"]   = None
        session.data["night_save"]   = None
        session.data["night_see"]    = None
        session.data["actions_done"] = set()
        session.data["phase"]        = "night"

        alive = [n for n, p in players.items() if p.alive]
        await self.say(chan,
            f"[Werewolf] \x02Night {day}\x02 — {len(alive)} players remain. "
            "The village sleeps. Night roles: send your action via NOTICE to the bot."
        )

        # Prompt living special roles
        wolves = [n for n in session.data["wolves"] if players[n].alive]
        for w in wolves:
            targets = ", ".join(n for n in alive if n not in wolves)
            await self.notice(w, f"[Werewolf] Choose a kill target: !wkill <nick>  |  Alive non-wolves: {targets}")

        for nick, p in players.items():
            if not p.alive:
                continue
            if p.role == SEER:
                targets = ", ".join(n for n in alive if n != nick)
                await self.notice(nick, f"[Werewolf] Choose who to investigate: !wsee <nick>  |  Alive: {targets}")
            elif p.role == DOCTOR:
                targets = ", ".join(alive)
                await self.notice(nick, f"[Werewolf] Choose who to protect: !wsave <nick>  |  Alive: {targets}")

        try:
            await asyncio.wait_for(self._wait_night_actions(session), timeout=NIGHT_SECS)
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            return

        await self._resolve_night(session)

    async def _wait_night_actions(self, session: GameSession):
        """Wait until all living special roles have submitted or timeout."""
        while True:
            await asyncio.sleep(2)
            if self._all_night_actions_done(session):
                return

    def _all_night_actions_done(self, session: GameSession) -> bool:
        players = session.data["players"]
        wolves  = [n for n in session.data["wolves"] if players[n].alive]
        need: Set[str] = set()
        if wolves:
            need.add("kill")
        for nick, p in players.items():
            if not p.alive:
                continue
            if p.role == SEER:
                need.add("see")
            if p.role == DOCTOR:
                need.add("save")
        return need.issubset(session.data["actions_done"])

    async def _resolve_night(self, session: GameSession):
        chan      = session.target
        players   = session.data["players"]
        kill_tgt  = session.data["night_kill"]
        save_tgt  = session.data["night_save"]
        see_tgt   = session.data["night_see"]
        day       = session.data["day"]

        # Reset protections from last round
        for p in players.values():
            p.protected = False

        if save_tgt and save_tgt in players:
            players[save_tgt].protected = True

        killed = None
        if kill_tgt and kill_tgt in players and players[kill_tgt].alive:
            if not players[kill_tgt].protected:
                players[kill_tgt].alive = False
                killed = kill_tgt

        await self.say(chan, f"[Werewolf] \x02Dawn breaks on Day {day}\x02…")

        if killed:
            role_reveal = ROLE_LABELS[players[killed].role]
            await self.say(chan,
                f"[Werewolf] \x02{killed}\x02 was found dead at dawn. They were: {role_reveal}"
            )
        else:
            await self.say(chan, "[Werewolf] Miraculously, no one died last night!")

        # Seer result — private notice only
        if see_tgt and see_tgt in players:
            seer = next((n for n, p in players.items() if p.role == SEER and p.alive), None)
            if seer:
                await self.notice(seer,
                    f"[Werewolf] {see_tgt} is a {ROLE_LABELS[players[see_tgt].role]}"
                )

        winner = self._check_winner(session)
        if winner:
            return await self._end_game(session, winner)

        await self._run_day(session)

    async def _run_day(self, session: GameSession):
        chan    = session.target
        players = session.data["players"]
        day    = session.data["day"]

        session.data["votes"]      = {}
        session.data["phase"]      = "day"
        session.data["vote_event"] = asyncio.Event()

        alive = [n for n, p in players.items() if p.alive]
        await self.say(chan,
            f"[Werewolf] \x02Day {day}\x02 — Discuss and vote to lynch! "
            f"Type \x02!wvote <nick>\x02. You have {DAY_SECS}s. "
            f"Alive: {', '.join(alive)}"
        )

        try:
            await asyncio.wait_for(
                self._wait_majority_vote(session),
                timeout=DAY_SECS
            )
        except asyncio.TimeoutError:
            await self.say(chan, "[Werewolf] Time's up! No majority reached — no lynch today.")
        except asyncio.CancelledError:
            return

        await self._resolve_day(session)

    async def _wait_majority_vote(self, session: GameSession):
        while True:
            await asyncio.sleep(1)
            if self._majority_reached(session):
                session.data["vote_event"].set()
                return

    def _majority_reached(self, session: GameSession) -> bool:
        players = session.data["players"]
        votes   = session.data["votes"]
        alive   = sum(1 for p in players.values() if p.alive)
        needed  = (alive // 2) + 1
        tally: Dict[str, int] = {}
        for t in votes.values():
            tally[t] = tally.get(t, 0) + 1
        return any(v >= needed for v in tally.values())

    def _vote_tally(self, session: GameSession) -> Dict[str, int]:
        tally: Dict[str, int] = {}
        for t in session.data["votes"].values():
            tally[t] = tally.get(t, 0) + 1
        return tally

    async def _resolve_day(self, session: GameSession):
        chan    = session.target
        players = session.data["players"]
        tally   = self._vote_tally(session)

        if not tally:
            await self.say(chan, "[Werewolf] No votes cast. No one was lynched.")
        else:
            max_votes  = max(tally.values())
            candidates = [n for n, v in tally.items() if v == max_votes]
            if len(candidates) > 1:
                await self.say(chan,
                    f"[Werewolf] Tie vote between {', '.join(candidates)} — no lynch today."
                )
            else:
                lynched     = candidates[0]
                players[lynched].alive = False
                role_reveal = ROLE_LABELS[players[lynched].role]
                await self.say(chan,
                    f"[Werewolf] The village has spoken! \x02{lynched}\x02 is lynched. "
                    f"They were: {role_reveal}"
                )

        winner = self._check_winner(session)
        if winner:
            return await self._end_game(session, winner)

        session.data["day"] += 1
        await asyncio.sleep(3)
        await self._run_night(session)

    def _check_winner(self, session: GameSession) -> Optional[str]:
        players         = session.data["players"]
        alive_wolves    = sum(1 for n in session.data["wolves"] if players[n].alive)
        alive_villagers = sum(1 for n, p in players.items()
                              if p.alive and n not in session.data["wolves"])
        if alive_wolves == 0:
            return "villagers"
        if alive_wolves >= alive_villagers:
            return "werewolves"
        return None

    async def _end_game(self, session: GameSession, winner: str):
        chan    = session.target
        players = session.data["players"]

        if winner == "villagers":
            await self.say(chan,
                "[Werewolf] \x02\x033Villagers win!\x03\x02 The village is safe… for now."
            )
        else:
            wolf_names = ", ".join(session.data["wolves"])
            await self.say(chan,
                f"[Werewolf] \x02\x034Werewolves win!\x03\x02 "
                f"The wolves ({wolf_names}) devour the village!"
            )

        await self.say(chan, "[Werewolf] ── Final roles ──")
        for nick, p in players.items():
            status = "✓ alive" if p.alive else "✗ dead"
            await self.say(chan, f"  {nick}: {ROLE_LABELS[p.role]}  [{status}]")

        for nick, p in players.items():
            is_winner = (
                (winner == "villagers" and nick not in session.data["wolves"])
                or (winner == "werewolves" and nick in session.data["wolves"])
            )
            await self._save_stats(nick, won=is_winner)

        await asyncio.sleep(3)
        await self.stop_session(session.key)

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts   = text.strip().split()
        if not parts:
            return
        cmd     = parts[0].lower()
        phase   = session.data.get("phase", "")
        players = session.data["players"]
        chan    = session.target

        if cmd == "!wjoin":
            if phase != "registering":
                return await self.notice(nick, "Game already in progress. Wait for the next one.")
            if nick in players:
                return await self.notice(nick, "You're already in the game.")
            players[nick] = WPlayer(nick=nick, role=VILLAGER)
            await self.say(chan, f"[Werewolf] {nick} joined. ({len(players)} players)")

        elif cmd == "!wstart":
            if phase != "registering":
                return
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only a chan-op can force-start.")
            if session.task and not session.task.done():
                session.task.cancel()
            await self._begin_game(session)

        elif cmd == "!werewolf" and len(parts) > 1 and parts[1].lower() == "stop":
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only a chan-op can stop the game.")
            await self.stop_session(session.key)

        elif cmd == "!wvote" and phase == "day":
            if nick not in players or not players[nick].alive:
                return await self.notice(nick, "You're not an alive player.")
            if len(parts) < 2:
                return await self.notice(nick, "Usage: !wvote <nick>")
            target = parts[1]
            if target not in players or not players[target].alive:
                return await self.notice(nick, f"{target} is not an alive player.")
            if target == nick:
                return await self.notice(nick, "You can't vote for yourself.")
            session.data["votes"][nick] = target
            tally     = self._vote_tally(session)
            tally_str = "  ".join(f"{t}:{v}" for t, v in sorted(tally.items(), key=lambda x: -x[1]))
            await self.say(chan, f"[Werewolf] {nick} votes for {target}.  [{tally_str}]")

        elif cmd == "!wunvote" and phase == "day":
            if nick in session.data["votes"]:
                del session.data["votes"][nick]
                await self.say(chan, f"[Werewolf] {nick} removed their vote.")

        elif cmd == "!wstats":
            if self._on_cooldown(chan, "wstats"):
                return
            alive = [n for n, p in players.items() if p.alive]
            dead  = [n for n, p in players.items() if not p.alive]
            await self.say(chan,
                f"[Werewolf] Day {session.data['day']} | Phase: {phase} | "
                f"Alive ({len(alive)}): {', '.join(alive) or 'none'} | "
                f"Dead: {', '.join(dead) or 'none'}"
            )

        elif cmd == "!whelp":
            if not self._on_cooldown(chan, "whelp"):
                await self._show_help(chan)

    async def on_NOTICE(self, session: GameSession, nick: str, text: str, event=None):
        """Handle night-action notices sent directly to the bot."""
        parts   = text.strip().split()
        if not parts:
            return
        cmd     = parts[0].lower()
        players = session.data["players"]
        phase   = session.data.get("phase", "")

        if phase != "night":
            return
        if nick not in players or not players[nick].alive:
            return

        p = players[nick]

        if cmd == "!wkill" and p.role == WEREWOLF:
            if "kill" in session.data["actions_done"]:
                return await self.notice(nick, "Kill already decided for tonight.")
            if len(parts) < 2:
                return await self.notice(nick, "Usage: !wkill <nick>")
            target           = parts[1]
            alive_non_wolves = [n for n, pl in players.items()
                                if pl.alive and n not in session.data["wolves"]]
            if target not in alive_non_wolves:
                return await self.notice(nick, f"{target} is not a valid target.")
            session.data["night_kill"] = target
            session.data["actions_done"].add("kill")
            # Notify the whole pack
            for w in session.data["wolves"]:
                if players[w].alive:
                    await self.notice(w, f"[Werewolf] Pack decision: kill {target} tonight.")

        elif cmd == "!wsee" and p.role == SEER:
            if "see" in session.data["actions_done"]:
                return await self.notice(nick, "You've already used your power tonight.")
            if len(parts) < 2:
                return await self.notice(nick, "Usage: !wsee <nick>")
            target = parts[1]
            if target not in players or not players[target].alive or target == nick:
                return await self.notice(nick, f"{target} is not a valid target.")
            session.data["night_see"] = target
            session.data["actions_done"].add("see")
            await self.notice(nick, f"[Werewolf] Investigating {target}…")

        elif cmd == "!wsave" and p.role == DOCTOR:
            if "save" in session.data["actions_done"]:
                return await self.notice(nick, "You've already used your power tonight.")
            if len(parts) < 2:
                return await self.notice(nick, "Usage: !wsave <nick>")
            target = parts[1]
            if target not in players or not players[target].alive:
                return await self.notice(nick, f"{target} is not a valid target.")
            session.data["night_save"] = target
            session.data["actions_done"].add("save")
            await self.notice(nick, f"[Werewolf] You protect {target} tonight.")

    async def _show_help(self, chan: str):
        self._set_cooldown(chan, "whelp")
        lines = [
            "[Werewolf] Commands:",
            "  !werewolf          - Start a new game",
            "  !wjoin             - Join during registration",
            "  !wstart            - Op: force-start now",
            "  !wvote <nick>      - Vote to lynch (day phase)",
            "  !wunvote           - Remove your vote",
            "  !wstats            - Show alive/dead players",
            "  !werewolf stop     - Op: end the game",
            "  Night actions (NOTICE to bot):",
            "  !wkill <nick>      - Werewolf: kill target",
            "  !wsee  <nick>      - Seer: investigate",
            "  !wsave <nick>      - Doctor: protect",
        ]
        for line in lines:
            await self.say(chan, line)

    async def _save_stats(self, nick: str, won: bool):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                "INSERT INTO werewolf_stats(nick, games_played, wins) VALUES(?,1,?) "
                "ON CONFLICT(nick) DO UPDATE SET "
                "games_played=games_played+1, "
                "wins=wins+?, "
                "updated_at=strftime('%s','now')",
                (nick, int(won), int(won))
            )

    def _on_cooldown(self, chan: str, cmd: str) -> bool:
        now  = time.monotonic()
        last = self._cmd_cooldowns.setdefault(chan, {}).get(cmd, 0)
        if now - last < CMD_COOLDOWN_SECS:
            return True
        self._cmd_cooldowns[chan][cmd] = now
        return False

    def _set_cooldown(self, chan: str, cmd: str):
        self._cmd_cooldowns.setdefault(chan, {})[cmd] = time.monotonic()

    async def say(self, target: str, msg: str):
        await self.send_privmsg(target, msg)

    async def notice(self, nick: str, msg: str):
        await self.send_notice(nick, msg)
