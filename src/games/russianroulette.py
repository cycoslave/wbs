# src/games/russianroulette.py
"""
WBS Game: russianroulette.py
version: 0.1.0
by: cyco
Description: Russian Roulette for WBS.
             Players join a round, the bot loads a 6-chamber revolver with 1 bullet,
             then players take turns using !pull. One player dies; all survivors get 1 point.
             Scores are persisted per channel for leaderboard tracking.

Flow:
  Partyline: .gstart russianroulette channel #chan  → makes game available (idle)
  In-channel:
    !rrstart               - Open a round for players to join.
    !rrjoin                - Join the current round.
    !rrpull                - Pull the trigger on your turn.
    !rrstats [nick]        - Show stats.
    !rrtop                 - Top 5 scores.
    !rrhelp                - Show commands.
    !rrstop                - Chan-op ends the game.
"""
import asyncio
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from . import Game, GameSession
from ..db import get_db

REGISTRATION_SECS = 45
REGISTRATION_WARN = 15
TURN_SECS = 30
MIN_PLAYERS = 2
CMD_COOLDOWN_SECS = 120

@dataclass
class RRPlayer:
    nick: str
    alive: bool = True

class RussianRouletteGame(Game):
    name = "russianroulette"
    version = "0.1.0"
    scopes = {"channel"}

    TABLE_SQL = [
        """
        CREATE TABLE IF NOT EXISTS russianroulette_settings (
            channel       TEXT    PRIMARY KEY,
            turn_secs     INTEGER DEFAULT 30,
            updated_at    INTEGER DEFAULT (strftime('%s','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS russianroulette_scores (
            channel       TEXT    NOT NULL,
            nick          TEXT    NOT NULL,
            points        INTEGER NOT NULL DEFAULT 0,
            wins          INTEGER NOT NULL DEFAULT 0,
            deaths        INTEGER NOT NULL DEFAULT 0,
            rounds        INTEGER NOT NULL DEFAULT 0,
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
            await db.execute(self.TABLE_SQL[0])
            await db.execute(self.TABLE_SQL[1])
            await db.commit()
        self.log.info(f"Game {self.name} {self.version} loaded")

    async def unload(self):
        await super().unload()
        self.log.info(f"Game {self.name} {self.version} unloaded")

    async def start_session(self, session: GameSession, restore: bool = False):
        chan = session.target
        session.data["cfg"] = await self._load_settings(chan)
        session.data["phase"] = "idle"
        session.data["players"] = {}
        session.data["order"] = []
        session.data["turn_index"] = 0
        session.data["bullet_chamber"] = None
        session.data["current_chamber"] = 0
        session.data["current_player"] = None
        session.data["turn_done"] = None
        await super().start_session(session)
        if not restore:
            await self.say(
                chan,
                "\x02[Russian Roulette]\x02 Game is available. "
                "Type \x02!rrstart\x02 to open a round."
            )

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.say(session.target, "[Russian Roulette] Table closed.")
        await super().stop_session(key)

    async def _registration_phase(self, session: GameSession):
        try:
            await asyncio.sleep(REGISTRATION_SECS - REGISTRATION_WARN)
            await self.say(
                session.target,
                f"[Russian Roulette] \x02{REGISTRATION_WARN}s left\x02 to join! "
                "Type \x02!rrjoin\x02."
            )
            await asyncio.sleep(REGISTRATION_WARN)
        except asyncio.CancelledError:
            return
        await self._begin_round(session)

    async def _begin_round(self, session: GameSession):
        chan = session.target
        players: Dict[str, RRPlayer] = session.data["players"]

        if len(players) < MIN_PLAYERS:
            await self.say(chan, "[Russian Roulette] Not enough players. Round cancelled.")
            session.data["phase"] = "idle"
            session.task = None
            return

        order = list(players.keys())
        random.shuffle(order)

        session.data["order"] = order
        session.data["turn_index"] = 0
        session.data["bullet_chamber"] = random.randint(0, 5)
        session.data["current_chamber"] = 0
        session.data["phase"] = "playing"

        await self.say(
            chan,
            f"[Russian Roulette] \x02{len(order)}\x02 players: {', '.join(order)}"
        )
        await self.say(
            chan,
            "[Russian Roulette] The revolver has \x026 chambers\x02. "
            "One round is loaded. Cylinder spun."
        )

        await self._play_round(session)

    async def _play_round(self, session: GameSession):
        chan = session.target
        cfg = session.data["cfg"]
        players: Dict[str, RRPlayer] = session.data["players"]
        order: List[str] = session.data["order"]

        while True:
            alive_order = [nick for nick in order if players[nick].alive]
            if len(alive_order) <= 1:
                break

            if session.data["turn_index"] >= len(order):
                session.data["turn_index"] = 0

            nick = order[session.data["turn_index"]]
            if not players[nick].alive:
                session.data["turn_index"] += 1
                continue

            session.data["current_player"] = nick
            session.data["turn_done"] = asyncio.Event()

            await self.say(
                chan,
                f"[Russian Roulette] \x02{nick}\x02's turn. "
                f"Type \x02!pull\x02 within {cfg['turn_secs']}s."
            )

            try:
                await asyncio.wait_for(
                    session.data["turn_done"].wait(),
                    timeout=cfg["turn_secs"]
                )
            except asyncio.TimeoutError:
                await self.say(
                    chan,
                    f"  {nick} hesitated... the bot pulls for them."
                )
                await self._do_pull(session, nick)

            session.data["turn_index"] += 1

        await self._finish_round(session)

    async def _do_pull(self, session: GameSession, nick: str):
        chan = session.target
        players: Dict[str, RRPlayer] = session.data["players"]

        bullet = session.data["bullet_chamber"]
        chamber = session.data["current_chamber"]

        if chamber == bullet:
            players[nick].alive = False
            await self.say(
                chan,
                f"  \x034BANG!\x03 \x02{nick}\x02 dies."
            )
            session.data["phase"] = "finished"
            if session.data.get("turn_done") and not session.data["turn_done"].is_set():
                session.data["turn_done"].set()
            return

        await self.say(
            chan,
            f"  \x0303CLICK\x03... {nick} survives."
        )
        session.data["current_chamber"] += 1
        if session.data.get("turn_done") and not session.data["turn_done"].is_set():
            session.data["turn_done"].set()

    async def _finish_round(self, session: GameSession):
        chan = session.target
        players: Dict[str, RRPlayer] = session.data["players"]
        survivors = [p.nick for p in players.values() if p.alive]
        dead = [p.nick for p in players.values() if not p.alive]

        await self.say(chan, "[Russian Roulette] ── Results ──")

        for nick, p in players.items():
            await self._record_round(chan, nick, survived=p.alive)

        if dead:
            await self.say(chan, f"  Dead: {', '.join(dead)}")
        if survivors:
            await self.say(
                chan,
                f"  Survivors (+1 point): {', '.join(survivors)}"
            )

        session.data["players"] = {}
        session.data["order"] = []
        session.data["turn_index"] = 0
        session.data["bullet_chamber"] = None
        session.data["current_chamber"] = 0
        session.data["current_player"] = None
        session.data["turn_done"] = None
        session.data["phase"] = "finished"
        session.task = None

        await self.say(
            chan,
            "[Russian Roulette] Round over. "
            "\x02!rrstart\x02 to play again  |  "
            "\x02!rrstop\x02 to end."
        )

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        parts = text.strip().split()
        if not parts:
            return

        cmd = parts[0].lower()
        chan = session.target
        phase = session.data.get("phase", "idle")
        players: Dict[str, RRPlayer] = session.data["players"]

        if cmd == "!rrstart" and phase in ("idle", "finished"):
            session.data["players"] = {}
            session.data["order"] = []
            session.data["phase"] = "registering"

            if nick not in players:
                players[nick] = RRPlayer(nick=nick)
                await self.say(
                    chan,
                    f"[Russian Roulette] {nick} opened the round and joined."
                )

            await self.say(
                chan,
                f"[Russian Roulette] Registration open for {REGISTRATION_SECS}s. "
                "Type \x02!rrjoin\x02 to play."
            )
            session.task = asyncio.create_task(self._registration_phase(session))
            return

        elif cmd == "!rrstart" and phase == "registering":
            if not self.core.nick_isop(nick, chan) and nick not in players:
                return await self.notice(
                    nick,
                    "Only a joined player or chan-op can start immediately."
                )
            if session.task and not session.task.done():
                session.task.cancel()
            await self._begin_round(session)
            return

        elif cmd == "!rrjoin":
            if phase != "registering":
                return await self.notice(nick, "No registration is open right now.")
            if nick in players:
                return await self.notice(nick, "You're already in this round.")
            players[nick] = RRPlayer(nick=nick)
            await self.say(chan, f"[Russian Roulette] {nick} joins the round.")
            return

        elif cmd == "!rrpull":
            if phase != "playing":
                return await self.notice(nick, "No active turn right now.")
            if session.data.get("current_player") != nick:
                return
            await self._do_pull(session, nick)
            return

        elif cmd == "!rrstop":
            if not self.core.nick_isop(nick, chan):
                return await self.notice(nick, "Only a chan-op can stop the game.")
            await self.stop_session(session.key)
            return

        elif cmd == "!rrstats":
            target = parts[1] if len(parts) > 1 else nick
            await self._show_stats(chan, target)
            return

        elif cmd == "!rrtop":
            if not self._on_cooldown(chan, "rrtop"):
                await self._show_top(chan)
            return

        elif cmd == "!rrhelp":
            if not self._on_cooldown(chan, "rrhelp"):
                await self._show_help(chan)
            return

    async def _record_round(self, channel: str, nick: str, survived: bool):
        async with get_db(self.core.db_path) as db:
            await db.execute(
                """
                INSERT INTO russianroulette_scores(channel, nick, points, wins, deaths, rounds)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(channel, nick) DO UPDATE SET
                    points = russianroulette_scores.points + excluded.points,
                    wins   = russianroulette_scores.wins + excluded.wins,
                    deaths = russianroulette_scores.deaths + excluded.deaths,
                    rounds = russianroulette_scores.rounds + excluded.rounds,
                    updated_at = strftime('%s','now')
                """,
                (
                    channel,
                    nick,
                    1 if survived else 0,
                    1 if survived else 0,
                    0 if survived else 1,
                    1,
                ),
            )
            await db.commit()

    async def _show_stats(self, chan: str, nick: str):
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                """
                SELECT points, wins, deaths, rounds
                FROM russianroulette_scores
                WHERE channel=? AND nick=?
                """,
                (chan, nick),
            ) as cur:
                row = await cur.fetchone()

        if not row:
            return await self.say(chan, f"[Russian Roulette] No stats yet for {nick}.")

        await self.say(
            chan,
            f"[Russian Roulette] {nick}: "
            f"{row['points']} pts, {row['wins']} survived, "
            f"{row['deaths']} died, {row['rounds']} rounds."
        )

    async def _show_top(self, chan: str):
        self._set_cooldown(chan, "rrtop")
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                """
                SELECT nick, points, wins, deaths, rounds
                FROM russianroulette_scores
                WHERE channel=?
                ORDER BY points DESC, wins DESC, rounds DESC
                LIMIT 5
                """,
                (chan,),
            ) as cur:
                rows = await cur.fetchall()

        if not rows:
            return await self.say(chan, "[Russian Roulette] No score records yet.")

        board = "  ".join(
            f"{i + 1}. {r['nick']} {r['points']}pts"
            for i, r in enumerate(rows)
        )
        await self.say(chan, f"[Russian Roulette] Top survivors: {board}")

    async def _show_help(self, chan: str):
        self._set_cooldown(chan, "rrhelp")
        await self.say(chan, "[Russian Roulette] commands:")
        await self.say(chan, "    !rrstart            - Open a round and auto-join.")
        await self.say(chan, "    !rrjoin      - Join the current round.")
        await self.say(chan, "    !rrpull               - Pull the trigger on your turn.")
        await self.say(chan, "    !rrstats [nick]     - Show stats.")
        await self.say(chan, "    !rrtop              - Top 5 scores.")
        await self.say(chan, "    !rrstop      - Owner or chan-op ends the game.")

    async def _load_settings(self, channel: str) -> dict:
        async with get_db(self.core.db_path) as db:
            async with db.execute(
                "SELECT * FROM russianroulette_settings WHERE channel=?",
                (channel,),
            ) as cur:
                row = await cur.fetchone()

        if row:
            return {"turn_secs": row["turn_secs"]}

        return {"turn_secs": TURN_SECS}

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