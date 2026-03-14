# src/games/duckhunt.py
"""
Just a small duck hunting game.
"""
import asyncio
import random
import time
from typing import Optional

from src.games import Game, GameSession

class DuckHunt(Game):
    name = "duckhunt"
    scopes = {"channel"}
    allow_multiple_sessions = False

    async def load(self):
        self.log.info("DuckHunt loaded")

    async def unload(self):
        await super().unload()
        self.log.info("DuckHunt unloaded")

    async def start_session(self, session: GameSession):
        session.data.setdefault("min_delay", 180)
        session.data.setdefault("max_delay", 7200)
        session.data.setdefault("duck_timeout", 7200)
        session.data.setdefault("reload_time", 2.0)
        session.data.setdefault("duck_up", False)
        session.data.setdefault("duck_time", 0.0)
        session.data.setdefault("scores", {})
        session.data.setdefault("quickest", None)
        session.data.setdefault("longest", None)
        session.data.setdefault("last_shot", {})
        session.data.setdefault("consecutive_misses", 0)
        session.data.setdefault("lock", asyncio.Lock())

        await super().start_session(session)

        await self.send_privmsg(
            session.target,
            "DuckHunt started. Wait for a duck, then use !bang",
        )

        session.task = asyncio.create_task(self._hunt_loop(session))

    async def stop_session(self, key: str):
        session = self.sessions.get(key)
        if session:
            await self.send_privmsg(session.target, "DuckHunt stopped.")
        await super().stop_session(key)

    async def handle_command(
        self,
        session: GameSession,
        nick: str,
        command: str,
        args: list[str],
        event: Optional[dict] = None,
    ):
        command = command.lower()

        if command == "bang":
            await self._bang(session, nick)
            return

        if command in {"duckstats", "duckscores"}:  # Instead of score,scores,stats
            await self._show_scores(session)
            return

        if command == "duckstatus":
            min_delay = session.data.get("min_delay", 20)
            max_delay = session.data.get("max_delay", 60)
            duck_up = session.data["duck_up"]
            misses = session.data.get("consecutive_misses", 0)
            
            status = "duck UP!" if duck_up else "no duck"
            quiet = " (quiet after 2 misses)" if misses >= 2 else f" ({misses} misses)"
            
            next_range = f"{min_delay/60:.0f}-{max_delay/3600:.1f}h"
            await self.send_privmsg(
                session.target, 
                f"Ducks: {status}{quiet}. Next possible in ~{next_range}"
            )
            return

        if command == "duckset" and args:
            param, value = args[0].lower(), int(args[1])
            if param == "timeout":
                session.data["duck_timeout"] = value
                await self.send_privmsg(session.target, f"Duck timeout: {value//3600}h")

        if command == "duckhelp":
            await self.send_privmsg(
                session.target,
                "DuckHunt: !bang (shoot), !duckstats (scores), !duckstatus (info), !duckhelp"
            )
            return

        await self.send_notice(nick, f"Unknown duckhunt command: {command}")

    async def _hunt_loop(self, session: GameSession):
        try:
            while True:
                delay = random.randint(
                    int(session.data["min_delay"]),
                    int(session.data["max_delay"]),
                )
                await asyncio.sleep(delay)

                if session.key not in self.sessions or session.state != "running":
                    return

                if session.data["duck_up"]:
                    continue

                session.data["duck_up"] = True
                session.data["duck_time"] = time.monotonic()

                duck_msg = random.choice([
                    "・゜゜・。。・゜゜\\_o< QUACK!",
                    "・゜゜・。。・゜゜\\_O< FLAP FLAP!",
                    "・゜゜・。。・゜゜\\_0< quack!",
                ])
                await self.send_privmsg(session.target, duck_msg)

                base_timeout = float(session.data["duck_timeout"])
                duck_timeout = random.uniform(base_timeout * 0.5, base_timeout * 1.5)
                await asyncio.sleep(float(session.data["duck_timeout"]))

                if session.key not in self.sessions or session.state != "running":
                    return

                if session.data["duck_up"]:
                    session.data["duck_up"] = False
                    session.data["consecutive_misses"] += 1  # Track miss
                    await self.send_privmsg(session.target, "Duck flew away after hours...")
                    
                    if session.data["consecutive_misses"] >= 2:
                        break_min = 8 * 3600   # 8 hours
                        break_max = 24 * 3600  # 24 hours
                        break_time = random.randint(break_min, break_max)
                        hours = break_time // 3600
                        mins = (break_time % 3600) // 60
                        #await self.send_privmsg(session.target, f"Ducks quiet after misses. Break ~{break_time//60} min.")
                        await asyncio.sleep(break_time)
                        session.data["consecutive_misses"] = 0  # Reset

                if session.key not in self.sessions or session.state != "running":
                    return

                if session.data["duck_up"]:
                    session.data["duck_up"] = False
                    await self.send_privmsg(session.target, "The duck got away...")
        except asyncio.CancelledError:
            raise

    async def _bang(self, session: GameSession, nick: str):
        async with session.data["lock"]:
            now = time.monotonic()
            last_shot = session.data["last_shot"].get(nick.lower(), 0.0)
            reload_time = float(session.data["reload_time"])

            if now - last_shot < reload_time:
                remain = reload_time - (now - last_shot)
                await self.send_notice(nick, f"Reloading... {remain:.1f}s left")
                return

            session.data["last_shot"][nick.lower()] = now
            scores = session.data["scores"]

            if not session.data["duck_up"]:
                scores[nick.lower()] = scores.get(nick.lower(), 0) - 1
                await self.send_privmsg(
                    session.target,
                    f"{nick} fires wildly at nothing and loses a point. "
                    f"Score: {scores[nick.lower()]}",
                )
                return

            reaction = now - float(session.data["duck_time"])
            session.data["duck_up"] = False

            scores[nick.lower()] = scores.get(nick.lower(), 0) + 1

            quickest = session.data["quickest"]
            longest = session.data["longest"]

            if quickest is None or reaction < quickest[1]:
                session.data["quickest"] = (nick, reaction)

            if longest is None or reaction > longest[1]:
                session.data["longest"] = (nick, reaction)

            session.data["consecutive_misses"] = 0

            await self.send_privmsg(
                session.target,
                f"{nick} got the duck in {reaction:.3f}s! "
                f"Score: {scores[nick.lower()]}",
            )

    async def _show_scores(self, session: GameSession):
        scores = session.data["scores"]
        if not scores:
            await self.send_privmsg(session.target, "No duck scores yet.")
            return

        top = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        score_line = ", ".join(f"{nick}:{score}" for nick, score in top)

        extra = []
        if session.data["quickest"]:
            qnick, qtime = session.data["quickest"]
            extra.append(f"quickest={qnick} {qtime:.3f}s")
        if session.data["longest"]:
            lnick, ltime = session.data["longest"]
            extra.append(f"longest={lnick} {ltime:.3f}s")

        suffix = f" ({', '.join(extra)})" if extra else ""
        await self.send_privmsg(session.target, f"Duck scores: {score_line}{suffix}")

    async def on_PUBMSG(self, session: GameSession, nick: str, text: str, event=None):
        command = text.strip().lower()
        if command == '!bang':
            await self._bang(session, nick)
        elif command == '!duckstats':
            await self._show_scores(session)
        elif command == '!duckstatus':
            min_delay = session.data.get("min_delay", 20)
            max_delay = session.data.get("max_delay", 60)
            duck_up = session.data["duck_up"]
            misses = session.data.get("consecutive_misses", 0)
            
            status = "duck UP!" if duck_up else "no duck"
            quiet = " (quiet after 2 misses)" if misses >= 2 else f" ({misses} misses)"
            
            next_range = f"{min_delay/60:.0f}-{max_delay/3600:.1f}h"
            await self.send_privmsg(
                session.target, 
                f"Ducks: {status}{quiet}. Next possible in ~{next_range}"
            )
            return
        elif command == '!duckhelp':
            await self.send_privmsg(session.target, "DuckHunt: !bang, !duckstats, !duckstatus, !duckhelp")