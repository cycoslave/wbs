# src/console.py
"""Non-blocking console for asyncio main process"""
import asyncio
import sys
import logging
from typing import Optional
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.history import InMemoryHistory

log = logging.getLogger("wbs.console")

class Console:
    def __init__(self, partyline: "Partyline", session_id: int, handle: str = "console") -> None:
        self.partyline = partyline
        self.session_id = session_id
        self.handle = handle
        self.running = True
        self._stop_event = asyncio.Event()
        self.session = PromptSession(history=InMemoryHistory())
        self._error_count = 0
        self._max_errors = 5

    async def run(self) -> None:
        """Directly calls partyline.handle_input for input processing."""
        if not sys.stdin.isatty():
            log.warning("No TTY available for console")
            return

        print(f"{self.handle}> Type .help for commands, .exit to quit.")

        with patch_stdout():
            while self.running and not self._stop_event.is_set():
                try:
                    line = await self.session.prompt_async(f"{self.handle}> ")
                    stripped = line.strip()
                    if not stripped:
                        continue

                    # Local .exit — no flag check required for console operator
                    if stripped.lower() == ".exit":
                        print("Closing console session. Bot continues running.")
                        log.info("Console .exit received")
                        self.partyline.unregister_session(self.session_id)
                        self.running = False
                        break

                    self._error_count = 0  # reset on successful input
                    await self.partyline.handle_input(self.session_id, stripped)

                except (EOFError, KeyboardInterrupt):
                    log.info("Console exit signal received (EOF/Ctrl+C)")
                    self.running = False
                    # Signal the bot to shut down — same as .quit via partyline
                    await self.partyline.handle_input(self.session_id, ".quit")
                    break

                except Exception as e:
                    self._error_count += 1
                    log.error("Console error (%d/%d): %s", self._error_count, self._max_errors, e)
                    if self._error_count >= self._max_errors:
                        log.critical("Console exceeded max consecutive errors — stopping console")
                        self.running = False
                        break
                    await asyncio.sleep(0.1)

        log.info("Console session ended")

    async def stop(self) -> None:
        """Externally stop the console (e.g., called by core.py on shutdown)."""
        self.running = False
        self._stop_event.set()