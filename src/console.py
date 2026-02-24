# src/console.py
"""Non-blocking console for asyncio main process"""

import asyncio
import sys
import select
import logging
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.history import InMemoryHistory

log = logging.getLogger(__name__)

class Console:
    def __init__(self, partyline, session_id, handle='console'):
        self.partyline = partyline
        self.session_id = session_id
        self.handle = handle
        self.running = True
        self.session = PromptSession(history=InMemoryHistory())
        
    async def run(self):
        """Directly calls partyline.handle_input for input processing."""
        if not sys.stdin.isatty():
            log.warning("No TTY available for console")
            return
        log.info("Type .help for commands. Ctrl+C to quit.")
        with patch_stdout():
            while self.running:
                try:
                    line = await self.session.prompt_async(f"{self.handle}> ")
                    if line.strip():
                        await self.partyline.handle_input(self.session_id, line.strip())
                except (EOFError, KeyboardInterrupt):
                    log.info("Console exit signal received")
                    self.running = False
                    break
                except Exception as e:
                    log.error(f"Console error: {e}")
                    await asyncio.sleep(0.1)
        log.info("Console session ended")
        
        log.info("Console session ended")
