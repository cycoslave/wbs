# src/console.py
"""Non-blocking console for asyncio main process"""

import asyncio
import sys
import select
import logging
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.history import InMemoryHistory

logger = logging.getLogger(__name__)

class ConsoleTask:
    def __init__(self, partyline_hub, session_id, handle='console'):
        self.partyline_hub = partyline_hub
        self.session_id = session_id
        self.handle = handle
        self.running = True
        self.session = PromptSession(history=InMemoryHistory())
        
    async def run(self):
        """Non-blocking console task"""
        if not sys.stdin.isatty():
            logger.warning("No TTY available for console")
            return
            
        logger.info("Console active. Type .help for commands. Ctrl+C to quit.")
        
        with patch_stdout():
            while self.running:
                try:
                    line = await self.session.prompt_async(f"{self.handle}> ")
                    
                    if line.strip():
                        await self.partyline_hub.handle_input(
                            self.session_id,
                            line.strip()
                        )
                
                except (EOFError, KeyboardInterrupt):
                    logger.info("Console: Exit signal received")
                    self.running = False
                    break
                    
                except Exception as e:
                    logger.error(f"Console error: {e}")
                    await asyncio.sleep(0.1)
        
        logger.info("Console session ended")
