# src/console.py
"""Non-blocking console for asyncio main process"""

import asyncio
import sys
import select
import logging

logger = logging.getLogger(__name__)

class ConsoleTask:
    def __init__(self, command_queue):
        self.command_queue = command_queue
        self.running = True
        
    async def run(self):
        """Non-blocking console task"""
        if not sys.stdin.isatty():
            logger.warning("No TTY available for console")
            return
            
        logger.info("Console active. Type .help for commands. Ctrl+C to quit.")
        
        loop = asyncio.get_event_loop()
        
        while self.running:
            try:
                # Non-blocking stdin check
                ready, _, _ = select.select([sys.stdin], [], [], 0)
                if ready:
                    line = sys.stdin.readline().strip()
                    if line:
                        # Send to core via queue
                        await self.command_queue.put({
                            'source': 'console',
                            'user': 'console',
                            'command': line
                        })
                
                await asyncio.sleep(0.01)  # Yield to event loop
                
            except KeyboardInterrupt:
                logger.info("Console: Ctrl+C received")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Console error: {e}")
                await asyncio.sleep(0.1)
