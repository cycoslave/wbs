# src/session.py
"""
Handles partyline sessions for WBS.
"""
import asyncio
import multiprocessing as mp
import logging
import sys
from typing import Optional, Union

logger = logging.getLogger(__name__)


class Session:
    """partyline session - handles console/telnet/DCC"""
    
    def __init__(
        self,
        session_id: int,
        session_type: str,  # 'console', 'telnet', 'dcc'
        handle: str,
        core_q: mp.Queue,
        response_q=None, 
        **transports
    ):
        self.session_id = session_id
        self.session_type = session_type
        self.handle = handle
        self.core_q = core_q
        self.running = True
        self.responseq = response_q or mp.Queue()
        
        # Transport-specific storage
        self.reader = transports.get('reader')
        self.writer = transports.get('writer')
        self.dcc = transports.get('dcc_session')
        self.prompt_session = None
        
        # Initialize console if needed
        if session_type == 'console':
            from prompt_toolkit import PromptSession
            self.prompt_session = PromptSession()
    
    async def send(self, message: str) -> None:
        """Unified send: console print, telnet/DCC write."""
        try:
            if self.session_type == 'console':
                print(message, flush=True)
            elif self.session_type in ('telnet', 'socket') and self.writer:
                self.writer.write(f"{message}\n".encode())
                await self.writer.drain()
            elif self.session_type == 'dcc' and self.dcc:
                await self.dcc.send(message)
        except Exception as e:
            logger.error(f"Send error {self.session_type}: {e}")
    
    async def receive(self) -> Optional[str]:
        """Abstraction layer - receive from appropriate transport"""
        try:
            if self.session_type == 'console':
                if self.prompt_session:
                    return await self.prompt_session.prompt_async(f"{self.handle}> ")
            
            elif self.session_type in ('telnet', 'socket'):
                if self.reader:
                    data = await self.reader.readline()
                    if not data:
                        return None
                    return data.decode('utf-8', errors='ignore').strip()
            
            elif self.session_type == 'dcc':
                if self.dcc:
                    return await self.dcc.receive()
        
        except (EOFError, KeyboardInterrupt):
            return None
        except Exception as e:
            logger.error(f"Receive error ({self.session_type}): {e}")
            return None
    
    async def close(self) -> None:
        """Unified close (no partyline logic here)."""
        try:
            if self.session_type in ('telnet', 'socket') and self.writer:
                self.writer.close()
                await self.writer.wait_closed()
            elif self.session_type == 'dcc' and self.dcc:
                await self.dcc.close()
        except Exception as e:
            logger.error(f"Close error {self.session_type}: {e}")
    
    async def run(self):
        """Main session loop - works for all transport types"""
        logger.info(f"Partyline session {self.session_id} ({self.session_type}) started: {self.handle}")
        
        # Welcome message
        await self.send(f"Welcome to WBS partyline, {self.handle}!")
        await self.send("Type .help for commands, .quit to exit")
        
        # Start response listener
        response_task = asyncio.create_task(self._handle_responses())
        
        try:
            # Main input loop
            while self.running:
                line = await self.receive()
                
                if line is None:  # Connection closed
                    break
                
                if not line.strip():
                    continue
                
                # Handle .quit
                if line.strip() == '.quit':
                    await self.send("Goodbye!")
                    break
                
                # Send to core for processing
                self.core_q.put_nowait({
                    'type': 'PARTYLINE_INPUT',
                    'session_id': self.session_id,
                    'handle': self.handle,
                    'text': line.strip()
                })
        
        except Exception as e:
            logger.error(f"Session {self.session_id} error: {e}")
        
        finally:
            response_task.cancel()
            await self.close()
            
            # Notify core of disconnect
            self.core_q.put_nowait({
                'type': 'PARTYLINE_DISCONNECT',
                'session_id': self.session_id
            })
            
            logger.info(f"Session {self.session_id} closed")
    
    async def _handle_responses(self):
        """Poll response_q and send via transport"""
        while self.running:
            try:
                try:
                    msg = self.response_q.get_nowait()
                    await self.send(msg['text'])
                except:
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Response handler error: {e}")
