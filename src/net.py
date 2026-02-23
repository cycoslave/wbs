# src/net.py
"""
Handle network connections for WBS.
"""
import asyncio
import os
import multiprocessing as mp
import logging

logger = logging.getLogger(__name__)

class NetListener:
    def __init__(self, core_q: mp.Queue):  # core_q direct!
        self.core_q = core_q
        self.server = None
    
    async def listen(self, host: str = '0.0.0.0', port: int = 3333):
        """Listen → DUP FD → core_q (no close!)."""
        self.server = await asyncio.start_server(self.handle_connection, host, port)
        logger.info(f"Net listening on {host}:{port}")
        async with self.server:
            await self.server.serve_forever()
    
    async def handle_connection(self, reader, writer):
        """DUP FD → core_q immediately."""
        peer = writer.get_extra_info('peername')
        logger.info(f"Net incoming {peer}")
        try:
            data = await asyncio.wait_for(reader.readline(), 30.0)
            line = data.decode('utf-8', errors='ignore').strip()
            
            # DUP FD (core gets independent copy)
            orig_sock = writer.transport.get_extra_info('socket')
            sockfd = orig_sock.fileno()
            dup_fd = os.dup(sockfd)
            
            logger.info(f"DUP fd {dup_fd} (orig {sockfd}) → core for {peer}")
            
            # DIRECT TO CORE
            self.core_q.put_nowait({
                'type': 'PARTYLINE_CONNECT',
                'handle': f"user_{peer[0]}_{peer[1]}",
                'peer': peer,
                'firstline': line,
                'sockfd': dup_fd
            })

            logger.debug(f"Net closing original sock {sockfd} for {peer}")
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            logger.warning(f"Timeout {peer}")
        except Exception as e:
            logger.error(f"Net handoff failed {peer}: {e}")
        # NO close() - server owns writer forever