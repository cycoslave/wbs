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
        """Detect botlink vs partyline → route to core_q with DUP FD or picklable data."""
        peer = writer.get_extra_info('peername')
        logger.info(f"Incoming {peer}")
        
        try:
            data = await asyncio.wait_for(reader.readline(), 30.0)
            line = data.decode('utf-8', errors='ignore').strip()

            logger.info(f"RAW firstline: {repr(data)}")
            logger.info(f"LINE firstline: '{line}' (len={len(line)})")
            
            if line.startswith('BOTLINK'):
                # Botnet link → DUP FD to core for full control
                parts = line.split()
                if len(parts) >= 3:
                    remotehandle = parts[1]
                    logger.info(f"Botlink from {remotehandle}")
                    
                    # DUP FD → core handles link entirely
                    orig_sock = writer.transport.get_extra_info('socket')
                    sockfd = orig_sock.fileno()
                    dup_fd = os.dup(sockfd)
                    
                    self.core_q.put_nowait({
                        'type': 'BOTLINK_CONNECT', 
                        'handle': remotehandle,
                        'peer': peer,
                        'firstline': line,
                        'sockfd': dup_fd
                    })
                else:
                    logger.warning(f"Invalid BOTLINK from {peer}: {line}")
            else:
                # Partyline user → picklable data only (no FD)
                handle = f"user_{peer[0]}_{peer[1]}"
                logger.info(f"Partyline user: {handle}")
                
                orig_sock = writer.transport.get_extra_info('socket')
                sockfd = orig_sock.fileno()
                dup_fd = os.dup(sockfd)

                self.core_q.put_nowait({
                    'type': 'PARTYLINE_CONNECT',
                    'handle': f"user_{peer[0]}_{peer[1]}",
                    'peer': peer,
                    'firstline': line,
                    'sockfd': dup_fd
                })
                
        except asyncio.TimeoutError:
            logger.warning(f"Handshake timeout {peer}")
        except Exception as e:
            logger.error(f"Connection error {peer}: {e}")
        finally:
            # Always close original in net process
            logger.debug(f"Net closing original for {peer}")
            writer.close()
            await writer.wait_closed()