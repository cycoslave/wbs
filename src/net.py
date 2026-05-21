# src/net.py
"""
Handle network connections for WBS.
"""
import asyncio
import os
import ssl as ssl_lib
import multiprocessing as mp
import logging

log = logging.getLogger("wbs.net")

class NetListener:
    def __init__(self, core_q: mp.Queue, config: dict = None):
        self.core_q = core_q
        self.config = config or {}
        self.server = None
    
    def _build_ssl_context(self) -> ssl_lib.SSLContext | None:
        """Build server-side TLS context from config['settings'], or None if disabled."""
        cfg = self.config.get('settings', {})
        if not cfg.get('ssl', False):
            return None

        certfile = cfg.get('certfile')
        keyfile  = cfg.get('keyfile')
        if not certfile or not keyfile:
            log.warning("SSL enabled but certfile/keyfile missing — falling back to plaintext")
            return None

        ctx = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        ctx.verify_mode = ssl_lib.CERT_NONE
        log.info(f"TLS enabled (cert={certfile})")
        return ctx

    async def listen(self, host: str = '0.0.0.0', port: int = 3333):
        """Listen → DUP FD → core_q (no close!)."""
        ssl_ctx = self._build_ssl_context()
        self.server = await asyncio.start_server(
            self.handle_connection, host, port, ssl=ssl_ctx
        )
        mode = "TLS" if ssl_ctx else "plaintext"
        log.info(f"Net listening on {host}:{port} ({mode})")
        async with self.server:
            await self.server.serve_forever()

    async def handle_connection(self, reader, writer):
        """Detect botlink vs partyline → route to core_q with DUP FD or picklable data."""
        peer = writer.get_extra_info('peername')
        orig_sock = writer.transport.get_extra_info('socket')
        sockfd = orig_sock.fileno()
        dup_fd = os.dup(orig_sock.fileno())
        log.debug(f"Incoming {peer}")

        try:
            data = await asyncio.wait_for(reader.readline(), 30.0)
            line = data.decode('utf-8', errors='ignore').strip()

            if line.startswith('BOTLINK'):
                parts = line.split()
                if len(parts) >= 3:
                    remote_handle = parts[1]
                    log.info(f"Botlink from {remote_handle}")
                    self.core_q.put_nowait({
                        'type': 'BOT_CONNECT',
                        'handle': remote_handle,
                        'peer': peer,
                        'data': line,
                        'sockfd': dup_fd
                    })
                else:
                    log.warning(f"Invalid BOTLINK from {peer}: {line}")
            else:
                handle = f"user_{peer[0]}_{peer[1]}"
                log.info(f"Partyline user: {handle}")
                self.core_q.put_nowait({
                    'type': 'PARTYLINE_CONNECT',
                    'handle': handle,
                    'peer': peer,
                    'firstline': line,
                    'sockfd': dup_fd
                })

        except asyncio.TimeoutError:
            log.warning(f"Handshake timeout {peer}")
            os.close(dup_fd)
        except ssl_lib.SSLError as e:
            log.error(f"TLS handshake failed from {peer}: {e}")
            os.close(dup_fd)
        except Exception as e:
            log.error(f"Connection error {peer}: {e}")
            os.close(dup_fd)
        finally:
            log.debug(f"Net closing original for {peer}")
            writer.close()
            await writer.wait_closed()