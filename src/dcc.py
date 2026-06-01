"""
src/dcc.py

DCC CHAT manager — firewall-friendly implementation.

Three connection modes (auto-negotiated):
  1. Active DCC   — bot opens listening socket, advertises IP:port  (classic eggdrop)
  2. Passive DCC  — bot sends CTCP "DCC CHAT chat 0 0 <token>",
                    user's client calls back; bot never needs a public port for listen
                    (RFC-compatible with mIRC/HexChat passive DCC)
  3. IRC fallback — full partyline session over PRIVMSG/NOTICE for clients
                    behind symmetric NAT where DCC is simply impossible

Flow:
  - User sends  /ctcp botnick DCC CHAT chat <ip> <port>   → Active request (user wants bot to connect to them) — NOT STANDARD but we support it
  - User sends  /dcc chat botnick                          → irc.py on_ctcp fires DCC_CHAT_REQUEST
  - Core routes DCC_CHAT_REQUEST → dcc.DCCManager.handle_request()
  - DCCManager picks mode, negotiates, registers session with partyline
"""
import asyncio
import logging
import socket
import struct
import time
import random
import string
from typing import Optional, Dict

log = logging.getLogger("wbs.dcc")

ACTIVE_LISTEN_TIMEOUT   = 60   # seconds to wait for user to connect (active mode)
PASSIVE_CONNECT_TIMEOUT = 60   # seconds to wait for user's client to call back
SESSION_IDLE_TIMEOUT    = 300  # seconds of silence before auto-disconnect

def _ip_to_int(ip: str) -> int:
    """Convert dotted-decimal IP to 32-bit int for DCC CTCP."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def _int_to_ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))

def _random_token(length: int = 12) -> str:
    """12 digits = 1 trillion combinations, negligible collision risk."""
    return ''.join(random.choices(string.digits, k=length))

class DCCSession:
    """
    Represents one active DCC CHAT session with a user.
    Registered as a 'dcc' session in Partyline.
    """

    def __init__(self, session_id: int, nick: str,
                 reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 partyline):
        self.session_id = session_id
        self.nick       = nick
        self.reader     = reader
        self.writer     = writer
        self.partyline  = partyline
        self._closed    = False
        self._last_activity = time.time()

    async def send(self, text: str):
        """Send a line to the DCC peer."""
        if self._closed:
            return
        try:
            self.writer.write((text + "\r\n").encode("utf-8", errors="replace"))
            await self.writer.drain()
            self._last_activity = time.time()
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            log.warning(f"[DCC] Send error to {self.nick}: {e}")
            await self.close()

    async def recv_loop(self):
        """Read lines from peer and forward to partyline."""
        try:
            while not self._closed:
                line = await asyncio.wait_for(
                    self.reader.readline(),
                    timeout=SESSION_IDLE_TIMEOUT
                )
                if not line:
                    log.info(f"[DCC] {self.nick} closed connection.")
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    self._last_activity = time.time()
                    await self.partyline.handle_input(self.session_id, text)
        except asyncio.TimeoutError:
            log.info(f"[DCC] {self.nick} idle timeout.")
        except Exception as e:
            log.warning(f"[DCC] recv_loop error ({self.nick}): {e}")
        finally:
            await self.close()

    async def close(self):
        self._closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        self.partyline.unregister_session(self.session_id)
        log.info(f"[DCC] Session closed: {self.nick} (sid={self.session_id})")

class DCCManager:
    """
    Owned by Core.  Handles incoming DCC CHAT negotiations from irc.py events
    and manages active DCC sessions.

    Config keys (under config['dcc']):
        enabled         bool    — master switch (default: True)
        mode            str     — 'auto' | 'active' | 'passive' | 'irc'
                                  auto = try active, fall back to passive
        public_ip       str     — override detected IP (useful behind NAT)
        port_min        int     — port range for active listen (default: 1024)
        port_max        int     — port range for active listen (default: 65535)
        max_sessions    int     — concurrent DCC sessions cap (default: 10)
        listen_ip       str     — interface to bind the active DCC listener (default: '0.0.0.0' — all interfaces)
    """

    def __init__(self, core):
        self.core       = core
        self.cfg        = core.config.get('dcc', {})
        self.settings   = core.config.get('settings', {})
        self.enabled    = self.cfg.get('enabled', True)
        self.mode       = self.cfg.get('mode', 'auto')
        self.public_ip  = self.cfg.get('public_ip') or None
        self.port_min   = int(self.cfg.get('port_min', 1024))
        self.port_max   = int(self.cfg.get('port_max', 65535))
        self.max_sessions = int(self.cfg.get('max_sessions', 10))
        self.listen_ip  = self.settings.get('listen_host') or '0.0.0.0'

        self._passive_pending: Dict[str, dict] = {}
        self._sessions: Dict[int, DCCSession] = {}
        self._passive_server: Optional[asyncio.AbstractServer] = None
        self._passive_port: Optional[int] = None

    async def handle_request(self, nick: str, host: str, ctcp_args: list):
        """
        Called by Core when irc.py emits a DCC_CHAT event.

        ctcp_args from `DCC CHAT chat <ip_int> <port>` → ['CHAT', 'chat', '<ip>', '<port>']
        or from user typing /dcc chat botnick (empty args) → ['CHAT']
        """
        if not self.enabled:
            log.debug("[DCC] DCC disabled, ignoring request.")
            return

        if len(self._sessions) >= self.max_sessions:
            await self._irc_notice(nick, "DCC: too many sessions, try again later.")
            return

        # Parse optional reverse-DCC fields sent by user's client
        # Standard: DCC CHAT chat <ip_as_int> <port>
        user_ip   = None
        user_port = None
        if len(ctcp_args) >= 4:
            try:
                user_ip   = _int_to_ip(int(ctcp_args[2]))
                user_port = int(ctcp_args[3])
            except (ValueError, OSError):
                pass

        mode = self.mode
        if mode == 'auto':
            mode = 'active' if self.public_ip else 'passive'

        log.info(f"[DCC] Incoming request from {nick} — negotiating mode={mode}")

        if mode == 'active':
            await self._negotiate_active(nick, user_ip, user_port)
        elif mode == 'passive':
            await self._negotiate_passive(nick)
        else:
            # IRC-fallback: open a partyline session right now, no socket
            await self._open_irc_fallback(nick)

    async def on_passive_callback(self, nick: str, token: str,
                                  user_ip_int: int, user_port: int):
        """
        Called by Core when user's client sends:
            CTCP DCC CHAT chat <ip> <port> <token>
        confirming a passive session we initiated.
        """
        entry = self._passive_pending.pop(token, None)
        if not entry:
            log.warning(f"[DCC] Unknown passive token {token!r} from {nick}")
            return
        if entry['nick'] != nick:
            log.warning(f"[DCC] Token nick mismatch: expected {entry['nick']}, got {nick}")
            return

        user_ip = _int_to_ip(user_ip_int)
        log.info(f"[DCC] Passive callback from {nick} → {user_ip}:{user_port}")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(user_ip, user_port),
                timeout=PASSIVE_CONNECT_TIMEOUT
            )
            await self._open_session(nick, reader, writer)
        except asyncio.TimeoutError:
            log.warning(f"[DCC] Passive connect timeout to {nick} ({user_ip}:{user_port})")
        except OSError as e:
            log.warning(f"[DCC] Passive connect failed to {nick}: {e}")
            await self._irc_notice(nick, f"DCC connect failed: {e}")

    async def _negotiate_active(self, nick: str,
                                 reverse_ip: Optional[str] = None,
                                 reverse_port: Optional[int] = None):
        """
        Active DCC: bot opens a listening socket and advertises IP:port via CTCP.
        If reverse_ip/port were supplied, the *user* is offering a reverse DCC —
        we connect to them instead (uncommon but supported by some clients).
        """
        # User offered reverse DCC (they have a listener) — connect to them
        if reverse_ip and reverse_port:
            log.info(f"[DCC] Reverse-DCC: connecting to {nick} at {reverse_ip}:{reverse_port}")
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(reverse_ip, reverse_port),
                    timeout=PASSIVE_CONNECT_TIMEOUT
                )
                await self._open_session(nick, reader, writer)
            except Exception as e:
                log.warning(f"[DCC] Reverse-DCC connect failed: {e}")
                await self._irc_notice(nick, f"DCC connect failed: {e}")
            return

        # Standard active: bot listens, advertises
        if not self.public_ip:
            log.warning("[DCC] No public IP; falling back to passive.")
            await self._negotiate_passive(nick)
            return

        port = await self._find_free_port()
        if port is None:
            await self._irc_notice(nick, "DCC: no free port available.")
            return

        server = await asyncio.start_server(
            lambda r, w: asyncio.create_task(self._accept_active(nick, r, w, server)),
            self.listen_ip, port
        )

        ip_int = _ip_to_int(self.public_ip)
        ctcp_msg = f"\x01DCC CHAT chat {ip_int} {port}\x01"
        await self._irc_ctcp(nick, ctcp_msg)
        log.info(f"[DCC] Sent active offer to {nick}: {self.public_ip}:{port}")

        # Timeout watchdog
        async def _timeout_watchdog():
            await asyncio.sleep(ACTIVE_LISTEN_TIMEOUT)
            log.info(f"[DCC] Active listen timeout for {nick}, closing server.")
            server.close()
            await server.wait_closed()

        asyncio.create_task(_timeout_watchdog())

    async def _accept_active(self, nick: str,
                              reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter,
                              server: asyncio.AbstractServer):
        """Accept the single connection from the user in active mode."""
        server.close()
        await server.wait_closed()
        peer = writer.get_extra_info('peername')
        log.info(f"[DCC] Active connection from {nick} ({peer})")
        await self._open_session(nick, reader, writer)

    async def _negotiate_passive(self, nick: str):
        """
        Passive/Reverse DCC (RFC extension):
        Bot sends: CTCP DCC CHAT chat 0 0 <token>
        User's client then opens a socket and sends back:
            CTCP DCC CHAT chat <real_ip_int> <real_port> <token>
        Bot connects outbound to the user.

        This works even when the bot is behind NAT — *user* opens the port.
        """
        token = _random_token()
        self._passive_pending[token] = {'nick': nick, 'ts': time.time()}

        ctcp_msg = f"\x01DCC CHAT chat 0 0 {token}\x01"
        await self._irc_ctcp(nick, ctcp_msg)
        log.info(f"[DCC] Sent passive offer to {nick} (token={token})")

        # Expire the token after timeout
        async def _expire():
            await asyncio.sleep(PASSIVE_CONNECT_TIMEOUT)
            if self._passive_pending.pop(token, None):
                log.info(f"[DCC] Passive token {token} expired for {nick}")

        asyncio.create_task(_expire())

    async def _open_irc_fallback(self, nick: str):
        """
        IRC-fallback: open a full partyline session that communicates
        entirely over PRIVMSG/NOTICE instead of a raw TCP socket.
        The DCCIRCSession handles I/O via the IRC queue.
        """
        log.info(f"[DCC] Opening IRC-fallback session for {nick}")
        session = DCCIRCSession(nick, self.core)
        session_id = self.core.partyline.register_remote(
            'dcc-irc', nick, session.response_queue
        )
        session.session_id = session_id
        self._sessions[session_id] = session   # type: ignore[assignment]
        await self._irc_notice(
            nick,
            "DCC not available — starting IRC-based partyline session. "
            "Type '.quit' to exit."
        )
        asyncio.create_task(session.recv_loop())

    async def _open_session(self, nick: str, host: str,
                            reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter):
        user_mgr = self.core.partyline.user
        user = await user_mgr.get_by_host(f"{nick}!{host}")   # hostmask-aware lookup
        if not user:
            log.warning(f"[DCC] Rejected unmatched host: {nick}!{host}")
            try:
                writer.write(b"Access denied.\r\n")
                await writer.drain()
                writer.close()
            except Exception:
                pass
            return

        q = asyncio.Queue()
        session_id = self.core.partyline.register_remote('dcc', nick, q)
        session = DCCSession(session_id, nick, reader, writer, self.core.partyline, q)
        self._sessions[session_id] = session
        session.reader   = reader
        session.writer   = writer
        session.nick     = nick
        session._closed  = False
        session._last_activity = time.time()

        # Use a multiprocessing-safe queue shim (partyline expects queue-like obj)
        import asyncio as _aio
        session._queue = _aio.Queue()

        session_id = self.core.partyline.register_remote(
            'dcc', nick, session._queue
        )
        session.session_id = session_id
        session.partyline  = self.core.partyline
        self._sessions[session_id] = session

        await session.send(
            f"[WBS {self.core.botname}] DCC CHAT connected. "
            f"Type .help for commands, .quit to disconnect."
        )
        log.info(f"[DCC] Session opened: {nick} (sid={session_id})")

        # Drain the asyncio queue → writer (partyline → DCC socket bridge)
        asyncio.create_task(self._queue_drain(session))
        asyncio.create_task(session.recv_loop())

    async def _queue_drain(self, session: DCCSession):
        """Forward partyline messages from queue → DCC socket."""
        q = session._queue
        while not session._closed:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=5)
                if msg:
                    text = msg.get('text', '')
                    if text:
                        await session.send(text)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.warning(f"[DCC] queue_drain error: {e}")
                break

    async def _find_free_port(self) -> Optional[int]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._find_free_port_sync)

    def _find_free_port_sync(self) -> Optional[int]:
        ports = list(range(self.port_min, self.port_max + 1))
        random.shuffle(ports)
        for port in ports[:50]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind((self.listen_ip, port))
                    return port
                except OSError:
                    continue
        return None

    async def _irc_ctcp(self, nick: str, message: str):
        """Send raw CTCP — bypass clean_message which strips \x01."""
        self.core.irc_q.put_nowait({
            'cmd': 'raw',
            'line': f"PRIVMSG {nick} :{message}"
        })

    async def _irc_notice(self, nick: str, text: str):
        """Send a plain NOTICE to a nick."""
        self.core.irc_q.put_nowait({'cmd': 'notice', 'target': nick, 'text': text})

class DCCIRCSession:
    """
    A pseudo-DCC session that runs entirely over IRC PRIVMSG/NOTICE.
    Used when both active and passive DCC fail (symmetric NAT, etc.).
    Partyline sees it as a normal 'dcc-irc' remote session.
    """

    def __init__(self, nick: str, core):
        self.nick        = nick
        self.core        = core
        self.session_id  = None
        self.response_queue = asyncio.Queue()
        self._closed     = False

    async def recv_loop(self):
        while not self._closed:
            try:
                msg = await asyncio.wait_for(self.response_queue.get(), timeout=5)
                if msg:
                    text = msg.get('text', '')
                    if text:
                        self.core.irc_q.put_nowait({
                            'cmd': 'notice', 'target': self.nick, 'text': text
                        })
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.warning(f"[DCC-IRC] recv_loop error: {e}")
                break
        await self.close()

    async def close(self):
        self._closed = True
        if self.session_id is not None:
            self.core.partyline.unregister_session(self.session_id)
            log.info(f"[DCC-IRC] Session closed: {self.nick} (sid={self.session_id})")