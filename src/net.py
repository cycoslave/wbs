# src/net.py
"""
WBS network listener + connection admission control.
"""
import asyncio
import fnmatch
import ipaddress
import json
import logging
import multiprocessing as mp
import socket
import ssl as ssl_lib
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("wbs.net")

@dataclass
class _BlockEntry:
    ip:         str
    reason:     str  = "manual"
    added_by:   str  = "system"
    added_at:   int  = field(default_factory=lambda: int(time.time()))
    expires_at: int  = 0              # 0 = permanent
    note:       str  = ""

    def is_expired(self) -> bool:
        return self.expires_at != 0 and time.time() > self.expires_at

@dataclass
class _FailureRecord:
    count:    int   = 0
    first_at: float = field(default_factory=time.time)
    last_at:  float = field(default_factory=time.time)

class AccessGuard:
    """
    IP-level admission controller for the partyline / botlink listener.

    Modes (config['partyline']['access_mode']):

      blacklist (default)
        All IPs allowed unless explicitly blocked.
        Auto-blocks after max_failures failed auth attempts.
        Operators can manually add/remove entries via partyline commands.

      whitelist
        Only IPs whose reverse-hostname matches a known hostmask in the
        users or bots table are admitted.  Everything else is dropped at
        TCP accept time before any data is read.
        Auto-block on auth failure still applies.

    Blocklist entries are persisted to `net_blocklist` so bans
    survive restarts.  In-memory dict is the hot path for every decision.
    """

    def __init__(self, db_path: str, config: dict) -> None:
        self.db_path = db_path
        cfg = config.get("settings", {}) 

        self.mode = cfg.get("access_mode", "blacklist").lower()
        self.max_failures = int(cfg.get("max_failures", 5))
        self.lockout_seconds = int(cfg.get("lockout_seconds", 300))
        self.max_connections = int(cfg.get("max_connections", 10))

        self._blocklist: dict[str, _BlockEntry]    = {}  # ip → entry
        self._failures:  dict[str, _FailureRecord] = {}  # ip → record (ephemeral)
        self._active:    dict[str, int]            = {}  # ip → open conn count
        self._loaded = False

    async def load(self) -> None:
        """Load persisted blocklist from DB.  Call once at startup."""
        from .db import get_db
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT ip, reason, added_by, added_at, expires_at, note "
                "FROM net_blocklist"
            )
        now = int(time.time())
        count = 0
        for row in rows:
            entry = _BlockEntry(
                ip=row["ip"], reason=row["reason"],
                added_by=row["added_by"], added_at=row["added_at"],
                expires_at=row["expires_at"], note=row["note"],
            )
            if entry.expires_at == 0 or entry.expires_at > now:
                self._blocklist[row["ip"]] = entry
                count += 1
        self._loaded = True
        log.info(f"AccessGuard: loaded {count} blocklist entries (mode={self.mode})")

    async def admit(self, ip: str) -> tuple[bool, str]:
        """
        Called at TCP accept time — before any data is read.
        Returns (allowed, reason_string).
        """
        if not self._loaded:
            await self.load()

        if sum(self._active.values()) >= self.max_connections:
            return False, "Connection limit reached"

        entry = self._blocklist.get(ip)
        if entry:
            if entry.is_expired():
                await self._remove_from_blocklist(ip, reason="expired")
            else:
                log.warning(f"AccessGuard: DENY {ip} — blocklisted ({entry.reason})")
                return False, "Connection refused"

        if self.mode == "whitelist":
            if not await self._whitelist_check(ip):
                log.warning(f"AccessGuard: DENY {ip} — not in whitelist")
                return False, "Connection refused"

        self._active[ip] = self._active.get(ip, 0) + 1
        return True, "ok"

    def release(self, ip: str) -> None:
        """Decrement active connection count.  Call when any connection closes."""
        if ip in self._active:
            self._active[ip] = max(0, self._active[ip] - 1)
            if self._active[ip] == 0:
                del self._active[ip]

    async def record_failure(self, ip: str, handle: str = "") -> None:
        """Record a failed auth attempt; auto-block after threshold."""
        rec = self._failures.setdefault(ip, _FailureRecord())
        rec.count  += 1
        rec.last_at = time.time()
        log.warning(
            f"AccessGuard: auth failure from {ip}"
            + (f" (handle={handle!r})" if handle else "")
            + f" [{rec.count}/{self.max_failures}]"
        )
        if rec.count >= self.max_failures:
            expires = (int(time.time()) + self.lockout_seconds
                       if self.lockout_seconds > 0 else 0)
            await self.block(
                ip=ip, reason="auth_failure", added_by="system",
                expires_at=expires,
                note=f"Auto-blocked after {rec.count} failures"
                     + (f"; last handle: {handle}" if handle else ""),
            )
            del self._failures[ip]

    def record_success(self, ip: str) -> None:
        """Clear failure counter on successful auth."""
        self._failures.pop(ip, None)

    async def block(
        self,
        ip: str,
        reason:     str = "manual",
        added_by:   str = "operator",
        expires_at: int = 0,
        note:       str = "",
    ) -> None:
        """Block an IP and persist to DB.  Accepts hostname — resolves to IP."""
        ip = _resolve_to_ip(ip)
        if ip is None:
            log.error("AccessGuard.block: could not resolve address")
            return
        entry = _BlockEntry(
            ip=ip, reason=reason, added_by=added_by,
            added_at=int(time.time()), expires_at=expires_at, note=note,
        )
        self._blocklist[ip] = entry
        await self._persist(entry)
        log.info(
            f"AccessGuard: BLOCKED {ip} reason={reason} "
            f"expires={expires_at or 'never'} by={added_by}"
        )

    async def unblock(self, ip: str, removed_by: str = "operator") -> bool:
        """Remove an IP from the blocklist.  Returns True if it was present."""
        ip = _resolve_to_ip(ip) or ip
        if ip not in self._blocklist:
            return False
        await self._remove_from_blocklist(ip, reason=f"removed by {removed_by}")
        return True

    def list_blocked(self) -> list[_BlockEntry]:
        """Return all non-expired blocklist entries."""
        return [e for e in self._blocklist.values() if not e.is_expired()]

    async def _whitelist_check(self, ip: str) -> bool:
        """
        Reverse-resolve IP → hostname, then fnmatch against the host
        portion of every mask in users + bots tables.
        """
        from .db import get_db

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, socket.gethostbyaddr, ip
            )
            resolved_host = result[0]
        except (socket.herror, socket.gaierror):
            resolved_host = ip

        candidates = {ip, resolved_host}

        async with get_db(self.db_path) as db:
            user_rows = await db.execute_fetchall(
                "SELECT hostmasks FROM users WHERE deleted_at IS NULL"
            )
            bot_rows = await db.execute_fetchall(
                "SELECT hostmasks FROM bots"
            )

        masks: list[str] = []
        for row in (*user_rows, *bot_rows):
            raw = row["hostmasks"]
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except (ValueError, TypeError):
                parsed = [raw]
            for mask in parsed:
                # Extract host portion from nick!user@host
                host_part = mask.split("@")[-1] if "@" in mask else mask
                masks.append(host_part)

        return any(
            fnmatch.fnmatch(candidate, mask)
            for candidate in candidates
            for mask in masks
        )

    async def _persist(self, entry: _BlockEntry) -> None:
        from .db import get_db
        async with get_db(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO net_blocklist
                    (ip, reason, added_by, added_at, expires_at, note)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason     = excluded.reason,
                    added_by   = excluded.added_by,
                    added_at   = excluded.added_at,
                    expires_at = excluded.expires_at,
                    note       = excluded.note
                """,
                (entry.ip, entry.reason, entry.added_by,
                 entry.added_at, entry.expires_at, entry.note),
            )

    async def _remove_from_blocklist(self, ip: str, reason: str = "") -> None:
        self._blocklist.pop(ip, None)
        from .db import get_db
        async with get_db(self.db_path) as db:
            await db.execute(
                "DELETE FROM net_blocklist WHERE ip = ?", (ip,)
            )
        log.info(f"AccessGuard: UNBLOCKED {ip} ({reason})")


def _resolve_to_ip(host: str) -> Optional[str]:
    """Return the IP string for a given hostname or IP.  None on failure."""
    try:
        ipaddress.ip_address(host)
        return host                          # already an IP
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)    # resolve hostname → IP
    except socket.gaierror:
        return None

class NetListener:
    """
    Async TCP server for the partyline / botlink port.

    Instantiate with an AccessGuard to enable admission control.
    Without a guard, all connections are passed through (dev mode).
    """

    def __init__(
        self,
        core_q:       mp.Queue,
        config:       dict         = None,
        access_guard: AccessGuard  = None,
    ) -> None:
        self.core_q          = core_q
        self.config          = config or {}
        self.guard           = access_guard
        self.server          = None
        self._pending_streams: dict = {}   # handle.lower() → (reader, writer)

    def _build_ssl_context(self) -> ssl_lib.SSLContext | None:
        """Build server-side TLS context, or None if disabled."""
        cfg = self.config.get("settings", {})
        if not cfg.get("ssl", False):
            return None
        certfile = cfg.get("certfile")
        keyfile  = cfg.get("keyfile")
        if not certfile or not keyfile:
            log.warning("SSL enabled but certfile/keyfile missing — falling back to plaintext")
            return None
        ctx = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl_lib.TLSVersion.TLSv1_2   # no TLS 1.0/1.1
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        ctx.verify_mode = ssl_lib.CERT_NONE
        log.info(f"TLS enabled (cert={certfile}, min=TLSv1.2)")
        return ctx

    async def listen(self) -> None:
        """
        Bind and serve.
        listen_host: '' or absent → '0.0.0.0'.  Use '127.0.0.1' for loopback-only.
        listen_port: default 3333.
        """
        cfg  = self.config.get("settings", {})
        host = cfg.get("listen_host") or "0.0.0.0"
        port = int(cfg.get("listen_port", 3333))

        ssl_ctx = self._build_ssl_context()
        self.server = await asyncio.start_server(
            self.handle_connection, host, port, ssl=ssl_ctx
        )
        mode = "TLS" if ssl_ctx else "plaintext"
        log.info(f"Net listening on {host}:{port} ({mode})")
        async with self.server:
            await self.server.serve_forever()

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer    = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"

        if self.guard:
            allowed, reason = await self.guard.admit(peer_ip)
            if not allowed:
                log.warning(f"NetListener: rejected {peer_ip} — {reason}")
                try:
                    writer.write(f"ERROR :{reason}\r\n".encode())
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()
                return

        cfg = self.config.get("settings", {})
        timeout = float(cfg.get("handshake_timeout", 30))
        try:
            data = await asyncio.wait_for(reader.read(4096), float(timeout))
            line = data.decode("utf-8", errors="ignore").strip()

            if line.startswith("BOTLINK"):
                await self._handle_botlink(line, peer, peer_ip, reader, writer)
            else:
                await self._handle_partyline(line, peer, peer_ip, reader, writer)
            return  # streams handed off — do NOT release guard or close

        except asyncio.TimeoutError:
            log.warning(f"Handshake timeout from {peer_ip}")
        except ssl_lib.SSLError as e:
            log.error(f"TLS handshake failed from {peer_ip}: {e}")
        except Exception as e:
            log.error(f"Connection error from {peer_ip}: {e}")

        # Only reached on error — release slot and close
        if self.guard:
            self.guard.release(peer_ip)
        writer.close()
        await writer.wait_closed()

    async def _handle_botlink(
        self,
        line:    str,
        peer:    tuple,
        peer_ip: str,
        reader:  asyncio.StreamReader,
        writer:  asyncio.StreamWriter,
    ) -> None:
        parts = line.split()
        if len(parts) >= 4:
            remote_handle = parts[1]
            subnet_id     = int(parts[3])
            log.info(f"Botlink from {remote_handle} ({peer_ip})")
            # Store FIRST, then notify — prevents race in on_bot_connect
            self._pending_streams[remote_handle.lower()] = (reader, writer)
            self.core_q.put_nowait({
                "type":      "BOT_CONNECT",
                "handle":    remote_handle,
                "peer":      peer,
                "peer_ip":   peer_ip,
                "subnet_id": subnet_id,
                "data":      line,
            })
        else:
            log.warning(f"Invalid BOTLINK from {peer_ip}: {line!r}")
            if self.guard:
                self.guard.release(peer_ip)
            writer.close()
            await writer.wait_closed()

    async def _handle_partyline(
        self,
        line:    str,
        peer:    tuple,
        peer_ip: str,
        reader:  asyncio.StreamReader,
        writer:  asyncio.StreamWriter,
    ) -> None:
        handle = f"user_{peer_ip}_{peer[1]}"
        log.info(f"Partyline connect: {handle}")
        self._pending_streams[handle.lower()] = (reader, writer)
        self.core_q.put_nowait({
            "type":      "PARTYLINE_CONNECT",
            "handle":    handle,
            "peer":      peer,
            "peer_ip":   peer_ip,
            "firstline": line,
        })