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
import re
import socket
import ssl as ssl_lib
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .db import get_db
from .user import UserManager
from .helper import _resolve_to_ip

log = logging.getLogger("wbs.net")
PER_IP_MAX = 3
_HANDLE_MAX_LEN  = 64
_HANDLE_RE       = re.compile(r"^[A-Za-z0-9_\-\.]{1,64}$")
_LINE_MAX_BYTES  = 512

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
        Only IPs that match a known hostmask (by IP or reverse-hostname)
        in the users or bots table are admitted.  Everything else is dropped
        at TCP accept time before any data is read.
        Auto-block on auth failure still applies.

    Blocklist entries are persisted to `net_blocklist` so bans
    survive restarts.  In-memory dict is the hot path for every decision.

    Auth failure counts are also persisted so counter survives restarts.
    """

    def __init__(self, db_path: str, config: dict) -> None:
        self.db_path = db_path
        cfg = config.get("settings", config)
        self.mode            = cfg.get("access_mode", "blacklist").lower()
        self.max_failures    = int(cfg.get("max_failures", 5))
        self.lockout_seconds = int(cfg.get("lockout_seconds", 300))
        self.max_connections = int(cfg.get("max_connections", 50))
        self._blocklist: dict[str, _BlockEntry]    = {}   # ip → entry
        self._failures:  dict[str, _FailureRecord] = {}   # ip → record
        self._active:    dict[str, int]            = {}   # ip → open conn count
        self._loaded = False

    async def load(self) -> None:
        """Load persisted blocklist and failure counts from DB.  Call once at startup."""
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT ip, reason, added_by, added_at, expires_at, note "
                "FROM net_blocklist"
            )
        now   = int(time.time())
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

        async with get_db(self.db_path) as db:
            fail_rows = await db.execute_fetchall(
                "SELECT ip, count, first_at, last_at FROM net_auth_failures"
            )
        for row in fail_rows:
            self._failures[row["ip"]] = _FailureRecord(
                count=row["count"],
                first_at=row["first_at"],
                last_at=row["last_at"],
            )

        self._loaded = True
        log.info(
            "AccessGuard: loaded %d blocklist entries, %d failure records (mode=%s)",
            count, len(self._failures), self.mode,
        )

    async def admit(self, ip: str) -> tuple[bool, str]:
        """
        Called at TCP accept time — before any data is read.
        Returns (allowed, reason_string).
        """
        if not self._loaded:
            await self.load()

        ip_count = self._active.get(ip, 0)
        if ip_count >= PER_IP_MAX:
            log.warning("AccessGuard: DENY %s — per-IP limit (%d)", ip, PER_IP_MAX)
            return False, "Connection refused"

        if sum(self._active.values()) >= self.max_connections:
            return False, "Connection refused"

        entry = self._blocklist.get(ip)
        if entry:
            if entry.is_expired():
                await self._remove_from_blocklist(ip, reason="expired")
            else:
                log.warning("AccessGuard: DENY %s — blocklisted (%s)", ip, entry.reason)
                return False, "Connection refused"

        if self.mode == "whitelist":
            if not await self._whitelist_check(ip):
                log.warning("AccessGuard: DENY %s — not in whitelist", ip)
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
        rec         = self._failures.setdefault(ip, _FailureRecord())
        rec.count  += 1
        rec.last_at = time.time()
        log.warning(
            "AccessGuard: auth failure from %s%s [%d/%d]",
            ip,
            f" (handle={handle!r})" if handle else "",
            rec.count, self.max_failures,
        )

        await self._persist_failure(ip, rec)

        if rec.count >= self.max_failures:
            expires = (int(time.time()) + self.lockout_seconds
                       if self.lockout_seconds > 0 else 0)
            await self.block(
                ip=ip, reason="auth_failure", added_by="system",
                expires_at=expires,
                note=f"Auto-blocked after {rec.count} failures"
                     + (f"; last handle: {handle}" if handle else ""),
            )
            self._failures.pop(ip, None)
            await self._delete_failure_record(ip)

    def record_success(self, ip: str) -> None:
        """Clear in-memory failure counter on successful auth."""
        self._failures.pop(ip, None)
        # DB cleanup is fire-and-forget; schedule as a task so we stay sync here
        asyncio.get_event_loop().create_task(self._delete_failure_record(ip))

    async def block(
        self,
        ip:         str,
        reason:     str = "manual",
        added_by:   str = "operator",
        expires_at: int = 0,
        note:       str = "",
    ) -> None:
        """Block an IP and persist to DB.  Accepts hostname — resolves to IP."""
        ip = await _resolve_to_ip(ip)
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
            "AccessGuard: BLOCKED %s reason=%s expires=%s by=%s",
            ip, reason, expires_at or "never", added_by,
        )

    async def unblock(self, ip: str, removed_by: str = "operator") -> bool:
        """Remove an IP from the blocklist.  Returns True if it was present."""
        ip = await _resolve_to_ip(ip) or ip
        if ip not in self._blocklist:
            return False
        await self._remove_from_blocklist(ip, reason=f"removed by {removed_by}")
        return True

    def list_blocked(self) -> list[_BlockEntry]:
        """Return all non-expired blocklist entries."""
        return [e for e in self._blocklist.values() if not e.is_expired()]

    async def _whitelist_check(self, ip: str) -> bool:
        """
        Check IP against known hostmasks in users + bots tables.

        Two-pass strategy (Issue #6):
          1. Direct IP match against CIDR ranges extracted from masks.
          2. Reverse-DNS hostname fnmatch (informational — PTR is attacker-
             controlled, so this pass alone is not authoritative).

        A connection is admitted only if at least the IP-based pass matches,
        OR both passes agree.  Pure PTR-only matches are logged but rejected.
        """
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            resolved_host = result[0]
        except (socket.herror, socket.gaierror):
            resolved_host = ip

        async with get_db(self.db_path) as db:
            user_rows = await db.execute_fetchall(
                "SELECT hostmasks FROM users WHERE deleted_at IS NULL"
            )
            bot_rows = await db.execute_fetchall(
                "SELECT hostmasks FROM bots"
            )

        ip_matched  = False
        ptr_matched = False

        try:
            check_ip = ipaddress.ip_address(ip)
        except ValueError:
            check_ip = None

        for row in (*user_rows, *bot_rows):
            raw = row["hostmasks"]
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except (ValueError, TypeError):
                parsed = [raw]
            for mask in parsed:
                host_part = mask.split("@")[-1] if "@" in mask else mask

                if check_ip is not None:
                    try:
                        net = ipaddress.ip_network(host_part, strict=False)
                        if check_ip in net:
                            ip_matched = True
                    except ValueError:
                        pass  # not a CIDR — fall through to fnmatch

                # PTR / wildcard fnmatch
                if fnmatch.fnmatch(resolved_host, host_part) or fnmatch.fnmatch(ip, host_part):
                    ptr_matched = True

        if ip_matched:
            return True
        if ptr_matched and not ip_matched:
            log.warning(
                "AccessGuard: whitelist PTR-only match for %s (resolved=%s) — REJECTED "
                "(PTR records are attacker-controlled; add a CIDR mask to allow this host)",
                ip, resolved_host,
            )
        return False

    async def _persist(self, entry: _BlockEntry) -> None:
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
        async with get_db(self.db_path) as db:
            await db.execute(
                "DELETE FROM net_blocklist WHERE ip = ?", (ip,)
            )
        log.info("AccessGuard: UNBLOCKED %s (%s)", ip, reason)

    async def _persist_failure(self, ip: str, rec: _FailureRecord) -> None:
        async with get_db(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO net_auth_failures (ip, count, first_at, last_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    count    = excluded.count,
                    last_at  = excluded.last_at
                """,
                (ip, rec.count, rec.first_at, rec.last_at),
            )

    async def _delete_failure_record(self, ip: str) -> None:
        async with get_db(self.db_path) as db:
            await db.execute(
                "DELETE FROM net_auth_failures WHERE ip = ?", (ip,)
            )

class NetListener:
    """
    Async TCP server for the partyline / botlink port.

    An AccessGuard MUST be provided in production.  Omitting it is only
    permitted when dev_mode=true is set in config — otherwise startup raises.
    """

    def __init__(
        self,
        core_q:       mp.Queue,
        config:       Optional[dict] = None,
        access_guard: Optional[AccessGuard] = None,
    ) -> None:
        self._pending_streams: dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self._stream_timestamps: dict[str, float] = {}   # Issue #3: TTL tracking
        self.core_q  = core_q
        self.config  = config or {}
        self.guard: Optional[AccessGuard] = access_guard
        self.server  = None

        cfg = self.config.get("settings", {})
        if access_guard is None and not cfg.get("dev_mode", False):
            raise RuntimeError(
                "NetListener requires an AccessGuard in production. "
                "Pass access_guard=... or set dev_mode=true in config to bypass (unsafe)."
            )
        if access_guard is None:
            log.warning(
                "NetListener: no AccessGuard — running in dev_mode with NO admission control!"
            )

    def _build_ssl_context(self) -> ssl_lib.SSLContext | None:
        """Build server-side TLS context, or None if SSL is disabled.

        Raises RuntimeError at startup if ssl=true but cert/key files are
        missing or fail to load.

        plaintext requires explicit allow_plaintext=true override.
        A security-first bot must never silently serve credentials over cleartext.
        """
        cfg = self.config.get("settings", {})
        if not cfg.get("ssl", False):
            if not cfg.get("allow_plaintext", False):
                raise RuntimeError(
                    "SSL is disabled but allow_plaintext=true is not set. "
                    "Configure ssl=true with cert/key paths, or explicitly set "
                    "allow_plaintext=true to accept the security risk."
                )
            log.warning(
                "NetListener: TLS is DISABLED and allow_plaintext=true is set. "
                "Credentials will be transmitted in cleartext — DO NOT use in production!"
            )
            return None

        certfile = cfg.get("certfile")
        keyfile  = cfg.get("keyfile")
        if not certfile or not keyfile:
            raise RuntimeError(
                "SSL is enabled but certfile and/or keyfile are not configured. "
                "Set ssl=false or provide valid cert/key paths in config."
            )
        ctx = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl_lib.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        except (ssl_lib.SSLError, FileNotFoundError, PermissionError) as exc:
            raise RuntimeError(
                f"SSL is enabled but cert/key failed to load "
                f"(cert={certfile!r}, key={keyfile!r}): {exc}"
            ) from exc
        log.info("TLS enabled (cert=%s, min=TLSv1.2)", certfile)
        return ctx

    async def listen(self) -> None:
        """
        Bind and serve.
        listen_host: '' or absent → '0.0.0.0'.  Use '127.0.0.1' for loopback-only.
        listen_port: default 3333.
        """
        cfg = self.config.get("settings", {})
        host = cfg.get("listen_host") or "0.0.0.0"
        port = int(cfg.get("listen_port", 3333))

        ssl_ctx = self._build_ssl_context()
        self.server = await asyncio.start_server(
            self.handle_connection, host, port, ssl=ssl_ctx
        )
        mode = "TLS" if ssl_ctx else "PLAINTEXT (allow_plaintext=true)"
        log.info("Net listening on %s:%d (%s)", host, port, mode)

        asyncio.get_running_loop().create_task(self._reap_pending_streams())

        async with self.server:
            await self.server.serve_forever()

    async def _reap_pending_streams(self) -> None:
        """
        Periodically close any _pending_streams entries that core never claimed.
        TTL: 60 seconds.  Prevents resource exhaustion from unanswered handshakes.
        """
        TTL = 60.0
        while True:
            await asyncio.sleep(30)
            now    = time.monotonic()
            stale  = [k for k, ts in self._stream_timestamps.items() if now - ts > TTL]
            for key in stale:
                streams = self._pending_streams.pop(key, None)
                self._stream_timestamps.pop(key, None)
                if streams:
                    _, writer = streams
                    log.warning("NetListener: reaping unclaimed stream key=%r", key)
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer    = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"
        release_on_exit = False
        handed_off      = False

        if self.guard:
            allowed, reason = await self.guard.admit(peer_ip)
            if not allowed:
                try:
                    writer.write(b"ERROR :Connection refused\r\n")
                    await writer.drain()
                except Exception:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                return
            release_on_exit = True

        cfg     = self.config.get("settings", {})
        timeout = float(cfg.get("handshake_timeout", 30))
        try:
            data = await asyncio.wait_for(
                reader.read(_LINE_MAX_BYTES), timeout
            )
            line = data.decode("utf-8", errors="ignore").split("\n")[0].strip()
            if not line:
                raise ValueError("Empty handshake line")

            if line.startswith("BOTLINK"):
                await self._handle_botlink(line, peer, peer_ip, reader, writer)
            else:
                await self._handle_partyline(line, peer, peer_ip, reader, writer)

            release_on_exit = False
            handed_off      = True

        except asyncio.TimeoutError:
            log.warning("Handshake timeout from %s", peer_ip)
        except Exception as e:
            log.error("Connection error from %s: %s", peer_ip, e)

        finally:
            if release_on_exit and self.guard:
                self.guard.release(peer_ip)
            if not handed_off:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _handle_botlink(
        self,
        line:      str,
        peer:      tuple,
        peer_ip:   str,
        reader:    asyncio.StreamReader,
        writer:    asyncio.StreamWriter,
    ) -> None:
        # TODO: PSK / cert auth challenge goes here before
        #       storing streams or queuing BOT_CONNECT.
        parts = line.split()
        if len(parts) >= 4:
            remote_handle = parts[1]
            try:
                subnet_id = int(parts[3])
            except ValueError:
                log.warning(
                    "Invalid BOTLINK subnet_id from %s: %r — defaulting to subnet 1",
                    peer_ip, line,
                )
                subnet_id = 1
            log.info("Botlink from %s (%s)", remote_handle, peer_ip)
            key = remote_handle.lower()
            self._pending_streams[key]     = (reader, writer)
            self._stream_timestamps[key]   = time.monotonic()
            self.core_q.put_nowait({
                "type":      "BOT_CONNECT",
                "handle":    remote_handle,
                "peer":      peer,
                "peer_ip":   peer_ip,
                "subnet_id": subnet_id,
                "data":      line,
            })
        else:
            log.warning("Invalid BOTLINK from %s: %r", peer_ip, line)
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
        if line.upper().startswith(("GET ", "POST ", "HEAD ", "OPTIONS ", "PUT ", "DELETE ")):
            log.info("HTTP probe from %s — dropped silently", peer_ip)
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        cfg     = self.config.get("settings", {})
        timeout = float(cfg.get("auth_timeout", 60))

        async def _readline() -> str:
            data = await asyncio.wait_for(reader.read(_LINE_MAX_BYTES), timeout)
            return data.decode("utf-8", errors="ignore").split("\n")[0].strip()

        try:
            raw_handle = line
            if not _HANDLE_RE.match(raw_handle):
                log.warning(
                    "Partyline: invalid handle characters from %s (len=%d)",
                    peer_ip, len(raw_handle),
                )
                writer.write(b"ERROR :Connection refused\r\n")
                await writer.drain()
                return

            handle = raw_handle
            writer.write(b"Password: ")
            await writer.drain()
            password = await _readline()
        except asyncio.TimeoutError:
            log.warning("Auth timeout from %s", peer_ip)
            writer.write(b"ERROR :Login timeout\r\n")
            await writer.drain()
            return

        authed = False
        try:
            async with get_db(self.db_path) as db:
                async with db.execute(
                    "SELECT password_hash, locked FROM users "
                    "WHERE handle = ? AND deleted_at IS NULL",
                    (handle,)
                ) as cursor:
                    row = await cursor.fetchone()
            if row and not row["locked"]:
                um     = UserManager(self.db_path)
                authed = um.verify_password(password, row["password_hash"])
        except Exception as e:
            log.error("Auth DB error for %r from %s: %s", handle, peer_ip, e)

        if not authed:
            if self.guard:
                await self.guard.record_failure(peer_ip, handle)
            log.warning("Failed partyline auth: handle=%r ip=%s", handle, peer_ip)
            writer.write(b"ERROR :Connection refused\r\n")
            await writer.drain()
            return

        if self.guard:
            self.guard.record_success(peer_ip)

        conn_id = str(uuid.uuid4())
        self._pending_streams[conn_id]   = (reader, writer)
        self._stream_timestamps[conn_id] = time.monotonic()
        self.core_q.put_nowait({
            "type":    "PARTYLINE_CONNECT",
            "handle":  handle,
            "peer":    peer,
            "peer_ip": peer_ip,
            "conn_id": conn_id,
        })