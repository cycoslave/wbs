# src/safehttp.py
"""
Shared SSRF-safe outbound HTTP fetch policy for WBS plugins (SAST-008).

Every plugin that fetches a URL on behalf of an IRC user (or talks to a fixed
third-party provider) goes through :class:`SafeHttpClient`. The guarantees:

* Only http/https, only the configured ports, no userinfo in URLs, optional
  exact-hostname allowlist (no substring/suffix matching).
* Automatic redirects are disabled. Every hop's URL is re-validated by the
  same policy before it is requested, and the hop count is bounded.
* DNS is resolved exactly once per connection by a policy-enforcing resolver
  that rejects the whole host if ANY returned address is internal. The
  connector dials only those validated addresses (no second lookup, no DNS
  cache), so the checked address is the connected address (no rebinding).
* A socket factory re-checks the numeric peer address before a socket is
  even created (defense in depth, covers literal-IP URLs as well).
* Loopback, private, link-local, CGNAT, multicast, reserved, unspecified,
  documentation/benchmark ranges, site-local, ULA and IPv6 transition
  addresses that embed such IPv4 (mapped, compatible, 6to4, NAT64) or tunnel
  anywhere (Teredo) are denied unless their network is *explicitly*
  authorized via ``SafeFetchPolicy.allow_networks``.
* Response bodies are read incrementally and capped in decompressed bytes
  (decompression is done here with a bounded zlib stream, so gzip bombs stop
  at the budget). Wall-clock time and concurrency are bounded too.
* No proxies from the environment, no cookies persisted between hosts.
"""
from __future__ import annotations

import asyncio
import errno
import ipaddress
import json
import logging
import socket
import urllib.parse
import zlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult
from multidict import CIMultiDict

log = logging.getLogger("wbs.safehttp")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Hostnames that are never fetched, independent of what DNS says.
_DENIED_HOSTNAMES = frozenset({
    "localhost", "localhost.localdomain", "broadcasthost",
    "ip6-localhost", "ip6-loopback",
})
_DENIED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")

# Extra IPv4 ranges denied on top of ``not is_global`` (belt and braces: some
# of these are also covered by the stdlib tables, depending on the version).
_EXTRA_DENIED_V4 = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",        # "this" network
    "10.0.0.0/8",
    "100.64.0.0/10",    # CGNAT (RFC 6598)
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",     # IETF protocol assignments
    "192.0.2.0/24",     # TEST-NET-1
    "192.88.99.0/24",   # 6to4 relay anycast
    "192.168.0.0/16",
    "198.18.0.0/15",    # benchmarking
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",   # TEST-NET-3
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reserved + broadcast
))
_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_V4_COMPAT = ipaddress.ip_network("::/96")


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------
class FetchError(Exception):
    """Base class for all safe-fetch failures. ``str()`` is IRC-safe."""


class FetchBlocked(FetchError):
    """URL, redirect target, or resolved address violates the policy."""


class FetchTooLarge(FetchError):
    """Response exceeded the byte budget (strict mode)."""


class FetchTimeout(FetchError):
    """Whole fetch (all hops) exceeded the time budget."""


class FetchBusy(FetchError):
    """Too many concurrent fetches in flight; request refused."""


class BlockedDestinationError(OSError):
    """Raised inside the connector (resolver / socket factory).

    Subclasses OSError so aiohttp's connector error handling treats it as a
    connection failure; :class:`SafeHttpClient` maps it back to FetchBlocked.
    """

    MARKER = "[wbs-fetch-policy]"

    def __init__(self, message: str):
        super().__init__(errno.EACCES, f"{self.MARKER} {message}")


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------
def _parse_networks(nets: Iterable[str | IPNetwork]) -> tuple[IPNetwork, ...]:
    out = []
    for n in nets:
        out.append(n if isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                   else ipaddress.ip_network(n, strict=False))
    return tuple(out)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def ip_denial_reason(addr: IPAddress) -> str | None:
    """Return why ``addr`` is not a safe public destination, or None."""
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            inner = ip_denial_reason(addr.ipv4_mapped)
            return f"IPv4-mapped {inner}" if inner else None
        if addr.teredo is not None:
            return "Teredo tunnel address"
        if addr.sixtofour is not None:
            inner = ip_denial_reason(addr.sixtofour)
            return f"6to4-embedded {inner}" if inner else None
        if addr in _NAT64_LOCAL:
            return "local-use NAT64 address"
        if addr in _NAT64_WKP:
            inner = ip_denial_reason(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
            return f"NAT64-embedded {inner}" if inner else None
        if addr in _V4_COMPAT:
            # ::/96 holds ::, ::1 and deprecated IPv4-compatible addresses.
            return "IPv4-compatible/unspecified/loopback IPv6 address"
        if addr.is_site_local:
            return "site-local address"
    if addr.is_unspecified:
        return "unspecified address"
    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address"
    if addr.is_multicast:
        return "multicast address"
    if addr.is_private:
        return "private address"
    if addr.is_reserved:
        return "reserved address"
    if isinstance(addr, ipaddress.IPv4Address):
        for net in _EXTRA_DENIED_V4:
            if addr in net:
                return f"special-purpose range {net}"
    if not addr.is_global:
        return "non-global address"
    return None


@dataclass(frozen=True)
class SafeFetchPolicy:
    """Immutable fetch policy. Defaults deny every non-public destination."""

    schemes: frozenset[str] = frozenset({"http", "https"})
    ports: frozenset[int] = frozenset({80, 443, 8080, 8443})
    #: Exact (normalized) hostnames allowed; ``None`` means any public host.
    allowed_hosts: frozenset[str] | None = None
    #: Hostname suffixes denied in addition to the built-in internal names.
    denied_host_suffixes: tuple[str, ...] = ()
    #: Networks explicitly authorized despite being internal. Empty = none.
    allow_networks: tuple[IPNetwork, ...] = ()
    max_redirects: int = 3
    max_bytes: int = 1_048_576
    total_timeout: float = 10.0
    connect_timeout: float = 5.0
    max_concurrency: int = 4
    max_waiters: int = 8
    user_agent: str = "WBS"

    def __post_init__(self) -> None:
        object.__setattr__(self, "schemes", frozenset(s.lower() for s in self.schemes))
        object.__setattr__(self, "ports", frozenset(int(p) for p in self.ports))
        if self.allowed_hosts is not None:
            object.__setattr__(self, "allowed_hosts",
                               frozenset(_normalize_host(h) for h in self.allowed_hosts))
        object.__setattr__(self, "allow_networks", _parse_networks(self.allow_networks))
        object.__setattr__(self, "denied_host_suffixes",
                           tuple(s.lower() for s in self.denied_host_suffixes))
        if self.max_bytes <= 0 or self.max_redirects < 0 or self.max_concurrency <= 0:
            raise ValueError("invalid SafeFetchPolicy bounds")

    # -- addresses ---------------------------------------------------------
    def address_denial(self, raw_ip: str | IPAddress) -> str | None:
        """Reason the numeric address may not be dialled, or None if allowed."""
        try:
            addr = raw_ip if isinstance(raw_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) \
                else ipaddress.ip_address(str(raw_ip).split("%", 1)[0])
        except ValueError:
            return f"unparseable address {raw_ip!r}"
        for net in self.allow_networks:
            if addr.version == net.version and addr in net:
                return None
        return ip_denial_reason(addr)

    # -- URLs --------------------------------------------------------------
    def check_url(self, url: str, *, allowed_hosts: Iterable[str] | None = None,
                  schemes: Iterable[str] | None = None) -> urllib.parse.SplitResult:
        """Statically validate one hop (no DNS). Raises FetchBlocked."""
        try:
            parts = urllib.parse.urlsplit(url)
            port = parts.port
        except ValueError:
            raise FetchBlocked("malformed URL") from None
        scheme = parts.scheme.lower()
        allowed_schemes = self.schemes if schemes is None else \
            self.schemes & frozenset(s.lower() for s in schemes)
        if scheme not in allowed_schemes:
            raise FetchBlocked(f"scheme '{scheme or '?'}' not allowed")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise FetchBlocked("credentials in URL not allowed")
        host = _normalize_host(parts.hostname or "")
        if not host:
            raise FetchBlocked("no hostname")
        if any(c in host for c in " \t\r\n\\/%"):
            raise FetchBlocked("invalid hostname")
        if port is None:
            port = 443 if scheme == "https" else 80
        if port not in self.ports:
            raise FetchBlocked(f"port {port} not allowed")

        hosts = self.allowed_hosts
        if allowed_hosts is not None:
            extra = frozenset(_normalize_host(h) for h in allowed_hosts)
            hosts = extra if hosts is None else hosts & extra
        if hosts is not None and host not in hosts:
            raise FetchBlocked("host not in allowlist")

        self.check_host(host)
        return parts

    def check_host(self, host: str) -> IPAddress | None:
        """Statically validate a hostname or IP literal (no DNS).

        Returns the parsed address for IP literals, None for DNS names.
        Raises FetchBlocked.
        """
        host = _normalize_host(host)
        if not host:
            raise FetchBlocked("no hostname")
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            reason = self.address_denial(literal)
            if reason:
                raise FetchBlocked(f"destination not allowed ({reason})")
            return literal
        if host in _DENIED_HOSTNAMES or host.endswith(_DENIED_HOST_SUFFIXES):
            raise FetchBlocked("internal hostname not allowed")
        for suffix in self.denied_host_suffixes:
            bare = suffix.lstrip(".")
            if host == bare or host.endswith("." + bare):
                raise FetchBlocked(f"hostname suffix {suffix} not allowed")
        # WHATWG "ends in a number": a last label that is decimal or 0x-hex
        # means a legacy numeric IPv4 form (2130706433, 127.1, 0x7f.0.0.1)
        # that resolvers would map to an address. Refuse instead of guessing.
        last = host.rsplit(".", 1)[-1]
        if last.isdigit() or (last.startswith("0x") and
                              all(c in "0123456789abcdef" for c in last[2:])):
            raise FetchBlocked("non-canonical numeric host not allowed")
        return None


# ---------------------------------------------------------------------------
# connector plumbing
# ---------------------------------------------------------------------------
class PolicyResolver(AbstractResolver):
    """Resolve once, deny the host if any answer is internal."""

    def __init__(self, policy: SafeFetchPolicy, inner: AbstractResolver | None = None):
        self._policy = policy
        self._inner = inner
        self._owns_inner = inner is None

    async def resolve(self, host: str, port: int = 0,
                      family: socket.AddressFamily = socket.AF_INET) -> list[ResolveResult]:
        if self._inner is None:
            self._inner = aiohttp.DefaultResolver()
        infos = await self._inner.resolve(host, port, family)
        if not infos:
            raise OSError(errno.EHOSTUNREACH, f"no addresses for {host}")
        for info in infos:
            reason = self._policy.address_denial(info["host"])
            if reason:
                raise BlockedDestinationError(
                    f"{host} resolved to a denied address ({reason})")
        return list(infos)

    async def close(self) -> None:
        if self._owns_inner and self._inner is not None:
            await self._inner.close()
            self._inner = None


def _bounded_decoder(encoding: str):
    enc = (encoding or "").strip().lower()
    if enc in ("", "identity"):
        return None
    if enc in ("gzip", "x-gzip"):
        return zlib.decompressobj(16 + zlib.MAX_WBITS)
    if enc == "deflate":
        return "deflate"  # zlib-wrapped or raw; decided on first bytes
    raise FetchError(f"unsupported content-encoding '{enc}'")


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: int
    headers: Mapping[str, str]
    body: bytes
    truncated: bool = False
    redirects: tuple[str, ...] = field(default_factory=tuple)

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "").split(";")[0].strip().lower()

    @property
    def charset(self) -> str:
        for part in self.headers.get("Content-Type", "").split(";")[1:]:
            k, _, v = part.partition("=")
            if k.strip().lower() == "charset" and v.strip():
                return v.strip().strip('"\'')
        return "utf-8"

    def text(self) -> str:
        try:
            return self.body.decode(self.charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text())


class SafeHttpClient:
    """One aiohttp session wired to a :class:`SafeFetchPolicy`."""

    def __init__(self, policy: SafeFetchPolicy | None = None, *,
                 resolver: AbstractResolver | None = None):
        self.policy = policy or SafeFetchPolicy()
        self._inner_resolver = resolver
        self._resolver: PolicyResolver | None = None
        self._session: aiohttp.ClientSession | None = None
        self._sem = asyncio.Semaphore(self.policy.max_concurrency)
        self._pending = 0
        #: counters for diagnostics/tests
        self.dials = 0
        self.blocked_dials = 0

    @property
    def inner_resolver(self) -> AbstractResolver | None:
        """Injected backend resolver (None = aiohttp default)."""
        return self._inner_resolver

    # -- lifecycle ---------------------------------------------------------
    def _socket_factory(self, addr_info) -> socket.socket:
        family, type_, proto, _, sockaddr = addr_info
        reason = self.policy.address_denial(sockaddr[0])
        if reason:
            self.blocked_dials += 1
            raise BlockedDestinationError(f"refusing to dial {sockaddr[0]} ({reason})")
        self.dials += 1
        return socket.socket(family=family, type=type_, proto=proto)

    def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is not None and not self._session.closed:
            return self._session
        self._resolver = PolicyResolver(self.policy, self._inner_resolver)
        try:
            connector = aiohttp.TCPConnector(
                resolver=self._resolver,
                use_dns_cache=False,
                force_close=True,
                limit=self.policy.max_concurrency,
                socket_factory=self._socket_factory,
            )
        except TypeError as exc:  # aiohttp without socket_factory: fail closed
            raise FetchError("HTTP client unavailable (aiohttp too old)") from exc
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": self.policy.user_agent,
                     "Accept-Encoding": "gzip, deflate"},
            auto_decompress=False,
            trust_env=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            timeout=aiohttp.ClientTimeout(
                total=self.policy.total_timeout,
                connect=self.policy.connect_timeout,
                sock_connect=self.policy.connect_timeout,
                sock_read=self.policy.total_timeout,
            ),
        )
        return self._session

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None
        if self._resolver is not None:
            await self._resolver.close()
            self._resolver = None

    # -- fetching ----------------------------------------------------------
    async def fetch(self, url: str, *, method: str = "GET",
                    allowed_hosts: Iterable[str] | None = None,
                    schemes: Iterable[str] | None = None,
                    max_bytes: int | None = None,
                    timeout: float | None = None,
                    truncate: bool = False,
                    accept_types: Iterable[str] | None = None,
                    headers: Mapping[str, str] | None = None) -> FetchResult:
        """Fetch ``url`` under the policy, following validated redirects.

        ``truncate=True`` returns at most ``max_bytes`` of body and marks the
        result truncated; otherwise exceeding the budget raises FetchTooLarge.
        ``accept_types`` refuses (without reading the body) any final
        response whose media type is not listed.
        """
        method = method.upper()
        if method not in ("GET", "HEAD"):
            raise FetchBlocked(f"method {method} not allowed")
        limit = min(max_bytes or self.policy.max_bytes, self.policy.max_bytes)
        allowed_hosts = None if allowed_hosts is None else tuple(allowed_hosts)
        schemes = None if schemes is None else tuple(schemes)
        accept = None if accept_types is None else frozenset(t.lower() for t in accept_types)

        budget = self.policy.total_timeout if timeout is None else \
            min(float(timeout), self.policy.total_timeout)
        if self._pending >= self.policy.max_concurrency + self.policy.max_waiters:
            raise FetchBusy("too many HTTP requests in flight")
        self._pending += 1
        try:
            async with asyncio.timeout(budget):
                async with self._sem:
                    return await self._fetch_hops(url, method, allowed_hosts, schemes,
                                                  limit, truncate, accept, headers)
        except TimeoutError:
            raise FetchTimeout("request timed out") from None
        finally:
            self._pending -= 1

    async def _fetch_hops(self, url, method, allowed_hosts, schemes, limit,
                          truncate, accept, headers) -> FetchResult:
        session = self._ensure_session()
        redirects: list[str] = []
        current = url
        for _hop in range(self.policy.max_redirects + 1):
            self.policy.check_url(current, allowed_hosts=allowed_hosts, schemes=schemes)
            try:
                async with session.request(method, current, allow_redirects=False,
                                           headers=headers) as resp:
                    location = resp.headers.get("Location")
                    if resp.status in REDIRECT_STATUSES and location:
                        nxt = urllib.parse.urljoin(current, location.strip())
                        nxt = urllib.parse.urldefrag(nxt)[0]
                        if urllib.parse.urlsplit(current).scheme.lower() == "https" and \
                                urllib.parse.urlsplit(nxt).scheme.lower() != "https":
                            raise FetchBlocked("redirect downgrades https")
                        current = nxt
                        redirects.append(current)
                        continue
                    if accept is not None and resp.content_type.lower() not in accept:
                        raise FetchError(f"unexpected content-type '{resp.content_type}'")
                    if method == "HEAD":
                        body, truncated = b"", False
                    else:
                        body, truncated = await self._read_bounded(resp, limit, truncate)
                    return FetchResult(url=current, status=resp.status,
                                       headers=CIMultiDict(resp.headers), body=body,
                                       truncated=truncated, redirects=tuple(redirects))
            except FetchError:
                raise
            except TimeoutError:
                raise
            except Exception as exc:  # aiohttp/OSError; find a policy denial
                cur: BaseException | None = exc
                seen = 0
                while cur is not None and seen < 10:
                    if isinstance(cur, BlockedDestinationError) or \
                            BlockedDestinationError.MARKER in str(cur):
                        raise FetchBlocked("destination not allowed") from None
                    cur = cur.__cause__ or cur.__context__ or getattr(cur, "os_error", None)
                    seen += 1
                log.debug("safe fetch network error for %s: %r", current, exc)
                raise FetchError("network error") from None
        raise FetchBlocked("too many redirects")

    @staticmethod
    async def _read_bounded(resp: aiohttp.ClientResponse, limit: int,
                            truncate: bool) -> tuple[bytes, bool]:
        declared = resp.content_length
        encoding = resp.headers.get("Content-Encoding", "")
        if not truncate and declared is not None and declared > limit and \
                encoding.strip().lower() in ("", "identity"):
            raise FetchTooLarge("response too large")
        decoder = _bounded_decoder(encoding)
        out = bytearray()
        wire = 0
        overflow = False

        def feed(data: bytes) -> None:
            nonlocal decoder, overflow
            if decoder is None:
                out.extend(data[: limit + 1 - len(out)])
            else:
                if decoder == "deflate":
                    decoder = zlib.decompressobj(zlib.MAX_WBITS if data[:1] == b"\x78"
                                                 else -zlib.MAX_WBITS)
                chunk = data
                while True:
                    room = limit + 1 - len(out)
                    if room <= 0:
                        break
                    try:
                        piece = decoder.decompress(chunk, room)
                    except zlib.error:
                        raise FetchError("corrupt compressed response") from None
                    out.extend(piece)
                    chunk = decoder.unconsumed_tail
                    if not chunk:
                        break
            if len(out) > limit:
                overflow = True

        async for data in resp.content.iter_chunked(16384):
            wire += len(data)
            feed(data)
            if overflow or wire > limit:
                overflow = True
                break
        if overflow:
            if not truncate:
                raise FetchTooLarge("response too large")
            return bytes(out[:limit]), True
        return bytes(out), False


async def resolve_public(host: str, policy: SafeFetchPolicy | None = None,
                         resolver: AbstractResolver | None = None) -> list[str]:
    """Resolve ``host`` once and return its addresses only if all are allowed.

    For non-HTTP plugin sockets (e.g. port checks): dial exactly the returned
    addresses so the validated address is the connected address.
    """
    policy = policy or SafeFetchPolicy()
    host = _normalize_host(host)
    if any(c in host for c in " \t\r\n\\/%@:") and not _is_ip(host):
        raise FetchBlocked("invalid hostname")
    literal = policy.check_host(host)
    if literal is not None:
        return [str(literal)]
    own = resolver is None
    res = PolicyResolver(policy, resolver)
    try:
        infos = await res.resolve(host, 0, socket.AF_UNSPEC)
    except BlockedDestinationError:
        raise FetchBlocked("destination not allowed") from None
    except OSError:
        raise FetchError("DNS resolution failed") from None
    finally:
        if own:
            await res.close()
    seen: list[str] = []
    for info in infos:
        if info["host"] not in seen:
            seen.append(info["host"])
    return seen
