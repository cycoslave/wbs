# src/plugins/url.py
"""
WBS Plugin: url.py
version: 0.2.0
by: cyco
Description: Plugin that shows title of URL being displayed in IRC channels.
"""
import re
import ipaddress
import socket
import urllib.parse
import aiohttp
from bs4 import BeautifulSoup

from . import Plugin
from .. import __version__

URL_PATTERN = re.compile(r'(https?://[^\s<>"{}|\\^`\[\]]+)', re.IGNORECASE)
MAX_CONTENT_BYTES = 524_288   # 512 KB cap on response body read
ALLOWED_CONTENT_TYPES = {'text/html', 'application/xhtml+xml'}  # Only these content-types will be parsed
BLOCKED_TLDS = {'.gov', '.mil'}  # TLDs blocked regardless of IP resolution
# Explicit hostname/IP blocklist
BLOCKED_HOSTS = {
    'localhost',
    'broadcasthost',
    'ip6-localhost',
    'ip6-loopback',
}

class urlPlugin(Plugin):
    name    = "url"
    version = "0.2.0"

    def __init__(self, core):
        super().__init__(core)
        self._session: aiohttp.ClientSession | None = None

    async def load(self):
        """Initialize plugin: create shared HTTP session."""
        await super().load()
        self._session = aiohttp.ClientSession(
            headers={"User-Agent": f"WBS/{__version__}"},
            timeout=aiohttp.ClientTimeout(total=5, connect=3),
        )
        self.log.info(f"Plugin {self.name} {self.version} loaded")

    async def unload(self):
        """Unload plugin: close shared HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        await super().unload()
        self.log.info(f"Plugin {self.name} {self.version} unloaded")

    async def on_PUBMSG(self, event):
        """Handle public channel messages."""
        text    = event['text'].strip()
        channel = event['channel']
        nick    = event['nick']
        uhost   = event.get('uhost', '')

        if nick == self.core.botname:
            return
        if await self.is_exempt(uhost, nick):
            return
        if text.startswith('!'):
            return

        match = URL_PATTERN.search(text)
        if not match:
            return

        url = match.group(1).rstrip('.,;:!?')
        safe, reason = self._is_safe_url(url)
        if not safe:
            self.log.warning("SSRF blocked URL from %s: %s (%s)", nick, url, reason)
            return

        title = await self.fetch_title(url)
        if title:
            await self.send_privmsg(channel, f"Title: {title}")

    async def is_exempt(self, uhost: str, nick: str) -> bool:
        """Exempt linked botnet peers."""
        for peer in self.core.botnet.peers.values():
            if isinstance(peer, str):
                if peer == nick:
                    return True
            elif hasattr(peer, 'nick') and peer.nick == nick:
                return True
        return False

    async def fetch_title(self, url: str) -> str | None:
        """
        Fetch and extract page title.

        - Uses shared session (no per-request overhead)
        - Validates Content-Type before reading body
        - Hard-caps body read at MAX_CONTENT_BYTES
        - Returns None (silently) on any error
        """
        if not self._session or self._session.closed:
            self.log.error("fetch_title called with no active session")
            return None
        try:
            async with self._session.get(
                url,
                allow_redirects=True,
                max_redirects=3,
            ) as resp:
                resp.raise_for_status()

                # Content-Type gate — don't read binary/unknown responses
                ct = resp.headers.get('Content-Type', '').split(';')[0].strip().lower()
                if ct not in ALLOWED_CONTENT_TYPES:
                    self.log.debug("Skipping non-HTML response: %s (%s)", url, ct)
                    return None

                # Capped read — never buffer more than 512 KB
                raw = await resp.content.read(MAX_CONTENT_BYTES)
                html = raw.decode('utf-8', errors='replace')

        except aiohttp.ClientResponseError as e:
            self.log.debug("HTTP error fetching %s: %s", url, e.status)
            return None
        except Exception as e:
            self.log.debug("fetch_title error for %s: %s", url, e)
            return None

        return self._extract_title(html) or self._extract_meta_title(html)

    def _extract_title(self, html: str) -> str | None:
        soup = BeautifulSoup(html, 'html.parser')
        tag  = soup.find('title')
        if tag:
            return tag.get_text().strip()[:200] or None
        return None

    def _extract_meta_title(self, html: str) -> str | None:
        soup  = BeautifulSoup(html, 'html.parser')
        metas = [
            soup.find('meta', property='og:title'),
            soup.find('meta', property='twitter:title'),
            soup.find('meta', attrs={'name': 'twitter:title'}),
        ]
        for meta in metas:
            if meta and meta.get('content'):
                return meta.get('content').strip()[:200] or None
        return None
    
    def _is_safe_url(self, url: str) -> tuple[bool, str]:
        """
        Validate a URL for SSRF safety.

        Returns (True, '') if safe, or (False, reason) if blocked.

        Checks (in order):
        1. Scheme must be http or https
        2. Hostname must be present
        3. Blocked TLDs (.gov, .mil)
        4. Explicit hostname blocklist
        5. IP address ranges: loopback, private, link-local,
            multicast, reserved, broadcast (255.255.255.255),
            unspecified (0.0.0.0/::)
        6. DNS resolution — all resolved IPs must also pass range checks
            (prevents DNS rebinding: public hostname → private IP)
        """
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return False, "unparseable URL"

        if parsed.scheme not in ('http', 'https'):
            return False, f"scheme '{parsed.scheme}' not allowed"

        host = (parsed.hostname or '').lower().strip('.')
        if not host:
            return False, "no hostname"

        # TLD check
        for tld in BLOCKED_TLDS:
            if host == tld.lstrip('.') or host.endswith(tld):
                return False, f"blocked TLD ({tld})"

        # Explicit hostname blocklist
        if host in BLOCKED_HOSTS:
            return False, f"blocked host ({host})"

        # Try parsing as a literal IP first
        literal_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        try:
            literal_ip = ipaddress.ip_address(host)
        except ValueError:
            pass  # It's a hostname — will be resolved below

        def _ip_is_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
            """Return a reason string if the address is forbidden, else None."""
            if addr.is_loopback:
                return "loopback address"
            if addr.is_private:
                return "private address"
            if addr.is_link_local:
                return "link-local address"
            if addr.is_multicast:
                return "multicast address"
            if addr.is_reserved:
                return "reserved address"
            if addr.is_unspecified:
                return "unspecified address (0.0.0.0 / ::)"
            # IPv4 broadcast
            if isinstance(addr, ipaddress.IPv4Address) and str(addr) == '255.255.255.255':
                return "broadcast address"
            # Bogon / documentation ranges
            bogons = [
                ipaddress.ip_network('100.64.0.0/10'),    # Shared address space (RFC 6598)
                ipaddress.ip_network('192.0.0.0/24'),      # IETF Protocol Assignments
                ipaddress.ip_network('192.0.2.0/24'),      # TEST-NET-1 (RFC 5737)
                ipaddress.ip_network('198.51.100.0/24'),   # TEST-NET-2
                ipaddress.ip_network('203.0.113.0/24'),    # TEST-NET-3
                ipaddress.ip_network('240.0.0.0/4'),       # Reserved (RFC 1112)
            ]
            for net in bogons:
                if addr in net:
                    return f"bogon/documentation range ({net})"
            return None

        if literal_ip is not None:
            reason = _ip_is_blocked(literal_ip)
            if reason:
                return False, reason
            return True, ''

        # Hostname — resolve all A/AAAA records and validate every one.
        # This defeats DNS rebinding: attacker registers public.evil.com → 192.168.1.1
        try:
            results = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False, "DNS resolution failed"

        if not results:
            return False, "DNS returned no results"

        for res in results:
            raw_ip = res[4][0]
            try:
                addr = ipaddress.ip_address(raw_ip)
            except ValueError:
                return False, f"unparseable resolved IP: {raw_ip}"
            reason = _ip_is_blocked(addr)
            if reason:
                return False, f"resolved to blocked IP {raw_ip} ({reason})"

        return True, ''    