# src/plugins/url.py
"""
WBS Plugin: url.py
version: 0.3.0
by: cyco
Description: Plugin that shows title of URL being displayed in IRC channels.

All network access goes through the shared SSRF-safe fetch policy in
src/safehttp.py (SAST-008): every redirect hop is re-validated, DNS is
resolved once by a policy resolver and the connection is pinned to the
validated addresses, internal destinations are never dialled, and the body
is capped in decompressed bytes.
"""
import re

from bs4 import BeautifulSoup

from .. import __version__
from ..safehttp import FetchBlocked, FetchError, SafeFetchPolicy, SafeHttpClient
from . import Plugin

URL_PATTERN = re.compile(r'(https?://[^\s<>"{}|\\^`\[\]]+)', re.IGNORECASE)
MAX_CONTENT_BYTES = 524_288   # 512 KB cap on (decompressed) body read
ALLOWED_CONTENT_TYPES = {'text/html', 'application/xhtml+xml'}  # Only these content-types will be parsed
BLOCKED_TLDS = ('.gov', '.mil')  # TLDs blocked regardless of IP resolution
MAX_TITLE_LEN = 200

URL_FETCH_POLICY = SafeFetchPolicy(
    schemes=frozenset({'http', 'https'}),
    ports=frozenset({80, 443, 8080, 8443}),
    denied_host_suffixes=BLOCKED_TLDS,
    max_redirects=3,
    max_bytes=MAX_CONTENT_BYTES,
    total_timeout=5.0,
    connect_timeout=3.0,
    max_concurrency=2,
    max_waiters=4,
    user_agent=f"WBS/{__version__}",
)


def _clean_title(text: str | None) -> str | None:
    """Collapse whitespace and strip control chars so a title is one IRC line."""
    if not text:
        return None
    text = ''.join(ch if ch.isprintable() else ' ' for ch in text)
    text = ' '.join(text.split())
    return text[:MAX_TITLE_LEN] or None


class urlPlugin(Plugin):
    name    = "url"
    version = "0.3.0"

    def __init__(self, core, http: SafeHttpClient | None = None):
        super().__init__(core)
        self._http: SafeHttpClient | None = http

    async def load(self):
        """Initialize plugin: create shared policy-bound HTTP client."""
        await super().load()
        if self._http is None:
            self._http = SafeHttpClient(URL_FETCH_POLICY)
        self.log.info(f"Plugin {self.name} {self.version} loaded")

    async def unload(self):
        """Unload plugin: close shared HTTP client."""
        if self._http is not None:
            await self._http.close()
            self._http = None
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
        Fetch and extract page title under URL_FETCH_POLICY.

        - Every hop (initial URL and each redirect) is validated; internal
          destinations are refused before any socket is created
        - Validates Content-Type before reading body
        - Hard-caps decompressed body at MAX_CONTENT_BYTES (truncates)
        - Returns None (silently) on any error
        """
        if self._http is None:
            self.log.error("fetch_title called with no active HTTP client")
            return None
        try:
            res = await self._http.fetch(
                url,
                accept_types=ALLOWED_CONTENT_TYPES,
                max_bytes=MAX_CONTENT_BYTES,
                truncate=True,
            )
        except FetchBlocked as e:
            self.log.warning("SSRF blocked fetch of %s: %s", url, e)
            return None
        except FetchError as e:
            self.log.debug("fetch_title error for %s: %s", url, e)
            return None
        except Exception as e:  # never let a plugin fetch crash dispatch
            self.log.debug("fetch_title unexpected error for %s: %r", url, e)
            return None
        if res.status >= 400:
            self.log.debug("HTTP error fetching %s: %s", url, res.status)
            return None

        html = res.text()
        return self._extract_title(html) or self._extract_meta_title(html)

    def _extract_title(self, html: str) -> str | None:
        soup = BeautifulSoup(html, 'html.parser')
        tag  = soup.find('title')
        if tag:
            return _clean_title(tag.get_text())
        return None

    def _extract_meta_title(self, html: str) -> str | None:
        soup  = BeautifulSoup(html, 'html.parser')
        metas = [
            soup.find('meta', property='og:title'),
            soup.find('meta', property='twitter:title'),
            soup.find('meta', attrs={'name': 'twitter:title'}),
        ]
        for meta in metas:
            content = meta.get('content') if meta else None
            if isinstance(content, str) and content:
                return _clean_title(content)
        return None

    def _is_safe_url(self, url: str) -> tuple[bool, str]:
        """
        Static (no DNS) pre-check of a URL against URL_FETCH_POLICY.

        Returns (True, '') if the URL may be attempted, or (False, reason).
        This is only a cheap early filter: the authoritative checks run again
        in SafeHttpClient on every hop, at resolution time and at dial time.
        """
        policy = self._http.policy if self._http is not None else URL_FETCH_POLICY
        try:
            policy.check_url(url)
        except FetchBlocked as e:
            return False, str(e)
        return True, ''
