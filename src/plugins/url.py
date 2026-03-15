# src/plugins/url.py
"""
WBS Plugin: url.py 
version: 0.1.1
by: cyco
Description: Plugin that shows title of URL being displayed in the IRC channels.
"""
import re
import aiohttp
from bs4 import BeautifulSoup

from . import Plugin
from .. import __version__

URL_PATTERN = re.compile(r'(https?://[^\s<>"{}|\\^`\[\]]+)', re.IGNORECASE)

class urlPlugin(Plugin):
    name    = "url"
    version = "0.1.1"

    def __init__(self, core):
        super().__init__(core)
    
    async def load(self):
        """Initialize plugin and register timers"""
        await super().load()
        self.log.info(f"Plugin {self.name} {self.version} loaded")
    
    async def unload(self):
        """Unload plugin and unregister timers"""
        await super().unload()
        self.log.info(f"Plugin {self.name} {self.version} unloaded")

    async def on_PUBMSG(self, event):
        """Handle public channel messages."""
        text = event['text'].strip()
        channel = event['channel']
        nick = event['nick']
        uhost = event.get('uhost', '')

        # Ignore own messages
        if nick == self.core.botname:
            return

        # Skip if exempt (linked bot)
        if await self.is_exempt(uhost, nick):
            return

        # Ignore bot commands
        if text.startswith('!'):
            return

        match = URL_PATTERN.search(text)
        if match:
            url = match.group(1).rstrip('.,;:!?')
            title = await self.fetch_title(url)
            await self.send_privmsg(channel, f"Title: {title}")
            # Optional: await self.update_stats(channel, nick, text)

    async def is_exempt(self, uhost: str, nick: str) -> bool:  # Add nick param from event
        """Exempt if user has 'U' flag or is linked bot by nick/host."""
        # Check linked bots (botnet.py)
        for peer in self.core.botnet.peers.values():
            if isinstance(peer, str):
                if peer == nick:
                    return True
            elif hasattr(peer, 'nick') and peer.nick == nick:
                return True
        
        return False
    
    async def fetch_title(self, url: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    headers={"User-Agent": f"WBS/{__version__}"}
                ) as resp:
                    resp.raise_for_status()
                    html = await resp.text()

            title = self._extract_title(html)
            if title:
                return title[:200]
            title = self._extract_meta_title(html)
            if title:
                return title[:200]
            return "No title found"
        except Exception:
            return "Unable to fetch title"

    def _extract_title(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        title_tag = soup.find('title')
        return title_tag.get_text().strip() if title_tag else None

    def _extract_meta_title(self, html): 
        soup = BeautifulSoup(html, 'html.parser')
        metas = [
            soup.find('meta', property='og:title'),
            soup.find('meta', property='twitter:title'),
            soup.find('meta', attrs={'name': 'twitter:title'})
        ]
        for meta in metas:
            if meta and meta.get('content'):
                return meta.get('content').strip()
        return None    