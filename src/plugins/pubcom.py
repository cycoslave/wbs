# src/plugins/pubcom.py
"""
WBS Plugin: pubcom.py 
version: 0.1.0
by: cyco
Description: Public commands in the channel.
"""
import asyncio
import logging
import re
import time
import json
from datetime import datetime
from typing import Optional, Dict
import aiohttp  # Now available
import aiohttp.client_exceptions

from . import Plugin

log = logging.getLogger("wbs.plugins.pubcom")

class pubcomPlugin(Plugin):
    """Public commands plugin - provides IRC channel commands"""
    
    def __init__(self, core):
        super().__init__(core)
        self.name = 'pubcom'
        self.version = '0.1.0'
        self.auth_sessions = {}  # nick -> timestamp
        self.auth_timeout = 43200  # 12 hours
        self.http_session = None
    
    async def load(self):
        """Initialize plugin"""
        self.http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'WBS/6.0'}
        )
        log.info(f"Plugin {self.name} {self.version} loaded")
    
    async def unload(self):
        """Cleanup"""
        self.auth_sessions.clear()
        if self.http_session:
            await self.http_session.close()
        log.info("Pubcom plugin unloaded")

    # Helper methods
    def check_auth(self, nick: str) -> bool:
        """Check if user is authenticated"""
        nick_lower = nick.lower()
        if nick_lower in self.auth_sessions:
            elapsed = time.time() - self.auth_sessions[nick_lower]
            if elapsed < self.auth_timeout:
                return True
            else:
                del self.auth_sessions[nick_lower]
        return False
    
    async def is_pubcom_enabled(self, channel: str) -> bool:
        """Check if pubcom is enabled for channel"""
        chan_settings = await self.core.chan.get(channel)
        return chan_settings and chan_settings.get('pubcom', False)
    
    # Authentication handlers
    async def on_PRIVMSG(self, event):
        """Handle private messages for authentication"""
        nick = event['nick']
        text = event['text'].strip()
        
        if not text.startswith('identify'):
            return
        
        parts = text.split()
        if len(parts) < 2:
            await self.send_notice(nick, f"Usage: /msg {self.core.botnick} identify [handle] <password>")
            return
        
        # Parse identify command
        if len(parts) == 2:
            handle = event['uhost']  # Use their nick as handle
            password = parts[1]
        else:
            handle = parts[1]
            password = parts[2]
        
        # Verify credentials
        if await self.core.user.verify_password(handle, password):
            self.auth_sessions[nick.lower()] = time.time()
            await self.send_notice(nick, "Logged in successfully!")
        else:
            await self.send_notice(nick, "Invalid credentials!")
    
    # Public message handlers
    async def on_PUBMSG(self, event):
        """Handle public channel messages"""
        text = event['text'].strip()
        channel = event['channel']
        nick = event['nick']
        uhost = event.get('uhost', '')
        
        #if not await self.is_pubcom_enabled(channel):
        #    return
        
        # Route commands
        cmd_map = {
            '!info': self.cmd_info,
            '!identify': self.cmd_identify_help,
            '!version': self.cmd_version,
            '!uptime': self.cmd_uptime,
            '!time': self.cmd_time,
            '!news': self.cmd_news,
            '!cve': self.cmd_cve,
            '!lastcve': self.cmd_lastcve,
            '!epss': self.cmd_epss,
            '!whois': self.cmd_whois,
            '!portscan': self.cmd_portscan,
            '!youtube': self.cmd_youtube,
            '!a': self.cmd_dns_a,
            '!aaaa': self.cmd_dns_aaaa,
            '!ptr': self.cmd_dns_ptr,
            '!ptr6': self.cmd_dns_ptr6,
            '!mx': self.cmd_dns_mx,
            '!ns': self.cmd_dns_ns,
            '!website': self.cmd_website,
            '!waf': self.cmd_waf,
            '!tech': self.cmd_tech,
            '!geoip': self.cmd_geoip,
            '!asn': self.cmd_asn,
            '!trend': self.cmd_trend,
            '!crypto': self.cmd_crypto,
            '!op': self.cmd_op,
            '!deop': self.cmd_deop,
            '!voice': self.cmd_voice,
            '!devoice': self.cmd_devoice,
            '!kick': self.cmd_kick,
            '!ban': self.cmd_ban,
            '!mode': self.cmd_mode,
            '!rehash': self.cmd_rehash,
            '!restart': self.cmd_restart,
            '!jump': self.cmd_jump,
        }
        
        for cmd, handler in cmd_map.items():
            if text.startswith(cmd):
                arg = text[len(cmd):].strip()
                await handler(nick, uhost, channel, arg)
                break
    
    # Command implementations
    async def cmd_info(self, nick, uhost, channel, arg):
        """Display available commands"""
        commands = "!version !uptime !time !op !deop !voice !devoice !kick !ban !mode " \
                   "!rehash !restart !jump !news !cve !epss !whois !portscan !youtube " \
                   "!a !aaaa !ptr !ptr6 !mx !ns !website !waf !tech !geoip !asn !trend !crypto"
        await self.send_privmsg(channel, f"Valid commands are: {commands}")
    
    async def cmd_identify_help(self, nick, uhost, channel, arg):
        """Show identify help"""
        await self.send_notice(nick, f"To identify: /msg {self.core.botnick} identify [handle] <password>")
    
    async def cmd_version(self, nick, uhost, channel, arg):
        """Show bot version"""
        version = self.core.config.get('version', '6.0.0')
        await self.send_privmsg(channel, f"I run Wicked Bot System {version}!")
    
    async def cmd_uptime(self, nick, uhost, channel, arg):
        """Show uptime"""
        uptime = time.time() - self.core.start_time
        uptime_str = self.format_duration(uptime)
        await self.send_privmsg(channel, f"Bot uptime: {uptime_str}")
    
    async def cmd_time(self, nick, uhost, channel, arg):
        """Show current time"""
        now = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        await self.send_privmsg(channel, f"Current time is: {now}")
    
    async def cmd_news(self, nick, uhost, channel, arg):
        """Fetch tech news from RSS feeds"""
        num = 5
        if arg and arg.isdigit():
            num = max(1, min(10, int(arg)))
        
        feeds = [
            'https://news.ycombinator.com/rss',
            'https://techcrunch.com/feed/',
            'https://www.bleepingcomputer.com/feed/',
        ]
        
        # Fetch and parse feeds (simplified - you'd use feedparser)
        await self.send_privmsg(channel, f"Fetching {num} news items...")
        # Implementation would parse RSS feeds
    
    async def cmd_cve(self, nick, uhost, channel, arg):
        """Lookup CVE details"""
        cve_id = arg.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            await self.send_privmsg(channel, "Invalid CVE format. Use: !cve CVE-YYYY-XXXXX")
            return
        
        try:
            async with self.http_session.get(f'https://cve.circl.lu/api/cve/{cve_id}') as resp:
                if resp.status == 200:
                    data = await resp.json()
                    title = data.get('summary', 'Title not available')
                    cvss = data.get('cvss', 'N/A')
                    msg = f"{cve_id} - {title} (CVSS: {cvss}) - https://nvd.nist.gov/vuln/detail/{cve_id}"
                    await self.send_privmsg(channel, msg)
                else:
                    await self.send_privmsg(channel, f"CVE not found")
        except aiohttp.client_exceptions.ClientError as e:
            log.error(f"CVE lookup error: {e}")
            await self.send_privmsg(channel, "Error fetching CVE details")
    
    async def cmd_epss(self, nick, uhost, channel, arg):
        """Lookup EPSS score for CVE"""
        cve_id = arg.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            await self.send_privmsg(channel, "Invalid CVE format. Use: !epss CVE-YYYY-XXXXX")
            return
        
        try:
            async with self.http_session.get(f'https://cve.circl.lu/api/epss/{cve_id}') as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if 'data' in data and len(data['data']) > 0:
                        epss_data = data['data'][0]
                        epss = f"{epss_data.get('epss', 0):.6f}"
                        percentile = f"{epss_data.get('percentile', 0):.6f}"
                        updated = epss_data.get('date', 'N/A')
                        msg = f"{cve_id} - EPSS: {epss} (Percentile: {percentile}) - Updated: {updated}"
                    else:
                        msg = f"{cve_id} - No EPSS data available"
                    await self.send_privmsg(channel, msg)
        except aiohttp.client_exceptions.ClientError as e:
            log.error(f"EPSS lookup error: {e}")
            await self.send_privmsg(channel, "Error fetching EPSS details")
    
    async def cmd_crypto(self, nick, uhost, channel, arg):
        """Crypto price lookup"""
        parts = arg.lower().split()
        if not parts:
            await self.send_privmsg(channel, "Usage: !crypto <coin> [currency] [amount]")
            return
        
        coin_map = {
            'btc': ('bitcoin', 'BTC'),
            'eth': ('ethereum', 'ETH'),
            'doge': ('dogecoin', 'DOGE'),
        }
        
        coin = parts[0]
        currency = parts[1] if len(parts) > 1 else 'usd'
        amount = float(parts[2]) if len(parts) > 2 else 1.0
        
        if coin not in coin_map:
            coin = 'btc'
        
        crypto_id, symbol = coin_map[coin]
        
        try:
            url = f"https://api.coingecko.com/api/v3/simple/price?ids={crypto_id}&vs_currencies={currency}"
            async with self.http_session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    price = data[crypto_id][currency]
                    total = price * amount
                    await self.send_privmsg(channel, f"{amount} {symbol} = ${total:,.2f} {currency.upper()}")
                else:
                    await self.send_privmsg(channel, "Crypto API error")
        except Exception as e:
            log.error(f"Crypto lookup error: {e}")
            await self.send_privmsg(channel, "Error fetching crypto price")
    
    # Channel management commands (require auth)
    async def cmd_op(self, nick, uhost, channel, arg):
        """Give op to user"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        target = arg.strip() if arg else nick
        await self.send_mode(channel, '+o', target)
    
    async def cmd_deop(self, nick, uhost, channel, arg):
        """Remove op from user"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        target = arg.strip() if arg else nick
        await self.send_mode(channel, '-o', target)
    
    async def cmd_voice(self, nick, uhost, channel, arg):
        """Give voice to user"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        target = arg.strip() if arg else nick
        await self.send_mode(channel, '+v', target)
    
    async def cmd_devoice(self, nick, uhost, channel, arg):
        """Remove voice from user"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        target = arg.strip() if arg else nick
        await self.send_mode(channel, '-v', target)
    
    async def cmd_kick(self, nick, uhost, channel, arg):
        """Kick user from channel"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        parts = arg.split(maxsplit=1)
        target = parts[0] if parts else nick
        reason = parts[1] if len(parts) > 1 else nick
        
        self.core.irc_q.put({
            'cmd': 'KICK',
            'channel': channel,
            'nick': target,
            'reason': reason
        })
    
    async def cmd_ban(self, nick, uhost, channel, arg):
        """Ban and kick user"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        parts = arg.split(maxsplit=1)
        target = parts[0] if parts else nick
        reason = parts[1] if len(parts) > 1 else nick
        
        # Get target hostmask
        # Set ban mode
        # Kick user
        await self.send_mode(channel, '+b', f'*!*@{target}')
        self.core.irc_q.put({
            'cmd': 'KICK',
            'channel': channel,
            'nick': target,
            'reason': reason
        })
    
    async def cmd_mode(self, nick, uhost, channel, arg):
        """Set channel mode"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        self.core.irc_q.put({
            'cmd': 'MODE',
            'channel': channel,
            'modes': arg
        })
    
    async def cmd_rehash(self, nick, uhost, channel, arg):
        """Rehash bot configuration"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        await self.send_privmsg(channel, "Rehashing...")
        self.core.event_q.put({'cmd': 'REHASH'})
    
    async def cmd_restart(self, nick, uhost, channel, arg):
        """Restart bot"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        await self.send_privmsg(channel, "Restarting...")
        self.core.event_q.put({'cmd': 'RESTART'})
    
    async def cmd_jump(self, nick, uhost, channel, arg):
        """Jump to different server"""
        if not self.check_auth(nick):
            await self.send_notice(nick, "You must identify first")
            return
        
        await self.send_privmsg(channel, "Jumping server...")
        self.core.irc_q.put({
            'cmd': 'JUMP',
            'server': arg if arg else None
        })
    
    # DNS commands (simplified versions - full implementations would call external tools)
    async def cmd_dns_a(self, nick, uhost, channel, arg):
        """DNS A record lookup"""
        await self.send_privmsg(channel, f"A records for {arg}: [would perform DNS lookup]")
    
    async def cmd_dns_aaaa(self, nick, uhost, channel, arg):
        """DNS AAAA record lookup"""
        await self.send_privmsg(channel, f"AAAA records for {arg}: [would perform DNS lookup]")
    
    async def cmd_dns_ptr(self, nick, uhost, channel, arg):
        """DNS PTR record lookup"""
        await self.send_privmsg(channel, f"PTR record for {arg}: [would perform reverse DNS]")
    
    async def cmd_dns_ptr6(self, nick, uhost, channel, arg):
        """DNS PTR6 record lookup"""
        await self.send_privmsg(channel, f"PTR6 record for {arg}: [would perform reverse DNS]")
    
    async def cmd_dns_mx(self, nick, uhost, channel, arg):
        """DNS MX record lookup"""
        await self.send_privmsg(channel, f"MX records for {arg}: [would perform DNS lookup]")
    
    async def cmd_dns_ns(self, nick, uhost, channel, arg):
        """DNS NS record lookup"""
        await self.send_privmsg(channel, f"NS records for {arg}: [would perform DNS lookup]")
    
    # Utility commands (simplified)
    async def cmd_whois(self, nick, uhost, channel, arg):
        """WHOIS lookup"""
        await self.send_privmsg(channel, f"WHOIS for {arg}: [would perform lookup]")
    
    async def cmd_portscan(self, nick, uhost, channel, arg):
        """Port scan (requires validation)"""
        await self.send_privmsg(channel, "Port scanning requires additional validation")
    
    async def cmd_youtube(self, nick, uhost, channel, arg):
        """YouTube title lookup"""
        await self.send_privmsg(channel, f"YouTube: [would fetch title for {arg}]")
    
    async def cmd_website(self, nick, uhost, channel, arg):
        """Website title lookup"""
        await self.send_privmsg(channel, f"Website: [would fetch title for {arg}]")
    
    async def cmd_waf(self, nick, uhost, channel, arg):
        """WAF detection"""
        await self.send_privmsg(channel, f"WAF detection for {arg}: [would check]")
    
    async def cmd_tech(self, nick, uhost, channel, arg):
        """Technology detection"""
        await self.send_privmsg(channel, f"Tech detection for {arg}: [would analyze]")
    
    async def cmd_geoip(self, nick, uhost, channel, arg):
        """GeoIP lookup"""
        await self.send_privmsg(channel, f"GeoIP for {arg}: [would perform lookup]")
    
    async def cmd_asn(self, nick, uhost, channel, arg):
        """ASN lookup"""
        await self.send_privmsg(channel, f"ASN for {arg}: [would perform lookup]")
    
    async def cmd_trend(self, nick, uhost, channel, arg):
        """CVE trends"""
        await self.send_privmsg(channel, "CVE trends: [would fetch trending CVEs]")
    
    async def cmd_lastcve(self, nick, uhost, channel, arg):
        """Latest CVEs"""
        await self.send_privmsg(channel, "Latest CVEs: [would fetch recent CVEs]")
    
    # Helper methods for IRC communication
    async def send_privmsg(self, target, message):
        """Send message to channel/user"""
        self.core.irc_q.put({
            'cmd': 'msg',
            'target': target,
            'text': message
        })
    
    async def send_notice(self, target, message):
        """Send notice to user"""
        self.core.irc_q.put({
            'cmd': 'notice',
            'target': target,
            'text': message
        })
    
    async def send_mode(self, channel, mode, target):
        """Send mode command"""
        self.core.irc_q.put({
            'cmd': 'mode',
            'channel': channel,
            'mode': mode,
            'target': target
        })
    
    def format_duration(self, seconds):
        """Format duration in human readable form"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        parts = []
        if days: parts.append(f"{days}d")
        if hours: parts.append(f"{hours}h")
        if minutes: parts.append(f"{minutes}m")
        if secs: parts.append(f"{secs}s")
        
        return " ".join(parts) if parts else "0s"
