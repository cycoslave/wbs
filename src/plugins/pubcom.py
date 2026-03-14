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
import psutil
import feedparser
import random
import aiodns
import ipaddress
import whoisit
import aiohttp
import aiohttp.client_exceptions
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List
from bs4 import BeautifulSoup

from . import Plugin
from .. import __version__
from ..helper import clean_message

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
            headers={'User-Agent': f"WBS/{__version__}"}
        )
        self.dns_resolver = aiodns.DNSResolver()
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
            '!a': self.cmd_a,
            '!aaaa': self.cmd_aaaa,
            '!ptr': self.cmd_ptr,
            '!ptr6': self.cmd_ptr6,
            '!mx': self.cmd_mx,
            '!ns': self.cmd_ns,
            '!dmarc': self.cmd_dmarc,
            '!spf': self.cmd_spf,
            '!dkim': self.cmd_dkim,
            '!soa': self.cmd_soa,
            '!srv': self.cmd_srv,
            '!caa': self.cmd_caa,
            '!txt': self.cmd_txt,
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
        
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        handler = cmd_map.get(cmd)
        if handler:
            await handler(nick, uhost, channel, arg)
        #for cmd, handler in cmd_map.items():
        #    if text.startswith(cmd):
        #        arg = text[len(cmd):].strip()
        #        await handler(nick, uhost, channel, arg)
        #        break
    
    # Command implementations
    async def cmd_info(self, nick, uhost, channel, arg):
        """Display available commands"""
        commands = "!version !uptime !time !op !deop !voice !devoice !kick !ban !mode !crypto " \
                   "!rehash !restart !jump !news !cve !epss !trend !lastcve !whois !portscan !youtube !dmarc !spf !dkim " \
                   "!srv !soa !txt !caa !a !aaaa !ptr !ptr6 !mx !ns !website !waf !tech !geoip !asn"
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
        suptime = time.time() - self.core.connected_on
        suptime_str = self.format_duration(suptime)
        await self.send_privmsg(channel, f"Server uptime: {suptime_str}")
        muptime = time.time() -  psutil.boot_time()
        muptime_str = self.format_duration(muptime)
        await self.send_privmsg(channel, f"Machine uptime: {muptime_str}")
    
    async def cmd_time(self, nick, uhost, channel, arg):
        """Show current time"""
        now = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        await self.send_privmsg(channel, f"Current time is: {now}")
    
    async def cmd_cve(self, nick, uhost, channel, arg):
        """Lookup CVE details from CIRCL API"""
        cve_id = arg.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            await self.send_privmsg(channel, "Invalid CVE format. Use: !cve CVE-YYYY-XXXXX")
            return
        
        try:
            url = f'https://cve.circl.lu/api/cve/{cve_id}'
            async with self.http_session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # Extract description - try containers.cna.descriptions first, then fallback to summary
                    summary = None
                    containers = data.get('containers', {})
                    if containers:
                        cna = containers.get('cna', {})
                        descriptions = cna.get('descriptions', [])
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                summary = desc.get('value')
                                break
                    
                    # Fallback to root-level summary
                    if not summary:
                        summary = data.get('summary', 'No description available')
                    
                    # Extract CVSS scores from CVE 5.1 format
                    score = 'N/A'
                    severity = ''

                    containers = data.get('containers', {})
                    if containers:
                        cna = containers.get('cna', {})

                        # Try to get CVSS from metrics (CVE 5.x format)
                        metrics = cna.get('metrics', [])
                        for metric in metrics:
                            # Check for CVSS v3.1
                            if 'cvssV3_1' in metric:
                                cvss_data = metric['cvssV3_1']
                                score = cvss_data.get('baseScore', score)
                                severity = cvss_data.get('baseSeverity', '').upper()
                                break
                            # Check for CVSS v3.0
                            elif 'cvssV3_0' in metric:
                                cvss_data = metric['cvssV3_0']
                                score = cvss_data.get('baseScore', score)
                                severity = cvss_data.get('baseSeverity', '').upper()
                                break
                            # Check for CVSS v2.0
                            elif 'cvssV2_0' in metric:
                                cvss_data = metric['cvssV2_0']
                                score = cvss_data.get('baseScore', score)
                                # Calculate severity for v2
                                if isinstance(score, (int, float)):
                                    if score >= 7.0:
                                        severity = 'HIGH'
                                    elif score >= 4.0:
                                        severity = 'MEDIUM'
                                    else:
                                        severity = 'LOW'
                                break
                        
                            # Fallback: try legacy v4 record if no metrics found
                            if score == 'N/A':
                                legacy = cna.get('x_legacyV4Record', {})
                                if legacy:
                                    # Try impact.baseMetricV3
                                    impact = legacy.get('impact', {})
                                    if 'baseMetricV3' in impact:
                                        cvss3 = impact['baseMetricV3'].get('cvssV3', {})
                                        score = cvss3.get('baseScore', score)
                                        severity = cvss3.get('baseSeverity', '').upper()
                                    # Fallback to baseMetricV2
                                    elif 'baseMetricV2' in impact:
                                        cvss2 = impact['baseMetricV2'].get('cvssV2', {})
                                        score = cvss2.get('baseScore', score)
                                        if isinstance(score, (int, float)):
                                            if score >= 7.0:
                                                severity = 'HIGH'
                                            elif score >= 4.0:
                                                severity = 'MEDIUM'
                                            else:
                                                severity = 'LOW'

                        severity_str = f" [{severity}]" if severity else ""

                    # Extract affected products
                    affected_products = []
                    if containers:
                        cna = containers.get('cna', {})
                        affected = cna.get('affected', [])
                        for item in affected[:3]:  # Limit to first 3 products
                            product = item.get('product', '')
                            vendor = item.get('vendor', '')
                            if vendor and vendor not in ('n/a', 'N/A') and product:
                                affected_products.append(f"{vendor} {product}")
                            elif product:
                                affected_products.append(product)
                    
                    # Fallback to vulnerable_product CPE parsing
                    if not affected_products:
                        vuln_products = data.get('vulnerable_product', [])
                        if vuln_products:
                            for cpe in vuln_products[:3]:
                                parts = cpe.split(':')
                                if len(parts) >= 5:
                                    vendor = parts[3].replace('_', ' ')
                                    product = parts[4].replace('_', ' ')
                                    affected_products.append(f"{vendor} {product}")
                    
                    products_str = f"{', '.join(affected_products)}" if affected_products else ""
                    
                    # Truncate summary for IRC (adjust based on product length)
                    max_summary_len = 180 - len(products_str)
                    if len(summary) > max_summary_len:
                        summary = summary[:max_summary_len-3] + "..."
                    
                    msg = f"{products_str} - CVSS: {score}{severity_str} | {summary}"
                    await self.send_privmsg(channel, msg)
                    
                elif resp.status == 404:
                    await self.send_privmsg(channel, f"{cve_id} not found")
                else:
                    await self.send_privmsg(channel, f"CVE lookup failed (status {resp.status})")
                    
        except aiohttp.client_exceptions.ClientError as e:
            log.error(f"CVE lookup error: {e}")
            await self.send_privmsg(channel, "Network error fetching CVE")
        except (KeyError, ValueError, TypeError) as e:
            log.error(f"CVE parsing error for {cve_id}: {e}")
            await self.send_privmsg(channel, "Error parsing CVE response")
    
    async def cmd_epss(self, nick, uhost, channel, arg):
        """Lookup EPSS score for CVE"""
        cve_id = arg.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            await self.send_privmsg(channel, "Invalid CVE format. Use: !epss CVE-YYYY-XXXXX")
            return
        
        try:
            # Use FIRST.org EPSS API
            url = f'https://api.first.org/data/v1/epss?cve={cve_id}'
            async with self.http_session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # Check if data exists
                    if data.get('status') == 'OK' and 'data' in data and len(data['data']) > 0:
                        epss_data = data['data'][0]
                        epss_score = float(epss_data.get('epss', 0))
                        percentile = float(epss_data.get('percentile', 0))
                        date = epss_data.get('date', 'N/A')
                        
                        # Convert to percentages for readability
                        epss_pct = epss_score * 100
                        percentile_pct = percentile * 100
                        
                        msg = f"{cve_id} | EPSS: {epss_pct:.2f}% (Top {100-percentile_pct:.1f}% risk) | Updated: {date}"
                        await self.send_privmsg(channel, msg)
                    else:
                        await self.send_privmsg(channel, f"{cve_id} - No EPSS data available")
                elif resp.status == 404:
                    await self.send_privmsg(channel, f"{cve_id} - No EPSS data found")
                else:
                    await self.send_privmsg(channel, f"EPSS lookup failed (status {resp.status})")
                    
        except aiohttp.client_exceptions.ClientError as e:
            log.error(f"EPSS lookup error: {e}")
            await self.send_privmsg(channel, "Network error fetching EPSS")
        except (KeyError, ValueError, TypeError) as e:
            log.error(f"EPSS parsing error for {cve_id}: {e}")
            await self.send_privmsg(channel, "Error parsing EPSS response")
    
    async def cmd_crypto(self, nick, uhost, channel, arg):
        """Crypto price lookup - matches original Tcl vwckcrypto"""
        
        parts = arg.lower().split()
        if not parts:
            await self.send_privmsg(channel, "Usage: !crypto <coin> [currency] [amount]")
            return
        
        coin_input = parts[0]
        currency_input = parts[1] if len(parts) > 1 else 'usd'
        amount_input = parts[2] if len(parts) > 2 else None
        
        # Coin mapping from Tcl (coin_id, symbol, fullname - fullname unused)
        coin_map = {
            'btc': ('bitcoin', 'BTC', 'Bitcoin'),
            'bitcoin': ('bitcoin', 'BTC', 'Bitcoin'),
            'ltc': ('litecoin', 'LTC', 'Litecoin'),
            'litecoin': ('litecoin', 'LTC', 'Litecoin'),
            'eth': ('ethereum', 'ETH', 'Ethereum'),
            'ethereum': ('ethereum', 'ETH', 'Ethereum'),
            'nmc': ('namecoin', 'NMC', 'Namecoin'),
            'namecoin': ('namecoin', 'NMC', 'Namecoin'),
            'doge': ('dogecoin', 'DOGE', 'Dogecoin'),
            'dogecoin': ('dogecoin', 'DOGE', 'Dogecoin'),
            'xmr': ('monero', 'XMR', 'Monero'),
            'monero': ('monero', 'XMR', 'Monero'),
            'sol': ('solana', 'SOL', 'Solana'),
            'solana': ('solana', 'SOL', 'Solana'),
            'gala': ('gala', 'GALA', 'Gala'),
            'ada': ('cardano', 'ADA', 'Cardano'),
            'dot': ('polkadot', 'DOT', 'Polkadot'),
            'avax': ('avalanche-2', 'AVAX', 'Avalanche'),
            'link': ('chainlink', 'LINK', 'Chainlink'),
            'matic': ('matic-network', 'MATIC', 'Polygon'),
            'bnb': ('binancecoin', 'BNB', 'Binance Coin'),
            'shib': ('shiba-inu', 'SHIB', 'Shiba Inu'),
            'usdt': ('tether', 'USDT', 'Tether'),
            'usdc': ('usd-coin', 'USDC', 'USD Coin'),
            'trx': ('tron', 'TRX', 'Tron'),
            'atom': ('cosmos', 'ATOM', 'Cosmos'),
            'etc': ('ethereum-classic', 'ETC', 'Ethereum Classic'),
            'xrp': ('ripple', 'XRP', 'XRP (Ripple)'),
            'vet': ('vechain', 'VET', 'VeChain'),
            'algo': ('algorand', 'ALGO', 'Algorand'),
            'hbar': ('hedera-hashgraph', 'HBAR', 'Hedera'),
            'xlm': ('stellar', 'XLM', 'Stellar'),
        }
        
        crypto_id, symbol, fullname = coin_map.get(coin_input, coin_map['btc'])
        
        # Fiat mapping from Tcl (fiat_id, symbol_str)
        fiat_map = {
            'usd': ('usd', '$USD'),
            'cad': ('cad', '$CAD'),
            'eur': ('eur', '€EUR'),
            'gbp': ('gbp', '£GBP'),
            'jpy': ('jpy', '¥JPY'),
            'aud': ('aud', '$AUD'),
            'chf': ('chf', 'CHF'),
            'cny': ('cny', '¥CNY'),
            'inr': ('inr', '₹INR'),
            'rub': ('rub', '₽RUB'),
            'nzd': ('nzd', '$NZD'),
            'hkd': ('hkd', '$HKD'),
            'krw': ('krw', '₩KRW'),
            'brl': ('brl', 'R$BRL'),
            'mxn': ('mxn', '$MXN'),
            'zar': ('zar', 'RZAR'),
            'sgd': ('sgd', '$SGD'),
            'try': ('try', '₺TRY'),
            'sek': ('sek', 'krSEK'),
            'nok': ('nok', 'krNOK'),
        }
        
        fiat_id, fsymbol = fiat_map.get(currency_input, fiat_map['usd'])
        
        try:
            url = f"https://api.coingecko.com/api/v3/simple/price?ids={crypto_id}&vs_currencies={fiat_id}"
            async with self.http_session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    await self.send_privmsg(channel, "Error fetching crypto data")
                    return
                data = await resp.json()
                if crypto_id not in data or fiat_id not in data[crypto_id]:
                    await self.send_privmsg(channel, "Error: Could not parse price.")
                    return
                
                price = data[crypto_id][fiat_id]
                if amount_input is None:
                    await self.send_privmsg(channel, f"Crypto price: {price}{fsymbol} per {symbol}")
                else:
                    try:
                        amount = float(amount_input)
                        total = price * amount
                        await self.send_privmsg(channel, f"Crypto price: {total}{fsymbol} for {amount} {symbol}")
                    except ValueError:
                        await self.send_privmsg(channel, "Invalid amount")
        except Exception as e:
            self.log.error(f"Crypto lookup error: {e}")
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
    
    async def cmd_news(self, nick, uhost, channel, arg):
        """News from RSS feeds - matches original Tcl vwcknews"""
        
        num = 5
        if arg.strip() and arg.strip().isdigit():
            num = max(1, min(10, int(arg.strip())))
        
        rss_feeds = [
            "https://news.ycombinator.com/rss",
            "https://techcrunch.com/feed/",
            "http://www.theregister.com/headlines.atom",
            "https://lifehacker.com/rss",  # Fixed: was /feed/rss
            "https://www.bleepingcomputer.com/feed/",
        ]
        
        today_str = datetime.utcnow().strftime("%Y-%m-%d")
        
        async def fetch_feed(url):
            try:
                async with self.http_session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.text()
                        feed = feedparser.parse(data)
                        return feed.entries or []
            except Exception:
                pass
            return []
        
        # Concurrent fetch all feeds
        tasks = [fetch_feed(url) for url in rss_feeds]
        all_entries = []
        for entries in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(entries, list):
                all_entries.extend(entries)
        
        # Filter today's GMT articles (match Tcl logic)
        news_list = []
        for entry in all_entries:
            pubdate_str = entry.get('published') or entry.get('updated', '')
            try:
                pubdate = feedparser.parsedate_to_datetime(pubdate_str)
                if pubdate and pubdate.strftime("%Y-%m-%d") == today_str:
                    title = entry.get('title', '').strip()
                    link = entry.get('link', '').strip()
                    if title and link:
                        news_list.append(f"{title} - {link}")
            except:
                pass
        
        if not news_list:
            await self.send_privmsg(channel, "No news available at the moment.")
            return
        
        # Shuffle (match Tcl rand shuffle)
        random.shuffle(news_list)
        news_list = news_list[:num]
        
        # Send one per line
        for item in news_list:
            await self.send_privmsg(channel, item)

    # MX - matches vwckdns_mx exactly
    async def cmd_mx(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'MX')
        if not records:
            await self.send_privmsg(channel, "No MX records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"MX records for {domain}: {display}")

    # A records
    async def cmd_a(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'A')
        if not records:
            await self.send_privmsg(channel, "No A records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"A records for {domain}: {display}")

    # AAAA records
    async def cmd_aaaa(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'AAAA')
        if not records:
            await self.send_privmsg(channel, "No AAAA records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"AAAA records for {domain}: {display}")

    # NS records
    async def cmd_ns(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'NS')
        if not records:
            await self.send_privmsg(channel, "No NS records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"NS records for {domain}: {display}")

    # PTR records (IPv4 reverse)
    async def cmd_ptr(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'PTR')
        if not records:
            await self.send_privmsg(channel, "No PTR records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"PTR records for {domain}: {display}")

    # PTR6 (IPv6 reverse lookup)
    async def cmd_ptr6(self, nick, uhost, channel, ip):
        ip = ip.strip()
        try:
            ipv6 = ipaddress.IPv6Address(ip)
            rev_domain = ipv6.reverse_pointer
        except ValueError:
            await self.send_privmsg(channel, "Invalid IPv6 address format.")
            return
        
        records = await self.get_dns_records(rev_domain, 'PTR')
        if not records:
            await self.send_privmsg(channel, f"No PTR6 records found for {ip}")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"PTR6 records for {ip} ({rev_domain}): {display}")

    # DMARC (_dmarc.domain.com TXT)
    async def cmd_dmarc(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        dmarc_domain = f"_dmarc.{domain}"
        records = await self.get_dns_records(dmarc_domain, 'TXT')
        if not records:
            await self.send_privmsg(channel, f"No DMARC record found for {domain}")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"DMARC record for {domain}: {display}")

    # SPF (TXT v=spf1 filtered)
    async def cmd_spf(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'TXT')
        spf_records = [r for r in records if r.startswith('v=spf')]
        if not spf_records:
            await self.send_privmsg(channel, f"No SPF record found for {domain}")
            return
        display = ', '.join(spf_records)
        await self.send_privmsg(channel, f"SPF record for {domain}: {display}")

    # DKIM (common selectors)
    async def cmd_dkim(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        selectors = ['google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2', 'mail', 'default']
        found = []
        for sel in selectors:
            records = await self.get_dns_records(f"{sel}._domainkey.{domain}", 'TXT')
            if records:  # records is now list[str]
                found.append(f"{sel}: {records[0][:80]}...")
        if not found:
            await self.send_privmsg(channel, f"No common DKIM selectors found for {domain}")
            return
        display = ', '.join(found)
        await self.send_privmsg(channel, f"DKIM selectors for {domain}: {display}")

    # SOA
    async def cmd_soa(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'SOA')
        if not records:
            await self.send_privmsg(channel, "No SOA records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"SOA records for {domain}: {display}")

    # SRV
    async def cmd_srv(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'SRV')
        if not records:
            await self.send_privmsg(channel, "No SRV records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"SRV records for {domain}: {display}")

    # CAA
    async def cmd_caa(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'CAA')
        if not records:
            await self.send_privmsg(channel, "No CAA records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"CAA records for {domain}: {display}")

    # TXT (all)
    async def cmd_txt(self, nick, uhost, channel, domain):
        domain = domain.strip()
        if re.search(r'[^a-zA-Z0-9._-]', domain):
            await self.send_privmsg(channel, "Invalid domain format.")
            return
        records = await self.get_dns_records(domain, 'TXT')
        if not records:
            await self.send_privmsg(channel, "No TXT records found")
            return
        display = ', '.join(records)
        await self.send_privmsg(channel, f"TXT records for {domain}: {display}")
    
    async def cmd_trend(self, nick, uhost, channel, arg):
        """CVE Trends RSS - pure regex, matches Tcl vwcktrend"""        
        num = 5
        if arg.strip():
            try:
                n = float(arg.strip())
                num = max(1, min(10, n))
            except ValueError:
                pass
        
        url = "https://intel.intruder.io/rss/cvetrends/latest"
        
        try:
            async with self.http_session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                xml = await resp.text()
        except Exception as e:
            self.log.error(f"Trend fetch error: {e}")
            await self.send_privmsg(channel, f"Error fetching trend data: {e}")
            return
        
        if not xml.strip():
            await self.send_privmsg(channel, "Error: Failed to fetch data.")
            return
        
        # Pure regex - exact Tcl patterns
        item_pattern = r'<item>.*?</item>'
        items = re.findall(item_pattern, xml, re.DOTALL | re.IGNORECASE)
        
        count = 0
        for item in items:
            if count >= num:
                return
            
            # CVE from <title><![CDATA[CVE-...]]></title>
            cve_pattern = r'<title><!\[CDATA\[(.*?)\]\]></title>'
            cve_match = re.search(cve_pattern, item, re.IGNORECASE)
            cve = cve_match.group(1).strip() if cve_match else ""
            
            # Link from <link>URL</link>
            link_pattern = r'<link>(.*?)</link>'
            link_match = re.search(link_pattern, item, re.DOTALL | re.IGNORECASE)
            link = link_match.group(1).strip() if link_match else ""
            
            # Hype from <intruder:hypeScore>NN</intruder:hypeScore>
            hype_pattern = r'<intruder:hypeScore>(\d+)</intruder:hypeScore>'
            hype_match = re.search(hype_pattern, item, re.IGNORECASE)
            hype = hype_match.group(1) if hype_match else ""
            
            if cve and link and hype:
                await self.send_privmsg(channel, f"{cve} - Hype: {hype}/100, Link: {link}")
            count += 1
        
        return
    
    async def cmd_lastcve(self, nick, uhost, channel, arg):
        """Last CVEs - matches original Tcl vwcklastcve"""        
        num = 5
        if arg.strip() and arg.strip().lstrip('-').isdigit():
            n = float(arg.strip())
            num = max(1, min(10, n))
        
        url = f"https://cve.circl.lu/api/last/{int(num)}"
        
        try:
            async with self.http_session.get(url, timeout=30) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                data_text = await resp.text()
                cves: List[Dict[str, Any]] = json.loads(data_text)
        except Exception as e:
            self.log.error(f"CVE fetch error: {e}")
            await self.send_privmsg(channel, f"Error fetching CVEs: {e}")
            return
        
        count = 0
        for cve in cves:
            if count >= num:
                break
            
            # Extract CVE ID (match Tcl: cveMetadata or aliases regex CVE-*-*)
            cve_id = ""
            if cve.get('cveMetadata', {}).get('cveId'):
                cve_id = cve['cveMetadata']['cveId']
            elif 'aliases' in cve:
                for alias in cve['aliases']:
                    if isinstance(alias, str) and alias.startswith('CVE-') and '-' in alias[4:]:
                        cve_id = alias
                        break
            
            if not cve_id:
                continue
            
            # Extract first English desc/title (match Tcl priority)
            cve_title = "No description available"
            containers = cve.get('containers', {})
            cna = containers.get('cna', {})
            descriptions = cna.get('descriptions', [])
            for desc_dict in descriptions:
                if isinstance(desc_dict, dict) and desc_dict.get('lang') == 'en' and 'value' in desc_dict:
                    cve_title = desc_dict['value']
                    break
            else:
                # Fallback to details if no desc
                cve_title = cve.get('details', 'No description available')
            
            msg = f"{cve_id}: {cve_title}"
            await self.send_privmsg(channel, clean_message(msg))
            count += 1
        
        if count == 0:
            await self.send_privmsg(channel, "No recent CVEs found.")
    
    # Utility commands (simplified)
    async def cmd_website(self, nick, uhost, channel, arg):
        """Website title lookup"""
        url = arg.strip()
        if not url:
            await self.send_privmsg(channel, "Usage: !website <url>")
            return
        
        if not re.match(r'^https?://', url):
            url = 'https://' + url
        
        try:
            async with self.http_session.get(url, timeout=10, allow_redirects=True) as resp:
                if resp.status != 200:
                    await self.send_privmsg(channel, f"Error: HTTP {resp.status}")
                    return
                html = await resp.text()
        except Exception as e:
            await self.send_privmsg(channel, f"Error fetching {url}: {e}")
            return
        
        title = await self._extract_title(html)
        if title:
            await self.send_privmsg(channel, f"Title: {title}")
        else:
            await self.send_privmsg(channel, f"No title found for {url}")

    async def cmd_youtube(self, nick, uhost, channel, arg):
        """YouTube title lookup"""  
        url = arg.strip()
        if not url:
            await self.send_privmsg(channel, "Usage: !youtube <url>")
            return
        
        parsed = urllib.parse.urlparse(url)
        if 'youtube.com' not in parsed.netloc and 'youtu.be' not in parsed.netloc:
            await self.send_privmsg(channel, "Invalid YouTube URL")
            return
        
        try:
            async with self.http_session.get(url, timeout=10, allow_redirects=True) as resp:
                if resp.status != 200:
                    await self.send_privmsg(channel, f"Error: HTTP {resp.status}")
                    return
                html = await resp.text()
        except Exception as e:
            await self.send_privmsg(channel, f"Error fetching YouTube: {e}")
            return
        
        # YouTube meta title fallback
        title = (await self._extract_title(html) or
                self._extract_meta_title(html) or
                "No title found")
        await self.send_privmsg(channel, f"Title: {title}")

    async def cmd_portscan(self, nick, uhost, channel, arg):
        """Port scan - your Tcl blocks + safe Python logic"""

        parts = arg.split()
        scanall = parts and parts[0] == '-all'
        if scanall:
            parts = parts[1:]
        target = ' '.join(parts).strip()
        
        if re.search(r'[^a-zA-Z0-9._-]', target):
            await self.send_privmsg(channel, "Invalid input. Please enter a valid IP or domain.")
            return
        
        # Your exact .gov block
        if re.search(r'\.gov$', target):
            await self.send_privmsg(channel, "Invalid input. Please enter a valid IP or domain.")
            return
        
        # Your exact private/special IP block
        private_regex = r'^(127\..*|10\..*|192\.168\..*|172\.(1[6-9]|2[0-9]|3[0-1])\..*|169\.254\..*|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\..*|224\..*|255\.255\.255\.255|0\.0\.0\.0)$'
        if re.match(private_regex, target):
            await self.send_privmsg(channel, f"Scan denied: {target} is a private or special IP.")
            return
        
        # Parse ports (default top 20 if missing)
        port_parts = target.split(':')
        ip = port_parts[0]
        ports_str = port_parts[1] if len(port_parts) > 1 else "21,22,23,25,53,80,110,143,443,993,995,1723,3306,3389,5432,5900,8080,8443"
        
        ports = [int(p) for p in ports_str.split(',') if p.strip().isdigit()]
        if len(ports) > 20:
            await self.send_privmsg(channel, "Max 20 ports (anti-abuse)")
            return
        if not ports:
            await self.send_privmsg(channel, "No valid ports specified")
            return
        
        # Safe async TCP scan (max 10 concurrent)
        open_ports = []
        semaphore = asyncio.Semaphore(10)
        
        async def check_port(p):
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, p), timeout=2
                    )
                    writer.close()
                    await writer.wait_closed()
                    return p
                except:
                    return None
        
        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        open_ports = sorted([p for p in results if p])
        
        if open_ports:
            scan_results = f"{ip} - Open Ports: {','.join(map(str, open_ports))}"
            # Split long output (your Tcl logic)
            max_length = 400
            max_messages = 5
            count = 0
            while len(scan_results) > max_length and count < max_messages:
                part = scan_results[:max_length]
                scan_results = scan_results[max_length + 1:]
                await self.send_privmsg(channel, part)
                count += 1
            if scan_results and count < max_messages:
                await self.send_privmsg(channel, scan_results)
            if count >= max_messages:
                await self.send_privmsg(channel, "Output too long. Some results may be missing.")
        else:
            await self.send_privmsg(channel, f"No open ports found on {ip}.")

    async def cmd_waf(self, nick, uhost, channel, arg):
        """WAF detection"""
        
        if not arg.strip():
            await self.send_privmsg(channel, "Usage: !waf <URL>")
            return
        
        url = arg.strip()
        if not re.match(r'^https?://', url):
            url = 'https://' + url
        
        try:
            # HEAD only (-nobody equivalent)
            async with self.http_session.head(url, timeout=10, allow_redirects=True) as resp:
                headers = str(resp.headers).lower()
        except Exception as e:
            await self.send_privmsg(channel, f"Error accessing {url}: {e}")
            return
        
        waf_patterns = [
            # Your original (top tier)
            "cloudflare", "sucuri", "imperva", "akamai", "f5 big-ip", "incapsula",
            "barracuda", "fortiweb", "aws waf", "radware", "stackoverflow",
            
            # Cloud giants (2026 leaders)
            "azure", "google cloud", "fastly", "cloudfront", "gcp",
            
            # Enterprise heavyweights
            "modsecurity", "nginx", "nginx waf", "varnish", "litespeed",
            
            # Regional/niche from wafw00f
            "360waf", "alicloud", "aliyundun", "barracuda", "bitninja",
            "cloudbric", "ddos-guard", "fortigate", "imunify360", "palo alto",
            "wallarm", "watchguard", "webknight"
        ]
        
        for pattern in waf_patterns:
            if pattern.lower() in headers:
                await self.send_privmsg(channel, f"{url} is protected by a WAF: {pattern.title()}")
                return
        
        await self.send_privmsg(channel, f"No known WAF detected on {url}.")

    async def cmd_tech(self, nick, uhost, channel, arg):
        """Tech detection"""
        
        if not arg.strip():
            await self.send_privmsg(channel, "Usage: !tech <URL>")
            return
        
        url = arg.strip()
        if not re.match(r'^https?://', url):
            url = 'https://' + url
        
        try:
            async with self.http_session.get(url, timeout=10, allow_redirects=True) as resp:
                page_content = (await resp.text()).lower()
        except Exception as e:
            await self.send_privmsg(channel, f"Failed to fetch content from {url}: {e}")
            return
        
        tech_patterns = [
            # Your original CMS
            ("WordPress", '<meta name="generator" content="wordpress"'),
            ("Joomla", "com_content"),
            ("Drupal", "/sites/default/files/"),
            
            # Additional CMS
            ("Magento", "/magento_version"),
            ("Shopify", "shopify"),
            ("Squarespace", "squarespace"),
            ("Wix", "wix"),
            ("Ghost", "ghost"),
            ("Discourse", "/discourse"),
            
            # PHP Frameworks
            ("Laravel", "laravel_session"),
            ("CodeIgniter", "codeigniter"),
            ("Symfony", "symfony/"),
            
            # JS Frameworks (dev/prod)
            ("ReactJS", "react.development.js"),
            ("ReactJS", "__webpack_require__"),
            ("AngularJS", "angular.js"),
            ("VueJS", "vue.js"),
            ("Next.js", "/_next/"),
            ("Nuxt.js", "/nuxt/"),
            
            # Common libraries
            ("jQuery", "jquery.min.js"),
            ("Bootstrap", "bootstrap.min.css"),
            ("React", "react-dom"),
            
            # Servers/Hosting
            ("Apache", "apache"),
            ("Nginx", "nginx"),
            ("IIS", "iis"),
            ("cPanel", "cpanel"),
            
            # Analytics/Tracking
            ("Google Analytics", "_ga="),
            ("Matomo", "matomo"),
            
            # E-commerce
            ("WooCommerce", "woocommerce"),
            ("PrestaShop", "prestashop")
        ]
        
        found = []
        for tech, pattern in tech_patterns:
            if pattern.lower() in page_content:
                found.append(tech)
        
        if found:
            await self.send_privmsg(channel, f"{url} is using: {', '.join(found)}.")
        else:
            await self.send_privmsg(channel, f"No common technologies detected on {url}.")
        
    async def cmd_whois(self, nick, uhost, channel, arg):
        """WHOIS lookup (domain/IP/AS)"""
        if not self.bot.get_channel_setting(channel, 'pubcom', False):
            return
        arg = arg.strip()
        if not arg:
            await self.send_privmsg(channel, "Usage: !whois <domain|IP|ASN>")
            return
        try:
            if arg.isdigit():
                result = await whoisit.asn_async(arg)
                title = f"AS{result.get('asn', '')} {result.get('name', 'N/A')}"
            else:
                result = await whoisit.domain_async(arg)
                title = result.get('domain', arg)
            await self.send_privmsg(channel, f"WHOIS {arg}: {title}")
        except Exception as e:
            await self.send_privmsg(channel, f"WHOIS error: {e}")
    
    async def cmd_geoip(self, nick, uhost, channel, arg):
        """GeoIP via whois - matches Tcl vwckgeoip (free)"""
        if not self.bot.get_channel_setting(channel, 'pubcom', False):
            return
        
        if not arg.strip():
            await self.send_privmsg(channel, "Usage: !geoip <IP>")
            return
        
        ip = arg.strip()
        
        # Your exact IPv4 validation
        match = re.match(r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$', ip)
        if not match:
            await self.send_privmsg(channel, "Invalid IP address format.")
            return
        
        o1, o2, o3, o4 = map(int, match.groups())
        if any(o < 0 or o > 255 for o in [o1, o2, o3, o4]):
            await self.send_privmsg(channel, "Invalid IP address format.")
            return
        
        # Your exact 16 reserved ranges (subnet/mask)
        reserved_ips = [
            (0,0,0,0,8), (10,0,0,0,8), (100,64,0,0,10), (127,0,0,0,8),
            (169,254,0,0,16), (172,16,0,0,12), (192,0,0,0,24), (192,0,2,0,24),
            (192,88,99,0,24), (192,168,0,0,16), (198,18,0,0,15), (198,51,100,0,24),
            (203,0,113,0,24), (224,0,0,0,4), (240,0,0,0,4), (255,255,255,255,32)
        ]
        
        # Binary subnet match (your logic)
        ip_binary = f"{o1:08b}{o2:08b}{o3:08b}{o4:08b}"
        for s1, s2, s3, s4, mask in reserved_ips:
            subnet_binary = f"{s1:08b}{s2:08b}{s3:08b}{s4:08b}"
            if ip_binary[:mask] == subnet_binary[:mask]:
                await self.send_privmsg(channel, f"{ip} is a reserved/private IP address.")
                return
        
        # Your whois + Country: regex
        try:
            proc = await asyncio.create_subprocess_exec(
                'whois', ip, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            whois_result = stdout.decode('utf-8', errors='ignore')
            
            country_match = re.search(r'country:\s*(.+)', whois_result, re.IGNORECASE)
            if country_match:
                country = country_match.group(1).strip()
                await self.send_privmsg(channel, f"IP {ip} is registered in: {country}")
            else:
                await self.send_privmsg(channel, f"Could not determine location for IP {ip}.")
        except Exception:
            await self.send_privmsg(channel, "Whois lookup failed.")
    
    async def cmd_asn(self, nick, uhost, channel, arg):
        """ASN via whois - matches Tcl vwckasn (free)"""
        if not self.bot.get_channel_setting(channel, 'pubcom', False):
            return
        
        if not arg.strip():
            await self.send_privmsg(channel, "Usage: !asn <IP>")
            return
        
        ip = arg.strip()
        
        # Reuse geoip validation (IPv4 + reserved check)
        match = re.match(r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$', ip)
        if not match:
            await self.send_privmsg(channel, "Invalid IP address format.")
            return
        
        o1, o2, o3, o4 = map(int, match.groups())
        if any(o < 0 or o > 255 for o in [o1, o2, o3, o4]):
            await self.send_privmsg(channel, "Invalid IP address format.")
            return
        
        # Reserved IPs (reuse your geoip list)
        reserved_ips = [
            (0,0,0,0,8), (10,0,0,0,8), (100,64,0,0,10), (127,0,0,0,8),
            (169,254,0,0,16), (172,16,0,0,12), (192,0,0,0,24), (192,0,2,0,24),
            (192,88,99,0,24), (192,168,0,0,16), (198,18,0,0,15), (198,51,100,0,24),
            (203,0,113,0,24), (224,0,0,0,4), (240,0,0,0,4), (255,255,255,255,32)
        ]
        
        ip_binary = f"{o1:08b}{o2:08b}{o3:08b}{o4:08b}"
        for s1, s2, s3, s4, mask in reserved_ips:
            subnet_binary = f"{s1:08b}{s2:08b}{s3:08b}{s4:08b}"
            if ip_binary[:mask] == subnet_binary[:mask]:
                await self.send_privmsg(channel, f"{ip} is a reserved/private IP address.")
                return
        
        # Your exact whois + OriginAS: regex
        try:
            proc = await asyncio.create_subprocess_exec(
                'whois', ip, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            whois_result = stdout.decode('utf-8', errors='ignore')
            
            asn_match = re.search(r'OriginAS:\s*(AS\d+)', whois_result, re.IGNORECASE)
            if asn_match:
                asn = asn_match.group(1)
                await self.send_privmsg(channel, f"IP {ip} belongs to ASN: {asn}")
            else:
                await self.send_privmsg(channel, f"Could not determine ASN for IP {ip}.")
        except Exception:
            await self.send_privmsg(channel, "Whois lookup failed.")
    
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

    async def get_dns_records(self, domain: str, qtype: str) -> List[str]:
        """Helper: returns list[str] from aiodns results"""
        try:
            results = await self.dns_resolver.query(domain, qtype)
            if qtype == 'TXT':
                return [r.text for r in results if hasattr(r, 'text')]
            else:
                return [str(r.host) for r in results if hasattr(r, 'host')]
        except Exception:
            return []
        
    async def _extract_title(self, html):
        """Extract <title> tag"""
        soup = BeautifulSoup(html, 'html.parser')
        title_tag = soup.find('title')
        return (title_tag.get_text().strip() if title_tag else None)

    def _extract_meta_title(self, html):
        """Fallback: og:title or twitter:title meta"""
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