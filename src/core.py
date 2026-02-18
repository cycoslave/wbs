# src/core.py
"""
Core WBS bot logic: IRC event handling, commands, botnet integration.
Delegates to wbs.user/channel/botnet/db modules.
"""

import irc.bot
import irc.strings
import asyncio
import logging
import os
import sys
import time
import random
from pathlib import Path
from typing import Optional, Dict, Any, List

from .db import get_db
from .user import get_user_info, get_user_flags, SeenDB
from .channel import get_channel_info
from .botnet import BotnetManager

logger = logging.getLogger("wbs.core")

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "wbs.db"

class WBSBot(irc.bot.SingleServerIRCBot):
    def __init__(self, server_list: List[str], nickname: str, realname: str,
                 db_path: Path = DB_PATH, channels: List[str] = None):
        super().__init__(server_list, nickname, realname)
        self.db_path = db_path
        self.channels = channels or []
        self.db = None
        self.seen = None
        self.botnet_mgr: Optional[BotnetManager] = None
        self.irc_queue = asyncio.Queue()

    async def start(self):
        """Initialize DB/tasks then start IRC reactor."""
        self.db = await get_db(self.db_path)
        self.seen = SeenDB(self.db)
        await self.botnet_init()
        asyncio.create_task(self.limit_timer())
        asyncio.create_task(self.start_update_check())
        super().start()

    async def botnet_init(self):
        """Load botnet manager."""
        self.botnet_mgr = BotnetManager(self.db, self)
        await self.botnet_mgr.load_bots()

    def on_welcome(self, conn, event):
        for ch in self.channels:
            conn.join(ch)
        logger.info(f"WBS joined channels: {self.channels}")

    def on_pubmsg(self, conn, event):
        msg = event.arguments[0]
        prefix, *cmd_parts = msg.split(":", 1)
        if len(cmd_parts) > 0 and irc.strings.lower(prefix) == irc.strings.lower(conn.get_nickname()):
            asyncio.create_task(self.do_command(event, cmd_parts[0].strip()))

    def on_privmsg(self, conn, event):
        asyncio.create_task(self.do_command(event, event.arguments[0]))

    def on_join(self, conn, event):
        asyncio.create_task(self.on_event_join(event))

    def on_part(self, conn, event):
        asyncio.create_task(self.on_event_part(event))

    async def on_event_join(self, event):
        """Unified JOIN tracking."""
        nick = event.source.nick
        hostmask = getattr(event.source, 'host', '') or ''
        channel = event.target
        await self.seen.update_seen(nick, hostmask, channel, 'JOIN')

    async def on_event_part(self, event):
        """Unified PART tracking."""
        nick = event.source.nick
        hostmask = getattr(event.source, 'host', '') or ''
        channel = event.target
        await self.seen.update_seen(nick, hostmask, channel, 'PART')

    async def do_command(self, event, text: str):
        """Handle authorized commands."""
        nick = event.source.nick
        conn = self.connection
        user_info = await get_user_info(self.db, nick)
        if not user_info.get('authorized', False):
            conn.notice(nick, "Not authorized.")
            return
        
        parts = text.split(maxsplit=1)
        cmd, args = (parts[0].lower(), parts[1] if len(parts) > 1 else "")
        
        if cmd == "stats":
            await self.cmd_stats(conn, nick)
        elif cmd == "seen":
            await self.cmd_seen(nick, args, conn)
        elif cmd == "help":
            conn.notice(nick, "Commands: stats seen help wckbots wckbotinfo net subnet")
        elif cmd.startswith("wck"):
            await self.handle_dcc_cmd(cmd, nick, args)
        else:
            conn.notice(nick, f"Unknown: {text}")

    async def cmd_stats(self, conn, nick: str):
        """Channel user stats."""
        for chname in self.channels:
            ch_info = await get_channel_info(self.db, chname)
            users = len(ch_info.get('users', []))
            conn.notice(nick, f"{chname}: {users} users")

    async def cmd_seen(self, from_nick: str, target_nick: str, conn):
        """gseen.mod-style seen command."""
        if not await self.seen.check_rate_limit(from_nick):
            conn.notice(from_nick, "Rate limit exceeded.")
            return
        data = await self.seen.get_seen(target_nick)
        if data:
            msg = (f"{target_nick} last seen {data['lastseen_str']} "
                   f"on {data['channels']} ({data['action']}) from {data['hostmask']}")
            conn.notice(from_nick, msg)
        else:
            conn.notice(from_nick, f"{target_nick} not seen.")

    async def handle_dcc_cmd(self, full_cmd: str, hand: str, arg: str):
        """DCC partyline commands (.wck*)."""
        cmd = full_cmd[3:].lower()  # wckbots -> bots
        if cmd == "bots":
            await self.handle_wckbots(hand)
        elif cmd == "botinfo":
            await self.handle_wckbotinfo(hand)
        elif cmd == "net":
            await self.handle_net(hand, arg)
        elif cmd == "subnet":
            await self.handle_subnet(hand, arg)

    async def handle_wckbots(self, hand: str):
        """List linked/unlinked bots."""
        if not self.botnet_mgr:
            return
        await self.botnet_mgr.load_bots()
        linked_count = sum(1 for info in self.botnet_mgr.bots.values() if info.get('is_linked'))
        unlinked_count = len(self.botnet_mgr.bots) - linked_count - 1  # -self
        self.botnet_mgr.send_dcc(hand, f"Linked: {linked_count} Unlinked: {unlinked_count}")

    async def handle_wckbotinfo(self, hand: str):
        """Bot runtime info."""
        pid = os.getpid()
        pwd = os.getcwd()
        admin_flags = await get_user_flags(self.db, hand)
        self.botnet_mgr.send_dcc(hand, f"Pid: {pid} | Dir: {pwd} | Flags: {admin_flags}")

    async def handle_net(self, hand: str, arg: str):
        """Botnet network commands."""
        if not self.botnet_mgr or not await self.botnet_mgr.auth_sender(hand, flags='A'):
            return
        parts = arg.split()
        to_bot = "*"
        subnet = None
        this_too = True
        if parts and parts[0] in ("-b", "-B"):
            to_bot = parts[1]; parts = parts[2:]; this_too = False
        elif parts and parts[0] in ("-s", "-S"):
            subnet = parts[1]; parts = parts[2:]
        if parts and parts[0].startswith("!"):
            parts[0] = parts[0][1:]; this_too = False
        if not parts: return
        cmd = parts[0].lower()
        args_str = " ".join(parts[1:])
        
        if cmd == "op" and len(parts) >= 3:
            nick, chan = parts[1], parts[2]
            await self.botnet_mgr.broadcast("mode", f"+o {nick}", this_too, subnet, target=chan)
        elif cmd == "deop":
            # Similar
            pass
        elif cmd == "restart":
            os.execv(sys.executable, [sys.executable, "main.py"] + sys.argv[1:])
        # save/rehash/die/chanset etc.

    async def handle_subnet(self, hand: str, arg: str):
        """Subnet management."""
        if not self.botnet_mgr or not await self.botnet_mgr.auth_sender(hand):
            return
        parts = arg.split(maxsplit=1)
        cmd = parts[0].lower() if parts else ""
        if cmd == "show":
            self.botnet_mgr.send_dcc(hand, f"My Subnet: {self.botnet_mgr.subnet}")
        elif cmd == "set" and len(parts) > 1:
            old = self.botnet_mgr.subnet
            self.botnet_mgr.subnet = parts[1]
            await self.botnet_mgr.save_config()
            self.botnet_mgr.send_dcc(hand, f"Subnet: '{old}' → '{parts[1]}'")

    async def handle_botnet_cmd(self, msg: Dict[str, Any]):
        """Process incoming botnet message."""
        cmd = msg["cmd"]
        hand = msg["sender"]["hand"]
        if not await self.botnet_mgr.auth_sender(hand, msg.get("auth", {})):
            logger.warning(f"Unauthorized botnet cmd {cmd} from {hand}")
            return
        
        if cmd in ["op", "deop", "mode", "join", "part", "msg"]:
            await self.irc_queue.put((cmd, *msg["args"]))
        elif cmd == "restart":
            logger.info("Botnet restart triggered")
            os.execv(sys.executable, [sys.executable, "main.py"] + sys.argv[1:])
        elif cmd == "save":
            await self.db.save_all()
        elif cmd == "rehash":
            await self.botnet_mgr.load_config()
        logger.debug(f"Botnet cmd executed: {cmd}")

    async def limit_timer(self):
        """Auto-adjust channel limits."""
        while True:
            if not self.connection or not self.connection.is_connected():
                await asyncio.sleep(300)
                continue
            for chan in self.channels:
                now = time.time()
                last_change = await get_channel_info(self.db, chan, 'last_limit_change', 0)
                if now - last_change < 300:
                    continue
                users = len((await get_channel_info(self.db, chan)).get('users', []))
                new_limit = users + 5
                self.connection.mode(chan, f"+l {new_limit}")
                # Update DB last_change
            await asyncio.sleep(300 + random.randint(-30, 30))

    async def start_update_check(self):
        """Hourly update checker."""
        while True:
            # Implement update_mgr.check_update()
            await asyncio.sleep(3600)
