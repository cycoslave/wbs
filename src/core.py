#!/usr/bin/env python3
"""
src/core.py - Core logic process: event_q -> commands/DB; cmd_q -> irc.py.
No IRC reactor; pure queue processor.
"""
import asyncio
import multiprocessing as mp
import queue
import time
import logging
import os
from pathlib import Path
from typing import Dict, Any

import aiosqlite  # For inline DB if needed

# Local modules
from .db import get_db, init_db  # Async DB conn
from .user import get_user_info, get_user_flags, SeenDB
from .channel import get_channel_info
from .botnet import BotnetManager

logger = logging.getLogger("wbs.core")
BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / "wbs.db"  # Or from config

class CoreEventLoop:
    def __init__(self, config: dict, event_q: mp.Queue, cmd_q: mp.Queue):
        self.config = config
        self.event_q = event_q
        self.cmd_q = cmd_q
        self.db = None
        self.seen = SeenDB()
        self.botnet_mgr = None
        self.db_path = config.get('db_path', config['db']['path'])
        self.channels = config.get('channels', config['bot'].get('channels', []))

    def run(self):
        """Sync main loop: poll event_q, process events."""
        asyncio.run(self._async_init())
        logger.info("Core event loop started")
        
        while True:
            try:
                msg_type, data = self.event_q.get(timeout=1.0)
                if msg_type == 'event':
                    asyncio.run(self.handle_event(data))
            except queue.Empty:
                self._periodic_tasks()
                time.sleep(0.05)  # 20Hz poll, low CPU

    async def _async_init(self):
        """One-time async setup: DB schema, managers."""
        await init_db(self.db_path)  # Schema only
        self.seen = SeenDB() 
        
        # Conditional + correct args (per file:5: queuetocore, queuefromcore, dbpath)
        botnet_cfg = self.config.get('botnet', {})
        if botnet_cfg.get('enabled', False):
            from .botnet import BotnetManager
            self.botnet_mgr = BotnetManager(self.cmd_q, self.event_q, self.db_path)
            await self.botnet_mgr.load_config()  # Method name from file:5
        else:
            self.botnet_mgr = None
        
        logger.info(f"Core ready: path={self.db_path}, botnet={self.botnet_mgr is not None}")

    async def handle_event(self, event: Dict[str, Any]):
        """Dispatch events to handlers."""
        etype = event['type']
        if etype == 'COMMAND':
            await self.do_command(event)
        elif etype == 'PUBMSG':
            await self.on_pubmsg(event)
        elif etype == 'PRIVMSG':
            await self.on_privmsg(event)
        elif etype == 'JOIN':
            await self.on_join(event)
        elif etype == 'PART':
            await self.on_part(event)
        elif etype == 'READY':
            logger.info("IRC connected")
        elif etype == 'ERROR':
            logger.error(f"IRC error: {event.get('data')}")
        # Add KICK, QUIT, etc.

    async def do_command(self, event: Dict[str, Any]):
        """Execute authorized commands (Eggdrop-style)."""
        nick = event['nick']
        text = event['text'].strip()
        user_info = await get_user_info(self.db, nick)
        
        if not user_info.get('authorized', False):
            self.send_cmd('msg', nick, "Not authorized.")
            return
        
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        if cmd == 'stats':
            await self.cmd_stats(nick)
        elif cmd == 'seen':
            await self.cmd_seen(nick, args)
        elif cmd == 'help':
            self.send_cmd('msg', nick, "Commands: stats seen help .wckbots .wckbotinfo .net .subnet")
        elif cmd.startswith('.wck'):  # DCC partyline
            await self.handle_dcc_cmd(cmd[4:], nick, args)  # .wckbots -> bots
        else:
            self.send_cmd('msg', nick, f"Unknown command: {text}")

    async def cmd_stats(self, nick: str):
        """Channel stats."""
        for ch in self.channels:
            ch_info = await get_channel_info(self.db, ch)
            users = len(ch_info.get('users', []))
            self.send_cmd('msg', nick, f"{ch}: {users} users")

    async def cmd_seen(self, from_nick: str, target_nick: str):
        """Track/find users."""
        if not await self.seen.check_rate_limit(from_nick):
            self.send_cmd('msg', from_nick, "Rate limit hit.")
            return
        data = await self.seen.get_seen(target_nick)
        if data:
            msg = f"{target_nick} seen {data['time']} on {data['channel']} ({data['action']}) host:{data['host']}"
            self.send_cmd('msg', from_nick, msg)
        else:
            self.send_cmd('msg', from_nick, f"{target_nick} not seen.")

    async def handle_dcc_cmd(self, cmd: str, hand: str, arg: str):
        """DCC partyline: bots, botinfo, net op/deop, subnet."""
        if cmd == 'bots':
            await self.botnet_mgr.cmd_bots(hand)
        elif cmd == 'botinfo':
            pid = os.getpid()
            pwd = os.getcwd()
            self.send_cmd('msg', hand, f"Pid: {pid} Dir: {pwd}")
        elif cmd == 'net':
            await self.botnet_mgr.handle_net(hand, arg, self.cmd_q)
        elif cmd == 'subnet':
            await self.botnet_mgr.handle_subnet(hand, arg)

    async def on_pubmsg(self, event):
        """Public msg: seen update, flood check."""
        nick = event['nick']
        host = event['host']
        await self.seen.update_seen(nick, host, event['channel'], 'PUBMSG')

    async def on_privmsg(self, event):
        """Private: treat as command if authorized."""
        # Reuse do_command logic
        await self.do_command(event)

    async def on_join(self, event):
        nick = event['nick']
        await self.seen.update_seen(nick, '', event['channel'], 'JOIN')

    async def on_part(self, event):
        nick = event['nick']
        await self.seen.update_seen(nick, '', event['channel'], 'PART')

    def send_cmd(self, cmd_type: str, target: str, text: str = ""):
        """Send to irc.py via cmd_q."""
        cmd_data = {'cmd': cmd_type, 'target': target}
        if text:
            cmd_data['text'] = text
        self.cmd_q.put(cmd_data)

    def _periodic_tasks(self):
        """Botnet poll, lag check (every ~5s)."""
        if self.botnet_mgr:
            self.botnet_mgr.poll_links()

def start_core_process(config: dict, event_q: mp.Queue, cmd_q: mp.Queue):
    """mp.Process target for main.py."""
    loop = CoreEventLoop(config, event_q, cmd_q)
    loop.run()
