#!/usr/bin/env python3
"""
src/core.py - Core logic process: event_q -> commands/DB; cmd_q -> irc.py.
No IRC reactor; pure queue processor.
"""
import asyncio
import multiprocessing as mp
import janus
import threading
import queue
import time
import logging
import os
from pathlib import Path
from typing import Dict, Any
from prompt_toolkit import PromptSession
from prompt_toolkit.styles import Style
from prompt_toolkit.patch_stdout import patch_stdout

import aiosqlite  # For inline DB if needed

# Local modules
from .db import get_db, init_db  # Async DB conn
from .user import get_user_info, get_user_flags, SeenDB, UserManager
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
        self.pending_events = []

    def event_poller(self):
        """Threaded poller like IRC/botnet – non-blocking get_nowait()."""
        while True:
            try:
                msg = self.event_q.get_nowait()
                logger.info(f"Core event: {msg.get('type')}, qsize={self.event_q.qsize()}")
                # Buffer for async loop (thread-safe list or queue)
                self.pending_events.append(msg)
            except queue.Empty:
                pass
            threading.Event().wait(0.05)  # Low CPU

    async def run(self):
        """Async main loop: drain buffer, process, periodic."""
        await self._async_init()
        logger.info("Core event loop started")
        
        poller_thread = threading.Thread(target=self.event_poller, daemon=True)
        poller_thread.start()
        
        while True:
            # Drain buffered events
            while self.pending_events:
                event = self.pending_events.pop(0)
                await self.handle_event(event)
            
            await self._periodic_tasks_async()
            await asyncio.sleep(0.1)

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
        """Sync put to IRC."""
        cmd_data = {'cmd': cmd_type, 'target': target}
        if text: cmd_data['text'] = text
        logger.info(f"Cmd put: {cmd_data}, qsize={self.cmd_q.qsize()}")
        self.cmd_q.put(cmd_data)

    def _periodic_tasks(self):
        """Botnet poll, lag check (every ~5s)."""
        if hasattr(self, 'botnet_mgr') and self.botnet_mgr:
            self.botnet_mgr.poll_links()
    
    async def _periodic_tasks_async(self):
        """Async wrapper for sync _periodic_tasks."""
        await asyncio.to_thread(self._periodic_tasks)

class Partyline:
    def __init__(self, config, event_q, cmd_q, irc_p, botnet_p): 
        self.config = config
        self.event_q = event_q
        self.cmd_q = cmd_q
        self.irc_p = irc_p
        self.botnet_p = botnet_p
        self.current_chan = 0
        self.user = "console"
        self.db_path = self.config['db']['path']
        self.db = get_db(self.db_path)
        self.users = UserManager()
        self.channels = {0: set()}
        self.sessions = {}
        self.event_q = event_q

    async def poll_botnet_events(self):  # <- HERE: async def in Partyline
        """Background: Print botnet/IRC events to partyline console."""
        while True:
            try:
                event = self.event_q.get_nowait()  # Fixed: sync get_nowait()
                logger.info(f"Partyline event: {event}")  # Debug
                if event.get('type') == 'chat':
                    print(f"[{event.get('channel', 0)}] <{event.get('user', '?')}> {event.get('text', '')}")
                elif event.get('type') == 'irc_join':
                    print(f"IRC: {event['nick']} joined {event['chan']}")
                # Add more: PRIVMSG → print, botnet cmds
            except queue.Empty:  # Fixed: catches mp.Queue exception
                pass
            await asyncio.sleep(0.05)  # Non-blocking

    async def handle_input(self, line):
        """Parse stdin → cmd_q for IRC/botnet."""
        line = line.strip()
        if not line:
            return
        
        if line.startswith('.'):
            cmd = line[1:].split(maxsplit=1)
            cmd_name = cmd[0]
            cmd_args = cmd[1] if len(cmd) > 1 else ''
            
            if cmd_name == 'help':
                print(".help .chans .status .sendnet <cmd> | chat freely")
            elif cmd_name == 'version':
                print("WBS 6.0.0")
            elif cmd_name == 'chans':
                print(f"Current: {self.current_chan} (0=global)")
            elif cmd_name == 'join':
                if len(cmd_args) >= 1:
                    cmd_data = {'cmd': cmd_name, 'channel': cmd_args if cmd_args else None}
                    await self.cmd_q.put(cmd_data)
                    print(f"→ JOIN: {cmd_args}")
                else:
                    print("Usage: .join #channel")
            elif cmd_name == 'part':
                if len(cmd_args) >= 1:
                    cmd_data = {'cmd': cmd_name, 'channel': cmd_args if cmd_args else None}
                    await self.cmd_q.put(cmd_data)
                    print(f"→ PART: {cmd_args}")
                else:
                    print("Usage: .part #channel")
            elif cmd_name == 'say':
                if len(cmd_args) >= 2:
                    chan = cmd_args[0]
                    msg = ' '.join(cmd_args[1:])
                    await self.cmd_q.privmsg(chan, msg)
                    print(f"→ SAY {chan}: {msg}")
                else:
                    print("Usage: .say #chan message")
            elif cmd_name == 'msg':
                if len(cmd_args) >= 2:
                    nick = cmd_args[0]
                    msg = ' '.join(cmd_args[1:])
                    await self.cmd_q.privmsg(nick, msg)
                    print(f"→ MSG {nick}: {msg}")
                else:
                    print("Usage: .msg nick message")                
            elif cmd_name == 'quit' or cmd_name == 'die':
                quit_msg = cmd_args or "WBS 6.0.0"
                await self.cmd_q.put(('cmd', 'quit', quit_msg))
                await asyncio.sleep(0.1)
                raise KeyboardInterrupt('Quit')
            elif cmd_name == 'chan':
                try:
                    self.current_chan = int(cmd_args) or 0
                    print(f"Switched to channel {self.current_chan}")
                except ValueError:
                    print("Usage: .chan <number>")
            #elif cmd_name == 'sendnet':
            #    self.cmd_q.put({'type': 'botnet_cmd', 'cmd': cmd_args, 'target': 'all'})
            #    print(f"→ Botnet: {cmd_args}")
            else:
                print("Invalid command!")
        else:
            # Chat → botnet
            await self.cmd_q.put({
                'type': 'chat', 'user': self.user,
                'text': line, 'channel': self.current_chan
            })
            print(f"[{self.current_chan}] <{self.user}> {line}")

    async def dispatch_cmd(self, cmd: str):
        parts = cmd.split()
        if parts[0] == 'help':
            # send help text
            pass
        elif parts[0] == 'chat':
            self.current_chan = int(parts[1]) if len(parts) > 1 else 0
        # Add .bots, .chans, .status, botnet cmds (.subnet, .sendnet)
        elif parts[0] == 'adduser':
            self.users.add_user(parts[1], hostmask=parts[2] if len(parts)>2 else None)

    def broadcast(self, msg: str, prefix='', local=False):
        chan_users = self.channels[self.current_chan]
        for handle in chan_users:
            # Send via session or botnet relay
            if local or not self.botnet.is_remote(handle):
                self.sessions[handle].output.write(f"{prefix}{msg}\n")

    async def run(self):
        """Partyline main loop + event poller."""
        poller_task = asyncio.create_task(self.poll_botnet_events())  # <- Starts it here
        
        session = PromptSession(message=f"WBS[{self.current_chan}] ")
        try:
            while True:
                line = await session.prompt_async()
                await self.handle_input(line)
        except KeyboardInterrupt:
            print("\nPartyline shutdown...")
        finally:
            poller_task.cancel()  # Clean shutdown

async def run_foreground_partyline(config, event_q, cmd_q, irc_p, botnet_p):
    """Entrypoint for main.py."""
    partyline = Partyline(config, event_q, cmd_q, irc_p, botnet_p)
    await partyline.run()

def start_core_process(config, event_q, cmd_q):
    loop = CoreEventLoop(config, event_q, cmd_q)
    asyncio.run(loop.run())  # Ensures async run()
