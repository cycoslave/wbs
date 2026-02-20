#!/usr/bin/env python3
"""
src/partyline.py - Console/DCC partyline interface

Handles:
- Console input/output for foreground mode
- Command parsing and routing to commands.py
- Event display from IRC/botnet processes
- Channel switching for multi-channel partyline
"""
import sys
import asyncio
import logging
from typing import Optional
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.history import InMemoryHistory 

from .commands import COMMANDS, handle_dcc_chat, handle_partyline_command
from .user import UserManager

logger = logging.getLogger(__name__)


class Partyline:
    def __init__(self, config, core_q):  # Only core_q needed
        self.config = config
        self.core_q = core_q  # ALL commands go to Core
        
        self.current_chan = 0
        self.user = "console"
        self.db_path = config['db']['path']
        self.users = UserManager()
        self.channels = {0: {'console'}}
        self.sessions = {}
        self.running = False

    async def poll_events(self):
        """Background task: display IRC/botnet events."""
        while self.running:
            try:
                event = await self.party_q.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.05)
            else:
                await self._handle_event(event)

    async def _handle_event(self, event: dict):
        """Process and display events from IRC/botnet."""
        event_type = event.get('type')
        
        if event_type == 'chat':
            # Botnet chat message
            chan = event.get('channel', 0)
            user = event.get('user', '?')
            text = event.get('text', '')
            print(f"[{chan}] <{user}> {text}")
            
        elif event_type == 'irc_join':
            nick = event.get('nick', '?')
            channel = event.get('chan', '?')
            print(f"*** {nick} joined {channel}")
            
        elif event_type == 'irc_part':
            nick = event.get('nick', '?')
            channel = event.get('chan', '?')
            reason = event.get('reason', '')
            print(f"*** {nick} left {channel} ({reason})")
            
        elif event_type == 'irc_msg':
            target = event.get('target', '?')
            nick = event.get('nick', '?')
            text = event.get('text', '')
            print(f"<{nick}:{target}> {text}")
            
        elif event_type == 'irc_notice':
            nick = event.get('nick', '?')
            text = event.get('text', '')
            print(f"-{nick}- {text}")
            
        elif event_type == 'botnet_link':
            bot = event.get('bot', '?')
            print(f"*** Botnet: {bot} linked")
            
        elif event_type == 'botnet_unlink':
            bot = event.get('bot', '?')
            print(f"*** Botnet: {bot} unlinked")
            
        elif event_type == 'error':
            msg = event.get('message', 'Unknown error')
            print(f"!!! ERROR: {msg}")
            
        else:
            logger.debug(f"Unhandled event type: {event_type}")


    async def handle_input(self, line: str):
        """Parse and route user input - commands or chat."""
        line = line.strip()
        if not line:
            return
        
        # Command dispatch
        if line.startswith('.'):
            await self._handle_command(line[1:])
        else:
            # Chat message to current botnet channel
            await self._send_chat(line)


    async def _handle_command(self, cmd_line: str):
        """Parse dot commands and route to appropriate handler."""
        parts = cmd_line.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ''
        if cmd == 'help':
            self._show_help()
        elif cmd == 'version':
            print("WBS 6.0.0")
        elif cmd == 'who':
            self._show_who()
        elif cmd == 'status':
            await self._show_status()
        elif cmd in COMMANDS:
            idx = 0
            await COMMANDS[cmd](self.config, self.core_q, self.irc_q, self.botnet_q, self.party_q, self.user, idx, args)
        else:
            print(f"Unknown command: .{cmd} (try .help)")


    async def _send_chat(self, text: str):
        """Send chat to core process."""
        await self.core_q.put({
            'type': 'chat',
            'user': self.user,
            'text': text,
            'channel': self.current_chan
        })
        print(f"[{self.current_chan}] <{self.user}> {text}")


    async def _switch_channel(self, args: str):
        """Switch partyline channel."""
        try:
            chan_id = int(args) if args else 0
            if chan_id not in self.channels:
                self.channels[chan_id] = set()
            self.current_chan = chan_id
            print(f"Switched to channel {chan_id}")
        except ValueError:
            print("Usage: .chan <number>")


    def _show_help(self):
        """Display help text."""
        help_text = """
WBS Partyline Commands:
  .help              - This help
  .version           - Show version
  .chans             - List partyline channels
  .chan <num>        - Switch partyline channel
  .who               - Show users on current channel
  .status            - Show bot status
  
IRC Commands:
  .join <#chan>      - Join IRC channel
  .part <#chan>      - Leave IRC channel
  .say <#chan> <msg> - Send message to channel
  .msg <nick> <msg>  - Send private message
  .act <target> <action> - Send CTCP ACTION
  
Botnet Commands:
  .bots              - List linked bots
  .link <bot>        - Link to bot
  .unlink <bot>      - Unlink from bot
  .sendnet <cmd>     - Send command to botnet
  
Admin Commands:
  .quit [msg]        - Quit bot
  .die [msg]         - Alias for quit
  
Chat: Type normally (no dot) to chat on current partyline channel
"""
        print(help_text)


    def _show_who(self):
        """Show users on current channel."""
        users = self.channels.get(self.current_chan, set())
        print(f"Channel {self.current_chan}: {', '.join(users) if users else '(empty)'}")

    async def _show_status(self):
        """Request and display bot status."""
        self.core_q.put_nowait({'cmd': 'status'})

    async def run(self):
        """Main loop"""
        self.running = True
        event_task = asyncio.create_task(self.poll_events())
        
        session = PromptSession(history=InMemoryHistory())
        
        try:
            while self.running:
                try:
                    prompt = f"WBS[{self.current_chan}]> "
                    line = await session.prompt_async(prompt)
                    await self.handle_input(line)
                except KeyboardInterrupt:
                    self.running = FALSE
                    continue
                except EOFError:
                    break
        finally:
            self.running = False
            event_task.cancel()
            print("Partyline terminated.")


class ConsoleSession:
    def __init__(self, handle="console"):
        self.handle = handle
        self.idx = 0  # Single console session

def partyline_target(config_path, party_q, core_q, quit_event):
    import json, asyncio, os
    config = json.load(open(config_path))
    
    # Use env flag (set by main.py)
    if os.environ.get('WBS_FOREGROUND') == '1':
        print("WBS Partyline active. Type .help for commands. Ctrl+C to quit.")
        # Only pass core_q (Core handles everything)
        asyncio.run(run_foreground_partyline(config, core_q))
    else:
        # Background telnet/DCC server (TODO)
        print("Partyline server mode (telnet/DCC) - not implemented")
        while not quit_event.is_set():
            asyncio.sleep(1)

async def run_foreground_partyline(config, core_q):  # Simplified signature
    """Foreground console - ONLY needs config + core_q."""
    pl = Partyline(config, core_q)  # Simplified constructor
    await pl.run()