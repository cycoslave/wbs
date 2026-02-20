# src/commands.py
"""
Partyline commands for WBS
"""

import asyncio
import secrets
import socket
import subprocess
import time
from datetime import datetime, timedelta
from typing import Optional

#from src.core import CoreEventLoop
from .user import UserManager
#from .channel import get_channel_modes, bot_is_op, chanlist
from .db import get_db
from .botnet import BotnetManager
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .core import CoreEventLoop

# Universal (-|-)
async def cmd_uptime(core, handle, session_id, arg, respond):
    """Show bot/server/system uptime."""
    #start_time = getattr(core, 'start_time', time.time())
    start_time = 0
    uptime = str(timedelta(seconds=int(time.time() - start_time)))
    await respond(f"Bot uptime: {uptime}")
    
    # Server uptime if connected
    #if not core.config.get('limbo_hub') and hasattr(core, 'server_online_time'):
    #    server_up = str(timedelta(seconds=int(time.time() - core.server_online_time)))
    #    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"Server uptime: {server_up}")
    
    # System uptime for admins
    #user_mgr = UserManager()
    #if await user_mgr.matchattr(hand, '+A'):
    #    try:
    #        out = subprocess.check_output(['uptime'], timeout=2).decode().strip()
    #        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"System: {out}")
    #    except:
    #        pass
    return 1

async def cmd_mode(core, handle, session_id, arg, respond):
    """Change channel modes (.mode #chan +o nick)."""
    if core.config.get('limbo_hub'):
        return await respond("Cannot use MODE as limbo hub.")
    
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        return await respond("Usage: .mode <#channel> <modes>")
    
    chan, modes = parts
    user_mgr = UserManager()
    
    if await user_mgr.matchattr(hand, 'o|o', chan):
        # Queue IRC command
        core.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': modes})
        await respond(f"Mode set: {chan} {modes}")
    else:
        await respond("Access denied (need +o)")
    return 1

#async def cmd_channels(core, handle, session_id, arg, respond):
#    """List active channels."""
#    if core.config.get('limbo_hub'):
#        return await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Limbo hub: no channels.")
#    
#    lines = ["=== Active Channels ==="]
#    for chan in core.channels:
#        modes = await get_channel_modes(core, chan)
#        op_status = "op" if await bot_is_op(core, chan) else "no-op"
#        lines.append(f"{chan} [{modes}] [{op_status}]")
#    
#    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, '\n'.join(lines))
#    return 1

async def cmd_join(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .join #channel [key]")
        return
    parts = arg.split()
    core.irc_q.put_nowait({'cmd': 'join', 'channel': parts[0]})
    await respond(f"→ JOIN {parts[0]}")

async def cmd_part(core, handle, session_id, arg, respond):
    """Leave IRC channel."""
    if not arg:
        await respond("Usage: .part #channel [reason]")
        return
    parts = arg.split()
    core.irc_q.put_nowait({'cmd': 'part', 'channel': parts[0],
              'reason': parts[1] if len(parts) > 1 else ''})
    await respond(f"→ PART {parts}")

async def cmd_quit(core, handle, session_id, arg, respond):
    """Shutdown bot."""
    quit_msg = arg or "WBS 6.0.0"
    core.irc_q.put_nowait({'cmd': 'quit', 'message': quit_msg})
    await core._shutdown(quit_msg)
    await respond("→ Shutdown initiated...")

async def cmd_msg(core, handle, session_id, arg, respond):
    """Send message to channel."""
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        await respond("Usage: .say #channel message")
        return
    core.irc_q.put_nowait({'cmd': 'msg', 'target': parts[0], 'text': parts[1]})
    await respond(f"→ SAY {parts[0]}: {parts[1]}")

async def cmd_act(core, handle, session_id, arg, respond):
    """Send CTCP ACTION."""
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        await respond("Usage: .act #channel action")
        return
    action_text = f"\x01ACTION {parts[1]}\x01"
    core.irc_q.put_nowait({'cmd': 'msg', 'target': parts[0], 'text': action_text})
    await respond(f"→ ACTION {parts[0]}: {parts[1]}")

async def cmd_bots(core, handle, session_id, arg, respond):
    """List botnet status."""
    # Check botnet config/status via core or simple check
    core.irc_q.put_nowait({'cmd': 'botnet_list'})
    await respond(" Botnet currently: disabled")

async def cmd_help(core, handle, session_id, arg, respond):
    """Show help"""
    help_text = """
WBS Partyline Commands:
.help      - This help
.uptime    - Bot uptime  
.say #chan msg - Send message
.msg nick msg - Send message
.join #chan - Join channel
.part #chan - Join channel
.quit      - Shutdown bot
"""
    
    for line in help_text.split('\n'):
        await respond(line)

# Command registry
COMMANDS = {
    'help': cmd_help,
    'uptime': cmd_uptime,
    'mode': cmd_mode,
    'mass': cmd_mass,
    'dns': cmd_dns,
    'join': cmd_join,
    'part': cmd_part,
    'say': cmd_msg,
    'msg': cmd_msg,
    'act': cmd_act,
    'bots': cmd_bots,
    'quit': cmd_quit,
    'die': cmd_quit,
}

async def handle_partyline_command(config, core_q, irc_q, botnet_q, party_q, idx: int, text: str):
    """
    Dispatch partyline commands (dot-commands).
    Called from Partyline.handle_input() in core.py
    """
    if not text.startswith('.'):
        return  # Not a command, relay to chat
    
    parts = text[1:].split(maxsplit=1)
    cmd_name = parts[0].lower()
    cmd_arg = parts[1] if len(parts) > 1 else ''
    
    # Get user handle from session
    #hand = core.partyline_sessions.get(idx, {}).get('handle', 'console')
    hand = 'console'
    
    if cmd_name in COMMANDS:
        await COMMANDS[cmd_name](config, core_q, irc_q, botnet_q, party_q, hand, idx, cmd_arg)
    else:
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"Unknown command: .{cmd_name} (try .help)")

async def handle_dcc_chat(config, core_q, irc_q, botnet_q, party_q, nick: str, text: str):
    """Handle DCC CHAT input from IRC users (dispatched from core.py oncommand)."""
    # Pseudo-session for IRC privmsg/DCC relay
    idx = hash(nick) % 10000  # Consistent session ID
    hand = nick  # Use nick as handle (extend with user lookup)
    
    if text.startswith('.'):
        await handle_partyline_command(config, core_q, irc_q, botnet_q, party_q, idx, text)  # Dot-command
    else:
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"<{nick}> {text}")  # Relay chat
