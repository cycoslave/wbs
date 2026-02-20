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

async def send_partyline(config, core_q, irc_q, botnet_q, party_q, idx: int, msg: str):
    """Send message to partyline session."""
    try:
        await party_q.put({'type': 'partyline_msg', 'idx': idx, 'text': msg})
    except Exception as e:
        print(f"SEND ERROR: {e}")

# Universal (-|-)
async def cmd_uptime(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Show bot/server/system uptime."""
    #start_time = getattr(core, 'start_time', time.time())
    start_time = 0
    uptime = str(timedelta(seconds=int(time.time() - start_time)))
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"Bot uptime: {uptime}")
    
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

# Ops (o|o)
async def cmd_mode(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Change channel modes (.mode #chan +o nick)."""
    if core.config.get('limbo_hub'):
        return await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Cannot use MODE as limbo hub.")
    
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        return await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Usage: .mode <#channel> <modes>")
    
    chan, modes = parts
    user_mgr = UserManager()
    
    if await user_mgr.matchattr(hand, 'o|o', chan):
        # Queue IRC command
        core.send_cmd('raw', '', f"MODE {chan} {modes}")
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"Mode set: {chan} {modes}")
    else:
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Access denied (need +o)")
    return 1


# Masters (m|m)
async def cmd_mnote(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Send note to users matching flags (.mnote m #chan message)."""
    parts = arg.split(maxsplit=2)
    if len(parts) < 2:
        return await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Usage: .mnote <flags> [#chan] <message>")
    
    flag = parts[0]
    rest = ' '.join(parts[1:])
    
    # Parse optional channel
    chan = None
    if rest.startswith('#'):
        chan, text = rest.split(maxsplit=1)
    else:
        text = rest
    
    user_mgr = UserManager()
    sent, failed = 0, 0
    
    async with get_db() as db:
        users = await user_mgr.list_users(flag)
        for user in users:
            # Check if user matches flag in channel context
            if await user_mgr.matchattr(user.handle, f"+{flag}", chan):
                # Send via botnet note system
                if core.botnet_mgr:
                    ok = await core.botnet_mgr.send_note(user.handle, text)
                    if ok:
                        sent += 1
                    else:
                        failed += 1
                    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, 
                        f"Note {user.handle}: {'OK' if ok else 'FAIL'}")
    
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"Sent: {sent}, Failed: {failed}")
    return 1


# Owners/Admins (n|A)
async def cmd_nopass(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """List users without passwords."""
    async with get_db() as db:
        cursor = await db.execute(
            "SELECT handle, flags FROM users WHERE password IS NULL OR password = ''"
        )
        rows = await cursor.fetchall()
    
    if not rows:
        return await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "No users without password.")
    
    msg_lines = ["Users without password:"]
    for i, (handle, flags) in enumerate(rows, 1):
        msg_lines.append(f"  {i}. {handle} (+{flags})")
    msg_lines.append("Use .fixpass to generate passwords.")
    
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, '\n'.join(msg_lines))
    return 1


async def cmd_fixpass(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Generate random passwords for users without one."""
    fixed = 0
    user_mgr = UserManager()
    
    async with get_db() as db:
        cursor = await db.execute(
            "SELECT handle FROM users WHERE password IS NULL OR password = ''"
        )
        rows = await cursor.fetchall()
        
        for (handle,) in rows:
            password = secrets.token_urlsafe(24)
            await user_mgr.set_password(handle, password)
            
            # Update comment field
            comment = f"{hand} .fixpass {int(time.time())}"
            await db.execute(
                "UPDATE users SET info = ? WHERE handle = ?",
                (comment, handle)
            )
            fixed += 1
            await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"  {fixed}. {handle}: {password}")
        
        await db.commit()
    
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"Fixed {fixed} passwords.")
    return 1


async def cmd_mass(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Mass op/deop channel (.mass op #chan)."""
    parts = arg.split()
    if len(parts) < 2:
        return await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Usage: .mass <op|deop> <#channel>")
    
    action, chan = parts[0].lower(), parts[1]
    
    # Check if bot has ops
    if not await bot_is_op(core, chan):
        return await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"Not opped on {chan}")
    
    user_mgr = UserManager()
    targets = []
    skip_flags = {'d', 'f', 'o', 'b'} if action == 'op' else {'o'}
    
    # Get channel user list
    users = await chanlist(core, chan)
    
    for nick in users:
        if nick.lower() == core.config['bot']['nick'].lower():
            continue  # Skip self
        
        # Match nick to handle
        handle = await user_mgr.match_user(f"*!*@{nick}")
        if handle:
            # Check flags
            has_skip = any(await user_mgr.matchattr(handle, f"+{f}", chan) 
                          for f in skip_flags)
            if not has_skip:
                if action == 'op' or await bot_is_op(core, chan, nick):
                    targets.append(nick)
    
    # Send MODE commands in batches of 4
    mode_char = '+' if action == 'op' else '-'
    for i in range(0, len(targets), 4):
        batch = targets[i:i+4]
        modes = mode_char + ('o' * len(batch))
        core.send_cmd('raw', '', f"MODE {chan} {modes} {' '.join(batch)}")
    
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"Mass {action}: {len(targets)} users")
    return 1


async def cmd_channels(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """List active channels."""
    if core.config.get('limbo_hub'):
        return await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Limbo hub: no channels.")
    
    lines = ["=== Active Channels ==="]
    for chan in core.channels:
        modes = await get_channel_modes(core, chan)
        op_status = "op" if await bot_is_op(core, chan) else "no-op"
        lines.append(f"{chan} [{modes}] [{op_status}]")
    
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, '\n'.join(lines))
    return 1


async def cmd_dns(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Resolve hostname (.dns example.com)."""
    host = arg.strip()
    if not host:
        return await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Usage: .dns <hostname>")
    
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"Resolving {host}...")
    try:
        loop = asyncio.get_running_loop()
        addrs = await loop.getaddrinfo(host, None)
        ip = addrs[0][4][0]
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"{host} → {ip}")
    except Exception as e:
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"DNS failed: {e}")
    return 1

async def cmd_join(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Join IRC channel."""
    if not arg:
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Usage: .join #channel [key]")
        return
    parts = arg.split()
    irc_q.put_nowait({'cmd': 'join', 'channel': parts[0], 
              'key': parts[1] if len(parts) > 1 else None})
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"→ JOIN {parts}")


async def cmd_part(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Leave IRC channel."""
    if not arg:
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Usage: .part #channel [reason]")
        return
    parts = arg.split(maxsplit=1)
    irc_q.put_nowait({'cmd': 'part', 'channel': parts[0],
              'reason': parts[1] if len(parts) > 1 else ''})
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"→ PART {parts}")


async def cmd_say(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Send message to channel."""
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Usage: .say #channel message")
        return
    irc_q.put_nowait({'cmd': 'msg', 'target': parts[0], 'text': parts[1]})
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"→ SAY {parts[0]}: {parts[1]}")


async def cmd_msg(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Send private message."""
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Usage: .msg nick message")
        return
    irc_q.put_nowait({'cmd': 'msg', 'target': parts[0], 'text': parts[1]})
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"→ MSG {parts[0]}: {parts[1]}")


async def cmd_act(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Send CTCP ACTION."""
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "Usage: .act #channel action")
        return
    action_text = f"\x01ACTION {parts[1]}\x01"
    irc_q.put_nowait({'cmd': 'msg', 'target': parts[0], 'text': action_text})
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, f"→ ACTION {parts[0]}: {parts[1]}")


async def cmd_bots(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """List botnet status."""
    # Check botnet config/status via core or simple check
    irc_q.put_nowait({'cmd': 'botnet_list'})
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "→ Requesting botnet list...")


async def cmd_quit(config, core_q, irc_q, botnet_q, party_q, hand: str, idx: int, arg: str):
    """Shutdown bot."""
    quit_msg = arg or "WBS 6.0.0"
    irc_q.put_nowait({'cmd': 'quit', 'message': quit_msg})
    await send_partyline(config, core_q, irc_q, botnet_q, party_q, idx, "→ Shutdown initiated...")
    # Note: self.running=False happens in partyline.py after delay

async def cmd_help(core_q, irc_q, botnet_q, handle: str, session_id: int, arg: str, respond):
    """Show help"""
    help_text = """WBS Partyline Commands:
.help      - This help
.uptime    - Bot uptime  
.join #chan - Join channel
.say #chan msg - Send message
.quit      - Shutdown bot"""
    
    for line in help_text.split('\n'):
        await respond(line)

# Command registry
COMMANDS = {
    'help': cmd_help,
    'uptime': cmd_uptime,
    'mode': cmd_mode,
    'mnote': cmd_mnote,
    'nopass': cmd_nopass,
    'fixpass': cmd_fixpass,
    'mass': cmd_mass,
    'dns': cmd_dns,
    'join': cmd_join,
    'part': cmd_part,
    'say': cmd_say,
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
