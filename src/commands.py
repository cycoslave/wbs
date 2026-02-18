# src/commands.py - DCC chat commands for WBS (Eggdrop partyline port)

import asyncio
import secrets
import socket
import subprocess
import time
from datetime import datetime
from typing import Optional

from wbs.irc import IRCBot
from wbs.core import BotCore
from wbs.user import matchattr, get_attributes_str, set_pass, set_comment, nick2hand, has_attr
from wbs.channel import get_channel_modes, bot_is_op, chanlist
from wbs.db import get_db
from wbs.botnet import send_note


async def send_dcc(bot: BotCore, idx: int, msg: str):
    """Send to DCC session idx."""
    if hasattr(bot, 'dcc_sessions') and idx in bot.dcc_sessions:
        await bot.dcc_sessions[idx].send(msg)


# Universal (-|-)
async def cmd_uptime(bot: BotCore, hand: str, idx: int, arg: str):
    uptime = str(datetime.timedelta(seconds=int(time.time() - getattr(bot, 'start_time', 0))))
    await send_dcc(bot, idx, f"Bot uptime: {uptime}")
    if not getattr(bot, 'is_limbo_hub', False) and hasattr(bot, 'server_online_time'):
        sup = str(datetime.timedelta(seconds=int(time.time() - bot.server_online_time)))
        await send_dcc(bot, idx, f"Server uptime: {sup}")
    if await has_attr(bot.db, hand, 'A'):
        try:
            out = subprocess.check_output(['uptime']).decode().split()[:5]
            await send_dcc(bot, idx, f"System uptime: {' '.join(out)}")
        except: pass
    return 1


async def cmd_version(bot: BotCore, hand: str, idx: int, arg: str):
    await send_dcc(bot, idx, f"WBS v0.1 on {socket.gethostname()}")
    return 1


async def cmd_time(bot: BotCore, hand: str, idx: int, arg: str):
    await send_dcc(bot, idx, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return 1


# Ops (o|o)
async def cmd_mode(bot: BotCore, hand: str, idx: int, arg: str):
    if getattr(bot, 'is_limbo_hub', False):
        return await send_dcc(bot, idx, "No as limbo hub.")
    parts = arg.split(maxsplit=1)
    if len(parts) < 2: return await send_dcc(bot, idx, ".mode <#chan> <modes>")
    chan, modes = parts
    if await matchattr(bot.db, hand, 'o|o', chan):
        await bot.send_raw(f"MODE {chan} {modes}")
    else:
        await send_dcc(bot, idx, "Access denied.")
    return 1


# Masters (m|m)  
async def cmd_mnote(bot: BotCore, hand: str, idx: int, arg: str):
    parts = arg.split(maxsplit=2)
    if len(parts) < 2: return await send_dcc(bot, idx, ".mnote <flag> [chan] <text>")
    flag, rest = parts[0], ' '.join(parts[1:])
    chan = rest.split()[0] if rest.startswith('#') else None
    text = rest.split(maxsplit=1)[1] if len(rest.split()) > 1 else rest
    
    async with get_db() as conn:
        for u in await bot.db.userlist(conn, flag, chan):
            ok = await send_note(u, text)
            await send_dcc(bot, idx, f"Note {u}: {'OK' if ok else 'FAIL'}")
    return 1


# Owners/Admins (n|A)
async def cmd_nopass(bot: BotCore, hand: str, idx: int, arg: str):
    async with get_db() as conn:
        nopass = await bot.db.users_no_pass(conn)
    if not nopass:
        return await send_dcc(bot, idx, "No users w/o pass.")
    msg = "\n".join(f"{i}. {h} (+{a})" for i, (h, a) in enumerate(nopass, 1))
    await send_dcc(bot, idx, msg + "\n.fixpass to fix.")
    return 1


async def cmd_fixpass(bot: BotCore, hand: str, idx: int, arg: str):
    fixed = 0
    async with get_db() as conn:
        for handle, _ in await bot.db.users_no_pass(conn):
            pw = secrets.token_urlsafe(24)
            await set_pass(conn, handle, pw)
            await set_comment(conn, handle, f"{hand} .fixpass {int(time.time())}")
            fixed += 1
            await send_dcc(bot, idx, f"{fixed}. {handle} fixed!")
    await send_dcc(bot, idx, f"Fixed {fixed} passes.")
    return 1


async def cmd_mass(bot: BotCore, hand: str, idx: int, arg: str):
    parts = arg.split()
    if len(parts) < 2: return await send_dcc(bot, idx, ".mass <op|dop> <#chan>")
    act, chan = parts[0].lower(), parts[1]
    if not await bot_is_op(bot, chan):
        return await send_dcc(bot, idx, f"Not opped: {chan}")
    
    targets, skip = [], {'d','fob'} if act=='op' else {'o'}
    for nick in await chanlist(bot, chan):
        if nick.lower() != bot.nick.lower():
            hnick = await nick2hand(bot.db, nick, chan)
            if hnick and not any(await matchattr(bot.db, hnick, a, chan) for a in skip):
                if act=='op' or await bot_is_op(bot, chan, nick):
                    targets.append(nick)
    
    mode = '+oooo' if act=='op' else '-oooo'
    for i in range(0, len(targets), 4):
        batch = targets[i:i+4]
        await bot.send_raw(f"MODE {chan} {mode[:len(batch)]} {' '.join(batch)}", quick=True)
    await send_dcc(bot, idx, f"Mass-{act}: {len(targets)}")
    return 1


async def cmd_channels(bot: BotCore, hand: str, idx: int, arg: str):
    if getattr(bot, 'is_limbo_hub', False):
        return await send_dcc(bot, idx, "Limbo: no chans.")
    lines = [f"{c} [{await get_channel_modes(bot,c)}] [{'op' if await bot_is_op(bot,c) else 'no'}]" 
             for c in bot.channels]
    await send_dcc(bot, idx, f"=== Channels ({len(lines)}) ===\n" + '\n'.join(lines))
    return 1


async def cmd_dns(bot: BotCore, hand: str, idx: int, arg: str):
    host = arg.strip()
    if not host: return await send_dcc(bot, idx, ".dns <host>")
    await send_dcc(bot, idx, f"Resolving {host}...")
    try:
        addr = await asyncio.get_running_loop().getaddrinfo(host, None)
        await send_dcc(bot, idx, f"{host} -> {addr[0][4][0]}")
    except Exception as e:
        await send_dcc(bot, idx, f"DNS fail: {e}")
    return 1


# Registry
COMMANDS = {
    'uptime': cmd_uptime, 'version': cmd_version, 'time': cmd_time,
    'mode': cmd_mode, 'mnote': cmd_mnote, 'nopass': cmd_nopass, 
    'fixpass': cmd_fixpass, 'mass': cmd_mass, 'channels': cmd_channels,
    'dns': cmd_dns,
    # TODO: whowas, timers, join/part/nick, lock, chattr, etc.
}


async def handle_dcc_chat(bot: BotCore, idx: int, text: str):
    """Dispatch .commands from DCC chat."""
    if not text.startswith('.'): return  # relay elsewhere?
    parts = text[1:].split(maxsplit=1)
    cmd, arg = parts[0].lower(), parts[1] if len(parts)>1 else ''
    hand = bot.dcc_sessions[idx]['hand']
    
    if cmd in COMMANDS:
        await COMMANDS[cmd](bot, hand, idx, arg)
    else:
        await send_dcc(bot, idx, f"Unknown .{cmd}")
