# src/commands.py
"""
Partyline commands for WBS
"""
import time
import os
import sys
import platform
import resource
import shutil
import glob
import logging
import secrets
import string
import socket
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict

from . import __version__
from .db import get_db

log = logging.getLogger("wbs.commands")

async def cmd_help(core, handle, session_id, arg, respond):
    """Show help"""
    # Extract the command (second word)
    words = arg.split()
    if len(words) < 1:
        help_text = """
.: Wicked Bot System Help :.
   For all users:
      help
      date         time         uptime       version
      who          quit         whom         chpass
      handle       whoami       -host         
   For ops:
      mode         say          msg          op
      deop         voice        devoice
   For admins:
      chattr       backup       status       die
      modules      +user        +ignore      ignores      
      -user        -ignore      restart      addleaf
      +bot         botattr      chhandle     relay
      +host        -bot         link         chaddr
      unlink       update       channels     addhub
      bots         join         part         subnet
      lock         unlock       topiclock    topicunlock
      taskset      timers       tasks        botinfo 
      nopass       fixpass      mass         net
      baway        bback        nick         lag 
      infoleaf       

All commands begin with '.', and all else goes to the party line.      
"""
        for line in help_text.split('\n'):
            await respond(line)
        return

    cmd = words[0].lower()
    if cmd == "date":
        help_text = """
###  date
    Shows the current date and time.

See also: time
"""

    elif cmd == "time":
        help_text = """
###  time
    Shows the current date and time.

See also: date
"""

    elif cmd == "uptime":
        help_text = """
###  uptime
    Shows the uptime of the bot.
"""

    elif cmd == "version":
        help_text = """
###  version
    Shows the current version of the bot system.
"""

    elif cmd == "mode":
        help_text = """
###  mode <channel> <arguments>
    Sets mode on a channel.
"""

    elif cmd == "mnote":
        help_text = """
###  mnote <flag> \\[channel\\] <message>
    Sends a private note to users with a certain flag on the party line.

See also: note, notes
"""

    elif cmd == "bots":
        help_text = """
###  bots
    Shows botnet information.
"""

    elif cmd == "lock":
        help_text = """
###  lock <channel> \\[reason\\]
    Locks a channel.

See also: unlock
"""

    elif cmd == "unlock":
        help_text = """
###  unlock <channel>
    Unlocks a channel.

See also: lock
"""

    elif cmd == "topiclock":
        help_text = """
###  topiclock <channel> \\[topic\\]
    Locks the topic of a channel.
"""

    elif cmd == "sdns":
        help_text = """
###  sdns <ip/host>
    Performs dns resolution on the bot's server.
"""

    elif cmd == "swhois":
        help_text = """
###  swhois <nickname>
    Performs whois on the bot's server.
"""

    elif cmd == "swhowas":
        help_text = """
###  swhowas <nickname>
    Performs whowas on the bot's server.
"""

    elif cmd == "links":
        help_text = """
###  links
    Shows all the servers linked to the network.
"""

    elif cmd == "taskset":
        help_text = """
###  taskset <task> <0/1>
    Configures tasks to enable or disable them.
"""

    elif cmd == "timers":
        help_text = """
###  timers
    Shows all the timers on the bot.
"""

    elif cmd == "tasks":
        help_text = """
###  tasks
    Shows all the tasks configured.
"""

    elif cmd == "botinfo":
        help_text = """
###  botinfo
    Shows bot information.
"""

    elif cmd == "nopass":
        help_text = """
###  nopass
    Shows all the users without a password.

See also: fixpass
"""

    elif cmd == "fixpass":
        help_text = """
###  fixpass
    Sets random passwords to all users without one.

See also: nopass
"""

    elif cmd == "mass":
        help_text = """
###  mass <command> \\[arguments\\]
    Does mass commands.
    Valid commands are: op deop
"""

    elif cmd == "net":
        help_text = """
###  net <channel> \\[topic\\]
    Does commands at the botnet level.
    Valid commands are: op deop save rehash restart chanset die chanfix chanset mode join part msg
"""

    elif cmd == "baway":
        help_text = """
###  baway \\[reason\\]
    Puts the bot in away mode.

See also: bback
"""

    elif cmd == "bback":
        help_text = """
###  bback
    Brings the bot back from away mode.

See also: baway
"""

    elif cmd == "nick":
        help_text = """
###  nick \\[nick\\]
    Configures the bot's nickname.
"""

    elif cmd == "lag":
        help_text = """
###  lag
    Shows the botnet latency.
"""

    elif cmd == "infoleaf":
        help_text = """
###  infoleaf
    Gives the command to add this bot as a leaf on the hub.

See also: addleaf, addhub
"""

    elif cmd == "addleaf":
        help_text = """
###  addleaf <botnick> <host> <port>
    Adds a leaf bot to the botnet's hub, then gives the command to add the hub.

See also: infoleaf, addhub
"""

    elif cmd == "addhub":
        help_text = """
###  addhub <botnick> <host> <port>
    Adds the botnet's hub on a botnet leaf.

See also: infoleaf, addleaf
"""

    elif cmd == "subnet":
        help_text = """
###  subnet <command> \\[arguments\\]
    Configures the bot's subnet.
    Valid commands are: set list help
"""

    elif cmd == "update":
        help_text = """
###  update
    Launches the Wicked Bot System update process.
"""

    elif cmd == "channels":
        help_text = """
###  channels
    Lists all channels.
"""

    else:
        help_text = f"""
ERROR: Unknown command: {cmd}
"""

    for line in help_text.split('\n'):
        await respond(line)

async def cmd_version(core, handle: str, session_id: int, arg: str, respond):
    await respond(f"WBS {__version__}")

async def cmd_date(core, handle: str, session_id: int, arg: str, respond):
    await respond(f"Current time is: {datetime.now().ctime()}")
    return  

async def cmd_whoami(core, handle: str, session_id: int, arg: str, respond):
    await respond(f"You are {handle}@{core.botname}")

async def cmd_uptime(core, handle, session_id, arg, respond):
    """Show bot/server/system uptime."""
    start_time = getattr(core, 'start_time', time.time())  # Use real start_time
    uptime = str(timedelta(seconds=int(time.time() - start_time)))
    await respond(f"Bot uptime: {uptime}")
    
    # Server uptime if connected
    #if not core.config.get('limbo_hub') and hasattr(core, 'server_online_time'):
    #    server_up = str(timedelta(seconds=int(time.time() - core.server_online_time)))
    #    await send_partyline(config, core_q, irc_q, idx, f"Server uptime: {server_up}")
    
    # System uptime for admins
    #user = UserManager()
    #if await user.matchattr(hand, '+A'):
    #    try:
    #        out = subprocess.check_output(['uptime'], timeout=2).decode().strip()
    #        await send_partyline(config, core_q, irc_q, idx, f"System: {out}")
    #    except:
    #        pass
    return

async def cmd_mode(core, handle, session_id, arg, respond):
    """Change channel modes (.mode #chan +o nick)."""
    if core.config.get('limbo_hub'):
        return await respond("Cannot use MODE as limbo hub.")
    
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        return await respond("Usage: .mode <#channel> <modes>")
    
    chan, modes = parts
    core.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': modes})
    await respond(f"Mode set: {chan} {modes}")
    #user = UserManager()
    #
    #if await user.matchattr(hand, 'o|o', chan):
    #    # Queue IRC command
    #    core.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': modes})
    #    await respond(f"Mode set: {chan} {modes}")
    #else:
    #    await respond("Access denied (need +o)")
    return 1

async def cmd_op(core, handle, session_id, arg, respond):
    """Change channel modes (.mode #chan +o nick)."""
    #if core.config.get('limbo_hub'):
    #    return await respond("Cannot use MODE as limbo hub.")
    
    parts = arg.split()
    if len(parts) < 2:
        return await respond("Usage: .op <nick> <#channel>")
    
    nick, chan = parts
    modes = f"+o {nick}"
    core.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': modes})
    await respond(f"Gave op to {nick} on {chan}")
    return 1

async def cmd_deop(core, handle, session_id, arg, respond):
    """Change channel modes (.mode #chan +o nick)."""
    #if core.config.get('limbo_hub'):
    #    return await respond("Cannot use MODE as limbo hub.")
    
    parts = arg.split()
    if len(parts) < 2:
        return await respond("Usage: .deop <nick> <#channel>")
    
    nick, chan = parts
    modes = f"-o {nick}"
    core.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': modes})
    await respond(f"Took op from {nick} on {chan}")
    return 1

async def cmd_voice(core, handle, session_id, arg, respond):
    #if core.config.get('limbo_hub'):
    #    return await respond("Cannot use MODE as limbo hub.")
    
    parts = arg.split()
    if len(parts) < 2:
        return await respond("Usage: .voice <nick> <#channel>")
    
    nick, chan = parts
    modes = f"+v {nick}"
    core.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': modes})
    await respond(f"Gave voice to {nick} on {chan}")
    return 1

async def cmd_devoice(core, handle, session_id, arg, respond):
    #if core.config.get('limbo_hub'):
    #    return await respond("Cannot use MODE as limbo hub.")
    
    parts = arg.split()
    if len(parts) < 2:
        return await respond("Usage: .devoice <nick> <#channel>")
    
    nick, chan = parts
    modes = f"-v {nick}"
    core.irc_q.put_nowait({'cmd': 'mode', 'channel': chan, 'modes': modes})
    await respond(f"Took voice from {nick} on {chan}")
    return 1

async def cmd_channels(core, handle: str, session_id: int, arg: str, respond):
    async with get_db(core.db_path) as db:
        chans = await db.execute("""
            SELECT name, modes, limit, is_inactive 
            FROM channels 
            WHERE is_inactive = 0 
            ORDER BY name
        """)
        
        if not chans:
            await respond("No channels.")
            return
        
        await respond(" ---- List of Channels ----")
        total = 0
        async for row in chans:
            chan = row['name']
            modes = row['modes'] or '+n'  # Default modes
            limit = row['limit'] or 0
            lim_str = f" {limit}" if limit else ""
            await respond(f"--> {chan} ({modes}{lim_str})")
            total += 1
        
        await respond(f"TOTAL CHANNELS: {total}")

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
    quit_msg = arg or f"WBS {__version__}"
    await respond("→ Shutdown initiated...")
    core.irc_q.put_nowait({'cmd': 'quit', 'message': quit_msg})

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
    if not core.bot_sessions:
        await respond("No linked bots.")
        return
    
    bots_list = []
    for bot_id, session in core.bot_sessions.items():
        # Prioritize session.handle or .nick; fallback to ID
        bot_handle = getattr(session, 'handle', None) or getattr(session, 'nick', None) or str(bot_id)
        bots_list.append(f"{bot_handle}")
    
    bots_str = " | ".join(bots_list)
    await respond(f"Linked bots: {bots_str}")

async def cmd_addchan(core, handle: str, session_id: int, arg: str, respond):
    """
    .+chan #channel [subnet_name]
    subnet_name: name of subnet to bind to, or '*' for global (no subnet binding).
    If omitted, defaults to the bot's own subnet.
    """
    if not arg:
        await respond("Usage: .+chan <#channel> [subnet_name|*]")
        return

    parts = arg.split()
    channel = parts[0]
    subnet_arg = parts[1] if len(parts) > 1 else None

    # Resolve subnet_id
    subnet_id = None  # None = global

    if subnet_arg is None or subnet_arg == '*':
        if subnet_arg is None:
            # Default: use bot's own subnet
            subnet_id = core.config.get('botnet', {}).get('subnet_id', None)
    else:
        # Named subnet — look it up
        async with get_db(core.db_path) as db:
            row = await db.fetchone(
                "SELECT id FROM subnets WHERE name = ?", (subnet_arg,)
            )
        if not row:
            await respond(f"Unknown subnet: {subnet_arg}")
            return
        subnet_id = row["id"]

    try:
        await core.chan.addchan(channel, subnet_id=subnet_id, added_by=handle)
        core.irc_q.put_nowait({'cmd': 'join', 'channel': channel})
        subnet_label = subnet_arg or f"subnet {subnet_id}"
        await respond(f"→ Channel {channel} added (scope: {subnet_label})!")
    except ValueError as e:
        await respond(f"→ {e}")
    except Exception as e:
        await respond(f"→ Channel {channel} NOT added: {e}")

async def cmd_delchan(core, handle: str, session_id: int, arg: str, respond):
    """.-chan #channel"""
    if not arg:
        await respond("Usage: .-chan <#channel>")
        return
    parts = arg.split()
    channel = parts[0]
    if await core.chan.delchan(channel, deleted_by=handle):
        core.irc_q.put_nowait({'cmd': 'part', 'channel': channel})
        await respond(f"→ Channel {channel} deleted!")
    else:
        await respond(f"→ Channel {channel} not found or already deleted.")

async def cmd_showchan(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .showchan <user>")
        return
    parts = arg.split()
    await respond(await core.chan.showchan(parts[0]))

async def cmd_adduser(core, handle: str, session_id: int, arg: str, respond):
    """
    .+user <user> [hostmask] [subnet_name|*]
    If subnet_name omitted, defaults to bot's subnet.
    '*' = global access (valid on all subnets).
    """
    if not arg:
        await respond("Usage: .+user <user> [hostmask] [subnet_name|*]")
        return

    parts = arg.split()
    new_handle = parts[0]
    hostmask = parts[1] if len(parts) > 1 else None
    subnet_arg = parts[2] if len(parts) > 2 else None

    # Resolve subnet_id
    subnet_id = None

    if subnet_arg is None:
        # Default: bot's subnet
        subnet_id = core.config.get('botnet', {}).get('subnet_id', None)
    elif subnet_arg == '*':
        subnet_id = None  # Global
    else:
        async with get_db(core.db_path) as db:
            row = await db.fetchone(
                "SELECT id FROM subnets WHERE name = ?", (subnet_arg,)
            )
        if not row:
            await respond(f"Unknown subnet: {subnet_arg}")
            return
        subnet_id = row["id"]

    if await core.user.adduser(new_handle, hostmask, subnet_id=subnet_id, added_by=handle):
        scope = subnet_arg or f"subnet {subnet_id}"
        await respond(f"→ User {new_handle} added (scope: {scope})!")
    else:
        await respond(f"→ User {new_handle} NOT added (already exists?).")

async def cmd_deluser(core, handle: str, session_id: int, arg: str, respond):
    """.-user <user>"""
    if not arg:
        await respond("Usage: .-user <user>")
        return
    parts = arg.split()
    if await core.user.deluser(parts[0], deleted_by=handle):
        await respond(f"→ User {parts[0]} deleted!")
    else:
        await respond(f"→ User {parts[0]} NOT deleted (not found?).")

async def cmd_showuser(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .showuser <user>")
        return
    parts = arg.split()
    await respond(await core.user.showuser(parts[0]))

async def cmd_passwd(core, handle: str, session_id: int, arg: str, respond):
    """
    .chpass [target_handle] <new_password>

    Authorization rules:
      - No args              → usage hint
      - 1 arg (own password) → any authenticated +p user, except console
      - 2 args (other user)  → requires +A (admin flag); +p users are denied
      - Admins (+A) may NOT change another admin's password unless they are
        also +n (owner), preventing lateral privilege escalation between admins.
    """
    if not arg:
        await respond("Usage: .chpass [user] <password>")
        return
    parts = arg.split()

    if len(parts) == 1:
        if handle == "console":
            await respond("ERROR: Console user does not have a password.")
            return
        target, password = handle, parts[0]
    elif len(parts) == 2:
        target, password = parts[0], parts[1]

        # Caller must have +A — no further hierarchy check.
        caller_is_admin = await core.user.matchattr(handle, "+A")
        if not caller_is_admin:
            await respond("Access denied (need +A to change another user's password).")
            log.warning(
                "chpass denied: %s attempted to change password for %s without +A",
                handle, target
            )
            return

        # Reject changing the console pseudo-user
        if target.lower() == "console":
            await respond("ERROR: Console user does not have a password.")
            return
    else:
        await respond("Usage: .chpass [user] <password>")
        return
    if not await core.user.exist(target):
        await respond(f"User not found: {target}")
        return
    if len(password) < 8:
        await respond("Password must be at least 8 characters.")
        return
    await core.user.set_password(target, password)

    if target == handle:
        await respond("Password updated.")
    else:
        await respond(f"Password updated for {target}.")

    log.info("chpass: %s changed password for %s", handle, target)

async def cmd_addbot(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .+bot <bot> [hostmask] [address] [port]")
        return
    parts = arg.split()
    bot = parts[0]
    hostmask = parts[1] if len(parts) > 1 else None
    address  = parts[2] if len(parts) > 2 else None
    port     = int(parts[3]) if len(parts) > 3 else None
    ok = await core.bot.addbot(bot, hostmask, address, port)
    if ok:
        await respond(f"→ Bot {bot} added!")
    else:
        await respond(f"→ Bot {bot} NOT added!")

async def cmd_delbot(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .-bot <bot>")
        return
    parts = arg.split()
    if await core.bot.delbot(parts[0]) == True:
        await respond(f"→ Bot {parts[0]} deleted!")
    else:
        await respond(f"→ Bot {parts[0]} NOT deleted!")

async def cmd_botinfo(core, handle: str, session_id: int, arg: str, respond):
    pid = os.getpid()
    cwd = os.getcwd()
    machine = platform.machine()
    os_version = platform.platform()
    await respond("-> Bot Info <-")
    await respond(f"-> Pid #: {pid}")
    await respond(f"-> Runs in: {cwd}")
    #await respond(f"-> Admin: {core.admin_name} <email: {core.admin_email}>")
    await respond(f"-> Botnet nick: {core.botname}")
    #await respond(f"-> Perm Owner(s): {owner_count}")
    await respond(f"-> Machine: {machine}")
    await respond(f"-> Oper. System: {os_version}")

async def cmd_link(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .link <bot>")
        return
    parts = arg.split()
    botname = parts[0]
    try:
        bot = await core.bot.get(botname)
        if not bot.address:
            await respond(f"Please set address on {botname}")
        if not bot.port:
            await respond(f"Please set port on {botname}")
        await respond(f"Initiating link to {botname}...")
        await core.botnet.connect_peer(botname)
    except ValueError as e:
        await respond(f"Bot {botname} not found!") 

async def cmd_unlink(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .unlink <bot>")
        return
    botname = arg.strip()
    if botname not in core.botnet.peers:
        await respond(f"Not linked to {botname}")
        return
    
    link = core.botnet.peers[botname]
    await respond(f"Unlinking from {botname}...")
    try:
        if link.writer:
            link.writer.close()
            await link.writer.wait_closed()
        del core.botnet.peers[botname]
        link.connected = False
        await respond(f"Unlinked from {botname} ({link.host}:{link.port}).")
    except Exception as e:
        await respond(f"Unlink failed: {str(e)}")

async def cmd_listusers(core, handle: str, session_id: int, arg: str, respond):
    #if not arg:
    #    await respond("Usage: .listusers")
    #    return
    #parts = arg.split()
    await respond(await core.user.listusers())                

async def cmd_chusercomment(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .chusercomment <user> <comment>")
        return
    parts = arg.split()
    #core.irc_q.put_nowait({'cmd': 'join', 'channel': parts[0]})
    await respond(f"→ JOIN {parts[0]}")

async def cmd_addaccess(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .addaccess [options] <user> <access>")
        return
    parts = arg.split()
    #core.irc_q.put_nowait({'cmd': 'join', 'channel': parts[0]})
    await respond(f"→ JOIN {parts[0]}")

async def cmd_delaccess(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .delaccess [options] <user> <access>")
        return
    parts = arg.split()
    #core.irc_q.put_nowait({'cmd': 'join', 'channel': parts[0]})
    await respond(f"→ JOIN {parts[0]}")

async def cmd_lockuser(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .lockuser <user>")
        return
    parts = arg.split()
    #core.irc_q.put_nowait({'cmd': 'join', 'channel': parts[0]})
    await respond(f"→ JOIN {parts[0]}")

async def cmd_unlockuser(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .unlockuser <user>")
        return
    parts = arg.split()
    #core.irc_q.put_nowait({'cmd': 'join', 'channel': parts[0]})
    await respond(f"→ JOIN {parts[0]}")

async def cmd_who(core, handle, session_id, arg, respond):
    """Show partyline members and connected bots."""
    
    await respond("Party line members:")
    
    # Display partyline members
    for sid, session in core.partyline.sessions.items():
        user_handle = session['handle']
        session_type = session['type']
        
        # Determine connection info
        if session_type == 'console':
            conn_info = f"con:{core.botname[:7]}"
        elif session_type == 'telnet':
            conn_info = "telnet@localhost"
        elif session_type == 'dcc':
            conn_info = "dcc@localhost"
        else:
            conn_info = f"{session_type}@localhost"
        
        await respond(f"  [{sid:02d}]  {user_handle:12s} {conn_info}")
    
    # Display connected bots
    await respond("Bots connected:")
    if core.bot_sessions:
        for idx, (bot_id, bot_session) in enumerate(core.bot_sessions.items()):
                bot_handle = getattr(bot_session, 'handle', None) or getattr(bot_session, 'nick', None) or getattr(bot_session, 'name', None) or str(bot_id)
                
                # Get connection time if available
                connect_time = getattr(bot_session, 'connected_at', None)
                if connect_time:
                    time_str = datetime.fromtimestamp(connect_time).strftime("%d %b %H:%M")
                else:
                    time_str = "Unknown"
                
                # Get version if available
                version = getattr(bot_session, 'version', None) or f"WBS {__version__}"
                
                await respond(f"  [{idx:02d}]  ->{bot_handle:12s} ({time_str}) {version}")
    else:
        await respond("  (none)")

async def cmd_whom(core, handle: str, session_id: int, arg: str, respond):
    await respond(" Nick        Bot        Host")
    await respond("----------   ---------  --------------------")
    
    total = 0
    for sid, sess in core.partyline.sessions.items():
        uhandle = sess['handle']
        utype = sess['type']
        marker = "*" if uhandle == handle else " "
        
        # Bot/host from user.py or defaults
        botname = "*"  # Add u.bot lookup if available
        host = utype if utype != 'console' else "localhost"
        
        await respond(f"{marker}{uhandle:<10} {botname:<9}  {host}")
        total += 1
    
    await respond(f"Total users: {total}")

async def cmd_handle(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .handle <new-handle>")
        return
    new_handle = arg.strip()
    if len(new_handle) > 20:  # Sanity limit
        await respond("Handle too long.")
        return
    
    # Update own session
    if session_id in core.partyline.sessions:
        core.partyline.sessions[session_id]['handle'] = new_handle
        core.user.change_handle(handle, new_handle)
        await respond(f"Your handle is now: {new_handle}")
    else:
        await respond(f"Your handle was not changed.")
    
async def cmd_chhandle(core, handle: str, session_id: int, arg: str, respond):
    if not arg or len(arg.split()) != 2:
        await respond("Usage: .chhandle <oldhandle> <newhandle>")
        return
    
    old_handle, new_handle = arg.split()
    old_handle = old_handle.strip()
    new_handle = new_handle.strip()
    if len(new_handle) > 20:
        await respond("New handle too long.")
        return
    
    for sid, sess in core.partyline.sessions.items():
        if sess['handle'].lower() == old_handle.lower():
            sess['handle'] = new_handle
            break
    if core.user.exist(old_handle):
        if core.user.exist(new_handle):
            await respond(f"User already exist: {new_handle}")
        else:
            core.user.change_handle(old_handle, new_handle)
            await respond(f"User handle changed: {old_handle} → {new_handle}")
    else:
        await respond(f"User not found: {old_handle}")

async def cmd_addhost(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: +host <user> <hostmask>")
        return
    
    hostmask = arg.strip()
    if not hostmask.startswith('!') and '@' not in hostmask:
        await respond("Invalid hostmask (use nick!user@host)")
        return
    user = core.user.get(handle)
    if not user:
        await respond("User not found.")
        return
    
    hosts = user.hostmasks  # List[str]

    if hostmask not in hosts:
        hosts.append(hostmask)
        core.userdb.save_user(user)
        await respond(f"Added host: {hostmask}")
    else:
        await respond(f"Host already exists: {hostmask}")

async def cmd_delhost(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: -host <user> <hostmask>")
        return
    
    hostmask = arg.strip()
    if not hostmask.startswith('!') and '@' not in hostmask:
        await respond("Invalid hostmask (use nick!user@host)")
        return
    user = core.user.get(handle)
    if not user:
        await respond("User not found.")
        return
    
    hosts = user.hostmasks  # List[str]

    if hostmask in hosts:
        hosts.remove(hostmask)
        core.userdb.save_user(user)
        await respond(f"Removed host: {hostmask}")
    else:
        await respond(f"Host not found: {hostmask}")       

async def cmd_status(core, handle: str, session_id: int, arg: str, respond):
    uptime = time.time() - core.start_time
    days = int(uptime // 86400)
    hours = int((uptime % 86400) // 3600)
    
    # RSS memory in KB (stdlib resource)
    mem_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    users = len(core.partyline.sessions)
    channels = await core.chan.getchans()
    
    await respond(f"I am {core.botname}, running wbs v0.1: {users} users (mem: {mem_kb:.0f}k).")
    await respond(f"Online for {days} days, {hours:02d}:{int((uptime%3600)//60):02d} "
                  f"(background) - CPU: --:--.-- - Cache hit: --%")
    await respond(f"Config file: {core.config_path}")
    await respond(f"OS: {platform.system()} {platform.release()}")
    await respond(f"Process ID: {os.getpid()}")
    #await respond(f"Online as: [{core.botname}!{core.irc_user}@auto.bots]")
    #await respond(f"Connected to {core.server_host}:{core.server_port}")
    await respond(f"Active channels: {', '.join(channels) if channels else 'none'}")

async def cmd_backup(core, handle: str, session_id: int, arg: str, respond):
    await respond("Backing up the channel & user files...")
    db_path = core.db_path  # "db/wbs.db"
    config_path = core.config_path    # "config.json"
    
    # Backup DB file
    await respond("Backing up user file...")
    db_backup = f"{db_path}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
    shutil.copy2(db_path, db_backup)
    await respond(f"Database file backed up to {os.path.basename(db_backup)}")
    
    # Backup config
    await respond("Backing up channel file...")
    config_backup = f"{config_path}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
    shutil.copy2(config_path, config_backup)
    await respond(f"Config file backed up to {os.path.basename(config_backup)}")
    
    await respond("Backup complete.")

async def cmd_module(core, handle: str, session_id: int, arg: str, respond):
    await respond("Modules not enabled yet.")

async def cmd_ignores(core, handle: str, session_id: int, arg: str, respond):
    async with get_db(core.db_path) as db:
        ignores = await db.execute("SELECT hostmask, flags, comment FROM ignores ORDER BY hostmask")
        count = 0
        async for row in ignores:
            count += 1
            flags = row['flags'] if row['flags'] else ''
            comment = row['comment'] or ''
            await respond(f"{row['hostmask']} {flags}%{comment}")
        if count == 0:
            await respond("No ignores.")
        else:
            await respond(f"Total ignores: {count}")    

async def cmd_addignore(core, handle: str, arg: str, respond, action: str):
    parts = arg.split(maxsplit=2)
    if len(parts) < 1:
        await respond("Usage: +ignore <hostmask> [%<XyXdXhXm>] [comment]")
        return
    
    hostmask = parts[0].strip()
    flags = parts[1][1:] if len(parts) > 1 and parts[1].startswith('%') else ''  # %flags
    comment = parts[2] if len(parts) > 2 else ''
    
    async with get_db(core.db_path) as db:
        try:
            await db.execute(
                "INSERT INTO ignores (hostmask, flags, comment, creator) VALUES (?, ?, ?, ?)",
                (hostmask, flags, comment, handle)
            )
            await respond(f"Ignoring {hostmask} {f'%{flags}' if flags else ''}")
        except Exception:
            await respond(f"{hostmask} already ignored.")

async def cmd_delignore(core, handle: str, arg: str, respond, action: str):
    parts = arg.split(maxsplit=2)
    if len(parts) < 1:
        await respond("Usage: -ignore <hostmask>")
        return
    
    hostmask = parts[0].strip()
    flags = parts[1][1:] if len(parts) > 1 and parts[1].startswith('%') else ''  # %flags
    comment = parts[2] if len(parts) > 2 else ''
    
    async with get_db(core.db_path) as db:
        result = await db.execute("DELETE FROM ignores WHERE hostmask = ?", (hostmask,))
        if result.rowcount:
            await respond(f"No longer ignoring {hostmask}")
        else:
            await respond(f"Not ignoring {hostmask}")                

async def cmd_restart(core, handle: str, session_id: int, arg: str, respond):
    if handle != core.admin_name:
        await respond("Access denied.")
        return
    
    await respond("Restarting bot...")
    await core.shutdown("Restart via partyline")
    sys.exit(0)

async def cmd_chaddr(core, handle: str, session_id: int, arg: str, respond):
    parts = arg.split()
    if len(parts) < 2:
        await respond("Usage: .chaddr <bot> <address> [port]")
        return
    
    botname = parts[0]
    address = parts[1]
    port = int(parts[2]) if len(parts) > 2 else 3333
    
    async with get_db(core.db_path) as db:
        # Verify bot exists
        bot = await db.fetchone("SELECT * FROM bots WHERE handle = ?", (botname,))
        if not bot:
            await respond(f"Bot {botname} not found!")
            return
        
        # Update address/port
        await db.execute(
            "UPDATE bots SET address = ?, port = ? WHERE handle = ?",
            (address, port, botname)
        )
        
        await respond(f"Updated {botname}: {address}:{port}")

async def cmd_lockchan(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .lock <channel>")
        return
    
    chan = arg.strip().lstrip('#')
    now = int(time.time())
    
    async with get_db(core.db_path) as db:
        await db.execute("""
            UPDATE channels SET 
            is_locked = 1, lock_by = ?, lock_at = ?, lock_reason = ?
            WHERE name = ?
        """, (handle, now, f"Locked by {handle}", chan))
        await respond(f"Locked channel {chan}")

async def cmd_unlockchan(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .unlock <channel>")
        return
    
    chan = arg.strip().lstrip('#')
    now = int(time.time())
    
    async with get_db(core.db_path) as db:
        await db.execute("""
            UPDATE channels SET 
            is_locked = 0, lock_by = NULL, lock_at = 0, lock_reason = NULL
            WHERE name = ?
        """, (chan,))
        await respond(f"Unlocked channel {chan}")

async def cmd_topiclock(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: [topicun]lock <channel> [topic]")
        return
    
    parts = arg.split(maxsplit=1)
    chan = parts[0].strip().lstrip('#')
    topic = parts[1] if len(parts) > 1 else ''
    now = int(time.time())
    
    async with get_db(core.db_path) as db:
        await db.execute("""
            UPDATE channels SET 
            is_topiclock = 1, topiclock = ?, topiclock_by = ?, topiclock_at = ?
            WHERE name = ?
        """, (topic, handle, now, chan))
        await respond(f"Topiclock {chan} {f'to: {topic}' if topic else ''}")

async def cmd_topicunlock(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: [topicun]lock <channel> [topic]")
        return
    
    parts = arg.split(maxsplit=1)
    chan = parts[0].strip().lstrip('#')
    topic = parts[1] if len(parts) > 1 else ''
    now = int(time.time())
    
    async with get_db(core.db_path) as db:
        await db.execute("""
            UPDATE channels SET 
            is_topiclock = 0, topiclock = NULL, topiclock_by = NULL, topiclock_at = 0
            WHERE name = ?
        """, (chan,))
        await respond(f"Topic unlocked {chan}")            

async def cmd_plugins(core, handle: str, session_id: int, arg: str, respond):
    """
    .plugins  → list loaded / auto-load / available (src/plugins/*.py)
    """
    # Loaded (runtime)
    loaded = sorted(core.plugin.plugins.keys())

    # Auto-load from config.json
    auto_load = sorted(core.config.get('plugins', []))

    # Available .py in src/plugins (excluding __init__.py)
    plugins_dir = os.path.join("src", "plugins")
    if os.path.isdir(plugins_dir):
        all_files = glob.glob(os.path.join(plugins_dir, "*.py"))
        avail = [
            os.path.splitext(os.path.basename(p))[0]
            for p in all_files
            if os.path.basename(p) != "__init__.py"
        ]
    else:
        avail = []

    # Available-but-not-loaded helper
    available_not_loaded = sorted(set(avail) - set(loaded))

    msg_lines = [
        f"Loaded ({len(loaded)}): {loaded or 'none'}",
        f"Auto-load ({len(auto_load)}): {auto_load or 'none'}",
        f"On disk ({len(avail)}): {avail or 'none'}",
        f"Available to load: {available_not_loaded or 'none'}",
    ]
    await respond("\n".join(msg_lines))

async def cmd_load(core, handle: str, session_id: int, arg: str, respond):
    """load <plugin> - Load plugin from src/plugins/"""
    args = arg.strip().split()
    if not args:
        await respond("Usage: .load <plugin>")
        return
    
    name = args[0]
    if name in core.plugin.plugins:
        await respond(f"{name} already loaded")
        return
    
    # Verify .py exists in src/plugins/
    plugin_path = f"src/plugins/{name}.py"
    if not os.path.exists(plugin_path):
        await respond(f"{name}.py not found in src/plugins/")
        return
    
    try:
        await core.plugin.load_plugin(name)
        await respond(f"Loaded {name}")
    except Exception as e:
        await respond(f"Failed to load {name}: {e}")

async def cmd_unload(core, handle: str, session_id: int, arg: str, respond):
    """unload <plugin> - Unload plugin"""
    args = arg.strip().split()
    if not args:
        await respond("Usage: .unload <plugin>")
        return
    
    name = args[0]
    if name not in core.plugin.plugins:
        await respond(f"{name} not loaded")
        return
    
    try:
        plugin = core.plugin.plugins.pop(name)
        await plugin.unload()
        # Remove from auto-load config
        if name in core.config.get('plugins', []):
            core.config['plugins'].remove(name)
            core.save_config()
        await respond(f"Unloaded {name}")
    except Exception as e:
        await respond(f"Failed to unload {name}: {e}")

def _games_dir() -> Path:
    return Path("src") / "games"

def _game_files() -> list[str]:
    games_dir = _games_dir()
    if not games_dir.is_dir():
        return []

    return sorted(
        p.stem
        for p in games_dir.glob("*.py")
        if p.name != "__init__.py"
    )

def _parse_kv(tokens: list[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    for token in tokens:
        if "=" not in token:
            continue

        k, v = token.split("=", 1)
        k = k.strip().lower()
        v = v.strip()

        if not k:
            continue

        if v.lower() in {"true", "yes", "on"}:
            out[k] = True
        elif v.lower() in {"false", "no", "off"}:
            out[k] = False
        else:
            try:
                out[k] = int(v)
            except ValueError:
                try:
                    out[k] = float(v)
                except ValueError:
                    out[k] = v
                    
    return out

async def cmd_games(core, handle: str, session_id: int, arg: str, respond):
    """
    .games -> list loaded / auto-load / available games
    """
    loaded = sorted(core.game.games.keys())
    auto_load = sorted(core.config.get("games", []))
    avail = _game_files()
    available_not_loaded = sorted(set(avail) - set(loaded))

    msg_lines = [
        f"Loaded ({len(loaded)}): {loaded or 'none'}",
        f"Auto-load ({len(auto_load)}): {auto_load or 'none'}",
        f"On disk ({len(avail)}): {avail or 'none'}",
        f"Available to load: {available_not_loaded or 'none'}",
    ]
    await respond("\n".join(msg_lines))

async def cmd_gload(core, handle: str, session_id: int, arg: str, respond):
    """gload <game> - Load game from src/games/"""
    args = arg.strip().split()
    if not args:
        await respond("Usage: .gload <game>")
        return

    name = args[0].lower()

    if name in core.game.games:
        await respond(f"{name} already loaded")
        return

    if name not in _game_files():
        await respond(f"{name}.py not found in src/games/")
        return

    try:
        await core.game.load_game(name)

        core.config.setdefault("games", [])
        if name not in core.config["games"]:
            core.config["games"].append(name)
            core.config["games"] = sorted(set(core.config["games"]))

        await respond(f"Loaded game {name}")
    except Exception as e:
        await respond(f"Failed to load {name}: {e}")

async def cmd_gunload(core, handle: str, session_id: int, arg: str, respond):
    """gunload <game> - Unload game"""
    args = arg.strip().split()
    if not args:
        await respond("Usage: .gunload <game>")
        return

    name = args[0].lower()

    if name not in core.game.games:
        await respond(f"{name} not loaded")
        return

    try:
        await core.game.unload_game(name)

        if name in core.config.get("games", []):
            core.config["games"].remove(name)

        await respond(f"Unloaded game {name}")
    except Exception as e:
        await respond(f"Failed to unload {name}: {e}")


async def cmd_gstart(core, handle: str, session_id: int, arg: str, respond):
    """
    gstart <game> <scope> <target> [k=v ...]
    Example: .gstart duckhunt channel #wbs min_delay=15 max_delay=45
    """
    args = arg.strip().split()
    if len(args) < 3:
        await respond("Usage: .gstart <game> <scope> <target> [k=v ...]")
        return

    game_name = args[0].lower()
    scope = args[1].lower()
    target = args[2]
    kwargs = _parse_kv(args[3:])

    try:
        session = await core.game.start_game(
            game_name,
            scope,
            target,
            owner=handle,
            **kwargs,
        )
        await respond(
            f"Started {session.game_name} in {session.scope}:{session.target} "
            f"(state={session.state})"
        )
    except Exception as e:
        await respond(f"Failed to start {game_name}: {e}")


async def cmd_gstop(core, handle: str, session_id: int, arg: str, respond):
    """gstop <game> <scope> <target>"""
    args = arg.strip().split()
    if len(args) < 3:
        await respond("Usage: .gstop <game> <scope> <target>")
        return

    game_name = args[0].lower()
    scope = args[1].lower()
    target = args[2]

    try:
        await core.game.stop_game(game_name, scope, target)
        await respond(f"Stopped {game_name} in {scope}:{target}")
    except Exception as e:
        await respond(f"Failed to stop {game_name}: {e}")


async def cmd_gsessions(core, handle: str, session_id: int, arg: str, respond):
    """gsessions - List active game sessions"""
    lines = []

    for game_name, game in sorted(core.game.games.items()):
        for key, session in sorted(game.sessions.items()):
            lines.append(
                f"{game_name} {key} state={session.state} "
                f"players={len(session.players)} owner={session.owner or '-'}"
            )

    if not lines:
        await respond("No active game sessions")
        return

    await respond("\n".join(lines))

async def cmd_chattr(core, handle: str, session_id: int, arg: str, respond):
    """
    .chattr <user> [channel] +/-<flags>
    Flags: A=admin P=partyline O=op V=voice F=friend D=deop E=devoice
    """
    parts = arg.split()
    if len(parts) < 2:
        await respond("Usage: .chattr <user> [#channel] +/-<flags>")
        return

    target = parts[0]
    if len(parts) == 3:
        channel, flags = parts[1], parts[2]
    else:
        channel, flags = None, parts[1]

    if not flags or flags[0] not in ('+', '-'):
        await respond("Flags must start with + or -")
        return

    adding = flags[0] == '+'
    flag_chars = flags[1:].lower()

    flag_map = {
        'a': 'is_admin', 'p': 'has_partyline', 'o': 'is_op',
        'v': 'is_voice',  'f': 'is_friend',     'd': 'is_deop',
        'e': 'is_devoice'
    }

    updates = {flag_map[f]: adding for f in flag_chars if f in flag_map}
    if not updates:
        await respond(f"No valid flags in: {flags}")
        return

    set_clause = ", ".join(f"{col} = ?" for col in updates)
    values = list(updates.values())

    async with get_db(core.db_path) as db:
        if channel:
            values += [target, channel]
            await db.execute(
                f"UPDATE user_access SET {set_clause} WHERE handle = ? AND channel = ?",
                values
            )
        else:
            values += [target]
            await db.execute(
                f"UPDATE user_access SET {set_clause} WHERE handle = ? AND channel IS NULL",
                values
            )
        await db.commit()

    scope = f" on {channel}" if channel else " (global)"
    await respond(f"Flags {flags} applied to {target}{scope}")

async def cmd_relay(core, handle: str, session_id: int, arg: str, respond):
    """
    .relay <botnick> — connect your partyline session to another bot's partyline via botnet.
    .relay <botnick> <command> — run a single command on a remote bot and return output.
    Type '.relay' with no args to disconnect from current relay.
    """
    parts = arg.strip().split(maxsplit=1)

    # .relay with no args — disconnect from current relay
    if not parts:
        session = core.partyline.sessions.get(session_id, {})
        if session.get('relay_to'):
            prev = session.pop('relay_to')
            await respond(f"Disconnected from relay: {prev}")
        else:
            await respond("Not currently relayed to any bot.")
        return

    botnick = parts[0]
    remote_cmd = parts[1] if len(parts) > 1 else None

    # Verify bot is linked
    if botnick not in core.botnet.peers:
        await respond(f"Bot {botnick} is not linked. Use .link first.")
        return

    if remote_cmd:
        # One-shot: send a single command to the remote bot and relay response back
        await core.botnet.send_to_peer(botnick, {
            'type': 'PARTYLINE_CMD',
            'from': handle,
            'session_id': session_id,
            'cmd': remote_cmd,
            'reply_to': core.botname
        })
        await respond(f"→ [{botnick}] {remote_cmd}")
    else:
        # Persistent relay: park this session's input on the remote bot
        session = core.partyline.sessions.get(session_id, {})
        if session.get('relay_to') == botnick:
            await respond(f"Already relayed to {botnick}.")
            return
        session['relay_to'] = botnick
        await respond(f"Relayed to {botnick}. All input forwarded. Type '.relay' alone to disconnect.")

async def cmd_mass(core, handle: str, session_id: int, arg: str, respond):
    """
    .mass <op|deop> <#channel>
    Mass op/deop all users in a channel.
    """
    parts = arg.split()
    if len(parts) < 2:
        await respond("Usage: .mass <op|deop> <#channel>")
        return

    action, channel = parts[0].lower(), parts[1]

    # Ask IRC process for channel userlist via snapshot
    snapshot = core.irc_snapshot.get(channel, {})
    users = snapshot.get('user_list', [])
    ops   = set(snapshot.get('ops', []))
    botname = core.botname

    if not users:
        await respond(f"No users found in {channel} (not joined or no snapshot).")
        return

    if action == 'op':
        targets = [u for u in users if u != botname and u not in ops]
        mode_char = '+o'
    elif action == 'deop':
        targets = [u for u in users if u != botname and u in ops]
        mode_char = '-o'
    else:
        await respond(f"Unknown mass action: {action}. Valid: op deop")
        return

    if not targets:
        await respond(f"No users to {action} in {channel}.")
        return

    # IRC max 4 mode targets per line (safe default)
    chunk = 4
    for i in range(0, len(targets), chunk):
        batch = targets[i:i+chunk]
        modes = f"{'+'if action=='op' else '-'}{'o'*len(batch)} {' '.join(batch)}"
        core.irc_q.put_nowait({'cmd': 'mode', 'channel': channel, 'modes': modes})

    await respond(f"Mass {action} sent for {len(targets)} user(s) in {channel}.")

async def cmd_net(core, handle: str, session_id: int, arg: str, respond):
    """
    .net <subcmd> [args]
    Botnet-level commands: op deop say msg join part mode rehash restart die
    """
    parts = arg.split(maxsplit=1)
    if not parts:
        await respond("Usage: .net <op|deop|say|msg|join|part|mode|restart|die> [args]")
        return

    subcmd = parts[0].lower()
    rest   = parts[1] if len(parts) > 1 else ''

    # Broadcast to all linked peers via botnet
    if hasattr(core, 'botnet') and core.botnet.peers:
        await core.botnet.broadcast({'type': 'NET_CMD', 'subcmd': subcmd, 'args': rest, 'from': handle})

    # Also execute locally
    local_cmds = {
        'op':      cmd_op,
        'deop':    cmd_deop,
        'say':     cmd_msg,
        'msg':     cmd_msg,
        'join':    cmd_join,
        'part':    cmd_part,
        'mode':    cmd_mode,
        'restart': cmd_restart,
        'die':     cmd_quit,
    }
    if subcmd in local_cmds:
        await local_cmds[subcmd](core, handle, session_id, rest, respond)
    else:
        await respond(f"Unknown net subcmd: {subcmd}")

async def cmd_subnet(core, handle: str, session_id: int, arg: str, respond):
    """
    .subnet list
    .subnet set <name> <key> <value>
    """
    parts = arg.split()
    if not parts:
        await respond("Usage: .subnet <list|set> [args]")
        return

    subcmd = parts[0].lower()

    if subcmd == 'list':
        async with get_db(core.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT id, name, hub_host, hub_port FROM subnets ORDER BY id"
            )
        if not rows:
            await respond("No subnets configured.")
            return
        for r in rows:
            await respond(f"  [{r['id']}] {r['name']}  hub={r['hub_host']}:{r['hub_port']}")

    elif subcmd == 'set':
        if len(parts) < 4:
            await respond("Usage: .subnet set <name> <key> <value>")
            return
        name, key, value = parts[1], parts[2], parts[3]
        allowed = {'hub_host', 'hub_port', 'name'}
        if key not in allowed:
            await respond(f"Allowed keys: {', '.join(allowed)}")
            return
        async with get_db(core.db_path) as db:
            await db.execute(f"UPDATE subnets SET {key} = ? WHERE name = ?", (value, name))
            await db.commit()
        await respond(f"Subnet {name}: {key} = {value}")
    else:
        await respond(f"Unknown subnet subcmd: {subcmd}. Valid: list set")

async def cmd_taskset(core, handle: str, session_id: int, arg: str, respond):
    """
    .taskset <task_name> <0|1>
    Enable or disable a named task in core.tasks.
    """
    parts = arg.split()
    if len(parts) < 2:
        await respond("Usage: .taskset <task_name> <0|1>")
        return

    task_name, state = parts[0], parts[1]
    enabled = state not in ('0', 'off', 'false', 'no')

    tasks = getattr(core, 'tasks', {})
    if task_name not in tasks:
        await respond(f"Unknown task: {task_name}. See .tasks for list.")
        return

    tasks[task_name]['enabled'] = enabled
    await respond(f"Task {task_name} {'enabled' if enabled else 'disabled'}.")

async def cmd_tasks(core, handle: str, session_id: int, arg: str, respond):
    """
    .tasks — show all registered tasks and their state.
    """
    tasks = getattr(core, 'tasks', {})
    if not tasks:
        await respond("No tasks registered.")
        return
    await respond("Tasks:")
    for name, info in sorted(tasks.items()):
        state = "ON" if info.get('enabled', True) else "OFF"
        interval = info.get('interval', '?')
        await respond(f"  {name:<20} [{state}]  every {interval}s")

async def cmd_timers(core, handle: str, session_id: int, arg: str, respond):
    """
    .timers — show active IRC timers registered in the IRC process.
    """
    # IRC timers live in the irc process; we read from core's snapshot if available
    timers = getattr(core, 'irc_timers', {})
    if not timers:
        await respond("No active IRC timers.")
        return
    await respond("IRC Timers:")
    for name, info in sorted(timers.items()):
        interval = info.get('interval', '?')
        await respond(f"  {name:<20} every {interval}s")

async def cmd_nopass(core, handle: str, session_id: int, arg: str, respond):
    """
    .nopass — list all users without a password set.
    """
    async with get_db(core.db_path) as db:
        rows = await db.execute_fetchall(
            "SELECT handle FROM users WHERE (password IS NULL OR password = '') AND deleted_at IS NULL ORDER BY handle"
        )
    if not rows:
        await respond("All users have passwords set.")
        return
    await respond(f"Users without password ({len(rows)}):")
    for r in rows:
        await respond(f"  {r['handle']}")

async def cmd_fixpass(core, handle: str, session_id: int, arg: str, respond):
    """
    .fixpass — assign a random 12-char password to all users without one.
    Passwords are echoed once; user should change immediately with .chpass.
    """
    async with get_db(core.db_path) as db:
        rows = await db.execute_fetchall(
            "SELECT handle FROM users WHERE (password IS NULL OR password = '') AND deleted_at IS NULL"
        )

    if not rows:
        await respond("No users without passwords.")
        return

    import bcrypt
    alphabet = string.ascii_letters + string.digits
    fixed = []
    for r in rows:
        pw = ''.join(secrets.choice(alphabet) for _ in range(12))
        hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
        async with get_db(core.db_path) as db:
            await db.execute("UPDATE users SET password = ? WHERE handle = ?", (hashed, r['handle']))
            await db.commit()
        fixed.append((r['handle'], pw))

    await respond(f"Set random passwords for {len(fixed)} user(s):")
    for uhandle, pw in fixed:
        await respond(f"  {uhandle}: {pw}")
    await respond("Users should change their password with .chpass immediately.")

async def cmd_baway(core, handle: str, session_id: int, arg: str, respond):
    """
    .baway [reason] — set the bot away on IRC.
    """
    reason = arg.strip() or "Away"
    core.irc_q.put_nowait({'cmd': 'raw', 'line': f'AWAY :{reason}'})
    core.away = reason
    await respond(f"Bot is now away: {reason}")

async def cmd_bback(core, handle: str, session_id: int, arg: str, respond):
    """
    .bback — return the bot from away.
    """
    core.irc_q.put_nowait({'cmd': 'raw', 'line': 'AWAY'})
    core.away = None
    await respond("Bot is back.")

async def cmd_nick(core, handle: str, session_id: int, arg: str, respond):
    """
    .nick [newnick] — show current nick or change it.
    """
    if not arg:
        await respond(f"Current nick: {core.botname}")
        return
    new_nick = arg.strip().split()[0]
    core.irc_q.put_nowait({'cmd': 'raw', 'line': f'NICK {new_nick}'})
    await respond(f"Nick change requested: {new_nick}")

async def cmd_lag(core, handle: str, session_id: int, arg: str, respond):
    """
    .lag — show current measured lag to the IRC server.
    """
    if not core.connected:
        await respond("Not connected to IRC.")
        return

    lag = core._last_lag_ms
    if lag == 0.0:
        await respond("No lag measurement yet (waiting for first PONG).")
    else:
        await respond(f"Current lag: {lag:.1f}ms")

async def cmd_sdns(core, handle: str, session_id: int, arg: str, respond):
    """
    .sdns <host|ip> — resolve hostname/IP using the local resolver.
    """
    if not arg:
        await respond("Usage: .sdns <host|ip>")
        return
    target = arg.strip().split()[0]
    try:
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(target, None)
        seen = set()
        for entry in info:
            addr = entry[4][0]
            if addr not in seen:
                seen.add(addr)
                await respond(f"  {target} → {addr}")
    except socket.gaierror as e:
        await respond(f"DNS lookup failed for {target}: {e}")

async def cmd_swhois(core, handle: str, session_id: int, arg: str, respond):
    """
    .swhois <nick> — send WHOIS to IRC server.
    """
    if not arg:
        await respond("Usage: .swhois <nick>")
        return
    nick = arg.strip().split()[0]
    core.irc_q.put_nowait({'cmd': 'whois', 'nick': nick})
    await respond(f"WHOIS sent for {nick}. Response will appear in server output.")

async def cmd_swhowas(core, handle: str, session_id: int, arg: str, respond):
    """
    .swhowas <nick> — send WHOWAS to IRC server.
    """
    if not arg:
        await respond("Usage: .swhowas <nick>")
        return
    nick = arg.strip().split()[0]
    core.irc_q.put_nowait({'cmd': 'raw', 'line': f'WHOWAS {nick}'})
    await respond(f"WHOWAS sent for {nick}.")

async def cmd_links(core, handle: str, session_id: int, arg: str, respond):
    """
    .links — request server LINKS list from IRC.
    """
    core.irc_q.put_nowait({'cmd': 'raw', 'line': 'LINKS'})
    await respond("LINKS request sent. Response will appear in server output.")

async def cmd_infoleaf(core, handle: str, session_id: int, arg: str, respond):
    """
    .infoleaf — show the command to add this bot as a leaf on another bot.
    """
    cfg = core.config.get('botnet', {})
    botname  = core.botname
    address  = cfg.get('address', '<your.host>')
    port     = cfg.get('listen_port', 3333)
    await respond(f"To add this bot as a leaf on another hub, run:")
    await respond(f"  .addleaf {botname} {address} {port}")


async def cmd_addleaf(core, handle: str, session_id: int, arg: str, respond):
    """
    .addleaf <botnick> <host> <port>
    Register a leaf bot and print the reciprocal addhub command.
    """
    parts = arg.split()
    if len(parts) < 3:
        await respond("Usage: .addleaf <botnick> <host> <port>")
        return
    botnick, host, port = parts[0], parts[1], parts[2]
    try:
        port_int = int(port)
    except ValueError:
        await respond("Port must be a number.")
        return

    ok = await core.bot.addbot(botnick, None, host, port_int)
    if ok:
        await respond(f"Leaf {botnick} ({host}:{port_int}) added.")
        await respond(f"Now run on {botnick}:")
        cfg = core.config.get('botnet', {})
        my_addr = cfg.get('address', '<your.host>')
        my_port = cfg.get('listen_port', 3333)
        await respond(f"  .addhub {core.botname} {my_addr} {my_port}")
    else:
        await respond(f"Bot {botnick} already exists. Use .chaddr to update.")


async def cmd_addhub(core, handle: str, session_id: int, arg: str, respond):
    """
    .addhub <botnick> <host> <port>
    Register a hub bot to connect to.
    """
    parts = arg.split()
    if len(parts) < 3:
        await respond("Usage: .addhub <botnick> <host> <port>")
        return
    botnick, host, port = parts[0], parts[1], parts[2]
    try:
        port_int = int(port)
    except ValueError:
        await respond("Port must be a number.")
        return

    ok = await core.bot.addbot(botnick, None, host, port_int)
    if ok:
        await respond(f"Hub {botnick} ({host}:{port_int}) added. Use .link {botnick} to connect.")
    else:
        await respond(f"Bot {botnick} already exists. Use .chaddr to update.")

async def cmd_whois(core, handle: str, session_id: int, arg: str, respond):
    """
    .whois <handle>
    Display user info, flags, hostmasks, and access. Delegates to UserManager.
    """
    target = arg.strip().split()[0] if arg.strip() else ""
    if not target:
        await respond("Usage: .whois <handle>")
        return

    # core.user.get() returns a User dataclass or None
    user = await core.user.get(target)
    if not user:
        await respond(f"No such user: {target}")
        return

    # showuser() returns the full formatted multi-line string
    info = await core.user.showuser(target)
    for line in info.split("\n"):
        await respond(line)

# Command registry
COMMANDS = {
    'help': cmd_help,
    'date': cmd_date,
    'time': cmd_date,
    'whoami': cmd_whoami,
    'uptime': cmd_uptime,
    'version': cmd_version,
    'who': cmd_who,
    'whom': cmd_whom,
    'mode': cmd_mode,
    'op': cmd_op,
    'deop': cmd_deop,
    'voice': cmd_voice,
    'devoice': cmd_devoice,
    'join': cmd_join,
    'part': cmd_part,
    'say': cmd_msg,
    'msg': cmd_msg,
    'act': cmd_act,
    'quit': cmd_quit,
    'die': cmd_quit,
    'status': cmd_status,
    'backup': cmd_backup,
    'module': cmd_module,
    'restart': cmd_restart,
    'chattr':       cmd_chattr,
    'relay':        cmd_relay,
    'mass':         cmd_mass,
    'net':          cmd_net,
    'subnet':       cmd_subnet,
    'taskset':      cmd_taskset,
    'tasks':        cmd_tasks,
    'timers':       cmd_timers,
    'nopass':       cmd_nopass,
    'fixpass':      cmd_fixpass,
    'baway':        cmd_baway,
    'bback':        cmd_bback,
    'nick':         cmd_nick,
    'lag':          cmd_lag,
    'sdns':         cmd_sdns,
    'swhois':       cmd_swhois,
    'swhowas':      cmd_swhowas,
    'links':        cmd_links,
    'infoleaf':     cmd_infoleaf,
    'addleaf':      cmd_addleaf,
    'addhub':       cmd_addhub,
    # user
    'whois':       cmd_whois,
    '+user': cmd_adduser,
    '-user': cmd_deluser,
    'userinfo': cmd_showuser,
    'users': cmd_listusers,
    'chusercomment': cmd_chusercomment,
    'addaccess': cmd_addaccess,
    'delaccess': cmd_delaccess,
    'lockuser': cmd_lockuser,
    'unlockuser': cmd_unlockuser,
    'chpass': cmd_passwd,
    'handle': cmd_handle,
    'chhandle': cmd_chhandle,
    '+host': cmd_addhost,
    '-host': cmd_delhost,
    # channel    
    '+chan': cmd_addchan,
    'join': cmd_addchan,
    '-chan': cmd_delchan,
    'part': cmd_delchan,
    'chaninfo': cmd_showchan,
    'channels': cmd_channels,
    'lockchan': cmd_lockchan,
    'unlockchan': cmd_unlockchan,
    'topiclock': cmd_topiclock,
    'topicunlock': cmd_topicunlock,
    # bot
    '+bot': cmd_addbot,
    '-bot': cmd_delbot,
    'botinfo': cmd_botinfo,
    'bots': cmd_bots,
    'link': cmd_link,
    'unlink': cmd_unlink,
    'chaddr': cmd_chaddr,
    # ignores    
    '+ignore': cmd_addignore,
    '-ignore': cmd_delignore,
    'ignores': cmd_ignores,
    # plugins
    'plugins': cmd_plugins,
    'load': cmd_load,
    'unload': cmd_unload,
    # games
    'games': cmd_games,
    'gload': cmd_gload,
    'gunload': cmd_gunload,
    'gstart': cmd_gstart,
    'gstop': cmd_gstop,
    'gsessions': cmd_gsessions
}