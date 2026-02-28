# src/commands.py
"""
Partyline commands for WBS
"""

import time
from datetime import datetime, timedelta
from typing import Optional

from . import __version__

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
      handle       whoami       -host        note         
   For ops:
      mode         say          msg          op
      deop         voice        devoice
   For admins:
      chattr       backup       status       die
      modules      +user        +ignore      ignores      
      -user        -ignore      dccstat      restart
      +bot         botattr      chhandle     relay
      +host        -bot         link         chaddr
      unlink       dccstat      update       channels
      mnote        bots         join         part
      lock         unlock       topiclock    topicunlock
      sdns         swhois       swhowas      links 
      taskset      timers       tasks        botinfo 
      nopass       fixpass      mass         net
      baway        bback        nick         lag 
      infoleaf     addleaf      addhub       subnet  

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

#async def cmd_channels(core, handle, session_id, arg, respond):
#    """List active channels."""
#    if core.config.get('limbo_hub'):
#        return await send_partyline(config, core_q, irc_q, idx, "Limbo hub: no channels.")
#    
#    lines = ["=== Active Channels ==="]
#    for chan in core.channels:
#        modes = await get_channel_modes(core, chan)
#        op_status = "op" if await bot_is_op(core, chan) else "no-op"
#        lines.append(f"{chan} [{modes}] [{op_status}]")
#    
#    await send_partyline(config, core_q, irc_q, idx, '\n'.join(lines))
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
    if not arg:
        await respond("Usage: .addchan <user>")
        return
    parts = arg.split()
    if await core.chan.addchan(parts[0]) == True:
        core.irc_q.put_nowait({'cmd': 'join', 'channel': parts[0]})
        await respond(f"→ Channel {parts[0]} added!")
    else:
        await respond(f"→ Channel {parts[0]} NOT added!")

async def cmd_delchan(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .delchan <user>")
        return
    parts = arg.split()
    if await core.chan.delchan(parts[0]) == True:
        core.irc_q.put_nowait({'cmd': 'part', 'channel': parts[0]})
        await respond(f"→ Channel {parts[0]} deleted!")
    else:
        await respond(f"→ Channel {parts[0]} NOT deleted!")

async def cmd_showchan(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .showchan <user>")
        return
    parts = arg.split()
    await respond(await core.chan.showchan(parts[0]))

async def cmd_listchans(core, handle: str, session_id: int, arg: str, respond):
    await respond(await core.chan.listchans())    

async def cmd_adduser(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .adduser <user> [hostmask]")
        return
    parts = arg.split()
    if await core.user.adduser(parts[0], parts[1]) == True:
        await respond(f"→ User {parts[0]} added!")
    else:
        await respond(f"→ User {parts[0]} NOT added!")

async def cmd_deluser(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .deluser <user>")
        return
    parts = arg.split()
    if await core.user.deluser(parts[0]) == True:
        await respond(f"→ User {parts[0]} deleted!")
    else:
        await respond(f"→ User {parts[0]} NOT deleted!")

async def cmd_showuser(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .showuser <user>")
        return
    parts = arg.split()
    await respond(await core.user.showuser(parts[0]))

async def cmd_passwd(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .passwd [user] <password>")
        return
    parts = arg.split()
    if len(parts) > 1:
        await respond(core.user.set_password(parts[1], parts[2]))  
    else:
        if handle == "console":
            await respond("ERROR: Console user don't have a password to change.")
            return
        await respond(core.user.set_password(handle, parts[1]))
    return

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
    botinfo = """
-> Bot Info <-
-> Pid #: 503
-> Runs in: /home/blurr/wbs
-> Admin: cyco <email: loco@cyco.ca>
-> Botnet nick: blurr
-> Perm Owner(s):
-> Machine: armv6l
-> Oper. System: Linux 6.12.62+rpt-rpi-v6
-> Tcl Ver.: 8.6
-> I currently allow remote boots from shared bots only.
-> I am currently sorting my users...
"""
    await respond(botinfo)

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
    #if not arg:
    #    await respond("Usage: .listusers")
    #    return
    #parts = arg.split()
    await respond("Not implemented yet.")          

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
    # user
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
    '-chan': cmd_delchan,
    'chaninfo': cmd_showchan,
    'channels': cmd_listchans,
    # bot
    '+bot': cmd_addbot,
    '-bot': cmd_delbot,
    'botinfo': cmd_botinfo,
    'bots': cmd_bots,
    'link': cmd_link,
    'unlink': cmd_unlink,
    #'chaddr': cmd_chaddr,
}