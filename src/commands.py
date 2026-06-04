# src/commands.py
"""
Partyline commands for WBS
"""
import time
import os
import platform
import resource
import shutil
import glob
import logging
import secrets
import string
import socket
import asyncio
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict

from . import __version__
from .db import get_db
from .helper import _require_flag, _resolve_subnet_arg, _chan_mode_cmd, _list_loadables, _botnet_sync, _modify_hostmask

log = logging.getLogger("wbs.commands")
_CHATTR_ALLOWED_COLUMNS: frozenset[str] = frozenset({
    "is_admin", "has_partyline", "is_op",
    "is_voice", "is_friend", "is_deop", "is_devoice",
})
_BOTATTR_ALLOWED_COLUMNS: frozenset[str] = frozenset({
    "autolink", "role", "autolink_retry_interval",
    "share_level", "password", "comment",
})
_HANDLE_RE = re.compile(r'^[a-zA-Z0-9_\-\[\]\\^`|{}]{1,20}$')

async def cmd_help(core, handle, session_id, arg, respond):
    """Show help"""
    words = arg.split()
    if len(words) < 1:
        help_text = """\
.: Wicked Bot System Help :.
   For all users:
      help         date         time         uptime
      version      whoami       who          whom
      whois        handle       chpass       quit

   For ops:
      mode         say          msg          act
      op           deop         voice        devoice

   For admins:
      chattr       chhandle     chpass       backup
      status       die          restart      nick
      baway        bback        lag          botinfo
      rehash

   User management:
      +user        -user        users        userinfo
      chusercomment addaccess   delaccess    lockuser
      unlockuser   +host        -host        nopass
      fixpass

   Channel management:
      +chan        -chan        channels     chaninfo
      join         part         mode

   Bot/Botnet management:
      +bot         -bot         bots         botattr
      link         unlink       chaddr       relay
      infoleaf     addleaf      addhub       subnet
      net          mass

   Ignore management:
      +ignore      -ignore      ignores

   Security:
      denyhost     permithost   blocklist

   Plugins & Games:
      plugins      load         unload
      games        gload        gunload
      gstart       gstop        gsessions

   IRC server tools:
      sdns         swhois       swhowas      links

   Tasks & Timers:
      taskset      tasks        timers

   Updates:
      checkupdate  update

All commands begin with '.', and all else goes to the party line.
"""
        for line in help_text.split('\n'):
            await respond(line)
        return

    cmd = words[0].lower()

    if cmd == "help":
        help_text = """\
###  help [command]
    Shows help. Optionally specify a command name for detailed help.
"""

    elif cmd == "date" or cmd == "time":
        help_text = """\
###  date / time
    Shows the current date and time.
"""

    elif cmd == "uptime":
        help_text = """\
###  uptime
    Shows how long the bot has been running.
"""

    elif cmd == "version":
        help_text = """\
###  version
    Shows the current version of the bot system.
"""

    elif cmd == "whoami":
        help_text = """\
###  whoami
    Shows your current handle and bot name.
"""

    elif cmd == "who":
        help_text = """\
###  who
    Lists all users currently on the party line and connected bots.

See also: whom
"""

    elif cmd == "whom":
        help_text = """\
###  whom
    Shows party line members with their nick, bot, and host.

See also: who
"""

    elif cmd == "whois":
        help_text = """\
###  whois <handle>
    Shows detailed info for a user: flags, hostmasks, and access.

See also: userinfo, users
"""

    elif cmd == "handle":
        help_text = """\
###  handle <new-handle>
    Changes your own party line handle.

See also: chhandle
"""

    elif cmd == "chpass":
        help_text = """\
###  chpass [user] <password>
    Changes a password. With one argument, changes your own password.
    With two arguments (requires +A), changes another user's password.
    Password must be at least 8 characters.

See also: nopass, fixpass
"""

    elif cmd == "quit":
        help_text = """\
###  quit [message]
    Disconnects the bot from IRC and shuts it down.

See also: die, restart
"""

    elif cmd == "die":
        help_text = """\
###  die [message]
    Alias for quit. Disconnects the bot from IRC and shuts it down.

See also: quit, restart
"""

    elif cmd == "mode":
        help_text = """\
###  mode <#channel> <modes>
    Sets modes on a channel.
    Example: .mode #wbs +m

See also: op, deop, voice, devoice
"""

    elif cmd == "say" or cmd == "msg":
        help_text = """\
###  say <target> <message>
###  msg <target> <message>
    Sends a message to a channel or nick.
    Example: .say #wbs Hello world

See also: act
"""

    elif cmd == "act":
        help_text = """\
###  act <#channel> <action>
    Sends a CTCP ACTION (/me) to a channel.
    Example: .act #wbs waves hello

See also: say, msg
"""

    elif cmd == "op":
        help_text = """\
###  op <nick> <#channel>
    Gives channel operator status to a nick.

See also: deop, mode, mass
"""

    elif cmd == "deop":
        help_text = """\
###  deop <nick> <#channel>
    Removes channel operator status from a nick.

See also: op, mode, mass
"""

    elif cmd == "voice":
        help_text = """\
###  voice <nick> <#channel>
    Gives voice status to a nick.

See also: devoice, mode
"""

    elif cmd == "devoice":
        help_text = """\
###  devoice <nick> <#channel>
    Removes voice status from a nick.

See also: voice, mode
"""

    elif cmd == "chattr":
        help_text = """\
###  chattr <user> [#channel] +/-<flags>
    Changes user flags. Global if no channel given, channel-specific otherwise.
    Flags: A=admin P=partyline O=op V=voice F=friend D=deop E=devoice
    Example: .chattr bob +A
    Example: .chattr bob #wbs +O

See also: +user, userinfo
"""

    elif cmd == "chhandle":
        help_text = """\
###  chhandle <oldhandle> <newhandle>
    Changes another user's handle (admin).

See also: handle
"""

    elif cmd == "backup":
        help_text = """\
###  backup
    Backs up the database and config file with a timestamped filename.
"""

    elif cmd == "status":
        help_text = """\
###  status
    Shows bot status: uptime, memory usage, active channels, PID, OS.

See also: botinfo, uptime
"""

    elif cmd == "restart":
        help_text = """\
###  restart
    Performs a full bot restart. Core process exits and is relaunched
    by the supervisor. IRC connection is preserved during the transition.
    Requires 'n' (owner) flag.

See also: rehash, quit
"""

    elif cmd == "rehash":
        help_text = """\
###  rehash
    Restarts the Core process without disconnecting from IRC.
    Channel state and IRC connection are preserved.
    Requires 'm' (master) flag.

See also: restart, quit
"""

    elif cmd == "nick":
        help_text = """\
###  nick [newnick]
    Shows the bot's current nick, or changes it if a new nick is given.
"""

    elif cmd == "baway":
        help_text = """\
###  baway [reason]
    Puts the bot in IRC away mode.

See also: bback
"""

    elif cmd == "bback":
        help_text = """\
###  bback
    Returns the bot from IRC away mode.

See also: baway
"""

    elif cmd == "lag":
        help_text = """\
###  lag
    Shows the current measured lag to the IRC server in milliseconds.
"""

    elif cmd == "botinfo":
        help_text = """\
###  botinfo
    Shows bot system info: PID, working directory, OS, machine type.

See also: status
"""

    elif cmd == "+user":
        help_text = """\
###  +user <handle> [hostmask] [subnet|*]
    Adds a new user. Optionally set a hostmask and subnet scope.
    Use '*' for global access (valid on all subnets).

See also: -user, userinfo, chattr
"""

    elif cmd == "-user":
        help_text = """\
###  -user <handle>
    Removes a user.

See also: +user
"""

    elif cmd == "users":
        help_text = """\
###  users
    Lists all users and bots in the database.

See also: whois, userinfo, bots
"""

    elif cmd == "userinfo":
        help_text = """\
###  userinfo <handle>
    Shows detailed info for a user.

See also: whois, users
"""

    elif cmd == "chusercomment":
        help_text = """\
###  chusercomment <user> <comment>
    Sets a comment on a user record.
"""

    elif cmd == "addaccess":
        help_text = """\
###  addaccess [options] <user> <access>
    Adds access flags to a user.

See also: delaccess, chattr
"""

    elif cmd == "delaccess":
        help_text = """\
###  delaccess [options] <user> <access>
    Removes access flags from a user.

See also: addaccess, chattr
"""

    elif cmd == "lockuser":
        help_text = """\
###  lockuser <user>
    Locks a user account, preventing login.

See also: unlockuser
"""

    elif cmd == "unlockuser":
        help_text = """\
###  unlockuser <user>
    Unlocks a previously locked user account.

See also: lockuser
"""

    elif cmd == "+host":
        help_text = """\
###  +host <hostmask>
    Adds a hostmask to your user record. Format: nick!user@host
    Wildcards are supported (e.g. *!user@*.example.com).

See also: -host
"""

    elif cmd == "-host":
        help_text = """\
###  -host <hostmask>
    Removes a hostmask from your user record.

See also: +host
"""

    elif cmd == "nopass":
        help_text = """\
###  nopass
    Lists all users that do not have a password set.

See also: fixpass, chpass
"""

    elif cmd == "fixpass":
        help_text = """\
###  fixpass
    Assigns a random 12-character password to all users without one.
    Passwords are displayed once — users should change immediately with .chpass.

See also: nopass, chpass
"""

    elif cmd == "+chan":
        help_text = """\
###  +chan <#channel> [subnet|*]
    Adds a channel for the bot to join. Optionally bind to a subnet.
    Use '*' for global (no subnet binding).

See also: -chan, channels, chaninfo
"""

    elif cmd == "-chan":
        help_text = """\
###  -chan <#channel>
    Removes a channel and makes the bot part it.

See also: +chan, channels
"""

    elif cmd == "channels":
        help_text = """\
###  channels
    Lists all active channels the bot is configured to be in.

See also: +chan, -chan, chaninfo
"""

    elif cmd == "chaninfo":
        help_text = """\
###  chaninfo <#channel>
    Shows settings and info for a channel.

See also: channels
"""

    elif cmd == "join":
        help_text = """\
###  join <#channel> [key]
    Makes the bot join a channel.

See also: part
"""

    elif cmd == "part":
        help_text = """\
###  part <#channel> [reason]
    Makes the bot leave a channel.

See also: join
"""

    elif cmd == "+bot":
        help_text = """\
###  +bot <botnick> [hostmask] [address] [port]
    Adds a bot to the botnet database.

See also: -bot, botattr, link
"""

    elif cmd == "-bot":
        help_text = """\
###  -bot <botnick>
    Removes a bot from the botnet database.

See also: +bot
"""

    elif cmd == "bots":
        help_text = """\
###  bots
    Shows currently linked bots.

See also: link, unlink, botattr
"""

    elif cmd == "botattr":
        help_text = """\
###  botattr <botnick> [+/-flags] [key=value ...]
    Views or changes bot attributes.
    Flags: +/-a (autolink)  +/-h (hub)  +/-b (backup)  +/-l (leaf)  +/-n (none)
    Keys:  retry=<seconds>  share=full|subnet|none  pass=<password>  comment=<text>  role=<role>
    With no flags/keys, shows current attributes.

See also: +bot, chaddr, link
"""

    elif cmd == "link":
        help_text = """\
###  link <botnick>
    Initiates a botnet connection to a bot. Bot must have address and port set.

See also: unlink, +bot, chaddr
"""

    elif cmd == "unlink":
        help_text = """\
###  unlink <botnick>
    Disconnects from a linked bot.

See also: link
"""

    elif cmd == "chaddr":
        help_text = """\
###  chaddr <botnick> <address> [port]
    Updates the address and port for a bot. Default port: 3333.

See also: +bot, botattr, link
"""

    elif cmd == "relay":
        help_text = """\
###  relay <botnick> [command]
    Relays your party line session to another bot, or runs a single remote command.
    Type '.relay' with no arguments to disconnect from the current relay.

See also: link, net
"""

    elif cmd == "infoleaf":
        help_text = """\
###  infoleaf
    Displays the command to add this bot as a leaf on another bot's hub.

See also: addleaf, addhub
"""

    elif cmd == "addleaf":
        help_text = """\
###  addleaf <botnick> <host> <port>
    Registers a leaf bot and prints the reciprocal addhub command to run on it.

See also: infoleaf, addhub, link
"""

    elif cmd == "addhub":
        help_text = """\
###  addhub <botnick> <host> <port>
    Registers a hub bot to connect to. Use .link to connect after adding.

See also: infoleaf, addleaf, link
"""

    elif cmd == "subnet":
        help_text = """\
###  subnet <list|set> [args]
    Manages botnet subnets.
    subnet list               - lists all configured subnets
    subnet set <name> <key> <value>  - updates a subnet field (hub_host, hub_port, name)

See also: bots, link
"""

    elif cmd == "net":
        help_text = """\
###  net <subcmd> [args]
    Executes a command at the botnet level (broadcasts to all linked bots and runs locally).
    Valid subcommands: op deop say msg join part mode restart die

See also: relay, mass
"""

    elif cmd == "mass":
        help_text = """\
###  mass <op|deop> <#channel>
    Mass ops or deops all users in a channel.

See also: op, deop, net
"""

    elif cmd == "+ignore":
        help_text = """\
###  +ignore <hostmask> [%<duration>] [comment]
    Adds a hostmask to the ignore list.
    Example: .+ignore *!spammer@*.isp.net %1h Spammer

See also: -ignore, ignores
"""

    elif cmd == "-ignore":
        help_text = """\
###  -ignore <hostmask>
    Removes a hostmask from the ignore list.

See also: +ignore, ignores
"""

    elif cmd == "ignores":
        help_text = """\
###  ignores
    Lists all entries in the ignore list.

See also: +ignore, -ignore
"""

    elif cmd == "denyhost":
        help_text = """\
###  denyhost <ip|hostname> [duration_minutes] [reason]
    Blocks an IP from connecting to the party line.
    Duration 0 or omitted = permanent block.
    Example: .denyhost 1.2.3.4 60 Spammer

See also: permithost, blocklist
"""

    elif cmd == "permithost":
        help_text = """\
###  permithost <ip>
    Removes an IP from the party line blocklist.

See also: denyhost, blocklist
"""

    elif cmd == "blocklist":
        help_text = """\
###  blocklist
    Shows all current party line IP block entries.

See also: denyhost, permithost
"""

    elif cmd == "plugins":
        help_text = """\
###  plugins
    Lists loaded plugins, auto-load plugins, and all available plugins on disk.

See also: load, unload
"""

    elif cmd == "load":
        help_text = """\
###  load <plugin>
    Loads a plugin from src/plugins/.

See also: unload, plugins
"""

    elif cmd == "unload":
        help_text = """\
###  unload <plugin>
    Unloads a currently loaded plugin.

See also: load, plugins
"""

    elif cmd == "games":
        help_text = """\
###  games
    Lists loaded games, auto-load games, and all available games on disk.

See also: gload, gunload, gstart
"""

    elif cmd == "gload":
        help_text = """\
###  gload <game>
    Loads a game from src/games/.

See also: gunload, games, gstart
"""

    elif cmd == "gunload":
        help_text = """\
###  gunload <game>
    Unloads a currently loaded game.

See also: gload, games
"""

    elif cmd == "gstart":
        help_text = """\
###  gstart <game> <scope> <target> [key=value ...]
    Starts a game session in a given scope and target.
    Example: .gstart duckhunt channel #wbs min_delay=15 max_delay=45

See also: gstop, gsessions, gload
"""

    elif cmd == "gstop":
        help_text = """\
###  gstop <game> <scope> <target>
    Stops an active game session.
    Example: .gstop duckhunt channel #wbs

See also: gstart, gsessions
"""

    elif cmd == "gsessions":
        help_text = """\
###  gsessions
    Lists all active game sessions with state, player count, and owner.

See also: gstart, gstop
"""

    elif cmd == "sdns":
        help_text = """\
###  sdns <host|ip>
    Resolves a hostname or IP using the bot's local DNS resolver.
"""

    elif cmd == "swhois":
        help_text = """\
###  swhois <nick>
    Sends a WHOIS request to the IRC server.

See also: swhowas
"""

    elif cmd == "swhowas":
        help_text = """\
###  swhowas <nick>
    Sends a WHOWAS request to the IRC server.

See also: swhois
"""

    elif cmd == "links":
        help_text = """\
###  links
    Requests the LINKS list from the IRC server (all linked servers).
"""

    elif cmd == "taskset":
        help_text = """\
###  taskset <task_name> <0|1>
    Enables (1) or disables (0) a named task in the core task scheduler.

See also: tasks, timers
"""

    elif cmd == "tasks":
        help_text = """\
###  tasks
    Lists all registered tasks with their enabled state and interval.

See also: taskset, timers
"""

    elif cmd == "timers":
        help_text = """\
###  timers
    Lists all active IRC timers registered in the IRC process.

See also: tasks, taskset
"""

    elif cmd == "checkupdate":
        help_text = """\
###  checkupdate
    Checks GitHub for a new WBS version without installing anything.

See also: update
"""

    elif cmd == "update":
        help_text = """\
###  update
    Downloads and installs the latest WBS version. Restart required after.

See also: checkupdate
"""

    else:
        help_text = f"""\
ERROR: Unknown command: {cmd}
"""

    for line in help_text.split('\n'):
        await respond(line)

async def cmd_version(core, handle: str, session_id: int, arg: str, respond):
    await respond(f"WBS {__version__}")

async def cmd_date(core, handle: str, session_id: int, arg: str, respond):
    await respond(f"Current time is: {datetime.now().ctime()}")

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
    """Set channel modes. Requires +o on that channel."""
    if core.config.get("limbo_hub"):
        return await respond("Cannot use MODE as limbo hub.")
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        return await respond("Usage: .mode <#channel> <modes>")
    chan, modes = parts
    if not await _require_flag(core, handle, "+o", respond):
        return
    core.irc_q.put_nowait({"cmd": "mode", "channel": chan, "modes": modes})
    await respond(f"Mode set: {chan} {modes}")

async def cmd_op(core, handle, session_id, arg, respond):
    await _chan_mode_cmd(core, handle, arg, respond, "+o", "op", "Gave op to")

async def cmd_deop(core, handle, session_id, arg, respond):
    await _chan_mode_cmd(core, handle, arg, respond, "-o", "deop", "Took op from")

async def cmd_voice(core, handle, session_id, arg, respond):
    await _chan_mode_cmd(core, handle, arg, respond, "+v", "voice", "Gave voice to")

async def cmd_devoice(core, handle, session_id, arg, respond):
    await _chan_mode_cmd(core, handle, arg, respond, "-v", "devoice", "Took voice from")

async def cmd_channels(core, handle: str, session_id: int, arg: str, respond):
    """
    .channels — list all active channels with settings and optional IRC live state.

    DB columns used: name, modes, is_inactive, is_autoop, is_autovoice,
                     is_bitch, is_enforcebans, comment
    Live IRC state (if connected): users, ops, voices from core.irc_snapshot
    """
    async with get_db(core.db_path) as db:
        cursor = await db.execute("""
            SELECT
                c.name,
                c.modes,
                c.is_autoop,
                c.is_autovoice,
                c.is_bitch,
                c.is_enforcebans,
                c.comment
            FROM channels c
            WHERE c.deleted_at IS NULL
              AND c.is_inactive = 0
            ORDER BY c.name
        """)
        rows = await cursor.fetchall()

    if not rows:
        await respond("No channels configured.")
        return

    await respond(" ---- List of Channels ----")

    # irc_snapshot is a dict keyed by channel name, populated by irc.py
    # Structure: { '#chan': { 'user_list': [...], 'ops': [...], 'voices': [...] } }
    snapshot: dict = getattr(core, "irc_snapshot", {})
    connected: bool = getattr(core, "connected", False)

    total = 0
    for row in rows:
        chan    = row["name"]
        modes   = row["modes"] or ""
        comment = row["comment"] or ""

        # Channel flags summary
        flags = []
        if row["is_bitch"]:      flags.append("bitch")
        if row["is_autoop"]:     flags.append("autoop")
        if row["is_autovoice"]:  flags.append("autovoice")
        if row["is_enforcebans"]:flags.append("enforcebans")
        flag_str = f" [{', '.join(flags)}]" if flags else ""

        # Live IRC state
        if connected and chan in snapshot:
            chan_snap  = snapshot[chan]
            user_list  = chan_snap.get("user_list", [])
            ops        = chan_snap.get("ops", [])
            voices     = chan_snap.get("voices", [])
            live_str   = (
                f" | users:{len(user_list)}"
                f" ops:{len(ops)}"
                f" voice:{len(voices)}"
            )
            mode_str = modes or "+n"
        elif connected:
            live_str = " | (not joined)"
            mode_str = modes or "+n"
        else:
            live_str = ""
            mode_str = modes or "+n"

        comment_str = f"  # {comment}" if comment else ""
        await respond(f"--> {chan} ({mode_str}){flag_str}{live_str}{comment_str}")
        total += 1

    await respond(f"TOTAL CHANNELS: {total}")

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

async def cmd_bots(core, handle: str, session_id: int, arg: str, respond) -> None:
    """
    .bots — List all known bots: self, linked (with roles), unlinked, and
    indirect (topology-aware bots known via relay but not in the DB).
    Mirrors WBS5 dwckbots layout.
    """
    my_name = core.botname
    async with get_db(core.db_path) as db:
        rows = await db.execute_fetchall(
            "SELECT handle, role FROM bots WHERE deleted_at IS NULL ORDER BY handle"
        )

    linked_names: set[str] = set(core.botnet.peers.keys()) if hasattr(core, "botnet") else set()

    def role_tag(role: str | None) -> str:
        r = (role or "").lower()
        if r == "hub":  return " (hub)"
        if r == "leaf": return " (leaf)"
        return ""

    linked_count   = 1  # self counts as linked
    unlinked_count = 0

    await respond("  ---- List of Bots ----")
    await respond(" ---Linked:---")
    await respond(f"-> {my_name} (me!)")
    for row in rows:
        bname = row["handle"]
        if bname.lower() == my_name.lower():
            continue
        if bname in linked_names:
            await respond(f"-> {bname}{role_tag(row['role'])}")
            linked_count += 1

    indirect: dict[str, str] = {}
    if hasattr(core, "botnet") and hasattr(core.botnet, "topology"):
        known_handles = {row["handle"].lower() for row in rows}
        known_handles.add(my_name.lower())
        for bname, via in core.botnet.topology.items():
            if bname.lower() not in known_handles:
                indirect[bname] = via

    if indirect:
        #await respond(" ---Indirect (via relay):---")
        for bname, via in sorted(indirect.items()):
            await respond(f"-> {bname} (via {via})")

    await respond(" ---Unlinked:---")
    unlinked_lines = []
    for row in rows:
        bname = row["handle"]
        if bname.lower() == my_name.lower():
            continue
        if bname not in linked_names:
            unlinked_lines.append(f"-> {bname}{role_tag(row['role'])}")
            unlinked_count += 1

    if unlinked_lines:
        for line in unlinked_lines:
            await respond(line)
    else:
        await respond("-> (none)")

    indirect_count = len(indirect)
    total = linked_count + unlinked_count + indirect_count
    total_linked = linked_count + indirect_count
    parts = [f"Linked: {total_linked}", f"Unlinked: {unlinked_count}"]
    #if indirect_count:
    #    parts.append(f"Indirect: {indirect_count}")
    parts.append(f"-- TOTAL BOTS: {total}")
    await respond("  ".join(parts))

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

    subnet_id, ok = await _resolve_subnet_arg(core, subnet_arg, respond)
    if not ok:
        return

    try:
        await core.chan.addchan(channel, subnet_id=subnet_id, created_by=handle)
        core.irc_q.put_nowait({'cmd': 'join', 'channel': channel})
        subnet_label = subnet_arg or f"subnet {subnet_id}"
        await respond(f"→ Channel {channel} added (scope: {subnet_label})!")
        _botnet_sync(core, "sync_channel", "ADD", {"name": channel, "subnet_id": subnet_id})
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
        _botnet_sync(core, "sync_channel", "DEL", {"name": channel})
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
    hostmask   = parts[1] if len(parts) > 1 else None
    subnet_arg = parts[2] if len(parts) > 2 else None

    subnet_id, ok = await _resolve_subnet_arg(core, subnet_arg, respond)
    if not ok:
        return

    if await core.user.adduser(new_handle, hostmask, subnet_id=subnet_id, created_by=handle):
        scope = subnet_arg or f"subnet {subnet_id}"
        await respond(f"→ User {new_handle} added (scope: {scope})!")
        _botnet_sync(core, "sync_user", "ADD", {"handle": new_handle, "hostmask": hostmask, "subnet_id": subnet_id})
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
        _botnet_sync(core, "sync_user", "DEL", {"handle": parts[0]})
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
    password = None 

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
        _botnet_sync(core, "sync_bot", "ADD", {"handle": bot, "hostmask": hostmask, "address": address, "port": port})
    else:
        await respond(f"→ Bot {bot} NOT added!")

async def cmd_delbot(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .-bot <bot>")
        return
    parts = arg.split()
    if await core.bot.delbot(parts[0]):
        await respond(f"→ Bot {parts[0]} deleted!")
        _botnet_sync(core, "sync_bot", "DEL", {"handle": parts[0]})
    else:
        await respond(f"→ Bot {parts[0]} NOT deleted!")

async def cmd_botinfo(core, handle: str, session_id: int, arg: str, respond):
    pid = os.getpid()
    cwd = os.getcwd()
    machine = platform.machine()
    os_name = platform.system()
    os_ver = platform.platform()
    py_ver = platform.python_version()
    await respond("-> Bot Info <-")
    await respond(f"-> Pid #: {pid}")
    await respond(f"-> Runs in: {cwd}")
    await respond(f"-> Botnet nick: {core.botname}")
    await respond(f"-> Machine: {machine}")
    await respond(f"> Oper. System: {os_name} {os_ver}")
    await respond(f"> Python Ver.: {py_ver}")

async def cmd_link(core, handle: str, session_id: int, arg: str, respond):
    if not await _require_flag(core, handle, "+n", respond):
        return
    if not arg:
        await respond("Usage: .link <bot>")
        return
    botname = arg.split()[0]
    try:
        bot = await core.bot.get(botname)
        if not bot.address:
            await respond(f"Please set address on {botname} first (.chaddr).")
            return
        if not bot.port:
            await respond(f"Please set port on {botname} first (.chaddr).")
            return
        await respond(f"Initiating link to {botname}...")
        await core.botnet.connect_peer(botname)
    except ValueError as e:
        log.debug("link cmd failed for %s: %s", botname, e)
        await respond(f"Bot {botname} not found!")

async def cmd_unlink(core, handle: str, session_id: int, arg: str, respond):
    if not await _require_flag(core, handle, "+n", respond):
        return
    if not arg:
        await respond("Usage: .unlink <bot>")
        return
    botname = arg.strip()
    if botname not in core.botnet.peers:
        await respond(f"Not linked to {botname}.")
        return
    link = core.botnet.peers[botname]
    await respond(f"Unlinking from {botname}...")
    try:
        if link.writer:
            link.writer.close()
            await link.writer.wait_closed()
        # Use botnet method if available to avoid concurrent dict mutation
        if hasattr(core.botnet, "remove_peer"):
            core.botnet.remove_peer(botname)
        else:
            core.botnet.peers.pop(botname, None)
        link.connected = False
        await respond(f"Unlinked from {botname} ({link.host}:{link.port}).")
    except Exception as e:
        await respond(f"Unlink failed: {e}")

async def cmd_listusers(core, handle: str, session_id: int, arg: str, respond):
    #if not arg:
    #    await respond("Usage: .listusers")
    #    return
    #parts = arg.split()
    await respond(await core.user.listusers())                

async def cmd_chusercomment(core, handle: str, session_id: int, arg: str, respond) -> None:
    """Set a comment on a user record. Requires +A."""
    if not await _require_flag(core, handle, "A", respond):
        return
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        await respond("Usage: .chusercomment <user> <comment>")
        return
    target, comment = parts[0], parts[1]
    result = await core.user.set_comment(target, comment, updated_by=handle)
    if result == "not_found":
        await respond(f"No such user: {target}")
    else:
        await respond(f"Comment updated for {target}.")
        if hasattr(core, "botnet"):
            asyncio.create_task(core.botnet.sync_user("UPDATE", {"handle": target}))

async def cmd_addaccess(core, handle: str, session_id: int, arg: str, respond) -> None:
    """
    Add flags to a user's access row.
    Usage: .addaccess <user> +<flags> [#channel]

    Examples:
        .addaccess bob +Ap           (global admin + partyline)
        .addaccess bob +o #wbs       (channel op on #wbs)
    """
    if not await _require_flag(core, handle, "A", respond):
        return
    parts = arg.split()
    if len(parts) < 2:
        await respond("Usage: .addaccess <user> +<flags> [#channel]")
        return

    target   = parts[0]
    flag_str = parts[1]
    channel  = parts[2] if len(parts) >= 3 and parts[2].startswith("#") else None

    # Normalise: addaccess always means "+", strip any leading sign
    flag_str = "+" + flag_str.lstrip("+-")

    result = await core.user.chattr(target, flag_str, channel=channel, updated_by=handle)
    if result == "not_found":
        await respond(f"No such user: {target}")
    elif result == "bad_flag":
        await respond(f"Unknown flag in: {flag_str}")
    elif result == "no_access":
        await respond(f"No access row found for {target} on {channel or 'global'}. "
                      f"Use .+user to create the user first.")
    else:
        scope = f" on {channel}" if channel else " (global)"
        await respond(f"Added {flag_str} to {target}{scope}.")
        if hasattr(core, "botnet"):
            asyncio.create_task(core.botnet.sync_user("UPDATE", {"handle": target}))

async def cmd_delaccess(core, handle: str, session_id: int, arg: str, respond) -> None:
    """
    Remove flags from a user's access row.
    Usage: .delaccess <user> -<flags> [#channel]

    Examples:
        .delaccess bob -A            (remove global admin)
        .delaccess bob -o #wbs       (remove channel op on #wbs)
    """
    if not await _require_flag(core, handle, "A", respond):
        return
    parts = arg.split()
    if len(parts) < 2:
        await respond("Usage: .delaccess <user> -<flags> [#channel]")
        return

    target   = parts[0]
    flag_str = parts[1]
    channel  = parts[2] if len(parts) >= 3 and parts[2].startswith("#") else None

    # Normalise: delaccess always means "-"
    flag_str = "-" + flag_str.lstrip("+-")

    result = await core.user.chattr(target, flag_str, channel=channel, updated_by=handle)
    if result == "not_found":
        await respond(f"No such user: {target}")
    elif result == "bad_flag":
        await respond(f"Unknown flag in: {flag_str}")
    elif result == "no_access":
        await respond(f"No access row found for {target} on {channel or 'global'}.")
    else:
        scope = f" on {channel}" if channel else " (global)"
        await respond(f"Removed {flag_str} from {target}{scope}.")
        if hasattr(core, "botnet"):
            asyncio.create_task(core.botnet.sync_user("UPDATE", {"handle": target}))

async def cmd_lockuser(core, handle: str, session_id: int, arg: str, respond) -> None:
    """
    Lock a user account, preventing login.
    Usage: .lockuser <user>
    Requires +A.
    """
    if not await _require_flag(core, handle, "A", respond):
        return
    parts = arg.split()
    if not parts:
        await respond("Usage: .lockuser <user>")
        return
    target = parts[0]
    # Prevent self-lock — admins should not be able to lock themselves out
    if target.lower() == handle.lower():
        await respond("You cannot lock your own account.")
        return
    result = await core.user.set_locked(target, locked=True, updated_by=handle)
    if result == "not_found":
        await respond(f"No such user: {target}")
    elif result == "no_change":
        await respond(f"{target} is already locked.")
    else:
        await respond(f"{target} has been locked.")
        log.info("cmd_lockuser: %s locked by %s", target, handle)
        if hasattr(core, "botnet"):
            asyncio.create_task(core.botnet.sync_user("UPDATE", {"handle": target}))

async def cmd_unlockuser(core, handle: str, session_id: int, arg: str, respond) -> None:
    """
    Unlock a previously locked user account.
    Usage: .unlockuser <user>
    Requires +A.
    """
    if not await _require_flag(core, handle, "A", respond):
        return
    parts = arg.split()
    if not parts:
        await respond("Usage: .unlockuser <user>")
        return
    target = parts[0]
    result = await core.user.set_locked(target, locked=False, updated_by=handle)
    if result == "not_found":
        await respond(f"No such user: {target}")
    elif result == "no_change":
        await respond(f"{target} is not locked.")
    else:
        await respond(f"{target} has been unlocked.")
        log.info("cmd_unlockuser: %s unlocked by %s", target, handle)
        if hasattr(core, "botnet"):
            asyncio.create_task(core.botnet.sync_user("UPDATE", {"handle": target}))

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
    bot_sessions = getattr(core, 'bot_sessions', {})
    if bot_sessions:
        for idx, (bot_id, bot_session) in enumerate(bot_sessions.items()):
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
    new_handle = arg.strip()
    if not _HANDLE_RE.match(new_handle):
        await respond("Invalid handle. Use only letters, digits, and IRC-safe characters (max 20).")
        return
    # Update own session
    if session_id in core.partyline.sessions:
        core.partyline.sessions[session_id]['handle'] = new_handle
        await core.user.change_handle(handle, new_handle)
        await respond(f"Your handle is now: {new_handle}")
    else:
        await respond("Your handle was not changed.")
    
async def cmd_chhandle(core, handle: str, session_id: int, arg: str, respond):
    if not arg or len(arg.split()) != 2:
        await respond("Usage: .chhandle <oldhandle> <newhandle>")
        return
    
    old_handle, new_handle = arg.split()
    old_handle = old_handle.strip()
    new_handle = new_handle.strip()
    if not _HANDLE_RE.match(new_handle):
        await respond("Invalid handle. Use only letters, digits, and IRC-safe characters (max 20).")
        return
    
    for sid, sess in core.partyline.sessions.items():
        if sess['handle'].lower() == old_handle.lower():
            sess['handle'] = new_handle
            break
    if await core.user.exist(old_handle):
        if await core.user.exist(new_handle):
            await respond(f"User already exist: {new_handle}")
        else:
            core.user.change_handle(old_handle, new_handle)
            await respond(f"User handle changed: {old_handle} → {new_handle}")
    else:
        await respond(f"User not found: {old_handle}")

async def cmd_addhost(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .+host <hostmask>")
        return
    await _modify_hostmask(core, handle, arg.strip(), add=True, respond=respond)

async def cmd_delhost(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .-host <hostmask>")
        return
    await _modify_hostmask(core, handle, arg.strip(), add=False, respond=respond)
     
async def cmd_status(core, handle: str, session_id: int, arg: str, respond):
    uptime = time.time() - core.start_time
    days = int(uptime // 86400)
    hours = int((uptime % 86400) // 3600)
    
    # RSS memory in KB (stdlib resource)
    mem_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    users = len(core.partyline.sessions)
    channels = await core.chan.getchans()
    
    await respond(f"I am {core.botname}, running WBS {__version__}: {users} users (mem: {mem_kb:.0f}k).")
    await respond(f"Online for {days} days, {hours:02d}:{int((uptime%3600)//60):02d} "
                  f"(background) - CPU: --:--.-- - Cache hit: --%")
    await respond(f"Config file: {core.config_path}")
    await respond(f"OS: {platform.system()} {platform.release()}")
    await respond(f"Process ID: {os.getpid()}")
    #await respond(f"Online as: [{core.botname}!{core.irc_user}@auto.bots]")
    #await respond(f"Connected to {core.server_host}:{core.server_port}")
    await respond(f"Active channels: {', '.join(channels) if channels else 'none'}")

async def cmd_backup(core, handle: str, session_id: int, arg: str, respond):
    if not await _require_flag(core, handle, "+A", respond):
        return
    await respond("Backing up the channel & user files...")
    db_path = core.db_path
    config_path = core.config_path
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    await respond("Backing up database...")
    db_backup = f"{db_path}.{ts}.bak"
    shutil.copy2(db_path, db_backup)
    await respond(f"Database backed up to {os.path.basename(db_backup)}")

    await respond("Backing up config...")
    config_backup = f"{config_path}.{ts}.bak"
    shutil.copy2(config_path, config_backup)
    await respond(f"Config backed up to {os.path.basename(config_backup)}")

    await respond("Backup complete.")

async def cmd_ignores(core, handle: str, session_id: int, arg: str, respond):
    async with get_db(core.db_path) as db:
        cursor = await db.execute("SELECT hostmask, flags, comment FROM ignores ORDER BY hostmask")
        rows = await cursor.fetchall()
        count = len(rows)
        for row in rows:
            count += 1
            flags = row['flags'] if row['flags'] else ''
            comment = row['comment'] or ''
            await respond(f"{row['hostmask']} {flags}%{comment}")
        if count == 0:
            await respond("No ignores.")
        else:
            await respond(f"Total ignores: {count}")    

async def cmd_addignore(core, handle: str, session_id: int, arg: str, respond):
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

async def cmd_delignore(core, handle: str, session_id: int, arg: str, respond):
    parts = arg.split(maxsplit=2)
    if len(parts) < 1:
        await respond("Usage: -ignore <hostmask>")
        return
    hostmask = parts[0].strip()
    async with get_db(core.db_path) as db:
        result = await db.execute("DELETE FROM ignores WHERE hostmask = ?", (hostmask,))
        if result.rowcount:
            await respond(f"No longer ignoring {hostmask}")
        else:
            await respond(f"Not ignoring {hostmask}")

async def cmd_chaddr(core, handle: str, session_id: int, arg: str, respond):
    if not await _require_flag(core, handle, "+n", respond):
        return
    parts = arg.split()
    if len(parts) < 3:
        await respond("Usage: .chaddr <bot> <address> <port>")
        return
    botname = parts[0]
    address = parts[1]
    try:
        port = int(parts[2])
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        await respond("Invalid port. Must be 1–65535.")
        return

    async with get_db(core.db_path) as db:
        cursor = await db.execute("SELECT handle FROM bots WHERE handle = ?", (botname,))
        row = await cursor.fetchone()
        if not row:
            await respond(f"Bot {botname} not found!")
            return
        await db.execute(
            "UPDATE bots SET address = ?, port = ? WHERE handle = ?",
            (address, port, botname),
        )
        await db.commit()
    await respond(f"Updated {botname}: {address}:{port}")    

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

    invalid = set(updates) - _CHATTR_ALLOWED_COLUMNS
    if invalid:
        log.error("cmd_chattr: rejected unexpected columns: %s", sorted(invalid))
        await respond("Internal error: invalid attribute mapping.")
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
    if hasattr(core, 'botnet'):
        # Fetch current flags + hosts to broadcast complete state
        user = await core.user.get(target)
        if user:
            asyncio.create_task(core.botnet.sync_user_access({
                "handle": target,
                "flags": flags,
                "channel": channel,
                "hosts": getattr(user, "hostmasks", []),
            }))

async def cmd_relay(core, handle: str, session_id: int, arg: str, respond):
    """
    .relay <botnick>          — open a persistent relay session to another bot.
    .relay <botnick> <cmd>    — run a single command on a remote bot.
    .relay                    — disconnect from current relay.
    """
    parts = arg.strip().split(maxsplit=1)

    # .relay with no args — disconnect from current relay
    if not parts:
        relay = core.partyline.relay_sessions.get(session_id)
        if relay:
            del core.partyline.relay_sessions[session_id]
            # Notify the remote bot to close its side
            if relay.target in core.botnet.peers:
                await core.botnet.send_to_peer(relay.target, {
                    'type': 'RELAY_CLOSE',
                    'from': relay.handle,
                    'session_id': session_id,
                    'origin': relay.origin
                })
            await respond(f"Disconnected from relay: {relay.target}")
        else:
            await respond("Not currently relayed to any bot.")
        return

    botnick = parts[0]
    remote_cmd = parts[1] if len(parts) > 1 else None

    if botnick not in core.botnet.peers:
        await respond(f"Bot {botnick} is not linked. Use .link first.")
        return

    if remote_cmd:
        # One-shot: send a single command to the remote bot
        await core.botnet.send_to_peer(botnick, {
            'type': 'PARTYLINE_CMD',
            'from': handle,
            'session_id': session_id,
            'cmd': remote_cmd,
            'reply_to': core.botname
        })
        await respond(f"→ [{botnick}] {remote_cmd}")
    else:
        # Persistent relay — use open_relay() from partyline
        existing = core.partyline.relay_sessions.get(session_id)
        if existing:
            if existing.target == botnick:
                await respond(f"Already relayed to {botnick}.")
                return
            # Close the existing relay cleanly before opening a new one
            if existing.target in core.botnet.peers:
                await core.botnet.send_to_peer(existing.target, {
                    'type': 'RELAY_CLOSE',
                    'from': existing.handle,
                    'session_id': session_id,
                    'origin': existing.origin
                })
            del core.partyline.relay_sessions[session_id]

        opened = core.partyline.open_relay(session_id, botnick)
        if opened:
            await respond(f"Relayed to {botnick}. All input forwarded. Type '.relay' alone to disconnect.")
        else:
            await respond(f"Failed to open relay to {botnick}.")

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
    elif action == 'deop':
        targets = [u for u in users if u != botname and u in ops]
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
    parts = arg.split(maxsplit=1)
    subcmd = parts[0].lower() if parts else ''
    rest   = parts[1] if len(parts) > 1 else ''

    if not subcmd or subcmd == 'help':
        await respond("Usage: .net <subcmd> [args]")
        await respond("Subcommands:")
        await respond("  op      <nick> <#chan>    - Give op on all linked bots")
        await respond("  deop    <nick> <#chan>    - Remove op on all linked bots")
        await respond("  say     <#chan> <msg>     - Say to channel on all bots")
        await respond("  msg     <nick|#chan> <msg>- MSG to target on all bots")
        await respond("  join    <#chan>           - Join channel on all bots")
        await respond("  part    <#chan>           - Part channel on all bots")
        await respond("  mode    <#chan> <modes>   - Set modes on all bots")
        await respond("  restart                  - Restart all linked bots")
        await respond("  die                      - Shutdown all linked bots")
        return

    # Broadcast to all linked peers via botnet
    if hasattr(core, 'botnet') and core.botnet.peers:
        await core.botnet.broadcast_all(subcmd, rest)

    # Also execute locally
    local_cmds = {
        'op':      cmd_op,
        'deop':    cmd_deop,
        'say':     cmd_msg,
        'msg':     cmd_msg,
        'join':    cmd_addchan,
        'part':    cmd_delchan,
        'mode':    cmd_mode,
        'restart': cmd_restart,
        'die':     cmd_quit,
    }
    if subcmd in local_cmds:
        await local_cmds[subcmd](core, handle, session_id, rest, respond)
    else:
        await respond(f"Unknown net subcmd: {subcmd}  (try .net help)")

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
        _SUBNET_KEY_MAP: dict[str, str] = {
            'hub_host': 'hub_host',
            'hub_port': 'hub_port',
            'name':     'name',
        }
        col = _SUBNET_KEY_MAP.get(key.lower())
        if col is None:
            await respond(f"Allowed keys: {', '.join(_SUBNET_KEY_MAP)}")
            return
        async with get_db(core.db_path) as db:
            await db.execute(f"UPDATE subnets SET {col} = ? WHERE name = ?", (value, name))
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
    await respond("To add this bot as a leaf on another hub, run:")
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

async def cmd_checkupdate(core, handle: str, session_id: int, arg: str, respond):
    """`.checkupdate` — check for a new WBS version."""
    manifest = await core.update.check_update()
    if manifest:
        await respond(f"Update available: {manifest.version_str} by {manifest.author}")
    else:
        await respond("Already up to date.")
    return

async def cmd_update(core, handle: str, session_id: int, arg: str, respond):
    """`.update` — download and install the latest version."""
    manifest = await core.update.check_update()
    if not manifest:
        await respond("No update available.")
        return
    await respond(f"Installing {manifest.version_str}…")
    ok = await core.update.perform_update(manifest)
    if ok:
        await respond("Update installed. Restart the bot to load new code.")
    else:
        await respond("Update failed — rolled back to previous version. Check logs.")
    return

async def cmd_denyhost(core, session_id, args, respond):
    """
    .denyhost <ip|hostname> [duration_minutes] [reason]
    Block an IP from connecting to the partyline.
    Duration 0 or omitted = permanent.
    Requires: master flag (n)
    """
    parts = args.split(None, 2)
    if not parts:
        await respond("Usage: .denyhost <ip> [minutes] [reason]")
        return

    ip = parts[0]
    minutes = 0
    note = ""
    if len(parts) >= 2:
        try:
            minutes = int(parts[1])
        except ValueError:
            note = parts[1]
    if len(parts) == 3:
        note = parts[2]

    expires = int(time.time()) + minutes * 60 if minutes > 0 else 0
    caller = core.partyline.sessions[session_id].handle

    await core.guard.block(
        ip=ip, reason="manual", created_by=caller,
        expires_at=expires, note=note
    )
    duration_str = f"for {minutes}m" if minutes > 0 else "permanently"
    await respond(f"Blocked {ip} {duration_str}.")

async def cmd_permithost(core, session_id, args, respond):
    """
    .permithost <ip>
    Remove an IP from the blocklist.
    Requires: master flag (n)
    """
    ip = args.strip()
    if not ip:
        await respond("Usage: .permithost <ip>")
        return

    caller = core.partyline.sessions[session_id].handle
    removed = await core.guard.unblock(ip, removed_by=caller)
    if removed:
        await respond(f"Unblocked {ip}.")
    else:
        await respond(f"{ip} was not in the blocklist.")

async def cmd_blocklist(core, session_id, args, respond):
    """
    .blocklist
    Show all current blocklist entries.
    Requires: master flag (n)
    """
    entries = core.guard.list_blocked()
    if not entries:
        await respond("Blocklist is empty.")
        return

    await respond(f"{'IP':<18} {'Reason':<14} {'By':<12} {'Expires':<20} Note")
    await respond("-" * 72)
    for e in sorted(entries, key=lambda x: x.added_at):
        exp = (datetime.datetime.fromtimestamp(e.expires_at).strftime("%Y-%m-%d %H:%M")
               if e.expires_at else "never")
        await respond(f"{e.ip:<18} {e.reason:<14} {e.created_by:<12} {exp:<20} {e.note}")

async def cmd_botattr(core, handle: str, session_id: int, arg: str, respond):
    """
    .botattr <bothandle> [+/-<flags>] [key=value ...]

    Flags:
      +/-a  autolink          (auto-connect on startup/retry loop)
      +/-h  role=hub
      +/-b  role=backup
      +/-l  role=leaf
      +/-n  role=none

    Key=value pairs (no flag prefix):
      retry=<seconds>         autolink_retry_interval (15–600)
      share=full|subnet|none  share_level
      pass=<password>         bot password
      comment=<text>          comment field

    .botattr <bothandle>      (no flags) → show current attrs
    """
    parts = arg.split()
    if not parts:
        await respond("Usage: .botattr <bothandle> [+/-flags] [key=value ...]")
        return

    target = parts[0]
    tokens = parts[1:]

    # Verify bot exists
    async with get_db(core.db_path) as db:
        cursor = await db.execute("SELECT * FROM bots WHERE handle = ? AND deleted_at IS NULL", (target,))
        row = await cursor.fetchone()
    if not row:
        await respond(f"Bot not found: {target}")
        return

    # No further args → display current attrs
    if not tokens:
        role   = row["role"] or "none"
        share  = row["share_level"] or "subnet"
        al     = "yes" if row["autolink"] else "no"
        retry  = row["autolink_retry_interval"] or 60
        addr   = f"{row['address']}:{row['port']}"
        flags  = ""
        if row["autolink"]:        flags += "a"
        if role == "hub":          flags += "h"
        elif role == "backup":     flags += "b"
        elif role == "leaf":       flags += "l"
        await respond(f"Bot {target}: flags=[{flags or 'none'}] role={role} "
                      f"share={share} autolink={al} retry={retry}s addr={addr}")
        return

    # ---- Parse tokens ----
    flag_updates: dict[str, object] = {}
    kv_updates:   dict[str, object] = {}

    VALID_SHARE  = {"full", "subnet", "none"}
    VALID_ROLES  = {"hub", "backup", "leaf", "none"}

    for token in tokens:
        if token[0] in ("+", "-") and len(token) > 1:
            adding = token[0] == "+"
            for ch in token[1:].lower():
                if ch == "a":
                    flag_updates["autolink"] = 1 if adding else 0
                elif ch == "h":
                    if adding: flag_updates["role"] = "hub"
                elif ch == "b":
                    if adding: flag_updates["role"] = "backup"
                elif ch == "l":
                    if adding: flag_updates["role"] = "leaf"
                elif ch == "n":
                    if adding: flag_updates["role"] = "none"
                else:
                    await respond(f"Unknown flag: {ch!r}  (valid: a h b l n)")
                    return
        elif "=" in token:
            k, v = token.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "retry":
                try:
                    secs = int(v)
                    if not (15 <= secs <= 600):
                        await respond("retry must be 15–600 seconds")
                        return
                    kv_updates["autolink_retry_interval"] = secs
                except ValueError:
                    await respond(f"retry= requires an integer, got: {v!r}")
                    return
            elif k == "share":
                if v not in VALID_SHARE:
                    await respond(f"share= must be one of: {', '.join(VALID_SHARE)}")
                    return
                kv_updates["share_level"] = v
            elif k == "pass":
                if len(v) < 8:
                    await respond("Bot password must be at least 8 characters.")
                    return
                kv_updates["password"] = v   # stored plain for botnet auth; hash if desired
            elif k == "comment":
                kv_updates["comment"] = v
            elif k == "role":
                if v not in VALID_ROLES:
                    await respond(f"role= must be one of: {', '.join(VALID_ROLES)}")
                    return
                kv_updates["role"] = v
            else:
                await respond(f"Unknown key: {k!r}  (valid: retry share pass comment role)")
                return
        else:
            await respond(f"Unrecognised token: {token!r}  (use +/-flags or key=value)")
            return

    all_updates = {**flag_updates, **kv_updates}
    if not all_updates:
        await respond("No changes specified.")
        return

    invalid = set(all_updates) - _BOTATTR_ALLOWED_COLUMNS
    if invalid:
        log.error("cmd_botattr: rejected unexpected columns: %s", sorted(invalid))
        await respond("Internal error: invalid bot attribute mapping.")
        return

    set_clause = ", ".join(f"{col} = ?" for col in all_updates)
    values = list(all_updates.values())

    async with get_db(core.db_path) as db:
        await db.execute(
            f"UPDATE bots SET {set_clause}, updated_at = strftime('%s','now'), "
            f"updated_by = ? WHERE handle = ? AND deleted_at IS NULL",
            values + [handle, target]
        )
        await db.commit()

    changes = "  ".join(f"{k}={v}" for k, v in all_updates.items())
    await respond(f"botattr {target}: {changes}")
    log.info("botattr: %s updated %s → %s", handle, target, all_updates)
    if hasattr(core, 'botnet'):
        asyncio.create_task(core.botnet.sync_bot_access({
            "handle": target,
            "flags": {**flag_updates, **kv_updates},
        }))

async def cmd_restart(core, handle: str, session_id: int, arg: str, respond) -> None:
    """Full restart: Core exits, supervisor relaunches. Requires '+A' (admin) flag."""
    async with get_db(core.db_path) as db:
        cursor = await db.execute(
            """SELECT EXISTS(
                   SELECT 1 FROM user_access
                   WHERE handle = ? AND channel IS NULL
                   AND is_admin = 1 AND deleted_at IS NULL
               ) AS has_access""",
            (handle,)
        )
        row = await cursor.fetchone()

    if not row or not row['has_access']:
        await respond("Access denied. Requires '+A' flag.")
        return

    await respond("Restarting...")
    log.info("Restart initiated by %s", handle)
    await core.do_restart()

async def cmd_rehash(core, handle: str, session_id: int, arg: str, respond) -> None:
    """Rehash: restart Core process, IRC stays connected. Requires '+A' (admin) flag."""
    async with get_db(core.db_path) as db:
        cursor = await db.execute(
            """SELECT EXISTS(
                   SELECT 1 FROM user_access
                   WHERE handle = ? AND channel IS NULL
                   AND is_admin = 1 AND deleted_at IS NULL
               ) AS has_access""",
            (handle,)
        )
        row = await cursor.fetchone()

    if not row or not row['has_access']:
        await respond("Access denied. Requires '+A' flag.")
        return

    await respond("Rehashing...")
    log.info("Rehash initiated by %s", handle)
    await core.do_rehash()

async def cmd_plugins(core, handle: str, session_id: int, arg: str, respond):
    await _list_loadables(core, respond, "plugin", "plugins", "plugins")

async def cmd_games(core, handle: str, session_id: int, arg: str, respond):
    await _list_loadables(core, respond, "game", "games", "games")

async def cmd_detach(core, handle, session_id, arg, respond):
    session = core.partyline.sessions.get(session_id, {})
    if session.get('type') != 'console':
        await respond("Error: .detach is only valid for console sessions.")
        return
    await respond("Detaching. Bot continues in background. Reconnect via telnet or DCC.")
    core.partyline.unregister_session(session_id)
    if core.console:
        await core.console.stop()

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
    'say': cmd_msg,
    'msg': cmd_msg,
    'act': cmd_act,
    'quit': cmd_quit,
    'die': cmd_quit,
    'status': cmd_status,
    'backup': cmd_backup,
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
    'rehash': cmd_rehash,
    'restart': cmd_restart,
    'detach': cmd_detach,
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
    # bot
    '+bot': cmd_addbot,
    '-bot': cmd_delbot,
    'botinfo': cmd_botinfo,
    'bots': cmd_bots,
    'link': cmd_link,
    'unlink': cmd_unlink,
    'chaddr': cmd_chaddr,
    'botattr': cmd_botattr,
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
    'gsessions': cmd_gsessions,
    # updates
    'checkupdate': cmd_checkupdate,
    'update': cmd_update,
    # block/allow list
    'blocklist': cmd_blocklist,
    'permithost': cmd_permithost,
    'denyhost': cmd_denyhost
}