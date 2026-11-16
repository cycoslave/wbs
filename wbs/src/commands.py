# src/commands.py
"""
Partyline commands for WBS
"""
import time
import os
import platform
import resource
import shutil
import logging
import secrets
import string
import socket
import asyncio
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict

from . import __version__, crypto_exec
from .db import get_db, private_file
from . import ignore as ignore_mod
from . import plugins as plugin_mod
from .idrules import (valid_handle, valid_hostmask, HANDLE_RULE_TEXT, HOSTMASK_RULE_TEXT,
                      valid_channel, valid_nick, validate_mode_string, NICK_MODES,
                      CHANNEL_RULE_TEXT, NICK_RULE_TEXT, valid_address, parse_port,
                      ADDRESS_RULE_TEXT, PORT_RULE_TEXT)
from .subnet import botnet_listen, botnet_public_address
from .share import normalize_share_level
from .user import GLOBAL_FLAGS, FLAG_LEGEND, expand_flag_words, unknown_flags
from .helper import (_require_flag, _resolve_subnet_arg, _chan_mode_cmd, _list_loadables,
                     _botnet_sync, _modify_hostmask, _authorize_scope_change,
                     _can_manage_user, _scope_label, local_subnet, _is_console,
                     gate_allows, _require_op, _mode_channel, _nick_on_channel,
                     _refuse_cross_subnet_bot, is_same_subnet_bot, clean_message)
from . import ircreq
from .tasks import format_tasks
from .net import normalize_host_mask, HOST_MASK_RULE_TEXT, PERMIT_REASON
from .subnet import SubnetManager, parse_subnet_id, SUBNET_ID_MAX
from .games import SUPPORTED_SCOPES

log = logging.getLogger("wbs.commands")


def _revoke_sessions(core, target: str, reason: str) -> None:
    """Close every open partyline session of `target` (lock/delete: SAST-004)."""
    revoke = getattr(getattr(core, "partyline", None), "revoke_handle", None)
    if callable(revoke):
        revoke(target, reason)

_FLAG_LEGEND_ITEMS = FLAG_LEGEND.split()
# Flag letters for help text, from the one table (USR-5).  Case-sensitive.
_FLAG_HELP = ("    Flags (case-sensitive): " + " ".join(_FLAG_LEGEND_ITEMS[:7]) + "\n"
              "                            " + " ".join(_FLAG_LEGEND_ITEMS[7:]))
_BOTATTR_ALLOWED_COLUMNS: frozenset[str] = frozenset({
    "autolink", "role", "autolink_retry_interval",
    "share_level", "password", "comment", "subnet_id",
})
# Local-only bot attributes that are never replicated to peers
# (link key: SAST-001; authoritative subnet scope: SAST-002; share policy
# and autolink settings: SAST-003).
_BOTATTR_LOCAL_ONLY: frozenset[str] = frozenset({
    "password", "subnet_id", "share_level", "autolink", "autolink_retry_interval",
})
_HANDLE_RE = re.compile(r'^[a-zA-Z0-9_\-\[\]\\^`{}]{1,20}$')

def _plugin_help_section() -> str:
    """The `.help` overview section for commands of loaded plugins (PLG-6)."""
    names = sorted(plugin_mod.PLUGIN_COMMANDS)
    if not names:
        return ""
    rows = ["      " + "".join(f"{n:<13}" for n in names[i:i + 4]).rstrip()
            for i in range(0, len(names), 4)]
    return "\n   Plugin commands:\n" + "\n".join(rows)


async def _visible_help_lines(core, handle, session_id, help_text: str) -> list:
    """Filter the command overview down to what this caller may run.

    Same policy as the partyline gate (partyline.COMMAND_MIN_FLAGS, local
    subnet scope); the console session is the operator and sees everything.
    Sections left without a command are dropped.
    """
    from .partyline import COMMAND_MIN_FLAGS  # lazy: partyline imports this module

    console = _is_console(core, session_id)
    verdicts: dict = {}

    async def allowed(cmd: str) -> bool:
        if console:
            return True
        cmd = cmd.lower()
        if cmd not in COMMAND_MIN_FLAGS:    # the gate would refuse it
            return False
        flag = COMMAND_MIN_FLAGS[cmd]
        if flag is None:
            return True
        if flag not in verdicts:
            verdicts[flag] = bool(await gate_allows(core, handle, flag))
        return verdicts[flag]

    alias_of = {real: alias for alias, real in ALIASES.items()}
    out: list = []
    header = None
    for line in help_text.split('\n'):
        if line.startswith('      '):
            names = [w for w in line.split() if await allowed(w)]
            names = [f"{w} ({alias_of[w]})" if w in alias_of else w for w in names]
            if not names:
                continue
            if header is not None:
                if out:
                    out.append('')
                out.append(header)
                header = None
            out.append('      ' + ''.join(f"{n:<{max(13, len(n) + 1)}}" for n in names).rstrip())
        elif line.startswith('   ') and line.rstrip().endswith(':'):
            header = line
        elif not line.strip():
            continue            # section separators are re-created above
        elif line.startswith('All commands begin'):
            out.extend(['', line])
        else:
            out.append(line)    # title
    return out

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
      lag

   For ops:
      mode         say          msg          act
      op           deop         voice        devoice

   For admins:
      chattr       chhandle     backup       status
      die          restart      nick         baway
      bback        botinfo      rehash       detach

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
      plugins      plugin       load         unload
      games        gload        gunload      gpurge
      gstart       gstop        gsessions

   IRC server tools:
      sdns         swhois       swhowas      servlinks
      links

   Tasks & Timers:
      taskset      tasks        timers

   Updates:
      checkupdate  update
{plugin_section}
All commands begin with '.', and all else goes to the party line.
"""
        help_text = help_text.replace("{plugin_section}", _plugin_help_section())
        for line in await _visible_help_lines(core, handle, session_id, help_text):
            await respond(line)
        return

    cmd = words[0].lower()
    cmd = ALIASES.get(cmd, cmd)         # `.help adduser` == `.help +user`

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
        help_text = f"""\
###  whois <handle>
    Shows detailed info for a user: flags, hostmasks, and access.
{_FLAG_HELP}

See also: userinfo, users
"""

    elif cmd == "handle":
        help_text = """\
###  handle <new-handle>
    Renames your own account (login with the new handle, same password).
    A handle that already exists is refused.

See also: chhandle
"""

    elif cmd == "chpass":
        help_text = """\
###  chpass [user] <password>
    Changes a password. With one argument, changes your own password.
    With two arguments (requires +A), changes another user's password.
    Only an owner (+n) may change the password of another admin or owner;
    the changed user's open partyline sessions are closed.
    Password must be at least 8 characters.

See also: nopass, fixpass
"""

    elif cmd == "quit":
        help_text = """\
###  quit
    Leaves the partyline: closes your current session (DCC, telnet or IRC
    chat). The bot keeps running. On the console, which has no session to
    leave, it only prints a hint (use .die or .detach).

See also: die, detach
"""

    elif cmd == "die":
        help_text = """\
###  die [message]
    Disconnects the bot from IRC and shuts it down. Requires +A.

See also: quit, restart
"""

    elif cmd == "mode":
        help_text = """\
###  mode <#channel> <modes>
    Sets modes on a channel.  Requires +o; owners (+n) and admins (+A)
    have op rights without an explicit +o.
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
    Gives channel operator status to a nick.  Requires +o; owners (+n)
    and admins (+A) have op rights without an explicit +o.

See also: deop, mode, mass
"""

    elif cmd == "deop":
        help_text = """\
###  deop <nick> <#channel>
    Removes channel operator status from a nick.  Requires +o (or +n/+A).

See also: op, mode, mass
"""

    elif cmd == "voice":
        help_text = """\
###  voice <nick> <#channel>
    Gives voice status to a nick.  Requires +o (or +n/+A).

See also: devoice, mode
"""

    elif cmd == "devoice":
        help_text = """\
###  devoice <nick> <#channel>
    Removes voice status from a nick.  Requires +o (or +n/+A).

See also: voice, mode
"""

    elif cmd == "chattr":
        help_text = f"""\
###  chattr <user> [#channel] +/-<flags> [subnet_name|*]
    Changes user flags on one scope: this bot's subnet if omitted,
    '*' for the global row (all subnets), or a named subnet.
    Global or other-subnet changes need a global +A; +n/-n (owner)
    needs an owner (+n) or the console.  A channel row is created
    on demand when the channel exists on that subnet.
{_FLAG_HELP}
    Example: .chattr bob +A *
    Example: .chattr bob #wbs +o

See also: +user, userinfo, addaccess
"""

    elif cmd == "chhandle":
        help_text = """\
###  chhandle <oldhandle> <newhandle>
    Renames another user's account (admin).

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

See also: rehash, die
"""

    elif cmd == "rehash":
        help_text = """\
###  rehash
    Restarts the Core process without disconnecting from IRC.
    Channel state and IRC connection are preserved.
    Requires 'm' (master) flag.

See also: restart, die
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
    New users get +p (partyline/DCC) by default; no other flags.
    Existing users are not changed.

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
        help_text = f"""\
###  userinfo <handle>
    Shows detailed info for a user: one line of flags per access row
    (channel or '*', and scope).
{_FLAG_HELP}

See also: whois, users
"""

    elif cmd == "chusercomment":
        help_text = """\
###  chusercomment <user> <comment>
    Sets a comment on a user record.
"""

    elif cmd == "addaccess":
        help_text = f"""\
###  addaccess <user> +<flags> [#channel] [subnet_name|*]
    Adds access flags to one scope of a user's access.
    Scope: omitted = this bot's subnet; '*' = global (all subnets).
    Global or other-subnet grants need a global +A; +n needs an owner.
    A channel row is created on demand when the channel exists there.
{_FLAG_HELP}
    Example: .addaccess bob +o #wbs

See also: delaccess, chattr
"""

    elif cmd == "delaccess":
        help_text = f"""\
###  delaccess <user> -<flags> [#channel] [subnet_name|*]
    Removes access flags from one scope of a user's access.
    Scope: omitted = this bot's subnet; '*' = the global row.
{_FLAG_HELP}

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
    Keys:  retry=<seconds>  share=all|subnet|none  pass=<password>  comment=<text>  role=<role>
           subnet=<id|name|none>  authoritative subnet of the bot; ops, modes and botnet
                                  commands are only exchanged with same-subnet bots.
                                  The subnet must exist here (.subnet add <name> <id>).
           subnet=proposed        accept the subnet a linked peer announced (shown as
                                  'proposed' in the attribute list); never automatic
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
    The remote bot runs your input as your own handle with its own access
    checks (you need +p there), and only if its config delegates you to this
    bot: "botnet": {"relay_from": {"<thisbot>": ["<yourhandle>"]}}.
    Both bots must be linked, same-subnet peers.
    The console cannot relay; log in over telnet/DCC.

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
###  subnet <list|add|del|set> [args]
    Manages botnet subnets (rows of the local database).
    subnet list                       - lists subnets: [id] name (this bot / bots / channels)
    subnet add <name> [id]            - creates a subnet (next free id if omitted); use the
                                        peer's id when you add the subnet of a remote bot
    subnet del <name|id>              - deletes a subnet; refused for this bot's own subnet
                                        and while bots, channels or access rows use it
    subnet set <name|id> name <new>   - renames a subnet
    Names: a letter first, then letters, digits, '_', '-' or '.' (max 32).
    add/del/set need +A.

See also: botattr, bots, link
"""

    elif cmd == "net":
        help_text = """\
###  net <subcmd> [args]
    Executes a command at the botnet level (sends to same-subnet linked bots and runs locally).
    Linked bots of other subnets never receive or act on it.
    Valid subcommands: op deop say msg join part mode restart die

See also: relay, mass
"""

    elif cmd == "mass":
        help_text = """\
###  mass <op|deop|voice|devoice|kick> <#channel> [reason]
    Ops, deops, voices, devoices or kicks everyone in a channel the bot
    is on. The bot itself is skipped; deop, devoice and kick also skip
    known users with op access (+o, +A, +n or channel +o) and friends
    (+f). kick only targets users without op. Modes are sent in batches
    of the server's MODES limit.

See also: op, deop, net
"""

    elif cmd == "+ignore":
        help_text = """\
###  +ignore <hostmask> [%<duration>] [comment]
    Adds a hostmask to the ignore list. The bot drops every message,
    notice, CTCP and DCC request from a matching host, before any
    command, game or plugin sees it.
    Duration: %10m, %1h, %2d12h, %1y; none or %0 = permanent.
    Owner/admin hostmasks cannot be ignored.
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
    Lists the active ignores with their expiry and comment.

See also: +ignore, -ignore
"""

    elif cmd == "denyhost":
        help_text = """\
###  denyhost <mask> [minutes|%XdXhXm] [reason]
    Denies a host mask: an IP (1.2.3.4), a CIDR network (10.0.0.0/8) or a
    host glob (*.example.net, 10.0.*; *!*@host is accepted too).  Inbound
    botlink and telnet connections from it are refused before login, and
    DCC CHAT from it is refused.  No duration = permanent.  Needs +A.
    Example: .denyhost 1.2.3.4 60 Spammer
             .denyhost *.badisp.example %1d

See also: permithost, blocklist
"""

    elif cmd == "permithost":
        help_text = """\
###  permithost <mask>
    Removes the deny for <mask>.  If a wider deny still covers it, a permit
    entry is stored that overrides that deny.  Automatic bans for repeated
    login failures still apply.  Needs +A.

See also: denyhost, blocklist
"""

    elif cmd == "blocklist":
        help_text = """\
###  blocklist
    Lists the net blocklist: denied masks, permits and automatic
    login-failure bans, with who added them and when they expire.  Needs +A.

See also: denyhost, permithost
"""

    elif cmd == "plugins":
        help_text = """\
###  plugins
    Lists loaded plugins, plugins that load on start (auto-load), and all
    plugins on disk.

See also: load, unload, plugin
"""

    elif cmd == "plugin":
        help_text = """\
###  plugin purge <plugin>
    Deletes everything a plugin has stored (its database tables: settings,
    stats, audit log) and forgets it in the auto-load list.  Cannot be
    undone.  The plugin must be unloaded first.  Needs +A.

See also: unload, plugins
"""

    elif cmd == "load":
        help_text = """\
###  load <plugin>
    Loads a plugin from src/plugins/ and marks it to load again on start.
    Names: a lowercase letter, then lowercase letters, digits or '_'.

See also: unload, plugins
"""

    elif cmd == "unload":
        help_text = """\
###  unload <plugin>
    Unloads a currently loaded plugin.  It stays unloaded after a restart
    until you .load it again.  Its stored data is kept (see .plugin purge).

See also: load, plugins, plugin
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
    Unloads a currently loaded game.  Its running sessions are stopped
    (announced in their channels) and forgotten; its stored data (cash,
    stats, settings) is kept (see .gpurge).

See also: gload, games, gpurge
"""

    elif cmd == "gpurge":
        help_text = """\
###  gpurge <game>
    Deletes everything a game has stored (its database tables: cash,
    stats, settings) and forgets it in the auto-load list.  Cannot be
    undone.  The game must be unloaded first.  Needs +A.

See also: gunload, games
"""

    elif cmd == "gstart":
        help_text = """\
###  gstart <game> channel <#channel> [key=value ...]
    Starts a game session in a channel.  Only the "channel" scope exists:
    games cannot be started for a user, a subnet or the botnet.
    The key=value settings are checked against the game's own settings
    and override the stored ones for this session only; an unknown key
    is refused with the list of valid ones.
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

    elif cmd == "servlinks":
        help_text = """\
###  servlinks
    Asks the IRC server for its LINKS list (the servers of the IRC network) and
    shows the answer. For links between bots, see .bots.
    (.links is the old name of this command.)
"""

    elif cmd == "links":
        help_text = """\
###  links
    Old name of .servlinks (IRC server LINKS, not botnet links).
"""

    elif cmd == "taskset":
        help_text = """\
###  taskset <task> on|off|interval=<seconds>
    Switches a Core task (see .tasks) on or off, or changes how often it
    runs (1..86400 s). The setting is saved and survives a restart.

See also: tasks, timers
"""

    elif cmd == "tasks":
        help_text = """\
###  tasks
    Lists the Core's periodic tasks (autolink retry, request timeouts,
    flood unbans, lag check, update check, plugin timers) with on/off
    state, interval, last and next run and the last error.

See also: taskset, timers
"""

    elif cmd == "timers":
        help_text = """\
###  timers
    Asks the IRC process for its timers (maintenance: channel rejoin and
    nick reclaim; plugin IRC timers) with interval, last and next run.

See also: tasks, taskset
"""

    elif cmd == "checkupdate":
        help_text = """\
###  checkupdate
    Checks the configured update server (update.host) for a new WBS
    version without installing anything.

See also: update
"""

    elif cmd == "update":
        help_text = """\
###  update [confirm]
    Checks the configured update server (update.host) for a new WBS
    version. With 'confirm', downloads, verifies and installs it.
    Restart required after.

See also: checkupdate
"""

    else:
        plugin_cmd = plugin_mod.PLUGIN_COMMANDS.get(cmd or "")
        if plugin_cmd is not None:
            need = f"Needs +{plugin_cmd.min_flag}." if plugin_cmd.min_flag else "Any session."
            help_text = f"""\
###  {plugin_cmd.help}
    Provided by the {plugin_cmd.owner} plugin (present while it is loaded). {need}
"""
        else:
            help_text = f"""\
ERROR: Unknown command: {cmd}
"""

    for line in help_text.split('\n'):
        await respond(line)
    names = sorted(a for a, real in ALIASES.items() if real == cmd)
    if names and not help_text.startswith("ERROR"):
        await respond(f"Alias: {', '.join(names)}")

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
    if not await _require_op(core, handle, respond, session_id=session_id):
        return
    if not await _mode_channel(core, chan, respond):
        return
    err, changes = validate_mode_string(modes)
    if err:
        return await respond(err)
    # A nick-mode parameter must be someone on the (synced) channel.
    for sign, letter, target in changes:
        if letter in NICK_MODES and _nick_on_channel(core, chan, target) is False:
            return await respond(f"{target} is not on {chan}.")
    # NET-3: never op/mode a bot of another (or unknown) subnet.
    for sign, letter, target in changes:
        if letter in NICK_MODES and await _refuse_cross_subnet_bot(
                core, handle, target, f"mode {sign}{letter}", respond):
            return
    ircreq.for_core(core).add_mode(chan, changes, f"set {modes} on {chan}",
                                   f"Mode set: {chan} {modes}", respond)
    core.irc_q.put_nowait({"cmd": "mode", "channel": chan, "modes": " ".join(modes.split())})

async def cmd_op(core, handle, session_id, arg, respond):
    await _chan_mode_cmd(core, handle, arg, respond, "+o", "op", "Gave op to", session_id=session_id)

async def cmd_deop(core, handle, session_id, arg, respond):
    await _chan_mode_cmd(core, handle, arg, respond, "-o", "deop", "Took op from", session_id=session_id)

async def cmd_voice(core, handle, session_id, arg, respond):
    await _chan_mode_cmd(core, handle, arg, respond, "+v", "voice", "Gave voice to", session_id=session_id)

async def cmd_devoice(core, handle, session_id, arg, respond):
    await _chan_mode_cmd(core, handle, arg, respond, "-v", "devoice", "Took voice from", session_id=session_id)

async def cmd_channels(core, handle: str, session_id: int, arg: str, respond):
    """
    .channels — list all active channels with settings and optional IRC live state.

    DB columns used: name, modes, is_inactive, is_autoop, is_autovoice,
                     is_bitch, is_enforcebans, comment
    Live IRC state (if joined): users, ops, voices from core.live_channel()
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

        # Live IRC state (IRC-2): Core's channel state, kept by IRC events.
        live = core.live_channel(chan)
        if live is not None:
            bot = "op" if live.bot_op else "halfop" if live.bot_halfop else "no op"
            live_str = (
                f" | users:{len(live.users)}"
                f" ops:{len(live.ops)}"
                f" voice:{len(live.voiced)}"
                f" bot:{bot}"
                + ("" if live.synced else " (syncing)")
            )
        elif connected:
            live_str = " | (not joined)"
        else:
            live_str = " | (not connected)"
        mode_str = modes or "+n"

        comment_str = f"  # {comment}" if comment else ""
        await respond(f"--> {chan} ({mode_str}){flag_str}{live_str}{comment_str}")
        total += 1

    await respond(f"TOTAL CHANNELS: {total}")

async def cmd_quit(core, handle, session_id, arg, respond):
    """Leave the partyline: close THIS session (DCC, telnet or IRC fallback).

    Never shuts the bot down (that is .die).  The console has no session to
    leave, so it only gets a hint.
    """
    partyline = getattr(core, 'partyline', None)
    session = (partyline.sessions.get(session_id) if partyline else None) or {}
    stype = session.get('type')

    if stype == 'dcc':
        # Covers DCC sockets and the IRC-fallback (NOTICE) session.
        dcc_sessions = getattr(getattr(core, 'dcc', None), '_sessions', None)
        sess = dcc_sessions.get(session_id) if isinstance(dcc_sessions, dict) else None
        if sess is not None:
            await sess.send("Goodbye!")
            await sess.close("left via .quit")
            return
    elif stype == 'telnet':
        party = (getattr(core, 'party_sessions', None) or {}).get(session_id)
        if party is not None:
            await party.send("Goodbye!")
            party.running = False
            await party.close()
            return
    elif stype == 'console':
        await respond("The console has no session to leave: .quit does not shut "
                      "the bot down. Use .die to shut it down, or .detach to "
                      "leave it running in the background.")
        return

    await respond("There is no session to leave here (.quit never shuts the bot down).")

async def cmd_die(core, handle, session_id, arg, respond):
    """Shutdown bot (+A)."""
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
    if len(parts) > 2:
        await respond("Usage: .+chan <#channel> [subnet_name|*]")
        return
    if not valid_channel(channel):
        await respond(f"→ {CHANNEL_RULE_TEXT} Got: {channel[:60]!r}")
        return

    subnet_id, ok = await _resolve_subnet_arg(core, subnet_arg, respond, default_local=True)
    if not ok:
        return

    try:
        await core.chan.addchan(channel, subnet_id=subnet_id, created_by=handle)
        core.irc_q.put_nowait({'cmd': 'join', 'channel': channel})
        subnet_label = subnet_arg or f"subnet {subnet_id}"
        if subnet_arg == "*":
            subnet_label = "global"
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

async def cmd_chaninfo(core, handle: str, session_id: int, arg: str, respond):
    """Show stored DB config + live IRC state for a channel."""
    if not arg:
        await respond("Usage: .chaninfo <#channel>")
        return
    chan_name = arg.strip().lower()
    live_chan = core.get_chan(chan_name)
    result = await core.chan.showchan(chan_name, live=live_chan)
    for line in result.splitlines():
        await respond(line)

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

    if not valid_handle(new_handle):
        await respond(HANDLE_RULE_TEXT)
        return
    if hostmask is not None and not valid_hostmask(hostmask):
        await respond(HOSTMASK_RULE_TEXT)
        return
    subnet_id, ok = await _resolve_subnet_arg(core, subnet_arg, respond, default_local=True)
    if not ok:
        return
    # A subnet-local admin may only create users on this bot's subnet; a
    # global ('*') or foreign-subnet user needs a global +A grant (SAST-004).
    if not await _authorize_scope_change(core, handle, subnet_id, respond, session_id):
        return

    if await core.user.adduser(new_handle, hostmask, subnet_id=subnet_id, added_by=handle):
        scope = subnet_arg or _scope_label(subnet_id)
        await respond(f"→ User {new_handle} added (scope: {scope})!")
        _botnet_sync(core, "sync_user", "ADD", {"handle": new_handle, "hostmask": hostmask, "subnet_id": subnet_id})
    else:
        await respond(f"→ User {new_handle} NOT added (already exists, in any letter case?).")

async def cmd_deluser(core, handle: str, session_id: int, arg: str, respond):
    """.-user <user>"""
    if not arg:
        await respond("Usage: .-user <user>")
        return
    parts = arg.split()
    if not await _can_manage_user(core, handle, parts[0], respond, session_id):
        return
    if await core.user.deluser(parts[0], deleted_by=handle):
        await respond(f"→ User {parts[0]} deleted!")
        _revoke_sessions(core, parts[0], "your account was deleted")
        _botnet_sync(core, "sync_user", "DEL", {"handle": parts[0]})
    else:
        await respond(f"→ User {parts[0]} NOT deleted (not found?).")

async def cmd_showuser(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .showuser <user>")
        return
    parts = arg.split()
    await respond(await core.user.showuser(parts[0]))

async def _authorize_password_reset(core, caller: str, target: str, respond,
                                    session_id) -> bool:
    """
    May `caller` reset the password of another account `target`? (SAST-020)

    Operator policy (2026-09-30): only an OWNER (+n) may reset the password
    of another admin (+A) or owner (+n); admins (+A) may reset regular
    users' passwords.  Everyone else is denied.  The local console session
    is the operator and is always allowed.

    Scoped ACL (SAST-004 model, user_access.subnet_id NULL = global):
      * caller needs +A on this bot's subnet and must be allowed to manage
        the target account (_can_manage_user: a subnet-local admin only
        manages users confined to this subnet);
      * a target holding +A/+n anywhere (any subnet or channel row, locked
        or not) is privileged.  If all of its privileged rows are local to
        this bot's subnet, the caller needs +n here (global or local grant);
        if any privileged row is global or foreign, the caller needs a
        GLOBAL +n grant: a subnet-local owner never resets a global/foreign
        admin or owner.
    Denials are logged without any password material.
    """
    if _is_console(core, session_id):
        return True
    local = local_subnet(core)
    if not await core.user.matchattr(caller, "+A", subnet_id=local):
        await respond("Access denied (need +A to change another user's password).")
        log.warning("chpass denied: %s -> %s (caller lacks +A)", caller, target)
        return False
    if not await _can_manage_user(core, caller, target, respond, session_id):
        log.warning("chpass denied: %s -> %s (target outside caller's scope)", caller, target)
        return False
    privileged = await core.user.privileged_scopes(target)
    if not privileged:
        return True
    owner_scope = local if privileged <= {local} else None
    if await core.user.matchattr(caller, "+n", subnet_id=owner_scope):
        return True
    need = "+n" if owner_scope is not None else "global +n"
    await respond(f"Access denied (need {need}: only an owner may change the "
                  f"password of an admin or owner).")
    log.warning("chpass denied: %s -> %s (privileged target, caller lacks %s)",
                caller, target, need)
    return False


async def cmd_passwd(core, handle: str, session_id: int, arg: str, respond):
    """
    .chpass [target_handle] <new_password>

    Authorization rules (SAST-020, operator policy 2026-09-30):
      - No args                      → usage hint
      - 1 arg, or 2 args naming self → own password: any authenticated +p
                                       user (admins and owners included);
                                       the console has no password
      - 2 args (other user)          → regular target: requires +A;
                                       admin/owner target: requires +n (owner)
                                       in a scope covering the target's
                                       privileged grants
                                       (see _authorize_password_reset)
      - The local console session may reset any user's password.
    A reset of another user's password closes that user's open partyline
    sessions.
    """
    if not arg:
        await respond("Usage: .chpass [user] <password>")
        return
    parts = arg.split()

    if len(parts) == 2 and parts[0].lower() == str(handle).lower() \
            and not _is_console(core, session_id):
        parts = parts[1:]                  # ".chpass <self> <pw>" is a self-reset

    if len(parts) == 1:
        if handle == "console" or _is_console(core, session_id):
            await respond("ERROR: Console user does not have a password.")
            return
        target, password = handle, parts[0]
    elif len(parts) == 2:
        target, password = parts[0], parts[1]

        # Reject changing the console pseudo-user
        if target.lower() == "console":
            await respond("ERROR: Console user does not have a password.")
            return
        if not await _authorize_password_reset(core, handle, target, respond, session_id):
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
    updated = await core.user.set_password(target, password)
    password = None
    if not updated:
        await respond(f"User not found: {target}")
        return

    if target == handle:
        await respond("Password updated.")
    else:
        await respond(f"Password updated for {target}.")
        _revoke_sessions(core, target, f"your password was changed by {handle}")

    log.info("chpass: %s changed password for %s", handle, target)

async def _register_bot(core, bot: str, hostmask, address, port_text, respond):
    """
    Shared validation + insert for .+bot / .addleaf / .addhub (NET-5).
    Returns True when the bot row was created; every user mistake gets a plain
    message (never the generic 'Error executing').
    """
    if not valid_handle(bot):
        await respond(HANDLE_RULE_TEXT)
        return False
    if hostmask is not None and not valid_hostmask(hostmask):
        await respond(HOSTMASK_RULE_TEXT)
        return False
    if address is not None and not valid_address(address):
        await respond(ADDRESS_RULE_TEXT)
        return False
    port = None
    if port_text is not None:
        port = parse_port(port_text)
        if port is None:
            await respond(PORT_RULE_TEXT)
            return False
    try:
        await core.bot.addbot(bot, hostmask, address, port)
    except ValueError:
        await respond(f"Bot '{bot}' already exists")
        return False
    return True

async def cmd_addbot(core, handle: str, session_id: int, arg: str, respond):
    parts = arg.split()
    usage = "Usage: .+bot <bot> <hostmask> <address> [port]"
    if len(parts) < 3 or len(parts) > 4:
        # address is NOT NULL in the schema: without it the insert used to
        # end in a raw sqlite error
        await respond(usage)
        return
    bot, hostmask, address = parts[0], parts[1], parts[2]
    port_text = parts[3] if len(parts) > 3 else "3333"
    if await _register_bot(core, bot, hostmask, address, port_text, respond):
        port = parse_port(port_text)
        await respond(f"→ Bot {bot} added!")
        _botnet_sync(core, "sync_bot", "ADD", {"handle": bot, "hostmask": hostmask, "address": address, "port": port})

async def cmd_delbot(core, handle: str, session_id: int, arg: str, respond):
    if not arg:
        await respond("Usage: .-bot <bot>")
        return
    parts = arg.split()
    target = parts[0]
    botnet = getattr(core, "botnet", None)
    # A linked peer is unlinked BEFORE its row goes (NET-6): the live link must
    # not outlive the record it was authenticated against.  No-op if unlinked.
    if botnet is not None and hasattr(botnet, "unlink_peer"):
        if await botnet.unlink_peer(target, f"bot record deleted by {handle}"):
            await respond(f"→ Unlinked {target} (bot record is being deleted).")
    if await core.bot.delbot(target):
        await respond(f"→ Bot {target} deleted!")
        _botnet_sync(core, "sync_bot", "DEL", {"handle": target})
    else:
        await respond(f"→ Bot {target} NOT deleted!")

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
    if not await _require_flag(core, handle, "+n", respond, session_id=session_id):
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
    if not await _require_flag(core, handle, "+n", respond, session_id=session_id):
        return
    if not arg:
        await respond("Usage: .unlink <bot>")
        return
    botname = arg.strip()
    unlink = getattr(core.botnet, "unlink_peer", None)
    if unlink is not None:
        # Full unlink (NET-6): tell the peer, close, clean routing/.bots state.
        link = core.botnet.peers.get(botname.lower())
        if link is None:
            await respond(f"Not linked to {botname}.")
            return
        await respond(f"Unlinking from {botname}...")
        try:
            await unlink(botname, f"unlinked by {handle}")
            await respond(f"Unlinked from {botname} ({link.host}:{link.port}).")
        except Exception as e:
            await respond(f"Unlink failed: {e}")
        return
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
    if not await _require_flag(core, handle, "A", respond, session_id=session_id):
        return
    parts = arg.split(maxsplit=1)
    if len(parts) < 2:
        await respond("Usage: .chusercomment <user> <comment>")
        return
    target, comment = parts[0], parts[1]
    if not await _can_manage_user(core, handle, target, respond, session_id):
        return
    result = await core.user.set_comment(target, comment, updated_by=handle)
    if result == "not_found":
        await respond(f"No such user: {target}")
    else:
        await respond(f"Comment updated for {target}.")
        if hasattr(core, "botnet"):
            asyncio.create_task(core.botnet.sync_user("UPDATE", {"handle": target}))

async def _parse_access_scope(core, extra: list[str], respond):
    """
    Parse the optional trailing args of .addaccess/.delaccess/.chattr:
    [#channel] [subnet_name|*] in any order.

    Returns (channel, subnet_id, ok).  Omitted subnet = this bot's own subnet
    (never global); '*' = the global row (applies on all subnets).
    """
    channel = None
    subnet_arg = None
    for tok in extra:
        if tok[:1] in ("#", "&"):
            if channel is not None:
                await respond("Only one channel may be given.")
                return None, None, False
            channel = tok
        else:
            if subnet_arg is not None:
                await respond("Only one subnet may be given.")
                return None, None, False
            subnet_arg = tok
    subnet_id, ok = await _resolve_subnet_arg(core, subnet_arg, respond, default_local=True)
    return channel, subnet_id, ok


async def _warn_inherited(core, target: str, cols: set[str], channel, subnet_id, respond):
    """After removing flags from a subnet row, say which ones a global row still grants."""
    if subnet_id is None:
        return
    still = []
    for ch, col in GLOBAL_FLAGS.items():
        if col not in cols:
            continue
        spec = f"*|{ch}" if channel else f"+{ch}"
        if await core.user.matchattr(target, spec, channel, subnet_id=None):
            still.append(ch)
    if still:
        await respond(f"Note: {target} still has +{''.join(still)} from a global (*) grant; "
                      f"use scope '*' to remove it.")


def _scope_text(channel, subnet_id) -> str:
    where = f" on {channel}" if channel else ""
    return f"{where} ({_scope_label(subnet_id)})"


async def _apply_flags(core, handle: str, session_id, target: str, flag_str: str,
                       channel, subnet_id, respond):
    """
    Shared core of .chattr/.addaccess/.delaccess (USR-5, USR-8).

    Letters come from the one table, user.GLOBAL_FLAGS, case-sensitive (no
    folding: `+O` is refused, `+a` is autoop, never admin).  +n/-n (owner)
    needs an owner (+n) in the row's scope or the console; +A alone is not
    enough.  A channel row is created on demand by user.chattr() when the
    channel exists in that scope.  Returns True when flags were applied
    (after responding), False after an error response.
    """
    bad = unknown_flags(flag_str)
    if bad or not flag_str.strip("+-"):
        what = f"Unknown flag(s) {''.join(bad)} in: {flag_str}" if bad else \
            f"No flags in: {flag_str}"
        await respond(f"{what}. Valid flags (case-sensitive): {FLAG_LEGEND}")
        return False
    if "n" in flag_str and not _is_console(core, session_id):
        if not await core.user.matchattr(handle, "+n", subnet_id=subnet_id):
            await respond(f"Access denied (need +n ({_scope_label(subnet_id)}) "
                          f"to change the owner flag).")
            log.warning("owner flag change denied: %s -> %s %s", handle, target, flag_str)
            return False

    result = await core.user.chattr(target, flag_str, channel=channel,
                                    subnet_id=subnet_id, updated_by=handle)
    if result == "not_found":
        await respond(f"No such user: {target}")
    elif result == "no_channel":
        await respond(f"No such channel: {channel} ({_scope_label(subnet_id)}).")
    elif result == "no_access":
        await respond(f"No access row found for {target}{_scope_text(channel, subnet_id)}.")
    elif result == "wildcard_host":
        await respond(f"Cannot grant +n/+A to {target}: the user has a hostmask whose "
                      f"host part is only wildcards. Remove it (.-host) and add a "
                      f"specific host first.")
    elif result == "bad_flag":          # unreachable after unknown_flags(); kept as a guard
        await respond(f"Unknown flag in: {flag_str}. Valid flags (case-sensitive): {FLAG_LEGEND}")
    else:
        return True
    return False


async def cmd_addaccess(core, handle: str, session_id: int, arg: str, respond) -> None:
    """
    Add flags to a user's access row of one scope.
    Usage: .addaccess <user> +<flags> [#channel] [subnet_name|*]

    Scope: omitted = this bot's subnet; '*' = global (all subnets; needs a
    global +A grant, as does any other subnet).

    Examples:
        .addaccess bob +p            (partyline on this bot's subnet)
        .addaccess bob +A *          (global admin)
        .addaccess bob +o #wbs       (channel op on #wbs, this subnet)
    """
    if not await _require_flag(core, handle, "A", respond, session_id=session_id):
        return
    parts = arg.split()
    if len(parts) < 2:
        await respond("Usage: .addaccess <user> +<flags> [#channel] [subnet_name|*]")
        return

    target   = parts[0]
    flag_str = parts[1]
    channel, subnet_id, ok = await _parse_access_scope(core, parts[2:], respond)
    if not ok:
        return
    if not await _authorize_scope_change(core, handle, subnet_id, respond, session_id):
        return

    # Normalise: addaccess always means "+", strip any leading sign; word
    # names (admin, op, voice ...) are synonyms of the letters.
    flag_str = "+" + expand_flag_words(flag_str.lstrip("+-"))

    if await _apply_flags(core, handle, session_id, target, flag_str,
                          channel, subnet_id, respond):
        await respond(f"Added {flag_str} to {target}{_scope_text(channel, subnet_id)}.")
        if hasattr(core, "botnet"):
            asyncio.create_task(core.botnet.sync_user("UPDATE", {"handle": target}))

async def cmd_delaccess(core, handle: str, session_id: int, arg: str, respond) -> None:
    """
    Remove flags from a user's access row of one scope.
    Usage: .delaccess <user> -<flags> [#channel] [subnet_name|*]

    Scope: omitted = this bot's subnet; '*' = the global row.

    Examples:
        .delaccess bob -A *          (remove global admin)
        .delaccess bob -o #wbs       (remove channel op on #wbs, this subnet)
    """
    if not await _require_flag(core, handle, "A", respond, session_id=session_id):
        return
    parts = arg.split()
    if len(parts) < 2:
        await respond("Usage: .delaccess <user> -<flags> [#channel] [subnet_name|*]")
        return

    target   = parts[0]
    flag_str = parts[1]
    channel, subnet_id, ok = await _parse_access_scope(core, parts[2:], respond)
    if not ok:
        return
    if not await _authorize_scope_change(core, handle, subnet_id, respond, session_id):
        return

    # Normalise: delaccess always means "-"; word names as in addaccess
    flag_str = "-" + expand_flag_words(flag_str.lstrip("+-"))

    if await _apply_flags(core, handle, session_id, target, flag_str,
                          channel, subnet_id, respond):
        await respond(f"Removed {flag_str} from {target}{_scope_text(channel, subnet_id)}.")
        await _warn_inherited(core, target, {GLOBAL_FLAGS[c] for c in flag_str[1:]},
                              channel, subnet_id, respond)
        if hasattr(core, "botnet"):
            asyncio.create_task(core.botnet.sync_user("UPDATE", {"handle": target}))

async def cmd_lockuser(core, handle: str, session_id: int, arg: str, respond) -> None:
    """
    Lock a user account, preventing login.
    Usage: .lockuser <user>
    Requires +A.
    """
    if not await _require_flag(core, handle, "A", respond, session_id=session_id):
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
    if not await _can_manage_user(core, handle, target, respond, session_id):
        return
    result = await core.user.set_locked(target, locked=True, updated_by=handle)
    if result == "not_found":
        await respond(f"No such user: {target}")
    elif result == "no_change":
        await respond(f"{target} is already locked.")
    else:
        await respond(f"{target} has been locked.")
        log.info("cmd_lockuser: %s locked by %s", target, handle)
        # Revoke already-open sessions: a lock takes effect immediately.
        _revoke_sessions(core, target, "your account was locked")
        if hasattr(core, "botnet"):
            asyncio.create_task(core.botnet.sync_user("UPDATE", {"handle": target}))

async def cmd_unlockuser(core, handle: str, session_id: int, arg: str, respond) -> None:
    """
    Unlock a previously locked user account.
    Usage: .unlockuser <user>
    Requires +A.
    """
    if not await _require_flag(core, handle, "A", respond, session_id=session_id):
        return
    parts = arg.split()
    if not parts:
        await respond("Usage: .unlockuser <user>")
        return
    target = parts[0]
    if not await _can_manage_user(core, handle, target, respond, session_id):
        return
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
        
        # Bot column (IRC-12): the bot the session is on.  Relayed users
        # (botnet sessions) carry the origin bot; everything else is local.
        botname = str(sess.get('origin') or core.botname or "?")
        host = utype if utype != 'console' else "localhost"
        
        await respond(f"{marker}{uhandle:<10} {botname:<9}  {host}")
        total += 1
    
    await respond(f"Total users: {total}")

async def _rename_user(core, actor: str, old_handle: str, new_handle: str, respond) -> bool:
    """DB rename first (one transaction); live sessions follow only on success."""
    if not _HANDLE_RE.match(new_handle):
        await respond("Invalid handle. Use only letters, digits, and IRC-safe characters (max 20).")
        return False
    try:
        err = await core.user.change_handle(old_handle, new_handle, changed_by=actor)
    except Exception as e:
        log.error("rename %s -> %s failed: %r", old_handle, new_handle, e)
        err = "database error, nothing was changed"
    if err:
        await respond(f"Handle not changed: {err}")
        return False
    rename = getattr(getattr(core, "partyline", None), "rename_handle", None)
    if callable(rename):
        rename(old_handle, new_handle)
    return True

async def cmd_handle(core, handle: str, session_id: int, arg: str, respond):
    """.handle <newhandle>: rename your OWN account (USR-3).  It never switches
    the session to another user: an existing handle is refused."""
    parts = arg.split()
    if len(parts) != 1:
        await respond("Usage: .handle <newhandle>")
        return
    if _is_console(core, session_id):
        await respond("The console has no user account; use .chhandle <old> <new>.")
        return
    if await _rename_user(core, handle, handle, parts[0], respond):
        await respond(f"Your handle is now: {parts[0]}")

async def cmd_chhandle(core, handle: str, session_id: int, arg: str, respond):
    """.chhandle <oldhandle> <newhandle>: rename another user (+A, USR-4)."""
    parts = arg.split()
    if len(parts) != 2:
        await respond("Usage: .chhandle <oldhandle> <newhandle>")
        return
    old_handle = await core.user.resolve_handle(parts[0])
    if not old_handle or not await core.user.exist(old_handle):
        await respond(f"User not found: {parts[0]}")
        return
    if not await _can_manage_user(core, handle, old_handle, respond, session_id):
        return
    if await _rename_user(core, handle, old_handle, parts[1], respond):
        await respond(f"User handle changed: {old_handle} → {parts[1]}")

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
    if not await _require_flag(core, handle, "+A", respond, session_id=session_id):
        return
    await respond("Backing up the channel & user files...")
    db_path = core.db_path
    config_path = core.config_path
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    await respond("Backing up database...")
    db_backup = f"{db_path}.{ts}.bak"
    # SYS-6: backups hold password hashes / link keys: owner-only (0600).
    private_file(db_backup)
    shutil.copyfile(db_path, db_backup)
    await respond(f"Database backed up to {os.path.basename(db_backup)}")

    await respond("Backing up config...")
    config_backup = f"{config_path}.{ts}.bak"
    private_file(config_backup)
    shutil.copyfile(config_path, config_backup)
    await respond(f"Config backed up to {os.path.basename(config_backup)}")

    await respond("Backup complete.")

def _ignores_changed(core) -> None:
    """Tell the IRC process to reload its ignore list (USR-11)."""
    send = getattr(core, "send_irc", None)
    if callable(send):
        send({'cmd': 'reload_ignores'})


async def cmd_ignores(core, handle: str, session_id: int, arg: str, respond):
    now = time.time()
    async with get_db(core.db_path) as db:
        purged = await ignore_mod.purge_expired(db, now)
        rows = await ignore_mod.active_ignores(db, now)
    if purged:
        _ignores_changed(core)
    if not rows:
        await respond("No ignores.")
        return
    await respond("Currently ignoring:")
    for row in rows:
        exp = ignore_mod.expires_at(row)
        when = f"expires in {ignore_mod.format_duration(exp - now)}" if exp else "permanent"
        by = f", by {row['created_by']}" if row['created_by'] else ""
        comment = f": {row['comment']}" if row['comment'] else ""
        await respond(f"  {row['hostmask']} ({when}{by}){comment}")
    await respond(f"Total ignores: {len(rows)}")

async def cmd_addignore(core, handle: str, session_id: int, arg: str, respond):
    usage = "Usage: +ignore <hostmask> [%<XyXdXhXm>] [comment]"
    parts = arg.split(maxsplit=1)
    if not parts:
        await respond(usage)
        return
    hostmask = ignore_mod.normalize_mask(parts[0].strip())
    rest = parts[1].strip() if len(parts) > 1 else ""
    duration = ""
    if rest.startswith('%'):
        token, _, rest = rest.partition(' ')
        seconds = ignore_mod.parse_duration(token[1:])
        if seconds is None:
            await respond(f"Invalid duration {token}: use e.g. %10m, %1h, %2d12h, %1y (%0 = permanent).")
            return
        duration = token[1:].lower() if seconds else ""
    comment = rest.strip()
    if not valid_hostmask(hostmask):
        await respond(HOSTMASK_RULE_TEXT)
        return

    async with get_db(core.db_path) as db:
        purged = await ignore_mod.purge_expired(db)
        # Owner/admin hostmasks are never ignorable (operator decision).
        for prot in await ignore_mod.protected_masks(db, local_subnet(core)):
            if ignore_mod.masks_overlap(hostmask, prot):
                await respond(f"Cannot ignore {hostmask}: it matches the owner/admin "
                              f"hostmask {prot}.")
                if purged:
                    _ignores_changed(core)
                return
        existing = await db.execute_fetchall(
            "SELECT hostmask FROM ignores WHERE LOWER(hostmask) = LOWER(?) AND deleted_at IS NULL",
            (hostmask,))
        if existing:
            await respond(f"{existing[0]['hostmask']} is already ignored.")
            if purged:
                _ignores_changed(core)
            return
        # A soft-deleted row would still hold the UNIQUE mask.
        await db.execute(
            "DELETE FROM ignores WHERE LOWER(hostmask) = LOWER(?) AND deleted_at IS NOT NULL",
            (hostmask,))
        await db.execute(
            "INSERT INTO ignores (hostmask, flags, comment, created_at, created_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (hostmask, duration, comment, int(time.time()), handle))
    _ignores_changed(core)
    span = f"for {duration}" if duration else "permanently"
    await respond(f"Now ignoring {hostmask} {span}" + (f" ({comment})" if comment else "") + ".")

async def cmd_delignore(core, handle: str, session_id: int, arg: str, respond):
    parts = arg.split()
    if len(parts) != 1:
        await respond("Usage: -ignore <hostmask>")
        return
    hostmask = ignore_mod.normalize_mask(parts[0])
    async with get_db(core.db_path) as db:
        purged = await ignore_mod.purge_expired(db)
        result = await db.execute(
            "DELETE FROM ignores WHERE LOWER(hostmask) = LOWER(?)", (hostmask,))
        removed = result.rowcount
    if removed or purged:
        _ignores_changed(core)
    if removed:
        await respond(f"No longer ignoring {hostmask}.")
    else:
        await respond(f"Not ignoring {hostmask}.")

async def cmd_chaddr(core, handle: str, session_id: int, arg: str, respond):
    if not await _require_flag(core, handle, "+n", respond, session_id=session_id):
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
        cursor = await db.execute(
            "SELECT handle FROM bots WHERE LOWER(handle) = LOWER(?) AND deleted_at IS NULL", (botname,))
        row = await cursor.fetchone()
        if not row:
            await respond(f"Bot {botname} not found!")
            return
        botname = row["handle"]
        await db.execute(
            "UPDATE bots SET address = ?, port = ? WHERE LOWER(handle) = LOWER(?)",
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
    # PLG-5 / D8: validate the name before any path or import use; the
    # existence check is against the plugins package, never the CWD.
    if not plugin_mod.valid_plugin_name(name):
        await respond(plugin_mod.PLUGIN_NAME_RULE_TEXT)
        return
    if name in core.plugin.plugins:
        await respond(f"{name} already loaded")
        return
    if not plugin_mod.plugin_exists(name):
        await respond(f"{name}.py not found in src/plugins/")
        return
    
    try:
        await core.plugin.load_plugin(name)
        await respond(f"Loaded {name}")
    except Exception as e:
        await respond(f"Failed to load {name}: {e}")

async def cmd_unload(core, handle: str, session_id: int, arg: str, respond):
    """unload <plugin> - Unload plugin (stays unloaded across restarts)"""
    args = arg.strip().split()
    if not args:
        await respond("Usage: .unload <plugin>")
        return
    
    name = args[0]
    if not plugin_mod.valid_plugin_name(name):
        await respond(plugin_mod.PLUGIN_NAME_RULE_TEXT)
        return
    if name not in core.plugin.plugins:
        await respond(f"{name} not loaded")
        return
    
    try:
        # PLG-4: through the manager, so loaded_modules records autoload=0.
        await core.plugin.unload_plugin(name)
        await respond(f"Unloaded {name}")
    except Exception as e:
        await respond(f"Failed to unload {name}: {e}")

async def cmd_plugin(core, handle: str, session_id: int, arg: str, respond):
    """plugin purge <plugin> - Delete a plugin's stored data (+A)"""
    if not await _require_flag(core, handle, "+A", respond, session_id=session_id):
        return
    args = arg.strip().split()
    if len(args) != 2 or args[0].lower() != "purge":
        await respond("Usage: .plugin purge <plugin>")
        return
    name = args[1]
    if not plugin_mod.valid_plugin_name(name):
        await respond(plugin_mod.PLUGIN_NAME_RULE_TEXT)
        return
    if name in core.plugin.plugins:
        await respond(f"{name} is loaded; .unload {name} first")
        return
    if not plugin_mod.plugin_exists(name):
        await respond(f"{name}.py not found in src/plugins/")
        return
    try:
        tables = await core.plugin.purge_plugin(name)
    except Exception as e:
        await respond(f"Failed to purge {name}: {e}")
        return
    log.warning("Plugin %s purged by %s (tables: %s)", name, handle, tables)
    if tables:
        await respond(f"Purged {name}: dropped {', '.join(tables)}")
    else:
        await respond(f"Purged {name}: it stores no tables")

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
    gstart <game> channel <#channel> [k=v ...]
    Example: .gstart duckhunt channel #wbs min_delay=15 max_delay=45
    Only the channel scope is supported (GAM-9).
    """
    args = arg.strip().split()
    if len(args) < 3:
        await respond("Usage: .gstart <game> channel <#channel> [k=v ...]"
                      "  (games run in channels only)")
        return

    game_name = args[0].lower()
    scope = args[1].lower()
    target = args[2]
    if scope not in SUPPORTED_SCOPES:
        await respond(f"Failed to start {game_name}: scope '{scope}' is not "
                      f"supported; games run in channels only "
                      f"(.gstart {game_name} channel <#channel>)")
        return
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
        stopped = await core.game.stop_game(game_name, scope, target)
    except Exception as e:
        await respond(f"Failed to stop {game_name}: {e}")
        return
    if stopped:
        await respond(f"Stopped {game_name} in {scope}:{target}")
    else:
        await respond(f"No such session: {game_name} in {scope}:{target}")


async def cmd_gpurge(core, handle: str, session_id: int, arg: str, respond):
    """gpurge <game> - Delete a game's stored data (+A)"""
    args = arg.strip().split()
    if len(args) != 1:
        await respond("Usage: .gpurge <game>")
        return
    name = args[0].lower()
    if name in core.game.games:
        await respond(f"{name} is loaded; .gunload {name} first")
        return
    if name not in _game_files():
        await respond(f"{name}.py not found in src/games/")
        return
    try:
        tables = await core.game.purge_game(name)
    except Exception as e:
        await respond(f"Failed to purge {name}: {e}")
        return
    log.warning("Game %s purged by %s (tables: %s)", name, handle, tables)
    if tables:
        await respond(f"Purged {name}: dropped {', '.join(tables)}")
    else:
        await respond(f"Purged {name}: it stores no tables")


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
    .chattr <user> [#channel] +/-<flags> [subnet_name|*]
    Flags: the one table, user.GLOBAL_FLAGS (case-sensitive; see .help chattr).
    Scope: omitted = this bot's subnet; '*' = the global row (all subnets).
    Global or foreign-subnet changes need a global +A grant (SAST-004);
    +n/-n needs an owner (+n) or the console.  A channel row is created on
    demand when the channel exists in that scope (USR-8).
    """
    parts = arg.split()
    usage = "Usage: .chattr <user> [#channel] +/-<flags> [subnet_name|*]"
    if len(parts) < 2:
        await respond(usage)
        return

    target = parts[0]
    flags = None
    scope_args: list[str] = []
    for tok in parts[1:]:
        if tok[:1] in ('+', '-'):
            if flags is not None:
                await respond(usage)
                return
            flags = tok
        else:
            scope_args.append(tok)

    if not flags:
        await respond("Flags must start with + or -")
        return

    channel, subnet_id, ok = await _parse_access_scope(core, scope_args, respond)
    if not ok:
        return
    if not await _authorize_scope_change(core, handle, subnet_id, respond, session_id):
        return

    # USR-5: no private letter map and no case folding; GLOBAL_FLAGS decides.
    if not await _apply_flags(core, handle, session_id, target, flags,
                              channel, subnet_id, respond):
        return

    await respond(f"Flags {flags} applied to {target}{_scope_text(channel, subnet_id)}")
    removed: set[str] = set()
    mode = '+'
    for ch in flags:
        if ch in '+-':
            mode = ch
        elif mode == '-':
            removed.add(GLOBAL_FLAGS[ch])
    if removed:
        await _warn_inherited(core, target, removed, channel, subnet_id, respond)
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

    Uses the authenticated, owner-bound relay protocol in relay.py (SAST-017):
    the remote bot runs input as this user under its own authorization and
    only if its operator listed this bot in botnet.relay_from.
    """
    relay = core.partyline.relay
    parts = arg.strip().split(maxsplit=1)

    # .relay with no args — disconnect from current relay
    if not parts:
        target = await relay.close_local(session_id)
        if target:
            await respond(f"Disconnected from relay: {target}")
        else:
            await respond("Not currently relayed to any bot.")
        return

    botnick = parts[0]
    remote_cmd = parts[1] if len(parts) > 1 else None
    _, message = await relay.open(session_id, botnick, remote_cmd)
    await respond(message)

def _has_op(m: str) -> bool:
    return any(c in 'qao' for c in m)


_MASS_ACTIONS = {
    # action: (sign, mode, member selector over prefix modes, bot needs)
    'op':      ('+', 'o', lambda m: not _has_op(m), 'op'),
    'deop':    ('-', 'o', lambda m: 'o' in m, 'op'),
    'voice':   ('+', 'v', lambda m: 'v' not in m, 'halfop'),
    'devoice': ('-', 'v', lambda m: 'v' in m, 'halfop'),
    'kick':    (None, None, lambda m: not _has_op(m), 'op'),
}


async def _is_protected(core, chan, nick: str) -> bool:
    """A recognised user with op-level access (+o/+A/+n here, or +o on the
    channel) or +f: .mass deop/devoice/kick leaves them alone (IRC-2)."""
    host = chan.hosts.get(nick.lower())
    if not host:
        return False
    who = await core.user.match_user(f"{nick}!{host}")
    if not who:
        return False
    scope = local_subnet(core)
    for spec in ('o', 'A', 'n', 'f'):
        if await core.user.matchattr(who, spec, subnet_id=scope):
            return True
    return await core.user.matchattr(who, '*|o', chan.name, subnet_id=scope)


async def cmd_mass(core, handle: str, session_id: int, arg: str, respond):
    """
    .mass <op|deop|voice|devoice|kick> <#channel> [kick reason]
    Mode or kick everyone in a channel the bot is in, from the live channel
    state (IRC-1).  The bot itself is skipped; deop/devoice/kick also skip
    recognised users with op access (+o/+A/+n, channel +o) or +f.  Modes are
    batched per the server's 005 MODES limit.
    """
    usage = "Usage: .mass <op|deop|voice|devoice|kick> <#channel> [reason]"
    if core.config.get("limbo_hub"):
        return await respond("Cannot use this command as limbo hub.")
    parts = arg.split(maxsplit=2)
    if len(parts) < 2:
        return await respond(usage)
    action, channel = parts[0].lower(), parts[1]
    reason = parts[2] if len(parts) > 2 else "Mass kick"
    if action not in _MASS_ACTIONS:
        return await respond(f"Unknown mass action: {action}. Valid: {', '.join(_MASS_ACTIONS)}")
    # Same rule as the partyline gate: +o, or +A/+n (which imply op rights).
    if not _is_console(core, session_id) and not await gate_allows(core, handle, "o"):
        return await respond("Access denied (need +o).")

    chan = core.live_channel(channel)
    if chan is None:
        return await respond(f"I'm not on {channel}.")
    if not chan.synced:
        return await respond(f"{channel} is still syncing, try again in a moment.")
    sign, mode, wanted, needs = _MASS_ACTIONS[action]
    if not (chan.bot_op or (needs == 'halfop' and chan.bot_halfop)):
        return await respond(f"I need {'op' if needs == 'op' else 'op or halfop'} on {channel}.")

    me = (core.botname or '').lower()
    targets = []
    skipped_bots = []
    for nick in chan.users:
        if nick == me or not wanted(chan.prefixes.get(nick, '')):
            continue
        if action in ('deop', 'devoice', 'kick') and await _is_protected(core, chan, nick):
            continue
        # NET-3: never change modes of a bot of another (or unknown) subnet.
        if mode and await is_same_subnet_bot(core, nick) is False:
            skipped_bots.append(nick)
            continue
        targets.append(nick)
    if skipped_bots:
        log.warning("Denied mass %s by %s on %s for %s: bot(s) outside the local subnet %s "
                    "(or of unknown subnet scope)", action, handle, channel,
                    ", ".join(skipped_bots), local_subnet(core))
        await respond(f"Skipped {', '.join(skipped_bots)}: bot(s) outside this bot's subnet "
                      f"(bots only op/mode bots of their own subnet).")
    if not targets:
        return await respond(f"No users to {action} in {channel}.")

    if action == 'kick':
        for nick in targets:
            core.send_irc({'cmd': 'kick', 'channel': channel, 'nick': nick, 'reason': reason})
    else:
        core.send_irc({'cmd': 'mass_mode', 'channel': channel, 'sign': sign,
                       'mode': mode, 'nicks': targets})
    await respond(f"Mass {action} sent for {len(targets)} user(s) in {channel}.")

def _net_nick_targets(subcmd: str, rest: str) -> list:
    """Nicks a `.net op|deop|mode` line would change modes of."""
    words = rest.split()
    if subcmd in ('op', 'deop'):
        return words[:1]
    if subcmd == 'mode' and len(words) > 1:
        err, changes = validate_mode_string(" ".join(words[1:]))
        if err:
            # Unparseable: treat every parameter as a possible nick.
            return words[2:]
        return [t for _, letter, t in changes if letter in NICK_MODES and t]
    return []


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

    # NET-3: an op/mode aimed at a bot of another (or unknown) subnet is
    # refused here, before anything is sent: neither this bot nor any peer
    # acts on it (peers would deny it too, authorize_peer_command).
    for nick in _net_nick_targets(subcmd, rest):
        if await _refuse_cross_subnet_bot(core, handle, nick, f"net {subcmd}", respond):
            return

    # Send only to same-subnet peers: ops/modes/restart never cross subnets (SAST-002).
    if hasattr(core, 'botnet') and core.botnet.peers:
        await core.botnet.broadcast_subnet(subcmd, rest)

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
        'die':     cmd_die,
    }
    if subcmd in local_cmds:
        await local_cmds[subcmd](core, handle, session_id, rest, respond)
    else:
        await respond(f"Unknown net subcmd: {subcmd}  (try .net help)")

def _subnet_mgr(core):
    """The live SubnetManager (keeps its cache in step), else a DB-only one."""
    mgr = getattr(getattr(core, 'botnet', None), 'subnet', None)
    return mgr if isinstance(mgr, SubnetManager) else SubnetManager(core.db_path)


def _proposed_subnet(core, bot: str):
    """(id, name|None) the live link of `bot` announced (NET-7), or None."""
    peers = getattr(getattr(core, 'botnet', None), 'peers', None)
    link = peers.get(bot.lower()) if isinstance(peers, dict) else None
    prop = getattr(link, 'proposed_subnet', None)
    return prop if isinstance(prop, tuple) else None


async def _find_subnet(core, ref: str):
    """Subnet row (id, name) for an id or a (case-insensitive) name, or None."""
    async with get_db(core.db_path) as db:
        sid = parse_subnet_id(ref)
        if sid is not None:
            cur = await db.execute("SELECT id, name FROM subnets WHERE id = ?", (sid,))
        else:
            cur = await db.execute(
                "SELECT id, name FROM subnets WHERE LOWER(name) = LOWER(?)", (ref,))
        return await cur.fetchone()


async def cmd_subnet(core, handle: str, session_id: int, arg: str, respond):
    """
    .subnet list
    .subnet add <name> [id]
    .subnet del <name|id>
    .subnet set <name|id> name <newname>
    """
    parts = arg.split()
    usage = ("Usage: .subnet list | .subnet add <name> [id] | .subnet del <name|id> | "
             ".subnet set <name|id> name <newname>")
    if not parts:
        await respond(usage)
        return

    subcmd = parts[0].lower()
    local_id = local_subnet(core)

    if subcmd == 'list':
        async with get_db(core.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT id, name FROM subnets WHERE deleted_at IS NULL ORDER BY id")
        if not rows:
            await respond("No subnets configured.")
            return
        mgr = _subnet_mgr(core)
        for r in rows:
            refs = await mgr.references(r['id'])
            info = []
            if r['id'] == local_id:
                info.append("this bot")
            for what in ("bots", "channels"):
                if refs.get(what):
                    info.append(f"{what}: {', '.join(refs[what])}")
            extra = f"  ({'; '.join(info)})" if info else ""
            await respond(f"  [{r['id']}] {r['name']}{extra}")
        return

    if subcmd not in ('add', 'del', 'set'):
        await respond(f"Unknown subnet subcmd: {subcmd}. Valid: list add del set")
        return
    if not await _require_flag(core, handle, "+A", respond, session_id=session_id):
        return

    if subcmd == 'add':
        if len(parts) not in (2, 3):
            await respond("Usage: .subnet add <name> [id]")
            return
        name = parts[1]
        sid = None
        if len(parts) == 3:
            sid = parse_subnet_id(parts[2])
            if sid is None:
                await respond(f"Invalid subnet id: {parts[2]!r} (use 1-{SUBNET_ID_MAX}).")
                return
        try:
            s = await _subnet_mgr(core).create(name, created_by=handle, subnet_id=sid)
        except ValueError as exc:
            await respond(str(exc))
            return
        await respond(f"Subnet added: [{s.id}] {s.name}")
        log.info("subnet: %s added subnet %s (id=%s)", handle, s.name, s.id)

    elif subcmd == 'del':
        if len(parts) != 2:
            await respond("Usage: .subnet del <name|id>")
            return
        row = await _find_subnet(core, parts[1])
        if not row:
            await respond(f"Unknown subnet: {parts[1]!r}")
            return
        ok, reason = await _subnet_mgr(core).delete(row['id'], local_id=local_id)
        if not ok:
            await respond(f"Subnet [{row['id']}] {row['name']} NOT deleted: {reason}.")
            return
        await respond(f"Subnet deleted: [{row['id']}] {row['name']}")
        log.info("subnet: %s deleted subnet %s (id=%s)", handle, row['name'], row['id'])

    else:  # set
        if len(parts) != 4:
            await respond("Usage: .subnet set <name|id> name <newname>")
            return
        ref, key, value = parts[1], parts[2].lower(), parts[3]
        if key != 'name':
            await respond("Allowed keys: name")
            return
        row = await _find_subnet(core, ref)
        if not row:
            await respond(f"Unknown subnet: {ref!r}")
            return
        try:
            await _subnet_mgr(core).rename(row['id'], value)
        except ValueError as exc:
            await respond(str(exc))
            return
        await respond(f"Subnet [{row['id']}] renamed: {row['name']} -> {value}")

async def cmd_taskset(core, handle: str, session_id: int, arg: str, respond):
    """
    .taskset <task> on|off|interval=<seconds>   (NET-9)
    Switch a Core registry task on/off or change its interval; the choice is
    saved (task_settings) and applied again after a restart.
    """
    usage = "Usage: .taskset <task> on|off|interval=<seconds>"
    parts = arg.split()
    if len(parts) != 2:
        await respond(usage)
        return
    name, action = parts[0], parts[1].lower()
    reg = getattr(core, 'tasks', None)
    if reg is None or name not in reg.tasks:
        await respond(f"Unknown task: {name}. See .tasks for the list.")
        return
    try:
        if action in ('on', '1', 'enable', 'yes'):
            await reg.set_enabled(name, True)
            await respond(f"Task {name} enabled (every {int(reg.tasks[name].interval)}s).")
        elif action in ('off', '0', 'disable', 'no'):
            await reg.set_enabled(name, False)
            await respond(f"Task {name} disabled.")
        elif action.startswith('interval='):
            raw = action.split('=', 1)[1]
            if not raw.isdigit():
                await respond(f"Invalid interval {raw!r}: whole seconds expected.")
                return
            await reg.set_interval(name, int(raw))
            await respond(f"Task {name} interval set to {int(raw)}s.")
        else:
            await respond(usage)
    except ValueError as e:
        await respond(str(e))

async def cmd_tasks(core, handle: str, session_id: int, arg: str, respond):
    """
    .tasks — the Core's periodic jobs with state, interval, last/next run
    and last error (NET-9).
    """
    reg = getattr(core, 'tasks', None)
    if reg is None or not reg.tasks:
        await respond("No tasks registered.")
        return
    for line in format_tasks(reg.tasks.values()):
        await respond(line)

async def cmd_timers(core, handle: str, session_id: int, arg: str, respond):
    """
    .timers — the timers of the IRC process, asked over the IRC queue; the
    answer arrives as an IRC_TIMERS event (NET-9).
    """
    p = ircreq.for_core(core).add_timers(respond)
    core.send_irc({'cmd': 'timers', 'req_id': p.nick})

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

    Setting another user's password is a password reset, so each target
    goes through the same hierarchy/scope check as .chpass (SAST-020):
    accounts the caller may not reset are skipped and left unchanged.
    """
    async with get_db(core.db_path) as db:
        rows = await db.execute_fetchall(
            "SELECT handle FROM users WHERE (password IS NULL OR password = '') AND deleted_at IS NULL"
        )

    if not rows:
        await respond("No users without passwords.")
        return

    async def _quiet(_msg):
        pass

    allowed, skipped = [], []
    for r in rows:
        uhandle = r['handle']
        if (uhandle.lower() == str(handle).lower() and not _is_console(core, session_id)) \
                or await _authorize_password_reset(core, handle, uhandle, _quiet, session_id):
            allowed.append(uhandle)
        else:
            skipped.append(uhandle)

    alphabet = string.ascii_letters + string.digits
    fixed = []
    for uhandle in allowed:
        pw = ''.join(secrets.choice(alphabet) for _ in range(12))
        hashed = await crypto_exec.hash_password(pw)
        async with get_db(core.db_path) as db:
            cur = await db.execute(
                "UPDATE users SET password = ? WHERE handle = ? AND deleted_at IS NULL "
                "AND (password IS NULL OR password = '')", (hashed, uhandle))
            await db.commit()
        if cur.rowcount > 0:
            fixed.append((uhandle, pw))

    await respond(f"Set random passwords for {len(fixed)} user(s):")
    for uhandle, pw in fixed:
        await respond(f"  {uhandle}: {pw}")
    if skipped:
        await respond(f"Skipped {len(skipped)} user(s) you may not reset "
                      f"(admins/owners need +n, or outside your scope): {', '.join(skipped)}")
    for uhandle, _pw in fixed:
        if uhandle.lower() != str(handle).lower():
            _revoke_sessions(core, uhandle, f"your password was set by {handle}")
        log.info("fixpass: %s set a password for %s", handle, uhandle)
    await respond("Users should change their password with .chpass immediately.")

async def cmd_baway(core, handle: str, session_id: int, arg: str, respond):
    """
    .baway [reason] — set the bot away on IRC.
    """
    reason = clean_message(arg.strip()) or "Away"
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
    if not valid_nick(new_nick):
        await respond(f"Invalid nick '{new_nick[:40]}'. {NICK_RULE_TEXT}")
        return
    if new_nick == core.botname:
        await respond(f"Already using nick {new_nick}")
        return
    if not core.connected:
        await respond("Not connected to IRC.")
        return
    ircreq.for_core(core).add_nick(new_nick, respond)
    core.irc_q.put_nowait({'cmd': 'nick', 'nick': new_nick})

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
    .swhois <nick> — WHOIS on the IRC server; the server's answer is sent
    back to the caller (IRC-10).
    """
    await _server_whois(core, "whois", "swhois", arg, respond)

async def cmd_swhowas(core, handle: str, session_id: int, arg: str, respond):
    """
    .swhowas <nick> — WHOWAS on the IRC server; the answer is sent back to
    the caller (IRC-10).
    """
    await _server_whois(core, "whowas", "swhowas", arg, respond)

async def _server_whois(core, kind: str, cmd: str, arg: str, respond):
    words = arg.split()
    if not words:
        await respond(f"Usage: .{cmd} <nick>")
        return
    nick = words[0]
    if not valid_nick(nick):
        await respond(NICK_RULE_TEXT)
        return
    if not core.connected:
        await respond("Not connected to IRC.")
        return
    ircreq.for_core(core).add_whois(kind, nick, respond)
    core.irc_q.put_nowait({'cmd': kind, 'nick': nick})
    await respond(f"{kind.upper()} sent for {nick}; waiting for the server (10 s).")

async def cmd_servlinks(core, handle: str, session_id: int, arg: str, respond):
    """
    .servlinks — the IRC server's LINKS list (servers of the IRC network),
    returned to the caller (NET-12).  Not the botnet: see .bots.
    """
    if not core.connected:
        await respond("Not connected to IRC.")
        return
    ircreq.for_core(core).add_links(respond)
    core.irc_q.put_nowait({'cmd': 'raw', 'line': 'LINKS'})
    await respond("LINKS sent; waiting for the server (10 s).")

async def cmd_links(core, handle: str, session_id: int, arg: str, respond):
    """.links — old name of .servlinks (it lists IRC servers, not botnet links)."""
    await respond(".links was renamed .servlinks (it lists IRC servers; "
                  "use .bots for botnet links).")
    await cmd_servlinks(core, handle, session_id, arg, respond)

def _botnet_endpoint(core):
    """(address to give other bots, listen host, listen port) of this bot (NET-11)."""
    host, port = botnet_listen(core.config)
    return botnet_public_address(core.config) or '<your.host>', host, port

async def cmd_infoleaf(core, handle: str, session_id: int, arg: str, respond):
    """
    .infoleaf — show the command to add this bot as a leaf on another bot.
    """
    address, host, port = _botnet_endpoint(core)
    await respond(f"Botnet listener: {host}:{port}")
    if address == '<your.host>':
        await respond("Set botnet.address in config.json to the host name other bots "
                      "should connect to.")
    await respond("To add this bot as a leaf on another hub, run:")
    await respond(f"  .addleaf {core.botname} {address} {port}")


async def cmd_addleaf(core, handle: str, session_id: int, arg: str, respond):
    """
    .addleaf <botnick> <host> <port>
    Register a leaf bot and print the reciprocal addhub command.
    """
    parts = arg.split()
    if len(parts) != 3:
        await respond("Usage: .addleaf <botnick> <host> <port>")
        return
    botnick, host, port = parts
    if await _register_bot(core, botnick, None, host, port, respond):
        await respond(f"Leaf {botnick} ({host}:{parse_port(port)}) added.")
        await respond(f"Now run on {botnick}:")
        my_addr, _h, my_port = _botnet_endpoint(core)
        await respond(f"  .addhub {core.botname} {my_addr} {my_port}")

async def cmd_addhub(core, handle: str, session_id: int, arg: str, respond):
    """
    .addhub <botnick> <host> <port>
    Register a hub bot to connect to.
    """
    parts = arg.split()
    if len(parts) != 3:
        await respond("Usage: .addhub <botnick> <host> <port>")
        return
    botnick, host, port = parts
    if await _register_bot(core, botnick, None, host, port, respond):
        await respond(f"Hub {botnick} ({host}:{parse_port(port)}) added. Use .link {botnick} to connect.")

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
    if not getattr(core.update, "configured", True):
        await respond(f"{core.update.NOT_CONFIGURED}.")     # SYS-8
        return
    manifest = await core.update.check_update()
    if manifest:
        await respond(f"Update available: {manifest.version_str} by {manifest.author}")
    elif getattr(core.update, "last_error", None):
        await respond(f"Update check failed: {core.update.last_error}")
    else:
        await respond("Already up to date.")
    return

async def cmd_update(core, handle: str, session_id: int, arg: str, respond):
    """`.update [confirm]` — check, then (with `confirm`) install the latest version."""
    words = (arg or "").split()
    if words and words != ["confirm"]:
        await respond("Usage: .update [confirm]")
        return
    if not getattr(core.update, "configured", True):
        await respond(f"{core.update.NOT_CONFIGURED}.")     # SYS-8
        return
    manifest = await core.update.check_update()
    if not manifest:
        if getattr(core.update, "last_error", None):
            await respond(f"Update check failed: {core.update.last_error}")
        else:
            await respond("No update available.")
        return
    if words != ["confirm"]:
        # SYS-8: installing replaces the running code; ask for it explicitly.
        await respond(f"Update available: {manifest.version_str} by {manifest.author}. "
                      f"Type '.update confirm' to install it.")
        return
    await respond(f"Installing {manifest.version_str}…")
    ok = await core.update.perform_update(manifest)
    if ok:
        await respond("Update installed. Restart the bot to load new code.")
    else:
        reason = getattr(core.update, "last_error", None) or "see logs"
        await respond(f"Update failed; previous version kept: {reason}")
    return

def _blocklist_guard(core):
    """The AccessGuard that owns net_blocklist (None if this core has none)."""
    return getattr(core, "guard", None)

async def cmd_denyhost(core, handle: str, session_id: int, arg: str, respond):
    """
    .denyhost <mask> [minutes|%XdXhXm] [reason]
    Deny a host mask (IP, CIDR, or host glob such as *.example.net) at the
    botlink / telnet listener and for DCC CHAT.  No duration = permanent.
    Requires +A (COMMAND_MIN_FLAGS).
    """
    if not await _require_flag(core, handle, "+A", respond, session_id=session_id):
        return
    usage = "Usage: .denyhost <ip|cidr|host-glob> [minutes|%XdXhXm] [reason]"
    parts = arg.split(None, 1)
    if not parts:
        await respond(usage)
        return
    mask = normalize_host_mask(parts[0])
    if mask is None:
        await respond(HOST_MASK_RULE_TEXT)
        return
    rest = parts[1].strip() if len(parts) > 1 else ""
    seconds = 0
    first, _, tail = rest.partition(" ")
    if first.startswith("%"):
        parsed = ignore_mod.parse_duration(first[1:])
        if parsed is None:
            await respond(f"Invalid duration {first}: use e.g. %10m, %1h, %2d12h (%0 = permanent).")
            return
        seconds, rest = parsed, tail.strip()
    elif first.isdigit():
        if int(first) > ignore_mod.MAX_DURATION // 60:
            await respond(f"Invalid duration {first}: too long.")
            return
        seconds, rest = int(first) * 60, tail.strip()
    reason = rest[:200]

    guard = _blocklist_guard(core)
    if guard is None:
        await respond("No connection guard on this bot; the blocklist is unavailable.")
        return
    expires = int(time.time()) + seconds if seconds else 0
    stored = await guard.block(ip=mask, reason="manual", added_by=handle or "console",
                               expires_at=expires, note=reason)
    if stored is None:
        await respond(HOST_MASK_RULE_TEXT)
        return
    when = f"for {ignore_mod.format_duration(seconds)}" if seconds else "permanently"
    log.info("denyhost: %s denied %s %s (%s)", handle, stored, when, reason or "no reason")
    await respond(f"Denied {stored} {when}" + (f": {reason}" if reason else "") + ".")

async def cmd_permithost(core, handle: str, session_id: int, arg: str, respond):
    """
    .permithost <mask>
    Remove the deny for <mask>; if a wider deny still covers it, store a
    permit that overrides that deny.  Automatic auth-failure bans of an
    overlapping wider mask are not overridden.  Requires +A.
    """
    if not await _require_flag(core, handle, "+A", respond, session_id=session_id):
        return
    parts = arg.split()
    if len(parts) != 1:
        await respond("Usage: .permithost <ip|cidr|host-glob>")
        return
    if normalize_host_mask(parts[0]) is None:
        await respond(HOST_MASK_RULE_TEXT)
        return
    guard = _blocklist_guard(core)
    if guard is None:
        await respond("No connection guard on this bot; the blocklist is unavailable.")
        return
    mask, removed, permitted = await guard.permit(parts[0], added_by=handle or "console")
    log.info("permithost: %s permitted %s (removed=%s, permit=%s)",
             handle, mask, removed, permitted)
    if permitted:
        prefix = f"Removed the deny for {mask}; " if removed else f"Permitted {mask}: "
        await respond(prefix + "it is allowed despite wider deny entries.")
    elif removed:
        await respond(f"Removed {mask} from the blocklist.")
    else:
        await respond(f"{mask} was not denied.")

async def cmd_blocklist(core, handle: str, session_id: int, arg: str, respond):
    """
    .blocklist
    Show the net blocklist: denies, permits and automatic failure bans.
    Requires +A.
    """
    if not await _require_flag(core, handle, "+A", respond, session_id=session_id):
        return
    guard = _blocklist_guard(core)
    if guard is None:
        await respond("No connection guard on this bot; the blocklist is unavailable.")
        return
    await guard._purge_expired()
    entries = guard.list_blocked()
    if not entries:
        await respond("Blocklist is empty.")
        return

    await respond(f"{'Mask':<24} {'Type':<12} {'By':<12} {'Expires':<17} Note")
    for e in sorted(entries, key=lambda x: (x.added_at, x.ip)):
        exp = (datetime.fromtimestamp(e.expires_at).strftime("%Y-%m-%d %H:%M")
               if e.expires_at else "never")
        kind = "PERMIT" if e.reason == PERMIT_REASON else e.reason
        await respond(f"{e.ip:<24} {kind:<12} {e.added_by:<12} {exp:<17} {e.note}")
    await respond(f"Total entries: {len(entries)}")

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
      share=all|subnet|none   share_level: what data is replicated with this peer
                              (none: nothing; subnet: local-subnet data only;
                              all: data of every subnet the peer is in; full = all)
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
        cursor = await db.execute(
            "SELECT * FROM bots WHERE LOWER(handle) = LOWER(?) AND deleted_at IS NULL", (target,))
        row = await cursor.fetchone()
    if not row:
        await respond(f"Bot not found: {target}")
        return
    # Bot handles are case-insensitive: work on the stored spelling from here on.
    target = row["handle"]

    # No further args → display current attrs
    if not tokens:
        role   = row["role"] or "none"
        share  = normalize_share_level(row["share_level"])
        al     = "yes" if row["autolink"] else "no"
        retry  = row["autolink_retry_interval"] or 60
        addr   = f"{row['address']}:{row['port']}"
        flags  = ""
        if row["autolink"]:        flags += "a"
        if role == "hub":          flags += "h"
        elif role == "backup":     flags += "b"
        elif role == "leaf":       flags += "l"
        subnet = row["subnet_id"] if row["subnet_id"] is not None else "unset"
        prop = _proposed_subnet(core, target)
        proposed = (f" proposed={prop[0]}" + (f"({prop[1]})" if prop[1] else "")) if prop else ""
        pw = " password=****" if row["password"] else ""
        await respond(f"Bot {target}: flags=[{flags or 'none'}] role={role} "
                      f"share={share} autolink={al} retry={retry}s addr={addr} subnet={subnet}"
                      f"{proposed}{pw}")
        return

    # ---- Parse tokens ----
    flag_updates: dict[str, object] = {}
    kv_updates:   dict[str, object] = {}

    VALID_SHARE  = {"all", "full", "subnet", "none"}
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
            elif k == "subnet":
                # Authoritative peer scope (SAST-002); local only, never replicated.
                if v.lower() in ("none", "-"):
                    kv_updates["subnet_id"] = None
                else:
                    proposed = v.lower() == "proposed"
                    if proposed:
                        # Operator accepts the subnet the live peer announced (NET-7).
                        prop = _proposed_subnet(core, target)
                        if not prop:
                            await respond(f"{target} has not announced a subnet "
                                          f"(it must be linked first).")
                            return
                        v = str(prop[0])
                    async with get_db(core.db_path) as db:
                        if v.isdigit():
                            cur = await db.execute(
                                "SELECT id FROM subnets WHERE id = ? AND deleted_at IS NULL",
                                (parse_subnet_id(v) or 0,))
                        else:
                            cur = await db.execute(
                                "SELECT id FROM subnets WHERE LOWER(name) = LOWER(?) AND deleted_at IS NULL",
                                (v,))
                        srow = await cur.fetchone()
                    if not srow:
                        if proposed and prop[1]:
                            hint = f".subnet add {prop[1]} {prop[0]}"
                        elif v.isdigit():
                            hint = f".subnet add <name> {v}"
                        else:
                            hint = f".subnet add {v} <id>"
                        await respond(f"Unknown subnet: {v!r} (create it first: {hint}; "
                                      f"see .subnet list)")
                        return
                    kv_updates["subnet_id"] = int(srow["id"])
            else:
                await respond(f"Unknown key: {k!r}  (valid: retry share pass comment role subnet)")
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
            f"updated_by = ? WHERE LOWER(handle) = LOWER(?) AND deleted_at IS NULL",
            values + [handle, target]
        )
        await db.commit()

    # The botlink key is never echoed or logged (NET-8).
    shown = {k: ("****" if k == "password" else v) for k, v in all_updates.items()}
    changes = "  ".join(f"{k}={v}" for k, v in shown.items())
    await respond(f"botattr {target}: {changes}")
    log.info("botattr: %s updated %s → %s", handle, target, shown)
    if hasattr(core, 'botnet'):
        if "subnet_id" in all_updates or "share_level" in all_updates:
            # Re-scope a live link immediately (SAST-002 / SAST-003).
            await core.botnet.refresh_peer_scope(target)
        # Never broadcast the botlink pre-shared key (SAST-001), the locally
        # authoritative subnet scope (SAST-002) or share policy (SAST-003).
        synced = {k: v for k, v in all_updates.items() if k not in _BOTATTR_LOCAL_ONLY}
        if synced:
            asyncio.create_task(core.botnet.sync_bot_access({
                "handle": target,
                "flags": synced,
            }))

async def cmd_restart(core, handle: str, session_id: int, arg: str, respond) -> None:
    """Full restart: Core exits, supervisor relaunches. Requires '+A' (admin) flag."""
    if not await _require_flag(core, handle, "+A", respond, session_id=session_id):
        return

    await respond("Restarting...")
    log.info("Restart initiated by %s", handle)
    await core.do_restart()

async def cmd_rehash(core, handle: str, session_id: int, arg: str, respond) -> None:
    """Rehash: restart Core process, IRC stays connected. Requires '+A' (admin) flag."""
    if not await _require_flag(core, handle, "+A", respond, session_id=session_id):
        return

    await respond("Rehashing...")
    log.info("Rehash initiated by %s", handle)
    await core.do_rehash()

async def cmd_plugins(core, handle: str, session_id: int, arg: str, respond):
    await _list_loadables(core, respond, "plugin", "plugins", "plugins")

async def cmd_games(core, handle: str, session_id: int, arg: str, respond):
    await _list_loadables(core, respond, "game", "games", "games")
    await respond("Games run in channels only: .gstart <game> channel <#channel>")

async def cmd_detach(core, handle, session_id, arg, respond):
    """Console only: send the foreground bot to the background (USR-9)."""
    session = core.partyline.sessions.get(session_id, {})
    if session.get('type') != 'console':
        await respond("Error: .detach is only valid for console sessions.")
        return
    can_detach = getattr(core, 'can_detach', None)
    if not callable(can_detach) or not can_detach():
        await respond("Cannot detach: this console is not running under the WBS "
                      "supervisor. Use .die to stop the bot.")
        return
    await respond("Detaching. Bot continues in background. Reconnect via telnet or DCC.")
    core.partyline.unregister_session(session_id)
    core.request_detach()

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
    'die': cmd_die,
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
    'servlinks':    cmd_servlinks,
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
    'chaninfo': cmd_chaninfo,
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
    'plugin': cmd_plugin,
    'load': cmd_load,
    'unload': cmd_unload,
    # games
    'games': cmd_games,
    'gload': cmd_gload,
    'gunload': cmd_gunload,
    'gpurge': cmd_gpurge,
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

# README / eggdrop-style names (USR-2).  An alias is the SAME handler object as
# the real command; partyline.py gives it the real command's COMMAND_MIN_FLAGS
# entry and relay.py its relay block, so an alias is never less restricted.
ALIASES: dict[str, str] = {
    'adduser':    '+user',
    'deluser':    '-user',
    'showuser':   'userinfo',
    'listusers':  'users',
    'passwd':     'chpass',
    'addhost':    '+host',
    'delhost':    '-host',
    'addignore':  '+ignore',
    'delignore':  '-ignore',
}
COMMANDS.update({_alias: COMMANDS[_real] for _alias, _real in ALIASES.items()})