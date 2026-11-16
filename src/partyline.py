# src/partyline.py
"""
Partyline hub - coordinates chat between console, telnet, DCC, and botnet
"""
import asyncio
import logging
from typing import Optional

from .commands import COMMANDS, ALIASES
from .helper import gate_allows
from .logsafe import command_error
from .relay import RelayManager

log = logging.getLogger("wbs.partyline")
VALID_REMOTE_SESSION_TYPES = frozenset({'telnet', 'dcc', 'bot'})
# Centralized partyline authorization policy.
# Maps command name (without leading dot) -> required global flag using
# UserManager.matchattr. None means no additional flags beyond having a
# partyline session.
COMMAND_MIN_FLAGS: dict[str, Optional[str]] = {
    # Low‑impact / informational
    "help": None,
    "version": None,
    "date": None,
    "time": None,
    "uptime": None,

    # Basic partyline usage
    "whoami": "p",
    "who": "p",
    "whom": "p",
    "handle": "p",
    "chpass": "p",
    "whois": "p",
    "quit": None,   # leave the partyline: any session may close itself

    # Channel‑op style actions (require global +o)
    "mode": "o",
    "op": "o",
    "deop": "o",
    "voice": "o",
    "devoice": "o",
    "mass": "o",

    # High‑impact admin/maintenance commands (require +A)
    "die": "A",
    "restart": "A",
    "backup": "A",
    "status": "A",
    "checkupdate": "A",
    "update": "A",
    "blocklist": "A",
    "permithost": "A",
    "denyhost": "A",
    "detach": "A",

    # User / access management
    "chattr": "A",
    "+user": "A",
    "-user": "A",
    "userinfo": "A",
    "users": "A",
    "addaccess": "A",
    "delaccess": "A",
    "lockuser": "A",
    "unlockuser": "A",
    "nopass": "A",
    "fixpass": "A",

    # Bot / botnet management
    "+bot": "A",
    "-bot": "A",
    "bots": "A",
    "link": "A",
    "unlink": "A",
    "chaddr": "A",
    "infoleaf": "A",
    "addleaf": "A",
    "addhub": "A",
    "net": "A",
    "subnet": "A",
    "relay": "A",
    "botattr": "A",

    # Channel list / lifecycle
    "channels": "A",
    "+chan": "A",
    "-chan": "A",
    "chaninfo": "A",

    # Scheduler / timers
    "taskset": "A",
    "tasks": "A",
    "timers": "A",

    # IRC identity / presence for the bot
    "baway": "A",
    "bback": "A",
    "nick": "A",

    # Plugins and games (can run arbitrary code / network IO)
    "plugins": "A",
    "plugin": "A",
    "load": "A",
    "unload": "A",
    "games": "A",
    "gload": "A",
    "gunload": "A",
    "gpurge": "A",
    "gstart": "A",
    "gstop": "A",
    "gsessions": "A",

    # Complete the table (USR-6 / IRC-4 / NET-10): every key of
    # commands.COMMANDS needs an entry, else the gate below answers
    # "Unknown command" even to an admin (tests/test_command_flags.py).
    # Channel actions as the bot (require global +o)
    "say": "o",
    "msg": "o",
    "act": "o",
    # IRC server tools; read-only for the bot, but they cost server traffic
    "sdns": "o",
    "swhois": "o",
    "swhowas": "o",
    "links": "o",
    "servlinks": "o",
    "lag": "p",
    # Bot maintenance / info (host details: pid, cwd, OS)
    "rehash": "A",
    "botinfo": "A",
    # Account management beyond the caller's own handle
    "chusercomment": "A",
    "chhandle": "A",
    "+host": "A",
    "-host": "A",
    # Channel lifecycle aliases of +chan / -chan
    "join": "A",
    "part": "A",
    # Ignore list: reading is for ops, changing it is admin-only
    "ignores": "o",
    "+ignore": "A",
    "-ignore": "A",
}

# USR-2: aliases (commands.ALIASES) are gated exactly like the command they
# name; copying the entry keeps `.adduser` from ever being weaker than `.+user`.
COMMAND_MIN_FLAGS.update({alias: COMMAND_MIN_FLAGS[real] for alias, real in ALIASES.items()})

class Partyline:
    """Central partyline hub - runs in core process, manages all sessions"""
    
    def __init__(self, core):
        self.core = core
        self.irc_q = self.core.irc_q
        
        # Session registry: session_id -> session info
        self.sessions = {}  # {session_id: {'type': 'console/telnet/dcc', 'handle': str, 'queue': Queue}}
        # Interactive botnet relay, both directions (SAST-017; see relay.py).
        # Inbound relayed users get virtual sessions of type 'relay' here.
        self.relay = RelayManager(core, self)
        self.next_id = 0
        
        # Console session (special case - no queue, direct output)
        self.console_session_id = None
        self.console_output_callback = None
        
    def register_console(self, handle: str, output_callback):
        """Register console as partyline session (main process, no multiprocessing)"""
        session_id = self.next_id
        self.next_id += 1
        
        self.sessions[session_id] = {
            'type': 'console',
            'handle': handle,
            'queue': None,  # Console uses callback instead
            'output': output_callback
        }
        
        self.console_session_id = session_id
        self.console_output_callback = output_callback
        
        log.info(f"Console registered as partyline session {session_id}")
        self.broadcast(f"*** {handle} joined the partyline (console)", exclude_session=session_id)
        return session_id
    
    def register_remote(self, sessiontype: str, handle: str, responsequeue=None):
        if sessiontype not in VALID_REMOTE_SESSION_TYPES:
            raise ValueError(
                f"Invalid session type {sessiontype!r}. "
                f"Allowed: {', '.join(sorted(VALID_REMOTE_SESSION_TYPES))}"
            )
        sessionid = self.next_id
        self.next_id += 1
        self.sessions[sessionid] = {'type': sessiontype, 'handle': handle, 'queue': responsequeue}
        log.info(f"Remote session {sessionid} ({sessiontype}) registered for {handle}")
        self.broadcast(f"{handle} joined the partyline ({sessiontype})", exclude_session=sessionid)
        return sessionid
    
    def unregister_session(self, session_id: int):
        """Remove session from partyline"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            handle = session['handle']
            self.broadcast(f"*** {handle} left the partyline")
            del self.sessions[session_id]
            self.relay.session_ended(session_id)
            log.info(f"Session {session_id} unregistered")

    def revoke_session(self, session_id, reason: str) -> bool:
        """
        Forcibly end a non-console partyline session (SAST-004): the user was
        locked or deleted.  The session is removed first, so any further input
        on it is ignored even if the transport close is still in flight.
        """
        session = self.sessions.get(session_id)
        if not session or session.get('type') == 'console':
            return False
        handle = session.get('handle')
        self.send_to_session(session_id, f"*** Session closed: {reason}.")
        del self.sessions[session_id]
        self.relay.session_ended(session_id, reason)
        log.warning("Revoked partyline session %s of %s (%s)", session_id, handle, reason)

        # Close the transport but leave transport bookkeeping (party_sessions,
        # DCC _sessions, listener slot release) to the normal disconnect path.
        transports = []
        party = (getattr(self.core, 'party_sessions', None) or {}).get(session_id)
        if party is not None:
            party.running = False
            transports.append(party)
        dcc_sessions = getattr(getattr(self.core, 'dcc', None), '_sessions', None)
        dcc = dcc_sessions.get(session_id) if isinstance(dcc_sessions, dict) else None
        if dcc is not None:
            transports.append(dcc)
        try:
            loop = asyncio.get_running_loop()
            for t in transports:
                close = getattr(t, 'close', None)
                if close is not None:
                    loop.create_task(close())
        except RuntimeError:
            pass  # No running loop: the session is already detached from the partyline
        self.broadcast(f"*** {handle} left the partyline", local_only=True)
        return True

    def revoke_handle(self, handle: str, reason: str) -> int:
        """Revoke every open non-console session of `handle`; returns how many."""
        if not handle:
            return 0
        target = handle.lower()
        sids = [sid for sid, s in list(self.sessions.items())
                if str(s.get('handle') or '').lower() == target and s.get('type') != 'console']
        return sum(1 for sid in sids if self.revoke_session(sid, reason))

    def rename_handle(self, old: str, new: str) -> int:
        """
        A user was renamed in the DB (USR-3/USR-4): carry their open local
        sessions over to the new handle.  Call only AFTER the DB rename
        committed.  Matches the stored spelling exactly.  Relay sessions are
        left alone: they re-authorize the old name on their next line and
        close (fail closed).  Returns how many sessions were renamed.
        """
        if not old or not new:
            return 0
        renamed = 0
        for sid, s in list(self.sessions.items()):
            if s.get('handle') != old or s.get('type') in ('console', 'relay'):
                continue
            s['handle'] = new
            renamed += 1
            # Transport objects keep their own copy (DCC one-session-per-handle,
            # telnet log lines).
            party = (getattr(self.core, 'party_sessions', None) or {}).get(sid)
            dcc_sessions = getattr(getattr(self.core, 'dcc', None), '_sessions', None)
            dcc = dcc_sessions.get(sid) if isinstance(dcc_sessions, dict) else None
            for t in (party, dcc):
                if t is not None and getattr(t, 'handle', None) == old:
                    t.handle = new
        if renamed:
            log.info("Renamed %d live session(s) %s -> %s", renamed, old, new)
        return renamed
    
    async def handle_input(self, session_id: int, text: str):
        session = self.sessions.get(session_id)
        if not session:
            return

        # A local session with a persistent relay forwards its input (SAST-017).
        relay = self.relay.outbound_for(session_id)
        if relay is not None:
            if (session.get('type') != 'console'
                    and not await self.core.user.is_active(session['handle'])):
                # Locked/deleted user: no more relayed input (SAST-004).
                self.revoke_session(session_id, "your account is locked or deleted")
                return
            if text.strip() in ('.relay', '.disconnect'):
                target = await self.relay.close_local(session_id)
                self.send_to_session(session_id,
                                     f"Relay to {target} closed. Back on {self.core.botname}.")
                return
            await self.relay.send_input(session_id, text)
            return

        await self._handle_command(session_id, session['handle'], text)
    
    async def _handle_command(self, session_id: int, handle: str, text: str):
        """Handle partyline command.

        This is the single choke‑point for partyline authorization. All
        .commands must pass through here so we can enforce UserManager
        matchattr() checks before dispatching to commands.py.

        SAST-004: every input of a non-console session re-checks that the
        user is still active (not locked / deleted) and evaluates flags in
        this bot's subnet scope, so revocations apply to already-open
        sessions on their next request.
        """
        # Console has full access
        is_console = self.sessions.get(session_id, {}).get('type') == 'console'

        if not is_console and not await self.core.user.is_active(handle):
            log.warning("Partyline input from inactive (locked/deleted) user %s on "
                        "session %s: revoking", handle, session_id)
            self.revoke_session(session_id, "your account is locked or deleted")
            return

        if not text.startswith('.'):
            # Non‑command input is treated as chat on the partyline.
            self.broadcast(f"{handle}: {text}", exclude_session=session_id)
            return

        parts = text[1:].split(maxsplit=1)
        if not parts:
            return
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if not is_console:
            # Map command to minimum required flag; fall back to +p for
            # commands that are not explicitly listed.
            if cmd not in COMMAND_MIN_FLAGS:
                self.send_to_session(session_id, f"Unknown command .{cmd}   (Type .help)")
                log.warning("Blocked unknown command .%s from %s (not in COMMAND_MIN_FLAGS)", cmd, handle)
                return

            required_flag = COMMAND_MIN_FLAGS[cmd]

            if required_flag:
                # matchattr defaults to positive semantics when no +/- prefix.
                # Scope: global grants plus grants for this bot's own subnet.
                allowed = await gate_allows(self.core, handle, required_flag)
                if not allowed:
                    self.send_to_session(session_id, f"Access denied for .{cmd} (need +{required_flag}).")
                    return
        
        # Dispatch to commands.py
        if cmd in COMMANDS:
            try:
                async def respond(msg: str):
                    self.send_to_session(session_id, msg)
                
                await COMMANDS[cmd](self.core, handle, session_id, arg, respond)
            except Exception as e:
                command_error(log, cmd, e)
                self.send_to_session(session_id, f"Error executing .{cmd}")
        else:
            self.send_to_session(session_id, f"Unknown command .{cmd}   (Type .help)")
    
    async def on_command_response(self, session_id: int, message: str):
        """Commands call this to send responses back to session"""
        self.send_to_session(session_id, message)
    
    def broadcast(self, message: str, local_only=False, exclude_session: Optional[int] = None):
        if not local_only and self.core.botnet and self.core.botnet.peers:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(
                    self.core.botnet.broadcast_chat(self.core.botname, message, exclude=self.core.botname)
                )
            except RuntimeError:
                pass  # No running loop; skip botnet broadcast
        for session_id, session in self.sessions.items():
            if session_id == exclude_session:
                continue
            if session['type'] in ('console', 'relay'):
                if session.get('output'):
                    session['output'](message)
            elif session['queue']: 
                try:
                    session['queue'].put_nowait({'type': 'MESSAGE', 'text': message})
                except asyncio.QueueFull as e:
                    log.warning("Queue full for session %s: %s", session_id, e)

    def send_to_session(self, session_id: int, message: str):
        """Send message to specific session (command response)"""
        if session_id not in self.sessions:
            return

        session = self.sessions[session_id]

        if session['type'] in ('console', 'relay'):
            # console: local callback; relay: synchronous write to the origin
            # bot's link (relay.py), never awaited.
            if session.get('output'):
                session['output'](message)
        elif session['type'] == 'telnet':
            party_sessions = getattr(self.core, 'party_sessions', None)
            if party_sessions and session_id in party_sessions:
                try:
                    asyncio.get_running_loop().create_task(party_sessions[session_id].send(message))
                    log.debug("TELNET direct send to session %s", session_id)
                except RuntimeError:
                    log.warning("No running event loop; cannot send to telnet session %s", session_id)
            else:
                log.warning("Telnet session %s not found in core.party_sessions", session_id)
        else:
            if session.get('queue'):
                try:
                    session['queue'].put_nowait({
                        'type': 'RESPONSE',
                        'text': message
                    })
                except asyncio.QueueFull as e:
                    log.warning("Queue full for session %s: %s", session_id, e)
                except Exception as e:
                    log.warning("Failed to send response to session %s: %s", session_id, e)
