# src/partyline.py
"""
Partyline hub - coordinates chat between console, telnet, DCC, and botnet
"""
import asyncio
import logging
from typing import Optional
from dataclasses import dataclass

from .commands import COMMANDS

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

    # Channel‑op style actions (require global +o)
    "mode": "o",
    "op": "o",
    "deop": "o",
    "voice": "o",
    "devoice": "o",
    "mass": "o",

    # High‑impact admin/maintenance commands (require +A)
    "quit": "A",
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
    "load": "A",
    "unload": "A",
    "games": "A",
    "gload": "A",
    "gunload": "A",
    "gstart": "A",
    "gstop": "A",
    "gsessions": "A",
}

@dataclass
class RelaySession:
    """Tracks an active relay connection from a local session to a remote bot."""
    handle: str           # local user's handle
    origin: str           # local bot name (self)
    target: str           # remote bot name being relayed to
    orig_sid: int         # local session_id this relay belongs to

class Partyline:
    """Central partyline hub - runs in core process, manages all sessions"""
    
    def __init__(self, core):
        self.core = core
        self.irc_q = self.core.irc_q
        
        # Session registry: session_id -> session info
        self.sessions = {}  # {session_id: {'type': 'console/telnet/dcc', 'handle': str, 'queue': Queue}}
        self.relay_sessions: dict[int, RelaySession] = {}  # session_id → RelaySession
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
            log.info(f"Session {session_id} unregistered")
    
    async def handle_input(self, session_id: int, text: str):
        session = self.sessions.get(session_id)
        if not session:
            return

        # Check relay_sessions instead of inline session keys
        relay = self.relay_sessions.get(session_id)
        if relay:
            if text.strip() in ('.relay', '.disconnect'):
                del self.relay_sessions[session_id]  # clean removal
                if relay.target in self.core.botnet.peers:
                    await self.core.botnet.send_to_peer(relay.target, {
                        'type': 'RELAY_CLOSE',
                        'from': relay.handle,
                        'session_id': session_id,
                        'origin': relay.origin
                    })
                await self._send(session_id, f"Relay closed. Back on {self.core.botname}.")
                return

            await self.core.botnet.send_to_peer(relay.target, {
                'type': 'RELAY_INPUT',
                'from': relay.handle,
                'session_id': session_id,
                'origin': relay.origin,
                'text': text
            })
            return

        await self._handle_command(session_id, session['handle'], text)
    
    async def _handle_command(self, session_id: int, handle: str, text: str):
        """Handle partyline command.

        This is the single choke‑point for partyline authorization. All
        .commands must pass through here so we can enforce UserManager
        matchattr() checks before dispatching to commands.py.
        """
        if not text.startswith('.'):
            # Non‑command input is treated as chat on the partyline.
            self.broadcast(f"{handle}: {text}", exclude_session=session_id)
            return

        parts = text[1:].split(maxsplit=1)
        if not parts:
            return
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        
        # Console has full access
        is_console = self.sessions.get(session_id, {}).get('type') == 'console'

        if not is_console:
            # Map command to minimum required flag; fall back to +p for
            # commands that are not explicitly listed.
            if cmd not in COMMAND_MIN_FLAGS:
                self.send_to_session(session_id, f"Unknown command .{cmd}   (Type .help)")
                log.warning("Blocked unknown command .%s from %s (not in COMMAND_MIN_FLAGS)", cmd, handle)
                return

            required_flag = COMMAND_MIN_FLAGS[cmd]

            if required_flag:
                # matchattr defaults to positive semantics when no +/- prefix
                flagspec = required_flag
                allowed = await self.core.user.matchattr(handle, flagspec)
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
                log.error(f"Command '{cmd}' error: {e}")
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
            if session['type'] == 'console':
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

        if session['type'] == 'console':
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

    def open_relay(self, session_id: int, target_bot: str) -> bool:
        """Open a relay session from session_id to a remote bot. Returns False if already in relay."""
        if session_id in self.relay_sessions:
            return False
        session = self.sessions.get(session_id)
        if not session:
            return False
        self.relay_sessions[session_id] = RelaySession(
            handle=session['handle'],
            origin=self.core.botname,
            target=target_bot,
            orig_sid=session_id
        )
        log.info("Relay opened: session %s -> %s", session_id, target_bot)
        return True