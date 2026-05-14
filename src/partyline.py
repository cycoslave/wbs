# src/partyline.py
"""
Partyline hub - coordinates chat between console, telnet, DCC, and botnet
"""
import asyncio
import logging
from typing import Optional
from .user import UserManager

log = logging.getLogger("wbs.partyline")

class Partyline:
    """Central partyline hub - runs in core process, manages all sessions"""
    
    def __init__(self, core):
        self.core = core
        self.irc_q = self.core.irc_q
        
        # Session registry: session_id -> session info
        self.sessions = {}  # {session_id: {'type': 'console/telnet/dcc', 'handle': str, 'queue': Queue}}
        self.relay_sessions: dict = {}  # relay_key → {handle, origin, orig_sid, respond}
        self.next_id = 0
        
        # Console session (special case - no queue, direct output)
        self.console_session_id = None
        self.console_output_callback = None
        self.user = UserManager(self.core.config['db']['path']) 
        
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

        relay_target = session.get('relay_to')
        if relay_target:
            # '.relay' alone always disconnects regardless of what remote thinks
            if text.strip() in ('.relay', '.disconnect'):
                session.pop('relay_to', None)
                session.pop('relay_origin', None)
                if relay_target in self.core.botnet.peers:
                    await self.core.botnet.send_to_peer(relay_target, {
                        'type': 'RELAY_CLOSE',
                        'from': session['handle'],
                        'session_id': session_id,
                        'origin': self.core.botname
                    })
                await self._send(session_id, f"Relay closed. Back on {self.core.botname}.")
                return

            # Forward everything else verbatim to remote bot's partyline
            await self.core.botnet.send_to_peer(relay_target, {
                'type': 'RELAY_INPUT',
                'from': session['handle'],
                'session_id': session_id,
                'origin': self.core.botname,
                'text': text
            })
            return

        # Normal local dispatch
        await self.dispatch_command(session['handle'], session_id, text)
    
    async def _handle_command(self, session_id: int, handle: str, text: str):
        """Handle partyline command"""
        parts = text[1:].split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        
        # Console has full access
        #is_console = self.sessions[session_id]['type'] == 'console'
        
        #if not is_console:
        #    # Check user flags
        #    user = await self.user.get(handle)
        #    if not user or 'n' not in user.flags:
        #        self.send_to_session(session_id, "Access denied.")
        #        return
        
        # Dispatch to commands.py
        from .commands import COMMANDS
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
        """Broadcast to all sessions (console callback, remote queues)."""
        if not local_only:
            asyncio.create_task(
                self.core.botnet.broadcast_chat(self.core.botname, message, exclude=self.core.botname)
            )
        for session_id, session in self.sessions.items():
            if session_id == exclude_session:
                continue
            if session['type'] == 'console':
                if session.get('output'):
                    session['output'](message)
            elif session['queue']: 
                try:
                    session['queue'].put_nowait({'type': 'MESSAGE', 'text': message})
                except:
                    log.warning(f"Failed to send to session {session_id}")

    def send_to_session(self, session_id: int, message: str):
        """Send message to specific session (command response)"""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        
        if session['type'] == 'console':
            if session['output']:
                session['output'](message)
        elif session['type'] == 'telnet':
            if hasattr(self, 'core') and session_id in self.core.party_sessions:
                telnet_session = self.core.party_sessions[session_id]
                asyncio.create_task(telnet_session.send(message))
                log.debug(f"TELNET direct send to session {session_id}")
                return     
        else:
            if session['queue']:
                try:
                    session['queue'].put_nowait({
                        'type': 'RESPONSE',
                        'text': message
                    })
                except:
                    log.warning(f"Failed to send response to session {session_id}")