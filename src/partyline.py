# src/partyline.py
"""Partyline hub - coordinates chat between console, telnet, DCC, and botnet"""

import asyncio
import multiprocessing as mp
import logging
from typing import Dict, Optional
from .user import UserManager

logger = logging.getLogger(__name__)

class PartylineHub:
    """Central partyline hub - runs in core process, manages all sessions"""
    
    def __init__(self, core):
        self.core = core
        self.irc_q = self.core.irc_q
        self.botnet_q = self.core.botnet_q
        
        # Session registry: session_id -> session info
        self.sessions = {}  # {session_id: {'type': 'console/telnet/dcc', 'handle': str, 'queue': Queue}}
        self.next_id = 1
        
        # Console session (special case - no queue, direct output)
        self.console_session_id = None
        self.console_output_callback = None
        self.user_mgr = UserManager('db/wbs.db') 
        
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
        
        logger.info(f"Console registered as partyline session {session_id}")
        self.broadcast(f"*** {handle} joined the partyline (console)", exclude_session=session_id)
        return session_id
    
    def register_remote(self, session_type: str, handle: str, response_queue: mp.Queue):
        """Register telnet/DCC session (separate process)"""
        session_id = self.next_id
        self.next_id += 1
        
        self.sessions[session_id] = {
            'type': session_type,
            'handle': handle,
            'queue': response_queue,
            'output': None
        }
        
        logger.info(f"Remote session {session_id} ({session_type}) registered for {handle}")
        self.broadcast(f"*** {handle} joined the partyline ({session_type})", exclude_session=session_id)
        return session_id
    
    def unregister_session(self, session_id: int):
        """Remove session from partyline"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            handle = session['handle']
            self.broadcast(f"*** {handle} left the partyline")
            del self.sessions[session_id]
            logger.info(f"Session {session_id} unregistered")
    
    async def handle_input(self, session_id: int, text: str):
        """Handle input from any partyline session"""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        handle = session['handle']
        
        if text.startswith('.'):
            # Command - handle locally
            await self._handle_command(session_id, handle, text)
        else:
            # Chat - broadcast
            self.broadcast(f"<{handle}> {text}", exclude_session=session_id)
            
            # Forward to botnet
            if self.botnet_q:
                self.botnet_q.put_nowait({
                    'type': 'PARTYLINE_CHAT',
                    'from': handle,
                    'text': text
                })
    
    async def _handle_command(self, session_id: int, handle: str, text: str):
        """Handle partyline command"""
        parts = text[1:].split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        
        # Console has full access
        is_console = self.sessions[session_id]['type'] == 'console'
        
        if not is_console:
            # Check user flags
            user = await self.user_mgr.get_user(handle)
            if not user or 'n' not in user.flags:
                self.send_to_session(session_id, "Access denied.")
                return
        
        # Dispatch to commands.py
        from .commands import COMMANDS
        if cmd in COMMANDS:
            try:
                async def respond(msg: str):
                    self.send_to_session(session_id, msg)
                
                await COMMANDS[cmd](self.core, handle, session_id, arg, respond)
            except Exception as e:
                logger.error(f"Command '{cmd}' error: {e}")
                self.send_to_session(session_id, f"Error executing .{cmd}")
        else:
            self.send_to_session(session_id, f"Unknown command .{cmd} (.help)")
    
    async def on_command_response(self, session_id: int, message: str):
        """Commands call this to send responses back to session"""
        self.send_to_session(session_id, message)
    
    def broadcast(self, message: str, exclude_session: Optional[int] = None):
        """Broadcast message to all partyline sessions"""
        for session_id, session in self.sessions.items():
            if session_id == exclude_session:
                continue
            
            if session['type'] == 'console':
                # Console: use callback
                if session['output']:
                    session['output'](message)
            else:
                # Remote: use queue
                if session['queue']:
                    try:
                        session['queue'].put_nowait({
                            'type': 'MESSAGE',
                            'text': message
                        })
                    except:
                        logger.warning(f"Failed to send to session {session_id}")
    
    def send_to_session(self, session_id: int, message: str):
        """Send message to specific session (command response)"""
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        
        if session['type'] == 'console':
            if session['output']:
                session['output'](message)
        else:
            if session['queue']:
                try:
                    session['queue'].put_nowait({
                        'type': 'RESPONSE',
                        'text': message
                    })
                except:
                    logger.warning(f"Failed to send response to session {session_id}")


class PartylineSession:
    """Remote partyline session (telnet/DCC) - runs in separate process"""
    
    def __init__(self, session_id: int, session_type: str, handle: str, 
                 core_q: mp.Queue, response_q: mp.Queue):
        self.session_id = session_id
        self.session_type = session_type
        self.handle = handle
        self.core_q = core_q
        self.response_q = response_q
        self.running = True
    
    async def run(self):
        """Session main loop"""
        logger.info(f"Session {self.session_id} ({self.session_type}) started")
        
        if self.session_type == 'telnet':
            await self._handle_telnet()
        elif self.session_type == 'dcc':
            await self._handle_dcc()
    
    async def _handle_telnet(self):
        """Handle telnet connection (future)"""
        # Read from socket, send to hub via core_q
        # Listen to response_q, send to socket
        pass
    
    async def _handle_dcc(self):
        """Handle DCC connection (future)"""
        pass
