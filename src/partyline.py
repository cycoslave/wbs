# src/partyline.py
"""Partyline session manager - spawns processes per connection"""

import multiprocessing as mp
import logging

logger = logging.getLogger(__name__)

class PartylineManager:
    """Manages partyline sessions (not a process itself)"""
    
    def __init__(self, core_queue):
        self.core_queue = core_queue
        self.sessions = {}  # session_id -> Process
        self.next_id = 1
        
    def spawn_session(self, source_type, source_info):
        """Spawn a partyline session process on-demand
        
        Args:
            source_type: 'console', 'telnet', 'dcc'
            source_info: dict with connection details
        """
        session_id = self.next_id
        self.next_id += 1
        
        session = PartylineSession(
            session_id=session_id,
            source_type=source_type,
            source_info=source_info,
            core_queue=self.core_queue
        )
        
        proc = mp.Process(target=session.run, name=f"Partyline-{session_id}")
        proc.start()
        
        self.sessions[session_id] = {
            'process': proc,
            'type': source_type,
            'info': source_info
        }
        
        logger.info(f"Spawned partyline session {session_id} ({source_type})")
        return session_id
        
    def close_session(self, session_id):
        """Terminate a partyline session"""
        if session_id in self.sessions:
            self.sessions[session_id]['process'].terminate()
            del self.sessions[session_id]
            logger.info(f"Closed partyline session {session_id}")


class PartylineSession:
    """Individual partyline session - runs as separate process"""
    
    def __init__(self, session_id, source_type, source_info, core_queue):
        self.session_id = session_id
        self.source_type = source_type
        self.source_info = source_info
        self.core_queue = core_queue
        self.response_queue = mp.Queue()
        
    def run(self):
        """Session process main loop"""
        logger.info(f"Session {self.session_id} started ({self.source_type})")
        
        try:
            if self.source_type == 'console':
                # Should not reach here - console uses main process
                logger.error("Console should not spawn partyline session")
                return
                
            elif self.source_type == 'telnet':
                self._handle_telnet()
                
            elif self.source_type == 'dcc':
                self._handle_dcc()
                
        except Exception as e:
            logger.error(f"Session {self.session_id} error: {e}")
            
    def _handle_telnet(self):
        """Handle telnet connection (future)"""
        # socket = self.source_info['socket']
        # Read from socket, send to core_queue, relay responses
        pass
        
    def _handle_dcc(self):
        """Handle DCC chat connection (future)"""
        # Similar to telnet but via DCC protocol
        pass

class PartylineService:
    """Partyline service - listens for connections"""
    
    def __init__(self, command_queue):
        self.command_queue = command_queue
        
    async def start_telnet_server(self, port=3333):
        """Future: Telnet listener"""
        # asyncio.start_server(...)
        pass