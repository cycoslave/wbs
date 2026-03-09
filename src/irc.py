# src/irc.py
"""
IRC client process
"""
import os
import queue
import threading
import time
import logging
import json
import asyncio
import irc.bot
from datetime import datetime, timedelta
from irc.client import ServerConnectionError

from .user import UserManager
from .channel import ChannelManager
from . import __version__

log = logging.getLogger("wbs.irc")

# Event type constants
class EventType:
    PUBMSG = 'PUBMSG'
    PRIVMSG = 'PRIVMSG'
    NEWCHAN = 'NEWCHAN'
    JOIN = 'JOIN'
    PART = 'PART'
    NICK = 'NICK'
    MODE = 'MODE'
    KICK = 'KICK'
    QUIT = 'QUIT'
    COMMAND = 'COMMAND'
    READY = 'READY'
    DISCONNECT = 'DISCONNECT'
    ERROR = 'ERROR'
    WHOIS_USER = 'WHOIS_USER'
    WHOIS_END = 'WHOIS_END'


class WbsIrcBot(irc.bot.SingleServerIRCBot):
    """IRC bot instance - pure dispatcher, no business logic"""
    
    def __init__(self, config, core_q, irc_q):
        self.config = config
        self.chan = ChannelManager(self.config['db']['path'])
        self.user = UserManager(self.config['db']['path'])
        self.core_q = core_q
        self.irc_q = irc_q
        self.config_id = config.get('id', 1)
        self.whois_trackers = {}  # Track pending WHOIS requests
        self.maintenance_state = {
            'last_rejoin': {},         # channel -> timestamp
            'last_nick': 0,            # timestamp
            'linked_bots': {}          # handle -> current_nick
        }
        self.irc_timers = {}  # name → task
        servers = self._parse_servers(config)
        bot_config = config.get('bot', {})
        super().__init__(
            servers,
            bot_config.get('nick', 'wbs'),
            bot_config.get('realname', 'WBS Bot')
        )
        self._emit_event({'type': 'REQUEST_BOTLINKS'})

    def _parse_servers(self, config: dict) -> list[tuple[str, int]]:
        """Extract server list from config (supports multiple formats)"""
        try:
            # New format: config['bot']['servers'] = [{'host': ..., 'port': ...}]
            servers_list = config['bot']['servers']
            return [(s['host'], s['port']) for s in servers_list]
        except (KeyError, TypeError):
            # Legacy format: config['server'], config['port']
            host = config.get('server', 'irc.wcksoft.com')
            port = config.get('port', 6667)
            return [(host, port)]
    
    def _emit_event(self, event_data: dict):
        """Send event to core.py via queue"""
        event_data['config_id'] = self.config_id
        try:
            self.core_q.put(event_data, block=False)
        except queue.Full:
            log.error(f"Event queue full, dropping: {event_data['type']}")
        
    def _connect(self):
        """Override to handle connection errors gracefully"""
        try:
            super()._connect()
        except ServerConnectionError as e:
            log.error(f"Connection failed: {e}")
            self._emit_event({
                'type': EventType.ERROR,
                'data': 'connect_fail',
                'error': str(e)
            })

    def is_op(self, chan: str, nick: str) -> bool:
        """Check if nick is op on channel"""
        if chan in self.channels:
            return self.channels[chan].is_oper(nick)
        return False

    def on_chan(self, chan: str, nick: str) -> bool:
        """Check if nick is present in channel"""
        if chan in self.channels:
            return self.channels[chan].has_user(nick)
        return False

    def is_bot_op(self, chan: str) -> bool:
        """Check if bot is op on channel"""
        return self.is_op(chan, self.connection.get_nickname())
    
    def is_voice(self, chan: str, nick: str) -> bool:
        """Check if nick is voiced on channel"""
        if chan in self.channels:
            return self.channels[chan].is_voiced(nick)
        return False

    def is_online(self, nick: str) -> bool:
        """Check if nick is online anywhere (global users)"""
        return any(nick in chan.users for chan in self.connection.channels.values())

    @property 
    def is_connected(self) -> bool:
        """Connected to IRC server?"""
        return self.connection.is_connected()

    def on_welcome(self, conn, event):
        """Connected and registered - join channels"""
        log.info(f"Connected as {conn.get_nickname()}")
        conn.mode(conn.get_nickname(), "+i-ws")
        numerics = {
            '332': self.on_332,    # RPL_TOPIC
            '324': self.on_324,    # RPL_CHANNELMODEIS
            '329': self.on_329,    # RPL_CHANNELCREATETIME
            '367': self.on_367,    # RPL_BANLIST
            '346': self.on_346,    # RPL_INVITELIST
            '348': self.on_348,    # RPL_EXCEPTLIST
            '368': self.on_368,    # RPL_ENDOFBANLIST etc.
            '347': self.on_347,    # RPL_ENDOFINVITELIST
            '349': self.on_349,    # RPL_ENDOFEXCEPTLIST
        }
        for numeric, handler in numerics.items():
            conn.add_global_handler(numeric, handler, -20)
        self._emit_event({
            'type': EventType.READY,
            'botname': conn.get_nickname()
        })
    
    def on_disconnect(self, conn, event):
        """Connection lost"""
        log.warning("Disconnected from server")
        self._emit_event({
            'type': EventType.ERROR,
            'data': 'disconnect'
        })
        self._emit_event({'type': EventType.DISCONNECT})
        
    def on_pubmsg(self, conn, event):
        """Public channel message"""
        text = event.arguments[0]
        event_data = {
            'type': EventType.PUBMSG,
            'channel': event.target,
            'nick': event.source.nick,
            'host': str(event.source),
            'text': text
        }
        log.debug(f"[IRC] Emitting PUBMSG: {event_data}")
        self._emit_event(event_data)
    
    def on_privmsg(self, conn, event):
        """Private message"""
        self._emit_event({
            'type': EventType.PRIVMSG,
            'target': event.target,
            'nick': event.source.nick,
            'host': str(event.source),
            'text': event.arguments[0]
        })
    
    def on_join(self, conn, event):
        nick = event.source.nick
        chan = event.target
        if nick in self.maintenance_state['linked_bots'].values():
            pass
        if nick.lower() ==  conn.get_nickname().lower():
            chan_obj = self.channels.get(chan)
            if chan_obj:
                log.info(f"Building snapshot for {chan}")
                    
                try:
                    snapshot = {
                        'users': len(chan_obj.users()),
                        'user_list': list(chan_obj.users()),
                        'bot_op': self.is_bot_op(chan),  # Use your existing helper method
                        'ops': list(chan_obj.opers()),
                        'voiced': list(chan_obj.voiced()),
                        'mode': getattr(chan_obj, 'mode', ''),
                        'mode_params': getattr(chan_obj, 'mode_params', {})
                    }
                    log.debug(f"Successfully added {chan} to snapshot")
                    
                except Exception as inner_e:
                    log.error(f"Error building snapshot for {chan}: {inner_e}", exc_info=True)
            self._emit_event({
                'type': EventType.NEWCHAN,
                'channel': chan,
                'nick': nick,
                'host': str(event.source),
                'irc_data': snapshot
            })
        else:
            self._emit_event({
                'type': EventType.JOIN,
                'channel': chan,
                'nick': nick,
                'host': str(event.source)
            })
    
    def on_part(self, conn, event):
        reason = event.arguments[0] if event.arguments else ''
        self._emit_event({
            'type': EventType.PART,
            'channel': event.target,
            'nick': event.source.nick,
            'reason': reason
        })
    
    def on_kick(self, conn, event):
        kicked_nick = event.arguments[0]
        reason = event.arguments[1] if len(event.arguments) > 1 else ''
        channel = event.target
        if kicked_nick == conn.get_nickname():
            if self.chan.exist(channel):
                conn.join(channel)
        self._emit_event({
            'type': EventType.KICK,
            'channel': channel,
            'nick': event.source.nick,
            'kicked': kicked_nick,
            'reason': reason
        })
    
    def on_quit(self, conn, event):
        reason = event.arguments[0] if event.arguments else ''
        self._emit_event({
            'type': EventType.QUIT,
            'nick': event.source.nick,
            'reason': reason
        })
    
    def on_nick(self, conn, event):
        self._emit_event({
            'type': EventType.NICK,
            'old_nick': event.source.nick,
            'new_nick': event.target
        })
    
    def on_mode(self, conn, event):
        channel = event.target.lower()
        modes = event.arguments[0].lower() if event.arguments else ''
        mode_args = event.arguments[1:] if len(event.arguments) > 1 else []
        self._emit_event({
            'type': EventType.MODE,
            'channel': channel,
            'modes': modes,
            'args': mode_args,
            'nick': event.source.nick
        })
    
    def on_ctcp(self, conn, event):
        """Handle CTCP requests (PING, VERSION, etc)"""
        nick = event.source.nick
        ctcp_cmd = event.arguments[0].upper()
        
        if ctcp_cmd == 'PING':
            ts = event.arguments[1] if len(event.arguments) > 1 else ''
            conn.ctcp_reply(nick, f"PING {ts}")
        elif ctcp_cmd == 'VERSION':
            conn.ctcp_reply(nick, f"VERSION WBS {__version__}")
        else:
            super().on_ctcp(conn, event)
    
    def on_invite(self, conn, event):
        """Join channel on invite if tracked in DB"""
        inviter_nick = event.source.nick
        channel = event.arguments[0]
        
        if self.chan.exist(channel):
            conn.join(channel)
            log.info(f"Joined {channel} on invite from {inviter_nick}")
            self._emit_event({
                'type': 'ON_INVITE',
                'channel': channel,
                'inviter': inviter_nick,
                'solicitation': 'Solicited'
            })
        else:
            log.debug(f"Ignored invite to {channel} from {inviter_nick}")
            self._emit_event({
                'type': 'ON_INVITE',
                'channel': channel,
                'inviter': inviter_nick,
                'solicitation': 'Unsolicited'
            })

    def on_332(self, conn, event):  # RPL_TOPIC
        chan_name = event.arguments[1]
        topic = event.arguments[2]
        self._emit_event({
            'type': 'CHANNEL_TOPIC',
            'channel': chan_name,
            'topic': topic
        })

    def on_324(self, conn, event):  # RPL_CHANNELMODEIS
        chan_name = event.arguments[1]
        modes_str = ' '.join(event.arguments[2:])
        self._emit_event({
            'type': 'CHANNEL_MODES',
            'channel': chan_name,
            'modes_str': modes_str
        })

    def on_329(self, conn, event):  # RPL_CHANNELCREATIONTIME
        chan_name = event.arguments[1]
        created_ts = int(event.arguments[2])
        self._emit_event({
            'type': 'CHANNEL_CREATED',
            'channel': chan_name,
            'created': created_ts
        })

    def on_367(self, conn, event):  # RPL_BANLIST
        chan_name, ban_mask = event.arguments[1:3]
        self._emit_event({
            'type': 'BANLIST_ADD',
            'channel': chan_name,
            'ban': ban_mask
        })

    def on_346(self, conn, event):  # RPL_INVITELIST
        chan_name, invite_mask = event.arguments[1:3]
        self._emit_event({
            'type': 'INVITELIST_ADD',
            'channel': chan_name,
            'invite': invite_mask
        })

    def on_348(self, conn, event):  # RPL_EXCEPTLIST
        chan_name, exempt_mask = event.arguments[1:3]
        self._emit_event({
            'type': 'EXEMPTLIST_ADD',
            'channel': chan_name,
            'exempt': exempt_mask
        })

    def on_368(self, conn, event):  # RPL_ENDOFBANLIST
        chan_name = event.arguments[1]
        self._emit_event({
            'type': 'BANLIST_END',
            'channel': chan_name
        })

    def on_347(self, conn, event):  # RPL_ENDOFINVITELIST
        chan_name = event.arguments[1]
        self._emit_event({
            'type': 'INVITELIST_END',
            'channel': chan_name
        })

    def on_349(self, conn, event):  # RPL_ENDOFEXCEPTLIST
        chan_name = event.arguments[1]
        self._emit_event({
            'type': 'EXCEPTLIST_END',
            'channel': chan_name
        })                

    def on_whoisuser(self, conn, event):
        """WHOIS response (311 numeric)"""
        # event.arguments = [mynick, nick, user, host, *, realname]
        nick = event.arguments[1]
        req_id = hash(nick)
        
        if req_id in self.whois_trackers:
            self._emit_event({
                'type': EventType.WHOIS_USER,
                'nick': nick,
                'user': event.arguments[2],
                'host': event.arguments[3],
                'realname': event.arguments[5]
            })
    
    def on_endofwhois(self, conn, event):
        """WHOIS complete (318 numeric)"""
        nick = event.arguments[1]
        req_id = hash(nick)
        
        if req_id in self.whois_trackers:
            del self.whois_trackers[req_id]
            self._emit_event({
                'type': EventType.WHOIS_END,
                'nick': nick
            })
        
    def execute_command(self, cmd_data: dict):
        """Execute command from cmd_queue (called by poller thread)"""
        cmd = cmd_data.get('cmd')
        
        try:
            if cmd == 'UPDATE_BOTLINK':
                self.maintenance_state['linked_bots'] = cmd_data['botlinks']   

            elif cmd == 'BOTLINK_LINK':
                handle = cmd_data['handle']
                nick = cmd_data['nick']
                self.maintenance_state['linked_bots'][handle] = nick

            elif cmd == 'BOTLINK_UNLINK':
                handle = cmd_data['handle']
                if handle in self.maintenance_state['linked_bots']:
                    del self.maintenance_state['linked_bots'][handle]

            elif cmd == 'REGISTER_IRC_TIMER':
                name = cmd_data['name']
                interval = cmd_data['interval']
                self.loop.call_soon_threadsafe(self._schedule_register_timer, name, interval)
            
            elif cmd == 'UNREGISTER_IRC_TIMER':
                name = cmd_data['name']
                self.loop.call_soon_threadsafe(self._schedule_unregister_timer, name)

            else:
                if not self.connection.is_connected():
                    log.error(f"Not connected, dropping command: {cmd}")
                    return
                
                if cmd == 'msg':
                    self.connection.privmsg(cmd_data['target'], cmd_data['text'])
                
                elif cmd == 'notice':
                    self.connection.notice(cmd_data['target'], cmd_data['text'])
                
                elif cmd == 'action':
                    self.connection.action(cmd_data['target'], cmd_data['text'])
                
                elif cmd == 'join':
                    self.connection.join(cmd_data['channel'])
                
                elif cmd == 'part':
                    reason = cmd_data.get('reason', '')
                    self.connection.part(cmd_data['channel'], reason)
                
                elif cmd == 'mode':
                    self.connection.mode(cmd_data['channel'], cmd_data['modes'])

                elif cmd == 'quit':
                    self.connection.quit(cmd_data['message'])
                    time.sleep(2.0)
                    self.core_q.put_nowait({'cmd': 'quit', 'message': cmd_data['message']})
                
                elif cmd == 'kick':
                    reason = cmd_data.get('reason', 'Kicked')
                    self.connection.kick(
                        cmd_data['channel'],
                        cmd_data['nick'],
                        reason
                    )
                
                elif cmd == 'whois':
                    nick = cmd_data['nick']
                    req_id = hash(nick)
                    self.whois_trackers[req_id] = {'nick': nick}
                    self.connection.whois(nick)

                elif cmd == 'raw':
                    self.connection.send_raw(cmd_data['line'])
                
                else:
                    if cmd is not None:
                        log.error(f"[IRC] Unknown command: {cmd}")
        
        except Exception as e:
            log.error(f"Command failed {cmd_data}: {e}")

    async def maintenance_loop(self):
        """Maintenance every 30s (uncommented _enforce_settings later)"""
        while True:  # Add while True
            try:
                if self.is_connected:  # Check first
                    # Clean timers
                    for name, task in list(self.irc_timers.items()):
                        if task.done():
                            del self.irc_timers[name]
                    
                    await self._check_channels()
                    await self._check_nick()
                    # await self._enforce_settings()
                
                await asyncio.sleep(30)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Maintenance error: {e}")
                await asyncio.sleep(60) 

    async def _check_channels(self):
        """Rejoin active channels if missing"""
        try:
            if not self.is_connected:
                return
            
            active_chans = await self.chan.getchans() or []
            now = datetime.now()
            
            # Fix: self.channels (dict str -> Channel), not self.connection.channels
            current_chans = {chan_name.lower(): chan for chan_name, chan in self.channels.items()}
            
            log.debug(f"Active: {active_chans}, Current: {list(current_chans)}")
            
            for chan in active_chans:
                chan_lower = chan.lower()
                if chan_lower not in current_chans:
                    last_try = self.maintenance_state['last_rejoin'].get(chan, datetime.min)
                    if now - last_try > timedelta(minutes=1):
                        self.connection.join(chan)
                        self.maintenance_state['last_rejoin'][chan] = now
                        log.info(f"Rejoined {chan}")
                        
        except Exception as e:
            log.error(f"_check_channels error: {e}", exc_info=True)

    async def _check_nick(self):
        """Enforce bot nick if taken"""
        current_nick = self.connection.get_nickname()
        desired_nick = self.config['bot'].get('nick', 'wbs')

        if self.is_connected:
            if current_nick != desired_nick:
                now = datetime.now()
                attempts = self.maintenance_state['last_nick']
                last = attempts.get('last', now)
                
                if now - last > timedelta(minutes=1):
                    self.connection.nick(desired_nick)
                    attempts['last'] = now
                    log.info(f"Regaining nick: {desired_nick}")

    async def _enforce_settings(self):
        """Apply locks/limits/topiclock from DB"""
        if self.is_connected:
            channels = await self.chan.get_all_channels()
            for chan_obj in channels:
                if chan_obj.name not in self.connection.channels:
                    continue
                    
                now = datetime.now()
                
                # Channel lock
                #if chan_obj.is_locked and now - datetime.fromtimestamp(chan_obj.lock_at) > timedelta(minutes=1):
                #    irc_q.put({'cmd': 'part', 'channel': chan_obj.name, 'reason': f'Locked by {chan_obj.lock_by}'})
                
                # Topic lock
                #if chan_obj.is_topiclock and now - datetime.fromtimestamp(chan_obj.topiclock_at) > timedelta(minutes=1):
                #    irc_q.put({'cmd': 'topic', 'channel': chan_obj.name, 'topic': chan_obj.topiclock})
                #    self.maintenance_state['last_topic'][chan_obj.name] = now
                
                # Limit
                #if chan_obj.is_limit and now - datetime.fromtimestamp(chan_obj.limit_at) > timedelta(minutes=2):
                #    modes = f"+l {chan_obj.limit_add}"
                #    irc_q.put({'cmd': 'mode', 'channel': chan_obj.name, 'modes': modes})
                #    self.maintenance_state['last_limit'][chan_obj.name] = now 

    def _register_irc_timer(self, name: str, interval: float):
        """Register repeating timer"""
        if name in self.irc_timers:
            self.irc_timers[name].cancel()
        task = asyncio.create_task(self._irc_timer_loop(name, interval))
        self.irc_timers[name] = task
        log.info(f"Registered IRC timer: {name} ({interval}s)")

    def _unregister_irc_timer(self, name: str):
        """Cancel timer"""
        if name in self.irc_timers:
            self.irc_timers[name].cancel()
            del self.irc_timers[name]
            log.info(f"Unregistered IRC timer: {name}") 

    def _schedule_register_timer(self, name: str, interval: float):
        """Run on main event loop"""
        asyncio.create_task(self._register_irc_timer_task(name, interval))

    def _schedule_unregister_timer(self, name: str):
        """Run on main event loop"""
        asyncio.create_task(self._unregister_irc_timer_task(name))

    async def _register_irc_timer_task(self, name: str, interval: float):
        """Async timer registration"""
        if name in self.irc_timers:
            self.irc_timers[name].cancel()
        
        task = asyncio.create_task(self._irc_timer_loop(name, interval))
        self.irc_timers[name] = task
        log.info(f"Registered IRC timer: {name} ({interval}s)")

    async def _unregister_irc_timer_task(self, name: str):
        """Async timer unregistration"""
        if name in self.irc_timers:
            self.irc_timers[name].cancel()
            del self.irc_timers[name]
            log.info(f"Unregistered IRC timer: {name}")    

    async def _irc_timer_loop(self, name: str, interval: float):
        while True:
            await asyncio.sleep(interval)
            
            snapshot = {
                'connected': self.is_connected,
                'botname': self.connection.get_nickname() if self.connection else None,
                'channels': {}
            }
            
            #log.info(f"self.channels type: {type(self.channels)}")
            #log.info(f"self.channels content: {self.channels}")
            #log.info(f"self.channels.keys(): {list(self.channels.keys())}")
            for chan_name in list(self.channels.keys()):
                chan_obj = self.channels.get(chan_name)
                
                if chan_obj:
                    log.debug(f"Building snapshot for {chan_name}")
                    
                    try:
                        snapshot['channels'][chan_name] = {
                            'users': len(chan_obj.users()),
                            'user_list': list(chan_obj.users()),
                            'bot_op': self.is_bot_op(chan_name),  # Use your existing helper method
                            'ops': list(chan_obj.opers()),
                            'voiced': list(chan_obj.voiced()),
                            'mode': ''.join(f"{k}{v}" if v else k for k, v in chan_obj.modes.items()),
                            'mode_params': getattr(chan_obj, 'mode_params', {})
                        }
                        log.debug(f"Successfully added {chan_name} to snapshot")
                        
                    except Exception as inner_e:
                        log.error(f"Error building snapshot for {chan_name}: {inner_e}", exc_info=True)
                        
            event = {
                'type': 'IRC_TIMER_FIRED',
                'timer_name': name,
                'irc_data': snapshot
            }
            self._emit_event(event)                 

def start_irc_process(config, core_q, irc_q):
    """
    Entry point for IRC process
    """
    irc = WbsIrcBot(config, core_q, irc_q)

    # Start async maintenance
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    def command_poller():
        """Daemon thread: poll cmd_queue and execute commands"""
        irc.loop = loop
        throttle_interval = 0.5  # 500ms between commands (anti-flood)
        last_cmd_time = 0
        
        while True:
            try:
                elapsed = time.time() - last_cmd_time
                if elapsed < throttle_interval:
                    time.sleep(throttle_interval - elapsed)
                
                cmd_data = irc_q.get_nowait()
                if cmd_data is not None:
                    log.debug(f"Executing: {cmd_data}")
                    irc.execute_command(cmd_data)
                    last_cmd_time = time.time()
            
            except queue.Empty:
                time.sleep(0.01) 
            
            except Exception as e:
                log.error(f"Command poller error: {e}")
                time.sleep(0.1)
    
    poller = threading.Thread(target=command_poller, daemon=True)
    poller.start()

    # Async maintenance in event loop thread
    def event_loop_thread():
        irc.maintenance_task = loop.create_task(irc.maintenance_loop())
        try:
            loop.run_forever()
        finally:
            irc.maintenance_task.cancel()
            loop.close()
    
    event_loop = threading.Thread(target=event_loop_thread, daemon=True)
    event_loop.start()

    log.info(f"IRC process started. (pid={os.getpid()})")
    irc.start()

    #irc.maintenance_task.cancel()

def irc_process_launcher(config_path, core_q, irc_q):
    """Launcher for IRC multiprocessing.Process."""
    config = json.load(open(config_path))
    asyncio.run(start_irc_process(config, core_q, irc_q))