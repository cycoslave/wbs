# WBS 5.9 (6.0 - pre-release)
An Eggdrop like bot system in Python.


## Installation
It is recommended that you use pyenv to create a virtual environment to run WBS.
Works best with Python 3.12.7.

- git clone https://github.com/cycoslave/wbs.git
- cd wbs
- python3 -m venv .venv
- source .venv/bin/activate
- pip install .
- cp config.json.example config.json
- edit config.json
- ./wbs -f --seed (to seed the database) 
- make any changes you need, link bots, etc..
- .detach (to let bot go into background mode)

## Usage
```
usage: wbs [-h] [-c CONFIG] [-d DB_PATH] [-f] [-p] [-s] [-u] [--pidfile PIDFILE] [--logfile LOGFILE]

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to config file
  -d DB_PATH, --db-path DB_PATH
                        Override database path from config
  -f, --foreground      Run in foreground with console
  -p, --mkpasswd        Interactively prompt for a password and print its bcrypt hash. Use the output
                        in config.json with encryption=bcrypt.
  -s, --seed            Initialize the database and seed from config.json, then exit. Must be run once
                        before first launch.
  -u, --update          Check for a newer WBS release and install it if available, then exit. The bot
                        does not need to be running. Requires update.host in config.json.
  --pidfile PIDFILE     Override pid file path (default: from config settings.pid_file)
  --logfile LOGFILE     Override log file path (default: from config logging.file)
```

## Create your first user
- Edit config.json.example save it as config.json
- Launch your bot in foreground mode (./wbs -f)
- .adduser yourname *!ident@your.hostname.or.ip
- .addaccess yourname admin
- .detach 

## Todo
- News plugin creation/migration from WBS 5
- Create nick database (keeps track of user, host and nick, data useful for hand2nick or host matching)
- add !games to know which games are enabled on a channel
- add dependencies to games, it needs pubcom to be enabled.
- add ignore list/banlist for games.
- schema.sql — hostmasks / bans / invites as JSON Strings
Storing structured data as JSON blobs (TEXT DEFAULT '[]') in SQLite is functional but unindexed. The index on users.hostmasks (idx_users_hostmasks) won't help with LIKE-style searches. For RC2 this is acceptable, but for production at scale, normalize hostmasks to a proper junction table.
- add .net lag
- remove games announcement when rejoining channel.

## Bugs
- IRC related commands should check if connected first
2026-06-08 09:33:06,088 WARNING Socket probe failed
2026-06-08 09:33:06,243 ERROR Not connected, dropping command: ping
2026-06-08 09:33:06,753 WARNING Disconnected from server
2026-06-08 09:33:06,963 ERROR _check_channels error: Not connected.
Traceback (most recent call last):
  File "/home/loco/Code/eggdrop/wbs/src/irc.py", line 956, in _check_channels
    self.connection.join(chan)
  File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/irc/client.py", line 567, in join
    self.send_items('JOIN', channel, key)
  File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/irc/client.py", line 659, in send_items
    self.send_raw(' '.join(filter(None, items)))
  File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/irc/client.py", line 667, in send_raw
    raise ServerNotConnectedError("Not connected.")
irc.client.ServerNotConnectedError: Not connected.

- .net error
console> .net say #tohands test
→ SAY #tohands: test
2026-06-08 18:23:46,707 ERROR Command failed {'cmd': 'msg', 'target': '#tohands', 'text': 'test'}: 'WbsIrcBot' object has no attribute '_IRC_MAX_BYTES'

- if +A, then +o should be assumed
console> .net op cyco #tohands
Access denied (need +o).

- issues with .detach which only leaves party line, does not go to background like intended.
console> .detach
2026-06-08 09:57:06,049 INFO Session 0 unregistered
2026-06-08 09:57:06,049 ERROR Command 'detach' error: 'Core' object has no attribute 'console'
Detaching. Bot continues in background. Reconnect via telnet or DCC.
*** console left the partyline
console>
console>
console> .detach

- enable exponential timer for bot autolink
2026-06-09 08:36:29,518 INFO AutoLink: attempting connection to wbs
2026-06-09 08:37:29,877 INFO AutoLink: attempting connection to wbs
2026-06-09 08:38:30,307 INFO AutoLink: attempting connection to wbs
2026-06-09 08:39:30,514 INFO AutoLink: attempting connection to wbs

- bots name, should not be equal to a user's name + we need to be able to .whois bots
console> .whois cyco
User: cyco
  Comment: None
  Password: Set
  Locked: No
  Hostmasks: ["loco@cyco.ca"]
  Access:
    * (all subnets): +pA
    * (subnet 2): +pA
console> .whois hook6
No such user: hook6

- the issues +A / +o from .net is present in .mode
console> .mode
Usage: .mode <#channel> <modes>
console> .mode #tohands +i
Access denied (need +o).
console> .mode #tohands -i
Access denied (need +o).

- check if those are still needed
console> .tasks
No tasks registered.
console> .timers
No active IRC timers.

- we should be able to see all the sessions active in channels
console> .gsessions
No active game sessions

- issues with .mass
console> .mass
Usage: .mass <op|deop> <#channel>
console> .mass op #tohands
2026-06-09 23:55:17,998 ERROR Command 'mass' error: 'Core' object has no attribute 'irc_snapshot'
Error executing .mass

- chaninfo needs to show more infomation about the channel (live and stored data)
console> .chaninfo #tohands
Channel: #tohands
  Comment: None
