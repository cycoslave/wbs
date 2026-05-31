# WBS 6.0.1
An Eggdrop like bot system in Python.


## Installation
It is recommended that you use pyenv to create a virtual environment to run WBS.
Works best with Python 3.12.7.

- Run 'pip install -r requirements.lock' to install the dependencies


## Usage
```
usage: wbs [-h] [-c CONFIG] [-d DB_PATH] [-f] [-p] [-s] [--pidfile PIDFILE] [--logfile LOGFILE]

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to config file
  -d DB_PATH, --db-path DB_PATH
                        Override database path from config
  -f, --foreground      Run in foreground with console
  -p, --mkpasswd        Interactively prompt for a password and print its bcrypt hash. Use the output in config.json with encryption=bcrypt.
  -s, --seed            Initialize the database and seed from config.json, then exit. Must be run once before first launch.
  --pidfile PIDFILE     Override pid file path (default: from config settings.pid_file)
  --logfile LOGFILE     Override log file path (default: from config logging.file)
```

## Create your first user
- Edit config.json.example save it as config.json
- Launch your bot in foreground mode (./wbs -f)
- .adduser yourname *!ident@your.hostname.or.ip
- .addaccess yourname admin
- .die 

## Todo
- Complete seen plugin
- Complete channel + topic locking features
- News plugin creation/migration from WBS 5
- Complete data sharing between bot
- Create nick database (keeps track of user, host and nick, data useful for hand2nick or host matching)
- add !games to know which games are enabled on a channel
- add dependencies to games, it needs pubcom to be enabled.
- add ignore list/banlist for games.
- try to fix duckhunt cheating.

## Bugs
- .net issue
console> .net lag
2026-05-23 16:36:23,834 ERROR Command 'net' error: 'BotnetManager' object has no attribute 'broadcast'
Error executing .net

- schema.sql — hostmasks / bans / invites as JSON Strings
Storing structured data as JSON blobs (TEXT DEFAULT '[]') in SQLite is functional but unindexed. The index on users.hostmasks (idx_users_hostmasks) won't help with LIKE-style searches. For RC2 this is acceptable, but for production at scale, normalize hostmasks to a proper junction table.

- console> .+chan #test666
→ Channel #test666 NOT added: ChannelManager.addchan() got an unexpected keyword argument 'added_by'

- op commands are not broadcasted, only sent to directly linked bot

- a bot should send user changes to other bots

- background mode still display to stdout and stderr

- 2026-05-31 05:55:13,229 WARNING NetListener: rejected 198.23.237.193 — Connection limit reached

Unhandled exception in event loop:
  File "/home/mindwipe/wbs-6.0.0/src/net.py", line 348, in handle_connection
    await writer.wait_closed()
  File "/usr/lib/python3.13/asyncio/streams.py", line 358, in wait_closed
    await self._protocol._get_close_waiter(self)
  File "/usr/lib/python3.13/asyncio/sslproto.py", line 651, in _do_shutdown
    self._sslobj.unwrap()
    ~~~~~~~~~~~~~~~~~~~^^
  File "/usr/lib/python3.13/ssl.py", line 955, in unwrap
    return self._sslobj.shutdown()
           ~~~~~~~~~~~~~~~~~~~~~^^

Exception [SSL: APPLICATION_DATA_AFTER_CLOSE_NOTIFY] application data after close notify (_ssl.c:2776)
Press ENTER to continue...2026-05-31 05:55:14,240 WARNING NetListener: rejected 23.94.57.47 — Connection limit reached
2026-05-31 05:55:15,257 WARNING NetListener: rejected 64.23.230.103 — Connection limit reached

- .bots should show itself