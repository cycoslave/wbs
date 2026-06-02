# WBS 5.9.3 (6.0.0 - pre-release)
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
- schema.sql — hostmasks / bans / invites as JSON Strings
Storing structured data as JSON blobs (TEXT DEFAULT '[]') in SQLite is functional but unindexed. The index on users.hostmasks (idx_users_hostmasks) won't help with LIKE-style searches. For RC2 this is acceptable, but for production at scale, normalize hostmasks to a proper junction table.

## Bugs
- None for now.