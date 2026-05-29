# WBS 6.0.0 RC2
An Eggdrop like bot system in Python.


## Installation
It is recommended that you use pyenv to create a virtual environment to run WBS.
Works best with Python 3.12.7.

- Run 'pip install -e .' to install the dependencies


## Usage
```
usage: wbs [-h] [-f] [-c CONFIG] [-d DB_PATH] [-v]
options:
  -h, --help            show this help message and exit
  -f, --foreground      Run foreground
  -c CONFIG, --config CONFIG
                        Config file path
  -d DB_PATH, --db-path DB_PATH
                        Override DB path from config
  -v, --version         show program's version number and exit
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

- Botnet Key Exchange Uses Raw SHA-256 for Shared Secret Derivation
This is a KDF (key derivation), not an auth hash, so length-extension is less of a concern here. However: (a) the entropy of two secrets.token_hex(16) values XOR'd together and hashed is fine, but (b) there is no domain separation — an attacker who can observe both partials on the wire and forge the hash has a direct path. Use hashlib.sha256(f"wbs-keyex:{min_p}:{max_p}".encode()).hexdigest() at minimum, or preferably HKDF