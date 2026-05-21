# WBS 6.0.0
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
- blackjack: 
    <cyco> !bjjoin
    <WBS> [Blackjack] cyco joined with $750.
    <cyco> !bjtop
    <WBS> [Blackjack] Top chips: 1. randy $1500  2. cyco $0

- pubcom having issues pulling CVE:
    console> 2026-03-17 09:37:11,875 ERROR CVE fetch error: 
    2026-03-17 09:38:09,867 ERROR CVE fetch error: 
    2026-03-17 11:03:00,402 WARNING 

- pubcom
2026-05-15 09:14:50,656 ERROR Plugin pubcom.on_PUBMSG error: cannot access local variable 'severity_str' where it is not associated with a value
Traceback (most recent call last):
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/__init__.py", line 163, in dispatch
    await method(event)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/pubcom.py", line 165, in on_PUBMSG
    await handler(nick, uhost, channel, arg)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/pubcom.py", line 328, in cmd_cve
    msg = f"{products_str} - CVSS: {score}{severity_str} | {summary}"
                                           ^^^^^^^^^^^^
UnboundLocalError: cannot access local variable 'severity_str' where it is not associated with a value
2026-05-15 09:15:04,101 ERROR Plugin pubcom.on_PUBMSG error: cannot access local variable 'severity_str' where it is not associated with a value
Traceback (most recent call last):
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/__init__.py", line 163, in dispatch
    await method(event)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/pubcom.py", line 165, in on_PUBMSG
    await handler(nick, uhost, channel, arg)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/pubcom.py", line 328, in cmd_cve
    msg = f"{products_str} - CVSS: {score}{severity_str} | {summary}"
                                           ^^^^^^^^^^^^
UnboundLocalError: cannot access local variable 'severity_str' where it is not associated with a value