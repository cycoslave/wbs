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
- recode the WBS TCL scripts into python

## Bugs
- console does does not broadcast to partyline