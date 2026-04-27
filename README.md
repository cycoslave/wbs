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
- Some channel sync issues, probably missing some irc numerics

- Background mode is not totally going to background.

- blackjack: 
    <cyco> !bjjoin
    <WBS> [Blackjack] cyco joined with $750.
    <cyco> !bjtop
    <WBS> [Blackjack] Top chips: 1. randy $1500  2. cyco $0

- irc process crash:
    2026-03-17 11:03:00,402 WARNING 
    Unknown encoding encountered. See 'Decoding Input'
    in https://pypi.python.org/pypi/irc for details.

    Process IRC:
    Traceback (most recent call last):
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/multiprocessing/process.py", line 314, in _bootstrap
        self.run()
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/multiprocessing/process.py", line 108, in run
        self._target(*self._args, **self._kwargs)
      File "/home/loco/Code/eggdrop/wbs6.0.0/src/irc.py", line 749, in irc_process_launcher
        asyncio.run(start_irc_process(config, core_q, irc_q))
                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      File "/home/loco/Code/eggdrop/wbs6.0.0/src/irc.py", line 742, in start_irc_process
        irc.start()
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/irc/bot.py", line 347, in start
        super().start()
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/irc/client.py", line 1268, in start
        self.reactor.process_forever()
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/irc/client.py", line 910, in process_forever
        consume(repeatfunc(one))
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/more_itertools/recipes.py", line 204, in consume
        deque(iterator, maxlen=0)
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/irc/client.py", line 891, in process_once
        self.process_data(in_)
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/irc/client.py", line 856, in process_data
        conn.process_data()
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/irc/client.py", line 330, in process_data
        for line in self.buffer:
                    ^^^^^^^^^^^
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/jaraco/stream/buffer.py", line 103, in lines
        self.handle_exception()
      File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/site-packages/jaraco/stream/buffer.py", line 101, in lines
        yield line.decode(self.encoding, self.errors)
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xc9 in position 90: unexpected end of data

- pubcom having issues pulling CVE:
    console> 2026-03-17 09:37:11,875 ERROR CVE fetch error: 
    2026-03-17 09:38:09,867 ERROR CVE fetch error: 
    2026-03-17 11:03:00,402 WARNING 

- if nick is taken bot will not join irc
    2026-03-23 12:38:00,449 WARNING Disconnected from server
    2026-03-23 12:38:00,489 ERROR IRC error: disconnect
    2026-03-23 12:38:04,658 INFO Rejoined #tohands
    2026-03-23 12:38:04,658 INFO Rejoined #wbs

- PUBCOM: cannot identify
2026-04-03 19:21:30,128 ERROR Plugin pubcom.on_PRIVMSG error: 'uhost'
Traceback (most recent call last):
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/__init__.py", line 163, in dispatch
    await method(event)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/pubcom.py", line 90, in on_PRIVMSG
    handle = event['uhost']  # Use their nick as handle
             ~~~~~^^^^^^^^^
KeyError: 'uhost'
2026-04-03 19:22:11,676 ERROR Plugin pubcom.on_PRIVMSG error: 'UserManager' object has no attribute 'verify_password'
Traceback (most recent call last):
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/__init__.py", line 163, in dispatch
    await method(event)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/pubcom.py", line 97, in on_PRIVMSG
    if await self.core.user.verify_password(handle, password):
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: 'UserManager' object has no attribute 'verify_password'. Did you mean: 'set_password'?

- Issue with privmsg, should sanitize before sending to server.
2026-03-27 17:32:59,303 ERROR Command failed {'cmd': 'msg', 'target': '#tohands', 'text': 'Title: The Last Solo "Sugar Daddy"  Of 2025.💯🚵\u200d♂️💨\n\n#solo #mtbride\n#sugarloafpark #sugarloafprovincialpark #sugarloafbikepark #gopro #chinmount #chinmounts #mtbpark #mtbparks #mtbtrail #parcsnbparks #parksca'}: Carriage returns not allowed in privmsg(text)

- on invite issue:
console>
Traceback (most recent call last):
  File "/home/loco/Code/eggdrop/wbs6.0.0/./wbs", line 33, in <module>
    main()
  File "/home/loco/Code/eggdrop/wbs6.0.0/./wbs", line 30, in main
    asyncio.run(core.run(foreground=args.foreground))
  File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/asyncio/runners.py", line 194, in run
    return runner.run(main)
           ^^^^^^^^^^^^^^^^
  File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/asyncio/runners.py", line 118, in run
    return self._loop.run_until_complete(task)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/loco/.pyenv/versions/3.12.7/lib/python3.12/asyncio/base_events.py", line 687, in run_until_complete
    return future.result()
           ^^^^^^^^^^^^^^^
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/core.py", line 134, in run
    await self._main_loop_with_console()
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/core.py", line 416, in _main_loop_with_console
    await self.handle_event(event)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/core.py", line 190, in handle_event
    await handler(event)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/core.py", line 512, in on_invite
    inviter_nick = event['inviter_nick']
                   ~~~~~^^^^^^^^^^^^^^^^
KeyError: 'inviter_nick'

- on_pubcom bug:
026-04-21 09:40:29,946 ERROR Plugin pubcom.on_PUBMSG error: 'ChannelManager' object has no attribute 'get'
Traceback (most recent call last):
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/__init__.py", line 163, in dispatch
    await method(event)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/pubcom.py", line 165, in on_PUBMSG
    await handler(nick, uhost, channel, arg)
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/pubcom.py", line 1205, in cmd_whois
    if not await self.is_pubcom_enabled(channel):
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/loco/Code/eggdrop/wbs6.0.0/src/plugins/pubcom.py", line 71, in is_pubcom_enabled
    chan_settings = await self.core.chan.get(channel)
                          ^^^^^^^^^^^^^^^^^^
AttributeError: 'ChannelManager' object has no attribute 'get'
