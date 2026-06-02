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

## Bugs
- .net issue
console> .net lag
2026-05-23 16:36:23,834 ERROR Command 'net' error: 'BotnetManager' object has no attribute 'broadcast'
Error executing .net

- schema.sql — hostmasks / bans / invites as JSON Strings
Storing structured data as JSON blobs (TEXT DEFAULT '[]') in SQLite is functional but unindexed. The index on users.hostmasks (idx_users_hostmasks) won't help with LIKE-style searches. For RC2 this is acceptable, but for production at scale, normalize hostmasks to a proper junction table.

- part but the bot rejoins anyway
2026-06-02 20:58:02,096 INFO net part #test666 (from shrapnel6)
2026-06-02 20:58:02,205 INFO Bot parted #test666, removed from channels database
2026-06-02 20:58:02,769 INFO Trying to join: #test666 (attempts in last 5m: 1)
2026-06-02 20:58:02,826 INFO Building snapshot for #test666
2026-06-02 20:58:02,862 INFO Joined #test666; requested ops from peers

- users should only "join" the partyline once the user is authenticated, going to https://botip:botport will join the partyline.
<scavenge6@scavenge6> user_3.17.64.175_61174 joined the partyline (telnet)
<scavenge6@scavenge6> user_3.17.64.175_61174: Host: 185.65.206.71:3333
<scavenge6@scavenge6> user_3.17.64.175_61174: User-Agent: visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36
<scavenge6@scavenge6> user_3.17.64.175_61174: Accept: */*
<scavenge6@scavenge6> user_3.17.64.175_61174: Accept-Encoding: gzip
<scavenge6@scavenge6> user_3.17.64.175_61174 left the partyline

console> 2026-06-02 21:14:05,850 INFO Partyline connect: user_47.55.39.9_57134
2026-06-02 21:14:05,852 INFO Partyline newuser user_47.55.39.9_57134
2026-06-02 21:14:05,854 INFO Remote session 2 (telnet) registered for user_47.55.39.9_57134
2026-06-02 21:14:05,855 INFO Session 2 (telnet) started: user_47.55.39.9_57134
user_47.55.39.9_57134 joined the partyline (telnet)
console> 2026-06-02 21:14:05,905 INFO Session 2 closed
2026-06-02 21:14:05,908 INFO Partyline unregistered user_47.55.39.9_57134#2
user_47.55.39.9_57134: Host: 192.227.228.10:3333
user_47.55.39.9_57134: Connection: keep-alive
user_47.55.39.9_57134: Cache-Control: max-age=0
user_47.55.39.9_57134: sec-ch-ua: "Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"
user_47.55.39.9_57134: sec-ch-ua-mobile: ?0
user_47.55.39.9_57134: sec-ch-ua-platform: "Windows"
user_47.55.39.9_57134: DNT: 1
user_47.55.39.9_57134: Upgrade-Insecure-Requests: 1
user_47.55.39.9_57134: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
user_47.55.39.9_57134: Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
user_47.55.39.9_57134: Sec-Fetch-Site: none
user_47.55.39.9_57134: Sec-Fetch-Mode: navigate
user_47.55.39.9_57134: Sec-Fetch-User: ?1
user_47.55.39.9_57134: Sec-Fetch-Dest: document
user_47.55.39.9_57134: Accept-Encoding: gzip, deflate, br, zstd
user_47.55.39.9_57134: Accept-Language: en-CA,en-GB;q=0.9,en-US;q=0.8,en;q=0.7
user_47.55.39.9_57134 left the partyline
console> 2026-06-02 21:14:07,128 INFO Partyline connect: user_47.55.39.9_64276
2026-06-02 21:14:07,146 INFO Partyline newuser user_47.55.39.9_64276
2026-06-02 21:14:07,148 INFO Remote session 3 (telnet) registered for user_47.55.39.9_64276
2026-06-02 21:14:07,149 INFO Session 3 (telnet) started: user_47.55.39.9_64276
user_47.55.39.9_64276 joined the partyline (telnet)
console> 2026-06-02 21:14:07,181 INFO Session 3 closed
2026-06-02 21:14:07,201 INFO Partyline unregistered user_47.55.39.9_64276#3
user_47.55.39.9_64276: Host: 192.227.228.10:3333
user_47.55.39.9_64276: Connection: keep-alive
user_47.55.39.9_64276: Cache-Control: max-age=0
user_47.55.39.9_64276: sec-ch-ua: "Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"
user_47.55.39.9_64276: sec-ch-ua-mobile: ?0
user_47.55.39.9_64276: sec-ch-ua-platform: "Windows"
user_47.55.39.9_64276: DNT: 1
user_47.55.39.9_64276: Upgrade-Insecure-Requests: 1
user_47.55.39.9_64276: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
user_47.55.39.9_64276: Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
user_47.55.39.9_64276: Sec-Fetch-Site: none
user_47.55.39.9_64276: Sec-Fetch-Mode: navigate
user_47.55.39.9_64276: Sec-Fetch-User: ?1
user_47.55.39.9_64276: Sec-Fetch-Dest: document
user_47.55.39.9_64276: Accept-Encoding: gzip, deflate, br, zstd
user_47.55.39.9_64276: Accept-Language: en-CA,en-GB;q=0.9,en-US;q=0.8,en;q=0.7
user_47.55.39.9_64276 left the partyline


- foreign key conatrains on syncing users /  bots
2026-06-02 15:06:20,048 INFO UserManager.merge_from_peer: merged 1 users from mindwipe6

Unhandled exception in event loop:
  File "/home/shrapnel/wbs5.9.2/src/botnet.py", line 964, in handle_share_user_access
    await self.user.merge_access_from_peer(access_list, from_bot)
  File "/home/shrapnel/wbs5.9.2/src/user.py", line 630, in merge_access_from_peer
    await db.execute(
  File "/home/shrapnel/.local/lib/python3.11/site-packages/aiosqlite/core.py", line 223, in execute
    cursor = await self._execute(self._conn.execute, sql, parameters)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/shrapnel/.local/lib/python3.11/site-packages/aiosqlite/core.py", line 160, in _execute
    return await future
           ^^^^^^^^^^^^
  File "/home/shrapnel/.local/lib/python3.11/site-packages/aiosqlite/core.py", line 63, in _connection_worker_thread
    result = function()
             ^^^^^^^^^^

Exception FOREIGN KEY constraint failed
Press ENTER to continue...2026-06-02 15:06:20,218 INFO BotManager.merge_from_peer: merged 7 bots from mindwipe6

Unhandled exception in event loop:
  File "/home/shrapnel/wbs5.9.2/src/botnet.py", line 976, in handle_share_channels
    await self.chan.merge_from_peer(channels, from_bot)
  File "/home/shrapnel/wbs5.9.2/src/channel.py", line 568, in merge_from_peer
    await db.execute(
  File "/home/shrapnel/.local/lib/python3.11/site-packages/aiosqlite/core.py", line 223, in execute
    cursor = await self._execute(self._conn.execute, sql, parameters)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/shrapnel/.local/lib/python3.11/site-packages/aiosqlite/core.py", line 160, in _execute
    return await future
           ^^^^^^^^^^^^
  File "/home/shrapnel/.local/lib/python3.11/site-packages/aiosqlite/core.py", line 63, in _connection_worker_thread
    result = function()
             ^^^^^^^^^^

Exception FOREIGN KEY constraint failed
2026-06-02 20:36:19,989 INFO BotManager.merge_access_from_peer: merged 0 rows from shrapnel6

Unhandled exception in event loop:
  File "/home/mindwipe/wbs5.9.2/src/botnet.py", line 976, in handle_share_channels
    await self.chan.merge_from_peer(channels, from_bot)
  File "/home/mindwipe/wbs5.9.2/src/channel.py", line 568, in merge_from_peer
    await db.execute(
    ...<4 lines>...
    )
  File "/home/mindwipe/.local/lib/python3.13/site-packages/aiosqlite/core.py", line 223, in execute
    cursor = await self._execute(self._conn.execute, sql, parameters)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/mindwipe/.local/lib/python3.13/site-packages/aiosqlite/core.py", line 160, in _execute
    return await future
           ^^^^^^^^^^^^
  File "/home/mindwipe/.local/lib/python3.13/site-packages/aiosqlite/core.py", line 63, in _connection_worker_thread
    result = function()

Exception FOREIGN KEY constraint failed

- these messages need to go, this is a server type program
Press ENTER to continue...

