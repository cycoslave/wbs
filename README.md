# WBS 6.0.0 RC1
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
- None, for now.

## RC1 to prod points
Security & transport
Botnet TLS

Ensure all botnet client connections use SSL context (no plain asyncio.open_connection on public networks).

Ensure botnet listener (asyncio.start_server in net layer) also enforces TLS based on config.

Validate that SHARE USERS / SHARE BOTS / PARTYLINE relay messages never traverse plaintext connections.

Add a simple self‑check: log a clear warning if configured for public net but TLS is disabled.

IRC TLS

Confirm IRC connection code supports ssl=True and is correctly driven by config.

Add minimal logging around IRC connect (host, port, TLS yes/no) so misconfigurations are obvious.

Database schema & model alignment
Lock schema as source of truth

Walk schema.sql and each of: user.py, channel.py, bot.py, botnet.py, db.py, commands.py and remove all references to columns that do not exist (e.g. legacy flags, chan_flags, xtra, several subnet_id/added_by uses).

Add any missing columns that the new design truly needs (e.g. deleted_at/updated_at on users/channels/access) so soft‑delete & last‑write‑wins merge work end‑to‑end.

Users / access

Make User dataclass fields match users table exactly (including timestamps and soft‑delete markers).

Fix UserManager.get()/list_users() so they no longer expect legacy flags/xtra; rely on user_access booleans instead (is_admin, has_partyline, is_op, etc.).

Implement proper async helpers for hostmasks (add/remove) and wire . +host / .-host to those instead of the non‑existent core.userdb.save_user.

Channels / subnets

Make Channel dataclass + DB layer consistent with channels + channel_subnets (including soft‑delete, created/updated by, etc.).

Ensure . +chan / .-chan work with the final schema: global vs subnet‑scoped channels via channel_subnets, plus soft‑delete semantics.

Bots / bot_access / bot_subnets

Align Bot/BotAccess dataclasses and BotManager methods with bots, bot_access, and bot_subnets tables (no references to non‑existent added_by, subnet_id fields, etc.).

Fix BotManager.set_password() to update the correct table (bots, not users).

Runtime / init

Remove the duplicate runtime DDL in code and rely on the runtime table + triggers defined in schema.sql to avoid drift.

Ensure init_db() + migrations are idempotent and safe on an existing RC1 database (no destructive schema changes without explicit force/backup).

Core, partyline & command dispatch
Partyline command path

Confirm that all partyline commands go through Partyline._handle_command() and the (core, handle, session_id, arg, respond) call signature; kill any older direct paths.

Add minimal error reporting: any exceptions in command handlers should be logged and result in a single “Error: …” line on partyline, not a silent failure.

Access control

Replace any remaining user.flags‑style checks with helpers that query user_access (e.g. “has admin on this subnet/channel?”).

Implement a consistent “console is always owner” rule and ensure telnet/DCC users go through the same ACL path.

Stub commands

For .addaccess, .delaccess, .lockuser, .unlockuser, .chusercomment and any similar stubs: either

Implement real semantics against user_access, or

Remove them from .help and COMMANDS for production so operators don’t see dead commands.

Channel state & netop stability
Channel state as single source of truth

Finish wiring the updated Channel dataclass: JOIN/PART/QUIT/NICK/MODE/353/366 handlers in irc.py must keep users, ops, voiced, and bot_op in sync.

Ensure core helpers like nick_isop, chan_mode_string use that state and no longer rely on stale/duplicate structures.

netop plugin

Confirm the op‑storm fix is complete:

No re‑op if target already op in that channel.

Optional per‑channel+nick cooldown to prevent two bots endlessly trading +o after link/sync.

Add DEBUG log lines around auto‑ops (who opped whom where and why) for easier diagnosis on live networks.

Botnet behavior & subnets
Subnet semantics

Verify the “one bot → one subnet (default 0)” rule is enforced and that . +user / . +chan default scope is “this bot’s subnet unless * is passed for global”.

Confirm that botnet sharing respects this: channels/users from other subnets are stored but only joined/used when relevant to the local bot’s subnet/global scope.

Botnet APIs

Implement or clean up BotnetManager methods so there are no dead references:

Provide send_to_peer() and broadcast() (or adjust callers to use existing broadcast_all/broadcast_chat).

Fix stop() and any disconnect_peer() logic to iterate correctly over BotLink objects and close connections cleanly.

Ensure .net and .relay commands work against the final API and have reasonable error messages when a bot is not linked.

Config, packaging & operations
Entry point & install

Fix pyproject.toml entry point so wbs resolves to the real main module/function you use in the repo (not a non‑existent main:main).

Verify that installing the project into a venv and running wbs works with no local‑repo assumptions (paths, cwd, etc.).

Config handling

Handle missing config.json gracefully:

Either ship a default config.json, or

On startup, detect missing config and print “copy config.json.example to config.json” instead of a traceback.

Document botnet TLS config (cert/key locations, ssl_verify semantics) and IRC server settings in the README.

Logging & monitoring

Standardize logging format and levels; ensure noisy debug logs (especially from botnet and netop) can be toggled via config.

Add a very simple “health” signal (e.g., periodic log line or stats command) that shows: connected to IRC, connected peers, joined channels, DB path.

Testing & docs
Automated testing

Add basic tests for:

DB migrations / init on an empty and an existing DB.

Core commands on partyline (smoke tests for .join, .part, .channels, .users, .bots, .net, .relay).

Botnet TLS connect/link and a simple .relay round‑trip between two bots (can run locally with self‑signed certs).

Scenario “playbooks”

Write short docs for three scenarios:

Single bot on one network, no botnet.

Two bots linked over TLS on the same network, using netop and subnet features.

Multi‑subnet topology (e.g., two IRC networks, shared global users/channels).

Operator‑facing docs

Update README / src/plugins/README.md with:

Enabled core plugins (pubcom, stats, seen, limit, chanlock, topiclock, netop, url) and how to toggle them with .plugins/.load/.unload.

Summary of user/access model (what is_admin, has_partyline, is_op mean in practice).

Clear statement of which Eggdrop behaviours are intentionally dropped vs replaced so expectations are set.