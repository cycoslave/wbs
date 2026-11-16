# WBS 5.9 (6.0 - pre-release)
An Eggdrop like bot system in Python.


## Installation
WBS runs from a project-local virtual environment at `.venv`. Use Python 3.13 (see `.python-version`, 3.13.5): the system `/usr/bin/python3.13`, not a uv-managed or per-user interpreter.

Prerequisites (Debian/Ubuntu package names; a clean machine needs all of them):

- git
- python3.13 and python3.13-venv (without it `python3.13 -m venv` fails with "ensurepip is not available")
- python3.13-dev and build-essential (`pyasn` 1.6.2 is published only as a source
  archive, so installing it compiles a C extension and needs `Python.h` and a compiler;
  no wheel exists for any pyasn release, so the build cannot be avoided)
- uv, only for the `uv sync` path below

    sudo apt install git python3.13 python3.13-venv python3.13-dev build-essential

Install, option A: pip, hash-verified (this is the path `./wbs` and `./wbs --update` use):

    git clone https://github.com/cycoslave/wbs.git
    cd wbs
    python3.13 -m venv .venv
    .venv/bin/pip install --require-hashes -r requirements.lock
    .venv/bin/pip install --no-deps .

Install, option B: uv (creates the same `.venv`; pass the system interpreter):

    git clone https://github.com/cycoslave/wbs.git
    cd wbs
    uv sync --frozen --no-dev --python /usr/bin/python3.13

Then configure and start:

    install -m 600 config.json.example config.json
    # edit config.json
    ./wbs -f --seed        # seed the database
    # make any changes you need, link bots, etc..
    .detach                # (console command) let the bot go into background mode

`config.json` holds secrets (seed passwords, server and update credentials), so wbs
only starts if it is a regular file (not a symlink, directory or FIFO), owned by the
user running wbs, with mode 0600 (no group/other bits). `install -m 600` above creates it
that way. Otherwise startup exits non-zero with
`[fatal] refusing to use config file <path>: ... fix with: chmod 600 <path>`;
run that `chmod` (or `chown` the file to the bot user) and start again. The message never
contains the file's contents. The same check applies to `.rehash`, which keeps the
previous config if the file no longer passes.

Seed passwords: use `"encryption": "bcrypt"` with a hash from `./wbs --mkpasswd`.
`encryption` defaults to `bcrypt` when omitted, so a cleartext seed password needs an
explicit `"encryption": "none"`; that still works but logs a startup warning; once `./wbs -f --seed`
has run, remove the seed passwords from `config.json`.

Option B was run from a clean `git archive` checkout on Python 3.13.5 with the packages
above installed: `pyasn` builds, and `.venv/bin/wbs --help` works. Option A installs the same
locked versions from `requirements.lock` (identical to `uv.lock`, see Dependencies), but its
`pip install` step was not run end to end by the author of this change.

`./wbs` always runs under `.venv/bin/python`: started with any other interpreter
(e.g. `python3 wbs`) it re-execs itself into the venv, so no activation is
needed. If `.venv` is missing it exits with the commands above. A full upgrade via
`./wbs --update` installs into the same venv (hash-verified `requirements.lock`,
then `--no-deps`) and refuses to run pip outside a venv.
`pip install` also provides a `wbs` console command (`src.main:main`, the same
supervisor `./wbs` runs); it uses the current directory for config.json, db/ and logs/.

## Dependencies
uv.lock is the single source of truth for dependency versions. requirements.lock is
generated from it and must not be edited by hand. After changing pyproject.toml:

- uv lock
- uv export --frozen --no-dev --no-emit-project --format requirements-txt -o requirements.lock
- uvx pip-audit -r requirements.lock --require-hashes --disable-pip

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
- Create config.json with `install -m 600 config.json.example config.json` (mode 0600 is required), then edit it
- Launch your bot in foreground mode (./wbs -f --seed on the first run, ./wbs -f afterwards)
- Type these at the `console>` prompt (the console is the operator, it needs no login):
```
.adduser yourname *!ident@your.hostname.or.ip
.addaccess yourname admin
.passwd yourname a-password-of-8-or-more-characters
.showuser yourname
```
- Then connect with DCC chat or telnet as `yourname` using that password.
- Leave the console with `.detach`: the bot goes to the background (the shell prompt
  returns, logging goes to the log file) and stays reachable by DCC chat or telnet.
  `.quit` does not stop the bot, `.die` does.
- In foreground mode (`-f`) the log lines go to the console and also to `logging.file` (rotated, same format as in the background); after `.detach` they go to the file only.

## Running in the background
- `./wbs` (no `-f`) detaches and returns 0 once the bot is up. The pid file
  (`settings.pid_file`, default `wbs.pid`) holds the supervisor's pid and is locked while
  it runs: a second `./wbs` exits 1 with `WBS is already running (pid N)`. A stale pid
  file (bot gone) is taken over.
- Stop it with `kill -TERM $(cut -d' ' -f1 wbs.pid)`: the bot sends its IRC QUIT, saves
  state and exits within a few seconds; the pid file is removed.
- Files: the database and backups are created `0600`, the log `0640`. The log rotates by
  size: `"logging": {"max_bytes": 10485760, "backup_count": 5}` (the defaults;
  `max_bytes: 0` turns rotation off).
- Log contents: even at `"level": "DEBUG"` IRC events are logged as metadata only
  (type, nick, channel/target, text length), never the text: private messages carry
  `identify`/`chatauth` passwords and `.chpass`/`.botattr pass=` keys. Values are
  length-bounded with control characters escaped, and the irc/aiosqlite libraries'
  raw line and SQL-parameter traces are dropped at any level.
- Updates need `update.host` (and `update.signing_keys`) in config.json. `.checkupdate`
  only checks; `.update` checks and `.update confirm` installs.

Command names: the real names are `+user -user userinfo users chpass +host -host +ignore
-ignore`; each also answers to an alias with the same handler and the same required flag:

| command | alias |
|---|---|
| `+user` | `adduser` |
| `-user` | `deluser` |
| `userinfo` | `showuser` |
| `users` | `listusers` |
| `chpass` | `passwd` |
| `+host` | `addhost` |
| `-host` | `delhost` |
| `+ignore` | `addignore` |
| `-ignore` | `delignore` |

`.addaccess` / `.delaccess` / `.chattr` take flag letters (`A` admin, `n` owner, `p` partyline,
`o` op, `v` voice, `a` autoop, ...; see `.help chattr`). `.addaccess` and `.delaccess` also
accept the word names, comma separated: `admin owner partyline friend autoop op deop autohop
hop dehop voice devoice autokick` (e.g. `.addaccess yourname admin,partyline`).

Op rights: `.op .deop .voice .devoice .mode .mass` (and the public `!op !deop !voice !devoice
!kick !ban !mode`) need `+o`; owners (`+n`) and admins (`+A`) have op rights without an
explicit `+o`. A channel row with `+o` gives op rights on that channel only.

Auto-modes (enforced when a known user joins, once for everyone present after the bot has
synced a channel (join, reconnect, restart), and again when the bot gets op). A "known user"
is a joiner whose `nick!user@host` matches a user's hostmask; flags count from the user's
global row or the row of that channel:
- user `+k` (autokick): kicked; with the channel's `enforcebans` on, `*!*@host` is banned first.
- user `+a` (autoop): opped (not if the user also has `+d`).
- channel `autoop`: known users with op rights (`+o`, `+A` or `+n`) are opped even without `+a`.
- channel `autovoice`: known users with `+v` are voiced (not with `+q`).
- channel `bitch`: when someone other than the bot ops a nick that is not a known user with
  op rights or a bot with `+o`, the bot deops it.
- Strangers (no matching hostmask) are never opped or voiced; there is no "everyone" setting.
- Nothing is sent while the bot has no op (voice and kick also work with halfop), and
  nothing at all on an inactive channel.

Flood protection (channel columns `flood_<kind>` = N events and `flood_<kind>_time` = S
seconds, shown by `.chaninfo` as `N/Ss`; more than N in any S seconds is a flood, N or S = 0
turns that kind off):
- `pub` (channel PRIVMSG/NOTICE/ACTION), `ctcp` (CTCP to the channel), `join`: counted per
  host; the offender is kicked and `*!*@host` banned for 10 minutes.
- `pub` is decided before plugins and games see the line: once a host floods a channel,
  its text there is dropped (no plugin command, URL title or game move) for S seconds,
  with or without op.
- `nick`: counted per host; the offender is kicked.
- `kick`, `deop`: counted per op; that op is deopped.
- Never acted on: the bot, known users with op rights (`+o`, `+A`, `+n`), our op bots, and
  (except for kick/deop floods) whoever is opped. Without op the bot only logs it, once.
- The bot itself: config `settings.flood_msg` (private messages, default `"5:60"`) and
  `settings.flood_ctcp` (CTCP requests, default `"3:60"`), `"0"` = off. A flooding host is
  dropped and put on the ignore list as `*!*@host` for 1 minute (owner/admin never).

## Commands by private message (`/msg`)
Owner commands sent to the bot by `/msg` are OFF by default: config `settings.msg_commands`
(`false` unless set to the boolean `true`). While it is off every recognised sender is answered
`Access denied.` (unknown hosts are still ignored silently). When it is on, a command runs only
if the sender (1) matches a user holding `+n` by hostmask AND (2) has a live `identify` session
(`/msg <bot> identify [handle] <password>`) for that same handle from that same
`nick!user@host`; a hostmask match alone gets `Access denied.`. The session is the one the
pubcom plugin keeps (it ends on nick change, quit, `auth_timeout`, reconnect or a password
change), so pubcom must be loaded. The partyline, telnet and DCC logins are unchanged.

## Linking two bots (two subnets)
Each bot belongs to one subnet: `subnet.id` / `subnet.name` in its config.json, created by
`--seed`. A link authenticates both bots with a shared key; what a linked peer may do (ops,
modes, botnet commands, replication) is decided ONLY by the subnet you store for it on your own
bot. A new peer without one has scope "unknown" and everything from it is denied.

Example: A1 (subnet 1 `sub1`, listens on a1.example.org:3333) and B1 (subnet 2 `sub2`, listens
on b1.example.org:3333). Pick one link key of 8+ characters and keep it secret.

On A1:
```
.subnet add sub2 2                 (B1's subnet, with the SAME id B1 uses)
.+bot b1 *!*@b1.example.org b1.example.org 3333
.botattr b1 pass=<link-key> subnet=sub2 share=subnet
```
On B1:
```
.subnet add sub1 1
.+bot a1 *!*@a1.example.org a1.example.org 3333
.botattr a1 pass=<link-key> subnet=sub1 share=subnet
```
Then on either bot: `.link b1` (or `.link a1`); `.botattr b1 +a` makes it autolink.

- `.subnet list` shows `[id] name` and which bots/channels use each subnet; `.subnet del` refuses
  a subnet that is still in use and the bot's own subnet.
- Both bots announce their subnet on link (`SUBNET <id> <name>`). If you linked before setting
  `subnet=`, `.botattr b1` shows `subnet=unset proposed=2(sub2)`; accept it with
  `.botattr b1 subnet=proposed` (after `.subnet add sub2 2` if that subnet is not known yet). An
  announcement is never applied by itself.
- Bots of different subnets may link and share an IRC server, but never op each other or run
  each other's botnet commands. Two bots of the same subnet use the same steps with the same
  subnet on both sides (no `.subnet add` needed).

### Botnet settings (config.json)
All botnet settings live in ONE section, `botnet` (an object):
```
"botnet": {
  "address": "a1.example.org",   (what other bots dial; shown by .infoleaf)
  "listen_host": "0.0.0.0",      (interface the link/partyline listener binds; default 127.0.0.1 = loopback only, set 0.0.0.0 to accept remote bots)
  "listen_port": 3333,           (1-65535, default 3333)
  "subnet_id": 1,
  "relay_from": {}
}
```
The old `settings.listen_host` / `settings.listen_port` and a bare `"botnet": true/false` are
still read (the `botnet` section wins) but the config check warns about them. `.infoleaf` prints the
real listener (`host:port`) and the `.addleaf` line to run on the hub.

Bot commands validate their input: the handle follows the user-handle rule, the address is a
host name or IP, the port is 1-65535; an existing handle gives `Bot 'x' already exists`.
`.botattr <bot>` and `.botattr <bot> pass=...` show the link key only as `password=****`.
`.servlinks` shows the IRC server's LINKS list (`.links` is its old name).

Failed link attempts are counted per (address, claimed bot handle): after `settings.max_failures`
(default 5) that handle is refused from that address for `lockout_seconds`; the whole address is
only auto-blocked after `settings.max_failures_ip` (default 4x `max_failures`). A linked, authenticated
bot is never locked out or blocked by failures from its own address.

### DCC chat settings (config.json)
The `dcc` section has its own listener setting, independent of `botnet.listen_host`:
```
"dcc": {
  "mode": "auto",            (auto | active | passive | irc)
  "listen_host": "127.0.0.1", (interface for the active DCC listener; default 127.0.0.1 = loopback only, set 0.0.0.0 to accept remote DCC clients)
  "public_ip": ""            (address advertised in DCC offers; empty = detected from IRC)
}
```
- With no `listen_host`, `mode: auto` uses passive (reverse) DCC: your client opens the
  listener and the bot connects out. mIRC, HexChat and irssi support this; a client that cannot
  accept an inbound connection (e.g. behind NAT) needs `"listen_host": "0.0.0.0"` on the bot.
- With a non-loopback `listen_host` and a known public IP, `auto` uses active DCC: the bot listens
  on a random port from `port_min`..`port_max` and offers `public_ip:port`.
- The advertised address is always `public_ip` (configured, else IRC-detected), never
  `listen_host`, so a loopback or `0.0.0.0` bind is never offered to the client.
- `mode: active` with a loopback `listen_host` still listens, but logs a warning: only a client
  on the bot's own host can connect.
- Upgrading: DCC no longer follows `botnet.listen_host` / `settings.listen_host`. If you set one
  of those to `0.0.0.0` for DCC chat, set `dcc.listen_host` instead.

### TLS for outgoing bot links
Outgoing links use TLS (`settings.ssl`, default true) and verify the peer certificate (chain and
host name) by default. For a bot with a private CA or a self-signed certificate, keep verification
on with one of these `settings` keys (all optional; default behaviour is unchanged without them):
```
"ssl_ca_file": "/path/to/ca.pem",          (extra CA / peer certificate to trust; chain + host name still verified)
"ssl_fingerprint": "AB:CD:...:EF"          (SHA-256 of the peer's certificate, 64 hex digits, colons optional)
```
Get the fingerprint with `openssl x509 -in peer.crt -noout -fingerprint -sha256`. With only
`ssl_fingerprint` set, the certificate is accepted if and only if its SHA-256 matches (so
self-signed certificates work, no CA or host name needed); a mismatch drops the link before
anything is sent. With `ssl_ca_file` too, the chain is verified AND the pin must match. Both
settings apply to every outgoing link; an unreadable `ssl_ca_file` or a malformed
`ssl_fingerprint` refuses the link (logged as an error). `"ssl_verify": false` still works but
turns certificate checking off: a WARNING is logged at startup and on every link naming the bot.
Prefer the two options above. (Incoming links are not affected by these settings.)

## Todo
- News plugin creation/migration from WBS 5
- Create nick database (keeps track of user, host and nick, data useful for hand2nick or host matching)
- add !games to know which games are enabled on a channel
- add dependencies to games, it needs pubcom to be enabled.
- add ignore list/banlist for games.
- schema.sql — hostmasks / bans / invites as JSON Strings
Storing structured data as JSON blobs (TEXT DEFAULT '[]') in SQLite is functional but unindexed. The index on users.hostmasks (idx_users_hostmasks) won't help with LIKE-style searches. For RC2 this is acceptable, but for production at scale, normalize hostmasks to a proper junction table.
- add .net lag

## Bugs
- if +A, then +o should be assumed
console> .net op cyco #tohands
Access denied (need +o).

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

- issues with .mass
console> .mass
Usage: .mass <op|deop> <#channel>
console> .mass op #tohands
2026-06-09 23:55:17,998 ERROR Command 'mass' error: 'Core' object has no attribute 'irc_snapshot'
Error executing .mass