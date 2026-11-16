# src/helper.py
"""
Helper functions
"""
import asyncio
import sys
import os
import termios
import logging
import ipaddress
import socket
import re
from pathlib import Path
from typing import Optional

from .db import get_db
from .idrules import (valid_hostmask, HOSTMASK_RULE_TEXT, valid_channel, valid_nick,
                      CHANNEL_RULE_TEXT, NICK_RULE_TEXT)
from .subnet import local_subnet_id, bot_target_scope
from .bot import BotManager
from . import ircreq

log = logging.getLogger("wbs.helper")
_NICK_RE = re.compile(r'^[A-Za-z0-9_\-\[\]\\`^{}|]+$')
_CHAN_RE = re.compile(r'^[#&][A-Za-z0-9_\-\.]+$')

def clean_message(text: str, max_bytes: int = 255) -> str:
    """
    Sanitize and truncate an IRC message to fit within a byte limit.

    Normalizes line endings, collapses whitespace, and truncates to
    `max_bytes` bytes (UTF-8), appending '...' if truncated.

    Args:
        text: The raw message string to clean.
        max_bytes: Maximum byte length of the output (default: 255).

    Returns:
        A cleaned, byte-safe string.

    Raises:
        ValueError: If max_bytes is less than 4.
    """
    if not text:
        return ""

    if max_bytes < 4:
        raise ValueError(f"max_bytes must be at least 4, got {max_bytes}")

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\n", " ")
    text = " ".join(text.split())

    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text

    truncated = raw[:max_bytes - 3]
    while True:
        try:
            decoded = truncated.decode("utf-8")
            result = decoded + "..."
            if len(result.encode("utf-8")) <= max_bytes:
                return result
            truncated = truncated[:-1]
        except UnicodeDecodeError:
            truncated = truncated[:-1]
            if not truncated:
                return ""
            
def restore_terminal() -> None:
    """Restore terminal echo after prompt_toolkit raw mode.
    
    prompt_toolkit sets the terminal to raw/no-echo mode. If the process
    exits uncleanly (e.g. via os._exit()), this must be called manually
    before exit since finally blocks will not run.
    """
    try:
        if sys.stdin.isatty():
            fd = sys.stdin.fileno()
            attrs = termios.tcgetattr(fd)
            attrs[3] |= termios.ECHO
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
    except Exception as e:
        log.warning("Could not restore terminal state: %s", e)

async def _watch_parent(initial_ppid: int) -> None:
    """Exit if our parent process dies (works on Linux + macOS + Windows)."""
    while True:
        await asyncio.sleep(2)
        current = os.getppid()
        if current != initial_ppid or current == 1:
            log.warning("Parent process gone — self-terminating")
            os._exit(1)

def local_subnet(core) -> int:
    """This bot's subnet: the scope every local user-flag check runs in (SAST-004)."""
    return local_subnet_id(getattr(core, "config", None))

async def _require_flag(core, handle: str, flag: str, respond,
                        channel: Optional[str] = None, session_id=None) -> bool:
    """Return True if handle has the required flag on this bot's subnet
    (global or local grant, active unlocked user); respond+return False otherwise.

    The local foreground console session (session_id of type "console") is the
    operator and passes every flag check; it has no user row to match."""
    if _is_console(core, session_id):
        return True
    if not await core.user.matchattr(handle, flag, channel, subnet_id=local_subnet(core)):
        await respond(f"Access denied (need {flag}).")
        return False
    return True

async def gate_allows(core, handle: str, flag: str) -> bool:
    """Partyline command gate (COMMAND_MIN_FLAGS): may `handle` use a command
    that needs `flag`, in this bot's subnet scope?  Owner (+n) and admin (+A)
    imply channel-op rights (operator decision), so a +o requirement is also
    met by +A or +n."""
    scope = local_subnet(core)
    if await core.user.matchattr(handle, flag, subnet_id=scope):
        return True
    if flag == "o":
        return (await core.user.matchattr(handle, "A", subnet_id=scope)
                or await core.user.matchattr(handle, "n", subnet_id=scope))
    return False

async def _require_op(core, handle: str, respond, session_id=None) -> bool:
    """Channel-op permission check (.op/.deop/.voice/.devoice/.mode): +o, or
    +A/+n, which imply op rights (IRC-14).  The console always passes."""
    if _is_console(core, session_id) or await gate_allows(core, handle, "o"):
        return True
    await respond("Access denied (need +o, or +A/+n).")
    return False

def _scope_label(subnet_id: Optional[int]) -> str:
    return "global" if subnet_id is None else f"subnet {subnet_id}"

def _is_console(core, session_id) -> bool:
    """True only for the local foreground console session (full access)."""
    sessions = getattr(getattr(core, "partyline", None), "sessions", None) or {}
    return (sessions.get(session_id) or {}).get("type") == "console"

async def _authorize_scope_change(core, caller: str, subnet_id: Optional[int], respond,
                                  session_id=None) -> bool:
    """
    May `caller` create or change access rows of scope `subnet_id`?

    Rows of this bot's own subnet need +A here (the caller's command gate).
    Global rows (subnet_id None) and rows of any other subnet need a GLOBAL
    +A grant: a subnet-local admin never mints global or foreign rights.
    The local console session is the operator and is always allowed.
    """
    if _is_console(core, session_id):
        return True
    if subnet_id is not None and int(subnet_id) == local_subnet(core):
        return await _require_flag(core, caller, "+A", respond)
    if await core.user.matchattr(caller, "+A", subnet_id=None):
        return True
    await respond(f"Access denied (need global +A to change {_scope_label(subnet_id)} access).")
    log.warning("scope change denied: %s -> %s", caller, _scope_label(subnet_id))
    return False

async def _can_manage_user(core, caller: str, target: str, respond, session_id=None) -> bool:
    """
    May `caller` perform an account-wide action (delete, lock, password,
    comment) on `target`?  Account-wide changes affect every subnet, so a
    subnet-local admin may only manage users whose access is confined to this
    bot's subnet; anyone else needs a global +A grant.  The local console
    session is always allowed.
    """
    if _is_console(core, session_id):
        return True
    if await core.user.matchattr(caller, "+A", subnet_id=None):
        return True
    local = local_subnet(core)
    if not await core.user.matchattr(caller, "+A", subnet_id=local):
        await respond("Access denied (need +A).")
        return False
    foreign = {s for s in await core.user.access_scopes(target) if s != local}
    if foreign:
        await respond(f"Access denied: {target} has access outside subnet {local} "
                      f"(need global +A).")
        log.warning("user management denied: %s -> %s (foreign scopes %s)",
                    caller, target, sorted(foreign, key=lambda s: -1 if s is None else s))
        return False
    return True

async def _resolve_subnet_arg(
    core, subnet_arg: str | None, respond, *, default_local: bool = False
) -> tuple[int | None, bool]:
    """
    Resolve a subnet name argument to a subnet_id.

    Returns (subnet_id, ok):
      - ok=False means we already responded with an error; caller must return.
      - subnet_id=None means global (no subnet binding).
      - omitted argument: with default_local, this bot's own subnet (the
        authoritative local_subnet_id, never global); otherwise the legacy
        botnet.subnet_id config value (None when unset).
    """
    if subnet_arg is None:
        if default_local:
            return local_subnet(core), True
        return core.config.get("botnet", {}).get("subnet_id", None), True
    if subnet_arg == "*":
        return None, True
    async with get_db(core.db_path) as db:
        cursor = await db.execute("SELECT id FROM subnets WHERE name = ?", (subnet_arg,))
        row = await cursor.fetchone()
    if not row:
        await respond(f"Unknown subnet: {subnet_arg}")
        return None, False
    return row["id"], True            

def _live_chan(core, chan: str):
    """The bot's live state of `chan`, or None (no state kept / not known)."""
    getter = getattr(core, "get_chan", None)
    if getter is None or not hasattr(core, "channels"):
        return None
    return getter(chan)


async def _mode_channel(core, chan: str, respond) -> bool:
    """IRC-8: is `chan` a channel this bot may send MODE to?  False means the
    caller was already told why.

    A channel the bot is in (live state) passes.  Without live state (not yet
    joined, banned, disconnected) only a configured channel of this subnet
    passes and the server's own answer (442 ...) reports the result; any
    other name is refused.
    """
    if not valid_channel(chan):
        await respond(f"{CHANNEL_RULE_TEXT} Got: {chan[:60]!r}")
        return False
    live = _live_chan(core, chan)
    if live is not None and live.joined:
        return True
    manager = getattr(core, "chan", None)
    configured = []
    if manager is not None:
        try:
            configured = await manager.getchans(local_subnet(core)) or []
        except Exception as e:
            log.warning("_mode_channel: channel list unavailable: %s", e)
    if chan.lower() in {c.lower() for c in configured}:
        return True
    await respond(f"Unknown channel {chan}: I am not on it and it is not one of my channels "
                  f"(.+chan adds one).")
    return False


def _nick_on_channel(core, chan: str, nick: str):
    """True/False when live state of `chan` is synced, None when unknown."""
    live = _live_chan(core, chan)
    if live is None or not live.joined or not live.synced:
        return None
    low = nick.lower()
    return any(u.lower() == low for u in live.users)


async def is_same_subnet_bot(core, nick: str) -> Optional[bool]:
    """
    NET-3 / D17: may this bot op/mode `nick` as far as subnets go?

    True  -> `nick` is this bot or a bot of the local subnet.
    False -> `nick` is a bot of another subnet or of unknown scope: refuse.
    None  -> `nick` is not a known bot (a human): no subnet rule applies.

    Same rule (subnet.bot_target_scope) as the botnet-received path in
    BotnetManager.authorize_peer_command; scope comes from our own DB only.
    """
    botnet = getattr(core, "botnet", None)
    peers = getattr(botnet, "peers", None)
    bots = getattr(core, "bot", None)
    if bots is None or not hasattr(bots, "get_subnet_scope"):
        db_path = getattr(core, "db_path", None)
        bots = BotManager(db_path) if db_path else None
    config = getattr(core, "config", None) or {}
    return await bot_target_scope(
        nick, local=local_subnet(core),
        own_names=(getattr(core, "botname", ""), (config.get("bot") or {}).get("nick")),
        peers=list(peers.values()) if isinstance(peers, dict) else (),
        bots=bots)


async def _refuse_cross_subnet_bot(core, handle: str, nick: str, action: str, respond) -> bool:
    """True (caller must stop) when `nick` is a bot outside the local subnet or of
    unknown subnet scope; the caller is told why and the refusal is logged."""
    if await is_same_subnet_bot(core, nick) is not False:
        return False
    local = local_subnet(core)
    log.warning("Denied %s by %s: target %r is a bot outside the local subnet %s "
                "(or of unknown subnet scope)", action, handle, nick, local)
    await respond(f"Refused: {nick} is a bot outside this bot's subnet {local} (or its subnet "
                  f"is not set). Bots only op/mode bots of their own subnet.")
    return True


async def _chan_mode_cmd(core, handle, arg, respond, mode_str: str, label: str, msg: str,
                         session_id=None):
    """Shared implementation for op/deop/voice/devoice.

    The reply is the real outcome (IRC-8): the bot's own MODE echo confirms,
    a server error (482, 441, 401 ...) or silence is reported instead.
    """
    if core.config.get("limbo_hub"):
        return await respond("Cannot use this command as limbo hub.")
    parts = arg.split()
    if len(parts) != 2:
        return await respond(f"Usage: .{label} <nick> <#channel>")
    nick, chan = parts
    if not await _require_op(core, handle, respond, session_id=session_id):
        return
    if not valid_nick(nick, 64):
        return await respond(f"Invalid nick '{nick[:40]}'. {NICK_RULE_TEXT}")
    if await _refuse_cross_subnet_bot(core, handle, nick, label, respond):
        return
    if not await _mode_channel(core, chan, respond):
        return
    sign, letter = mode_str[0], mode_str[1]
    on_chan = _nick_on_channel(core, chan, nick)
    if on_chan is False:
        return await respond(f"{nick} is not on {chan}.")
    live = _live_chan(core, chan)
    if on_chan and live is not None:
        have = live.is_op(nick) if letter == "o" else live.is_voiced(nick)
        if have == (sign == "+"):
            state = {"+o": "already opped", "-o": "not opped",
                     "+v": "already voiced", "-v": "not voiced"}[mode_str]
            return await respond(f"{nick} is {state} on {chan}.")
    ircreq.for_core(core).add_mode(chan, [(sign, letter, nick)],
                                   f"{label} {nick} on {chan}", f"{msg} {nick} on {chan}", respond)
    core.irc_q.put_nowait({"cmd": "mode", "channel": chan, "modes": f"{mode_str} {nick}"})

async def _list_loadables(core, respond, manager_attr: str, config_key: str, src_subdir: str) -> None:
    loaded = sorted(getattr(core, manager_attr).games.keys()
                    if manager_attr == "game"
                    else list(getattr(core, manager_attr).plugins))
    if manager_attr == "plugin":
        # PLG-4: what loads on start is loaded_modules (autoload=1), the same
        # rows the Core autoloads; files come from the plugins package dir.
        from . import plugins as plugin_mod
        auto_load = await core.plugin.autoload_names()
        avail = plugin_mod.plugin_files()
    else:
        auto_load = sorted(core.config.get(config_key, []))
        src_dir = Path("src") / src_subdir
        if src_dir.is_dir():
            avail = sorted(p.stem for p in src_dir.glob("*.py") if p.name != "__init__.py")
        else:
            avail = []
    not_loaded = sorted(set(avail) - set(loaded))
    await respond(
        f"Loaded ({len(loaded)}): {loaded or 'none'}\n"
        f"Auto-load ({len(auto_load)}): {auto_load or 'none'}\n"
        f"On disk ({len(avail)}): {avail or 'none'}\n"
        f"Available to load: {not_loaded or 'none'}"
    )    

def _botnet_sync(core, sync_method: str, op: str, payload: dict) -> None:
    """Fire-and-forget a botnet sync task if botnet is active."""
    if hasattr(core, "botnet"):
        fn = getattr(core.botnet, sync_method, None)
        if fn:
            asyncio.create_task(fn(op, payload))
        else:
            log.warning("_botnet_sync: no method %r on botnet", sync_method)

async def _modify_hostmask(core, handle: str, hostmask: str, add: bool, respond) -> None:
    # Adding is validated (USR-7); removal accepts any string so a legacy
    # invalid mask can still be deleted (UserManager.delhost then says
    # "Host not found" if it is not stored).
    if add and not valid_hostmask(hostmask):
        await respond(HOSTMASK_RULE_TEXT)
        return
    user = await core.user.get(handle)
    if not user:
        await respond("User not found.")
        return
    # UserManager has no save_user(); addhost/delhost persist atomically.
    if add:
        res = await core.user.addhost(handle, hostmask, updated_by=handle)
        if res == "ok":
            await respond(f"Added host: {hostmask}")
        elif res == "duplicate":
            await respond(f"Host already exists: {hostmask}")
        elif res == "wildcard_host":
            await respond(f"Refused: {hostmask} has a host part of only wildcards, "
                          f"which is not allowed for +n/+A users.")
        else:
            await respond("User not found." if res == "not_found"
                          else "Invalid hostmask format. Use: nick!user@host")
    else:
        res = await core.user.delhost(handle, hostmask, updated_by=handle)
        if res == "ok":
            await respond(f"Removed host: {hostmask}")
        elif res == "no_such_host":
            await respond(f"Host not found: {hostmask}")
        else:
            await respond("User not found." if res == "not_found"
                          else "Invalid hostmask format. Use: nick!user@host")

async def _resolve_to_ip(host: str) -> Optional[str]:
    """Return the IP string for a given hostname or IP.  None on failure."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, socket.gethostbyname, host)
    except socket.gaierror:
        return None        
    
def _valid_nick(nick: str) -> bool:
    return bool(nick) and bool(_NICK_RE.match(nick)) and len(nick) <= 32

def _valid_channel(chan: str) -> bool:
    return bool(chan) and bool(_CHAN_RE.match(chan)) and len(chan) <= 50