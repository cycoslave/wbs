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
from pathlib import Path
from typing import Optional

from .db import get_db

log = logging.getLogger("wbs.helper")

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

async def _require_flag(core, handle: str, flag: str, respond) -> bool:
    """Return True if handle has the required flag; respond+return False otherwise."""
    if not await core.user.matchattr(handle, flag):
        await respond(f"Access denied (need {flag}).")
        return False
    return True

async def _resolve_subnet_arg(
    core, subnet_arg: str | None, respond
) -> tuple[int | None, bool]:
    """
    Resolve a subnet name argument to a subnet_id.

    Returns (subnet_id, ok):
      - ok=False means we already responded with an error; caller must return.
      - subnet_id=None means global (no subnet binding).
    """
    if subnet_arg is None:
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

async def _chan_mode_cmd(core, handle, arg, respond, mode_str: str, label: str, msg: str):
    """Shared implementation for op/deop/voice/devoice."""
    if core.config.get("limbo_hub"):
        return await respond("Cannot use this command as limbo hub.")
    parts = arg.split()
    if len(parts) < 2:
        return await respond(f"Usage: .{label} <nick> <#channel>")
    nick, chan = parts[0], parts[1]
    if not await _require_flag(core, handle, "+o", respond):
        return
    core.irc_q.put_nowait({"cmd": "mode", "channel": chan, "modes": f"{mode_str} {nick}"})
    await respond(f"{msg} {nick} on {chan}")

async def _list_loadables(core, respond, manager_attr: str, config_key: str, src_subdir: str) -> None:
    loaded = sorted(getattr(core, manager_attr).games.keys()
                    if manager_attr == "game"
                    else getattr(core, manager_attr).plugins.keys())
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
    if "!" not in hostmask or "@" not in hostmask:
        await respond("Invalid hostmask format. Use: nick!user@host")
        return
    user = core.user.get(handle)
    if not user:
        await respond("User not found.")
        return
    hosts: list[str] = user.hostmasks
    if add:
        if hostmask in hosts:
            await respond(f"Host already exists: {hostmask}")
            return
        hosts.append(hostmask)
        await core.user.save_user(user)
        await respond(f"Added host: {hostmask}")
    else:
        if hostmask not in hosts:
            await respond(f"Host not found: {hostmask}")
            return
        hosts.remove(hostmask)
        await core.user.save_user(user)
        await respond(f"Removed host: {hostmask}")

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