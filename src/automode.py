# src/automode.py
"""
Join-time channel enforcement (IRC-6): auto-op, auto-voice, auto-kick and
+bitch, from the user_access and channels tables.

Who gets what (a "recognised" user is a joiner whose nick!user@host matches a
live user's hostmask, the same match as every other IRC check; flags are read
with UserManager.matchattr in this bot's subnet scope, from the global row or
the row of this channel):

  user +k (autokick)   kicked; when the channel has enforcebans on, the bot
                       first sets a ban on *!*@host.
  user +a (autoop)     opped (unless the user also has +d).
  channel autoop       recognised users with op rights (+o, or +A/+n, which
                       imply op rights, IRC-14) are opped even without +a.
  user +v              voiced when the channel has autovoice on (unless +q).
  channel bitch        only recognised users with op rights, and bots with
                       +o, may hold op: anyone else opped by someone other
                       than the bot is deopped.

Strangers (no matching user) are never opped or voiced: the schema has no
"everyone" setting.  Nothing is sent unless the bot itself is opped (voice
and kick also work with halfop), so a bot without op never spams errors.

Runs for every join on a synced channel, and once for everyone present when
the bot's own sync ends (WHO list complete) and when the bot gets op.
"""
import fnmatch
import json
import logging
from typing import Optional

from .db import get_db
from .subnet import local_subnet_id

log = logging.getLogger("wbs.automode")

AUTOKICK_REASON = "Autokick"


def _scope(core) -> Optional[int]:
    return local_subnet_id(getattr(core, "config", None))


async def _has(core, handle: str, flag: str, channel: str) -> bool:
    """`handle` holds `flag` globally or on `channel` (this bot's subnet)."""
    user, sid = core.user, _scope(core)
    if await user.matchattr(handle, flag, subnet_id=sid):
        return True
    return await user.matchattr(handle, f"*|{flag}", channel, subnet_id=sid)


async def has_op_rights(core, handle: str, channel: str) -> bool:
    """+o (global or on this channel), or +A/+n, which imply op rights (IRC-14)."""
    if await _has(core, handle, "o", channel):
        return True
    sid = _scope(core)
    return (await core.user.matchattr(handle, "A", subnet_id=sid)
            or await core.user.matchattr(handle, "n", subnet_id=sid))


async def channel_settings(core, channel: str) -> dict:
    """The channel's DB row (case-insensitive name), {} if it has none."""
    async with get_db(core.db_path) as db:
        async with db.execute(
            "SELECT * FROM channels WHERE LOWER(name) = LOWER(?) AND deleted_at IS NULL "
            "ORDER BY (name = ?) DESC LIMIT 1", (channel, channel)) as cur:
            row = await cur.fetchone()
    return dict(row) if row else {}


async def _recognise(core, chan, nick: str) -> Optional[str]:
    host = chan.hosts.get(nick.lower())
    if not host:
        return None
    return await core.user.match_user(f"{nick}!{host}")


async def _is_op_bot(core, nick: str, host: str, channel: str) -> bool:
    """A bot of ours: a linked peer's nick, or a bots-table hostmask match
    whose bot_access grants +o (global or on this channel)."""
    botnet = getattr(core, "botnet", None)
    for link in (getattr(botnet, "peers", None) or {}).values():
        if (getattr(link, "nick", None) or "").lower() == nick.lower():
            return True
    if not host:
        return False
    full = f"{nick}!{host}".lower()
    async with get_db(core.db_path) as db:
        rows = await db.execute_fetchall(
            "SELECT handle, hostmasks FROM bots WHERE deleted_at IS NULL")
    for row in rows:
        try:
            masks = json.loads(row["hostmasks"] or "[]")
        except (json.JSONDecodeError, TypeError, ValueError):
            masks = []
        if any(isinstance(m, str) and fnmatch.fnmatch(full, m.lower()) for m in masks):
            bots = getattr(core, "bot", None)
            if bots is None:
                return False
            return (await bots.matchattr(row["handle"], "+o")
                    or await bots.matchattr(row["handle"], "+o", channel))
    return False


async def _decide(core, chan, nick: str, settings: dict) -> Optional[str]:
    """'kick', 'op', 'voice' or None for one member of `chan`."""
    handle = await _recognise(core, chan, nick)
    if not handle:
        return None                       # strangers: never anything
    name = chan.name
    if await _has(core, handle, "k", name):
        return "kick"
    if not chan.is_op(nick) and not await _has(core, handle, "d", name):
        if await _has(core, handle, "a", name):
            return "op"
        if settings.get("is_autoop") and await has_op_rights(core, handle, name):
            return "op"
    if (settings.get("is_autovoice") and not chan.is_op(nick) and not chan.is_voiced(nick)
            and await _has(core, handle, "v", name)
            and not await _has(core, handle, "q", name)):
        return "voice"
    return None


def _can(chan, action: str) -> bool:
    if action == "op":
        return chan.bot_op
    return chan.bot_op or chan.bot_halfop    # voice, kick


async def apply(core, chan, nicks) -> dict:
    """Enforce auto-modes for `nicks` of the live channel `chan`; returns
    {'op': [...], 'voice': [...], 'kick': [...]} of what was sent."""
    done = {"op": [], "voice": [], "kick": []}
    if chan is None or not chan.joined or not (chan.bot_op or chan.bot_halfop):
        return done
    settings = await channel_settings(core, chan.name)
    if settings.get("is_inactive"):
        return done
    me = (core.botname or "").lower()
    for nick in nicks:
        if not nick or nick.lower() == me:
            continue
        try:
            action = await _decide(core, chan, nick, settings)
        except Exception as e:            # one bad row never stops the sweep
            log.error("automode: %s on %s: %s", nick, chan.name, e)
            continue
        if action and _can(chan, action):
            done[action].append(nick)

    for nick in done["kick"]:
        host = chan.hosts.get(nick.lower(), "")
        if settings.get("is_enforcebans") and chan.bot_op and "@" in host:
            core.send_irc({"cmd": "mode", "channel": chan.name,
                           "modes": f"+b *!*@{host.split('@', 1)[1]}"})
        core.send_irc({"cmd": "kick", "channel": chan.name, "nick": nick,
                       "reason": AUTOKICK_REASON})
    for action, mode in (("op", "o"), ("voice", "v")):
        if done[action]:
            core.send_irc({"cmd": "mass_mode", "channel": chan.name, "sign": "+",
                           "mode": mode, "nicks": done[action]})
    if any(done.values()):
        log.info("automode %s: %s", chan.name,
                 {k: v for k, v in done.items() if v})
    return done


async def sweep(core, chan) -> dict:
    """Everyone in the channel (after the bot's own sync, or on getting op)."""
    if chan is None or not chan.synced:
        return {"op": [], "voice": [], "kick": []}
    return await apply(core, chan, list(chan.users))


async def enforce_bitch(core, chan, opped, setter: str) -> list:
    """+bitch: deop members opped by someone else who have no op rights."""
    if chan is None or not chan.bot_op or not opped:
        return []
    me = (core.botname or "").lower()
    if setter and setter.lower() == me:
        return []
    settings = await channel_settings(core, chan.name)
    if not settings.get("is_bitch"):
        return []
    deop = []
    for nick in opped:
        if not nick or nick.lower() == me:
            continue
        handle = await _recognise(core, chan, nick)
        if handle and await has_op_rights(core, handle, chan.name):
            continue
        if await _is_op_bot(core, nick, chan.hosts.get(nick.lower(), ""), chan.name):
            continue
        deop.append(nick)
    if deop:
        core.send_irc({"cmd": "mass_mode", "channel": chan.name, "sign": "-",
                       "mode": "o", "nicks": deop})
        log.info("bitch %s: deop %s (opped by %s)", chan.name, deop, setter)
    return deop
