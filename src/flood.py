# src/flood.py
"""
Flood protection (IRC-7).

Channel limits come from the channels table, one pair of columns per kind:
flood_<kind> = N events, flood_<kind>_time = S seconds (`.chaninfo` shows
them as `N/Ss`).  More than N events inside any S-second window is a flood;
N = 0 or S = 0 disables that kind.

  kind   counted per        counted on                       action
  pub    channel + host     PRIVMSG / NOTICE / ACTION to it  kick + ban
  ctcp   channel + host     CTCP to the channel              kick + ban
  join   channel + host     JOIN                             kick + ban
  nick   channel + host     NICK change while on it          kick
  kick   channel + nick     KICK by that op                  deop
  deop   channel + nick     -o by that op                    deop

Public channel text (pub: PUBMSG, channel NOTICE/ACTION) is decided BEFORE
plugins and games see it (SAST-001, `FloodProtect.public`): once a host
floods a channel, its text there is dropped for that channel's flood_pub_time
seconds (the "mute"), whether or not the bot holds op to kick/ban.  Every
other kind only counts and acts; nothing else is dropped.

Bans are `*!*@host` and are lifted again after FLOOD_BAN_SECONDS (only if
the bot set them).  Nobody is touched who is the bot itself, a recognised
user with op rights (+o, or +A/+n, which imply op rights), or one of our
op bots; pub/ctcp/join/nick floods also spare whoever is opped on the
channel.  Nothing is sent while the bot has no op on the channel; that is
logged once per channel until the bot is opped again.

The bot's own limit (config `settings.flood_msg` for private messages,
`settings.flood_ctcp` for CTCP requests, "N:S", "0" = off; defaults 5:60
and 3:60): the flooding host is dropped and put on the ignore list as
`*!*@host` for PRIVATE_IGNORE_SECONDS.  Owner/admin hostmasks are never
ignored (same rule as `.+ignore`).  CTCP is checked in the IRC process
(before any reply goes out); private messages in Core.

Every counter is a sliding window kept in memory (FloodGuard); counters of
idle keys are pruned, so a host-cycling flood cannot grow memory unbounded.
"""
import logging
import time
from collections import deque
from typing import Callable, Optional

log = logging.getLogger("wbs.flood")

FLOOD_BAN_SECONDS = 600          # temporary ban for pub/ctcp/join floods
PRIVATE_IGNORE_SECONDS = 60      # ignore for the bot's own PM/CTCP limit
SETTINGS_TTL = 10.0              # seconds a channels row stays cached
MAX_KEYS = 5000                  # counters kept before idle ones are pruned

DEFAULT_MSG_RATE = (5, 60)
DEFAULT_CTCP_RATE = (3, 60)

KINDS = ("pub", "ctcp", "join", "nick", "kick", "deop")
BAN_KINDS = frozenset({"pub", "ctcp", "join"})
REASONS = {
    "pub": "Channel flood",
    "ctcp": "CTCP flood",
    "join": "Join flood",
    "nick": "Nick flood",
}


def parse_rate(value) -> Optional[tuple]:
    """Config rate -> (N, S), or None when disabled.

    Accepts "N:S" (non-negative integers), 0 / "0" (off).  N:0 and 0:S are
    off as well.  Anything else raises ValueError."""
    if isinstance(value, bool):
        raise ValueError(f"not a rate: {value!r}")
    if isinstance(value, int):
        if value == 0:
            return None
        raise ValueError(f"rate must be \"N:S\" or 0, got {value!r}")
    if not isinstance(value, str):
        raise ValueError(f"rate must be \"N:S\" or 0, got {value!r}")
    text = value.strip()
    if text == "0":
        return None
    count, sep, secs = text.partition(":")
    if not sep or not count.isdigit() or not secs.isdigit():
        raise ValueError(f"rate must be \"N:S\" (e.g. 5:60) or 0, got {value!r}")
    count, secs = int(count), int(secs)
    if count <= 0 or secs <= 0:
        return None
    return count, secs


def config_rate(config, key: str, default: tuple) -> Optional[tuple]:
    """`settings.<key>` from the config as (N, S) / None; bad or missing
    values fall back to `default` (configcheck reports bad ones)."""
    settings = (config or {}).get("settings") if isinstance(config, dict) else None
    if not isinstance(settings, dict) or settings.get(key) is None:
        return default
    try:
        return parse_rate(settings[key])
    except ValueError:
        return default


def _as_int(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def channel_limit(settings: dict, kind: str) -> Optional[tuple]:
    """(N, S) for `kind` from a channels row, None when disabled/missing."""
    count = _as_int(settings.get(f"flood_{kind}"))
    secs = _as_int(settings.get(f"flood_{kind}_time"))
    if not count or not secs:
        return None
    return count, secs


class FloodGuard:
    """Sliding-window counters: hit() is True once a key has seen more than
    `limit` events in the last `window` seconds (then the key starts over,
    so one flood triggers one action)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = MAX_KEYS):
        self.clock = clock
        self.max_keys = max_keys
        self._hits: dict = {}            # key -> (window, deque of times)

    def hit(self, key, limit: int, window: float) -> bool:
        if not limit or not window or limit <= 0 or window <= 0:
            return False
        now = self.clock()
        entry = self._hits.get(key)
        if entry is None:
            if len(self._hits) >= self.max_keys:
                self.prune(now)
            entry = self._hits[key] = (window, deque())
        stamps = entry[1]
        stamps.append(now)
        while stamps and stamps[0] <= now - window:
            stamps.popleft()
        if len(stamps) > limit:
            del self._hits[key]
            return True
        if entry[0] != window:
            self._hits[key] = (window, stamps)
        return False

    def forget(self, key) -> None:
        self._hits.pop(key, None)

    def prune(self, now: Optional[float] = None) -> None:
        """Drop counters with no event inside their window; if that is not
        enough (a host-cycling flood), start over."""
        now = self.clock() if now is None else now
        for key in [k for k, (w, s) in self._hits.items() if not s or s[-1] <= now - w]:
            del self._hits[key]
        if len(self._hits) >= self.max_keys:
            self._hits.clear()

    def __len__(self) -> int:
        return len(self._hits)


def _userhost(full: str) -> str:
    """'nick!user@host' or 'user@host' -> 'user@host' ('' if none)."""
    full = full or ""
    return full.partition("!")[2] if "!" in full else full


def ban_mask(userhost: str) -> Optional[str]:
    if "@" not in (userhost or ""):
        return None
    host = userhost.rsplit("@", 1)[1]
    return f"*!*@{host}" if host else None


class FloodProtect:
    """Core-side flood protection: channel limits + the bot's PM limit."""

    def __init__(self, core, clock: Callable[[], float] = time.monotonic):
        self.core = core
        self.clock = clock
        self.guard = FloodGuard(clock)
        self._settings: dict = {}        # channel -> (expires, row)
        self._no_op_logged: set = set()
        self.unbans: list = []           # [(due, channel, mask)]
        self.ignored: dict = {}          # *!*@host -> until (PM drop, Core side)
        self.muted: dict = {}            # ("pub", channel, host) -> until (SAST-001)
        self.msg_rate = config_rate(getattr(core, "config", None), "flood_msg",
                                    DEFAULT_MSG_RATE)

    # --- channel settings ------------------------------------------------
    async def settings(self, channel: str) -> dict:
        from . import automode
        now = self.clock()
        key = channel.lower()
        cached = self._settings.get(key)
        if cached and cached[0] > now:
            return cached[1]
        row = await automode.channel_settings(self.core, channel)
        self._settings[key] = (now + SETTINGS_TTL, row)
        return row

    def invalidate(self, channel: Optional[str] = None) -> None:
        if channel is None:
            self._settings.clear()
        else:
            self._settings.pop(channel.lower(), None)

    # --- exemptions ------------------------------------------------------
    def _is_me(self, nick: str) -> bool:
        me = (getattr(self.core, "botname", "") or "").lower()
        return bool(nick) and nick.lower() == me

    async def exempt(self, chan, nick: str, userhost: str, kind: str = "") -> bool:
        """The bot, recognised users with op rights, our op bots; for
        pub/ctcp/join/nick floods also whoever is opped on the channel now
        (kick/deop floods are by ops, so op status exempts nobody there)."""
        from . import automode
        if not nick or self._is_me(nick):
            return True
        if kind not in ("kick", "deop") and chan.is_op(nick):
            return True
        if userhost:
            handle = await self.core.user.match_user(f"{nick}!{userhost}")
            if handle and await automode.has_op_rights(self.core, handle, chan.name):
                return True
        return await automode._is_op_bot(self.core, nick, userhost, chan.name)

    # --- channel floods --------------------------------------------------
    async def check(self, kind: str, channel: str, nick: str, host: str = "") -> bool:
        """Count one `kind` event by `nick` (host 'nick!user@host' or
        'user@host'; the live channel's WHO host is used when missing) and
        act when it is a flood.  True when an action was sent."""
        core = self.core
        chan = core.get_chan(channel) if channel else None
        if chan is None or not chan.joined or not nick or self._is_me(nick):
            return False
        userhost = _userhost(host) or chan.hosts.get(nick.lower(), "")
        if kind in ("kick", "deop"):
            key = (kind, chan.name, nick.lower())
        else:
            if "@" not in userhost:
                return False
            key = (kind, chan.name, userhost.rsplit("@", 1)[1].lower())
        settings = await self.settings(chan.name)
        if not settings or settings.get("is_inactive"):
            return False
        limit = channel_limit(settings, kind)
        if limit is None or not self.guard.hit(key, *limit):
            return False
        if await self.exempt(chan, nick, userhost, kind):
            log.info("flood: %s %s flood by %s ignored (exempt)", chan.name, kind, nick)
            return False
        return self._enforce(chan, kind, nick, userhost)

    def _enforce(self, chan, kind: str, nick: str, userhost: str) -> bool:
        """Act on a confirmed (non-exempt) flood when the bot is opped.
        True when an action was sent."""
        if not chan.bot_op:
            if chan.name not in self._no_op_logged:
                self._no_op_logged.add(chan.name)
                log.warning("flood: %s flood by %s on %s, but I have no op there; "
                            "not acting (logged once until I get op)", kind, nick, chan.name)
            return False
        self._no_op_logged.discard(chan.name)
        return self._act(chan, kind, nick, userhost)

    # --- public channel text: the pre-dispatch gate (SAST-001) ------------
    async def public(self, channel: str, nick: str, host: str = "",
                     count: bool = True) -> bool:
        """Decide one piece of public channel text by `nick` on `channel`
        BEFORE any plugin or game sees it.  True = drop it.

        `count=False` only consults the mute (an ACTION whose CHAN_ACTIVITY
        was already counted).  A flood by a non-exempt host kicks/bans when
        the bot is opped (as `check`) and, opped or not, mutes that host on
        that channel for the flood_pub_time window: its text there is
        dropped until the mute ends.  Exempt users (the bot, recognised op
        rights, our op bots, whoever is opped now) are never dropped."""
        chan = self.core.get_chan(channel) if channel else None
        if chan is None or not chan.joined or not nick or self._is_me(nick):
            return False
        userhost = _userhost(host) or chan.hosts.get(nick.lower(), "")
        if "@" not in userhost:
            return False
        settings = await self.settings(chan.name)
        if not settings or settings.get("is_inactive"):
            return False
        limit = channel_limit(settings, "pub")
        if limit is None:
            return False
        key = ("pub", chan.name, userhost.rsplit("@", 1)[1].lower())
        now = self.clock()
        until = self.muted.get(key)
        if until is not None:
            if until > now and not chan.is_op(nick):
                return True
            del self.muted[key]
        if not count or not self.guard.hit(key, *limit):
            return False
        if await self.exempt(chan, nick, userhost, "pub"):
            log.info("flood: %s pub flood by %s ignored (exempt)", chan.name, nick)
            return False
        self._mute(key, now + limit[1], now)
        self._enforce(chan, "pub", nick, userhost)
        log.info("flood: %s pub flood by %s!%s: dropping its text for %ds",
                 chan.name, nick, userhost, limit[1])
        return True

    def _mute(self, key, until: float, now: float) -> None:
        if key not in self.muted and len(self.muted) >= MAX_KEYS:
            for k in [k for k, u in self.muted.items() if u <= now]:
                del self.muted[k]
            if len(self.muted) >= MAX_KEYS:
                # A host-cycling flood: forget the oldest-ending mute.
                del self.muted[min(self.muted, key=lambda k: self.muted[k])]
        self.muted[key] = until

    def _act(self, chan, kind: str, nick: str, userhost: str) -> bool:
        send = self.core.send_irc
        if kind in ("kick", "deop"):
            if not chan.is_op(nick):
                return False
            send({"cmd": "mode", "channel": chan.name, "modes": f"-o {nick}"})
            log.warning("flood: %s flood by %s on %s: deopped", kind, nick, chan.name)
            return True
        if kind in BAN_KINDS:
            mask = ban_mask(userhost)
            if mask and mask not in chan.live_bans:
                send({"cmd": "mode", "channel": chan.name, "modes": f"+b {mask}"})
                self.unbans.append((self.clock() + FLOOD_BAN_SECONDS, chan.name, mask))
        if nick.lower() in chan.users:
            send({"cmd": "kick", "channel": chan.name, "nick": nick,
                  "reason": REASONS.get(kind, "Flood")})
        log.warning("flood: %s flood by %s!%s on %s: kicked%s", kind, nick, userhost,
                    chan.name, " and banned" if kind in BAN_KINDS else "")
        return True

    def expire_bans(self) -> list:
        """Lift flood bans that are due (bot opped, ban still set). Returns
        the (channel, mask) pairs unbanned."""
        now = self.clock()
        due = [u for u in self.unbans if u[0] <= now]
        if not due:
            return []
        done, keep = [], [u for u in self.unbans if u[0] > now]
        for item in due:
            _, channel, mask = item
            chan = self.core.get_chan(channel)
            if chan is None or not chan.joined or mask not in chan.live_bans:
                continue                    # gone, or someone removed it
            if not chan.bot_op:
                keep.append(item)           # retry once the bot is opped
                continue
            self.core.send_irc({"cmd": "mode", "channel": chan.name, "modes": f"-b {mask}"})
            done.append((chan.name, mask))
        self.unbans = keep
        if done:
            log.info("flood: lifted bans %s", done)
        return done

    # --- the bot's own private-message limit -----------------------------
    async def private(self, event: dict) -> bool:
        """Count a private message to the bot.  True = drop it (flooding
        host, now ignored for PRIVATE_IGNORE_SECONDS)."""
        full = event.get("host", "") or ""
        userhost = _userhost(full)
        mask = ban_mask(userhost)
        if mask is None:
            return False
        now = self.clock()
        until = self.ignored.get(mask)
        if until is not None:
            if until > now:
                return True
            del self.ignored[mask]
        if self.msg_rate is None:
            return False
        if not self.guard.hit(("msg", mask.lower()), *self.msg_rate):
            return False
        nick = event.get("nick", "") or full.partition("!")[0]
        if not await add_ignore(self.core, mask, f"{nick}!{userhost}", "PM flood"):
            return False
        self.ignored[mask] = now + PRIVATE_IGNORE_SECONDS
        return True


async def add_ignore(core, mask: str, source: str, reason: str,
                     seconds: int = PRIVATE_IGNORE_SECONDS) -> bool:
    """Put `mask` on the ignore list for `seconds` (rounded up to whole
    minutes, the ignore list's unit) and tell the IRC process.  Refused for
    owner/admin hostmasks; False when refused or already ignored."""
    from . import ignore as ignore_mod
    from .db import get_db
    from .subnet import local_subnet_id
    minutes = max(1, -(-int(seconds) // 60))
    async with get_db(core.db_path) as db:
        await ignore_mod.purge_expired(db)
        for prot in await ignore_mod.protected_masks(db, local_subnet_id(core.config)):
            if ignore_mod.masks_overlap(mask, prot) or ignore_mod.irc_match(prot, source):
                log.info("flood: %s by %s not ignored: owner/admin hostmask %s",
                         reason, source, prot)
                return False
        existing = await db.execute_fetchall(
            "SELECT 1 FROM ignores WHERE LOWER(hostmask) = LOWER(?) AND deleted_at IS NULL",
            (mask,))
        if existing:
            return False
        await db.execute(
            "DELETE FROM ignores WHERE LOWER(hostmask) = LOWER(?) AND deleted_at IS NOT NULL",
            (mask,))
        await db.execute(
            "INSERT INTO ignores (hostmask, flags, comment, created_at, created_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (mask, f"{minutes}m", f"{reason} ({source})", int(time.time()),
             getattr(core, "botname", None) or "flood"))
    core.send_irc({"cmd": "reload_ignores"})
    log.warning("flood: %s by %s: ignoring %s for %dm", reason, source, mask, minutes)
    return True


def for_core(core) -> FloodProtect:
    """The Core's FloodProtect, created on first use."""
    fp = getattr(core, "flood", None)
    if fp is None:
        fp = FloodProtect(core)
        core.flood = fp
    return fp
