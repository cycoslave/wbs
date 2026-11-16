# src/ircreq.py
"""
Real results for IRC requests the bot makes on a caller's behalf (IRC-8,
IRC-11).

`.mode`, `.op`, `.deop`, `.voice`, `.devoice` and `.nick` only queue a line to
the IRC process; whether the server accepted it is learned later.  Each
command registers a pending request here with its `respond` callback:

  * the bot's own MODE (or NICK) echo that carries the requested change
    confirms it -> the caller gets the success text;
  * a server error numeric (401, 403, 441, 442, 467, 472, 477, 482, 696, and
    for nicks 432/433) fails the oldest matching request -> the caller gets
    the reason;
  * silence for TIMEOUT seconds (checked from Core's periodic task) ends the
    request with "no confirmation", so the caller never waits forever.

`.swhois` / `.swhowas` (IRC-10) use the same list: the WHOIS/WHOWAS numerics
the server sends back are collected per request and handed to the caller on
the end-of-list numeric (318 / 369); 10 s of silence answers "No reply".

Nothing here blocks: Core's event loop keeps running while a request waits,
and the answer is sent from the event handler that sees the outcome.
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

log = logging.getLogger("wbs.ircreq")

TIMEOUT = 10.0
MAX_PENDING = 200
PREFIX_MODES = frozenset("qaohv")

Respond = Callable[[str], Awaitable[None]]


@dataclass
class Pending:
    kind: str                       # "mode" | "nick" | "whois" | "whowas" | "links"
    desc: str                       # "op bob on #chan"
    ok_text: str
    respond: Respond
    deadline: float
    channel: str = ""               # lower-case; "" for nick requests
    nick: str = ""                  # nick request: the wanted nick
    expect: list = field(default_factory=list)    # [(sign, letter, key)]
    seen: list = field(default_factory=list)
    lines: list = field(default_factory=list)     # whois/whowas: collected output

    def targets(self) -> set:
        return {k for _, ch, k in self.expect if k and ch in PREFIX_MODES}


def _key(letter: str, arg) -> str:
    """Matching key of a change's argument: prefix modes by nick; list, key
    and limit modes by letter only (servers normalise masks and limits)."""
    return (arg or "").lower() if letter in PREFIX_MODES else ""


def describe_error(numeric: str, channel: str, nick: str, text: str, letter: str = "") -> str:
    reason = {
        "401": f"no such nick: {nick}",
        "403": f"no such channel: {channel}",
        "432": f"the server refused '{nick}' as a nick (erroneous nickname)",
        "433": f"nick '{nick}' is already in use",
        "441": f"{nick} is not on {channel}",
        "442": f"I am not on {channel}",
        "467": f"channel key already set on {channel}",
        "472": f"the server does not know mode '{letter}'",
        "477": f"{channel} does not allow this mode change",
        "482": f"I am not a channel operator on {channel}",
        "696": f"the server rejected the mode parameter on {channel}",
    }.get(numeric, "the server refused it")
    return f"{reason} ({numeric}{': ' + text if text else ''})"


WHOIS_NUMERICS = frozenset({"311", "312", "313", "317", "318", "319", "330"})
WHOWAS_NUMERICS = frozenset({"314", "369"})
WHOIS_END = frozenset({"318", "369"})
# `.servlinks` (NET-12): RPL_LINKS / RPL_ENDOFLINKS.
LINKS_NUMERICS = frozenset({"364", "365"})
# Everything the IRC process forwards for a WHOIS/WHOWAS/LINKS (406: was no such nick).
WHOIS_FORWARD = WHOIS_NUMERICS | WHOWAS_NUMERICS | LINKS_NUMERICS | {"406"}


def format_timers(timers: list, now: Optional[float] = None) -> list:
    """`.timers` lines for the IRC process's timer list (NET-9)."""
    if not timers:
        return ["No active IRC timers."]
    now = time.time() if now is None else now
    lines = [f"IRC timers ({len(timers)}):"]
    for t in timers:
        last, nxt = t.get("last_run"), t.get("next_run")
        last_s = "never" if last is None else f"{int(max(0, now - last))}s ago"
        next_s = "-" if nxt is None else f"in {int(max(0, nxt - now))}s"
        try:
            every = f"{int(float(t.get('interval')))}s"
        except (TypeError, ValueError):
            every = "?"
        line = f"  {t.get('name', '?'):<20} every {every}, last {last_s}, next {next_s}"
        if t.get("description"):
            line += f" - {t['description']}"
        lines.append(line)
    return lines


def format_links(a: list) -> str:
    """One line for a 364 RPL_LINKS; `a` = args after our nick: mask server :hops info."""
    a = [str(x) for x in a] + [""] * 3
    hops, _, info = a[2].partition(" ")
    line = f"{a[1]} (via {a[0]}) hops {hops}"
    return f"{line}: {info}" if info else line


def format_whois(numeric: str, a: list) -> str:
    """One readable line for a WHOIS/WHOWAS numeric; `a` = args after our nick."""
    a = list(a) + [""] * 6
    nick = a[0]
    if numeric == "311":                       # nick user host * realname
        return f"{nick} is {a[1]}@{a[2]} * {a[4]}"
    if numeric == "314":
        return f"{nick} was {a[1]}@{a[2]} * {a[4]}"
    if numeric == "312":                       # nick server :info
        return f"{nick} using {a[1]} ({a[2]})"
    if numeric == "313":
        return f"{nick} {a[1] or 'is an IRC operator'}"
    if numeric == "317":                       # nick idle signon :text
        try:
            signon = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(a[2])))
        except (ValueError, OverflowError, OSError):
            signon = a[2]
        return f"{nick} idle {a[1]}s, signed on {signon}"
    if numeric == "319":
        return f"{nick} on {a[1]}"
    if numeric == "330":                       # nick account :text
        return f"{nick} is logged in as {a[1]}"
    return ""


class IrcRequests:
    def __init__(self):
        self.pending: list[Pending] = []

    # -- registration ------------------------------------------------------
    def add_mode(self, channel: str, changes, desc: str, ok_text: str,
                 respond: Respond, now: Optional[float] = None) -> Pending:
        p = Pending("mode", desc, ok_text, respond,
                    (now if now is not None else time.monotonic()) + TIMEOUT,
                    channel=channel.lower(),
                    expect=[(s, ch, _key(ch, a)) for s, ch, a in changes])
        return self._put(p)

    def add_nick(self, nick: str, respond: Respond, now: Optional[float] = None) -> Pending:
        p = Pending("nick", f"change nick to {nick}", f"Nick is now {nick}", respond,
                    (now if now is not None else time.monotonic()) + TIMEOUT,
                    nick=nick)
        return self._put(p)

    def add_whois(self, kind: str, nick: str, respond: Respond,
                  now: Optional[float] = None) -> Pending:
        """`.swhois` / `.swhowas`; kind is "whois" or "whowas"."""
        p = Pending(kind, f"{kind.upper()} {nick}", "", respond,
                    (now if now is not None else time.monotonic()) + TIMEOUT,
                    nick=nick)
        return self._put(p)

    def add_links(self, respond: Respond, now: Optional[float] = None) -> Pending:
        """`.servlinks`: collects the server's LINKS list (364 ... 365)."""
        p = Pending("links", "LINKS", "", respond,
                    (now if now is not None else time.monotonic()) + TIMEOUT)
        return self._put(p)

    def add_timers(self, respond: Respond, now: Optional[float] = None) -> Pending:
        """`.timers` (NET-9): a request to the IRC process; `nick` carries
        the request id echoed in its IRC_TIMERS answer."""
        self._seq = getattr(self, "_seq", 0) + 1
        p = Pending("timers", ".timers", "", respond,
                    (now if now is not None else time.monotonic()) + TIMEOUT,
                    nick=f"t{self._seq}")
        return self._put(p)

    async def on_timers(self, req_id, timers) -> bool:
        """The IRC process answered a `.timers` request."""
        p = next((x for x in self.pending
                  if x.kind == "timers" and x.nick == req_id), None)
        if p is None:
            return False
        self.pending.remove(p)
        for line in format_timers(timers or []):
            await self._say(p, line)
        return True

    def _put(self, p: Pending) -> Pending:
        if len(self.pending) >= MAX_PENDING:
            self.pending.pop(0)
        self.pending.append(p)
        return p

    async def _say(self, p: Pending, text: str) -> None:
        try:
            await p.respond(text)
        except Exception as e:          # a closed session must not stop Core
            log.debug("ircreq: reply to caller failed: %s", e)

    # -- outcomes ----------------------------------------------------------
    async def on_mode(self, channel: str, changes) -> None:
        """The bot's own MODE on `channel`; changes = [(sign, letter, arg)]."""
        channel = (channel or "").lower()
        for p in [x for x in self.pending if x.kind == "mode" and x.channel == channel]:
            for sign, ch, arg in changes:
                want = (sign, ch, _key(ch, arg))
                if want in p.expect and want not in p.seen:
                    p.seen.append(want)
            if len(p.seen) >= len(p.expect):
                self.pending.remove(p)
                await self._say(p, p.ok_text)

    async def on_nick(self, new_nick: str) -> None:
        """The bot's nick changed to `new_nick`."""
        for p in [x for x in self.pending if x.kind == "nick"]:
            if p.nick.lower() == (new_nick or "").lower():
                self.pending.remove(p)
                await self._say(p, p.ok_text)

    async def on_whois_numeric(self, numeric: str, args) -> bool:
        """A WHOIS/WHOWAS numeric (`args` exclude the bot's own nick).  It
        belongs to the oldest pending request of the right kind for that
        nick; 318/369 end the list and send everything collected to the
        caller.  401/406 (no such nick) end the request at once.  Returns
        False when no pending request owns it."""
        args = [str(a) for a in (args or [])]
        if numeric in LINKS_NUMERICS:
            p = next((x for x in self.pending if x.kind == "links"), None)
            if p is None:
                return False
            if numeric == "365":
                self.pending.remove(p)
                for line in p.lines or ["The server returned no links."]:
                    await self._say(p, line)
                await self._say(p, f"End of LINKS ({len(p.lines)} server(s)).")
            else:
                p.lines.append(format_links(args))
            return True
        nick = args[0].lower() if args else ""
        if numeric in ("401", "406"):
            kinds = ("whois", "whowas")
        else:
            kinds = ("whowas",) if numeric in WHOWAS_NUMERICS else ("whois",)
        p = next((x for x in self.pending
                  if x.kind in kinds and x.nick.lower() == nick), None)
        if p is None:
            return False
        if numeric in WHOIS_END or numeric in ("401", "406"):
            self.pending.remove(p)
            if numeric in ("401", "406"):
                p.lines.append(f"No such nick: {p.nick}"
                               + (f" ({args[1]})" if len(args) > 1 and args[1] else ""))
            for line in p.lines or [f"No information for {p.nick}."]:
                await self._say(p, line)
            return True
        line = format_whois(numeric, args)
        if line:
            p.lines.append(line)
        return True

    async def on_error(self, numeric: str, channel: str = "", nick: str = "",
                       text: str = "", letter: str = "") -> bool:
        """A server error numeric.  Fails the oldest request it belongs to;
        returns False when it belongs to none (someone else's command)."""
        channel, low = (channel or "").lower(), (nick or "").lower()
        for p in self.pending:
            if numeric in ("432", "433"):
                hit = p.kind == "nick" and p.nick.lower() == low
            elif p.kind != "mode":
                hit = False
            elif numeric == "401":
                hit = low in p.targets()
            elif numeric == "441":
                hit = p.channel == channel and low in p.targets()
            elif numeric == "472":
                hit = any(ch == letter for _, ch, _ in p.expect)
            else:       # 403 442 467 477 482 696: by channel
                hit = p.channel == channel
            if hit:
                self.pending.remove(p)
                msg = describe_error(numeric, channel or p.channel, nick, text, letter)
                await self._say(p, f"Could not {p.desc}: {msg}")
                return True
        return False

    async def expire(self, now: Optional[float] = None) -> None:
        now = now if now is not None else time.monotonic()
        for p in [x for x in self.pending if x.deadline <= now]:
            self.pending.remove(p)
            if p.kind in ("whois", "whowas", "links"):
                for line in p.lines:
                    await self._say(p, line)
                tail = " (list incomplete)" if p.lines else ""
                await self._say(p, f"No reply from the server to {p.desc}{tail}.")
            elif p.kind == "timers":
                await self._say(p, "No reply from the IRC process to .timers.")
            elif p.seen and p.kind == "mode":
                done = ", ".join(f"{s}{ch}" for s, ch, _ in p.seen)
                await self._say(p, f"Could not fully {p.desc}: the server confirmed only {done}.")
            else:
                await self._say(p, f"No confirmation from the server to {p.desc}; "
                                   "it may have changed nothing.")


def for_core(core) -> IrcRequests:
    """The Core's IrcRequests, created on first use."""
    reqs = getattr(core, "ircreq", None)
    if reqs is None:
        reqs = IrcRequests()
        core.ircreq = reqs
    return reqs
