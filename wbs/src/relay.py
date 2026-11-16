# src/relay.py
"""
Interactive partyline relay between directly linked bots (SAST-017).

A user on bot O(rigin) types `.relay T` (persistent) or `.relay T <cmd>`
(one-shot); their input then runs on bot T(arget) as *their own* handle, with
T's own authorization, and T's responses are shown in their O session.

Wire protocol (one line per message, over an AUTH2-authenticated botlink):

    RELAY <json object>

    op       direction   fields
    -------  ----------  ---------------------------------------------------
    open     O -> T      rid, handle            [, text  (one-shot command)]
    opened   T -> O      rid
    input    O -> T      rid, text
    output   T -> O      rid, text
    close    O <-> T     rid                    [, reason]

Every object also carries "v": 1.  Unknown ops, unknown or missing keys and
wrongly typed values are rejected (default deny); there is no "origin" or
"from" field: the origin of a message is always the authenticated link it
arrived on (`from_bot`, whose writer owns the registered BotLink).

Session ownership:

  * rid is a fresh 128-bit random hex id minted by the origin bot
    (secrets.token_hex), never a predictable local session number.
  * T keys an inbound relay by (sending peer, rid) and binds it to the exact
    BotLink object that opened it; O keys an outbound relay by rid and binds
    it to the target's BotLink.  input/output/close for a rid are honoured
    only from that same live link, so another peer (or a re-link under the
    same name) can neither inject input, forge output, nor close a session.

Authorization on the target (all required, checked at open and per input):

  * the sender is an authenticated peer of the local subnet (SAST-002);
  * the operator explicitly delegated authentication of *this user* to that
    peer in config `botnet.relay_from` = {"<peer>": ["<handle>", ...]}
    ("*" = any local user; default: nobody), so one trusted peer cannot
    assert the identity of a user who logs in on another bot;
  * the asserted handle is a real, active (unlocked, not deleted) user of this
    bot holding +p in this bot's subnet scope; "console" is never accepted.

Relayed input then runs through Partyline._handle_command on a virtual
session of type "relay": the same single authorization choke point as
telnet/DCC (COMMAND_MIN_FLAGS + matchattr in local subnet scope, SAST-004
active check).  A relay session is never a console session, so it never
receives console privileges.  Commands that would change the relayed
identity or nest relays are refused on relay sessions.

Origin side: `.relay` itself requires +A (COMMAND_MIN_FLAGS); the console
pseudo-user has no identity on other bots and cannot relay; the user must be
active and still hold the relay flag for every forwarded line.

Sync/async contract: sending is synchronous (`_send` writes one line to the
peer's StreamWriter, preserving order); Partyline.send_to_session is
synchronous and is never awaited.  Everything that touches the DB or runs a
command is async.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
from dataclasses import dataclass, field
from typing import Optional

from .subnet import local_subnet_id

log = logging.getLogger("wbs.relay")

RELAY_VERB = "RELAY"
PROTO_VERSION = 1
MAX_TEXT = 1024                    # chars of one input/output line
MAX_INBOUND_PER_PEER = 8           # concurrent relayed users from one peer
MAX_OUTBOUND_PER_SESSION = 4       # persistent + in-flight one-shots per local session
OPEN_TIMEOUT = 30.0                # seconds for the target to accept an open
ONESHOT_TIMEOUT = 60.0             # seconds a one-shot may stay open

_RID_RE = re.compile(r"^[0-9a-f]{32}$")
_HANDLE_RE = re.compile(r"^[A-Za-z0-9_\-\[\]\\^`|{}]{1,32}$")

# Required / optional payload keys per op (besides "v" and "op").
_SCHEMA: dict[str, tuple[frozenset, frozenset]] = {
    "open":   (frozenset({"rid", "handle"}), frozenset({"text"})),
    "opened": (frozenset({"rid"}), frozenset()),
    "input":  (frozenset({"rid", "text"}), frozenset()),
    "output": (frozenset({"rid", "text"}), frozenset()),
    "close":  (frozenset({"rid"}), frozenset({"reason"})),
}

# Commands never run on a relayed (delegated) session: no nested relays, no
# changes to the relayed identity or its credentials, no console-only ops.
RELAY_BLOCKED_COMMANDS = frozenset({"relay", "handle", "chpass", "passwd", "detach"})

# The flag a local user needs to keep forwarding input (matches the `.relay`
# entry of partyline.COMMAND_MIN_FLAGS).
ORIGIN_RELAY_FLAG = "A"


def new_relay_id() -> str:
    """Unpredictable 128-bit relay session id."""
    return secrets.token_hex(16)


def _clean_text(text: str) -> str:
    """One display line: no CR/LF/NUL, bounded length."""
    text = text.replace("\r", " ").replace("\n", " ").replace("\x00", "")
    return text[:MAX_TEXT]


def parse_relay_payload(raw: str) -> tuple[Optional[dict], Optional[str]]:
    """Strictly validate one RELAY payload. Returns (payload, None) or (None, reason)."""
    try:
        msg = json.loads(raw)
    except (ValueError, TypeError):
        return None, "malformed JSON"
    if not isinstance(msg, dict):
        return None, "payload is not an object"
    if msg.get("v") != PROTO_VERSION or isinstance(msg.get("v"), bool):
        return None, "unsupported relay protocol version"
    op = msg.get("op")
    if not isinstance(op, str) or op not in _SCHEMA:
        return None, f"unknown op {op!r}"
    required, optional = _SCHEMA[op]
    keys = set(msg) - {"v", "op"}
    if not required <= keys:
        return None, f"{op}: missing {sorted(required - keys)}"
    if keys - required - optional:
        return None, f"{op}: unexpected keys {sorted(keys - required - optional)}"
    rid = msg["rid"]
    if not isinstance(rid, str) or not _RID_RE.match(rid):
        return None, f"{op}: invalid rid"
    if "handle" in msg and (not isinstance(msg["handle"], str)
                            or not _HANDLE_RE.match(msg["handle"])):
        return None, f"{op}: invalid handle"
    for key in ("text", "reason"):
        if key in msg:
            if not isinstance(msg[key], str) or len(msg[key]) > MAX_TEXT:
                return None, f"{op}: invalid {key}"
    return msg, None


@dataclass
class OutboundRelay:
    """A local user's relay to a remote bot (origin side)."""
    rid: str
    session_id: int            # local partyline session owning the relay
    handle: str                # local user's handle
    target: str                # remote bot handle
    link: object = field(repr=False)   # BotLink the relay is bound to
    oneshot: bool = False
    state: str = "pending"     # pending -> open -> (removed)


@dataclass
class InboundRelay:
    """A remote user relayed into this bot (target side)."""
    rid: str
    peer: str                  # origin bot (authenticated link handle)
    handle: str                # stored local spelling of the relayed user
    vsid: int                  # virtual partyline session id (type 'relay')
    link: object = field(repr=False)
    oneshot: bool = False


class RelayManager:
    """Owns both sides of the relay protocol for one bot."""

    def __init__(self, core, partyline):
        self.core = core
        self.partyline = partyline
        self.outbound: dict[str, OutboundRelay] = {}           # rid -> relay
        self.persistent: dict[int, str] = {}                   # local session -> rid
        self.inbound: dict[tuple[str, str], InboundRelay] = {}  # (peer, rid) -> relay
        self.by_vsid: dict[int, tuple[str, str]] = {}           # virtual session -> key

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @property
    def botnet(self):
        return getattr(self.core, "botnet", None)

    def _local_subnet(self) -> int:
        return local_subnet_id(getattr(self.core, "config", None))

    def _delegated(self, peer: str, handle: str) -> bool:
        """
        May `peer` vouch for `handle`?  Config botnet.relay_from maps a peer to
        the handles it is trusted to authenticate, e.g.
        {"hub1": ["alice", "bob"], "hub2": ["*"]}; "*" is an explicit wildcard.
        Missing, malformed or list-form config delegates nothing.
        """
        cfg = (getattr(self.core, "config", None) or {}).get("botnet")
        raw = cfg.get("relay_from") if isinstance(cfg, dict) else None
        if not isinstance(raw, dict):
            return False
        allowed = None
        for key, value in raw.items():
            if isinstance(key, str) and key.lower() == peer.lower():
                allowed = value
                break
        if not isinstance(allowed, (list, tuple)):
            return False
        names = {str(h).lower() for h in allowed if isinstance(h, str) and h}
        return "*" in names or handle.lower() in names

    def _peer_link(self, peer: str):
        """The live, authenticated, same-subnet link for `peer`, or None."""
        botnet = self.botnet
        if botnet is None:
            return None
        link = botnet.same_subnet_peer(peer)
        if link is None or not botnet._writer_live(link.writer):
            return None
        return link

    def _bound(self, peer: str, link) -> bool:
        """True if `link` is still the registered live link of `peer`."""
        return link is not None and self._peer_link(peer) is link

    def _send(self, link, payload: dict) -> bool:
        """Synchronously write one RELAY line to `link` (ordered, never awaited)."""
        writer = getattr(link, "writer", None)
        if writer is None:
            return False
        try:
            if writer.is_closing():
                return False
            body = json.dumps({"v": PROTO_VERSION, **payload}, separators=(",", ":"))
            writer.write(f"{RELAY_VERB} {body}\n".encode())
            return True
        except Exception as exc:
            log.warning("Relay send to %s failed: %s", getattr(link, "name", "?"), exc)
            return False

    def _notify(self, session_id: int, text: str) -> None:
        self.partyline.send_to_session(session_id, text)

    def _schedule(self, delay: float, rid: str, state: str) -> None:
        """Expire relay `rid` if it is still in `state` after `delay` seconds."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.call_later(delay, self._expire, rid, state)

    def _expire(self, rid: str, state: str) -> None:
        rel = self.outbound.get(rid)
        if rel is None or (state != "*" and rel.state != state):
            return
        log.info("Relay %s to %s timed out (%s)", rid[:8], rel.target, rel.state)
        self._drop_outbound(rel, notify_peer=True, reason="timeout")
        self._notify(rel.session_id, f"*** Relay to {rel.target} timed out.")

    # ------------------------------------------------------------------
    # origin side (local user -> remote bot)
    # ------------------------------------------------------------------
    def outbound_for(self, session_id: int) -> Optional[OutboundRelay]:
        """The persistent relay of a local session, if any."""
        rid = self.persistent.get(session_id)
        return self.outbound.get(rid) if rid else None

    async def open(self, session_id: int, target: str,
                   command: Optional[str] = None) -> tuple[bool, str]:
        """Open a persistent relay, or a one-shot relay running `command` on `target`."""
        session = self.partyline.sessions.get(session_id)
        if not session:
            return False, "No such session."
        if session.get("type") == "relay":
            return False, "Relays cannot be nested."
        if session.get("type") == "console":
            return False, ("The console has no identity on other bots; "
                           "log in over telnet/DCC as a user to relay.")
        handle = session.get("handle") or ""
        if not _HANDLE_RE.match(handle):
            return False, "Your handle cannot be relayed."
        target = (target or "").strip()
        if not target or not _HANDLE_RE.match(target):
            return False, "Usage: .relay <botnick> [command]"
        if self.botnet is not None and target.lower() == str(self.botnet.my_handle).lower():
            return False, "Cannot relay to myself."
        link = self._peer_link(target)
        if link is None:
            return False, (f"Bot {target} is not linked, or not a same-subnet peer.")
        existing = self.outbound_for(session_id) if command is None else None
        if existing is not None:
            if existing.target.lower() == target.lower():
                return False, f"Already relayed to {existing.target}."
            self._drop_outbound(existing, notify_peer=True, reason="relay switched")
        owned = [r for r in self.outbound.values() if r.session_id == session_id]
        if len(owned) >= MAX_OUTBOUND_PER_SESSION:
            return False, "Too many relays in progress."
        if command is not None:
            command = _clean_text(command).strip()
            if not command:
                return False, "Usage: .relay <botnick> [command]"

        rid = new_relay_id()
        while rid in self.outbound:          # pragma: no cover - 2**-128
            rid = new_relay_id()
        rel = OutboundRelay(rid=rid, session_id=session_id, handle=handle,
                            target=link.name, link=link, oneshot=command is not None)
        payload = {"op": "open", "rid": rid, "handle": handle}
        if command is not None:
            payload["text"] = command
        if not self._send(link, payload):
            return False, f"Failed to open relay to {target}."
        self.outbound[rid] = rel
        if rel.oneshot:
            self._schedule(ONESHOT_TIMEOUT, rid, "*")
            log.info("Relay one-shot %s: %s -> %s", rid[:8], handle, link.name)
            return True, f"-> [{link.name}] {command}"
        self.persistent[session_id] = rid
        self._schedule(OPEN_TIMEOUT, rid, "pending")
        log.info("Relay %s opening: %s (session %s) -> %s", rid[:8], handle, session_id, link.name)
        return True, (f"Relaying to {link.name}... All input will be forwarded. "
                      f"Type '.relay' alone to disconnect.")

    async def send_input(self, session_id: int, text: str) -> bool:
        """Forward one line of a local relayed session to its target."""
        rel = self.outbound_for(session_id)
        if rel is None:
            return False
        session = self.partyline.sessions.get(session_id) or {}
        handle = session.get("handle")
        if not handle or handle != rel.handle:
            # The session's identity changed under the relay: fail closed.
            self._drop_outbound(rel, notify_peer=True, reason="identity changed")
            self._notify(session_id, f"*** Relay to {rel.target} closed (identity changed).")
            return False
        if not await self.core.user.matchattr(handle, ORIGIN_RELAY_FLAG,
                                              subnet_id=self._local_subnet()):
            self._drop_outbound(rel, notify_peer=True, reason="relay permission revoked")
            self._notify(session_id, f"*** Relay to {rel.target} closed "
                                     f"(need +{ORIGIN_RELAY_FLAG}).")
            return False
        if not self._bound(rel.target, rel.link):
            self._drop_outbound(rel, notify_peer=False, reason="link lost")
            self._notify(session_id, f"*** Relay to {rel.target} closed (link lost).")
            return False
        if rel.state != "open":
            self._notify(session_id, f"Relay to {rel.target} is not established yet.")
            return False
        if len(text) > MAX_TEXT:
            self._notify(session_id, f"Line too long for relay (max {MAX_TEXT}).")
            return False
        return self._send(rel.link, {"op": "input", "rid": rel.rid, "text": _clean_text(text)})

    async def close_local(self, session_id: int, reason: str = "closed by user") -> Optional[str]:
        """Close the persistent relay of a local session; returns the target name."""
        rel = self.outbound_for(session_id)
        if rel is None:
            return None
        self._drop_outbound(rel, notify_peer=True, reason=reason)
        return rel.target

    def _drop_outbound(self, rel: OutboundRelay, notify_peer: bool, reason: str) -> None:
        if self.outbound.get(rel.rid) is not rel:
            return
        del self.outbound[rel.rid]
        if self.persistent.get(rel.session_id) == rel.rid:
            del self.persistent[rel.session_id]
        if notify_peer and self._bound(rel.target, rel.link):
            self._send(rel.link, {"op": "close", "rid": rel.rid, "reason": reason[:200]})
        log.info("Relay %s to %s closed: %s", rel.rid[:8], rel.target, reason)

    # ------------------------------------------------------------------
    # target side (remote user -> this bot)
    # ------------------------------------------------------------------
    async def _authorize_open(self, peer: str, handle: str) -> tuple[Optional[str], str]:
        """(stored handle, '') if `peer` may relay `handle` in, else (None, reason)."""
        if self._peer_link(peer) is None:
            return None, "sender is not an authenticated same-subnet peer"
        if handle.lower() == "console":
            return None, "console cannot be relayed"
        stored = await self.core.user.resolve_handle(handle)
        if not stored:
            return None, f"unknown user {handle!r}"
        if not self._delegated(peer, stored):
            return None, (f"{peer} is not delegated to authenticate {stored!r} "
                          f"(botnet.relay_from)")
        if not await self.core.user.is_active(stored):
            return None, f"user {handle!r} is locked or deleted"
        if not await self.core.user.matchattr(stored, "p", subnet_id=self._local_subnet()):
            return None, f"user {handle!r} lacks +p on this bot"
        return stored, ""

    async def _handle_open(self, peer: str, link, msg: dict) -> None:
        rid = msg["rid"]
        key = (peer.lower(), rid)
        if key in self.inbound:
            log.warning("Relay open from %s denied: duplicate rid %s", peer, rid[:8])
            return  # never touch the existing session
        if sum(1 for (p, _) in self.inbound if p == key[0]) >= MAX_INBOUND_PER_PEER:
            self._send(link, {"op": "close", "rid": rid, "reason": "too many relays"})
            log.warning("Relay open from %s denied: too many relays", peer)
            return
        stored, reason = await self._authorize_open(peer, msg["handle"])
        if stored is None:
            log.warning("Relay open from %s for %r denied: %s", peer, msg["handle"], reason)
            self._send(link, {"op": "close", "rid": rid, "reason": "access denied"})
            return
        if not self._bound(peer, link) or key in self.inbound:
            return  # link changed (or raced) while authorizing

        vsid = self.partyline.next_id
        self.partyline.next_id += 1
        oneshot = "text" in msg
        rel = InboundRelay(rid=rid, peer=link.name, handle=stored, vsid=vsid,
                           link=link, oneshot=oneshot)

        def output(text: str, _rel=rel) -> None:
            if self.inbound.get((_rel.peer.lower(), _rel.rid)) is _rel and self._bound(_rel.peer, _rel.link):
                self._send(_rel.link, {"op": "output", "rid": _rel.rid, "text": _clean_text(str(text))})

        self.inbound[key] = rel
        self.by_vsid[vsid] = key
        self.partyline.sessions[vsid] = {
            "type": "relay",
            "handle": stored,
            "queue": None,
            "output": output,
            "origin": link.name,
            "rid": rid,
        }
        self._send(link, {"op": "opened", "rid": rid})
        log.info("Relay %s opened: %s@%s -> %s (virtual session %s)",
                 rid[:8], stored, link.name, getattr(self.core, "botname", "?"), vsid)
        if oneshot:
            await self._run_input(rel, msg["text"])
            self._drop_inbound(rel, notify_peer=True, reason="done")
        else:
            self.partyline.broadcast(f"*** {stored}@{link.name} joined the partyline (relay)",
                                     local_only=True, exclude_session=vsid)

    async def _run_input(self, rel: InboundRelay, text: str) -> None:
        """Run one relayed line through the partyline's authorized dispatcher."""
        stored, reason = await self._authorize_open(rel.peer, rel.handle)
        if stored is None:
            log.warning("Relay %s input denied (%s); closing", rel.rid[:8], reason)
            self._drop_inbound(rel, notify_peer=True, reason="access denied")
            return
        text = _clean_text(text)
        stripped = text.strip()
        if stripped.startswith("."):
            cmd = stripped[1:].split(maxsplit=1)
            if cmd and cmd[0].lower() in RELAY_BLOCKED_COMMANDS:
                self.partyline.send_to_session(rel.vsid, f"Not allowed over a relay: .{cmd[0].lower()}")
                return
        await self.partyline._handle_command(rel.vsid, rel.handle, text)

    async def _handle_input(self, peer: str, link, msg: dict) -> None:
        rel = self.inbound.get((peer.lower(), msg["rid"]))
        if rel is None or rel.link is not link or rel.oneshot:
            log.warning("Relay input from %s denied: no session %s owned by this link",
                        peer, msg["rid"][:8])
            return
        await self._run_input(rel, msg["text"])

    def _drop_inbound(self, rel: InboundRelay, notify_peer: bool, reason: str) -> None:
        key = (rel.peer.lower(), rel.rid)
        if self.inbound.get(key) is not rel:
            return
        del self.inbound[key]
        self.by_vsid.pop(rel.vsid, None)
        session = self.partyline.sessions.pop(rel.vsid, None)
        if notify_peer and self._bound(rel.peer, rel.link):
            self._send(rel.link, {"op": "close", "rid": rel.rid, "reason": reason[:200]})
        if session is not None and not rel.oneshot:
            self.partyline.broadcast(f"*** {rel.handle}@{rel.peer} left the partyline (relay)",
                                     local_only=True)
        log.info("Relay %s from %s closed: %s", rel.rid[:8], rel.peer, reason)

    # ------------------------------------------------------------------
    # replies to our own relays
    # ------------------------------------------------------------------
    def _own_outbound(self, peer: str, link, rid: str) -> Optional[OutboundRelay]:
        rel = self.outbound.get(rid)
        if rel is None or rel.link is not link or rel.target.lower() != peer.lower():
            return None
        return rel

    def _handle_opened(self, peer: str, link, msg: dict) -> None:
        rel = self._own_outbound(peer, link, msg["rid"])
        if rel is None or rel.state != "pending":
            log.warning("Relay opened from %s denied: no pending relay %s to it", peer, msg["rid"][:8])
            return
        rel.state = "open"
        if not rel.oneshot:
            self._notify(rel.session_id, f"*** Relayed to {rel.target}.")

    def _handle_output(self, peer: str, link, msg: dict) -> None:
        rel = self._own_outbound(peer, link, msg["rid"])
        if rel is None or rel.state != "open":
            log.warning("Relay output from %s denied: no open relay %s to it", peer, msg["rid"][:8])
            return
        text = _clean_text(msg["text"])
        self._notify(rel.session_id, f"[{rel.target}] {text}" if rel.oneshot else text)

    def _handle_close(self, peer: str, link, msg: dict) -> None:
        rid = msg["rid"]
        inbound = self.inbound.get((peer.lower(), rid))
        if inbound is not None and inbound.link is link:
            self._drop_inbound(inbound, notify_peer=False, reason="closed by origin")
            return
        rel = self._own_outbound(peer, link, rid)
        if rel is not None:
            self._drop_outbound(rel, notify_peer=False, reason="closed by target")
            reason = _clean_text(msg.get("reason") or "")
            if not rel.oneshot or rel.state == "pending":
                self._notify(rel.session_id, f"*** Relay to {rel.target} closed"
                                             f"{f' ({reason})' if reason else ''}.")
            return
        log.warning("Relay close from %s denied: no relay %s owned by this link", peer, rid[:8])

    # ------------------------------------------------------------------
    # entry points
    # ------------------------------------------------------------------
    async def on_message(self, from_bot: str, link, raw: str) -> None:
        """Handle one RELAY line from `from_bot`, whose `link` owns the connection."""
        if link is None:
            return
        msg, error = parse_relay_payload(raw)
        if msg is None:
            log.warning("Relay message from %s rejected: %s", from_bot, error)
            return
        op = msg["op"]
        if op == "open":
            await self._handle_open(from_bot, link, msg)
        elif op == "input":
            await self._handle_input(from_bot, link, msg)
        elif op == "opened":
            self._handle_opened(from_bot, link, msg)
        elif op == "output":
            self._handle_output(from_bot, link, msg)
        else:
            self._handle_close(from_bot, link, msg)

    def session_ended(self, session_id: int, reason: str = "session closed") -> None:
        """A local partyline session went away: close everything bound to it."""
        for rel in [r for r in self.outbound.values() if r.session_id == session_id]:
            self._drop_outbound(rel, notify_peer=True, reason=reason)
        key = self.by_vsid.get(session_id)
        if key is not None:
            rel = self.inbound.get(key)
            if rel is not None:
                self._drop_inbound(rel, notify_peer=True, reason=reason)

    def peer_down(self, peer: str) -> None:
        """A peer link dropped: discard every relay bound to it (no wire traffic)."""
        name = (peer or "").lower()
        for rel in [r for r in self.outbound.values() if r.target.lower() == name]:
            if self._bound(rel.target, rel.link):
                continue        # a newer live link: not ours to drop
            self._drop_outbound(rel, notify_peer=False, reason="link lost")
            self._notify(rel.session_id, f"*** Relay to {rel.target} closed (link lost).")
        for rel in [r for r in self.inbound.values() if r.peer.lower() == name]:
            if self._bound(rel.peer, rel.link):
                continue
            self._drop_inbound(rel, notify_peer=False, reason="link lost")
