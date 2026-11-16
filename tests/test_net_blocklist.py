"""
Regression tests for USR-12: `.blocklist`, `.denyhost`, `.permithost` work
AND are enforced.

* The three handlers were defined `(core, session_id, args, respond)` but
  dispatched `(core, handle, session_id, arg, respond)` -> TypeError on every
  call; they also read `.handle` off a session dict, passed `created_by=` to
  AccessGuard.block (net_blocklist's column is `added_by`) and used
  `datetime.datetime` on the class.
* Enforcement: a denied host mask / IP is refused at the listener (botlink
  and telnet) before any byte is read, and DCC CHAT from a denied host (IRC
  host or socket peer) is refused before the password prompt.  `.permithost`
  removes a deny or overrides a wider one; AccessGuard's automatic
  auth-failure bans keep working and are never overridden by a permit.

Throwaway sqlite DBs under tmp_path; fake streams only, no sockets.
"""
import asyncio
import time

import pytest

from src.commands import COMMANDS, cmd_blocklist, cmd_denyhost, cmd_permithost
from src.core import Core
from src.db import get_db
from src.net import AccessGuard, normalize_host_mask
from src.partyline import COMMAND_MIN_FLAGS, Partyline
from src.user import UserManager

from test_listener_admission import (  # noqa: E402  (shared offline fakes)
    IP_A, IP_B, build_db, connect, login, make_listener, run,
)

NET_A = "198.51.100.0/24"           # contains IP_A and IP_B


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
async def add_user(db, handle, cols):
    async with get_db(db) as d:
        await d.execute("INSERT INTO users(handle, hostmasks) VALUES (?, '[]')", (handle,))
        names = ["handle", "channel", "subnet_id", *sorted(cols)]
        await d.execute(
            f"INSERT INTO user_access ({', '.join(names)}) "
            f"VALUES ({', '.join('?' * len(names))})", [handle, None, None, *([1] * len(cols))])
        await d.commit()


def make_core(db, guard=None):
    core = object.__new__(Core)
    core.config = {"bot": {"nick": "wbs"}, "botnet": {"subnet_id": 1}, "db": {"path": db}}
    core.db_path = db
    core.botname = "wbs"
    core.irc_q = None
    core.core_q = None
    core.botnet = None
    core.dcc = None
    core.party_sessions = {}
    core.user = UserManager(db)
    core.guard = guard or AccessGuard(db, {"settings": {}})
    core.partyline = Partyline(core)
    return core


class Session:
    """A partyline session whose replies are collected."""

    def __init__(self, core, handle, kind="dcc"):
        self.core = core
        self.out: list[str] = []
        if kind == "console":
            self.sid = core.partyline.register_console(handle, self.out.append)
            self.q = None
        else:
            self.q = asyncio.Queue()
            self.sid = core.partyline.register_remote(kind, handle, self.q)

    async def cmd(self, text) -> list[str]:
        if self.q is not None:
            while not self.q.empty():
                self.q.get_nowait()
        self.out.clear()
        await self.core.partyline.handle_input(self.sid, text)
        if self.q is not None:
            while not self.q.empty():
                item = self.q.get_nowait()
                if item.get("type") == "RESPONSE":
                    self.out.append(item["text"])
        return list(self.out)


async def rows(db):
    async with get_db(db) as d:
        return [dict(r) for r in await d.execute_fetchall(
            "SELECT ip, reason, added_by, expires_at, note FROM net_blocklist ORDER BY ip")]


# ---------------------------------------------------------------------------
# handler signature / registration (the reported TypeError)
# ---------------------------------------------------------------------------
def test_handlers_use_dispatch_signature_and_are_admin_only():
    import inspect
    for name, fn in (("blocklist", cmd_blocklist), ("denyhost", cmd_denyhost),
                     ("permithost", cmd_permithost)):
        assert COMMANDS[name] is fn
        assert list(inspect.signature(fn).parameters) == [
            "core", "handle", "session_id", "arg", "respond"]
        assert COMMAND_MIN_FLAGS[name] == "A"


@pytest.mark.parametrize("raw,expected", [
    ("1.2.3.4", "1.2.3.4"),
    (" 1.2.3.4 ", "1.2.3.4"),
    ("10.0.0.0/8", "10.0.0.0/8"),
    ("10.1.2.3/8", "10.0.0.0/8"),
    ("10.1.2.3/32", "10.1.2.3"),
    ("2001:db8::/32", "2001:db8::/32"),
    ("::ffff:1.2.3.4", "1.2.3.4"),
    ("*.Example.NET", "*.example.net"),
    ("10.0.*", "10.0.*"),
    ("*!*@bad.host", "bad.host"),
    ("*@bad.host", "bad.host"),
])
def test_valid_masks_are_normalised(raw, expected):
    assert normalize_host_mask(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "*", "*.*", "?.?", "0.0.0.0/0", "::/0", "bob!*@bad.host", "*!ident@bad.host",
    "bad host", "a;b", "1.2.3.4/33", "x" * 300, "*!*@", "@", "!",
])
def test_invalid_masks_are_refused(raw):
    assert normalize_host_mask(raw) is None


# ---------------------------------------------------------------------------
# deny / list / permit round-trip through the real partyline dispatcher
# ---------------------------------------------------------------------------
def test_deny_list_permit_round_trip(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        await add_user(db, "boss", {"has_partyline", "is_admin"})
        core = make_core(db)
        s = Session(core, "boss")

        assert await s.cmd(".blocklist") == ["Blocklist is empty."]

        out = await s.cmd(".denyhost 203.0.113.9 60 Spammer here")
        assert out == ["Denied 203.0.113.9 for 1h: Spammer here."]
        out = await s.cmd(".denyhost *!*@*.Bad.Example %1d")
        assert out == ["Denied *.bad.example for 1d."]
        out = await s.cmd(f".denyhost {NET_A}")
        assert out == [f"Denied {NET_A} permanently."]

        stored = await rows(db)
        assert [(r["ip"], r["reason"], r["added_by"], r["note"]) for r in stored] == [
            ("*.bad.example", "manual", "boss", ""),
            ("198.51.100.0/24", "manual", "boss", ""),
            ("203.0.113.9", "manual", "boss", "Spammer here"),
        ]
        exp = {r["ip"]: r["expires_at"] for r in stored}
        assert exp["198.51.100.0/24"] == 0
        assert abs(exp["203.0.113.9"] - (time.time() + 3600)) < 5
        assert abs(exp["*.bad.example"] - (time.time() + 86400)) < 5

        listing = await s.cmd(".blocklist")
        text = "\n".join(listing)
        for mask in ("203.0.113.9", "*.bad.example", NET_A):
            assert mask in text
        assert "Spammer here" in text and "never" in text
        assert listing[-1] == "Total entries: 3"
        assert not any("Error executing" in line for line in listing)

        # exact permit removes the deny (a permit row also stays, because an
        # address may reverse-resolve into the *.bad.example name deny)
        assert await s.cmd(".permithost 203.0.113.9") == [
            "Removed the deny for 203.0.113.9; it is allowed despite wider deny entries."]
        assert {r["ip"]: r["reason"] for r in await rows(db)}["203.0.113.9"] == "permit"
        await s.cmd(".denyhost 203.0.113.9")
        # with no name deny left, an exact permit just removes the row
        await core.guard.unblock("*.bad.example")
        assert await s.cmd(".permithost 203.0.113.9") == ["Removed 203.0.113.9 from the blocklist."]
        assert await s.cmd(".permithost 203.0.113.9") == ["203.0.113.9 was not denied."]
        await s.cmd(".denyhost *.bad.example %1d")
        # a host inside a wider deny gets a permit row that overrides it
        out = await s.cmd(f".permithost {IP_A}")
        assert out == [f"Permitted {IP_A}: it is allowed despite wider deny entries."]
        stored = {r["ip"]: r for r in await rows(db)}
        assert set(stored) == {"*.bad.example", NET_A, IP_A}
        assert stored[IP_A]["reason"] == "permit" and stored[IP_A]["added_by"] == "boss"
        assert "PERMIT" in "\n".join(await s.cmd(".blocklist"))

        # a fresh guard (bot restart) reloads the same state from the DB
        fresh = AccessGuard(db, {"settings": {}})
        assert (await fresh.denied_by(ip=IP_A)) is None
        assert (await fresh.denied_by(ip=IP_B)).ip == NET_A
        assert (await fresh.denied_by(ip="203.0.113.9")) is None
        assert (await fresh.denied_by(host="x.bad.example")).ip == "*.bad.example"

        # .denyhost of the permitted mask itself turns it back into a deny
        await s.cmd(f".denyhost {IP_A}")
        assert (await fresh.denied_by(ip=IP_A)) is None      # other guard: stale cache
        assert (await core.guard.denied_by(ip=IP_A)) is not None
    run(main())


def test_bad_input_and_usage(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        core = make_core(db)
        s = Session(core, "operator", kind="console")      # console = operator
        assert (await s.cmd(".denyhost"))[0].startswith("Usage: .denyhost")
        assert (await s.cmd(".denyhost *"))[0].startswith("Invalid host mask")
        assert (await s.cmd(".denyhost 0.0.0.0/0"))[0].startswith("Invalid host mask")
        assert (await s.cmd(".denyhost nick!*@h.example"))[0].startswith("Invalid host mask")
        assert (await s.cmd(".denyhost 1.2.3.4 %bogus"))[0].startswith("Invalid duration")
        assert (await s.cmd(".permithost"))[0].startswith("Usage: .permithost")
        assert (await s.cmd(".permithost a b"))[0].startswith("Usage: .permithost")
        assert (await s.cmd(".permithost *"))[0].startswith("Invalid host mask")
        assert await rows(db) == []
        # console adds are attributed and work
        assert await s.cmd(".denyhost 1.2.3.4") == ["Denied 1.2.3.4 permanently."]
        assert (await rows(db))[0]["added_by"] == "operator"
    run(main())


def test_non_admin_is_refused(tmp_path):
    async def main():
        db = await build_db(tmp_path)          # alice: +p only
        core = make_core(db)
        s = Session(core, "alice")
        for text in (".blocklist", ".denyhost 1.2.3.4", ".permithost 1.2.3.4"):
            out = await s.cmd(text)
            assert len(out) == 1 and out[0].startswith("Access denied"), (text, out)
        assert await rows(db) == []
        # handler-level check too (callers that skip the partyline gate)
        said = []

        async def respond(m):
            said.append(m)
        await cmd_denyhost(core, "alice", s.sid, "1.2.3.4", respond)
        assert said == ["Access denied (need +A)."] and await rows(db) == []
    run(main())


def test_expired_entries_drop_out(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        core = make_core(db)
        s = Session(core, "operator", kind="console")
        await s.cmd(".denyhost 1.2.3.4 1")
        core.guard._blocklist["1.2.3.4"].expires_at = int(time.time()) - 1
        assert await s.cmd(".blocklist") == ["Blocklist is empty."]
        assert await rows(db) == []
        assert (await core.guard.denied_by(ip="1.2.3.4")) is None
    run(main())


# ---------------------------------------------------------------------------
# enforcement at the listener: botlink and telnet, before authentication
# ---------------------------------------------------------------------------
BOTLINK = b"BOTLINK hub 1.0 1\n"


@pytest.mark.parametrize("deny", [IP_A, NET_A, "198.51.100.*"])
def test_denied_ip_refused_at_botlink_and_telnet_accept(tmp_path, deny):
    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db)
        assert await guard.block(deny, reason="manual", added_by="boss") is not None

        for data in (BOTLINK, login()):
            reader, w = await connect(listener, data, ip=IP_A)
            assert w.text == "ERROR :Connection refused\r\n"    # no "Password:" prompt
            assert w.closed == 1
            assert reader.at_eof() is False and len(reader._buffer) == len(data)  # nothing read
        assert listener.core_q.events == []
        assert guard._active == {} and guard._failures == {}       # no failure counted

        # an address outside the mask is unaffected
        _, w = await connect(listener, login(), ip="203.0.113.50")
        assert listener.core_q.of("PARTYLINE_CONNECT")
    run(main())


def test_permitted_ip_gets_through_again(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db)
        await guard.block(NET_A, reason="manual")
        await guard.block(IP_B, reason="manual")

        # exact deny removed
        mask, removed, stored = await guard.permit(IP_B)
        assert (mask, removed, stored) == (IP_B, True, True)   # NET_A still covers it
        # override of the wider deny for IP_A
        assert await guard.permit(IP_A) == (IP_A, False, True)

        _, w = await connect(listener, BOTLINK, ip=IP_A)
        assert "Connection refused" not in w.text
        assert listener.core_q.of("BOT_CONNECT")
        _, w = await connect(listener, login(), ip=IP_B)
        assert "Password: " in w.text and listener.core_q.of("PARTYLINE_CONNECT")
        # the rest of the network stays denied
        _, w = await connect(listener, login(), ip="198.51.100.99")
        assert w.text == "ERROR :Connection refused\r\n"
    run(main())


def test_denied_and_permitted_logged(tmp_path, caplog):
    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db)
        await guard.block(IP_A, reason="manual", note="spam")
        with caplog.at_level("WARNING", logger="wbs.net"):
            await connect(listener, BOTLINK, ip=IP_A)
        assert any("DENY" in r.getMessage() and IP_A in r.getMessage()
                   and "spam" in r.getMessage() for r in caplog.records)
    run(main())


def test_name_glob_matches_reverse_dns_but_permit_needs_the_address(tmp_path, monkeypatch):
    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db)

        async def ptr(ip, timeout=3.0):
            return "dial-7.bad.example" if ip == IP_A else None
        monkeypatch.setattr(guard, "_reverse_name", ptr)
        await guard.block("*.bad.example", reason="manual")
        _, w = await connect(listener, BOTLINK, ip=IP_A)
        assert w.text == "ERROR :Connection refused\r\n"
        # a PTR-name permit is not trusted at the listener ...
        await guard.permit("dial-7.bad.example")
        _, w = await connect(listener, BOTLINK, ip=IP_A)
        assert w.text == "ERROR :Connection refused\r\n"
        # ... an address permit is
        await guard.permit(IP_A)
        _, w = await connect(listener, BOTLINK, ip=IP_A)
        assert "Connection refused" not in w.text
    run(main())


# ---------------------------------------------------------------------------
# AccessGuard failure bans keep working and are not bypassed by a permit
# ---------------------------------------------------------------------------
def test_failure_ban_still_applies_with_a_permit(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db, max_failures=2)
        await guard.block(NET_A, reason="manual")
        await guard.permit(IP_A)                        # permit row for IP_A

        for _ in range(2):
            _, w = await connect(listener, login("wrong"), ip=IP_A)
            assert "Password: " in w.text               # admitted, then failed auth
        # auto-banned despite the permit (the permit row is kept)
        entries = {e.ip: e.reason for e in guard.list_blocked()}
        assert entries[IP_A] == "permit"
        assert "auth_failure" in entries.values()
        _, w = await connect(listener, login(), ip=IP_A)
        assert w.text == "ERROR :Connection refused\r\n"
        # an operator permit lifts the failure ban
        mask, removed, stored = await guard.permit(IP_A)
        assert removed and stored
        _, w = await connect(listener, login(), ip=IP_A)
        assert listener.core_q.of("PARTYLINE_CONNECT")
    run(main())


def test_failure_ban_without_manual_entries_unchanged(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        listener, guard = make_listener(db, max_failures=2)
        for _ in range(2):
            await connect(listener, login("wrong"), ip=IP_A)
        assert [e.reason for e in guard.list_blocked()] == ["auth_failure"]
        _, w = await connect(listener, login(), ip=IP_A)
        assert w.text == "ERROR :Connection refused\r\n"
        # wider permit of a network does not lift the auto-ban of an address in it
        await guard.block(NET_A, reason="manual")
        await guard.permit("198.51.100.0/25")
        assert (await guard.denied_by(ip=IP_A)).reason == "auth_failure"
    run(main())


# ---------------------------------------------------------------------------
# DCC CHAT: denied IRC host or socket peer is refused before the password
# ---------------------------------------------------------------------------
def _dcc_fixture(tmp_path):
    from test_dcc_session_contract import FakeCore, build_db as dcc_db
    return FakeCore, dcc_db


def test_dcc_request_from_denied_host_is_refused(tmp_path):
    FakeCore, dcc_db = _dcc_fixture(tmp_path)

    async def main():
        db = await dcc_db(tmp_path)
        core = FakeCore(db, {"mode": "passive"})
        core.guard = AccessGuard(db, {"settings": {}})
        mgr = core.dcc
        who = ("Alice", "Alice!alice@home.example")
        assert (await mgr._authorize_why(*who))[0] == "alice"

        await core.guard.block("*.example", reason="manual")
        handle, why = await mgr._authorize_why(*who)
        assert handle is None and "denied by *.example" in why
        await mgr.handle_request(*who, ["DCC", "CHAT"])
        assert mgr._pending == {} and core.sent == []          # silently ignored

        # IRC host permit overrides the wider deny
        await core.guard.permit("home.example")
        assert (await mgr._authorize_why(*who))[0] == "alice"
    asyncio.run(main())


def test_dcc_socket_from_denied_peer_is_refused_before_password(tmp_path):
    FakeCore, dcc_db = _dcc_fixture(tmp_path)
    from test_dcc_negotiation import FakeWriter

    async def main():
        db = await dcc_db(tmp_path)
        core = FakeCore(db, {"mode": "passive"})
        core.guard = AccessGuard(db, {"settings": {}})
        mgr = core.dcc
        await core.guard.block("203.0.113.0/24", reason="manual")

        req = mgr._new_request("alice", "Alice", "Alice!alice@home.example", "active")
        reader = asyncio.StreamReader()
        reader.feed_data(b"alice-secret\r\n")
        w = FakeWriter(peer=("203.0.113.5", 5000))
        assert await mgr._open_session(req, reader, w) is False
        assert b"password" not in w.data.lower()
        assert core.partyline.sessions == {}
        mgr._release(req, "test")

        # same flow from an allowed address logs in
        req = mgr._new_request("alice", "Alice", "Alice!alice@home.example", "active")
        reader = asyncio.StreamReader()
        reader.feed_data(b"alice-secret\r\n")
        w = FakeWriter(peer=("8.8.8.8", 5000))
        assert await mgr._open_session(req, reader, w) is True
        assert [s["handle"] for s in core.partyline.sessions.values()] == ["alice"]
        for s in list(mgr._sessions.values()):
            s.shutdown("test")
        await asyncio.sleep(0)
    asyncio.run(main())
