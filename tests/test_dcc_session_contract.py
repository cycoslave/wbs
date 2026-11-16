"""
Offline regression tests for SAST-010: the DCC session contract.

Acceptance under test, for every mode (active listener, passive callback,
reverse dial, IRC fallback):
  * a valid user gets exactly one partyline session, registered once, as
    type 'dcc', under the canonical user.handle (never the IRC nick), and
    closing it cleans up exactly once (one unregister, manager forgets it,
    socket closed once) however many close paths fire;
  * the socket is bound to the account by a password challenge for the
    verified handle: a wrong/empty password, a peer that is not the
    requester (first to reach an active listener), a password of another
    user, or a user without a password get no session;
  * wrong host / wrong token never reach the session layer;
  * nickname != handle (including a nick equal to another user's handle)
    registers the canonical handle of the matched hostmask;
  * locked or no-partyline (+p) users are denied, also when the change
    happens between the offer and the login;
  * the IRC fallback takes its password only from the exact requesting
    nick!user@host, once; the session is bound to that identity (and to the
    services account seen at login) and ends on NICK/QUIT/reset/identity
    change; login lines never reach plugins, games or the command layer;
  * partyline revocation (SAST-004) of a DCC session cleans up once.

open_connection / start_server are mocked: no socket is ever opened.
Throwaway sqlite under pytest's tmp_path; no IRC, no bot process.
"""
import asyncio
import json
import shutil
from types import SimpleNamespace

import bcrypt
import pytest

from src import dcc as dccmod
from src.core import Core
from src.db import get_db
from src.dcc import DCCIRCSession, DCCManager, DCCSession
from src.partyline import Partyline
from src.user import UserManager

from test_pubcom_authz import _fresh_db  # noqa: E402  (offline DB template)
from test_dcc_negotiation import (  # noqa: E402  (shared offline fakes)
    FakeWriter, Net, chat_args, eof_reader, hm, ip_int, offered_token,
)

LOCAL_SUBNET = 1
PW = {"alice": "alice-secret", "carol": "carol-secret", "noparty": "np-secret",
      "locked": "lk-secret"}


def _hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=4)).decode()


# handle -> (hostmasks, access rows [(subnet_id, {cols})], locked, password)
USERS = {
    "alice":   (["*!alice@home.example"], [(None, {"has_partyline"})], 0, PW["alice"]),
    "carol":   (["*!carol@carol.example"], [(1, {"has_partyline"})], 0, PW["carol"]),
    "nopass":  (["*!nopw@nopw.example"], [(None, {"has_partyline"})], 0, None),
    "noparty": (["*!np@np.example"], [(None, {"is_op"})], 0, PW["noparty"]),
    "locked":  (["*!lk@lk.example"], [(None, {"has_partyline"})], 1, PW["locked"]),
}

ALICE = ("Alice", hm("Alice", "alice", "home.example"))
# Nick differs from the handle, and even equals another user's handle.
ALICE_AS_CAROL = ("carol", hm("carol", "alice", "home.example"))
ALICE_AS_WONDER = ("Wonder", hm("Wonder", "alice", "home.example"))
NOPASS = ("NoPw", hm("NoPw", "nopw", "nopw.example"))


async def build_db(tmp_path) -> str:
    db = str(tmp_path / "wbs.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        for handle, (masks, rows, locked, pw) in USERS.items():
            await d.execute(
                "INSERT INTO users(handle, password, hostmasks, is_locked) VALUES (?, ?, ?, ?)",
                (handle, _hash(pw) if pw else None, json.dumps(masks), locked))
            for sid, cols in rows:
                names = ["handle", "subnet_id", *sorted(cols)]
                vals = [handle, sid, *([1] * len(cols))]
                await d.execute(
                    f"INSERT INTO user_access ({', '.join(names)}) "
                    f"VALUES ({', '.join('?' * len(names))})", vals)
        await d.commit()
    return db


class SpyPartyline(Partyline):
    """Real Partyline that records registrations, removals and input."""

    def __init__(self, core):
        super().__init__(core)
        self.registered: list[tuple] = []
        self.removed: list[int] = []
        self.inputs: list[tuple] = []

    def register_remote(self, sessiontype, handle, responsequeue=None):
        sid = super().register_remote(sessiontype, handle, responsequeue)
        self.registered.append((sid, sessiontype, handle))
        return sid

    def unregister_session(self, session_id):
        if session_id in self.sessions:
            self.removed.append(session_id)
        super().unregister_session(session_id)

    async def handle_input(self, session_id, text):
        self.inputs.append((session_id, text))
        await super().handle_input(session_id, text)


class FakeCore:
    def __init__(self, db, dcc_cfg=None):
        self.config = {"bot": {"nick": "wbs"}, "botnet": {"subnet_id": LOCAL_SUBNET},
                       "dcc": dict(dcc_cfg or {}), "settings": {"listen_host": "127.0.0.1"}}
        self.botname = "wbs"
        self.irc_q = None
        self.botnet = SimpleNamespace(peers={})
        self.party_sessions = {}
        self.user = UserManager(db)
        self.sent: list[dict] = []
        self.partyline = SpyPartyline(self)
        self.dcc = DCCManager(self)

    def send_irc(self, payload):
        self.sent.append(payload)

    def notices(self, target=None):
        return [p["text"] for p in self.sent if p.get("cmd") == "notice"
                and (target is None or p.get("target") == target)]


@pytest.fixture(scope="module")
def db_template(tmp_path_factory):
    return asyncio.run(build_db(tmp_path_factory.mktemp("dcc010")))


@pytest.fixture
def db(db_template, tmp_path):
    path = str(tmp_path / "wbs.db")
    shutil.copyfile(db_template, path)
    return path


@pytest.fixture
def net(monkeypatch):
    n = Net()
    monkeypatch.setattr(asyncio, "open_connection", n.open_connection)
    monkeypatch.setattr(asyncio, "start_server", n.start_server)
    return n


def make(db, **cfg):
    cfg.setdefault("auth_timeout", 2)
    core = FakeCore(db, cfg)
    return core, core.dcc


async def until(cond, timeout=3.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not cond():
        if loop.time() > end:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.01)


async def settle(t=0.1):
    await asyncio.sleep(t)


def reader_with(*lines, eof=False) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    for line in lines:
        r.feed_data(line.encode() + b"\r\n")
    if eof:
        r.feed_eof()
    return r


def assert_one_session(core, mgr, handle, writer=None):
    pl = core.partyline
    assert len(pl.registered) == 1, pl.registered
    sid, stype, h = pl.registered[0]
    assert (stype, h) == ("dcc", handle)
    assert list(pl.sessions) == [sid] and pl.sessions[sid]["handle"] == handle
    assert list(mgr._sessions) == [sid]
    assert mgr._pending == {}
    if writer is not None:
        assert not writer.closed
    return sid, mgr._sessions[sid]


def assert_no_session(core, mgr):
    assert core.partyline.registered == []
    assert core.partyline.sessions == {}
    assert mgr._sessions == {}


def assert_cleaned_once(core, mgr, sid):
    assert core.partyline.removed == [sid]
    assert core.partyline.sessions == {} and mgr._sessions == {}


# ---------------------------------------------------------------------------
# Socket modes: drivers
# ---------------------------------------------------------------------------
async def run_active(mgr, requester, reader, writer=None):
    """Request in active mode; `reader` is what connects to the listener."""
    net = _NET
    await mgr.handle_request(*requester, chat_args())
    assert net.servers, "no listener"
    w = writer or FakeWriter()
    net.servers[-1].cb(reader, w)
    return w


async def run_passive(mgr, core, requester, reader):
    net = _NET
    net.next_reader = reader
    await mgr.handle_request(*requester, chat_args())
    tok = offered_token_from(core)
    t = asyncio.ensure_future(
        mgr.on_passive_callback(*requester, tok, ip_int("8.8.8.8"), "5000"))
    await until(lambda: net.writers or t.done())
    return net.writers[-1] if net.writers else None


async def run_reverse(mgr, requester, reader):
    net = _NET
    net.next_reader = reader
    t = asyncio.ensure_future(mgr.handle_request(*requester, chat_args("8.8.8.8", 5000)))
    await until(lambda: net.writers or t.done())
    return net.writers[-1] if net.writers else None


def offered_token_from(core) -> str:
    return offered_token(SimpleNamespace(
        ctcps=lambda: [p["line"] for p in core.sent if p.get("cmd") == "raw"]))


class ReaderNet(Net):
    """Net whose dialled sockets return a test-supplied reader."""

    def __init__(self):
        super().__init__()
        self.next_reader = None

    async def open_connection(self, host, port, *a, **kw):
        _, w = await super().open_connection(host, port, *a, **kw)
        r, self.next_reader = self.next_reader or eof_reader(), None
        return r, w


@pytest.fixture
def rnet(monkeypatch):
    n = ReaderNet()
    monkeypatch.setattr(asyncio, "open_connection", n.open_connection)
    monkeypatch.setattr(asyncio, "start_server", n.start_server)
    return n


_NET = None


def run(net, coro_fn):
    async def main():
        global _NET
        _NET = net
        return await coro_fn()
    return asyncio.run(main())


SOCKET_MODES = {
    "active": dict(mode="active", public_ip="198.51.100.7"),
    "passive": dict(mode="passive"),
    "reverse": dict(mode="passive"),
}


async def open_socket_mode(mode, core, mgr, requester, reader):
    if mode == "active":
        return await run_active(mgr, requester, reader)
    if mode == "passive":
        return await run_passive(mgr, core, requester, reader)
    return await run_reverse(mgr, requester, reader)


# ---------------------------------------------------------------------------
# 1. Valid session per socket mode: one registration, canonical handle,
#    one cleanup
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("requester", [ALICE, ALICE_AS_WONDER, ALICE_AS_CAROL],
                         ids=["nick~handle", "nick!=handle", "nick=other-handle"])
@pytest.mark.parametrize("mode", list(SOCKET_MODES))
def test_socket_mode_valid_login_registers_canonical_handle_once(db, rnet, mode, requester):
    core, mgr = make(db, **SOCKET_MODES[mode])

    async def go():
        reader = reader_with(PW["alice"])
        w = await open_socket_mode(mode, core, mgr, requester, reader)
        await until(lambda: mgr._sessions)
        sid, sess = assert_one_session(core, mgr, "alice", w)
        assert isinstance(sess, DCCSession) and sess.handle == "alice"
        assert sess.nick == requester[0]
        # Partyline input from the socket is attributed to the handle.
        reader.feed_data(b"hello there\r\n")
        await until(lambda: core.partyline.inputs)
        assert core.partyline.inputs == [(sid, "hello there")]
        await until(lambda: b"Welcome to the WBS partyline, alice!" in w.data)
        # Peer leaves: exactly one cleanup, then further closes are no-ops.
        reader.feed_eof()
        await until(lambda: not mgr._sessions)
        await sess.close("again")
        sess.shutdown("and again")
        assert_cleaned_once(core, mgr, sid)
        assert w.closed
        assert all(s.closed for s in rnet.servers)
    run(rnet, go)
    # Never registered under the IRC nick.
    assert all(h == "alice" for _, _, h in core.partyline.registered)


@pytest.mark.parametrize("mode", list(SOCKET_MODES))
def test_socket_mode_endchat_closes_once(db, rnet, mode):
    core, mgr = make(db, **SOCKET_MODES[mode])

    async def go():
        reader = reader_with(PW["alice"])
        w = await open_socket_mode(mode, core, mgr, ALICE, reader)
        await until(lambda: mgr._sessions)
        sid = next(iter(mgr._sessions))
        reader.feed_data(b".endchat\r\n")
        await until(lambda: not mgr._sessions)
        assert_cleaned_once(core, mgr, sid)
        assert w.closed and core.partyline.inputs == []
    run(rnet, go)


# ---------------------------------------------------------------------------
# 2. Socket identity binding: wrong password / wrong socket / other user
# ---------------------------------------------------------------------------
BAD_ANSWERS = {
    "wrong password x3": (["nope", "nope2", "nope3"], True),
    "other user's password": ([PW["carol"]] * 3, True),
    "empty answers": (["", "", ""], True),
    "silent then EOF": ([], True),
    "oversized": (["x" * 5000] * 3, True),
}


@pytest.mark.parametrize("label", list(BAD_ANSWERS))
@pytest.mark.parametrize("mode", list(SOCKET_MODES))
def test_socket_mode_bad_password_gets_no_session(db, rnet, mode, label):
    lines, eof = BAD_ANSWERS[label]
    core, mgr = make(db, **SOCKET_MODES[mode])

    async def go():
        w = await open_socket_mode(mode, core, mgr, ALICE, reader_with(*lines, eof=eof))
        await until(lambda: w.closed and not mgr._pending)
        return w
    w = run(rnet, go)
    assert_no_session(core, mgr)
    assert w.data.count(b"Enter your password.") == max(1, min(3, len(lines)))


def test_correct_password_after_max_attempts_is_ignored(db, rnet):
    core, mgr = make(db, mode="passive", auth_attempts=2)

    async def go():
        w = await open_socket_mode("passive", core, mgr, ALICE,
                                   reader_with("bad1", "bad2", PW["alice"]))
        await until(lambda: w.closed and not mgr._pending)
    run(rnet, go)
    assert_no_session(core, mgr)


def test_auth_attempts_config_is_capped(db):
    core, mgr = make(db, auth_attempts=1000)
    assert mgr.auth_attempts == dccmod.AUTH_ATTEMPTS_MAX


def test_active_listener_first_connector_must_prove_identity(db, rnet):
    """Anyone can reach the active listener: the socket, not the IRC
    request, has to prove the account.  An intruder that wins the race is
    refused, the listener is closed and the real user is not impersonated."""
    core, mgr = make(db, **SOCKET_MODES["active"])

    async def go():
        intruder = await run_active(mgr, ALICE, reader_with("guess", "guess2", "guess3"))
        late = FakeWriter()
        rnet.servers[-1].cb(reader_with(PW["alice"]), late)   # real user, too late
        await until(lambda: intruder.closed and not mgr._pending)
        return intruder, late
    intruder, late = run(rnet, go)
    assert late.closed and rnet.servers[-1].closed
    assert_no_session(core, mgr)


def test_challenge_timeout_closes_socket(db, rnet):
    core, mgr = make(db, mode="passive", auth_timeout=0.1)

    async def go():
        w = await open_socket_mode("passive", core, mgr, ALICE, reader_with())
        await until(lambda: w.closed and not mgr._pending)
        return w
    w = run(rnet, go)
    assert b"Login timeout." in w.data
    assert_no_session(core, mgr)


def test_request_expiry_during_challenge_cleans_up(db, rnet, monkeypatch):
    monkeypatch.setattr(dccmod, "AUTH_GRACE", 0)
    core, mgr = make(db, mode="passive", auth_timeout=5)
    mgr.auth_timeout = 5

    async def go():
        w = await open_socket_mode("passive", core, mgr, ALICE, reader_with())
        await until(lambda: mgr._pending and next(iter(mgr._pending.values())).writer)
        mgr.reset("IRC disconnected")
        await until(lambda: w.closed)
        return w
    run(rnet, go)
    assert_no_session(core, mgr)
    assert mgr._pending == {}


# ---------------------------------------------------------------------------
# 3. Wrong host / wrong token never reach the session layer
# ---------------------------------------------------------------------------
def test_passive_wrong_token_or_host_never_reaches_challenge(db, rnet):
    core, mgr = make(db, mode="passive")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        tok = offered_token_from(core)
        good = (ip_int("8.8.8.8"), "5000")
        await mgr.on_passive_callback(*ALICE, "111111111111", *good)
        await mgr.on_passive_callback("Alice", hm("Alice", "alice", "evil.example"), tok, *good)
        await mgr.on_passive_callback(*ALICE_AS_WONDER, tok, *good)
        await settle()
        assert rnet.dials == [] and len(mgr._pending) == 1
        mgr.reset("teardown")
    run(rnet, go)
    assert_no_session(core, mgr)


@pytest.mark.parametrize("mode", ["active", "passive", "reverse", "irc"])
@pytest.mark.parametrize("who", ["unknown host", "wrong user@host for nick"])
def test_wrong_host_gets_nothing(db, rnet, mode, who):
    cfg = dict(SOCKET_MODES.get(mode, {"mode": "irc"}))
    core, mgr = make(db, **cfg)
    requester = (("Mallory", hm("Mallory", "m", "evil.example")) if who == "unknown host"
                 else ("Alice", hm("Alice", "alice", "evil.example")))
    args = chat_args("8.8.8.8", 5000) if mode == "reverse" else chat_args()

    async def go():
        await mgr.handle_request(*requester, args)
        await mgr.on_privmsg({"nick": requester[0], "host": requester[1],
                              "text": f"chatauth {PW['alice']}"})
        await settle()
    run(rnet, go)
    assert rnet.dials == [] and rnet.servers == [] and core.sent == []
    assert_no_session(core, mgr)
    assert mgr._pending == {}


# ---------------------------------------------------------------------------
# 4. Locked / no-rights / no-password users are denied (all modes)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("mode", ["active", "passive", "reverse", "irc"])
@pytest.mark.parametrize("who,requester,pw", [
    ("locked", ("Lk", hm("Lk", "lk", "lk.example")), PW["locked"]),
    ("no +p", ("Np", hm("Np", "np", "np.example")), PW["noparty"]),
], ids=["locked", "no-partyline"])
def test_locked_or_no_rights_denied_up_front(db, rnet, mode, who, requester, pw):
    cfg = dict(SOCKET_MODES.get(mode, {"mode": "irc"}))
    core, mgr = make(db, **cfg)
    args = chat_args("8.8.8.8", 5000) if mode == "reverse" else chat_args()

    async def go():
        await mgr.handle_request(*requester, args)
        await mgr.on_privmsg({"nick": requester[0], "host": requester[1],
                              "text": f"chatauth {pw}"})
        await settle()
    run(rnet, go)
    assert rnet.dials == [] and rnet.servers == [] and core.sent == []
    assert_no_session(core, mgr)


@pytest.mark.parametrize("change", ["lock", "remove +p"])
@pytest.mark.parametrize("mode", list(SOCKET_MODES))
def test_rights_revoked_before_login_denied_socket(db, rnet, mode, change):
    """Offer accepted, then the user is locked / loses +p before answering."""
    core, mgr = make(db, **SOCKET_MODES[mode])

    async def go():
        reader = reader_with()
        w = await open_socket_mode(mode, core, mgr, ALICE, reader)
        if w is None:                                  # passive: callback re-auth denied
            return None
        await until(lambda: b"Enter your password." in w.data)
        if change == "lock":
            await core.user.set_locked("alice", True)
        else:
            async with get_db(core.user.db_path) as d:
                await d.execute("UPDATE user_access SET has_partyline = 0 WHERE handle='alice'")
                await d.commit()
        reader.feed_data(PW["alice"].encode() + b"\r\n")
        await until(lambda: w.closed and not mgr._pending)
        return w
    run(rnet, go)
    assert_no_session(core, mgr)


@pytest.mark.parametrize("mode", ["active", "passive", "reverse", "irc"])
def test_user_without_password_cannot_open_session(db, rnet, mode):
    cfg = dict(SOCKET_MODES.get(mode, {"mode": "irc"}))
    core, mgr = make(db, **cfg)

    async def go():
        # DCC-7: refused up front, so there is nothing to dial, listen on or
        # prompt; a (hypothetical) chatauth afterwards has no request to answer.
        await mgr.handle_request(*NOPASS, chat_args("8.8.8.8", 5000) if mode == "reverse"
                                 else chat_args())
        if mode == "irc":
            await mgr.on_privmsg({"nick": NOPASS[0], "host": NOPASS[1], "text": "chatauth x"})
        await settle()
    run(rnet, go)
    assert rnet.dials == [] and rnet.servers == [] and rnet.writers == []
    assert core.sent == [] and mgr._pending == {}
    assert_no_session(core, mgr)


# ---------------------------------------------------------------------------
# 5. Established session: revocation (SAST-004) and capacity
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("mode", ["passive", "irc"])
def test_locked_user_session_revoked_and_cleaned_once(db, rnet, mode):
    core, mgr = make(db, mode=mode)

    async def go():
        if mode == "irc":
            await mgr.handle_request(*ALICE, chat_args())
            await mgr.on_privmsg({"nick": ALICE[0], "host": ALICE[1],
                                  "text": f"chatauth {PW['alice']}"})
            sid, sess = assert_one_session(core, mgr, "alice")
            await core.user.set_locked("alice", True)
            assert await mgr.on_privmsg({"nick": ALICE[0], "host": ALICE[1],
                                         "text": "hello"}) is True
        else:
            reader = reader_with(PW["alice"])
            await open_socket_mode(mode, core, mgr, ALICE, reader)
            await until(lambda: mgr._sessions)
            sid, sess = assert_one_session(core, mgr, "alice")
            await core.user.set_locked("alice", True)
            reader.feed_data(b"hello\r\n")
        await until(lambda: not mgr._sessions)
        await settle()
        assert core.partyline.sessions == {} and sess.closed
        # Revocation removed it; the transport close did not unregister again.
        assert core.partyline.removed == []
        await sess.close()
        assert mgr._sessions == {}
    run(rnet, go)


def test_established_sessions_count_toward_max_sessions(db, rnet):
    core, mgr = make(db, mode="passive", max_sessions=1)

    async def go():
        await open_socket_mode("passive", core, mgr, ALICE, reader_with(PW["alice"]))
        await until(lambda: mgr._sessions)
        await mgr.handle_request(*("Carol", hm("Carol", "carol", "carol.example")), chat_args())
        assert any("too many sessions" in n for n in core.notices("Carol"))
        for s in list(mgr._sessions.values()):
            await s.close()
    run(rnet, go)


# ---------------------------------------------------------------------------
# 6. IRC fallback
# ---------------------------------------------------------------------------
def privmsg(requester, text, account=None):
    return {"type": "PRIVMSG", "nick": requester[0], "host": requester[1],
            "text": text, "account": account}


@pytest.mark.parametrize("requester", [ALICE, ALICE_AS_WONDER, ALICE_AS_CAROL],
                         ids=["nick~handle", "nick!=handle", "nick=other-handle"])
def test_irc_fallback_valid_login_one_session_canonical_handle(db, rnet, requester):
    core, mgr = make(db, mode="irc")

    async def go():
        await mgr.handle_request(*requester, chat_args())
        assert len(mgr._pending) == 1
        assert await mgr.on_privmsg(privmsg(requester, f"chatauth {PW['alice']}")) is True
        sid, sess = assert_one_session(core, mgr, "alice")
        assert isinstance(sess, DCCIRCSession)
        # Input is routed to the partyline under the session; output is a NOTICE.
        assert await mgr.on_privmsg(privmsg(requester, "hi all")) is True
        assert core.partyline.inputs == [(sid, "hi all")]
        await until(lambda: any("Welcome to the WBS partyline, alice!" in n
                                for n in core.notices(requester[0])))
        # A second login line (replay) changes nothing.
        assert await mgr.on_privmsg(privmsg(requester, f"chatauth {PW['alice']}")) is True
        assert len(core.partyline.registered) == 1
        assert await mgr.on_privmsg(privmsg(requester, ".endchat")) is True
        assert_cleaned_once(core, mgr, sid)
        mgr.forget_nick(requester[0])
        mgr.reset()
        await sess.close()
        assert_cleaned_once(core, mgr, sid)
    run(rnet, go)
    assert rnet.dials == [] and rnet.servers == []


@pytest.mark.parametrize("bad", ["wrong", "", "carol-secret", "x" * 300])
def test_irc_fallback_wrong_password_single_attempt(db, rnet, bad):
    core, mgr = make(db, mode="irc")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        assert await mgr.on_privmsg(privmsg(ALICE, f"chatauth {bad}")) is True
        assert mgr._pending == {}
        # The right password afterwards does not help: one answer per request.
        assert await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}")) is True
    run(rnet, go)
    assert_no_session(core, mgr)
    assert "DCC: authentication failed." in core.notices("Alice")


@pytest.mark.parametrize("impostor", [
    ("Alice", hm("Alice", "alice", "evil.example")),
    ("Alice", hm("Alice", "other", "home.example")),
    ("Carol", hm("Carol", "carol", "carol.example")),
    ("Mallory", hm("Mallory", "m", "x.example")),
], ids=["same-nick-other-host", "same-nick-other-user", "other-user", "unknown"])
def test_irc_fallback_login_only_from_requesting_hostmask(db, rnet, impostor):
    core, mgr = make(db, mode="irc")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        # Consumed (never reaches the command layer) but changes nothing.
        assert await mgr.on_privmsg(privmsg(impostor, f"chatauth {PW['alice']}")) is True
        assert len(mgr._pending) == 1 and mgr._sessions == {}
        # The real owner can still log in.
        assert await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}")) is True
        assert_one_session(core, mgr, "alice")
        mgr.reset()
    run(rnet, go)


@pytest.mark.parametrize("change", ["lock", "remove +p"])
def test_irc_fallback_rights_revoked_before_login(db, rnet, change):
    core, mgr = make(db, mode="irc")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        if change == "lock":
            await core.user.set_locked("alice", True)
        else:
            async with get_db(core.user.db_path) as d:
                await d.execute("UPDATE user_access SET has_partyline = 0 WHERE handle='alice'")
                await d.commit()
        await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}"))
    run(rnet, go)
    assert_no_session(core, mgr)
    assert mgr._pending == {}


def test_irc_fallback_request_expires(db, rnet):
    core, mgr = make(db, mode="irc", auth_timeout=0.1)
    mgr.auth_timeout = 0.05

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        await asyncio.sleep(0.2)
        assert mgr._pending == {}
        await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}"))
    run(rnet, go)
    assert_no_session(core, mgr)


@pytest.mark.parametrize("event", ["other host", "account change", "account vanished",
                                   "quit", "nick", "reset", "idle"])
def test_irc_fallback_session_bound_to_identity(db, rnet, event, monkeypatch):
    if event == "idle":
        monkeypatch.setattr(dccmod, "SESSION_IDLE_TIMEOUT", 0.1)
    core, mgr = make(db, mode="irc")
    fake = SimpleNamespace(dcc=mgr, botname="wbs", channels={}, connected=True)
    fake._is_me = lambda nick: Core._is_me(fake, nick)   # Core helper since IRC-1

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}", account="AliceAcct"))
        sid, sess = assert_one_session(core, mgr, "alice")
        assert await mgr.on_privmsg(privmsg(ALICE, "ok", account="aliceacct")) is True
        if event == "other host":
            spoof = ("Alice", hm("Alice", "alice", "evil.example"))
            assert await mgr.on_privmsg(privmsg(spoof, ".whoami", account="AliceAcct")) is False
        elif event == "account change":
            assert await mgr.on_privmsg(privmsg(ALICE, ".whoami", account="mallory")) is False
        elif event == "account vanished":
            assert await mgr.on_privmsg(privmsg(ALICE, ".whoami")) is False
        elif event == "quit":
            await Core.on_quit(fake, {"nick": "ALICE"})
        elif event == "nick":
            await Core.on_nick(fake, {"old_nick": "Alice", "new_nick": "Alice_"})
        elif event == "reset":
            await Core.on_disconnect(fake, {})
        else:
            await until(lambda: not mgr._sessions)
        assert_cleaned_once(core, mgr, sid)
        # Only "ok" ever reached the partyline.
        assert core.partyline.inputs == [(sid, "ok")]
    run(rnet, go)


def test_irc_fallback_one_session_per_nick(db, rnet):
    core, mgr = make(db, mode="irc")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}"))
        await mgr.handle_request(*ALICE, chat_args())
        assert mgr._pending == {}
        assert "DCC: you already have an IRC chat session." in core.notices("Alice")
        assert len(core.partyline.registered) == 1
        mgr.reset()
    run(rnet, go)


def test_irc_fallback_lines_never_reach_plugins_or_commands(db, rnet):
    """Core.handle_event: login answers and session input stop at the DCC
    layer (no debug log of the password, no plugin, game or command)."""
    core, mgr = make(db, mode="irc")
    dispatched, handled = [], []

    async def dispatch(etype, event):
        dispatched.append(event.get("text"))

    async def on_privmsg(event):
        handled.append(event.get("text"))
    fake = SimpleNamespace(dcc=mgr, plugin=SimpleNamespace(dispatch=dispatch),
                           handlers={"PRIVMSG": on_privmsg})

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        await Core.handle_event(fake, privmsg(ALICE, f"chatauth {PW['alice']}"))
        await Core.handle_event(fake, privmsg(ALICE, "partyline chat"))
        # Someone else, and a non-session line: normal processing.
        await Core.handle_event(fake, privmsg(("Carol", hm("Carol", "carol", "carol.example")),
                                              "seen bob"))
        # A stray login answer with nothing pending is still swallowed.
        await Core.handle_event(fake, privmsg(("Bob", hm("Bob", "b", "b.example")),
                                              "chatauth hunter2"))
        mgr.reset()
    run(rnet, go)
    assert dispatched == ["seen bob"] and handled == ["seen bob"]
    assert len(core.partyline.registered) == 1


def test_partyline_session_type_enum_not_relaxed():
    from src.partyline import VALID_REMOTE_SESSION_TYPES
    assert "dcc-irc" not in VALID_REMOTE_SESSION_TYPES


# ---------------------------------------------------------------------------
# 8. DCC-8: one session per handle, a new authenticated login replaces the old
# ---------------------------------------------------------------------------
CAROL = ("Carol", hm("Carol", "carol", "carol.example"))
ALICE2 = ("Alice2", hm("Alice2", "alice", "home.example"))


async def open_passive_again(rnet, core, mgr, requester, reader):
    """Like run_passive, but waits for a NEW socket (rnet.writers is shared)."""
    before = len(rnet.writers)
    rnet.next_reader = reader
    await mgr.handle_request(*requester, chat_args())
    tok = offered_token_from(core)
    asyncio.ensure_future(
        mgr.on_passive_callback(*requester, tok, ip_int("8.8.8.8"), "5000"))
    await until(lambda: len(rnet.writers) > before)
    return rnet.writers[-1]


async def whom_lines(core, sid):
    from src.commands import cmd_whom
    out = []

    async def respond(msg):
        out.append(msg)
    await cmd_whom(core, "alice", sid, "", respond)
    return out


def test_same_handle_twice_replaces_old_session(db, rnet):
    core, mgr = make(db, mode="passive")

    async def go():
        r1 = reader_with(PW["alice"])
        w1 = await open_socket_mode("passive", core, mgr, ALICE, r1)
        await until(lambda: mgr._sessions)
        (sid1, s1), = mgr._sessions.items()
        bystander = asyncio.Queue()
        core.partyline.register_remote("dcc", "carol", bystander)
        core.partyline.registered.clear()

        w2 = await open_passive_again(rnet, core, mgr, ALICE2, reader_with(PW["alice"]))
        await until(lambda: any(s.session_id != sid1 for s in mgr._sessions.values()))
        sid2 = next(i for i in mgr._sessions if i != sid1)
        # Old one: told why, closed, unregistered exactly once.
        assert s1.closed and w1.closed
        assert b"*** Replaced by a new session from Alice2!alice@home.example\r\n" in w1.data
        assert core.partyline.removed == [sid1]
        # New one: live and told.
        await until(lambda: b"Replaced your previous session." in w2.data)
        assert not w2.closed and not mgr._sessions[sid2].closed
        # Exactly one alice session, and .whom shows it once.
        assert [h for h in (s["handle"] for s in core.partyline.sessions.values())
                if h == "alice"] == ["alice"]
        assert list(core.partyline.sessions) == [i for i in core.partyline.sessions
                                                 if i != sid1]
        assert sum(1 for l in await whom_lines(core, sid2) if "alice" in l) == 1
        # One "left" line only for the replaced session.
        seen = []
        while not bystander.empty():
            seen.append(bystander.get_nowait()["text"])
        assert seen.count("*** alice left the partyline") == 1, seen
        # Late close paths on the old session do nothing more.
        await s1.close("again")
        assert core.partyline.removed == [sid1]
        for s in list(mgr._sessions.values()):
            await s.close()
    run(rnet, go)


def test_wrong_password_second_attempt_does_not_kick_first(db, rnet):
    core, mgr = make(db, mode="passive")

    async def go():
        w1 = await open_socket_mode("passive", core, mgr, ALICE,
                                    reader_with(PW["alice"]))
        await until(lambda: mgr._sessions)
        (sid1, s1), = mgr._sessions.items()
        w2 = await open_passive_again(rnet, core, mgr, ALICE2,
                                      reader_with("bad", "bad", "bad", eof=True))
        await until(lambda: w2.closed and not mgr._pending)
        assert not s1.closed and not w1.closed
        assert b"Replaced" not in w1.data
        assert core.partyline.removed == []
        assert list(mgr._sessions) == [sid1] and list(core.partyline.sessions) == [sid1]
        await s1.close()
    run(rnet, go)


def test_different_handles_coexist(db, rnet):
    core, mgr = make(db, mode="passive")

    async def go():
        w1 = await open_socket_mode("passive", core, mgr, ALICE, reader_with(PW["alice"]))
        await until(lambda: len(mgr._sessions) == 1)
        w2 = await open_passive_again(rnet, core, mgr, CAROL, reader_with(PW["carol"]))
        await until(lambda: len(mgr._sessions) == 2)
        assert not w1.closed and not w2.closed
        assert sorted(s.handle for s in mgr._sessions.values()) == ["alice", "carol"]
        assert core.partyline.removed == []
        assert b"Replaced" not in w1.data + w2.data
        for s in list(mgr._sessions.values()):
            await s.close()
    run(rnet, go)


def test_irc_fallback_replaced_by_dcc_session(db, rnet):
    core, mgr = make(db, mode="irc")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}"))
        (sid1, s1), = mgr._sessions.items()
        mgr.mode = "passive"
        w2 = await open_passive_again(rnet, core, mgr, ALICE2, reader_with(PW["alice"]))
        await until(lambda: len(mgr._sessions) == 1 and sid1 not in mgr._sessions)
        assert s1.closed and core.partyline.removed == [sid1]
        assert ("*** Replaced by a new session from Alice2!alice@home.example"
                in core.notices("Alice"))
        await until(lambda: b"Replaced your previous session." in w2.data)
        for s in list(mgr._sessions.values()):
            await s.close()
    run(rnet, go)


def test_irc_fallback_login_replaces_dcc_session(db, rnet):
    core, mgr = make(db, mode="passive")

    async def go():
        w1 = await open_socket_mode("passive", core, mgr, ALICE, reader_with(PW["alice"]))
        await until(lambda: mgr._sessions)
        (sid1, s1), = mgr._sessions.items()
        mgr.mode = "irc"
        await mgr.handle_request(*ALICE2, chat_args())
        await mgr.on_privmsg(privmsg(ALICE2, f"chatauth {PW['alice']}"))
        assert s1.closed and w1.closed and core.partyline.removed == [sid1]
        assert b"Replaced by a new session from Alice2!alice@home.example" in w1.data
        assert len(mgr._sessions) == 1
        await until(lambda: "Replaced your previous session." in core.notices("Alice2"))
        mgr.reset()
    run(rnet, go)
