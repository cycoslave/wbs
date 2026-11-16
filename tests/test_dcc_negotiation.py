"""
Offline regression tests for SAST-009: DCC negotiation must authorize the
requester and validate peer endpoints before any network access, and keep
pending negotiations bounded and cleaned up.

Acceptance under test:
  * unauthorized requesters (unknown host, no +p, locked, +p only on another
    subnet, hostmask not belonging to the nick) never cause a dial, a
    listener, a CTCP offer or a notice;
  * forbidden destinations (loopback, private, link-local/metadata, CGNAT,
    multicast, broadcast, 0.0.0.0, low/out-of-range ports, malformed) never
    dial, on both the reverse-request and the passive-callback path;
  * passive callbacks need the single-use token *and* the exact requesting
    nick!user@host, and are re-authorized at callback time;
  * pending floods stay bounded (max_pending, max_sessions incl. pending,
    one per handle) and per-source / global rate limits bound DB work;
  * every outcome (refused endpoint, connect error/timeout, expiry,
    NICK/QUIT, IRC disconnect, session refused or crashing) closes the
    listener/socket and frees the slot;
  * the session layer is on by default since SAST-010 (its contract is
    covered by test_dcc_session_contract.py); the kill switch
    sessions_available=False still refuses every authorized request.

open_connection / start_server are mocked: no socket is ever opened.
Throwaway sqlite under pytest's tmp_path; no IRC, no bot process.
"""
import asyncio
import ipaddress
import json
import shutil
import socket
import struct
from types import SimpleNamespace

import pytest

from src import dcc as dccmod
from src.core import Core
from src.db import get_db
from src.dcc import DCCManager, parse_chat_args
from src.user import UserManager

# Shared offline DB template helper from the SAST-006 suite (no tests imported).
from test_pubcom_authz import _fresh_db  # noqa: E402

LOCAL_SUBNET = 1

# handle -> (hostmasks, access rows [(subnet_id, {cols})], locked)
USERS = {
    "alice":   (["*!alice@home.example"], [(None, {"has_partyline"})], 0),
    "carol":   (["*!carol@carol.example"], [(1, {"has_partyline"})], 0),
    "noparty": (["*!np@np.example"], [(None, {"is_op", "is_admin"})], 0),
    "locked":  (["*!lk@lk.example"], [(None, {"has_partyline"})], 1),
    "foreign": (["*!fr@fr.example"], [(2, {"has_partyline"})], 0),
    "nopass":  (["*!nopass@nopass.example"], [(None, {"has_partyline"})], 0),
}
# Every user has a password (an opaque hash, never verified here) except these:
# DCC-7 refuses password-less accounts before any dial-out/listener/prompt.
NO_PASSWORD = {"nopass"}
FAKE_HASH = "$2b$04$" + "x" * 53
# Many authorized users on distinct hosts, for flood tests.
for _i in range(30):
    USERS[f"u{_i}"] = ([f"*!u{_i}@h{_i}.example"], [(None, {"has_partyline"})], 0)


def hm(nick, user, host):
    return f"{nick}!{user}@{host}"


ALICE = ("Alice", hm("Alice", "alice", "home.example"))
NOPASS = ("Nopass", hm("Nopass", "nopass", "nopass.example"))
CAROL = ("Carol", hm("Carol", "carol", "carol.example"))


def ip_int(ip: str) -> str:
    return str(struct.unpack("!I", socket.inet_aton(ip))[0])


def chat_args(ip=None, port=None, token=None):
    args = ["DCC", "CHAT", "chat"]
    if ip is not None:
        args += [ip_int(ip) if "." in str(ip) else str(ip), str(port)]
    if token is not None:
        args.append(str(token))
    return args


async def build_db(tmp_path) -> str:
    db = str(tmp_path / "wbs.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        for handle, (masks, rows, locked) in USERS.items():
            await d.execute(
                "INSERT INTO users(handle, password, hostmasks, is_locked) VALUES (?, ?, ?, ?)",
                (handle, "" if handle in NO_PASSWORD else FAKE_HASH,
                 json.dumps(masks), locked))
            for sid, cols in rows:
                names = ["handle", "subnet_id", *sorted(cols)]
                vals = [handle, sid, *([1] * len(cols))]
                await d.execute(
                    f"INSERT INTO user_access ({', '.join(names)}) "
                    f"VALUES ({', '.join('?' * len(names))})", vals)
        await d.commit()
    return db


class FakeCore:
    def __init__(self, db, dcc_cfg=None):
        self.config = {"bot": {"nick": "wbs"}, "botnet": {"subnet_id": LOCAL_SUBNET},
                       "dcc": dict(dcc_cfg or {}), "settings": {"listen_host": "127.0.0.1"}}
        self.botname = "wbs"
        self.user = UserManager(db)
        self.sent: list[dict] = []

    def send_irc(self, payload):
        self.sent.append(payload)

    def ctcps(self):
        return [p["line"] for p in self.sent if p.get("cmd") == "raw"]

    def notices(self):
        return [p["text"] for p in self.sent if p.get("cmd") == "notice"]


class FakeWriter:
    def __init__(self, peer=("8.8.8.8", 5000)):
        self.closed = False
        self.data = b""
        self.peer = peer

    def write(self, b):
        self.data += b

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def is_closing(self):
        return self.closed

    def get_extra_info(self, key, default=None):
        return self.peer if key == "peername" else default


class FakeServer:
    def __init__(self, cb, host, port):
        self.cb, self.host, self.port = cb, host, port
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def eof_reader() -> asyncio.StreamReader:
    """A peer that connects and leaves without answering the challenge."""
    r = asyncio.StreamReader()
    r.feed_eof()
    return r


class Net:
    """Records every network attempt; never touches a real socket."""

    def __init__(self, mode="ok"):
        self.dials: list[tuple] = []
        self.writers: list[FakeWriter] = []
        self.servers: list[FakeServer] = []
        self.mode = mode
        self.hang = asyncio.Event() if mode == "hang" else None

    async def open_connection(self, host, port, *a, **kw):
        self.dials.append((host, port))
        if self.mode == "refuse":
            raise ConnectionRefusedError(111, "refused")
        if self.mode == "hang":
            await asyncio.Event().wait()
        w = FakeWriter((host, port))
        self.writers.append(w)
        return eof_reader(), w

    async def start_server(self, cb, host=None, port=None, *a, **kw):
        s = FakeServer(cb, host, port)
        self.servers.append(s)
        return s


@pytest.fixture(scope="module")
def db_template(tmp_path_factory):
    return asyncio.run(build_db(tmp_path_factory.mktemp("dccdb")))


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


def make(db, enabled_sessions=True, **cfg):
    core = FakeCore(db, cfg)
    mgr = DCCManager(core)
    # On by default since SAST-010; a few tests switch it off on this instance.
    mgr.sessions_available = enabled_sessions
    return core, mgr


async def settle(n=5):
    for _ in range(n):
        await asyncio.sleep(0)


def offered_token(core) -> str:
    line = core.ctcps()[-1]
    return line.split()[-1].strip("\x01")


async def shutdown(mgr):
    mgr.reset("test teardown")
    await settle()


# ---------------------------------------------------------------------------
# 1. Unauthorized requesters never reach the network
# ---------------------------------------------------------------------------
UNAUTHORIZED = [
    ("unknown", "Mallory", hm("Mallory", "m", "evil.example")),
    ("no +p", "Np", hm("Np", "np", "np.example")),
    ("locked", "Lk", hm("Lk", "lk", "lk.example")),
    ("+p on other subnet", "Fr", hm("Fr", "fr", "fr.example")),
    ("hostmask of another nick", "Mallory", hm("Alice", "alice", "home.example")),
    ("no user@host", "Alice", "Alice"),
    ("empty", "", ""),
]


@pytest.mark.parametrize("label,nick,host", UNAUTHORIZED, ids=[u[0] for u in UNAUTHORIZED])
@pytest.mark.parametrize("args", [chat_args("127.0.0.1", 9), chat_args("8.8.8.8", 5000),
                                  chat_args(), ["DCC", "CHAT"]],
                         ids=["reverse-loopback", "reverse-public", "plain", "bare"])
@pytest.mark.parametrize("mode", ["auto", "active", "passive", "irc"])
def test_unauthorized_requester_never_dials_or_offers(db, net, label, nick, host, args, mode):
    core, mgr = make(db, mode=mode, public_ip="198.51.100.7")

    async def go():
        await mgr.handle_request(nick, host, args)
        await settle()
    asyncio.run(go())
    assert net.dials == [] and net.servers == []
    assert core.sent == []                 # no CTCP offer, no notice (no reflection)
    assert mgr._pending == {}


def test_audit_repro_unknown_user_127_0_0_1_port_9(db, net):
    """The auditor's repro, with the session layer forced on."""
    core, mgr = make(db)
    asyncio.run(mgr.handle_request("Mallory", hm("Mallory", "x", "evil.example"),
                                   ["DCC", "CHAT", "chat", "2130706433", "9"]))
    assert net.dials == []


def test_authorization_error_fails_closed(db, net):
    core, mgr = make(db)

    async def boom(*a, **kw):
        raise RuntimeError("db down")
    core.user.match_user = boom
    asyncio.run(mgr.handle_request(*ALICE, chat_args("8.8.8.8", 5000)))
    assert net.dials == [] and core.sent == [] and mgr._pending == {}


# ---------------------------------------------------------------------------
# 2. Session layer kill switch (SAST-010 coordination)
# ---------------------------------------------------------------------------
def test_session_layer_kill_switch(db, net):
    assert DCCManager.sessions_available is True        # SAST-010 repaired
    core, mgr = make(db, enabled_sessions=False, mode="auto", public_ip="198.51.100.7")

    async def go():
        for args in (chat_args("8.8.8.8", 5000), chat_args(), ["DCC", "CHAT"]):
            await mgr.handle_request(*ALICE, args)
        await settle()
    asyncio.run(go())
    assert net.dials == [] and net.servers == []
    assert core.ctcps() == []
    assert mgr._pending == {}
    assert all("unavailable" in n for n in core.notices())


def test_session_layer_refuses_peer_without_password(db, net):
    """A dialled peer that never answers the challenge is closed, no session."""
    core, mgr = make(db)

    async def go():
        await mgr.handle_request(*ALICE, chat_args("8.8.8.8", 5000))
        await settle()
    asyncio.run(go())
    assert net.dials == [("8.8.8.8", 5000)]
    assert net.writers[0].closed
    assert b"Enter your password." in net.writers[0].data
    assert mgr._pending == {} and mgr._sessions == {}

    # IRC fallback: only a login prompt; nothing is registered without it.
    core2, mgr2 = make(db, mode="irc")

    async def go2():
        await mgr2.handle_request(*ALICE, chat_args())
        assert len(mgr2._pending) == 1 and mgr2._sessions == {}
        await shutdown(mgr2)
    asyncio.run(go2())
    assert any("chatauth" in n for n in core2.notices())
    assert mgr2._pending == {} and mgr2._sessions == {}


@pytest.mark.parametrize("mode,args", [
    ("auto", chat_args("8.8.8.8", 5000)),       # reverse request: would dial out
    ("auto", chat_args()),                       # would open a listener / offer
    ("active", chat_args()),
    ("passive", chat_args()),
    ("irc", chat_args()),                        # would send the chatauth prompt
], ids=["reverse", "auto-offer", "active", "passive", "irc"])
def test_user_without_password_refused_before_any_io(db, net, caplog, mode, args):
    """DCC-7: no dial, listener, CTCP offer, notice, prompt or pending slot."""
    core, mgr = make(db, mode=mode, public_ip="198.51.100.7")

    async def go():
        await mgr.handle_request(*NOPASS, args)
        await settle()
    with caplog.at_level("WARNING", logger="wbs.dcc"):
        asyncio.run(go())
    assert net.dials == [] and net.servers == [] and net.writers == []
    assert core.sent == []
    assert mgr._pending == {} and mgr._sessions == {}
    assert "user nopass has no password" in caplog.text


def test_user_without_password_refused_on_client_passive_request(db, net):
    core, mgr = make(db, public_ip="198.51.100.7")
    asyncio.run(mgr.on_passive_callback(*NOPASS, CLIENT_TOKEN, ip_int("1.1.1.1"), "0"))
    assert net.servers == [] and net.dials == [] and core.sent == [] and mgr._pending == {}


def test_user_with_password_is_still_authorized(db):
    core, mgr = make(db)
    assert asyncio.run(mgr._authorize(*ALICE)) == "alice"
    assert asyncio.run(mgr._authorize_why(*NOPASS)) == (None, "user nopass has no password")


# ---------------------------------------------------------------------------
# 3. Endpoint policy on the reverse-request path
# ---------------------------------------------------------------------------
FORBIDDEN = [
    ("127.0.0.1", 9), ("127.0.0.1", 5000), ("10.0.0.1", 5000), ("172.16.5.5", 5000),
    ("192.168.1.10", 5000), ("169.254.169.254", 8080), ("100.64.0.1", 5000),
    ("224.0.0.1", 5000), ("255.255.255.255", 5000), ("240.0.0.1", 5000),
    ("192.0.2.1", 5000), ("198.18.0.1", 5000),
    ("8.8.8.8", 22), ("8.8.8.8", 0), ("8.8.8.8", 70000), ("8.8.8.8", -1),
]


@pytest.mark.parametrize("ip,port", FORBIDDEN, ids=[f"{i}:{p}" for i, p in FORBIDDEN])
def test_reverse_request_forbidden_destination_never_dials(db, net, ip, port):
    core, mgr = make(db)
    asyncio.run(mgr.handle_request(*ALICE, chat_args(ip, port)))
    assert net.dials == []
    assert mgr._pending == {}
    assert core.notices() == ["DCC: that address/port is not allowed."]


@pytest.mark.parametrize("raw", [["DCC", "CHAT", "chat", "abc", "5000"],
                                 ["DCC", "CHAT", "chat", "4294967296", "5000"],
                                 ["DCC", "CHAT", "chat", "134744072", "x"],
                                 ["DCC", "CHAT", "chat", "-1", "5000"],
                                 ["DCC", "CHAT", "chat", "134744072"]])
def test_reverse_request_malformed_endpoint_never_dials(db, net, raw):
    core, mgr = make(db)
    asyncio.run(mgr.handle_request(*ALICE, raw))
    assert net.dials == [] and mgr._pending == {}


def test_reverse_request_public_endpoint_dials_once_and_cleans_up(db, net):
    core, mgr = make(db)
    asyncio.run(mgr.handle_request(*ALICE, chat_args("8.8.8.8", 5000)))
    assert net.dials == [("8.8.8.8", 5000)]
    assert all(w.closed for w in net.writers)
    assert mgr._pending == {}


def test_allow_networks_and_peer_ports_are_explicit_opt_ins(db, net):
    core, mgr = make(db, allow_networks=["10.0.0.0/8", "not-a-cidr"],
                     peer_port_min=6000, peer_port_max=6010)

    async def go():
        await mgr.handle_request(*ALICE, chat_args("10.1.2.3", 6005))   # allowed
        await mgr.handle_request(*CAROL, chat_args("10.1.2.3", 5000))   # port outside
        await mgr.handle_request(*CAROL, chat_args("192.168.0.1", 6005))  # not listed
    asyncio.run(go())
    assert net.dials == [("10.1.2.3", 6005)]


def test_endpoint_policy_unit():
    mgr = DCCManager(SimpleNamespace(config={}))
    for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
        assert mgr.endpoint_denial(ip_int(ip), 5000)[2] is None
    for net_ in ("127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"):
        first = ipaddress.ip_network(net_)[1]
        assert mgr.endpoint_denial(int(first), 5000)[2] is not None


# ---------------------------------------------------------------------------
# 4. Passive callback path
# ---------------------------------------------------------------------------
def test_passive_offer_then_valid_callback_dials_validated_endpoint(db, net):
    core, mgr = make(db, mode="passive")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        assert len(mgr._pending) == 1 and net.dials == []
        tok = offered_token(core)
        assert tok.isdigit() and int(tok) < 2**31
        await mgr.on_passive_callback(*ALICE, tok, ip_int("8.8.4.4"), "5001")
        await settle()
    asyncio.run(go())
    assert net.dials == [("8.8.4.4", 5001)]
    assert all(w.closed for w in net.writers)
    assert mgr._pending == {}


@pytest.mark.parametrize("ip,port", FORBIDDEN[:12] + [("8.8.8.8", 80)],
                         ids=[f"{i}:{p}" for i, p in FORBIDDEN[:12]] + ["8.8.8.8:80"])
def test_passive_callback_forbidden_destination_never_dials(db, net, ip, port):
    core, mgr = make(db, mode="passive")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        tok = offered_token(core)
        await mgr.on_passive_callback(*ALICE, tok, ip_int(ip), str(port))
        # Token is single use: a retry with a good endpoint is refused too.
        await mgr.on_passive_callback(*ALICE, tok, ip_int("8.8.8.8"), "5000")
        await settle()
    asyncio.run(go())
    assert net.dials == []
    assert mgr._pending == {}


def test_passive_callback_wrong_token_or_wrong_identity_never_dials(db, net):
    core, mgr = make(db, mode="passive")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        tok = offered_token(core)
        good = (ip_int("8.8.8.8"), "5000")
        await mgr.on_passive_callback(*ALICE, "000000000000", *good)          # wrong token
        await mgr.on_passive_callback(*ALICE, "", *good)                      # no token
        await mgr.on_passive_callback("Alice", hm("Alice", "alice", "evil.example"), tok, *good)
        await mgr.on_passive_callback("Alice", hm("Alice", "other", "home.example"), tok, *good)
        await mgr.on_passive_callback(*CAROL, tok, *good)                     # other user
        await mgr.on_passive_callback("Mallory", hm("Mallory", "m", "x.example"), tok, *good)
        await settle()
        assert net.dials == []
        # The real owner's offer survived the impostors.
        assert len(mgr._pending) == 1
        await mgr.on_passive_callback("ALICE", hm("ALICE", "alice", "HOME.example"), tok, *good)
        await settle()
    asyncio.run(go())
    assert net.dials == [("8.8.8.8", 5000)]
    assert mgr._pending == {}


def test_passive_token_is_31_bit_and_unique_per_offer():
    toks = {dccmod._random_token() for _ in range(2000)}
    assert all(t.isdigit() and len(t) <= 9 and int(t) < 2**31 for t in toks)
    assert len(toks) > 1990


def test_passive_callback_accepts_32bit_truncated_echo_once(db, net):
    """A token and token+2**32 name the same offer; whichever comes first wins."""
    for variant in (0, 2**32, 3 * 2**32):
        net.dials.clear()
        core, mgr = make(db, mode="passive")

        async def go(core=core, mgr=mgr, variant=variant):
            await mgr.handle_request(*ALICE, chat_args())
            tok = offered_token(core)
            echoed = str(int(tok) + variant)
            await mgr.on_passive_callback(*ALICE, echoed, ip_int("8.8.8.8"), "5000")
            await settle()
            # single use: neither form can be replayed
            await mgr.on_passive_callback(*ALICE, tok, ip_int("8.8.4.4"), "5001")
            await mgr.on_passive_callback(*ALICE, str(int(tok) + 2**32),
                                          ip_int("8.8.4.4"), "5001")
            await settle()
        asyncio.run(go())
        assert net.dials == [("8.8.8.8", 5000)]
        assert mgr._pending == {}


def test_passive_callback_truncated_echo_still_bound_to_owner(db, net):
    core, mgr = make(db, mode="passive")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        tok = str(int(offered_token(core)) + 2**32)
        good = (ip_int("8.8.8.8"), "5000")
        await mgr.on_passive_callback("Alice", hm("Alice", "alice", "evil.example"), tok, *good)
        await mgr.on_passive_callback(*CAROL, tok, *good)
        await mgr.on_passive_callback(*ALICE, "12abc", *good)       # malformed
        await settle()
        assert net.dials == []
        assert len(mgr._pending) == 1                               # owner's offer intact
    asyncio.run(go())


def test_passive_callback_reauthorizes_requester(db, net):
    core, mgr = make(db, mode="passive")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        tok = offered_token(core)
        await core.user.set_locked("alice", True)
        await mgr.on_passive_callback(*ALICE, tok, ip_int("8.8.8.8"), "5000")
        await settle()
    asyncio.run(go())
    assert net.dials == []
    assert mgr._pending == {}


def test_passive_offer_expires(db, net, monkeypatch):
    monkeypatch.setattr(dccmod, "PASSIVE_CONNECT_TIMEOUT", 0.05)
    core, mgr = make(db, mode="passive")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        tok = offered_token(core)
        await asyncio.sleep(0.15)
        assert mgr._pending == {}
        await mgr.on_passive_callback(*ALICE, tok, ip_int("8.8.8.8"), "5000")
        await settle()
    asyncio.run(go())
    assert net.dials == []


# ---------------------------------------------------------------------------
# 5. Active (listener) path
# ---------------------------------------------------------------------------
def test_active_offer_listener_closed_on_expiry(db, net, monkeypatch):
    monkeypatch.setattr(dccmod, "ACTIVE_LISTEN_TIMEOUT", 0.05)
    core, mgr = make(db, mode="active", public_ip="198.51.100.7", port_min=40000, port_max=40100)

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        assert len(net.servers) == 1 and 40000 <= net.servers[0].port <= 40100
        assert net.servers[0].host == "127.0.0.1"
        assert f"DCC CHAT chat {ip_int('198.51.100.7')} {net.servers[0].port}" in core.ctcps()[-1]
        await asyncio.sleep(0.15)
    asyncio.run(go())
    assert net.servers[0].closed
    assert mgr._pending == {}
    assert net.dials == []


def test_active_accepts_one_connection_and_cleans_up(db, net):
    core, mgr = make(db, mode="active", public_ip="198.51.100.7")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        srv = net.servers[0]
        w1, w2 = FakeWriter(), FakeWriter()
        srv.cb(eof_reader(), w1)
        srv.cb(eof_reader(), w2)               # a second connection is refused
        assert w2.closed and srv.closed
        await settle()
        return w1, srv
    w1, srv = asyncio.run(go())
    assert w1.closed                               # no password answer → closed
    assert mgr._pending == {}


def test_active_no_free_port_releases_slot(db, net, monkeypatch):
    async def no_port(*a, **kw):
        raise OSError(98, "in use")
    monkeypatch.setattr(asyncio, "start_server", no_port)
    core, mgr = make(db, mode="active", public_ip="198.51.100.7")
    asyncio.run(mgr.handle_request(*ALICE, chat_args()))
    assert mgr._pending == {}
    assert "no free port" in core.notices()[-1]


# ---------------------------------------------------------------------------
# 6. Bounded pending requests and rate limits
# ---------------------------------------------------------------------------
def flood_users(n):
    return [(f"U{i}", hm(f"U{i}", f"u{i}", f"h{i}.example")) for i in range(n)]


@pytest.mark.parametrize("mode,extra", [("passive", {}), ("active", {"public_ip": "198.51.100.7"})])
def test_pending_flood_is_bounded_by_max_pending(db, net, mode, extra):
    core, mgr = make(db, mode=mode, max_pending=5, max_sessions=50,
                     global_rate_limit=1000, **extra)

    async def go():
        for nick, host in flood_users(30):
            await mgr.handle_request(nick, host, chat_args())
        await settle()
        assert len(mgr._pending) == 5
        assert len(core.ctcps()) == 5
        assert len(net.servers) == (5 if mode == "active" else 0)
        assert sum("too many pending" in n for n in core.notices()) == 25
        await shutdown(mgr)
    asyncio.run(go())
    assert mgr._pending == {}
    assert all(s.closed for s in net.servers)


def test_max_sessions_counts_pending_and_established(db, net):
    core, mgr = make(db, mode="passive", max_pending=10, max_sessions=3, global_rate_limit=1000)
    mgr._sessions = {1: object(), 2: object()}

    async def go():
        for nick, host in flood_users(5):
            await mgr.handle_request(nick, host, chat_args())
        await shutdown(mgr)
    asyncio.run(go())
    assert len(core.ctcps()) == 1
    assert sum("too many sessions" in n for n in core.notices()) == 4


def test_one_pending_request_per_handle(db, net):
    core, mgr = make(db, mode="passive", rate_limit=100)

    async def go():
        for _ in range(5):
            await mgr.handle_request(*ALICE, chat_args())
        # Same handle from a second matching nick is still the same owner.
        await mgr.handle_request("Alice2", hm("Alice2", "alice", "home.example"), chat_args())
        assert len(mgr._pending) == 1
        await shutdown(mgr)
    asyncio.run(go())
    assert len(core.ctcps()) == 1


def test_capacity_checked_before_reverse_dial(db, net):
    net.mode = "hang"
    core, mgr = make(db, max_pending=2, global_rate_limit=1000, connect_timeout=30)

    async def go():
        tasks = [asyncio.ensure_future(mgr.handle_request(n, h, chat_args("8.8.8.8", 5000)))
                 for n, h in flood_users(10)]
        await asyncio.sleep(0.2)
        assert len(net.dials) == 2 and len(mgr._pending) == 2
        await shutdown(mgr)
        await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run(go())
    assert mgr._pending == {}


def test_per_source_rate_limit_bounds_db_work(db, net):
    core, mgr = make(db, mode="passive", rate_limit=3)
    calls = []
    orig = core.user.match_user

    async def counting(mask):
        calls.append(mask)
        return await orig(mask)
    core.user.match_user = counting

    async def go():
        for _ in range(20):           # unknown attacker on one host ...
            await mgr.handle_request("M", hm("M", "m", "evil.example"), chat_args())
        for i in range(20):           # ... rotating nick and ident
            await mgr.handle_request(f"M{i}", hm(f"M{i}", f"m{i}", "EVIL.example"), chat_args())
    asyncio.run(go())
    assert len(calls) == 3
    assert core.sent == [] and net.dials == []


def test_global_rate_limit(db, net):
    core, mgr = make(db, mode="passive", rate_limit=100, global_rate_limit=4, max_pending=100,
                     max_sessions=100)

    async def go():
        for nick, host in flood_users(10):
            await mgr.handle_request(nick, host, chat_args())
        await shutdown(mgr)
    asyncio.run(go())
    assert len(core.ctcps()) == 4


def test_rate_limiter_window_and_key_bound():
    rl = dccmod._RateLimiter(2, 10, max_keys=3)
    assert rl.allow("a", 0) and rl.allow("a", 1) and not rl.allow("a", 2)
    assert rl.allow("a", 11)                      # window slid
    assert rl.allow("b", 11) and rl.allow("c", 11)
    assert not rl.allow("d", 12)                  # key table full of live keys
    assert rl.allow("d", 30)                      # stale keys pruned
    assert len(rl._hits) <= 3


# ---------------------------------------------------------------------------
# 7. Cleanup on every outcome
# ---------------------------------------------------------------------------
def test_connect_refused_releases_and_notices_generically(db, net):
    net.mode = "refuse"
    core, mgr = make(db)
    asyncio.run(mgr.handle_request(*ALICE, chat_args("8.8.8.8", 5000)))
    assert net.dials == [("8.8.8.8", 5000)]
    assert mgr._pending == {}
    assert core.notices() == ["DCC: connection failed."]   # no reflected error detail


def test_connect_timeout_releases(db, net):
    net.mode = "hang"
    core, mgr = make(db, connect_timeout=0.05)

    async def go():
        await mgr.handle_request(*ALICE, chat_args("8.8.8.8", 5000))
        await settle()
    asyncio.run(go())
    assert mgr._pending == {}
    assert core.notices() == ["DCC: connection failed."]


@pytest.mark.parametrize("trigger", ["quit", "nick", "reset"])
def test_release_during_dial_cancels_connect(db, net, trigger):
    net.mode = "hang"
    core, mgr = make(db, connect_timeout=30)

    async def go():
        t = asyncio.ensure_future(mgr.handle_request(*ALICE, chat_args("8.8.8.8", 5000)))
        await asyncio.sleep(0.05)
        assert len(mgr._pending) == 1
        req = next(iter(mgr._pending.values()))
        if trigger == "reset":
            assert mgr.reset("IRC disconnected") == 1
        else:
            assert mgr.forget_nick("alice") == 1        # RFC1459 casefold
        await asyncio.wait_for(t, 1)
        assert not t.cancelled()                         # caller's task ends cleanly
        assert req.tasks == set()
    asyncio.run(go())
    assert mgr._pending == {}


def test_session_layer_exception_closes_socket(db, net):
    core, mgr = make(db)

    async def crash(req, reader, writer):
        raise TypeError("broken session contract")
    mgr._open_session = crash
    asyncio.run(mgr.handle_request(*ALICE, chat_args("8.8.8.8", 5000)))
    assert net.writers[0].closed and mgr._pending == {}


def test_successful_session_handoff_keeps_socket_and_frees_slot(db, net):
    """Contract for SAST-010: True means the session layer owns the socket."""
    core, mgr = make(db)
    seen = []

    async def accept(req, reader, writer):
        seen.append((req.handle, req.hostmask, req.nick))
        return True
    mgr._open_session = accept
    asyncio.run(mgr.handle_request(*ALICE, chat_args("8.8.8.8", 5000)))
    assert seen == [("alice", "alice!alice@home.example", "Alice")]
    assert not net.writers[0].closed
    assert mgr._pending == {}


def test_expiry_during_session_setup_closes_socket(db, net, monkeypatch):
    core, mgr = make(db, mode="active", public_ip="198.51.100.7")
    monkeypatch.setattr(dccmod, "ACTIVE_LISTEN_TIMEOUT", 0.1)

    async def slow(req, reader, writer):
        await asyncio.sleep(10)
        return True
    mgr._open_session = slow

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        w = FakeWriter()
        net.servers[0].cb(asyncio.StreamReader(), w)
        await asyncio.sleep(0.3)
        return w
    w = asyncio.run(go())
    assert w.closed and net.servers[0].closed and mgr._pending == {}


# ---------------------------------------------------------------------------
# 8. Core wiring: routing, NICK/QUIT/disconnect expiry
# ---------------------------------------------------------------------------
def test_parse_chat_args():
    assert parse_chat_args(["DCC", "CHAT", "chat", "1", "2", "3"]) == ("1", "2", "3")
    assert parse_chat_args(["CHAT", "chat", "1", "2"]) == ("1", "2", None)
    assert parse_chat_args(["DCC", "CHAT"]) == (None, None, None)
    assert parse_chat_args(["DCC", "SEND", "x"]) == (None, None, None)


def test_core_routes_host_and_numeric_passive_token(db, net):
    core, mgr = make(db, mode="passive")
    tasks = []
    fake = SimpleNamespace(dcc=mgr, _create_safe_task=lambda c, name=None: tasks.append(
        asyncio.ensure_future(c)))

    async def go():
        await Core.on_dcc_chat_request(fake, {"nick": "Alice", "host": ALICE[1],
                                              "args": chat_args(), "passive_token": None})
        await asyncio.gather(*tasks)
        tok = offered_token(core)
        # irc.py sets passive_token only for non-numeric tokens; ours are numeric.
        await Core.on_dcc_chat_request(fake, {"nick": "Alice", "host": ALICE[1],
                                              "args": chat_args("8.8.8.8", 5000, tok),
                                              "passive_token": None})
        await asyncio.gather(*tasks)
        await settle()
    asyncio.run(go())
    assert net.dials == [("8.8.8.8", 5000)]


def test_core_routes_unknown_sender_without_network(db, net):
    core, mgr = make(db)
    tasks = []
    fake = SimpleNamespace(dcc=mgr, _create_safe_task=lambda c, name=None: tasks.append(
        asyncio.ensure_future(c)))

    async def go():
        await Core.on_dcc_chat_request(fake, {"nick": "M", "host": hm("M", "m", "x.example"),
                                              "args": ["DCC", "CHAT", "chat", "2130706433", "9"],
                                              "passive_token": None})
        await Core.on_dcc_chat_request(fake, {"nick": "M", "host": hm("M", "m", "x.example"),
                                              "args": ["DCC", "CHAT", "chat", "2130706433", "9",
                                                       "123456789012"],
                                              "passive_token": None})
        await asyncio.gather(*tasks)
    asyncio.run(go())
    assert net.dials == [] and core.sent == []


@pytest.mark.parametrize("event", ["quit", "nick_from", "nick_to", "bot_quit", "disconnect"])
def test_core_irc_events_expire_pending_offers(db, net, event):
    core, mgr = make(db, mode="passive")
    fake = SimpleNamespace(dcc=mgr, botname="wbs", channels={}, connected=True)
    fake._is_me = lambda nick: Core._is_me(fake, nick)   # Core helper since IRC-1

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        tok = offered_token(core)
        if event == "quit":
            await Core.on_quit(fake, {"nick": "ALICE"})
        elif event == "nick_from":
            await Core.on_nick(fake, {"old_nick": "Alice", "new_nick": "Alice_"})
        elif event == "nick_to":
            await Core.on_nick(fake, {"old_nick": "Someone", "new_nick": "alice"})
        elif event == "bot_quit":
            await Core.on_quit(fake, {"nick": "wbs"})
        else:
            await Core.on_disconnect(fake, {})
        assert mgr._pending == {}
        await mgr.on_passive_callback(*ALICE, tok, ip_int("8.8.8.8"), "5000")
        await settle()
    asyncio.run(go())
    assert net.dials == []


def test_unrelated_quit_keeps_offer(db, net):
    core, mgr = make(db, mode="passive")
    fake = SimpleNamespace(dcc=mgr, botname="wbs", channels={})
    fake._is_me = lambda nick: Core._is_me(fake, nick)   # Core helper since IRC-1

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        await Core.on_quit(fake, {"nick": "Carol"})
        assert len(mgr._pending) == 1
        await shutdown(mgr)
    asyncio.run(go())


# ---------------------------------------------------------------------------
# DCC-3: a configured dcc.public_ip is authoritative over the IRC-detected IP
# ---------------------------------------------------------------------------
def _fire_public_ip(mgr, ip):
    fake = SimpleNamespace(dcc=mgr, public_ip=None)
    asyncio.run(Core.on_bot_public_ip(fake, {"ip": ip}))


@pytest.mark.parametrize("mode", ["active", "auto"])
def test_configured_public_ip_wins_over_detected(db, net, mode):
    core, mgr = make(db, mode=mode, public_ip="127.0.0.1", listen_host="0.0.0.0")
    _fire_public_ip(mgr, "47.55.38.171")
    assert mgr.public_ip == "127.0.0.1"
    assert mgr.detected_public_ip == "47.55.38.171"

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        await shutdown(mgr)
    asyncio.run(go())
    assert f"DCC CHAT chat {ip_int('127.0.0.1')} " in core.ctcps()[-1]
    assert ip_int("47.55.38.171") not in core.ctcps()[-1]


def test_detected_public_ip_used_without_override(db, net):
    core, mgr = make(db, mode="auto", listen_host="0.0.0.0")
    assert mgr.public_ip is None
    _fire_public_ip(mgr, "47.55.38.171")
    assert mgr.public_ip == "47.55.38.171"

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        await shutdown(mgr)
    asyncio.run(go())
    assert f"DCC CHAT chat {ip_int('47.55.38.171')} " in core.ctcps()[-1]
    _fire_public_ip(mgr, "203.0.113.9")
    assert mgr.public_ip == "203.0.113.9"


# ---------------------------------------------------------------------------
# DCC-4. Client-initiated passive CHAT: `DCC CHAT chat <ip> 0 <token>`
# ---------------------------------------------------------------------------
CLIENT_TOKEN = "3735928559"        # chosen by the client; the bot never issued it


def _offer_fields(core):
    """(ip_int, port, token) of the last CTCP the bot sent."""
    ip, port, tok = core.ctcps()[-1].strip("\x01").split()[-3:]
    return ip, int(port), tok.rstrip("\x01")


def test_client_passive_request_is_answered_with_listener_and_echoed_token(db, net):
    core, mgr = make(db, mode="auto", public_ip="198.51.100.7", listen_host="0.0.0.0")

    async def go():
        await mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("1.1.1.1"), "0")
        await settle()
    asyncio.run(go())
    assert len(net.servers) == 1 and net.dials == []
    ip, port, tok = _offer_fields(core)
    assert core.ctcps()[-1] == (f"PRIVMSG Alice :\x01DCC CHAT chat {ip_int('198.51.100.7')} "
                                f"{port} {CLIENT_TOKEN}\x01")
    assert (ip, tok) == (ip_int("198.51.100.7"), CLIENT_TOKEN)
    assert net.servers[0].port == port and not net.servers[0].closed
    assert len(mgr._pending) == 1 and core.notices() == []


def test_client_passive_accepted_socket_runs_password_challenge(db, net):
    core, mgr = make(db, public_ip="198.51.100.7")

    async def go():
        await mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("1.1.1.1"), "0")
        w = FakeWriter(("1.1.1.1", 40000))
        net.servers[0].cb(eof_reader(), w)         # the client connects to our listener
        await settle(20)
        return w
    w = asyncio.run(go())
    assert w.closed and w.data              # challenge prompt sent, peer left unauthenticated
    assert net.servers[0].closed and mgr._pending == {} and mgr._sessions == {}


def test_client_passive_request_uses_configured_ip_over_detected(db, net):
    core, mgr = make(db, public_ip="198.51.100.7")
    mgr.set_detected_public_ip("203.0.113.9")
    asyncio.run(mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("1.1.1.1"), "0"))
    assert _offer_fields(core)[0] == ip_int("198.51.100.7")


@pytest.mark.parametrize("nick,host", [
    ("Mallory", hm("Mallory", "m", "evil.example")),
    ("Mallory", hm("Alice", "alice", "home.example")),
    ("Np", hm("Np", "np", "np.example")),
    ("Lk", hm("Lk", "lk", "lk.example")),
], ids=["unknown", "other-nick", "no +p", "locked"])
def test_client_passive_request_from_unauthorized_host_is_silent(db, net, nick, host):
    core, mgr = make(db, public_ip="198.51.100.7")
    asyncio.run(mgr.on_passive_callback(nick, host, CLIENT_TOKEN, ip_int("1.1.1.1"), "0"))
    assert net.servers == [] and net.dials == []
    assert core.sent == [] and mgr._pending == {}


def test_client_passive_request_honours_gates(db, net):
    # capacity: one pending request per handle
    core, mgr = make(db, public_ip="198.51.100.7")

    async def twice():
        await mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("1.1.1.1"), "0")
        await mgr.on_passive_callback(*ALICE, "12345", ip_int("1.1.1.1"), "0")
    asyncio.run(twice())
    assert len(net.servers) == 1 and len(core.ctcps()) == 1
    assert any("already have a DCC request pending" in n for n in core.notices())

    # disabled, kill switch, rate limit, no address to advertise
    core, mgr = make(db, public_ip="198.51.100.7", enabled=False)
    asyncio.run(mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("1.1.1.1"), "0"))
    assert core.sent == []
    core, mgr = make(db, enabled_sessions=False, public_ip="198.51.100.7")
    asyncio.run(mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("1.1.1.1"), "0"))
    assert core.ctcps() == [] and len(core.notices()) == 1
    core, mgr = make(db, public_ip="198.51.100.7", rate_limit=0)
    asyncio.run(mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("1.1.1.1"), "0"))
    assert core.sent == []
    core, mgr = make(db)                       # no configured or detected IP
    asyncio.run(mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("1.1.1.1"), "0"))
    assert core.ctcps() == [] and len(core.notices()) == 1
    assert net.dials == []


def test_client_passive_request_listener_released_on_expiry(db, net, monkeypatch):
    monkeypatch.setattr(dccmod, "ACTIVE_LISTEN_TIMEOUT", 0.05)
    core, mgr = make(db, public_ip="198.51.100.7")

    async def go():
        await mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("1.1.1.1"), "0")
        await asyncio.sleep(0.2)
    asyncio.run(go())
    assert net.servers[0].closed and mgr._pending == {}


def test_callback_for_bot_issued_token_still_dials_and_is_not_answered(db, net):
    core, mgr = make(db, mode="passive", public_ip="198.51.100.7")

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        tok = offered_token(core)
        sent = len(core.sent)
        await mgr.on_passive_callback(*ALICE, tok, ip_int("8.8.4.4"), "5001")
        await settle()
        return sent
    sent = asyncio.run(go())
    assert net.dials == [("8.8.4.4", 5001)] and net.servers == []
    assert len(core.ctcps()) == 1 and sent == 1       # only the original offer


def test_unknown_token_with_real_port_is_not_a_client_request(db, net):
    core, mgr = make(db, public_ip="198.51.100.7")
    asyncio.run(mgr.on_passive_callback(*ALICE, CLIENT_TOKEN, ip_int("8.8.8.8"), "5000"))
    assert net.servers == [] and net.dials == [] and core.sent == []


def test_client_passive_malformed_token_ignored(db, net):
    core, mgr = make(db, public_ip="198.51.100.7")
    asyncio.run(mgr.on_passive_callback(*ALICE, "12 34\\x01", ip_int("1.1.1.1"), "0"))
    asyncio.run(mgr.on_passive_callback(*ALICE, "1" * 40, ip_int("1.1.1.1"), "0"))
    assert net.servers == [] and core.sent == []


@pytest.mark.parametrize("tail,expected", [
    ([], None),
    (["3735928559"], "3735928559"),         # all-digit token must survive irc.py
    (["123456789012"], "123456789012"),
    (["abcXYZ"], "abcXYZ"),
], ids=["none", "digits", "long-digits", "alpha"])
def test_irc_ctcp_forwards_all_digit_token(tail, expected):
    from src.irc import WbsIrcBot
    events = []
    fake = SimpleNamespace(_emit_event=events.append,
                           _chan_activity=lambda kind, event: None,   # IRC-7
                           _ctcp_flooded=lambda event: False)
    source = type("S", (), {"nick": "Alice", "__str__": lambda s: ALICE[1]})()
    ev = SimpleNamespace(source=source,
                         arguments=["DCC", "CHAT chat 16843009 0 " + " ".join(tail)])
    WbsIrcBot.on_ctcp(fake, None, ev)
    assert len(events) == 1 and events[0]["passive_token"] == expected
    assert events[0]["host"] == ALICE[1]


def test_core_routes_client_passive_request_end_to_end(db, net):
    core, mgr = make(db, public_ip="198.51.100.7")
    tasks = []
    fake = SimpleNamespace(dcc=mgr, _create_safe_task=lambda c, name=None: tasks.append(
        asyncio.ensure_future(c)))

    async def go():
        await Core.on_dcc_chat_request(fake, {"nick": "Alice", "host": ALICE[1],
                                              "args": chat_args("1.1.1.1", 0, CLIENT_TOKEN),
                                              "passive_token": CLIENT_TOKEN})
        await asyncio.gather(*tasks)
    asyncio.run(go())
    assert len(net.servers) == 1 and net.dials == []
    assert _offer_fields(core)[2] == CLIENT_TOKEN


# ---------------------------------------------------------------------------
# F-06b. dcc.listen_host: loopback by default, independent of botnet.listen_host
# ---------------------------------------------------------------------------
def _handle(mgr):
    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        await settle()
        await shutdown(mgr)
    asyncio.run(go())


def test_dcc_listen_host_defaults_to_loopback(db):
    _core, mgr = make(db)
    assert mgr.listen_ip == "127.0.0.1" and mgr.listen_is_loopback
    for blank in ("", None):
        assert make(db, listen_host=blank)[1].listen_ip == "127.0.0.1"


def test_dcc_listen_host_ignores_botnet_and_settings_bind(db):
    core = FakeCore(db, {})
    core.config["botnet"]["listen_host"] = "0.0.0.0"
    core.config["settings"]["listen_host"] = "0.0.0.0"
    mgr = DCCManager(core)
    assert mgr.listen_ip == "127.0.0.1"


def test_dcc_explicit_all_interfaces_is_honoured(db, net):
    core, mgr = make(db, mode="active", public_ip="198.51.100.7", listen_host="0.0.0.0")
    assert mgr.listen_ip == "0.0.0.0" and not mgr.listen_is_loopback
    _handle(mgr)
    assert [s.host for s in net.servers] == ["0.0.0.0"]


@pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "::1", "[::1]", "localhost"])
def test_dcc_loopback_forms_detected(db, host):
    assert make(db, listen_host=host)[1].listen_is_loopback


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10"])
def test_dcc_non_loopback_forms_detected(db, host):
    assert not make(db, listen_host=host)[1].listen_is_loopback


def test_dcc_auto_with_default_bind_falls_back_to_passive(db, net, caplog):
    core, mgr = make(db, mode="auto", public_ip="198.51.100.7")
    with caplog.at_level("INFO", logger="wbs.dcc"):
        _handle(mgr)
    assert net.servers == [] and net.dials == []        # no active listener opened
    assert len(core.ctcps()) == 1                       # passive offer sent instead
    assert core.ctcps()[0].strip("\x01").split()[-2] == "0"      # passive: port 0 + token
    assert any("passive DCC" in r.getMessage() for r in caplog.records)


def test_dcc_auto_with_open_bind_stays_active(db, net):
    core, mgr = make(db, mode="auto", public_ip="198.51.100.7", listen_host="0.0.0.0")
    _handle(mgr)
    assert len(net.servers) == 1 and net.servers[0].host == "0.0.0.0"


def test_dcc_explicit_active_on_loopback_warns_but_listens(db, net, caplog):
    core, mgr = make(db, mode="active", public_ip="198.51.100.7")
    with caplog.at_level("WARNING", logger="wbs.dcc"):
        _handle(mgr)
    assert [s.host for s in net.servers] == ["127.0.0.1"]
    assert any(r.levelname == "WARNING" and "loopback" in r.getMessage()
               for r in caplog.records)


def test_dcc_open_bind_does_not_warn(db, net, caplog):
    core, mgr = make(db, mode="active", public_ip="198.51.100.7", listen_host="0.0.0.0")
    with caplog.at_level("WARNING", logger="wbs.dcc"):
        _handle(mgr)
    assert not any("loopback" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("bind", ["127.0.0.1", "0.0.0.0"])
def test_dcc_advertised_address_is_public_ip_never_the_bind(db, net, bind):
    core, mgr = make(db, mode="active", public_ip="198.51.100.7", listen_host=bind)
    _handle(mgr)
    offer = core.ctcps()[0]
    assert f"DCC CHAT chat {ip_int('198.51.100.7')} {net.servers[0].port}" in offer
    assert ip_int("127.0.0.1") not in offer and ip_int("0.0.0.0") + " " not in offer


def test_dcc_advertised_address_falls_back_to_detected_ip(db, net):
    core, mgr = make(db, mode="active", listen_host="0.0.0.0")
    _fire_public_ip(mgr, "47.55.38.171")
    _handle(mgr)
    assert f"DCC CHAT chat {ip_int('47.55.38.171')} " in core.ctcps()[0]
