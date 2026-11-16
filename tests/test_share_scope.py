"""
Offline regression tests for SAST-003: scoped peer replication and rejection of
unauthorized ACL writes.

Two subnets (1 "one", 2 "two").  The local bot "beta" is in subnet 1 and is
linked over a real AUTH2 handshake (in-memory fake writers, no network, no
IRC) to one peer per share policy:

    handle   stored subnet(s)  stored share_level   resulting share scope
    sub1     1                 subnet               {1}
    sub1b    1                 subnet               {1}   (second, for relays)
    none1    1                 none                 {}
    all2     2                 all                  {2}   (cross subnet)
    sub2     2                 subnet               {}    (cross subnet)
    all12    1, 2              all                  {1, 2}
    junk1    1                 'bogus'              {}    (unknown level = none)

Local data in beta's DB covers every ownership class: subnet-1 and subnet-2
users/channels/bots, a privileged (+A) user, a user with a global access row,
a global (unbound) channel, and a bcrypt password on every user.
Each DB is a throwaway sqlite file under pytest's tmp_path.
"""
import asyncio
import json
import os
import shutil
import tempfile
import time
import uuid
from types import SimpleNamespace as NS
from unittest.mock import patch

from src import botnet as botnet_mod
from src import commands
from src.botnet import BotnetManager
from src.db import get_db, init_db
from src.share import ReplicationPolicy, normalize_share_level

PSK = "test-only-link-key-0123456789"
FAKE_HASH = "$2b$12$" + "x" * 53          # bcrypt-shaped placeholder, not a secret
LOCAL = "beta"
PEERS = {
    # handle: (stored subnet_id, extra bot_subnets, share_level)
    "sub1": (1, (), "subnet"),
    "sub1b": (1, (), "subnet"),
    "none1": (1, (), "none"),
    "all2": (2, (), "all"),
    "sub2": (2, (), "subnet"),
    "all12": (1, (2,), "all"),
    "junk1": (1, (), "bogus"),
}


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------
class FakeWriter:
    def __init__(self):
        self.sent: list[str] = []
        self.closed = False

    def write(self, data: bytes):
        if not self.closed:
            self.sent.extend(l for l in data.decode().split("\n") if l)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def is_closing(self):
        return self.closed

    def get_extra_info(self, key):
        return ("192.0.2.10", 4444) if key == "peername" else None

    def take(self) -> list[str]:
        out, self.sent = self.sent, []
        return out


async def _nop(*a, **k):
    return None


_TEMPLATE_DB: str | None = None


async def _fresh_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-sast003-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


async def seed_local(db: str) -> None:
    async with get_db(db) as d:
        await d.executescript(f"""
            INSERT INTO channels(name) VALUES ('#one'), ('#two'), ('#global');
            INSERT INTO channel_subnets(channel_name, subnet_id) VALUES ('#one', 1), ('#two', 2);

            INSERT INTO users(handle, password, hostmasks) VALUES
                ('u1',    '{FAKE_HASH}', '["*!u1@one"]'),
                ('u2',    '{FAKE_HASH}', '["*!u2@two"]'),
                ('boss',  '{FAKE_HASH}', '["*!boss@one"]'),
                ('gl',    '{FAKE_HASH}', '["*!gl@any"]'),
                ('u1c',   '{FAKE_HASH}', '[]');
            INSERT INTO user_access(handle, channel, subnet_id, has_partyline, is_op, is_admin) VALUES
                ('u1',   NULL,   1,    1, 1, 0),
                ('u2',   NULL,   2,    1, 1, 0),
                ('boss', NULL,   1,    1, 1, 1),
                ('gl',   NULL,   NULL, 1, 0, 0),
                ('u1c',  '#one', 1,    0, 1, 0);

            INSERT INTO bots(handle, address, port, subnet_id) VALUES
                ('b1', '198.51.100.1', 3333, 1),
                ('b2', '198.51.100.2', 3333, 2);
            INSERT INTO bot_access(handle, channel, is_op) VALUES
                ('b1', NULL, 1), ('b2', NULL, 1), ('b1', '#one', 1), ('b2', '#two', 1);
        """)
        await d.commit()


async def make_mgr(tmp_path, nick: str, local_subnet: int, peers: dict, seed=False):
    db = str(tmp_path / f"{nick}.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        for handle, (sid, extra, share) in peers.items():
            await d.execute(
                "INSERT INTO bots(handle, password, address, port, subnet_id, share_level) "
                "VALUES (?, ?, '192.0.2.1', 3333, ?, ?)", (handle, PSK, sid, share))
            for x in extra:
                await d.execute("INSERT INTO bot_subnets(bot_handle, subnet_id) VALUES (?, ?)",
                                (handle, x))
        await d.commit()
    if seed:
        await seed_local(db)
    core = NS(
        db_path=db,
        config={"bot": {"nick": nick}, "botnet": {"subnet_id": local_subnet},
                "settings": {"ssl": False}},
        bot_sessions={},
        send_irc=lambda *a, **k: None,
        partyline=NS(broadcast=lambda *a, **k: None),
        botname=nick,
        bot_isop=lambda chan: True,
        channels={},
    )
    mgr = BotnetManager(core)
    core.botnet = mgr
    core.user, core.bot, core.chan = mgr.user, mgr.bot, mgr.chan
    mgr.share_all_data = _nop          # link-up share is driven explicitly by tests
    mgr.broadcast_topology = _nop
    await mgr.subnet.load()
    return mgr


async def link(initiator: BotnetManager, responder: BotnetManager):
    i_w = FakeWriter()

    async def fake_open(*args, **kwargs):
        return None, i_w

    with patch.object(botnet_mod.asyncio, "open_connection", fake_open), \
            patch.object(initiator, "read_peer", _nop):
        await initiator.connect_peer(responder.my_handle)
    r_w = FakeWriter()
    i, r = initiator.my_handle, responder.my_handle
    await responder.process_incoming(i, i_w.take()[0], None, r_w)
    await initiator.process_incoming(r, r_w.take()[0], None, i_w)
    await responder.process_incoming(i, i_w.take()[0], None, r_w)
    await initiator.process_incoming(r, r_w.take()[0], None, i_w)
    assert responder.peers[i].authed and initiator.peers[r].authed
    return i_w, r_w


async def build(tmp_path):
    beta = await make_mgr(tmp_path, LOCAL, 1, PEERS, seed=True)
    net = NS(beta=beta, w={}, peer={})
    for handle, (sid, _, _) in PEERS.items():
        peer = await make_mgr(tmp_path, handle, sid, {LOCAL: (1, (), "subnet")})
        _, beta_w = await link(peer, beta)
        net.peer[handle] = peer
        net.w[handle] = beta_w
    return net


def run(coro):
    return asyncio.run(coro)


def rid() -> str:
    return str(uuid.uuid4())


def reset(net):
    for w in net.w.values():
        w.take()


async def send(net, frm: str, line: str) -> None:
    await net.beta.process_incoming(frm, line, None, net.w[frm])


def update(entity: str, payload, action: str | None = None, msg_id: str | None = None) -> str:
    mid = msg_id or rid()
    head = f"UPDATE {mid} {entity}" + (f" {action}" if action else "")
    return f"{head} {json.dumps(payload)}"


def shares(w: FakeWriter) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for line in w.take():
        assert line.startswith("SHARE "), line
        _, ent, data = line.split(" ", 2)
        out[ent] = json.loads(data)
    return out


def updates(w: FakeWriter) -> list[tuple[str, str, str | None, dict]]:
    """[(msg_id, entity, action, payload)] of every UPDATE sent on w."""
    out = []
    for line in w.take():
        parts = line.split(" ", 4)
        assert parts[0] == "UPDATE", line
        if parts[2] in ("USER", "BOT", "CHANNEL"):
            out.append((parts[1], parts[2], parts[3], json.loads(parts[4])))
        else:
            out.append((parts[1], parts[2], None, json.loads(line.split(" ", 3)[3])))
    return out


async def q(net, sql: str, args=()):
    async with get_db(net.beta.db_path) as d:
        return [dict(r) for r in await d.execute_fetchall(sql, args)]


def now() -> int:
    return int(time.time())


SECRET_KEYS = {"password"}
PRIV_KEYS = {"is_admin", "is_owner"}
LOCAL_ONLY_BOT_KEYS = {"password", "share_level", "subnet_id", "autolink", "autolink_retry_interval"}


# ---------------------------------------------------------------------------
# share policy and scope
# ---------------------------------------------------------------------------
def test_share_level_normalization_defaults_to_none():
    assert normalize_share_level("subnet") == "subnet"
    assert normalize_share_level("ALL") == "all"
    assert normalize_share_level("full") == "all"
    for bad in (None, "", "bogus", 1, "none"):
        assert normalize_share_level(bad) == "none"
    p = ReplicationPolicy(":memory:", 1, LOCAL)
    assert p.scope_for("subnet", {1}) == {1}
    assert p.scope_for("subnet", {2}) == frozenset()
    assert p.scope_for("subnet", {1, 2}) == {1}
    assert p.scope_for("all", {1, 2}) == {1, 2}
    assert p.scope_for("all", set()) == frozenset()
    assert p.scope_for("none", {1}) == frozenset()


def test_stored_share_level_is_preserved_on_live_links(tmp_path):
    async def main():
        net = await build(tmp_path)
        b = net.beta
        want = {"sub1": {1}, "sub1b": {1}, "none1": set(), "all2": {2}, "sub2": set(),
                "all12": {1, 2}, "junk1": set()}
        assert b.peers["none1"].share_level == "none"
        assert b.peers["junk1"].share_level == "none"
        for h, scope in want.items():
            assert b.share_scope(b.peers[h]) == frozenset(scope), h

        # .botattr share= re-scopes a live link and is never replicated
        synced = []

        async def capture(data):
            synced.append(data)

        b.sync_bot_access = capture
        out = []

        async def respond(m):
            out.append(m)

        await commands.cmd_botattr(b.core, "owner", 1, "none1 share=all", respond)
        await asyncio.sleep(0)
        assert b.share_scope(b.peers["none1"]) == {1}
        await commands.cmd_botattr(b.core, "owner", 1, "none1 share=none", respond)
        assert b.share_scope(b.peers["none1"]) == frozenset()
        assert all("share_level" not in d.get("flags", {}) for d in synced)

    run(main())


# ---------------------------------------------------------------------------
# outbound: no disallowed data leaves
# ---------------------------------------------------------------------------
def _assert_clean(sh: dict[str, list[dict]]):
    for ent, recs in sh.items():
        for r in recs:
            assert not (SECRET_KEYS & r.keys()), (ent, r)
            if ent in ("USERS", "USERACCESS"):
                assert not (PRIV_KEYS & r.keys()), (ent, r)
            if ent == "BOTS":
                assert not (LOCAL_ONLY_BOT_KEYS & r.keys()), (ent, r)


def test_outbound_share_none_sends_nothing(tmp_path):
    async def main():
        net = await build(tmp_path)
        reset(net)
        for h in ("none1", "sub2", "junk1"):
            await BotnetManager.share_all_data(net.beta, h)
            assert net.w[h].take() == [], h

    run(main())


def test_outbound_share_subnet_sends_only_local_subnet_data(tmp_path):
    async def main():
        net = await build(tmp_path)
        reset(net)
        await BotnetManager.share_all_data(net.beta, "sub1")
        sh = shares(net.w["sub1"])
        _assert_clean(sh)
        assert {s["id"] for s in sh["SUBNETS"]} == {1}
        assert {c["name"] for c in sh["CHANNELS"]} == {"#one"}
        assert all(c["subnet_ids"] == [1] for c in sh["CHANNELS"])
        assert {u["handle"] for u in sh["USERS"]} == {"u1", "u1c"}
        assert {(a["handle"], a["channel"], a["subnet_id"]) for a in sh["USERACCESS"]} == {
            ("u1", None, 1), ("u1c", "#one", 1)}
        bots = {x["handle"] for x in sh["BOTS"]}
        assert "b1" in bots and "b2" not in bots and "sub1" not in bots and "all2" not in bots
        assert {(a["handle"], a["channel"]) for a in sh["BOTACCESS"]} >= {("b1", "#one")}
        assert all(a["handle"] != "b2" and a["channel"] in (None, "#one") for a in sh["BOTACCESS"])
        # no global or privileged data at all
        dump = json.dumps(sh)
        for leak in ("boss", '"gl"', "#global", "#two", "u2", FAKE_HASH):
            assert leak not in dump, leak

    run(main())


def test_outbound_share_all_cross_subnet_sends_only_that_subnet(tmp_path):
    async def main():
        net = await build(tmp_path)
        reset(net)
        await BotnetManager.share_all_data(net.beta, "all2")
        sh = shares(net.w["all2"])
        _assert_clean(sh)
        assert {s["id"] for s in sh["SUBNETS"]} == {2}
        assert {c["name"] for c in sh["CHANNELS"]} == {"#two"}
        assert {u["handle"] for u in sh["USERS"]} == {"u2"}
        assert {a["handle"] for a in sh["USERACCESS"]} == {"u2"}
        assert {x["handle"] for x in sh["BOTS"]} == {"b2", "sub2"}   # subnet-2 bots only
        dump = json.dumps(sh)
        for leak in ("boss", '"gl"', "#global", "#one", '"u1"', "b1", FAKE_HASH):
            assert leak not in dump, leak

    run(main())


def test_outbound_share_all_multi_subnet_peer_never_gets_global_data(tmp_path):
    async def main():
        net = await build(tmp_path)
        reset(net)
        await BotnetManager.share_all_data(net.beta, "all12")
        sh = shares(net.w["all12"])
        _assert_clean(sh)
        assert {c["name"] for c in sh["CHANNELS"]} == {"#one", "#two"}
        assert {u["handle"] for u in sh["USERS"]} == {"u1", "u2", "u1c"}
        dump = json.dumps(sh)
        for leak in ("boss", '"gl"', "#global", FAKE_HASH):
            assert leak not in dump, leak

    run(main())


def test_user_serialization_never_contains_passwords(tmp_path):
    async def main():
        net = await build(tmp_path)
        users = await net.beta.user.serialize_for_peer()
        assert users and all("password" not in u for u in users)

    run(main())


def test_local_sync_is_scoped_per_peer(tmp_path):
    async def main():
        net = await build(tmp_path)
        b = net.beta
        reset(net)
        await b.sync_user("ADD", {"handle": "u2"})
        got = {h: updates(w) for h, w in net.w.items()}
        assert {h for h, u in got.items() if u} == {"all2", "all12"}
        for u in got["all2"]:
            assert "password" not in u[3] and not (PRIV_KEYS & u[3].keys())

        reset(net)
        await b.sync_user("ADD", {"handle": "boss"})         # privileged: nobody
        await b.sync_user("ADD", {"handle": "gl"})           # global: nobody
        await b.sync_channel("ADD", {"name": "#global"})     # global: nobody
        await b.sync_user_access({"handle": "boss"})
        assert all(w.take() == [] for w in net.w.values())

        await b.sync_channel("ADD", {"name": "#one"})
        got = {h: updates(w) for h, w in net.w.items()}
        assert {h for h, u in got.items() if u} == {"sub1", "sub1b", "all12"}

        reset(net)
        await b.sync_bot_access({"handle": "b2"})
        got = {h: updates(w) for h, w in net.w.items()}
        assert {h for h, u in got.items() if u} == {"all2", "all12"}
        for u in got["all2"]:
            assert not (LOCAL_ONLY_BOT_KEYS & u[3].keys())

    run(main())


# ---------------------------------------------------------------------------
# inbound: no global / foreign ACL change lands
# ---------------------------------------------------------------------------
def test_inbound_global_admin_and_privilege_writes_rejected(tmp_path):
    async def main():
        net = await build(tmp_path)
        rows = [
            {"handle": "evil", "channel": None, "subnet_id": None, "is_admin": 1,
             "has_partyline": 1, "updated_at": now()},
            {"handle": "evil", "channel": None, "subnet_id": 1, "is_admin": 1, "updated_at": now()},
            {"handle": "evil", "channel": None, "subnet_id": 1, "is_owner": 1, "updated_at": now()},
            {"handle": "u1", "channel": None, "subnet_id": 1, "is_owner": 1, "is_op": 1,
             "updated_at": now() + 5},
            {"handle": "u1", "channel": None, "subnet_id": None, "is_admin": 1, "updated_at": now()},
            {"handle": "gl", "channel": None, "subnet_id": 1, "is_op": 1, "updated_at": now()},
            {"handle": "boss", "channel": None, "subnet_id": 1, "is_op": 0, "updated_at": now() + 5},
        ]
        for frm in ("sub1", "all12", "all2", "none1"):
            await send(net, frm, f"SHARE USERACCESS {json.dumps(rows)}")
            for r in rows:
                await send(net, frm, update("USERACCESS", r))
        assert await q(net, "SELECT * FROM users WHERE handle = 'evil'") == []
        assert await q(net, "SELECT * FROM user_access WHERE is_owner = 1") == []
        admins = await q(net, "SELECT handle FROM user_access WHERE is_admin = 1")
        assert admins == [{"handle": "boss"}]
        assert (await q(net, "SELECT is_op FROM user_access WHERE handle='boss'"))[0]["is_op"] == 1
        assert len(await q(net, "SELECT * FROM user_access WHERE handle = 'u1'")) == 1
        assert len(await q(net, "SELECT * FROM user_access WHERE handle = 'gl'")) == 1
        for sid in (None, 1, 2):
            assert await net.beta.user.matchattr("evil", "+A", subnet_id=sid) is False
            assert await net.beta.user.matchattr("u1", "+n", subnet_id=sid) is False

    run(main())


def test_inbound_foreign_subnet_writes_rejected(tmp_path):
    async def main():
        net = await build(tmp_path)
        t = now() + 5
        await send(net, "sub1", update("USERACCESS",
                   {"handle": "u2", "channel": None, "subnet_id": 2, "is_op": 0, "updated_at": t}))
        await send(net, "sub1", update("USERACCESS",
                   {"handle": "x9", "channel": None, "subnet_id": 2, "is_op": 1, "updated_at": t}))
        await send(net, "sub1", update("USERACCESS",   # subnet-1 row on a subnet-2 channel
                   {"handle": "x9", "channel": "#two", "subnet_id": 1, "is_op": 1, "updated_at": t}))
        await send(net, "sub1", update("USERACCESS",   # row on a global channel
                   {"handle": "x9", "channel": "#global", "subnet_id": 1, "is_op": 1, "updated_at": t}))
        await send(net, "all2", update("USERACCESS",   # cross peer writing subnet 1
                   {"handle": "u1", "channel": None, "subnet_id": 1, "is_op": 0, "updated_at": t}))
        await send(net, "sub1", update("USER", {"handle": "u2", "hostmasks": ["*!*@*"],
                                                "updated_at": t}, "ADD"))
        await send(net, "sub1", update("BOTACCESS", {"handle": "b2", "channel": None,
                                                     "is_op": 0, "updated_at": t}))
        await send(net, "sub1", update("BOT", {"handle": "b2", "address": "203.0.113.9",
                                               "updated_at": t}, "ADD"))
        await send(net, "sub1", update("CHANNEL", {"name": "#two", "comment": "pwn",
                                                   "updated_at": t}, "ADD"))
        await send(net, "sub1", update("CHANNEL", {"name": "#global", "comment": "pwn",
                                                   "updated_at": t}, "ADD"))
        await send(net, "sub1", update("CHANNEL", {"name": "#new2", "subnet_ids": [2],
                                                   "updated_at": t}, "ADD"))
        await send(net, "sub1", update("CHANNEL", {"name": "#newg", "updated_at": t}, "ADD"))
        await send(net, "sub1", f"SHARE SUBNETS {json.dumps([{'id': 7, 'name': 'seven'}])}")

        assert (await q(net, "SELECT is_op FROM user_access WHERE handle='u2'"))[0]["is_op"] == 1
        assert (await q(net, "SELECT is_op FROM user_access WHERE handle='u1'"))[0]["is_op"] == 1
        assert await q(net, "SELECT * FROM users WHERE handle='x9'") == []
        assert (await q(net, "SELECT hostmasks FROM users WHERE handle='u2'"))[0]["hostmasks"] \
            == '["*!u2@two"]'
        assert (await q(net, "SELECT is_op FROM bot_access WHERE handle='b2' AND channel IS NULL"
                        ))[0]["is_op"] == 1
        assert (await q(net, "SELECT address FROM bots WHERE handle='b2'"))[0]["address"] \
            == "198.51.100.2"
        assert {r["comment"] for r in await q(net, "SELECT comment FROM channels")} == {""}
        assert await q(net, "SELECT * FROM channels WHERE name IN ('#new2', '#newg')") == []
        assert await q(net, "SELECT * FROM subnets WHERE id = 7") == []

    run(main())


def test_inbound_in_scope_writes_land_without_credentials_or_local_policy(tmp_path):
    async def main():
        net = await build(tmp_path)
        t = now() + 5
        # new user via in-scope access row: inert shell, no password, no admin
        await send(net, "sub1", update("USERACCESS", {"handle": "newu", "channel": None,
                   "subnet_id": 1, "is_op": 1, "is_admin": 0, "updated_at": t}))
        rows = await q(net, "SELECT * FROM user_access WHERE handle='newu'")
        assert len(rows) == 1 and rows[0]["is_op"] == 1 and rows[0]["is_admin"] == 0
        assert (await q(net, "SELECT password FROM users WHERE handle='newu'"))[0]["password"] is None
        # an in-scope user update may change identity fields but never the password
        await send(net, "sub1", update("USER", {"handle": "u1", "password": "$2b$12$" + "a" * 53,
                   "hostmasks": ["*!u1@new"], "updated_at": t}, "ADD"))
        u1 = (await q(net, "SELECT password, hostmasks FROM users WHERE handle='u1'"))[0]
        assert u1 == {"password": FAKE_HASH, "hostmasks": '["*!u1@new"]'}
        # unknown users are never created from a USERS record
        await send(net, "sub1", update("USER", {"handle": "ghost", "password": "$2b$x",
                                                "updated_at": t}, "ADD"))
        assert await q(net, "SELECT * FROM users WHERE handle='ghost'") == []
        # in-scope bot update: carried fields only; local policy/scope/key untouched
        await send(net, "sub1", update("BOT", {"handle": "b1", "address": "203.0.113.1",
                   "share_level": "all", "subnet_id": 2, "autolink": 1, "password": "k" * 20,
                   "updated_at": t}, "ADD"))
        b1 = (await q(net, "SELECT * FROM bots WHERE handle='b1'"))[0]
        assert b1["address"] == "203.0.113.1" and b1["subnet_id"] == 1
        assert b1["share_level"] == "subnet" and b1["autolink"] == 0 and b1["password"] is None
        # bots we hold a link key for are operator-owned
        await send(net, "sub1", update("BOT", {"handle": "sub1b", "address": "203.0.113.66",
                                               "updated_at": t}, "ADD"))
        await send(net, "sub1", update("BOTACCESS", {"handle": "sub1b", "channel": None,
                                                     "is_op": 1, "updated_at": t}))
        assert (await q(net, "SELECT address FROM bots WHERE handle='sub1b'"))[0]["address"] \
            == "192.0.2.1"
        assert await q(net, "SELECT * FROM bot_access WHERE handle='sub1b'") == []
        # unknown bots are never created
        await send(net, "sub1", update("BOT", {"handle": "rogue", "address": "203.0.113.7",
                                               "updated_at": t}, "ADD"))
        assert await q(net, "SELECT * FROM bots WHERE handle='rogue'") == []
        # in-scope channel update and new subnet-1 channel
        await send(net, "sub1", update("CHANNEL", {"name": "#one", "comment": "ok",
                                                   "subnet_ids": [1, 2], "updated_at": t}, "ADD"))
        await send(net, "sub1", update("CHANNEL", {"name": "#new1", "subnet_ids": [1],
                                                   "updated_at": t}, "ADD"))
        assert (await q(net, "SELECT comment FROM channels WHERE name='#one'"))[0]["comment"] == "ok"
        assert {r["subnet_id"] for r in await q(
            net, "SELECT subnet_id FROM channel_subnets WHERE channel_name='#one'")} == {1}
        assert await q(net, "SELECT subnet_id FROM channel_subnets WHERE channel_name='#new1'") \
            == [{"subnet_id": 1}]

    run(main())


def test_share_none_peer_writes_nothing(tmp_path):
    async def main():
        net = await build(tmp_path)
        t = now() + 5
        for frm in ("none1", "junk1", "sub2"):
            await send(net, frm, update("USERACCESS", {"handle": "nn", "channel": None,
                       "subnet_id": 1 if frm != "sub2" else 2, "is_op": 1, "updated_at": t}))
            await send(net, frm, update("USER", {"handle": "u1", "comment": "x",
                                                 "updated_at": t}, "ADD"))
            await send(net, frm, update("USER", {"handle": "u1"}, "DEL"))
            await send(net, frm, f"SHARE CHANNELS {json.dumps([{'name': '#one', 'comment': 'x', 'updated_at': t}])}")
        assert await q(net, "SELECT * FROM users WHERE handle='nn'") == []
        u1 = (await q(net, "SELECT comment, deleted_at FROM users WHERE handle='u1'"))[0]
        assert u1 == {"comment": "", "deleted_at": None}
        assert (await q(net, "SELECT comment FROM channels WHERE name='#one'"))[0]["comment"] == ""

    run(main())


# ---------------------------------------------------------------------------
# deletes and timestamps
# ---------------------------------------------------------------------------
def test_unauthorized_deletes_rejected_and_authorized_deletes_are_soft(tmp_path):
    async def main():
        net = await build(tmp_path)
        for frm in ("sub1", "all2"):
            for h in ("boss", "gl"):
                await send(net, frm, update("USER", {"handle": h}, "DEL"))
            await send(net, frm, update("CHANNEL", {"name": "#global"}, "DEL"))
            await send(net, frm, update("BOT", {"handle": "sub1b"}, "DEL"))
            await send(net, frm, update("BOT", {"handle": LOCAL}, "DEL"))
        await send(net, "sub1", update("USER", {"handle": "u2"}, "DEL"))
        await send(net, "sub1", update("CHANNEL", {"name": "#two"}, "DEL"))
        await send(net, "sub1", update("BOT", {"handle": "b2"}, "DEL"))
        live = lambda t, k: q(net, f"SELECT {k} FROM {t} WHERE deleted_at IS NULL")
        assert {r["handle"] for r in await live("users", "handle")} == {"u1", "u2", "boss", "gl", "u1c"}
        assert {r["name"] for r in await live("channels", "name")} == {"#one", "#two", "#global"}
        assert {"b2", "sub1b"} <= {r["handle"] for r in await live("bots", "handle")}

        await send(net, "sub1", update("USER", {"handle": "u1"}, "DEL"))
        await send(net, "sub1", update("CHANNEL", {"name": "#one"}, "DEL"))
        await send(net, "sub1", update("BOT", {"handle": "b1"}, "DEL"))
        u1 = await q(net, "SELECT deleted_at, deleted_by FROM users WHERE handle='u1'")
        assert u1 and u1[0]["deleted_at"] and u1[0]["deleted_by"] == "sub1"     # soft
        assert (await q(net, "SELECT deleted_at FROM channels WHERE name='#one'"))[0]["deleted_at"]
        assert (await q(net, "SELECT deleted_at FROM bots WHERE handle='b1'"))[0]["deleted_at"]
        assert await q(net, "SELECT * FROM channel_subnets WHERE channel_name='#one'")

    run(main())


def test_stale_and_future_timestamps_rejected(tmp_path):
    async def main():
        net = await build(tmp_path)
        # stale delete loses to a newer local update
        await send(net, "sub1", update("USER", {"handle": "u1", "deleted_at": now() - 1000}, "DEL"))
        assert (await q(net, "SELECT deleted_at FROM users WHERE handle='u1'"))[0]["deleted_at"] is None
        await send(net, "sub1", update("CHANNEL", {"name": "#one", "deleted_at": now() - 1000}, "DEL"))
        assert (await q(net, "SELECT deleted_at FROM channels WHERE name='#one'"))[0]["deleted_at"] is None
        # future timestamps cannot pin a last-write-wins override
        far = now() + 10_000
        await send(net, "sub1", update("USERACCESS", {"handle": "u1", "channel": None,
                   "subnet_id": 1, "is_op": 0, "updated_at": far}))
        await send(net, "sub1", update("USER", {"handle": "u1", "comment": "future",
                                                "updated_at": far}, "ADD"))
        await send(net, "sub1", update("USER", {"handle": "u1", "deleted_at": far}, "DEL"))
        await send(net, "sub1", update("USER", {"handle": "u1", "updated_at": "soon"}, "ADD"))
        u1 = (await q(net, "SELECT comment, deleted_at FROM users WHERE handle='u1'"))[0]
        assert u1 == {"comment": "", "deleted_at": None}
        assert (await q(net, "SELECT is_op FROM user_access WHERE handle='u1'"))[0]["is_op"] == 1

    run(main())


# ---------------------------------------------------------------------------
# relay: validated before forwarding, re-scoped per destination
# ---------------------------------------------------------------------------
def test_denied_updates_are_not_relayed(tmp_path):
    async def main():
        net = await build(tmp_path)
        reset(net)
        bad = [
            update("USERACCESS", {"handle": "evil", "channel": None, "subnet_id": None,
                                  "is_admin": 1, "updated_at": now()}),
            update("USERACCESS", {"handle": "evil", "channel": None, "subnet_id": 2,
                                  "is_op": 1, "updated_at": now()}),
            update("USER", {"handle": "boss"}, "DEL"),
            update("USER", {"handle": "u2"}, "DEL"),
            update("CHANNEL", {"name": "#global"}, "DEL"),
            update("USER", {"handle": "u1", "updated_at": now() + 10_000}, "ADD"),
            f"UPDATE {rid()} USERACCESS {{not json",
            update("NOSUCH", {"x": 1}),
        ]
        for line in bad:
            await send(net, "sub1", line)
        for line in bad[:2]:
            await send(net, "none1", line.replace("UPDATE ", "UPDATE x", 1))
        assert {h: w.take() for h, w in net.w.items()} == {h: [] for h in net.w}

    run(main())


def test_allowed_updates_relay_sanitised_and_scoped_per_destination(tmp_path):
    async def main():
        net = await build(tmp_path)
        reset(net)
        mid = rid()
        await send(net, "sub1", update("USERACCESS", {"handle": "newu", "channel": None,
                   "subnet_id": 1, "is_op": 1, "is_admin": 0, "is_owner": 0,
                   "updated_at": now()}, msg_id=mid))
        got = {h: updates(w) for h, w in net.w.items()}
        # only other peers whose scope covers subnet 1; never back to the sender
        assert {h for h, u in got.items() if u} == {"sub1b", "all12"}
        for h in ("sub1b", "all12"):
            (m, ent, _, payload), = got[h]
            assert m == mid and ent == "USERACCESS"
            assert not (PRIV_KEYS & payload.keys()) and payload["subnet_id"] == 1

        # credential fields are stripped from relayed user records
        reset(net)
        await send(net, "sub1", update("USER", {"handle": "u1", "password": "$2b$12$" + "z" * 53,
                   "hostmasks": ["*!u1@x"], "updated_at": now() + 2}, "ADD"))
        got = {h: updates(w) for h, w in net.w.items()}
        assert {h for h, u in got.items() if u} == {"sub1b", "all12"}
        assert all("password" not in u[3] for u in got["sub1b"] + got["all12"])

        # cross-subnet peer's own-subnet update relays only to peers covering subnet 2
        reset(net)
        await send(net, "all2", update("USERACCESS", {"handle": "u2", "channel": None,
                   "subnet_id": 2, "is_voice": 1, "updated_at": now() + 2}))
        got = {h: updates(w) for h, w in net.w.items()}
        assert {h for h, u in got.items() if u} == {"all12"}
        assert (await q(net, "SELECT is_voice FROM user_access WHERE handle='u2'"))[0]["is_voice"] == 1

        # an authorized delete relays only within scope
        reset(net)
        await send(net, "sub1", update("USER", {"handle": "u1c"}, "DEL"))
        got = {h: updates(w) for h, w in net.w.items()}
        assert {h for h, u in got.items() if u} == {"sub1b", "all12"}
        assert all(u[2] == "DEL" for u in got["sub1b"])

        # a duplicate msg_id is neither re-applied nor re-relayed
        reset(net)
        await send(net, "sub1b", update("USERACCESS", {"handle": "newu", "channel": None,
                   "subnet_id": 1, "is_op": 0, "updated_at": now() + 3}, msg_id=mid))
        assert all(w.take() == [] for w in net.w.values())
        assert (await q(net, "SELECT is_op FROM user_access WHERE handle='newu'"))[0]["is_op"] == 1

    run(main())


def test_share_bulk_is_filtered_and_never_relayed(tmp_path):
    async def main():
        net = await build(tmp_path)
        reset(net)
        t = now() + 5
        rows = [
            {"handle": "okrow", "channel": None, "subnet_id": 1, "is_op": 1, "updated_at": t},
            {"handle": "adm", "channel": None, "subnet_id": None, "is_admin": 1, "updated_at": t},
            {"handle": "far", "channel": None, "subnet_id": 2, "is_op": 1, "updated_at": t},
        ]
        await send(net, "sub1", f"SHARE USERACCESS {json.dumps(rows)}")
        assert {r["handle"] for r in await q(
            net, "SELECT handle FROM users WHERE handle IN ('okrow','adm','far')")} == {"okrow"}
        assert all(w.take() == [] for w in net.w.values())

    run(main())


# ---------------------------------------------------------------------------
# defence in depth at the storage layer
# ---------------------------------------------------------------------------
def test_managers_never_store_peer_credentials_or_global_privileges(tmp_path):
    async def main():
        net = await build(tmp_path)
        b = net.beta
        await b.user.merge_access_from_peer(
            [{"handle": "z", "channel": None, "subnet_id": None, "is_admin": 1,
              "updated_at": now()}], "sub1")
        await b.user.merge_access_from_peer(
            [{"handle": "z", "channel": None, "subnet_id": 1, "is_admin": 1, "is_owner": 1,
              "is_op": 1, "updated_at": now()}], "sub1")
        z = await q(net, "SELECT subnet_id, is_admin, is_owner, is_op FROM user_access "
                         "WHERE handle='z'")
        assert z == [{"subnet_id": 1, "is_admin": 0, "is_owner": 0, "is_op": 1}]
        await b.user.merge_from_peer([{"handle": "u1", "password": "plain", "updated_at": now() + 5}],
                                     "sub1")
        assert (await q(net, "SELECT password FROM users WHERE handle='u1'"))[0]["password"] == FAKE_HASH
        await b.bot.merge_from_peer([{"handle": "b1", "share_level": "all", "updated_at": now() + 5}],
                                    "sub1")
        assert (await q(net, "SELECT share_level FROM bots WHERE handle='b1'"))[0]["share_level"] \
            == "subnet"

    run(main())
