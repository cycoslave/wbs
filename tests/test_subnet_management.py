"""
Regression tests for NET-1, NET-2 and NET-7: subnet management and peer binding.

NET-2  `.subnet list` / `.subnet set` crashed on non-existent hub_host/hub_port
       columns; list must print `[id] name`.
NET-1  `.subnet add <name> [id]` / `.subnet del <name|id>` (+A, validated,
       refused while referenced) so a remote bot's subnet can be created
       without raw SQL, then bound with `.botattr <peer> subnet=<id|name>`.
NET-7  The initiator's hello carries its real subnet id (was hard-coded '1');
       after auth each side announces `SUBNET <id> [name]`.  The announcement
       is recorded as a proposal and only applied when it matches a stored
       binding; a peer without a stored binding stays denied (SAST-002).

Throwaway sqlite DBs under pytest's tmp_path; no network, no IRC.
"""
import asyncio
from types import SimpleNamespace as NS

from src import commands
from src.db import get_db
from tests.test_subnet_authz import FakeWriter, PSK, link, make_mgr, _fresh_db


def run(coro):
    return asyncio.run(coro)


class Out(list):
    async def __call__(self, msg):
        self.append(msg)


CONSOLE, USER = 1, 2


def cmd_core(db: str, local_subnet: int = 1, admin: bool = False, botnet=None):
    """Minimal core for console commands: session 1 = console, 2 = a plain user."""
    async def matchattr(handle, flag, channel=None, subnet_id=None):
        return admin

    core = NS(
        db_path=db,
        config={"bot": {"nick": "beta"}, "botnet": {"subnet_id": local_subnet}},
        partyline=NS(sessions={CONSOLE: {"type": "console"}, USER: {"type": "telnet"}}),
        user=NS(matchattr=matchattr),
    )
    if botnet is not None:
        core.botnet = botnet
    return core


async def fresh(tmp_path, name="beta.db", rows=("(1, 'one')",)) -> str:
    db = str(tmp_path / name)
    await _fresh_db(db)
    async with get_db(db) as d:
        for r in rows:
            await d.execute(f"INSERT INTO subnets(id, name) VALUES {r}")
    return db


# ---------------------------------------------------------------------------
# NET-2: list / set no longer crash
# ---------------------------------------------------------------------------
def test_subnet_list_prints_id_and_name(tmp_path):
    async def main():
        db = await fresh(tmp_path, rows=("(1, 'sub1')", "(2, 'sub2')"))
        out = Out()
        await commands.cmd_subnet(cmd_core(db), "op", CONSOLE, "list", out)
        assert out[0].strip().startswith("[1] sub1")
        assert "this bot" in out[0]
        assert out[1].strip() == "[2] sub2"
        assert len(out) == 2
    run(main())


def test_subnet_set_renames_and_rejects_unknown_keys(tmp_path):
    async def main():
        db = await fresh(tmp_path, rows=("(1, 'sub1')", "(2, 'sub2')"))
        core, out = cmd_core(db), Out()
        await commands.cmd_subnet(core, "op", CONSOLE, "set sub2 hub_host 1.2.3.4", out)
        assert out[-1] == "Allowed keys: name"
        await commands.cmd_subnet(core, "op", CONSOLE, "set sub2 name remote", out)
        assert out[-1] == "Subnet [2] renamed: sub2 -> remote"
        await commands.cmd_subnet(core, "op", CONSOLE, "set 2 name SUB1", out)
        assert out[-1].startswith("Subnet name already in use: [1] sub1")
        await commands.cmd_subnet(core, "op", CONSOLE, "set nosuch name x", out)
        assert out[-1] == "Unknown subnet: 'nosuch'"
        out.clear()
        await commands.cmd_subnet(core, "op", CONSOLE, "list", out)
        assert out[1].strip() == "[2] remote"
    run(main())


def test_help_no_longer_advertises_hub_columns():
    import inspect
    src = inspect.getsource(commands)
    assert "hub_host" not in src and "hub_port" not in src


# ---------------------------------------------------------------------------
# NET-1: add / del round trip, validation, references, +A
# ---------------------------------------------------------------------------
def test_subnet_add_del_round_trip(tmp_path):
    async def main():
        db = await fresh(tmp_path)
        core, out = cmd_core(db), Out()
        await commands.cmd_subnet(core, "op", CONSOLE, "add sub2 2", out)
        assert out[-1] == "Subnet added: [2] sub2"
        await commands.cmd_subnet(core, "op", CONSOLE, "add extra", out)
        assert out[-1] == "Subnet added: [3] extra"
        out.clear()
        await commands.cmd_subnet(core, "op", CONSOLE, "list", out)
        assert [l.strip().split("  ")[0] for l in out] == ["[1] one", "[2] sub2", "[3] extra"]

        await commands.cmd_subnet(core, "op", CONSOLE, "del sub2", out)
        assert out[-1] == "Subnet deleted: [2] sub2"
        await commands.cmd_subnet(core, "op", CONSOLE, "del 3", out)
        assert out[-1] == "Subnet deleted: [3] extra"
        out.clear()
        await commands.cmd_subnet(core, "op", CONSOLE, "list", out)
        assert [l.strip().split("  ")[0] for l in out] == ["[1] one"]
    run(main())


def test_subnet_add_validation(tmp_path):
    async def main():
        db = await fresh(tmp_path)
        core, out = cmd_core(db), Out()
        for bad in ("add 2", "add 9abc", "add bad/name", "add " + "a" * 33, "add ok 0",
                    "add ok -1", "add ok x", "add ok 1234567890", "add", "add a b c"):
            await commands.cmd_subnet(core, "op", CONSOLE, bad, out)
            assert not out[-1].startswith("Subnet added"), (bad, out[-1])
        await commands.cmd_subnet(core, "op", CONSOLE, "add ONE", out)
        assert out[-1].startswith("Subnet name already in use: [1] one")
        await commands.cmd_subnet(core, "op", CONSOLE, "add other 1", out)
        assert out[-1].startswith("Subnet id 1 already in use")
        async with get_db(db) as d:
            rows = await d.execute_fetchall("SELECT id FROM subnets")
        assert [r["id"] for r in rows] == [1]
    run(main())


def test_subnet_del_refused_while_referenced_or_local(tmp_path):
    async def main():
        db = await fresh(tmp_path, rows=("(1, 'one')", "(2, 'two')", "(3, 'three')"))
        async with get_db(db) as d:
            await d.execute("INSERT INTO bots(handle, address, port, subnet_id) "
                            "VALUES ('peer', '192.0.2.1', 3333, 2)")
            await d.execute("INSERT INTO channels(name) VALUES ('#c')")
            await d.execute("INSERT INTO channel_subnets(channel_name, subnet_id) VALUES ('#c', 3)")
        core, out = cmd_core(db), Out()
        await commands.cmd_subnet(core, "op", CONSOLE, "del one", out)
        assert out[-1] == "Subnet [1] one NOT deleted: it is this bot's own subnet."
        await commands.cmd_subnet(core, "op", CONSOLE, "del two", out)
        assert out[-1] == "Subnet [2] two NOT deleted: still in use (bots: peer)."
        await commands.cmd_subnet(core, "op", CONSOLE, "del 3", out)
        assert out[-1] == "Subnet [3] three NOT deleted: still in use (channels: #c)."
        await commands.cmd_subnet(core, "op", CONSOLE, "del nosuch", out)
        assert out[-1] == "Unknown subnet: 'nosuch'"
        async with get_db(db) as d:
            rows = await d.execute_fetchall("SELECT id FROM subnets ORDER BY id")
            bot = await (await d.execute("SELECT subnet_id FROM bots")).fetchone()
        assert [r["id"] for r in rows] == [1, 2, 3] and bot["subnet_id"] == 2
    run(main())


def test_subnet_changes_need_admin(tmp_path):
    async def main():
        db = await fresh(tmp_path)
        out = Out()
        plain = cmd_core(db, admin=False)
        for line in ("add sub2 2", "del one", "set one name x"):
            await commands.cmd_subnet(plain, "bob", USER, line, out)
            assert out[-1] == "Access denied (need +A).", line
        await commands.cmd_subnet(plain, "bob", USER, "list", out)
        assert out[-1].strip().startswith("[1] one")
        await commands.cmd_subnet(cmd_core(db, admin=True), "adm", USER, "add sub2 2", out)
        assert out[-1] == "Subnet added: [2] sub2"
    run(main())


# ---------------------------------------------------------------------------
# NET-1: .botattr subnet= with a subnet created by .subnet add
# ---------------------------------------------------------------------------
def test_botattr_subnet_accepts_created_subnet(tmp_path):
    async def main():
        beta = await make_mgr(tmp_path, "beta", 1, {"nwb1": None})
        async with get_db(beta.db_path) as d:   # make_mgr seeds 1 and 2; start from 1 only
            await d.execute("DELETE FROM subnets WHERE id = 2")
        beta.sync_bot_access = lambda data: asyncio.sleep(0)
        core = beta.core
        core.partyline = NS(sessions={CONSOLE: {"type": "console"}},
                            broadcast=lambda *a, **k: None)
        out = Out()
        await commands.cmd_botattr(core, "op", CONSOLE, "nwb1 subnet=2", out)
        assert out[-1].startswith("Unknown subnet: '2' (create it first: .subnet add <name> 2")
        await commands.cmd_subnet(core, "op", CONSOLE, "add sub2 2", out)
        assert out[-1] == "Subnet added: [2] sub2"
        await commands.cmd_botattr(core, "op", CONSOLE, "nwb1 subnet=sub2", out)
        assert out[-1] == "botattr nwb1: subnet_id=2"
        assert await beta.bot.get_subnet_scope("nwb1") == frozenset({2})
        # the live SubnetManager knows the new subnet without a reload
        assert (await beta.subnet.get(2)).name == "sub2"
        # still in use now: delete refused
        await commands.cmd_subnet(core, "op", CONSOLE, "del sub2", out)
        assert "NOT deleted: still in use (bots: nwb1)" in out[-1]
    run(main())


# ---------------------------------------------------------------------------
# NET-7: hello carries the real subnet; announcements are proposals only
# ---------------------------------------------------------------------------
def _announce(writer: FakeWriter) -> list[str]:
    return [l for l in writer.sent if l.startswith("SUBNET ")]


def test_hello_carries_real_local_subnet(tmp_path):
    async def main():
        beta = await make_mgr(tmp_path, "beta", 2, {"alpha": 2})
        alpha = await make_mgr(tmp_path, "alpha", 2, {"beta": 2})
        i_w, r_w = await link(alpha, beta)          # alpha (subnet 2) initiates
        assert beta.peers["alpha"].subnet_field == "2"
        assert alpha.peers["beta"].subnet_field == "2"
        # the initiator announces id + name after auth (link() consumed the
        # responder's LINKREADY batch, which carried the responder's own)
        assert _announce(i_w) == ["SUBNET 2 two"]
        await beta._announce_subnet(beta.peers["alpha"])
        assert _announce(r_w) == ["SUBNET 2 two"]
    run(main())


def test_hello_token_from_connect_peer(tmp_path):
    from unittest.mock import patch
    from src import botnet as botnet_mod

    async def main():
        mgr = await make_mgr(tmp_path, "alpha", 7, {"beta": 1})
        w = FakeWriter()

        async def fake_open(*a, **k):
            return None, w

        async def nop(*a, **k):
            return None

        with patch.object(botnet_mod.asyncio, "open_connection", fake_open), \
                patch.object(mgr, "read_peer", nop):
            await mgr.connect_peer("beta")
        hello = w.sent[0].split()
        assert hello[:4] == ["BOTLINK", "alpha", "beta", "7"]
    run(main())


async def _deliver_announcements(a, b, a_w, b_w):
    """Feed the post-auth SUBNET lines: a_w carries a->b, b_w carries b->a."""
    an, bn = a.my_handle, b.my_handle
    for line in a_w.take():
        await b.process_incoming(an, line, None, b_w)
    for line in b_w.take():
        await a.process_incoming(bn, line, None, a_w)


def test_new_link_without_binding_records_proposal_and_stays_denied(tmp_path):
    async def main():
        # beta (subnet 1) has no stored subnet for alpha; alpha claims subnet 1
        beta = await make_mgr(tmp_path, "beta", 1, {"alpha": None})
        alpha = await make_mgr(tmp_path, "alpha", 1, {"beta": 1})
        i_w, r_w = await link(alpha, beta)
        await _deliver_announcements(alpha, beta, i_w, r_w)
        peer = beta.peers["alpha"]
        assert peer.proposed_subnet == (1, "one")
        # SAST-002 denial default unchanged: the claim is not scope
        assert peer.subnet_ids == frozenset() and peer.subnet_id is None
        assert not beta.same_subnet_peer("alpha")
        assert not await beta.authorize_peer_command("alpha", "op", ["victim", "#chan"])
        beta.sent_irc.clear()                       # drop the BOTLINK_LINK notice
        await beta.process_incoming("alpha", "CMD op victim #chan", None, r_w)
        assert beta.sent_irc == []
        assert beta.subnet.subnet_of_peer("alpha") is None

        # the operator sees the proposal and can accept it explicitly
        core = beta.core
        core.partyline = NS(sessions={CONSOLE: {"type": "console"}},
                            broadcast=lambda *a, **k: None)
        beta.sync_bot_access = lambda data: asyncio.sleep(0)
        out = Out()
        await commands.cmd_botattr(core, "op", CONSOLE, "alpha", out)
        assert "subnet=unset proposed=1(one)" in out[-1]
        await commands.cmd_botattr(core, "op", CONSOLE, "alpha subnet=proposed", out)
        assert out[-1] == "botattr alpha: subnet_id=1"
        assert peer.subnet_ids == frozenset({1}) and beta.same_subnet_peer("alpha")
        await beta.process_incoming("alpha", "CMD op victim #chan", None, r_w)
        assert beta.sent_irc == [{"cmd": "mode", "channel": "#chan", "modes": "+o victim"}]
    run(main())


def test_announcement_never_widens_a_stored_scope(tmp_path):
    async def main():
        # gamma is stored as subnet 2 on beta but claims beta's subnet 1
        beta = await make_mgr(tmp_path, "beta", 1, {"gamma": 2})
        gamma = await make_mgr(tmp_path, "gamma", 2, {"beta": 1})
        i_w, r_w = await link(gamma, beta)
        await _deliver_announcements(gamma, beta, i_w, r_w)
        r_w.take()
        await beta.process_incoming("gamma", "SUBNET 1 one", None, r_w)
        peer = beta.peers["gamma"]
        assert peer.proposed_subnet == (1, "one")
        assert peer.subnet_ids == frozenset({2}) and peer.subnet_id == 2
        assert not beta.same_subnet_peer("gamma")
        beta.sent_irc.clear()                       # drop the BOTLINK_LINK notice
        await beta.process_incoming("gamma", "CMD op victim #chan", None, r_w)
        assert beta.sent_irc == []
        # malformed announcements are ignored, the stored scope stays
        for bad in ("SUBNET", "SUBNET x", "SUBNET 0", "SUBNET 1 a b", "SUBNET 1234567890"):
            await beta.process_incoming("gamma", bad, None, r_w)
            assert peer.subnet_ids == frozenset({2})
    run(main())


def test_announcement_selects_primary_subnet_inside_stored_scope(tmp_path):
    async def main():
        # peer bound to {2, 3} (bots.subnet_id 2 + bot_subnets 3); it announces 3
        beta = await make_mgr(tmp_path, "beta", 1, {"multi": 2})
        async with get_db(beta.db_path) as d:
            await d.execute("INSERT INTO subnets(id, name) VALUES (3, 'three')")
        await beta.subnet.load()
        await beta.bot.bind_to_subnet("multi", 3)
        multi = await make_mgr(tmp_path, "multi", 3, {"beta": 1})
        async with get_db(multi.db_path) as d:
            await d.execute("INSERT INTO subnets(id, name) VALUES (3, 'three')")
        await multi.subnet.load()
        i_w, r_w = await link(multi, beta)
        assert beta.peers["multi"].proposed_subnet is None   # hello token is no proposal
        assert beta.peers["multi"].subnet_id == 2            # min of the stored {2, 3}
        await _deliver_announcements(multi, beta, i_w, r_w)
        peer = beta.peers["multi"]
        assert peer.proposed_subnet == (3, "three")
        assert peer.subnet_ids == frozenset({2, 3}) and peer.subnet_id == 3
        assert beta.subnet.subnet_of_peer("multi") == 3
        assert not beta.same_subnet_peer("multi")        # still not subnet 1
    run(main())


def test_proposed_requires_a_live_announcement(tmp_path):
    async def main():
        db = await fresh(tmp_path)
        async with get_db(db) as d:
            await d.execute("INSERT INTO bots(handle, password, address, port) "
                            "VALUES ('offline', ?, '192.0.2.1', 3333)", (PSK,))
        core, out = cmd_core(db, botnet=NS(peers={})), Out()
        await commands.cmd_botattr(core, "op", CONSOLE, "offline subnet=proposed", out)
        assert out[-1] == "offline has not announced a subnet (it must be linked first)."
    run(main())
