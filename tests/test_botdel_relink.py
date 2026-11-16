"""
Regression tests for NET-6 and NET-4 (REPORT_NET.md).

NET-6: `.-bot <linked peer>` deleted the bots row but left the live link up,
       so a later `.+bot` + `.link` said "already linked".
NET-4: replication to a live link used state cached on the link when it came
       up, so a delete/re-add of the peer's row was never seen and a target
       that could not be resolved was skipped without any log line.

Two real BotnetManagers ("alpha" and "beta", both subnet 1, share=subnet)
are linked over the real AUTH2 handshake on in-memory fake writers; the
commands run through the real command handlers with a console session.
Each DB is a throwaway sqlite file under pytest's tmp_path.  No sockets, no IRC.
"""
import asyncio
import logging
import os
import shutil
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import patch

from src import botnet as botnet_mod
from src import commands
from src.botnet import BotnetManager
from src.db import get_db, init_db

PSK = "test-only-link-key-0123456789"
CONSOLE_SID = 1


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
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-net46-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


async def add_peer_row(db: str, handle: str, share: str = "subnet",
                       subnet_id: int | None = 1) -> None:
    async with get_db(db) as d:
        await d.execute(
            "INSERT INTO bots(handle, password, address, port, subnet_id, share_level) "
            "VALUES (?, ?, '192.0.2.1', 3333, ?, ?)", (handle, PSK, subnet_id, share))
        await d.commit()


async def make_bot(tmp_path, nick: str, peer: str):
    db = str(tmp_path / f"{nick}.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        await d.commit()
    await add_peer_row(db, peer)
    irc: list[dict] = []
    party: list[str] = []
    core = NS(
        db_path=db,
        config={"bot": {"nick": nick}, "botnet": {"subnet_id": 1}, "settings": {"ssl": False}},
        bot_sessions={},
        send_irc=irc.append,
        irc_sent=irc,
        irc_q=asyncio.Queue(),
        partyline=NS(broadcast=lambda m, *a, **k: party.append(m),
                     sessions={CONSOLE_SID: {"type": "console", "handle": "console"}}),
        party=party,
        botname=nick,
        bot_isop=lambda chan: True,
        channels={},
    )
    mgr = BotnetManager(core)
    core.botnet = mgr
    core.user, core.bot, core.chan = mgr.user, mgr.bot, mgr.chan
    mgr.broadcast_topology = _nop
    await mgr.subnet.load()
    return core


class Net:
    def __init__(self, a, b):
        self.a, self.b = a, b
        self.i_w: FakeWriter | None = None
        self.r_w: FakeWriter | None = None

    async def link(self):
        """alpha initiates, beta responds; returns the two writers."""
        ia, rb = self.a.botnet, self.b.botnet
        i_w = FakeWriter()

        async def fake_open(*args, **kwargs):
            return None, i_w

        with patch.object(botnet_mod.asyncio, "open_connection", fake_open), \
                patch.object(ia, "read_peer", _nop):
            await ia.connect_peer("beta")
        if not i_w.sent:
            return False
        r_w = FakeWriter()
        await rb.process_incoming("alpha", i_w.take()[0], None, r_w)
        await ia.process_incoming("beta", r_w.take()[0], None, i_w)
        await rb.process_incoming("alpha", i_w.take()[0], None, r_w)
        await ia.process_incoming("beta", r_w.take()[0], None, i_w)
        self.i_w, self.r_w = i_w, r_w
        await self.pump()
        return ia.peers.get("beta") is not None and rb.peers.get("alpha") is not None

    async def pump(self, rounds: int = 20) -> list[tuple[str, str]]:
        """Deliver queued lines both ways; returns [(receiver, line)]."""
        delivered = []
        for _ in range(rounds):
            await settle()
            moved = False
            for line in self.i_w.take():
                moved = True
                delivered.append(("beta", line))
                await self.b.botnet.process_incoming("alpha", line, None, self.r_w)
            for line in self.r_w.take():
                moved = True
                delivered.append(("alpha", line))
                await self.a.botnet.process_incoming("beta", line, None, self.i_w)
            if not moved:
                break
        return delivered


async def build(tmp_path) -> Net:
    alpha = await make_bot(tmp_path, "alpha", "beta")
    beta = await make_bot(tmp_path, "beta", "alpha")
    net = Net(alpha, beta)
    assert await net.link()
    return net


async def settle() -> None:
    """Wait for fire-and-forget tasks (_botnet_sync, share_all_data) to finish."""
    me = asyncio.current_task()
    for _ in range(5):
        rest = [t for t in asyncio.all_tasks() if t is not me and not t.done()]
        if not rest:
            return
        await asyncio.wait(rest, timeout=5)


async def run_cmd(core, name: str, arg: str) -> list[str]:
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    await commands.COMMANDS[name](core, "console", CONSOLE_SID, arg, respond)
    await settle()
    return out


async def bots_listing(core) -> tuple[list[str], list[str]]:
    out = await run_cmd(core, "bots", "")
    linked, unlinked, cur = [], [], None
    for line in out:
        if "Linked:" in line:
            cur = linked
        elif "Unlinked:" in line:
            cur = unlinked
        elif line.startswith("-> ") and cur is not None:
            cur.append(line[3:].split()[0])
    return linked, unlinked


async def q(core, sql: str, args=()):
    async with get_db(core.db_path) as d:
        return [dict(r) for r in await d.execute_fetchall(sql, args)]


def updates(delivered, receiver="beta"):
    return [line for who, line in delivered if who == receiver and line.startswith("UPDATE ")]


def run(coro):
    async def wrapped():
        try:
            return await coro
        finally:
            me = asyncio.current_task()
            rest = [t for t in asyncio.all_tasks() if t is not me]
            if rest:
                _, pending = await asyncio.wait(rest, timeout=2)
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
    return asyncio.run(wrapped())


# ---------------------------------------------------------------------------
# NET-6
# ---------------------------------------------------------------------------
def test_delbot_of_linked_peer_drops_the_live_link(tmp_path):
    async def main():
        net = await build(tmp_path)
        a, b = net.a, net.b
        a.botnet.topology["gamma"] = "beta"          # a bot reachable via beta
        assert "beta" in (await bots_listing(a))[0]

        out = await run_cmd(a, "-bot", "beta")
        assert any("Unlinked beta" in l for l in out), out
        assert any("Bot beta deleted!" in l for l in out), out

        # local side: link, session, routing and .bots state are gone
        assert "beta" not in a.botnet.peers
        assert a.botnet._live_link("beta") is None
        assert "beta" not in a.bot_sessions
        assert "gamma" not in a.botnet.topology
        assert net.i_w.closed
        assert {"cmd": "BOTLINK_UNLINK", "handle": "beta"} in a.irc_sent
        assert await q(a, "SELECT handle FROM bots WHERE handle='beta'") == []
        linked, unlinked = await bots_listing(a)
        assert "beta" not in linked and "beta" not in unlinked

        # the peer was told (BYE) and dropped its side too
        assert any(l.startswith("BYE ") for l in net.i_w.sent), net.i_w.sent
        await net.pump()
        assert "alpha" not in b.botnet.peers
        assert net.r_w.closed
        assert {"cmd": "BOTLINK_UNLINK", "handle": "alpha"} in b.irc_sent

    run(main())


def test_delbot_of_unlinked_bot_unchanged(tmp_path):
    async def main():
        net = await build(tmp_path)
        a = net.a
        await add_peer_row(a.db_path, "idle")
        out = await run_cmd(a, "-bot", "idle")
        assert out == ["→ Bot idle deleted!"], out
        assert "beta" in a.botnet.peers and not net.i_w.closed      # untouched
        out = await run_cmd(a, "-bot", "nosuch")
        assert out == ["→ Bot nosuch NOT deleted!"], out

    run(main())


def test_readd_and_relink_after_delbot(tmp_path):
    async def main():
        net = await build(tmp_path)
        a, b = net.a, net.b
        await run_cmd(a, "-bot", "beta")
        await net.pump()
        await add_peer_row(a.db_path, "beta")
        # a new link comes up instead of "already linked"
        assert await net.link()
        assert a.botnet._live_link("beta") is not None
        assert b.botnet._live_link("alpha") is not None
        assert "beta" in (await bots_listing(a))[0]

    run(main())


# ---------------------------------------------------------------------------
# NET-4
# ---------------------------------------------------------------------------
def test_user_and_chan_replicate_after_delete_readd_relink(tmp_path, caplog):
    async def main():
        net = await build(tmp_path)
        a, b = net.a, net.b
        await run_cmd(a, "-bot", "beta")
        await net.pump()
        await add_peer_row(a.db_path, "beta")
        assert await net.link()

        caplog.clear()
        with caplog.at_level(logging.INFO, logger=botnet_mod.log.name):
            out = await run_cmd(a, "+chan", "#wbs-s1 one")
            assert any("added" in l for l in out), out
            got = await net.pump()
            assert any(" CHANNEL ADD " in l and "#wbs-s1" in l for l in updates(got)), got
            assert await q(b, "SELECT name FROM channels WHERE name='#wbs-s1'")

            out = await run_cmd(a, "+user", "bob *!bob@example.org one")
            assert any("added" in l for l in out), out
            got = await net.pump()
            lines = updates(got)
            assert any(l.split()[2] == "USERACCESS" and '"bob"' in l for l in lines), lines
            assert any(" USER ADD " in l and '"bob"' in l for l in lines), lines
            assert await q(b, "SELECT handle FROM users WHERE handle='bob'")
        assert any("replication out: channels ADD to beta" in r.getMessage()
                   for r in caplog.records)
        assert any("replication out: users ADD to beta" in r.getMessage()
                   for r in caplog.records)

    run(main())


def test_replication_resolves_peer_row_freshly_not_cached(tmp_path):
    """Row recreated behind the link's back (no .botattr refresh) is honoured."""
    async def main():
        net = await build(tmp_path)
        a = net.a
        async with get_db(a.db_path) as d:
            await d.execute("DELETE FROM bots WHERE handle='beta'")
            await d.commit()
        await add_peer_row(a.db_path, "beta", share="none")
        await run_cmd(a, "+chan", "#fresh-1 one")
        assert updates(await net.pump()) == []          # new row says share=none

        async with get_db(a.db_path) as d:
            await d.execute("UPDATE bots SET share_level='subnet' WHERE handle='beta'")
            await d.commit()
        await run_cmd(a, "+chan", "#fresh-2 one")
        assert any("#fresh-2" in l for l in updates(await net.pump()))

    run(main())


def test_unresolved_share_target_logs_warning(tmp_path, caplog):
    async def main():
        net = await build(tmp_path)
        a = net.a
        # The bots row vanishes while the link stays up (raw SQL, no .-bot).
        async with get_db(a.db_path) as d:
            await d.execute("DELETE FROM bots WHERE handle='beta'")
            await d.commit()
        caplog.clear()
        with caplog.at_level(logging.INFO, logger=botnet_mod.log.name):
            await run_cmd(a, "+chan", "#lost-1 one")
            got = await net.pump()
        assert updates(got) == []                       # nothing sent to an unknown peer
        warns = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("share target beta unresolved" in m and "no bots row" in m
                   for m in warns), warns

        # A row without a subnet binding is also reported, not skipped silently.
        await add_peer_row(a.db_path, "beta", subnet_id=None)
        caplog.clear()
        with caplog.at_level(logging.INFO, logger=botnet_mod.log.name):
            await run_cmd(a, "+chan", "#lost-2 one")
            got = await net.pump()
        assert updates(got) == []
        warns = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("share target beta unresolved" in m and "no stored subnet scope" in m
                   for m in warns), warns

    run(main())


def test_bot_deletes_still_not_replicated(tmp_path, caplog):
    async def main():
        net = await build(tmp_path)
        a = net.a
        await add_peer_row(a.db_path, "idle")
        with caplog.at_level(logging.INFO, logger=botnet_mod.log.name):
            await run_cmd(a, "-bot", "idle")
            got = await net.pump()
        assert not any(" BOT DEL " in l for l in updates(got))
        assert any("bot deletes are not replicated" in r.getMessage() for r in caplog.records)

    run(main())
