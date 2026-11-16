"""
Offline regression tests for DCC-5: `.quit` leaves the partyline (closes THIS
session, eggdrop style) and never shuts the bot down; shutdown is `.die` (+A).

Reuses the fake network / partyline / DB of the DCC session-contract tests.
No sockets, no IRC, no bot process.
"""
import asyncio
from types import SimpleNamespace


from src import commands
from src.db import get_db
from src.partyline import COMMAND_MIN_FLAGS

from test_dcc_session_contract import (  # noqa: F401  (fixtures + helpers)
    ALICE, PW, assert_cleaned_once, db, db_template, make, privmsg, reader_with,
    rnet, run, open_socket_mode, until, settle,
)
from test_dcc_negotiation import chat_args


async def make_admin(db_path, handle="alice"):
    async with get_db(db_path) as d:
        await d.execute("UPDATE user_access SET is_admin = 1 WHERE handle = ?", (handle,))
        await d.commit()


def shutdown_requests(core):
    q = core.irc_q
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return [m for m in out if m.get("cmd") == "quit"]


async def open_dcc(core, mgr, rnet_):
    reader = reader_with(PW["alice"])
    w = await open_socket_mode("active", core, mgr, ALICE, reader)
    await until(lambda: mgr._sessions)
    sid = next(iter(mgr._sessions))
    return reader, w, sid


ACTIVE = dict(mode="active", public_ip="198.51.100.7")


def test_quit_closes_dcc_session_and_core_keeps_running(db, rnet):
    core, mgr = make(db, **ACTIVE)
    core.irc_q = asyncio.Queue()

    async def go():
        reader, w, sid = await open_dcc(core, mgr, rnet)
        reader.feed_data(b".quit\r\n")
        await until(lambda: not mgr._sessions)
        assert_cleaned_once(core, mgr, sid)
        assert w.closed
        assert b"Goodbye!" in w.data
        assert shutdown_requests(core) == []
        assert not [p for p in core.sent if p.get("cmd") == "quit"]
    run(rnet, go)


def test_quit_closes_irc_fallback_session_and_core_keeps_running(db, rnet):
    core, mgr = make(db, mode="irc")
    core.irc_q = asyncio.Queue()

    async def go():
        await mgr.handle_request(*ALICE, chat_args())
        assert await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}")) is True
        sid = next(iter(mgr._sessions))
        assert await mgr.on_privmsg(privmsg(ALICE, ".quit")) is True
        await until(lambda: not mgr._sessions)
        assert_cleaned_once(core, mgr, sid)
        assert any("Goodbye!" in n for n in core.notices(ALICE[0]))
        assert shutdown_requests(core) == []
    run(rnet, go)


def test_quit_closes_telnet_session():
    sent, closed = [], []

    class Party:
        running = True

        async def send(self, text):
            sent.append(text)

        async def close(self):
            closed.append(True)

    party = Party()
    core = SimpleNamespace(
        partyline=SimpleNamespace(sessions={7: {"type": "telnet", "handle": "alice"}}),
        party_sessions={7: party}, irc_q=asyncio.Queue())
    out = []

    async def respond(msg):
        out.append(msg)

    asyncio.run(commands.COMMANDS["quit"](core, "alice", 7, "", respond))
    assert sent == ["Goodbye!"] and closed == [True] and party.running is False
    assert core.irc_q.empty()


def test_console_quit_prints_hint_and_does_not_shut_down(db, rnet):
    core, mgr = make(db, **ACTIVE)
    core.irc_q = asyncio.Queue()
    lines = []

    async def go():
        csid = core.partyline.register_console("console", lines.append)
        await core.partyline.handle_input(csid, ".quit")
        assert any(".die" in l for l in lines), lines
        assert csid in core.partyline.sessions          # console stays registered
        assert shutdown_requests(core) == []
    run(rnet, go)


def test_die_by_non_admin_is_refused(db, rnet):
    core, mgr = make(db, **ACTIVE)
    core.irc_q = asyncio.Queue()

    async def go():
        reader, w, sid = await open_dcc(core, mgr, rnet)
        reader.feed_data(b".die bye\r\n")
        await until(lambda: b"Access denied for .die (need +A)." in w.data)
        await settle()
        assert shutdown_requests(core) == []
        assert list(mgr._sessions) == [sid] and not w.closed
    run(rnet, go)


def test_die_by_admin_triggers_shutdown(db, rnet):
    core, mgr = make(db, **ACTIVE)
    core.irc_q = asyncio.Queue()

    async def go():
        await make_admin(db)
        reader, w, sid = await open_dcc(core, mgr, rnet)
        reader.feed_data(b".die bye now\r\n")
        await until(lambda: not core.irc_q.empty())
        assert core.irc_q.get_nowait() == {"cmd": "quit", "message": "bye now"}
        assert b"Shutdown initiated" in w.data
    run(rnet, go)


def test_quit_needs_no_flag_and_die_needs_admin():
    assert COMMAND_MIN_FLAGS["quit"] is None
    assert COMMAND_MIN_FLAGS["die"] == "A"
    assert commands.COMMANDS["quit"] is not commands.COMMANDS["die"]


def test_help_describes_quit_as_leave_and_die_as_shutdown():
    out = []

    async def respond(msg):
        out.append(msg)

    for word in ("quit", "die"):
        asyncio.run(commands.cmd_help(SimpleNamespace(), "alice", 1, word, respond))
    text = "\n".join(out)
    assert "Leaves the partyline" in text and "shuts it down" in text
    assert "Alias for quit" not in text
