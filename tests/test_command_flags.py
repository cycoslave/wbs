"""
Regression tests for USR-6 / IRC-4 / NET-10: every registered command must be
reachable over telnet/DCC with a flag.

partyline._handle_command refuses any command that has no COMMAND_MIN_FLAGS
entry ("Unknown command"), so a command missing from the table is dead for
every remote session, admins included.  The drift test fails as soon as a key
of commands.COMMANDS has no entry; the session tests drive the real gate with
a +A and a plain +p user; the help tests check `.help` lists only what the
caller may run.  Throwaway sqlite DB, no sockets, no IRC.
"""
import asyncio

import pytest

from src import commands
from src.partyline import COMMAND_MIN_FLAGS

from test_console_operator import FakeCore, build_db, console_sid  # noqa: F401


# --- drift guard -----------------------------------------------------------

def test_every_registered_command_has_a_min_flag_entry():
    missing = sorted(set(commands.COMMANDS) - set(COMMAND_MIN_FLAGS))
    assert not missing, (
        f"commands registered in COMMANDS but absent from "
        f"partyline.COMMAND_MIN_FLAGS (blocked as 'Unknown command'): {missing}")


def test_min_flags_has_no_stale_entries():
    stale = sorted(set(COMMAND_MIN_FLAGS) - set(commands.COMMANDS))
    assert not stale, f"COMMAND_MIN_FLAGS entries without a command: {stale}"


def test_min_flag_values_are_known_flags_or_none():
    for cmd, flag in COMMAND_MIN_FLAGS.items():
        assert flag is None or (isinstance(flag, str) and len(flag) == 1
                                and flag in commands.GLOBAL_FLAGS), (cmd, flag)


# --- real partyline gate ---------------------------------------------------

@pytest.fixture
def core(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    c = FakeCore(db, tmp_path)
    c.connected = True
    c._last_lag_ms = 12.5

    async def admin():
        from src.db import get_db
        async with get_db(db) as d:
            await d.execute("UPDATE user_access SET is_admin = 1 WHERE handle = 'bob'")
            await d.commit()
    asyncio.run(admin())
    return c


def session(core, handle):
    q = asyncio.Queue()
    return core.partyline.register_remote("dcc", handle, q), q


async def say(core, sid, q, text):
    await core.partyline._handle_command(sid, core.partyline.sessions[sid]["handle"], text)
    out = []
    while not q.empty():
        out.append(q.get_nowait()["text"])
    return out


def blocked(out):
    return any("Unknown command" in line for line in out)


def denied(out):
    return any("Access denied" in line and "need" in line for line in out)


ADMIN_CASES = [
    ("say", "#chan hello"), ("msg", "#chan hello"), ("act", "#chan waves"),
    ("lag", ""), ("sdns", "127.0.0.1"), ("botinfo", ""), ("rehash", ""),
]


@pytest.mark.parametrize("cmd,arg", ADMIN_CASES, ids=[c[0] for c in ADMIN_CASES])
def test_admin_session_can_run_command(core, cmd, arg):
    async def go():
        sid, q = session(core, "bob")      # bob has +A (+p)
        out = await say(core, sid, q, f".{cmd} {arg}".strip())
        assert not blocked(out) and not denied(out), out
        assert out, "command produced no output"
    asyncio.run(go())


def test_admin_say_reaches_irc_queue_and_rehash_runs(core):
    async def go():
        sid, q = session(core, "bob")
        await say(core, sid, q, ".say #chan hello there")
        assert core.irc_q.get_nowait() == {"cmd": "msg", "target": "#chan", "text": "hello there"}
        await say(core, sid, q, ".rehash")
        assert core.do_rehash.await_count == 1
    asyncio.run(go())


@pytest.mark.parametrize("cmd", sorted(c for c, f in COMMAND_MIN_FLAGS.items() if f))
def test_plain_p_user_gets_access_denied_not_unknown(core, cmd):
    """Every flagged command: +p only -> `Access denied (need +X)`, never
    `Unknown command`, and the command itself is not run."""
    if COMMAND_MIN_FLAGS[cmd] == "p":
        pytest.skip("+p is the baseline")

    async def go():
        sid, q = session(core, "plainp")
        out = await say(core, sid, q, f".{cmd} x")
        assert denied(out), out
        assert not blocked(out), out
        assert core.irc_q.empty()
    asyncio.run(go())


# --- .help lists only what the caller may run ------------------------------

async def help_names(core, handle, sid):
    out = []

    async def respond(m):
        out.append(m)

    await commands.cmd_help(core, handle, sid, "", respond)
    # `.help` shows an aliased command once as `+user (adduser)` (USR-2): both
    # names count as listed.
    names = {w for line in out if line.startswith("      ")
             for w in line.replace("(", " ").replace(")", " ").split()}
    return out, names


def test_help_for_plain_p_user_lists_only_runnable_commands(core):
    async def go():
        sid, _ = session(core, "plainp")
        out, names = await help_names(core, "plainp", sid)
        assert names, out
        allowed = {c for c, f in COMMAND_MIN_FLAGS.items() if f in (None, "p")}
        assert names <= allowed, sorted(names - allowed)
        assert {"help", "whoami", "who", "quit", "lag"} <= names
        for admin_only in ("die", "rehash", "say", "+user", "backup", "botinfo"):
            assert admin_only not in names
        assert not any(line.strip().endswith(":") and "admins" in line for line in out), out
    asyncio.run(go())


def test_help_for_admin_lists_every_registered_command(core):
    async def go():
        sid, _ = session(core, "bob")
        _, names = await help_names(core, "bob", sid)
        missing = set(commands.COMMANDS) - names
        assert not missing, sorted(missing)
        assert names <= set(COMMAND_MIN_FLAGS)
    asyncio.run(go())


def test_help_for_console_lists_everything(core):
    async def go():
        sid = console_sid(core)
        _, names = await help_names(core, "console", sid)
        assert set(commands.COMMANDS) <= names
    asyncio.run(go())


def test_help_only_lists_registered_commands_with_entries():
    """The static overview never advertises a command the gate would refuse."""
    src = open(commands.__file__, encoding="utf-8").read()
    block = src.split('help_text = """\\', 1)[1].split('"""', 1)[0]
    listed = {w for line in block.split("\n") if line.startswith("      ")
              for w in line.split()}
    assert listed <= set(COMMAND_MIN_FLAGS), sorted(listed - set(COMMAND_MIN_FLAGS))
    assert listed <= set(commands.COMMANDS), sorted(listed - set(commands.COMMANDS))
