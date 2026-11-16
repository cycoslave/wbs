"""
Regression tests for USR-3 (HIGH, security) and USR-4.

USR-3: `.handle alice` set the caller's session handle to `alice` BEFORE the
(failing) DB rename and without any existence check, so any +p user became
another user for the rest of the session.  A real rename always failed with
"FOREIGN KEY constraint failed" (user_access.handle -> users.handle).

USR-4: `.chhandle` never awaited UserManager.change_handle (nothing renamed)
and changed live session handles first.

Now: `.handle <new>` renames the caller's OWN account and is refused for any
existing handle; `.chhandle <old> <new>` (+A) renames another user.  Both
rename in the DB first, in one transaction covering users, user_access and
the *_by audit columns, and only then carry live sessions over.  Each DB is a
throwaway sqlite file.
"""
import asyncio

import pytest

from src.db import get_db
from src.net import NetListener
from src.partyline import COMMAND_MIN_FLAGS

from test_console_operator import FakeCore, build_db, console_sid, db_value, run_cmd

PW = "correct horse battery"


async def _setup(tmp_path):
    db = await build_db(tmp_path)          # subnet 1 'one'; plainp, bob (+p), carol (locked)
    async with get_db(db) as d:
        for handle, cols in (("alice", "has_partyline, is_admin"),
                             ("admin1", "has_partyline, is_admin")):
            await d.execute("INSERT INTO users(handle, password, hostmasks) "
                            "VALUES (?, '$2b$12$x', '[]')", (handle,))
            await d.execute(f"INSERT INTO user_access (handle, channel, subnet_id, {cols}) "
                            f"VALUES (?, NULL, 1, 1, 1)", (handle,))
        # bob also has a channel row and created a user (audit column)
        await d.execute("INSERT INTO user_access (handle, channel, subnet_id, is_op) "
                        "VALUES ('bob', '#wbs', 1, 1)")
        await d.execute("UPDATE users SET created_by = 'bob' WHERE handle = 'plainp'")
        # a soft-deleted user still owns its handle
        await d.execute("INSERT INTO users(handle, hostmasks, deleted_at) "
                        "VALUES ('ghost', '[]', 1)")
        await d.commit()
    return db


@pytest.fixture
def core(tmp_path):
    db = asyncio.run(_setup(tmp_path))
    c = FakeCore(db, tmp_path)
    asyncio.run(c.user.set_password("bob", PW))
    return c


def sid_of(core, handle):
    return core.partyline.register_remote("dcc", handle, asyncio.Queue())


async def handles(core):
    async with get_db(core.db_path) as d:
        rows = await d.execute_fetchall("SELECT handle FROM users ORDER BY handle")
    return [r[0] for r in rows]


async def access_handles(core):
    async with get_db(core.db_path) as d:
        rows = await d.execute_fetchall("SELECT DISTINCT handle FROM user_access ORDER BY handle")
    return [r[0] for r in rows]


async def as_session(core, sid, name, arg=""):
    """Run a command the way the partyline does: with the session's handle."""
    return await run_cmd(core, name, core.partyline.sessions[sid]["handle"], sid, arg)


def listener(core):
    return NetListener(asyncio.Queue(), {"settings": {"dev_mode": True},
                                         "botnet": {"subnet_id": 1}},
                       None, db_path=core.db_path)


# --- USR-3: no identity takeover --------------------------------------------

@pytest.mark.parametrize("target", ["alice", "ALICE", "admin1", "plainp", "ghost", "peerbot",
                                    "console", "Console"])
def test_handle_to_existing_name_is_refused_and_identity_kept(core, target):
    async def go():
        before_users, before_access = await handles(core), await access_handles(core)
        sid = sid_of(core, "bob")
        out = await as_session(core, sid, "handle", target)
        assert any("Handle not changed" in ln for ln in out), out
        assert not any("Your handle is now" in ln for ln in out), out
        # identity unchanged everywhere
        assert core.partyline.sessions[sid]["handle"] == "bob"
        assert await as_session(core, sid, "whoami") == ["You are bob@beta"]
        assert await handles(core) == before_users
        assert await access_handles(core) == before_access
        # and bob gained nothing: still no admin
        assert not await core.user.matchattr("bob", "+A", subnet_id=1)
    asyncio.run(go())


def test_handle_takeover_then_admin_command_is_impossible(core):
    """The report's exact chain: .handle alice, then a +A command."""
    async def go():
        sid = sid_of(core, "bob")
        await as_session(core, sid, "handle", "alice")
        sess = core.partyline.sessions[sid]
        assert sess["handle"] == "bob"
        # the partyline gate evaluates the session's handle
        await core.partyline.handle_input(sid, ".chattr bob +A")
        assert not await core.user.matchattr("bob", "+A", subnet_id=1)
        assert await db_value(core, "SELECT COUNT(*) FROM users WHERE handle = 'pwned'") == 0
    asyncio.run(go())


@pytest.mark.parametrize("bad", ["bad*name", "a" * 21, "ünï", "a b", "x!y@z", "a|b", ""])
def test_handle_invalid_refused(core, bad):
    async def go():
        before = await handles(core)
        sid = sid_of(core, "bob")
        out = await as_session(core, sid, "handle", bad)
        assert not any("Your handle is now" in ln for ln in out), out
        assert core.partyline.sessions[sid]["handle"] == "bob"
        assert await handles(core) == before
    asyncio.run(go())


# --- USR-3: a real own rename ------------------------------------------------

def test_handle_renames_own_account_everywhere(core):
    async def go():
        sid = sid_of(core, "bob")
        out = await as_session(core, sid, "handle", "robert")
        assert out == ["Your handle is now: robert"], out
        assert core.partyline.sessions[sid]["handle"] == "robert"
        assert await as_session(core, sid, "whoami") == ["You are robert@beta"]
        users = await handles(core)
        assert "robert" in users and "bob" not in users
        # every user_access row moved (no FK error, no orphans)
        assert await db_value(core, "SELECT COUNT(*) FROM user_access WHERE handle = 'bob'") == 0
        assert await db_value(core, "SELECT COUNT(*) FROM user_access WHERE handle = 'robert'") == 2
        assert await core.user.matchattr("robert", "+p", subnet_id=1)
        assert await core.user.matchattr("robert", "*|o", "#wbs", subnet_id=1)
        # audit columns follow
        assert await db_value(core, "SELECT created_by FROM users WHERE handle = 'plainp'") == "robert"
        async with get_db(core.db_path) as d:
            assert await d.execute_fetchall("PRAGMA foreign_key_check") == []
        # the renamed session keeps working through the gate (still active)
        await core.partyline.handle_input(sid, ".whoami")
        assert sid in core.partyline.sessions
    asyncio.run(go())


def test_login_as_new_handle_with_old_password(core):
    async def go():
        sid = sid_of(core, "bob")
        await as_session(core, sid, "handle", "robert")
        auth = listener(core).authenticate_partyline
        assert await auth("robert", PW) == "robert"
        assert await auth("bob", PW) is None
    asyncio.run(go())


def test_handle_case_only_change_of_self_allowed(core):
    async def go():
        sid = sid_of(core, "bob")
        out = await as_session(core, sid, "handle", "Bob")
        assert out == ["Your handle is now: Bob"], out
        assert "Bob" in await handles(core)
        assert await listener(core).authenticate_partyline("bob", PW) == "Bob"
    asyncio.run(go())


def test_handle_from_console_refused(core):
    async def go():
        before = await handles(core)
        out = await run_cmd(core, "handle", "console", console_sid(core), "robert")
        assert any(".chhandle" in ln for ln in out), out
        assert await handles(core) == before
    asyncio.run(go())


def test_rename_failure_rolls_back_everything(core):
    """A DB failure mid-transaction leaves users, access rows and sessions alone."""
    async def go():
        async with get_db(core.db_path) as d:
            await d.execute("CREATE TRIGGER boom BEFORE UPDATE OF handle ON user_access "
                            "BEGIN SELECT RAISE(ABORT, 'boom'); END")
            await d.commit()
        sid = sid_of(core, "bob")
        out = await as_session(core, sid, "handle", "robert")
        assert any("Handle not changed" in ln for ln in out), out
        assert core.partyline.sessions[sid]["handle"] == "bob"
        users = await handles(core)
        assert "bob" in users and "robert" not in users
        assert await db_value(core, "SELECT COUNT(*) FROM user_access WHERE handle = 'bob'") == 2
        assert await db_value(core, "SELECT created_by FROM users WHERE handle = 'plainp'") == "bob"
    asyncio.run(go())


# --- USR-4: .chhandle --------------------------------------------------------

def test_chhandle_console_renames_and_live_session_follows(core):
    async def go():
        bob_sid = sid_of(core, "bob")
        out = await run_cmd(core, "chhandle", "console", console_sid(core), "bob robert")
        assert out == ["User handle changed: bob → robert"], out
        assert core.partyline.sessions[bob_sid]["handle"] == "robert"
        info = "\n".join(await run_cmd(core, "userinfo", "console", console_sid(core), "robert"))
        assert "robert" in info and "not found" not in info, info
        gone = "\n".join(await run_cmd(core, "userinfo", "console", console_sid(core), "bob"))
        assert "not found" in gone, gone
        assert await listener(core).authenticate_partyline("robert", PW) == "robert"
    asyncio.run(go())


def test_chhandle_by_admin_session(core):
    async def go():
        bob_sid = sid_of(core, "bob")
        adm = sid_of(core, "admin1")
        out = await as_session(core, adm, "chhandle", "BOB robert")
        assert out == ["User handle changed: bob → robert"], out
        assert core.partyline.sessions[bob_sid]["handle"] == "robert"
        assert core.partyline.sessions[adm]["handle"] == "admin1"
        assert await db_value(core, "SELECT updated_by FROM users WHERE handle = 'robert'") == "admin1"
    asyncio.run(go())


def test_chhandle_refused_for_non_admin(core):
    async def go():
        assert COMMAND_MIN_FLAGS["chhandle"] == "A"
        before = await handles(core)
        sid = sid_of(core, "plainp")
        out = await as_session(core, sid, "chhandle", "bob robert")
        assert any("Access denied" in ln for ln in out), out
        assert await handles(core) == before
        # through the partyline gate as well
        await core.partyline.handle_input(sid, ".chhandle bob robert2")
        assert await handles(core) == before
    asyncio.run(go())


@pytest.mark.parametrize("arg, msg", [
    ("bob alice", "Handle not changed"),
    ("bob ALICE", "Handle not changed"),
    ("bob ghost", "Handle not changed"),
    ("bob peerbot", "Handle not changed"),
    ("bob bad*name", "Invalid handle"),
    ("nobody robert", "User not found"),
    ("ghost robert", "User not found"),
    ("bob", "Usage"),
])
def test_chhandle_refusals_change_nothing(core, arg, msg):
    async def go():
        before_users, before_access = await handles(core), await access_handles(core)
        bob_sid = sid_of(core, "bob")
        out = await run_cmd(core, "chhandle", "console", console_sid(core), arg)
        assert any(msg in ln for ln in out), out
        assert not any("User handle changed" in ln for ln in out), out
        assert core.partyline.sessions[bob_sid]["handle"] == "bob"
        assert await handles(core) == before_users
        assert await access_handles(core) == before_access
    asyncio.run(go())


def test_change_handle_is_a_coroutine_that_returns_status(core):
    """USR-4: the old call site dropped the coroutine; it must be awaited."""
    async def go():
        assert asyncio.iscoroutinefunction(core.user.change_handle)
        assert await core.user.change_handle("bob", "alice") is not None
        assert await core.user.change_handle("bob", "robert", changed_by="x") is None
    asyncio.run(go())
