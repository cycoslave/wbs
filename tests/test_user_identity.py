"""
Regression tests for USR-7 and USR-17.

USR-7: `.+user` accepted any handle/hostmask (`bad*name`, 40 chars, non-ASCII,
`notamask`); handles were case-sensitive for storage and lookups but
case-insensitive at login, so `ALICE` next to `alice` locked alice out.
USR-17: `.userinfo`/`.whois` printed soft-deleted users and their access rows,
and re-adding a deleted handle resurrected the old row (password hash, comment,
lock flag, access rows), so the old password worked again.

One definition (src/idrules.py) validates `.+user`, `.+host` and `--seed`.
Each DB is a throwaway sqlite file.
"""
import asyncio
import json
import logging

import pytest

from src.db import get_db, init_db, seed_db
from src.net import NetListener

from test_console_operator import FakeCore, build_db, console_sid, db_value, run_cmd

PW = "correct horse battery"


@pytest.fixture
def core(tmp_path):
    return FakeCore(asyncio.run(build_db(tmp_path)), tmp_path)


async def users(core):
    async with get_db(core.db_path) as d:
        rows = await d.execute_fetchall("SELECT handle FROM users ORDER BY handle")
    return [r[0] for r in rows]


async def add(core, arg):
    return await run_cmd(core, "+user", "console", console_sid(core), arg)


# --- USR-7: input validation --------------------------------------------------

BAD_HANDLES = ["bad*name", "a_very_long_handle_name_over_twenty", "x" * 21, "ünï", "a|b",
               "a\u00e9", "a.b", "a#b", "a@b", "a!b"]


@pytest.mark.parametrize("handle", BAD_HANDLES)
def test_adduser_rejects_bad_handle(core, handle):
    async def go():
        before = await users(core)
        out = await add(core, f"{handle} *!*@h.example")
        assert any("Invalid handle" in line for line in out), out
        assert await users(core) == before
        assert await db_value(core, "SELECT COUNT(*) FROM user_access WHERE handle = ?", handle) == 0
    asyncio.run(go())


@pytest.mark.parametrize("handle", ["a", "x" * 20, "Al_ice-1", "[a]\\`^{}", "UPPER"])
def test_adduser_accepts_good_handle(core, handle):
    async def go():
        out = await add(core, f"{handle} *!*@h.example")
        assert any("added" in line for line in out), out
        assert handle in await users(core)
    asyncio.run(go())


BAD_MASKS = ["notamask", "a!b", "a@b", "!@", "a!@h", "!u@h", "a!u@", "a!u@h@x", "a!b!c@h", "nick!u*@h@"]


@pytest.mark.parametrize("mask", BAD_MASKS)
def test_adduser_rejects_bad_hostmask(core, mask):
    async def go():
        out = await add(core, f"carol2 {mask}")
        assert any("Invalid hostmask" in line for line in out), out
        assert "carol2" not in await users(core)
    asyncio.run(go())


@pytest.mark.parametrize("mask", ["*!*@*", "nick!user@host.example", "*!*bob@*.example.com", "n?ck!u*@1.2.3.*"])
def test_adduser_accepts_wildcard_masks(core, mask):
    async def go():
        out = await add(core, f"dave {mask}")
        assert any("added" in line for line in out), out
        assert json.loads(await db_value(core, "SELECT hostmasks FROM users WHERE handle='dave'")) == [mask]
    asyncio.run(go())


def test_adduser_without_hostmask_still_works(core):
    async def go():
        out = await add(core, "dave")
        assert any("added" in line for line in out), out
    asyncio.run(go())


@pytest.mark.parametrize("mask", ["notamask", "a!b", "!@", "a!u@h@x"])
def test_addhost_uses_same_validation(core, mask):
    async def go():
        out = await run_cmd(core, "+host", "bob", None, mask)
        assert any("Invalid hostmask" in line for line in out), out
        assert json.loads(await db_value(core, "SELECT hostmasks FROM users WHERE handle='bob'")) == []
    asyncio.run(go())


def test_usermanager_layer_validates_too(core):
    """Callers other than the command (botnet, scripts) hit the same rules."""
    async def go():
        assert await core.user.adduser("bad*name") is False
        assert await core.user.adduser("okname", "notamask") is False
        assert await core.user.addhost("bob", "notamask") == "invalid"
        assert await core.user.adduser("okname", "*!*@h") is True
    asyncio.run(go())


def test_seed_validates_user_rows(tmp_path, caplog):
    db = str(tmp_path / "seed.db")
    config = {
        "bot": {"nick": "beta", "channels": []},
        "subnet": {"id": 1, "name": "one"},
        "users": [
            {"handle": "good", "password": PW, "hosts": ["*!*g@h.example", "notamask"],
             "access": [{"is_admin": True}]},
            {"handle": "bad*name", "password": PW, "hosts": ["*!*@h"]},
            {"handle": "ünï", "password": PW},
            {"handle": "L" * 21, "password": PW},
            {"handle": "Good", "password": PW},          # case-collides with `good`
        ],
    }

    async def go():
        await init_db(db)
        with caplog.at_level(logging.ERROR, logger="wbs.db"):
            await seed_db(db, config)
        async with get_db(db) as d:
            rows = await d.execute_fetchall("SELECT handle, hostmasks FROM users")
            access = await d.execute_fetchall("SELECT DISTINCT handle FROM user_access")
        assert [r[0] for r in rows] == ["good"]
        assert json.loads(rows[0][1]) == ["*!*g@h.example"]
        assert [r[0] for r in access] == ["good"]
    asyncio.run(go())
    text = caplog.text
    assert "bad*name" in text and "notamask" in text and "case-insensitive" in text


# --- USR-7: case-insensitive identity -------------------------------------------

def test_adduser_refused_when_handle_exists_in_other_case(core):
    async def go():
        out = await add(core, "BOB *!*@h.example")
        assert any("NOT added" in line for line in out), out
        out = await add(core, "bob *!*@h.example")
        assert any("NOT added" in line for line in out), out
        assert [h for h in await users(core) if h.lower() == "bob"] == ["bob"]
    asyncio.run(go())


def test_userinfo_and_whois_find_user_in_any_case(core):
    async def go():
        sid = console_sid(core)
        for cmd in ("userinfo", "whois"):
            out = await run_cmd(core, cmd, "console", sid, "BOB")
            assert any("User: bob" in line for line in out), (cmd, out)
    asyncio.run(go())


def test_case_collision_cannot_lock_out_login(core):
    """The report's case: `ALICE` (no password) next to `alice` made alice's login fail.

    New code never creates the pair; a database that already holds it (older
    versions) still logs each handle in as its own row.
    """
    async def go():
        await core.user.set_password("bob", PW)
        out = await add(core, "BoB *!*@h.example")
        assert any("NOT added" in line for line in out), out
        # legacy data: both spellings stored
        async with get_db(core.db_path) as d:
            await d.execute("INSERT INTO users(handle, password, hostmasks) VALUES ('BOB', NULL, '[]')")
            await d.commit()
        listener = NetListener(asyncio.Queue(), {"settings": {"dev_mode": True},
                                                 "botnet": {"subnet_id": 1}},
                               None, db_path=core.db_path)
        assert listener.users is not None
        canonical = await listener.users.resolve_handle("bob")
        assert canonical == "bob"                       # not the password-less BOB row
        assert await listener.users.authenticate(canonical, PW) is True
        assert await core.user.authenticate("bob", PW)
        assert await core.user.resolve_handle("BOB") == "BOB"
        assert not await core.user.authenticate("BOB", PW)   # BOB has no password of its own
    asyncio.run(go())


# --- USR-17: deleted users are not found; re-add is clean ------------------------

async def _delete_bob(core):
    sid = console_sid(core)
    out = await run_cmd(core, "-user", "console", sid, "bob")
    assert any("deleted" in line for line in out), out


def test_userinfo_whois_treat_deleted_as_not_found(core):
    async def go():
        sid = console_sid(core)
        await core.user.set_password("bob", PW)
        await _delete_bob(core)
        for cmd, arg in (("userinfo", "bob"), ("userinfo", "BOB"), ("whois", "bob")):
            out = await run_cmd(core, cmd, "console", sid, arg)
            text = "\n".join(out)
            assert "not found" in text.lower() or "no such user" in text.lower(), (cmd, out)
            assert "Access" not in text and "+p" not in text and "Password" not in text, out
    asyncio.run(go())


def test_readd_deleted_user_is_clean(core):
    """delete bob (+pA, has password), re-add bob: old password does NOT log in."""
    async def go():
        sid = console_sid(core)
        await core.user.set_password("bob", PW)
        await core.user.chattr("bob", "+A", subnet_id=1)
        await core.user.set_comment("bob", "old comment")
        await core.user.addhost("bob", "*!*old@old.example")
        await core.user.set_locked("bob", True)
        async with get_db(core.db_path) as d:
            await d.execute("INSERT INTO user_access (handle, channel, subnet_id, is_op) "
                            "VALUES ('bob', '#wbs', 1, 1)")
            await d.commit()
        await _delete_bob(core)
        assert not await core.user.authenticate("bob", PW)

        out = await add(core, "bob *!*new@new.example")
        assert any("added" in line for line in out), out

        assert not await core.user.authenticate("bob", PW)           # old password is gone
        row = await db_value(core, "SELECT password FROM users WHERE handle='bob'")
        assert row is None
        assert await db_value(core, "SELECT comment FROM users WHERE handle='bob'") == ""
        assert not await db_value(core, "SELECT is_locked FROM users WHERE handle='bob'")
        assert await db_value(core, "SELECT deleted_at FROM users WHERE handle='bob'") is None
        assert json.loads(await db_value(core, "SELECT hostmasks FROM users WHERE handle='bob'")) \
            == ["*!*new@new.example"]
        assert await db_value(core, "SELECT COUNT(*) FROM user_access WHERE handle='bob'") == 1

        out = await run_cmd(core, "userinfo", "console", sid, "bob")
        text = "\n".join(out)
        assert "Password: None" in text and "Locked: No" in text, text
        assert "Comment: None" in text, text
        assert "*!*new@new.example" in text and "old.example" not in text, text
        access = [line.strip() for line in text.splitlines() if "(subnet" in line]
        assert access == ["* (subnet 1): +p"], access               # fresh +p only: no A, no #wbs

        # and the new bob can be given a new password that works
        await core.user.set_password("bob", "another long pass")
        assert await core.user.authenticate("bob", "another long pass")
        assert not await core.user.authenticate("bob", PW)
    asyncio.run(go())


def test_readd_deleted_user_in_other_case_is_clean(core):
    async def go():
        await core.user.set_password("bob", PW)
        await _delete_bob(core)
        out = await add(core, "BOB")
        assert any("added" in line for line in out), out
        assert await users(core) == sorted(["BOB", "carol", "plainp"])
        assert not await core.user.authenticate("BOB", PW)
        assert not await core.user.authenticate("bob", PW)
    asyncio.run(go())


def test_deleted_user_cannot_be_managed_or_authenticated(core):
    async def go():
        await core.user.set_password("bob", PW)
        await _delete_bob(core)
        assert not await core.user.authenticate("bob", PW)
        assert not await core.user.exist("bob")
        assert await core.user.get("bob") is None
        assert await core.user.set_comment("bob", "x") == "not_found"
        assert await core.user.set_locked("bob", True) == "not_found"
        assert await core.user.chattr("bob", "+A", subnet_id=1) == "not_found"
        assert not await core.user.matchattr("bob", "+p", subnet_id=1)
    asyncio.run(go())
