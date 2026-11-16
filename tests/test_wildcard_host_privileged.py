"""
mythos F-01b: a user holding +n or +A never carries a hostmask whose host part
is only wildcards.  Enforced on `.+host`, on the +n/+A grant (`.chattr`) and on
botnet share import (UserManager.merge_from_peer).  Plain users are unaffected.
"""
import asyncio
import json
import logging

import pytest

from src.idrules import valid_hostmask, wildcard_only_host

from test_console_operator import FakeCore, build_db, console_sid, db_value, run_cmd

WILD_ONLY = ["*!*@*", "*!*@*.*", "n!u@?", "a!b@**", "a!b@*.?.*", "*!*bob@*"]
SPECIFIC = ["*!*@host.example", "n!u@*.example.com", "*!*@1.2.3.*", "*!*@*x", "*!*@a?"]


@pytest.fixture
def core(tmp_path):
    return FakeCore(asyncio.run(build_db(tmp_path)), tmp_path)


async def masks(core, handle):
    return json.loads(await db_value(core, "SELECT hostmasks FROM users WHERE handle = ?", handle))


async def grant(core, handle, col):
    await core.user.set_access_columns(handle, {col}, set(), subnet_id=1)


@pytest.mark.parametrize("mask", WILD_ONLY)
def test_helper_true_for_wildcard_only_hosts(mask):
    assert valid_hostmask(mask)
    assert wildcard_only_host(mask)


@pytest.mark.parametrize("mask", SPECIFIC + ["nohost", "a!b@", "", None, 5])
def test_helper_false_otherwise(mask):
    assert not wildcard_only_host(mask)


# --- +host ---------------------------------------------------------------------

@pytest.mark.parametrize("col", ["is_owner", "is_admin"])
@pytest.mark.parametrize("mask", WILD_ONLY)
def test_addhost_refused_for_privileged_user(core, col, mask):
    async def go():
        await grant(core, "bob", col)
        assert await core.user.addhost("bob", mask) == "wildcard_host"
        out = await run_cmd(core, "+host", "bob", None, mask)
        assert any("only wildcards" in line for line in out), out
        assert await masks(core, "bob") == []
    asyncio.run(go())


@pytest.mark.parametrize("col", ["is_owner", "is_admin"])
def test_addhost_specific_mask_still_ok_for_privileged_user(core, col):
    async def go():
        await grant(core, "bob", col)
        for mask in SPECIFIC:
            assert await core.user.addhost("bob", mask) == "ok"
        assert await masks(core, "bob") == SPECIFIC
    asyncio.run(go())


@pytest.mark.parametrize("mask", WILD_ONLY)
def test_plain_user_can_still_add_wildcard_masks(core, mask):
    async def go():
        assert await core.user.addhost("bob", mask) == "ok"
        assert await masks(core, "bob") == [mask]
        await grant(core, "carol", "is_friend")     # non-privileged flag
        assert await core.user.addhost("carol", mask) == "ok"
    asyncio.run(go())


def test_addhost_refused_when_privilege_is_on_a_channel_or_other_scope_row(core):
    async def go():
        await core.user.set_access_columns("bob", {"is_admin"}, set(), subnet_id=None)
        assert await core.user.addhost("bob", "*!*@*") == "wildcard_host"
    asyncio.run(go())


# --- +user (new users carry no flags yet) ------------------------------------------

def test_adduser_with_wildcard_mask_still_works_but_cannot_be_promoted(core):
    async def go():
        sid = console_sid(core)
        out = await run_cmd(core, "+user", "console", sid, "dave *!*@*")
        assert any("added" in line for line in out), out
        out = await run_cmd(core, "chattr", "console", sid, "dave +A")
        assert any("only wildcards" in line for line in out), out
        assert not await core.user.matchattr("dave", "+A", subnet_id=1)
    asyncio.run(go())


# --- chattr / grant ---------------------------------------------------------------

@pytest.mark.parametrize("flag,col", [("+n", "is_owner"), ("+A", "is_admin"), ("+nA", "is_owner")])
def test_grant_refused_when_user_has_wildcard_only_mask(core, flag, col):
    async def go():
        assert await core.user.addhost("bob", "*!*@*") == "ok"
        assert await core.user.chattr("bob", flag, subnet_id=1) == "wildcard_host"
        out = await run_cmd(core, "chattr", "console", console_sid(core), f"bob {flag}")
        assert any("only wildcards" in line for line in out), out
        assert await db_value(
            core, f"SELECT COALESCE(MAX({col}), 0) FROM user_access WHERE handle = 'bob'") == 0
    asyncio.run(go())


def test_grant_allowed_once_wildcard_mask_removed(core):
    async def go():
        await core.user.addhost("bob", "*!*@*")
        await core.user.addhost("bob", "*!*@host.example")
        assert await core.user.chattr("bob", "+A", subnet_id=1) == "wildcard_host"
        assert await core.user.delhost("bob", "*!*@*") == "ok"
        assert await core.user.chattr("bob", "+A", subnet_id=1) == "ok"
        assert await core.user.matchattr("bob", "+A", subnet_id=1)
    asyncio.run(go())


def test_grant_of_other_flags_unaffected_by_wildcard_mask(core):
    async def go():
        await core.user.addhost("bob", "*!*@*")
        assert await core.user.chattr("bob", "+pov", subnet_id=1) == "ok"
    asyncio.run(go())


# --- share import -----------------------------------------------------------------

def _peer(handle, mask_list, ts=4_000_000_000):
    return [{"handle": handle, "hostmasks": mask_list, "updated_at": ts}]


@pytest.mark.parametrize("col", ["is_owner", "is_admin"])
def test_share_import_drops_wildcard_masks_for_privileged_user(core, col, caplog):
    async def go():
        await grant(core, "bob", col)
        with caplog.at_level(logging.WARNING, logger="wbs.user"):
            await core.user.merge_from_peer(
                _peer("bob", ["*!*@*", "*!*@*.*", "*!*@good.example"]), "peerbot")
        assert await masks(core, "bob") == ["*!*@good.example"]
        assert any("dropped wildcard-only" in r.getMessage() and "bob" in r.getMessage()
                   for r in caplog.records)
    asyncio.run(go())


def test_share_import_keeps_wildcard_masks_for_plain_user(core):
    async def go():
        await core.user.merge_from_peer(_peer("bob", ["*!*@*", "*!*@good.example"]), "peerbot")
        assert await masks(core, "bob") == ["*!*@*", "*!*@good.example"]
    asyncio.run(go())


def test_share_import_json_string_hostmasks_handled(core):
    async def go():
        await grant(core, "bob", "is_owner")
        await core.user.merge_from_peer(
            _peer("bob", json.dumps(["*!*@*", "*!*@good.example"])), "peerbot")
        assert await masks(core, "bob") == ["*!*@good.example"]
    asyncio.run(go())


# --- seed import ------------------------------------------------------------------

def _seed(tmp_path, users):
    from src.db import get_db, init_db, seed_db
    db = str(tmp_path / "seed.db")
    config = {"bot": {"nick": "beta", "channels": []},
              "subnet": {"id": 1, "name": "one"}, "users": users}

    async def go():
        await init_db(db)
        await seed_db(db, config)
        async with get_db(db) as d:
            rows = await d.execute_fetchall("SELECT handle, hostmasks FROM users")
        return {r[0]: json.loads(r[1]) for r in rows}
    return asyncio.run(go())


@pytest.mark.parametrize("flag", ["is_owner", "is_admin"])
def test_seed_refuses_wildcard_only_host_for_privileged_user(tmp_path, caplog, flag):
    with caplog.at_level(logging.ERROR, logger="wbs.db"):
        got = _seed(tmp_path, [
            {"handle": "boss", "password": "pw-long-enough-1", "access": [{flag: True}],
             "hosts": ["*!*@*", "*!*@*.*", "*!*@good.example"]},
        ])
    assert got["boss"] == ["*!*@good.example"]
    assert any("boss" in r.getMessage() and "wildcard-only" in r.getMessage()
               for r in caplog.records if r.levelno == logging.ERROR)


def test_seed_owner_with_only_wildcard_host_gets_no_host(tmp_path):
    got = _seed(tmp_path, [{"handle": "boss", "password": "pw-long-enough-1",
                            "access": [{"is_owner": True}], "hosts": ["*!*@*"]}])
    assert got["boss"] == []


def test_seed_plain_user_keeps_wildcard_hosts(tmp_path):
    got = _seed(tmp_path, [
        {"handle": "pat", "password": "pw-long-enough-1", "hosts": ["*!*@*"]},
        {"handle": "opie", "password": "pw-long-enough-1", "access": [{"is_op": True}],
         "hosts": ["*!*@*"]},
    ])
    assert got["pat"] == ["*!*@*"] and got["opie"] == ["*!*@*"]
