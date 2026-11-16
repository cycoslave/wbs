"""
Regression tests for USR-5 and USR-8 (re-confirmed as IRC I12).

USR-5: `.chattr` had its own letter map (`a`=admin, input lower-cased, no
n/q/l/k), so `.chattr x +a` granted ADMIN while `.addaccess x +a` meant
autoop.  Now every command reads the one case-sensitive table,
user.GLOBAL_FLAGS: each letter round-trips chattr -> userinfo, `+a` is
autoop, `+O` is refused with the valid list, and `+n` (owner) can only be
set by an owner or the console, never by +A alone.

USR-8: channel access rows could never be created ("No access row found").
`.addaccess bob +o #chan` / `.chattr bob +o #chan` now create the
(user, channel, subnet) row on demand when the user and channel exist on
that subnet; matchattr honours the row.  Each DB is a throwaway sqlite file.
"""
import asyncio
from unittest.mock import AsyncMock

import pytest

from src import commands
from src.channel import ChannelManager
from src.db import get_db
from src.helper import _require_flag
from src.user import FLAG_LEGEND, GLOBAL_FLAGS

from test_console_operator import FakeCore, build_db, console_sid, run_cmd


async def _setup(tmp_path):
    db = await build_db(tmp_path)          # subnet 1 'one'; plainp, bob (+p), carol (locked)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (2, 'two')")
        for handle, cols in (("admin1", "has_partyline, is_admin"),
                             ("owner1", "has_partyline, is_admin, is_owner")):
            await d.execute("INSERT INTO users(handle, password, hostmasks) "
                            "VALUES (?, '$2b$12$x', '[]')", (handle,))
            await d.execute(f"INSERT INTO user_access (handle, channel, subnet_id, {cols}) "
                            f"VALUES (?, NULL, 1, {', '.join('1' * len(cols.split(',')))})",
                            (handle,))
        await d.commit()
    chans = ChannelManager(db)
    await chans.addchan("#wbs", subnet_id=1)        # bound to subnet 1
    await chans.addchan("#other", subnet_id=2)      # bound to subnet 2 only
    await chans.addchan("#everywhere")              # global channel
    return db


@pytest.fixture
def core(tmp_path):
    db = asyncio.run(_setup(tmp_path))
    c = FakeCore(db, tmp_path)
    c.botnet.sync_user_access = AsyncMock()     # real Botnet has it; .chattr calls it
    return c


def admin_sid(core, handle="admin1"):
    return core.partyline.register_remote("dcc", handle, asyncio.Queue())


async def access_lines(core, handle):
    out = await run_cmd(core, "userinfo", "console", console_sid(core), handle)
    text = "\n".join(out)
    return [ln.strip() for ln in text.split("\n") if "subnet" in ln and "): +" in ln]


async def row_flags(core, handle, channel=None, subnet_id=1):
    for ln in await access_lines(core, handle):
        where = channel or "*"
        scope = "all subnets" if subnet_id is None else f"subnet {subnet_id}"
        if ln.startswith(f"{where} ({scope}): +"):
            return ln.split("): +", 1)[1]
    return None


# --- USR-5: one table ---------------------------------------------------------

@pytest.mark.parametrize("letter", list(GLOBAL_FLAGS))
def test_each_flag_round_trips_chattr_to_userinfo(core, letter):
    async def go():
        sid = console_sid(core)
        out = await run_cmd(core, "chattr", "console", sid, f"bob +{letter}")
        assert any(f"Flags +{letter} applied to bob (subnet 1)" in ln for ln in out), out
        flags = await row_flags(core, "bob")
        assert flags is not None and letter in flags, (letter, flags)
        assert await core.user.matchattr("bob", f"+{letter}", subnet_id=1)
        # whois shows the same letters as userinfo
        whois = "\n".join(await run_cmd(core, "whois", "console", sid, "bob"))
        assert f"* (subnet 1): +{flags}" in whois
        out = await run_cmd(core, "chattr", "console", sid, f"bob -{letter}")
        assert any("applied" in ln for ln in out), out
        after = await row_flags(core, "bob")
        assert letter not in (after or ""), (letter, after)
        if letter != "p":
            assert after == "p"
    asyncio.run(go())


def test_chattr_plus_a_is_autoop_not_admin(core):
    async def go():
        out = await run_cmd(core, "chattr", "admin1", admin_sid(core), "bob +a")
        assert any("applied" in ln for ln in out), out
        assert await core.user.matchattr("bob", "+a", subnet_id=1) is True
        assert await core.user.matchattr("bob", "+A", subnet_id=1) is False
        assert await row_flags(core, "bob") == "pa"
        # .addaccess agrees with .chattr
        await run_cmd(core, "addaccess", "admin1", admin_sid(core), "plainp +a")
        assert await core.user.matchattr("plainp", "+A", subnet_id=1) is False
        assert await row_flags(core, "plainp") == "pa"
    asyncio.run(go())


@pytest.mark.parametrize("name,arg", [
    ("chattr", "bob +O"), ("chattr", "bob +e"), ("chattr", "bob +P"),
    ("chattr", "bob +oZ"), ("addaccess", "bob +O"), ("delaccess", "bob -P"),
])
def test_unknown_or_wrong_case_letter_refused_with_valid_list(core, name, arg):
    async def go():
        before = await access_lines(core, "bob")
        out = await run_cmd(core, name, "console", console_sid(core), arg)
        text = "\n".join(out)
        assert "Unknown flag" in text and FLAG_LEGEND in text, out
        assert "applied" not in text and "Added" not in text and "Removed" not in text
        assert await access_lines(core, "bob") == before
    asyncio.run(go())


@pytest.mark.parametrize("name,arg", [
    ("chattr", "bob +n"), ("addaccess", "bob +n"), ("addaccess", "bob owner"),
    ("chattr", "owner1 -n"), ("delaccess", "owner1 -n"), ("chattr", "bob +pn"),
])
def test_owner_flag_not_grantable_by_admin_alone(core, name, arg):
    async def go():
        out = await run_cmd(core, name, "admin1", admin_sid(core), arg)
        assert any("Access denied" in ln and "+n" in ln for ln in out), out
        assert await core.user.matchattr("bob", "+n", subnet_id=1) is False
        assert await core.user.matchattr("owner1", "+n", subnet_id=1) is True
    asyncio.run(go())


def test_owner_flag_grantable_by_owner_and_console(core):
    async def go():
        out = await run_cmd(core, "chattr", "owner1", admin_sid(core, "owner1"), "bob +n")
        assert any("applied" in ln for ln in out), out
        assert await core.user.matchattr("bob", "+n", subnet_id=1) is True
        out = await run_cmd(core, "delaccess", "console", console_sid(core), "bob -n")
        assert any("Removed -n" in ln for ln in out), out
        assert await core.user.matchattr("bob", "+n", subnet_id=1) is False
        out = await run_cmd(core, "addaccess", "console", console_sid(core), "bob owner")
        assert any("Added +n" in ln for ln in out), out
        # an owner of subnet 1 only cannot mint a GLOBAL owner
        out = await run_cmd(core, "chattr", "owner1", admin_sid(core, "owner1"), "plainp +n *")
        assert any("Access denied" in ln for ln in out), out
        assert await core.user.matchattr("plainp", "+n", subnet_id=None) is False
    asyncio.run(go())


def test_help_texts_use_the_one_table(core):
    async def go():
        sid = console_sid(core)
        for name in ("chattr", "addaccess", "delaccess", "userinfo", "whois"):
            text = "\n".join(await run_cmd(core, "help", "console", sid, name))
            for letter, col in GLOBAL_FLAGS.items():
                word = col.removeprefix("is_").removeprefix("has_")
                assert f"{letter}={word}" in text, (name, letter)
            assert "P=partyline" not in text and "E=devoice" not in text
            assert "+O" not in text
        assert "A=admin" in FLAG_LEGEND and "a=autoop" in FLAG_LEGEND
        assert "n=owner" in FLAG_LEGEND and "q=devoice" in FLAG_LEGEND
        assert not hasattr(commands, "_CHATTR_ALLOWED_COLUMNS")
    asyncio.run(go())


# --- USR-8: channel rows on demand ----------------------------------------------

def test_addaccess_creates_channel_row_on_demand(core):
    async def go():
        out = await run_cmd(core, "addaccess", "admin1", admin_sid(core), "bob +o #wbs")
        assert any("Added +o to bob on #wbs (subnet 1)" in ln for ln in out), out
        assert await row_flags(core, "bob", "#wbs") == "o"
        assert await row_flags(core, "bob") == "p"          # non-channel row untouched
        # second grant updates the same row (no duplicate)
        await run_cmd(core, "addaccess", "admin1", admin_sid(core), "bob +v #wbs")
        assert await row_flags(core, "bob", "#wbs") == "ov"
        assert sum(ln.startswith("#wbs ") for ln in await access_lines(core, "bob")) == 1
    asyncio.run(go())


def test_chattr_creates_channel_row_on_demand_and_folds_channel_case(core):
    async def go():
        sid = admin_sid(core)
        out = await run_cmd(core, "chattr", "admin1", sid, "bob #WBS +o")
        assert any("applied to bob on #wbs (subnet 1)" in ln.lower() for ln in out), out
        assert await row_flags(core, "bob", "#wbs") == "o"
        # global (unbound) channel works in this subnet too, flags before channel
        out = await run_cmd(core, "chattr", "admin1", sid, "bob +v #everywhere")
        assert any("applied" in ln for ln in out), out
        assert await row_flags(core, "bob", "#everywhere") == "v"
        # explicit subnet name, console
        out = await run_cmd(core, "chattr", "console", console_sid(core), "bob +o #other two")
        assert any("applied to bob on #other (subnet 2)" in ln for ln in out), out
        assert await row_flags(core, "bob", "#other", subnet_id=2) == "o"
    asyncio.run(go())


@pytest.mark.parametrize("name,arg,expect", [
    ("addaccess", "nobody +o #wbs", "No such user: nobody"),
    ("chattr", "nobody +o #wbs", "No such user: nobody"),
    ("addaccess", "bob +o #nochan", "No such channel: #nochan"),
    ("chattr", "bob +o #nochan", "No such channel: #nochan"),
    ("addaccess", "bob +o #other", "No such channel: #other (subnet 1)"),   # bound to subnet 2
    ("delaccess", "bob -o #wbs", "No access row found for bob on #wbs"),  # never creates
])
def test_channel_row_refusals(core, name, arg, expect):
    async def go():
        before = await access_lines(core, "bob")
        out = await run_cmd(core, name, "console", console_sid(core), arg)
        assert any(expect in ln for ln in out), out
        assert await access_lines(core, "bob") == before
        async with get_db(core.db_path) as d:
            n = (await (await d.execute(
                "SELECT COUNT(*) FROM user_access WHERE channel IS NOT NULL")).fetchone())[0]
        assert n == 0
    asyncio.run(go())


def test_matchattr_honours_on_demand_channel_rows(core):
    async def go():
        um = core.user
        assert await um.matchattr("bob", "*|o", "#wbs", subnet_id=1) is False
        await run_cmd(core, "addaccess", "admin1", admin_sid(core), "bob +o #wbs")
        assert await um.matchattr("bob", "*|o", "#wbs", subnet_id=1) is True
        assert await um.matchattr("bob", "*|o", "#WBS", subnet_id=1) is True
        assert await um.matchattr("bob", "p|o", "#wbs", subnet_id=1) is True
        assert await um.matchattr("bob", "*|o", "#wbs", subnet_id=2) is False
        assert await um.matchattr("bob", "*|o", "#everywhere", subnet_id=1) is False
        assert await um.matchattr("bob", "+o", subnet_id=1) is False       # channel-only grant
        # the channel-aware permission helper accepts the row
        out = []

        async def respond(m):
            out.append(m)
        assert await _require_flag(core, "bob", "*|o", respond, channel="#wbs") is True
        assert await _require_flag(core, "bob", "*|o", respond, channel="#everywhere") is False
        # removal through the same commands takes effect
        out = await run_cmd(core, "chattr", "admin1", admin_sid(core), "bob -o #wbs")
        assert any("applied" in ln for ln in out), out
        assert await um.matchattr("bob", "*|o", "#wbs", subnet_id=1) is False
        assert await row_flags(core, "bob", "#wbs") == "-"
    asyncio.run(go())


def test_channel_row_of_deleted_and_readded_user_is_revived_clean(core):
    async def go():
        sid = console_sid(core)
        await run_cmd(core, "addaccess", "console", sid, "bob +ov #wbs")
        assert await core.user.deluser("bob")
        assert await core.user.adduser("bob", subnet_id=1)
        assert await row_flags(core, "bob", "#wbs") is None             # soft-deleted row hidden
        assert await core.user.matchattr("bob", "*|o", "#wbs", subnet_id=1) is False
        out = await run_cmd(core, "addaccess", "console", sid, "bob +v #wbs")
        assert any("Added +v" in ln for ln in out), out
        assert await row_flags(core, "bob", "#wbs") == "v"               # old +o not revived
    asyncio.run(go())
