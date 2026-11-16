"""
Regression tests for USR-2: README command names are aliases of the real ones.

Real names stay (+user -user userinfo users chpass +host -host +ignore -ignore);
adduser deluser showuser listusers passwd addhost delhost addignore delignore
resolve to the SAME handler function and the SAME COMMAND_MIN_FLAGS entry.
`.help` lists each command once (`+user (adduser)`), `.addaccess` takes word
flag names, and the README "Create your first user" flow runs literally on a
fresh seeded database through the real partyline dispatcher.
"""
import asyncio
import re
from pathlib import Path

import pytest

from src import commands
from src.db import get_db, init_db, seed_db
from src.partyline import COMMAND_MIN_FLAGS
from src.relay import RELAY_BLOCKED_COMMANDS
from src.user import GLOBAL_FLAGS, FLAG_WORDS, expand_flag_words

from test_console_operator import FakeCore, build_db, console_sid, run_cmd

README = Path(__file__).resolve().parent.parent / "README.md"

EXPECTED = {
    "adduser": "+user", "deluser": "-user", "showuser": "userinfo",
    "listusers": "users", "passwd": "chpass", "addhost": "+host",
    "delhost": "-host", "addignore": "+ignore", "delignore": "-ignore",
}


# --- alias table ------------------------------------------------------------

def test_alias_table_is_the_operator_decision():
    assert commands.ALIASES == EXPECTED


@pytest.mark.parametrize("alias,real", sorted(EXPECTED.items()))
def test_alias_is_same_handler_and_same_flag(alias, real):
    assert commands.COMMANDS[alias] is commands.COMMANDS[real]
    assert alias in COMMAND_MIN_FLAGS
    assert COMMAND_MIN_FLAGS[alias] == COMMAND_MIN_FLAGS[real]


@pytest.mark.parametrize("alias,real", sorted(EXPECTED.items()))
def test_real_names_are_kept(alias, real):
    assert real in commands.COMMANDS and real in COMMAND_MIN_FLAGS


def test_chpass_alias_is_blocked_over_relay_like_chpass():
    assert "chpass" in RELAY_BLOCKED_COMMANDS and "passwd" in RELAY_BLOCKED_COMMANDS


# --- .help ------------------------------------------------------------------

@pytest.fixture
def core(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    return FakeCore(db, tmp_path)


def test_help_shows_each_command_once_with_its_alias(core):
    async def go():
        out = await run_cmd(core, "help", "console", console_sid(core))
        text = "\n".join(out)
        for alias, real in EXPECTED.items():
            assert f"{real} ({alias})" in text, (real, alias)
            # the alias is never listed as a command of its own
            assert not re.search(rf"(?<![\w(]){re.escape(alias)}(?![\w)])", text), alias
    asyncio.run(go())


def test_help_for_alias_is_help_for_real_command(core):
    async def go():
        sid = console_sid(core)
        real = await run_cmd(core, "help", "console", sid, "+user")
        via_alias = await run_cmd(core, "help", "console", sid, "adduser")
        assert via_alias == real
        assert not any("Unknown command" in line for line in via_alias)
        assert any("adduser" in line for line in real)       # "Alias: adduser"
    asyncio.run(go())


# --- word flag names ----------------------------------------------------------

def test_word_flags_cover_the_flag_table():
    assert set(FLAG_WORDS.values()) == set(GLOBAL_FLAGS)          # one word per letter
    assert FLAG_WORDS["admin"] == "A" and FLAG_WORDS["owner"] == "n"
    assert FLAG_WORDS["partyline"] == "p" and FLAG_WORDS["op"] == "o"
    assert FLAG_WORDS["voice"] == "v" and FLAG_WORDS["autoop"] == "a"


@pytest.mark.parametrize("spec,expected", [
    ("admin", "A"), ("ADMIN", "A"), ("admin,partyline", "Ap"), ("op,voice,op", "ov"),
    ("A", "A"), ("Ap", "Ap"), ("pov", "pov"),
    ("admin,bogus", "admin,bogus"), ("", ""), ("bogus", "bogus"),
])
def test_expand_flag_words(spec, expected):
    assert expand_flag_words(spec) == expected


def test_addaccess_and_delaccess_accept_word_names(core):
    async def go():
        sid = console_sid(core)
        col = "SELECT {} FROM user_access WHERE handle='bob' AND channel IS NULL AND subnet_id=1"
        out = await run_cmd(core, "addaccess", "console", sid, "bob admin")
        assert any("Added +A" in line for line in out), out
        async with get_db(core.db_path) as d:
            assert (await (await d.execute(col.format("is_admin"))).fetchone())[0] == 1
        out = await run_cmd(core, "addaccess", "console", sid, "bob autoop,voice")
        assert any("Added +av" in line for line in out), out
        out = await run_cmd(core, "delaccess", "console", sid, "bob admin")
        assert any("Removed -A" in line for line in out), out
        async with get_db(core.db_path) as d:
            row = await (await d.execute(
                "SELECT is_admin, is_autoop, is_voice FROM user_access "
                "WHERE handle='bob' AND channel IS NULL AND subnet_id=1")).fetchone()
        assert tuple(row) == (0, 1, 1)
        out = await run_cmd(core, "addaccess", "console", sid, "bob nonsense")
        assert any("Unknown flag" in line for line in out), out
    asyncio.run(go())


# --- README flow ---------------------------------------------------------------

def _readme_console_commands() -> list[str]:
    """The `.cmd` lines of the fenced block of 'Create your first user'."""
    text = README.read_text().replace("\r\n", "\n")
    section = text.split("## Create your first user", 1)[1].split("\n## ", 1)[0]
    block = re.search(r"```\n(.*?)```", section, re.S)
    assert block, "README first-user flow lost its command block"
    return [ln for ln in block.group(1).splitlines() if ln.strip()]


def test_readme_first_user_flow_on_fresh_seeded_db(tmp_path):
    """Type the README commands at the console of a fresh `--seed` db, literally."""
    lines = _readme_console_commands()
    assert [ln.split()[0] for ln in lines][:2] == [".adduser", ".addaccess"]
    assert all(ln.startswith(".") for ln in lines)

    async def go():
        db = str(tmp_path / "wbs.db")
        await init_db(db)
        config = {"bot": {"nick": "WBS", "channels": []},
                  "subnet": {"id": 1, "name": "default"}, "users": []}
        await seed_db(db, config)                      # == `./wbs --seed`, zero users

        core = FakeCore(db, tmp_path)
        shown: list[str] = []
        sid = core.partyline.register_console("console", shown.append)

        for line in lines:
            line = line.replace("yourname", "alice")
            n = len(shown)
            await core.partyline.handle_input(sid, line)
            await asyncio.sleep(0)
            reply = "\n".join(shown[n:])
            assert "Unknown command" not in reply, (line, reply)
            assert "Access denied" not in reply, (line, reply)
            assert "Error" not in reply and "Unknown flag" not in reply, (line, reply)
            assert reply, f"no reply to README line {line!r}"

        # the account really is a working admin that can log in
        pw = re.search(r"\.passwd alice (\S+)", "\n".join(lines).replace("yourname", "alice")).group(1)
        assert await core.user.authenticate("alice", pw)
        assert await core.user.matchattr("alice", "+A", subnet_id=1)
        assert await core.user.matchattr("alice", "+p", subnet_id=1)

        # ... and uses an alias over a remote session, gated like the real name
        asid = core.partyline.register_remote("dcc", "alice", asyncio.Queue())
        out: list = []
        core.partyline.send_to_session = lambda s, m: out.append(m)
        await core.partyline.handle_input(asid, ".listusers")
        assert any("alice" in m for m in out), out
    asyncio.run(go())


def test_alias_is_refused_like_the_real_command_for_a_plain_user(core):
    async def go():
        sid = core.partyline.register_remote("dcc", "plainp", asyncio.Queue())
        out: list = []
        core.partyline.send_to_session = lambda s, m: out.append(m)
        for text in (".adduser x *!x@h", ".+user x *!x@h", ".listusers", ".users",
                     ".addignore *!a@b", ".+ignore *!a@b"):
            out.clear()
            await core.partyline.handle_input(sid, text)
            assert any("Access denied" in m and "need +A" in m for m in out), (text, out)
        assert await core.user.exist("x") is False
    asyncio.run(go())
