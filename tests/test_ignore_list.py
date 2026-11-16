"""
Regression tests for USR-11: the ignore list works AND is enforced.

* `.+ignore` used to insert into a non-existent column (`creator`; the
  schema has `created_by`) inside a bare `except`, so every add answered
  "already ignored" and nothing was stored; `.ignores` double counted.
* Nothing read the table.  Now the IRC process drops PRIVMSG / NOTICE /
  CTCP (DCC included) from a matching host in the reactor, before any
  event reaches Core, commands, games or plugins.
* Owner/admin hostmasks are never ignorable.

The IRC side runs the real WbsIrcBot reactor dispatch on raw server lines
(no socket); its events go through the real Core.handle_event.  Throwaway
sqlite DB per test.
"""
import asyncio
import os
import queue
import shutil
import sqlite3
import tempfile
import time

import pytest

from src import ignore as ignore_mod
from src.commands import cmd_addignore, cmd_delignore, cmd_ignores
from src.core import Core
from src.db import get_db, init_db
from src.games import GameManager
from src.irc import WbsIrcBot
from src.partyline import Partyline
from src.plugins import PluginManager
from src.plugins.pubcom import pubcomPlugin
from src.user import UserManager

BOT = "wU2"
BOSS = ("wboss", "wboss!~irsa@home.example")       # +n +A, host *!*irsa@*
OWNER = ("wown", "wown!~own@own.example")          # +n only, host *!*own@own.example
SPAM = ("spammer", "spammer!~x@bad.host")
OTHER = ("friend", "friend!~y@good.host")
BOSS_PW = "boss-test-pass-1"          # test-only fixture value

_TEMPLATE_DB: str | None = None


async def build_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-usr11-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)
    users = {
        "boss": ('["*!*irsa@*"]', {"has_partyline", "is_owner", "is_admin"}),
        "owner": ('["*!*own@own.example"]', {"has_partyline", "is_owner"}),
        "plain": ('["*!*pl@plain.example"]', {"has_partyline"}),
    }
    async with get_db(path) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one')")
        await d.execute("INSERT INTO channels(name) VALUES ('#wbs')")
        await d.execute("INSERT INTO channel_subnets(channel_name, subnet_id) VALUES ('#wbs', 1)")
        for handle, (masks, cols) in users.items():
            await d.execute("INSERT INTO users(handle, hostmasks) VALUES (?, ?)", (handle, masks))
            names = ["handle", "channel", "subnet_id", *sorted(cols)]
            vals = [handle, None, 1, *([1] * len(cols))]
            await d.execute(
                f"INSERT INTO user_access ({', '.join(names)}) "
                f"VALUES ({', '.join('?' * len(names))})", vals)


class FakeIrcQ:
    def __init__(self):
        self.items: list[dict] = []

    def put_nowait(self, payload):
        self.items.append(payload)

    def replies_to(self, target):
        return [p["text"] for p in self.items
                if p.get("cmd") in ("msg", "notice") and p.get("target") == target]


class FakeChan:
    async def getchans(self, subnet_id=None):
        return ["#wbs"]


def make_core(db: str) -> Core:
    core = object.__new__(Core)
    core.config = {"bot": {"nick": BOT}, "botnet": {"subnet_id": 1},
                   "pubcom": {"channels": ["#wbs"]}, "db": {"path": db}}
    core.db_path = db
    core.botname = BOT
    core.irc_q = FakeIrcQ()
    core.core_q = None
    core.start_time = time.time()
    core.connected = True
    core.dcc = None
    core.dcc_sessions = {}
    core.party_sessions = {}
    core.botnet = None
    core.channels = {}          # IRC-7: on_pubmsg reads live channel state
    core.user = UserManager(db)
    core.chan = FakeChan()
    core.partyline = Partyline(core)
    core.plugin = PluginManager(core)
    core.plugin.plugins["pubcom"] = pubcomPlugin(core)
    core.game = GameManager(core)
    core.handlers = {"PRIVMSG": core.on_privmsg, "COMMAND": core.on_command,
                     "PUBMSG": core.on_pubmsg}
    return core


def make_irc(db: str) -> WbsIrcBot:
    config = {"bot": {"nick": BOT, "servers": [{"host": "irc.example", "port": 6667}]},
              "botnet": {"subnet_id": 1}, "db": {"path": db}, "id": 1}
    bot = WbsIrcBot(config, queue.Queue(), queue.Queue())
    bot.core_q.get_nowait()          # REQUEST_BOTLINKS from __init__
    # What connect() would have set; no socket is ever opened.
    bot.connection.real_server_name = "irc.example.net"
    bot.connection.real_nickname = BOT
    bot.connection.handlers = {}
    return bot


@pytest.fixture
def env(tmp_path):
    db = str(tmp_path / "wbs.db")
    asyncio.run(build_db(db))
    core, irc = make_core(db), make_irc(db)
    # F-01a: owner /msg commands need settings.msg_commands and a live pubcom
    # identify session (a hostmask match alone is refused).
    core.config["settings"] = {"msg_commands": True}
    assert asyncio.run(core.user.set_password("boss", BOSS_PW))
    deliver(core, irc, f":{BOSS[1]} PRIVMSG {BOT} :identify boss {BOSS_PW}")
    assert core.irc_q.replies_to(BOSS[0]) == ["Logged in successfully!"]
    core.irc_q.items.clear()
    return core, irc


def run_cmd(core, func, arg, handle="boss"):
    out: list[str] = []

    async def respond(msg):
        out.append(msg)
    asyncio.run(func(core, handle, 1, arg, respond))
    return out


def deliver(core, irc, line):
    """Feed one raw server line through the IRC reactor, then hand every
    event it emitted to Core; return what Core queued for IRC."""
    core.irc_q.items.clear()
    irc.connection._process_line(line)
    events = []
    while True:
        try:
            events.append(irc.core_q.get_nowait())
        except queue.Empty:
            break
    types = [e.get("type") for e in events]

    async def go():
        for ev in events:
            await core.handle_event(ev)
    asyncio.run(go())
    return types, list(core.irc_q.items)


def sync_irc(core, irc):
    """Apply the commands Core queued for the IRC process (reload_ignores)."""
    for p in core.irc_q.items:
        if p.get("cmd") == "reload_ignores":
            irc.execute_command(p)


def rows(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT hostmask, flags, comment, created_by FROM ignores "
                            "ORDER BY hostmask").fetchall()
    finally:
        conn.close()


# --- add / list / remove / expire --------------------------------------------

def test_add_stores_row_and_list_counts_once(env):
    core, _ = env
    assert run_cmd(core, cmd_ignores, "") == ["No ignores."]
    out = run_cmd(core, cmd_addignore, "*!*x@bad.host")
    assert out == ["Now ignoring *!*x@bad.host permanently."], out
    out = run_cmd(core, cmd_addignore, "*!*y@bad.host %10m spamming a lot")
    assert out == ["Now ignoring *!*y@bad.host for 10m (spamming a lot)."], out
    assert rows(core.db_path) == [("*!*x@bad.host", "", "", "boss"),
                                  ("*!*y@bad.host", "10m", "spamming a lot", "boss")]
    out = run_cmd(core, cmd_ignores, "")
    assert out[0] == "Currently ignoring:"
    assert out[1] == "  *!*x@bad.host (permanent, by boss)"
    assert out[2].startswith("  *!*y@bad.host (expires in 10m, by boss): spamming a lot"), out
    assert out[-1] == "Total ignores: 2", out          # not 4 (double count)
    assert {"cmd": "reload_ignores"} in core.irc_q.items


def test_duplicate_add_reports_already_ignored_only_when_present(env):
    core, _ = env
    assert run_cmd(core, cmd_addignore, "*!*x@bad.host")[0].startswith("Now ignoring")
    assert run_cmd(core, cmd_addignore, "*!*X@BAD.host") == ["*!*x@bad.host is already ignored."]
    assert run_cmd(core, cmd_delignore, "*!*x@bad.host") == ["No longer ignoring *!*x@bad.host."]
    assert run_cmd(core, cmd_addignore, "*!*x@bad.host")[0].startswith("Now ignoring")


def test_remove(env):
    core, _ = env
    run_cmd(core, cmd_addignore, "*!*x@bad.host")
    assert run_cmd(core, cmd_delignore, "*!*x@bad.host") == ["No longer ignoring *!*x@bad.host."]
    assert run_cmd(core, cmd_delignore, "*!*x@bad.host") == ["Not ignoring *!*x@bad.host."]
    assert rows(core.db_path) == []
    assert run_cmd(core, cmd_ignores, "") == ["No ignores."]


def test_expired_ignore_is_purged_lazily(env):
    core, irc = env
    run_cmd(core, cmd_addignore, "*!*x@bad.host %1h old")
    run_cmd(core, cmd_addignore, "*!*z@bad.host keep")
    conn = sqlite3.connect(core.db_path)
    conn.execute("UPDATE ignores SET created_at = ? WHERE hostmask = '*!*x@bad.host'",
                 (int(time.time()) - 3601,))
    conn.commit()
    conn.close()
    irc.ignores.reload()
    assert irc.ignores.match("x!~x@bad.host") is None        # expired: not enforced
    out = run_cmd(core, cmd_ignores, "")
    assert out[-1] == "Total ignores: 1", out
    assert [r[0] for r in rows(core.db_path)] == ["*!*z@bad.host"]   # row deleted
    # once expired, the mask can be added again
    assert run_cmd(core, cmd_addignore, "*!*x@bad.host")[0].startswith("Now ignoring")


def test_duration_parsing_and_bad_input(env):
    core, _ = env
    assert ignore_mod.parse_duration("10m") == 600
    assert ignore_mod.parse_duration("1h") == 3600
    assert ignore_mod.parse_duration("2d12h") == 2 * 86400 + 12 * 3600
    assert ignore_mod.parse_duration("0") == 0
    for bad in ("", "x", "10", "1s", "m", "-1h"):
        assert ignore_mod.parse_duration(bad) is None, bad
    assert run_cmd(core, cmd_addignore, "*!*x@bad.host %soon")[0].startswith("Invalid duration")
    assert run_cmd(core, cmd_addignore, "*!*x@bad.host %0 forever") == [
        "Now ignoring *!*x@bad.host permanently (forever)."]
    assert run_cmd(core, cmd_addignore, "") == ["Usage: +ignore <hostmask> [%<XyXdXhXm>] [comment]"]
    assert "Invalid hostmask" in run_cmd(core, cmd_addignore, "a!b!c@d")[0]
    # nick / user@host shorthand completes to a full mask
    assert run_cmd(core, cmd_addignore, "lamer")[0].startswith("Now ignoring lamer!*@*")
    assert rows(core.db_path)[0][0] in ("*!*x@bad.host", "lamer!*@*")


# --- owner/admin protection --------------------------------------------------

@pytest.mark.parametrize("mask", ["*!*irsa@*", "wboss!~irsa@home.example", "*!*@*",
                                  "*!*own@own.example", "*"])
def test_owner_or_admin_mask_cannot_be_ignored(env, mask):
    core, _ = env
    out = run_cmd(core, cmd_addignore, mask)
    assert out[0].startswith("Cannot ignore"), out
    assert rows(core.db_path) == []


def test_owner_admin_never_dropped_even_if_mask_slipped_in(env):
    core, irc = env
    conn = sqlite3.connect(core.db_path)
    conn.execute("INSERT INTO ignores(hostmask, flags) VALUES ('*!*@home.example', '')")
    conn.commit()
    conn.close()
    irc.ignores.reload()
    assert irc.ignores.match(BOSS[1]) is None
    events, out = deliver(core, irc, f":{BOSS[1]} PRIVMSG {BOT} :.whoami")
    assert events == ["PRIVMSG"]
    assert core.irc_q.replies_to(BOSS[0]) == ["You are boss@wU2"]


# --- enforcement --------------------------------------------------------------

def test_ignored_host_pm_and_pubcom_get_no_reply(env):
    core, irc = env
    # Before the ignore both paths answer (the PM is from a stranger, so
    # identify is the PM that answers).
    deliver(core, irc, f":{SPAM[1]} PRIVMSG #wbs :!version")
    assert core.irc_q.replies_to("#wbs"), core.irc_q.items
    deliver(core, irc, f":{SPAM[1]} PRIVMSG {BOT} :identify nobody pw")
    assert core.irc_q.replies_to(SPAM[0]) == ["Invalid credentials!"]

    run_cmd(core, cmd_addignore, "*!*x@bad.host %1h spam")
    sync_irc(core, irc)

    for line in (f":{SPAM[1]} PRIVMSG #wbs :!version",
                 f":{SPAM[1]} PRIVMSG {BOT} :identify nobody pw",
                 f":{SPAM[1]} PRIVMSG {BOT} :.help",
                 f":{SPAM[1]} NOTICE {BOT} :hello",
                 f":{SPAM[1]} NOTICE #wbs :hello",
                 f":{SPAM[1]} PRIVMSG #wbs :\x01ACTION waves\x01",
                 f":{SPAM[1]} PRIVMSG {BOT} :\x01VERSION\x01",
                 f":{SPAM[1]} PRIVMSG {BOT} :\x01DCC CHAT chat 16843009 5000\x01"):
        events, out = deliver(core, irc, line)
        assert events == [], (line, events)
        assert out == [], (line, out)

    # a non-matching host still works
    deliver(core, irc, f":{OTHER[1]} PRIVMSG #wbs :!version")
    assert core.irc_q.replies_to("#wbs"), core.irc_q.items
    deliver(core, irc, f":{OTHER[1]} PRIVMSG {BOT} :identify nobody pw")
    assert core.irc_q.replies_to(OTHER[0]) == ["Invalid credentials!"]
    events, _ = deliver(core, irc, f":{OTHER[1]} PRIVMSG {BOT} :\x01DCC CHAT chat 16843009 5000\x01")
    assert events == ["DCC_CHAT_REQUEST"]

    # and after -ignore the spammer is heard again
    run_cmd(core, cmd_delignore, "*!*x@bad.host")
    sync_irc(core, irc)
    deliver(core, irc, f":{SPAM[1]} PRIVMSG #wbs :!version")
    assert core.irc_q.replies_to("#wbs")


def test_owner_pm_command_still_works_with_unrelated_ignore(env):
    core, irc = env
    run_cmd(core, cmd_addignore, "*!*x@bad.host")
    sync_irc(core, irc)
    deliver(core, irc, f":{BOSS[1]} PRIVMSG {BOT} :.whoami")
    assert core.irc_q.replies_to(BOSS[0]) == ["You are boss@wU2"]


def test_server_notices_are_not_filtered(env):
    core, irc = env
    run_cmd(core, cmd_addignore, "*!*@*.example.net")
    sync_irc(core, irc)
    seen = []
    irc.connection.add_global_handler("privnotice", lambda c, e: seen.append(e), 0)
    irc.connection._process_line(f":irc.example.net NOTICE {BOT} :*** Looking up your hostname")
    assert len(seen) == 1


def test_irc_cache_matches_irc_glob_case_insensitive(tmp_path):
    db = str(tmp_path / "wbs.db")
    asyncio.run(build_db(db))
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO ignores(hostmask, flags) VALUES ('[lamer]!*@*', '')")
    conn.commit()
    conn.close()
    cache = ignore_mod.IgnoreCache(db, 1)
    assert cache.match("[LAMER]!u@h") == "[lamer]!*@*"
    assert cache.match("l!u@h") is None      # `[` is a nick character, not a class
