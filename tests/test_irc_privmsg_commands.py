"""
Regression tests for USR-13 / IRC-3 / IRC-15: the IRC private-message command
path.

* USR-13 / IRC-3: Core.on_command called handlers with the old
  (config, core_q, irc_q, handle, session_key, arg) shape, so every /msg
  command from a recognised +n user ended in "Error executing .X".  It must
  use the partyline call shape and the same COMMAND_MIN_FLAGS gate.
* IRC-15: a private message from an unrecognised host gets no reply at all,
  except `identify` (answered by the pubcom plugin).

The events go through the real Core.handle_event (plugin dispatch, game
dispatch, PRIVMSG handler) with a fake IRC queue; throwaway sqlite DB, no
sockets.
"""
import asyncio
import logging
import os
import shutil
import tempfile

import bcrypt
import pytest

from src import __version__
from src.core import Core
from src.db import get_db, init_db
from src.games import GameManager
from src.partyline import Partyline
from src.plugins import PluginManager
from src.plugins.pubcom import pubcomPlugin
from src.user import UserManager

PASSWORD = "correct-horse"          # test-only fixture value
HASH = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()

BOSS = ("wboss", "wboss!~irsa@home.example")        # +n +A +o (host *!*irsa@*)
OWNER = ("wown", "wown!~own@own.example")           # +n only
PLAIN = ("wplain", "wplain!~pl@plain.example")      # recognised, +p only
STRANGER = ("rando", "rando!~x@nowhere.example")    # no matching hostmask

_TEMPLATE_DB: str | None = None


async def _fresh_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-irc3-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


async def build_db(tmp_path) -> str:
    db = str(tmp_path / "wbs.db")
    await _fresh_db(db)
    rows = {
        "boss":   ('["*!*irsa@*"]', {"has_partyline", "is_owner", "is_admin", "is_op"}),
        "owner":  ('["*!*own@own.example"]', {"has_partyline", "is_owner"}),
        "plain":  ('["*!*pl@plain.example"]', {"has_partyline"}),
        "nohost": ('[]', {"has_partyline", "is_owner"}),
    }
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one')")
        for handle, (masks, cols) in rows.items():
            await d.execute("INSERT INTO users(handle, password, hostmasks) VALUES (?, ?, ?)",
                            (handle, HASH, masks))
            names = ["handle", "channel", "subnet_id", *sorted(cols)]
            vals = [handle, None, 1, *([1] * len(cols))]
            await d.execute(
                f"INSERT INTO user_access ({', '.join(names)}) "
                f"VALUES ({', '.join('?' * len(names))})", vals)
        await d.commit()
    return db


class FakeIrcQ:
    """Collects what Core would hand to the IRC process."""

    def __init__(self):
        self.items: list[dict] = []

    def put_nowait(self, payload):
        self.items.append(payload)

    def replies_to(self, nick):
        return [p["text"] for p in self.items
                if p.get("cmd") in ("msg", "notice") and p.get("target") == nick]

    def clear(self):
        self.items.clear()


def make_core(db: str, msg_commands=True) -> Core:
    """A real Core object without its process/socket setup."""
    core = object.__new__(Core)
    core.config = {"bot": {"nick": "wU2"}, "botnet": {"subnet_id": 1},
                   "pubcom": {"channels": []}}
    if msg_commands is not None:
        core.config["settings"] = {"msg_commands": msg_commands}
    core.db_path = db
    core.botname = "wU2"
    core.irc_q = FakeIrcQ()
    core.core_q = None
    core.start_time = 0
    core.connected = True
    core.dcc = None
    core.dcc_sessions = {}
    core.party_sessions = {}
    core.botnet = None
    core.user = UserManager(db)
    core.partyline = Partyline(core)
    core.plugin = PluginManager(core)
    core.plugin.plugins["pubcom"] = pubcomPlugin(core)
    core.game = GameManager(core)
    core.handlers = {"PRIVMSG": core.on_privmsg, "COMMAND": core.on_command}
    return core


@pytest.fixture
def raw_core(tmp_path):
    """msg_commands on, nobody identified."""
    return make_core(asyncio.run(build_db(tmp_path)))


@pytest.fixture
def core(raw_core):
    """msg_commands on, and BOSS / OWNER each hold an identify session for
    their own handle (F-01a: a hostmask match alone is not enough).  PLAIN is
    left unidentified: it is refused at the +n check anyway."""
    for who, handle in ((BOSS, "boss"), (OWNER, "owner")):
        assert pm(raw_core, who, f"identify {handle} {PASSWORD}") == ["Logged in successfully!"]
    return raw_core


def pm(core, who, text):
    """Deliver a private message exactly as irc.py emits it; return replies."""
    nick, host = who
    core.irc_q.clear()
    asyncio.run(core.handle_event({"type": "PRIVMSG", "target": core.botname,
                                   "nick": nick, "host": host,
                                   "account": None, "text": text}))
    return core.irc_q.replies_to(nick)


def errored(out):
    return any("Error executing" in line for line in out)


# --- USR-13 / IRC-3: recognised owner -------------------------------------

def test_owner_help(core):
    out = pm(core, BOSS, ".help")
    assert not errored(out), out
    assert any("Wicked Bot System Help" in line for line in out), out
    assert any("+user" in line for line in out), out      # admin sections listed


def test_owner_version(core):
    assert pm(core, BOSS, ".version") == [f"WBS {__version__}"]


def test_owner_version_without_dot(core):
    assert pm(core, BOSS, "version") == [f"WBS {__version__}"]


def test_owner_whoami(core):
    assert pm(core, BOSS, ".whoami") == ["You are boss@wU2"]


def test_owner_users(core):
    out = pm(core, BOSS, ".users")
    assert not errored(out), out
    text = "\n".join(out)
    for handle in ("boss", "owner", "plain"):
        assert handle in text, out
    assert all("\n" not in line for line in out)          # one PRIVMSG per line


def test_owner_op_queues_mode(core):
    """.op replies only once the server confirms (IRC-8): the line is queued,
    nothing is claimed yet, and the bot's own MODE echo produces the reply."""
    async def getchans(subnet_id=None):
        return ["#wbs"]
    core.chan = type("Chans", (), {"getchans": staticmethod(getchans)})()
    out = pm(core, BOSS, ".op somebody #wbs")
    assert out == [], out
    assert {"cmd": "mode", "channel": "#wbs", "modes": "+o somebody"} in core.irc_q.items
    asyncio.run(core.ircreq.on_mode("#wbs", [("+", "o", "somebody")]))
    assert core.irc_q.replies_to(BOSS[0]) == ["Gave op to somebody on #wbs"]


def test_owner_without_admin_flag_is_denied(core):
    out = pm(core, OWNER, ".users")
    assert out == ["Access denied for .users (need +A)."], out


def test_owner_without_admin_flag_runs_unflagged_commands(core):
    assert pm(core, OWNER, ".whoami") == ["You are owner@wU2"]
    assert pm(core, OWNER, ".version") == [f"WBS {__version__}"]


def test_owner_unknown_command(core):
    assert pm(core, BOSS, ".nosuch") == ["Unknown command: .nosuch"]


def test_quit_over_irc_does_not_shut_down(core):
    out = pm(core, BOSS, ".quit")
    assert not errored(out), out
    assert not any(p.get("cmd") == "quit" for p in core.irc_q.items)


# --- recognised user without +n --------------------------------------------

def test_recognised_user_without_owner_flag_is_denied(core):
    for cmd in (".help", ".version", ".whoami", ".users", ".op x #wbs"):
        assert pm(core, PLAIN, cmd) == ["Access denied."], cmd
    assert not any(p.get("cmd") == "mode" for p in core.irc_q.items)


# --- IRC-15: strangers ------------------------------------------------------

@pytest.mark.parametrize("text", [".help", ".version", "hello", ".users", ".op me #wbs",
                                  ".nosuch", "chatauth x", ""])
def test_stranger_gets_no_reply(core, text):
    assert pm(core, STRANGER, text) == []
    assert core.irc_q.items == []


def test_stranger_ignore_logged_at_debug(core, caplog):
    with caplog.at_level(logging.DEBUG, logger="wbs.core"):
        pm(core, STRANGER, ".help")
    hits = [r for r in caplog.records if "unrecognised" in r.getMessage()]
    assert hits and all(r.levelno == logging.DEBUG for r in hits)


def test_stranger_identify_still_works(raw_core):
    # 'nohost' has no hostmask: the bot does not recognise the sender, but
    # identify (pubcom) still answers, and nothing else does.
    out = pm(raw_core, STRANGER, f"identify nohost {PASSWORD}")
    assert out == ["Logged in successfully!"], out
    assert raw_core.plugin.plugins["pubcom"].auth_sessions


def test_stranger_identify_bad_password(raw_core):
    assert pm(raw_core, STRANGER, "identify nohost wrong") == ["Invalid credentials!"]


def test_recognised_identify_gets_only_the_pubcom_answer(raw_core):
    # IRC-15 report: identify used to yield "Logged in successfully!" plus
    # "Access denied." / "Unknown command: .identify".
    assert pm(raw_core, PLAIN, f"identify plain {PASSWORD}") == ["Logged in successfully!"]
    assert pm(raw_core, BOSS, f"identify boss {PASSWORD}") == ["Logged in successfully!"]


# --- F-01a: msg_commands switch + identify session gate ---------------------

@pytest.mark.parametrize("setting", [None, False, "true", 1, "false"])
def test_msg_commands_off_refuses_even_when_identified(tmp_path, setting):
    """Default (absent) and any non-True value: /msg commands are refused."""
    core = make_core(asyncio.run(build_db(tmp_path)), msg_commands=setting)
    assert pm(core, BOSS, f"identify boss {PASSWORD}") == ["Logged in successfully!"]
    for cmd in (".whoami", ".version", ".users", ".help"):
        assert pm(core, BOSS, cmd) == ["Access denied."], cmd
    assert pm(core, BOSS, ".op x #wbs") == ["Access denied."]
    assert not any(p.get("cmd") == "mode" for p in core.irc_q.items)


def test_msg_commands_off_stranger_still_silent(tmp_path):
    core = make_core(asyncio.run(build_db(tmp_path)), msg_commands=False)
    assert pm(core, STRANGER, ".help") == []
    assert core.irc_q.items == []


def test_msg_commands_on_without_identify_refuses(raw_core):
    for cmd in (".whoami", ".version", ".users", ".nosuch"):
        assert pm(raw_core, BOSS, cmd) == ["Access denied."], cmd
    assert pm(raw_core, OWNER, ".whoami") == ["Access denied."]


def test_msg_commands_on_with_identify_runs(raw_core):
    assert pm(raw_core, BOSS, ".whoami") == ["Access denied."]
    assert pm(raw_core, BOSS, f"identify boss {PASSWORD}") == ["Logged in successfully!"]
    assert pm(raw_core, BOSS, ".whoami") == ["You are boss@wU2"]


def test_identify_with_wrong_password_does_not_unlock(raw_core):
    assert pm(raw_core, BOSS, "identify boss nope") == ["Invalid credentials!"]
    assert pm(raw_core, BOSS, ".whoami") == ["Access denied."]


def test_identify_session_for_other_handle_refuses(raw_core):
    # The hostmask resolves to `boss`, but the nick identified as `owner`.
    assert pm(raw_core, BOSS, f"identify owner {PASSWORD}") == ["Logged in successfully!"]
    assert pm(raw_core, BOSS, ".whoami") == ["Access denied."]
    assert pm(raw_core, BOSS, ".users") == ["Access denied."]


def test_identify_session_from_other_hostmask_refuses(raw_core):
    # Same nick identified from another connection (a stranger host).
    spoof = ("wboss", "wboss!~evil@elsewhere.example")
    assert pm(raw_core, spoof, f"identify boss {PASSWORD}") == ["Logged in successfully!"]
    # The legitimate-looking hostmask sees no session of its own.
    assert pm(raw_core, BOSS, ".whoami") == ["Access denied."]
    # The spoofed host does not match any user's hostmask: ignored silently.
    assert pm(raw_core, spoof, ".whoami") == []


def test_identify_session_still_needs_owner_flag(raw_core):
    assert pm(raw_core, PLAIN, f"identify plain {PASSWORD}") == ["Logged in successfully!"]
    assert pm(raw_core, PLAIN, ".whoami") == ["Access denied."]


def test_identify_session_still_needs_command_flag(raw_core):
    assert pm(raw_core, OWNER, f"identify owner {PASSWORD}") == ["Logged in successfully!"]
    assert pm(raw_core, OWNER, ".users") == ["Access denied for .users (need +A)."]


def test_identify_session_ends_on_nick_change(core):
    asyncio.run(core.handle_event({"type": "NICK", "nick": BOSS[0], "newnick": "wboss2",
                                   "host": BOSS[1]}))
    moved = ("wboss2", "wboss2!~irsa@home.example")
    assert pm(core, moved, ".whoami") == ["Access denied."]


def test_identify_session_expires(core):
    pubcom = core.plugin.plugins["pubcom"]
    for sess in pubcom.auth_sessions.values():
        sess["ts"] -= pubcom.auth_timeout + 1
    assert pm(core, BOSS, ".whoami") == ["Access denied."]


def test_identify_session_revoked_when_password_changes(core):
    async def change():
        async with get_db(core.db_path) as d:
            await d.execute("UPDATE users SET password=? WHERE handle='boss'",
                            (bcrypt.hashpw(b"other-pass", bcrypt.gensalt(rounds=4)).decode(),))
            await d.commit()
    asyncio.run(change())
    assert pm(core, BOSS, ".whoami") == ["Access denied."]
