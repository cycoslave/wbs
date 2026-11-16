"""DCC-2: `.+user` grants +p by default; every ignored DCC request logs its
real reason while the IRC client sees nothing (no CTCP, no notice, no dial)."""
import asyncio
import logging

import pytest

from src import commands
from src.user import UserManager

from tests.test_user_scope import FakeCore as ScopeCore, build_db as scope_build_db
from test_dcc_negotiation import (  # noqa: F401  (fixtures + helpers)
    chat_args, db, db_template, hm, make, net, settle,
)


def _run_cmd(core, name, caller, arg):
    out = []

    async def respond(msg):
        out.append(msg)

    asyncio.run(commands.COMMANDS[name](core, caller, None, arg, respond))
    return out


def test_adduser_grants_plus_p_by_default(tmp_path):
    db_path = asyncio.run(scope_build_db(tmp_path))
    core = ScopeCore(db_path)
    out = _run_cmd(core, "+user", "ladmin", "fresh *!fresh@fresh.example")
    assert any("added" in line for line in out), out
    um = UserManager(db_path)

    async def check():
        sid = core.config["botnet"]["subnet_id"]
        assert await um.matchattr("fresh", "+p", subnet_id=sid)
        # +p only: nothing else is granted.
        for flag in ("+o", "+A", "+n", "+f", "+v"):
            assert not await um.matchattr("fresh", flag, subnet_id=sid), flag
    asyncio.run(check())


# (label, nick, host, expected log fragment)
REFUSALS = [
    ("no matching user", "Mallory", hm("Mallory", "m", "evil.example"),
     "no matching user"),
    ("lacks +p", "Np", hm("Np", "np", "np.example"), "user noparty lacks +p"),
    ("locked", "Lk", hm("Lk", "lk", "lk.example"), "user locked locked"),
]


@pytest.mark.parametrize("label,nick,host,reason", REFUSALS, ids=[r[0] for r in REFUSALS])
def test_refusal_logs_real_reason_and_stays_silent(db, net, caplog, label, nick, host, reason):
    core, mgr = make(db)
    with caplog.at_level(logging.WARNING, logger="wbs.dcc"):
        asyncio.run(mgr.handle_request(nick, host, chat_args("8.8.8.8", 5000)))
    msgs = [r.getMessage() for r in caplog.records if r.name == "wbs.dcc"]
    ignored = [m for m in msgs if "Ignored DCC request" in m]
    assert len(ignored) == 1, msgs
    assert host in ignored[0] and reason in ignored[0], ignored
    assert "unauthorized" not in ignored[0]
    # Nothing leaks to the client or the network.
    assert core.sent == []
    assert net.dials == [] and net.servers == []
    assert mgr._pending == {}
