"""
Live O-1: `.rehash` must keep the detected public IP, and no payload without
a command may reach the IRC process (it logged "Not connected, dropping
command: None" on the linked bot).

The public IP is learned once by the IRC process (USERHOST at registration);
a `.rehash` starts a fresh Core with a fresh DCCManager, so the IRC process
hands the IP to the new Core when it asks for the state.
"""
import ast
import asyncio
import logging
import pathlib
import queue

import pytest

from src.dcc import DCCManager

# Offline fixtures of the channel-sync suite (no tests imported by name).
from test_irc_channel_sync import make_core, make_irc, pump, build_db, BOT, SRV  # noqa: E402

PUBLIC = "47.55.38.171"
USERHOST = f"{SRV} 302 {BOT} :{BOT}=+~wbs@{PUBLIC}"


@pytest.fixture
def env(tmp_path):
    db = str(tmp_path / "wbs.db")
    asyncio.run(build_db(db))
    irc, sent = make_irc(db)
    core = make_core(db)
    core.dcc = DCCManager(core)
    return core, irc, sent


def rehash(core, config=None):
    """What the supervisor does on .rehash: a brand-new Core on the same queues."""
    fresh = make_core(core.db_path)
    if config:
        fresh.config["dcc"] = config
    fresh.dcc = DCCManager(fresh)
    fresh.handlers["BOT_PUBLIC_IP"] = fresh.on_bot_public_ip
    return fresh


def test_detected_ip_survives_rehash(env):
    core, irc, sent = env
    core.handlers["BOT_PUBLIC_IP"] = core.on_bot_public_ip
    pump(core, irc, f"{SRV} 001 {BOT} :Welcome", USERHOST)
    assert core.public_ip == PUBLIC and core.dcc.public_ip == PUBLIC

    fresh = rehash(core)
    assert fresh.dcc.public_ip is None            # what a new Core starts with
    irc.execute_command({"cmd": "state"})
    types = pump(fresh, irc)
    assert types[0] == "BOT_PUBLIC_IP" and "IRC_STATE" in types, types
    assert fresh.public_ip == PUBLIC
    assert fresh.dcc.public_ip == PUBLIC


def test_rehash_without_detected_ip_sends_none(env):
    core, irc, sent = env
    irc.execute_command({"cmd": "state"})
    fresh = rehash(core)
    types = pump(fresh, irc)
    assert "BOT_PUBLIC_IP" not in types
    assert fresh.dcc.public_ip is None


def test_configured_ip_wins_after_rehash(env):
    core, irc, sent = env
    pump(core, irc, f"{SRV} 001 {BOT} :Welcome", USERHOST)
    fresh = rehash(core, {"public_ip": "203.0.113.9"})
    irc.execute_command({"cmd": "state"})
    pump(fresh, irc)
    assert fresh.public_ip == PUBLIC              # what IRC detected is kept
    assert fresh.dcc.public_ip == "203.0.113.9"   # the operator's override wins


def test_dcc_offer_gets_an_address_after_rehash(env):
    core, irc, sent = env
    pump(core, irc, f"{SRV} 001 {BOT} :Welcome", USERHOST)
    fresh = rehash(core)
    irc.execute_command({"cmd": "state"})
    pump(fresh, irc)
    dcc = fresh.dcc
    fresh.irc_q.items.clear()

    async def authorize(nick, host):
        return "alice", ""

    async def listener(req):
        return object(), 40000

    dcc._authorize_why = authorize
    dcc._start_listener = listener
    asyncio.run(dcc._answer_client_passive("Alice", "alice@home.example", "tok"))
    texts = [p.get("text") or p.get("line") for p in fresh.irc_q.items]
    assert not any("no address to offer" in (t or "") for t in texts), texts
    ctcp = [t for t in texts if t and "DCC CHAT" in t]
    assert ctcp, texts
    assert str(int.from_bytes(bytes(map(int, PUBLIC.split("."))), "big")) in ctcp[0]


def test_commandless_payload_is_ignored_quietly(env, caplog):
    core, irc, sent = env
    irc.connection.connected = False              # even when not connected
    with caplog.at_level(logging.DEBUG):
        irc.execute_command({"type": "BOTLINK_LINK", "handle": "b", "nick": "b"})
        irc.execute_command({})
        irc.execute_command(None)
    assert sent == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], caplog.text
    assert "dropping command" not in caplog.text


def test_botlink_link_reaches_irc_as_command(env):
    core, irc, sent = env
    irc.execute_command({"cmd": "BOTLINK_LINK", "handle": "wbstestb", "nick": "wbstestb"})
    assert irc.maintenance_state["linked_bots"] == {"wbstestb": "wbstestb"}


def _irc_payload_dicts():
    for path in pathlib.Path(__file__).resolve().parent.parent.glob("src/**/*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if not (isinstance(node, ast.Call) and node.args
                    and isinstance(node.args[0], ast.Dict)):
                continue
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            owner = ast.unparse(f.value) if isinstance(f, ast.Attribute) else ""
            if name == "send_irc" or (name == "put_nowait" and owner.endswith("irc_q")):
                yield path, node.lineno, node.args[0]


def test_every_irc_payload_literal_has_a_cmd():
    """Static guard: a dict queued for the IRC process names its command."""
    bad = []
    for path, line, d in _irc_payload_dicts():
        if None in d.keys:                        # **spread: cannot tell
            continue
        keys = {k.value for k in d.keys if isinstance(k, ast.Constant)}
        if "cmd" not in keys:
            bad.append(f"{path.name}:{line} keys={sorted(keys)}")
    assert not bad, bad
