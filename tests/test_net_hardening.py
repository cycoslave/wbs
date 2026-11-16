"""
Regression tests for NET-5, NET-8, NET-11, NET-12 and NET-13.

NET-5   .+bot / .addleaf / .addhub validate handle, address and port.
NET-8   the bot link key is never echoed or logged by .botattr.
NET-11  one `botnet` config section (legacy settings.* still read), real
        listener in .infoleaf, config validation.
NET-12  .servlinks returns the server's LINKS answer; .links is an alias.
NET-13  auth failures are keyed by (ip, handle); linked peers are exempt.

Throwaway sqlite DBs, fake cores and streams; no sockets.
"""
import asyncio
import logging

import pytest

from src import commands, ircreq
from src.configcheck import validate_config
from src.db import get_db
from src.idrules import parse_port, valid_address
from src.net import AccessGuard
from src.partyline import COMMAND_MIN_FLAGS
from src.subnet import botnet_listen, botnet_public_address

from test_console_operator import FakeCore, build_db, db_value, run_cmd  # noqa: F401
from test_config_migrations import GOOD

IP = "127.0.0.1"


@pytest.fixture
def core(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    return FakeCore(db, tmp_path)


def cmd(core, name, arg=""):
    return asyncio.run(run_cmd(core, name, "console", 0, arg))


def bot_row(core, handle):
    async def go():
        async with get_db(core.db_path) as d:
            rows = await d.execute_fetchall(
                "SELECT handle, address, port FROM bots WHERE handle = ?", (handle,))
        return rows[0] if rows else None
    return asyncio.run(go())


# ---------------------------------------------------------------------------
# NET-5
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("text,ok", [
    ("1", True), ("3333", True), ("65535", True),
    ("0", False), ("65536", False), ("-1", False), ("+5", False), ("1e3", False),
    ("abc", False), ("", False), ("33.3", False), ("00000003333", False), ("٣٣٣", False),
])
def test_parse_port(text, ok):
    assert (parse_port(text) is not None) == ok


@pytest.mark.parametrize("addr,ok", [
    ("localhost", True), ("hub1.example.org", True), ("a-b.example", True),
    ("192.0.2.10", True), ("2001:db8::1", True), ("host.example.", True),
    ("999.1.1.1", False), ("1.2.3", False), ("bad host", False), ("-a.example", False),
    ("a..b", False), ("a_b.example", False), ("x;rm", False), ("", False),
    ("a" * 64 + ".example", False), ("é.example", False),
])
def test_valid_address(addr, ok):
    assert valid_address(addr) == ok


@pytest.mark.parametrize("name,arg", [
    ("+bot", "newbot *!*@h.example h.example"), ("+bot", "newbot *!*@h.example h.example 4000"),
    ("addleaf", "newbot h.example 4000"), ("addhub", "newbot h.example 4000"),
])
def test_valid_bot_is_added(core, name, arg):
    out = cmd(core, name, arg)
    assert any("added" in l.lower() for l in out), out
    assert bot_row(core, "newbot") is not None


@pytest.mark.parametrize("name,arg,needle", [
    ("+bot", "bad!handle *!*@h h.example 3333", "Invalid handle"),
    ("+bot", "x" * 21 + " *!*@h h.example 3333", "Invalid handle"),
    ("+bot", "nb notamask h.example 3333", "Invalid hostmask"),
    ("+bot", "nb *!*@h bad..host 3333", "Invalid address"),
    ("+bot", "nb *!*@h h.example abc", "Invalid port"),
    ("+bot", "nb *!*@h h.example 70000", "Invalid port"),
    ("+bot", "nb *!*@h h.example 0", "Invalid port"),
    ("addleaf", "nb bad..host 3333", "Invalid address"),
    ("addleaf", "nb h.example abc", "Invalid port"),
    ("addleaf", "nb h.example 99999", "Invalid port"),
    ("addleaf", "bad!nb h.example 3333", "Invalid handle"),
    ("addhub", "nb bad host 3333", "Usage"),
    ("addhub", "nb h.example -5", "Invalid port"),
    ("addhub", "n/b h.example 3333", "Invalid handle"),
])
def test_invalid_input_is_refused_without_a_row(core, name, arg, needle):
    out = cmd(core, name, arg)
    assert len(out) == 1 and needle in out[0], out
    assert "Error executing" not in out[0]
    assert bot_row(core, arg.split()[0]) is None


@pytest.mark.parametrize("name,arg", [
    ("+bot", ""), ("+bot", "a"), ("+bot", "a *!*@h"), ("+bot", "a b c d e"), ("addleaf", ""), ("addleaf", "a b"),
    ("addleaf", "a b c d"), ("addhub", ""), ("addhub", "a"),
])
def test_missing_args_print_usage(core, name, arg):
    out = cmd(core, name, arg)
    assert len(out) == 1 and out[0].startswith("Usage: ."), out


@pytest.mark.parametrize("name,arg", [
    ("+bot", "peerbot *!*@h h.example"), ("+bot", "PEERBOT *!*@h h.example 3333"),
    ("addleaf", "peerbot h.example 3333"), ("addhub", "PeerBot h.example 3333"),
])
def test_duplicate_bot(core, name, arg):
    out = cmd(core, name, arg)
    assert out == [f"Bot '{arg.split()[0]}' already exists"], out


# ---------------------------------------------------------------------------
# NET-8
# ---------------------------------------------------------------------------
KEY = "s3cret-link-key-123"


def test_botattr_pass_is_masked_in_reply_and_log(core, caplog):
    caplog.set_level(logging.DEBUG)
    out = cmd(core, "botattr", f"peerbot pass={KEY}")
    assert any("password=****" in l for l in out), out
    assert not any(KEY in l for l in out), out
    assert KEY not in caplog.text
    # stored for botnet auth
    assert asyncio.run(db_value(core, "SELECT password FROM bots WHERE handle='peerbot'")) == KEY


def test_botattr_show_masks_the_key(core, caplog):
    cmd(core, "botattr", f"peerbot pass={KEY}")
    out = cmd(core, "botattr", "peerbot")
    assert len(out) == 1 and "password=****" in out[0] and KEY not in out[0], out


def test_botattr_show_without_key_has_no_password_field(core):
    out = cmd(core, "botattr", "peerbot")
    assert "password" not in out[0], out


def test_botattr_short_key_rejected_without_echo(core):
    out = cmd(core, "botattr", "peerbot pass=short")
    assert out == ["Bot password must be at least 8 characters."]


# ---------------------------------------------------------------------------
# NET-11
# ---------------------------------------------------------------------------
def test_botnet_listen_prefers_botnet_section():
    cfg = {"botnet": {"listen_host": "10.0.0.5", "listen_port": 4000},
           "settings": {"listen_host": "127.0.0.1", "listen_port": 3333}}
    assert botnet_listen(cfg) == ("10.0.0.5", 4000)


def test_botnet_listen_legacy_and_defaults():
    assert botnet_listen({"settings": {"listen_host": "127.0.0.1", "listen_port": 3999,
                                       "botnet": True}, "botnet": True}) == ("127.0.0.1", 3999)
    # F-06: unset (or empty) listen_host binds loopback; wider needs an explicit host
    assert botnet_listen({}) == ("127.0.0.1", 3333)
    assert botnet_listen({"botnet": {"listen_port": 4001}}) == ("127.0.0.1", 4001)
    assert botnet_listen({"botnet": {"listen_host": ""}}) == ("127.0.0.1", 3333)
    assert botnet_listen({"botnet": {"listen_host": "0.0.0.0"}}) == ("0.0.0.0", 3333)
    assert botnet_listen({"settings": {"listen_host": "0.0.0.0"}}) == ("0.0.0.0", 3333)


def test_public_address():
    assert botnet_public_address({"botnet": {"address": "a.example"}}) == "a.example"
    assert botnet_public_address({"botnet": {"listen_host": "10.1.1.1"}}) == "10.1.1.1"
    assert botnet_public_address({"botnet": {"listen_host": "0.0.0.0"}}) is None
    assert botnet_public_address({}) is None


def test_infoleaf_prints_real_listener(core):
    core.config["botnet"] = {"address": "a.example", "listen_host": "10.0.0.5",
                             "listen_port": 4000}
    out = cmd(core, "infoleaf")
    assert "Botnet listener: 10.0.0.5:4000" in out
    assert "  .addleaf beta a.example 4000" in out


def test_infoleaf_with_legacy_settings(core):
    core.config = {"bot": {"nick": "beta"}, "botnet": True,
                   "settings": {"listen_host": "127.0.0.1", "listen_port": 3999}}
    out = cmd(core, "infoleaf")
    assert "Botnet listener: 127.0.0.1:3999" in out
    assert "  .addleaf beta 127.0.0.1 3999" in out        # a concrete host is a usable address


def test_infoleaf_wildcard_listener_asks_for_an_address(core):
    core.config = {"bot": {"nick": "beta"},
                   "botnet": {"listen_host": "0.0.0.0", "listen_port": 3999}}
    out = cmd(core, "infoleaf")
    assert "Botnet listener: 0.0.0.0:3999" in out
    assert any("botnet.address" in l for l in out)       # tells the operator what to set
    assert "  .addleaf beta <your.host> 3999" in out


def test_addleaf_prints_reciprocal_hub_line_from_botnet_section(core):
    core.config["botnet"] = {"address": "a.example", "listen_port": 4000}
    out = cmd(core, "addleaf", "newbot h.example 4001")
    assert "  .addhub beta a.example 4000" in out


def _with(**patch):
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in GOOD.items()}
    cfg.update(patch)
    return cfg


def test_config_botnet_section_valid():
    cfg = _with(botnet={"address": "a.example", "listen_port": 3333, "relay_from": {"h": ["x"]}})
    assert validate_config(cfg) == ([], [])


@pytest.mark.parametrize("botnet,path", [
    ({"listen_port": "3333"}, "botnet.listen_port"),
    ({"listen_port": 0}, "botnet.listen_port"),
    ({"listen_port": 70000}, "botnet.listen_port"),
    ({"address": 5}, "botnet.address"),
    ({"relay_from": []}, "botnet.relay_from"),
    ({"relay_from": {"h": "x"}}, "botnet.relay_from.h"),
    ("yes", "botnet"),
])
def test_config_botnet_section_errors(botnet, path):
    errors, _ = validate_config(_with(botnet=botnet))
    assert path in [p for p, _m in errors], errors


def test_config_legacy_forms_warn_but_pass():
    errors, warnings = validate_config(_with(botnet=True))
    assert errors == [] and "botnet" in [p for p, _m in warnings]
    cfg = _with(botnet={"relay_from": {}})
    cfg["settings"] = {**cfg.get("settings", {}), "listen_port": 3333}
    errors, warnings = validate_config(cfg)
    assert errors == [] and "settings.listen_port" in [p for p, _m in warnings]


# ---------------------------------------------------------------------------
# NET-12
# ---------------------------------------------------------------------------
def test_command_tables():
    assert "servlinks" in commands.COMMANDS and "links" in commands.COMMANDS
    assert COMMAND_MIN_FLAGS["servlinks"] == COMMAND_MIN_FLAGS["links"]


LINKS = [
    "irc.a.example 364 beta * irc.a.example :0 Alpha server",
    "irc.a.example 364 beta * hub.b.example :1 Beta hub",
    "irc.a.example 365 beta * :End of /LINKS list.",
]


def feed(core, numeric, *args):
    asyncio.run(core.ircreq.on_whois_numeric(numeric, list(args)))


def start_links(core, name="servlinks"):
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    async def go():
        await commands.COMMANDS[name](core, "console", 0, "", respond)
    asyncio.run(go())
    return out


@pytest.fixture
def ircore(core):
    core.irc_q = asyncio.Queue()
    ircreq.for_core(core)
    return core


def test_servlinks_returns_the_server_list(ircore):
    out = start_links(ircore)
    assert ircore.irc_q.get_nowait() == {"cmd": "raw", "line": "LINKS"}
    feed(ircore, "364", "*", "irc.a.example", "0 Alpha server")
    feed(ircore, "364", "*", "hub.b.example", "1 Beta hub")
    assert ircore.ircreq.pending
    feed(ircore, "365", "*", "End of /LINKS list.")
    text = "\n".join(out)
    assert "irc.a.example" in text and "hops 0: Alpha server" in text
    assert "hub.b.example" in text and "hops 1: Beta hub" in text
    assert "End of LINKS (2 server(s))." in out[-1]
    assert ircore.ircreq.pending == []


def test_servlinks_not_connected(ircore):
    ircore.connected = False
    assert start_links(ircore) == ["Not connected to IRC."]
    assert ircore.irc_q.empty()


def test_servlinks_timeout(ircore):
    out = start_links(ircore)
    feed(ircore, "364", "*", "irc.a.example", "0 Alpha")
    p = ircore.ircreq.pending[0]
    asyncio.run(ircore.ircreq.expire(now=p.deadline + 1))
    assert any("No reply" in l and "incomplete" in l for l in out), out
    assert any("irc.a.example" in l for l in out)


def test_links_alias_says_so_and_still_works(ircore):
    out = start_links(ircore, "links")
    assert ".servlinks" in out[0] and "renamed" in out[0]
    feed(ircore, "364", "*", "irc.a.example", "0 Alpha")
    feed(ircore, "365", "*", "End")
    assert any("hops 0: Alpha" in l for l in out)


def test_unsolicited_links_numerics_are_ignored(ircore):
    assert asyncio.run(ircore.ircreq.on_whois_numeric("364", ["*", "x", "0 y"])) is False


def test_links_numerics_are_forwarded_by_irc():
    from src.ircreq import WHOIS_FORWARD
    assert {"364", "365"} <= WHOIS_FORWARD


# ---------------------------------------------------------------------------
# NET-13
# ---------------------------------------------------------------------------
def guard(tmp_path, live=None, **cfg):
    db = asyncio.run(build_db(tmp_path))
    g = AccessGuard(db, {"settings": {"max_failures": 3, "lockout_seconds": 300, **cfg}})
    if live is not None:
        g.live_peer_check = lambda ip, handle=None: any(
            ip == i and (handle is None or handle.lower() == h) for i, h in live)
    asyncio.run(g.load())
    return g


def fail(g, ip, handle, n=1):
    async def go():
        for _ in range(n):
            await g.record_failure(ip, handle, peer=True)
    asyncio.run(go())


def test_one_handle_locks_only_that_handle(tmp_path):
    g = guard(tmp_path)
    fail(g, IP, "rogue", 3)
    assert g.handle_locked(IP, "rogue")
    assert g.handle_locked(IP, "ROGUE")            # case-insensitive
    assert not g.handle_locked(IP, "goodbot")
    assert asyncio.run(g.denied_by(ip=IP)) is None  # address not blocked


def test_ip_threshold_is_higher_and_blocks_the_address(tmp_path):
    g = guard(tmp_path)
    assert g.max_failures_ip == 12 > g.max_failures
    fail(g, IP, "a", 3)
    fail(g, IP, "b", 3)
    fail(g, IP, "c", 3)
    assert asyncio.run(g.denied_by(ip=IP)) is None
    fail(g, IP, "d", 3)
    entry = asyncio.run(g.denied_by(ip=IP))
    assert entry is not None and entry.reason == "auth_failure"


def test_ip_threshold_configurable(tmp_path):
    g = guard(tmp_path, max_failures_ip=5)
    fail(g, IP, "a", 1)
    fail(g, IP, "b", 1)
    fail(g, IP, "c", 1)
    fail(g, IP, "d", 1)
    assert asyncio.run(g.denied_by(ip=IP)) is None
    fail(g, IP, "e", 1)
    assert asyncio.run(g.denied_by(ip=IP)) is not None
    # never lower than the per-handle threshold
    assert guard(tmp_path, max_failures_ip=1).max_failures_ip == 3


def test_linked_peer_is_exempt(tmp_path):
    g = guard(tmp_path, live=[(IP, "linked")], max_failures_ip=4)
    fail(g, IP, "linked", 10)                       # claims of a live peer are ignored
    assert not g.handle_locked(IP, "linked")
    assert g._failures.get(IP) is None
    # rogue claims from the same address never block it while a peer is linked
    fail(g, IP, "rogue", 20)
    assert g.handle_locked(IP, "rogue")
    assert asyncio.run(g.denied_by(ip=IP)) is None


def test_live_peer_is_not_locked_even_after_earlier_failures(tmp_path):
    live = []
    g = guard(tmp_path)
    g.live_peer_check = lambda ip, handle=None: (ip, (handle or "linked")) in live
    fail(g, IP, "linked", 3)
    assert g.handle_locked(IP, "linked")
    live.append((IP, "linked"))
    assert not g.handle_locked(IP, "linked")


def test_existing_failure_ban_does_not_cut_off_linked_address(tmp_path):
    g = guard(tmp_path, max_failures_ip=3)
    fail(g, IP, "rogue", 3)
    assert asyncio.run(g.denied_by(ip=IP)) is not None
    g.live_peer_check = lambda ip, handle=None: ip == IP
    ok, reason = asyncio.run(g.admit(IP))
    assert ok, reason


def test_success_clears_handle_and_ip_counters(tmp_path):
    g = guard(tmp_path)
    fail(g, IP, "good", 2)

    async def go():
        g.record_success(IP, "good")
        await asyncio.sleep(0.05)
    asyncio.run(go())
    assert g._failures.get(IP) is None
    assert not g._handle_failures
    fail(g, IP, "good", 2)
    assert not g.handle_locked(IP, "good")


def test_handle_failures_survive_restart(tmp_path):
    g = guard(tmp_path)
    fail(g, IP, "rogue", 3)
    g2 = AccessGuard(g.db_path, {"settings": {"max_failures": 3, "lockout_seconds": 300}})
    asyncio.run(g2.load())
    assert g2.handle_locked(IP, "rogue") and not g2.handle_locked(IP, "other")


def test_handle_lock_expires_after_lockout(tmp_path):
    g = guard(tmp_path)
    fail(g, IP, "rogue", 3)
    g._handle_failures[(IP, "rogue")].last_at -= 301
    assert not g.handle_locked(IP, "rogue")
    fail(g, IP, "rogue", 1)                          # window restarted: 1 failure
    assert not g.handle_locked(IP, "rogue")


def test_handle_table_is_bounded(tmp_path):
    g = guard(tmp_path, max_failures_ip=10**9, max_failures=10**9)
    g._HANDLE_TABLE_MAX = 20

    async def go():
        for i in range(60):
            await g.record_failure(IP, f"h{i}", peer=True)
    asyncio.run(go())
    assert len(g._handle_failures) <= 20


def test_partyline_failures_stay_per_ip(tmp_path):
    g = guard(tmp_path)

    async def go():
        for _ in range(3):
            await g.record_failure(IP, "alice")
    asyncio.run(go())
    assert asyncio.run(g.denied_by(ip=IP)) is not None   # telnet logins: unchanged, per IP
