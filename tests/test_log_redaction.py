"""
Regression tests for SAST-002: Core (`Dispatching: {etype} - {event}`) and
PluginManager (`[DISPATCH] {event_type}: {event}`) wrote the complete IRC
event dict to the DEBUG log, so `/msg <bot> identify [handle] <password>`,
an unconsumed DCC `chatauth <password>`, `.chpass <password>` and any
control characters a user typed reached the log file.  The irc library's
own DEBUG wire trace (`FROM SERVER:` / `TO SERVER:` / `command: ...,
arguments: [...]`) leaked the same text, plus the server `PASS`.

Every test turns EVERY logger to DEBUG (root, wbs.*, irc.*: what an
operator troubleshooting with full debug would do), drives real input,
and asserts that a unique marker standing for the secret/text appears in
no captured record at any level, while the useful metadata (type, nick,
channel/target, length) is still logged.

Raw server lines go through the real WbsIrcBot reactor into the real Core,
the real PluginManager, the real pubcom identify handler, the real IRC
command path and the real partyline (helpers shared with
test_irc_channel_sync / test_automode / test_flood).  Throwaway sqlite DB
per test.
"""
import asyncio
import logging
import queue
import secrets
from types import SimpleNamespace as NS

import pytest

import src.commands as commands_mod
from src.db import get_db
from src.games import GameManager
from src.plugins.pubcom import pubcomPlugin

from test_automode import env as _automode_env, flush  # noqa: E402,F401
from test_flood import FakeGame, PmDcc  # noqa: E402
from test_irc_channel_sync import BOT, pump  # noqa: E402

OWN = "own!~own@own.example"          # +n owner (test_automode.USERS)
RANDO = "rando!~r@stranger.example"   # matches no user
OWN_PW = "Own-Initial-Pass-1"


def marker(tag: str) -> str:
    """A unique, unmistakable stand-in for a secret / private text."""
    return f"SAST002{tag}{secrets.token_hex(8)}"


# ---------------------------------------------------------------------------
# Capture: every logger at DEBUG, every record formatted (incl. tracebacks)
# ---------------------------------------------------------------------------
class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        self.records: list[tuple[str, int, str]] = []

    def emit(self, record):
        self.records.append((record.name, record.levelno, self.format(record)))

    def text(self) -> str:
        return "\n".join(r[2] for r in self.records)

    def lines(self, logger: str, contains: str = "") -> list[str]:
        return [r[2] for r in self.records
                if (r[0] == logger or r[0].startswith(logger + ".")) and contains in r[2]]

    def assert_absent(self, *secrets_):
        text = self.text()
        assert self.records, "nothing was logged at all: the capture is not wired"
        for s in secrets_:
            assert s not in text, f"{s!r} leaked into the log:\n" + "\n".join(
                r[2] for r in self.records if s in r[2])


_FORCED = ("", "wbs", "wbs.core", "wbs.plugins", "wbs.plugins.pubcom", "wbs.partyline",
           "wbs.commands", "wbs.games", "wbs.irc", "wbs.dcc", "wbs.flood", "wbs.user",
           "irc", "irc.client", "irc.client_aio", "irc.bot", "irc.connection",
           "aiosqlite")


@pytest.fixture
def capture():
    """All loggers forced to DEBUG, the irc library's included."""
    import src.irc  # noqa: F401  (installs the wire-trace guard, as at runtime)
    names = set(_FORCED) | {n for n, lg in logging.root.manager.loggerDict.items()
                            if isinstance(lg, logging.Logger)}
    saved = {n: logging.getLogger(n).level for n in names}
    for n in names:
        logging.getLogger(n).setLevel(logging.DEBUG)
    handler = Capture()
    logging.getLogger().addHandler(handler)
    try:
        yield handler
    finally:
        logging.getLogger().removeHandler(handler)
        for n, level in saved.items():
            logging.getLogger(n).setLevel(level)


class Probe:
    """A plugin that sees every private/public text event (and may raise)."""
    name = "probe"

    def __init__(self):
        self.seen: list = []
        self.raise_on_text = False

    def _record(self, event):
        self.seen.append((event.get("type"), event.get("text")))
        if self.raise_on_text:
            raise ValueError(f"cannot parse {event.get('text')!r}")

    async def on_PRIVMSG(self, event):
        self._record(event)

    async def on_NOTICE(self, event):
        self._record(event)

    async def on_PUBMSG(self, event):
        self._record(event)


class Game(FakeGame):
    async def dispatch_notice(self, nick, text, event=None):
        self.priv.append((nick, text))
        return False


async def _grant_admin(db_path: str, handle: str) -> None:
    async with get_db(db_path) as d:
        await d.execute("UPDATE user_access SET is_admin = 1 WHERE handle = ?", (handle,))
        await d.commit()


@pytest.fixture
def env(_automode_env, capture):
    core, irc, sent = _automode_env
    core.game = Game()
    # A DCC layer that does not consume the line: DCC off, or a chatauth
    # whose request already expired.  The text then reaches everything.
    core.dcc = PmDcc()
    core.handlers.update({"PUBMSG": core.on_pubmsg, "PRIVMSG": core.on_privmsg,
                          "NOTICE": core.on_notice})
    pubcom = pubcomPlugin(core)
    probe = Probe()
    core.plugin.plugins = {"pubcom": pubcom, "probe": probe}
    assert asyncio.run(core.user.set_password("own", OWN_PW))
    asyncio.run(_grant_admin(core.db_path, "own"))   # +A: .+bot / .botattr
    # F-01a: owner /msg commands need settings.msg_commands and a live pubcom
    # identify session (a hostmask match alone is refused).
    core.config.setdefault("settings", {})["msg_commands"] = True
    e = NS(core=core, irc=irc, sent=sent, pubcom=pubcom, probe=probe, log=capture)
    assert any("Logged in successfully!" in line
               for line in send(e, pm(OWN, f"identify own {OWN_PW}")))
    capture.records.clear()
    return e


def send(e, *raw) -> list[str]:
    """Feed raw server lines; return the IRC lines the bot sent back."""
    out = []
    for line in raw:
        pump(e.core, e.irc, line)
        out += flush(e.core, e.irc, e.sent)
    return out


def pm(who: str, text: str) -> str:
    return f":{who} PRIVMSG {BOT} :{text}"


def assert_metadata(e, etype: str, nick: str, where: str):
    """The safe metadata is still logged by both Core and PluginManager."""
    core = e.log.lines("wbs.core", f"Dispatching: type={etype} nick={nick} {where}")
    plug = e.log.lines("wbs.plugins", f"[DISPATCH] type={etype} nick={nick} {where}")
    assert core and plug, f"no {etype} metadata for {nick} {where}:\n{e.log.text()}"
    assert all(" len=" in line for line in core + plug)


# ---------------------------------------------------------------------------
# pubcom identify
# ---------------------------------------------------------------------------
def test_identify_password_never_logged(env):
    e = env
    good = marker("idok")
    asyncio.run(e.core.user.set_password("own", good))
    bad1, bad2 = marker("idbad"), marker("idbad")
    # (Any identify drops the nick's session first: the good one goes last.)
    out = send(e, pm(OWN, f"identify {bad1}"), pm(RANDO, f"identify own {bad2}"),
               pm(OWN, f"identify own {good}"))
    # Behaviour unchanged: the real pubcom handler authenticated.
    assert any("Logged in successfully!" in line for line in out)
    assert sum("Invalid credentials!" in line for line in out) == 2
    assert e.pubcom.auth_sessions                 # session bound for own
    e.log.assert_absent(good, bad1, bad2)
    assert_metadata(e, "PRIVMSG", "own", f"target={BOT}")
    assert_metadata(e, "PRIVMSG", "rando", f"target={BOT}")
    assert e.log.lines("wbs.plugins.pubcom", "identified as own")


# ---------------------------------------------------------------------------
# DCC chatauth not consumed by the DCC layer
# ---------------------------------------------------------------------------
def test_unconsumed_chatauth_password_never_logged(env):
    e = env
    s1, s2 = marker("chatauth"), marker("chatauth")
    send(e, pm(OWN, f"chatauth {s1}"), pm(RANDO, f"chatauth {s2}"))
    assert ("PRIVMSG", f"chatauth {s1}") in e.probe.seen    # it did reach plugins
    e.log.assert_absent(s1, s2)
    assert_metadata(e, "PRIVMSG", "own", f"target={BOT}")


# ---------------------------------------------------------------------------
# Password-changing commands: /msg path and partyline path
# ---------------------------------------------------------------------------
def test_chpass_over_irc_never_logged(env):
    e = env
    new1, new2 = marker("chpass"), marker("chpass")
    out = send(e, pm(OWN, f".chpass {new1}"))
    # F-01a: changing the password revokes the identify session, so the
    # owner identifies again (with the new password) before the second form.
    out += send(e, pm(OWN, f"identify own {new1}"), pm(OWN, f"chpass own {new2}"))
    assert sum("Password updated." in line for line in out) == 2
    assert asyncio.run(e.core.user.verify_password("own", new2))
    e.log.assert_absent(new1, new2)
    assert e.log.lines("wbs.commands", "chpass: own changed password for own")
    assert_metadata(e, "PRIVMSG", "own", f"target={BOT}")


def test_botattr_pass_over_irc_never_logged(env):
    """The botlink key reaches SQL as a parameter (aiosqlite traces those
    at DEBUG): dropped as well."""
    e = env
    key = marker("botkey")

    async def add_bot():
        async with get_db(e.core.db_path) as d:
            await d.execute("INSERT INTO bots(handle, address, port, subnet_id) "
                            "VALUES ('linkbot', 'lb.example', 3333, 1)")
            await d.commit()
    asyncio.run(add_bot())
    out = send(e, pm(OWN, f"botattr linkbot pass={key}"))
    assert any("password=****" in line for line in out), out
    e.log.assert_absent(key)
    assert e.log.lines("wbs.commands", "botattr: own updated linkbot")


def test_chpass_on_partyline_never_logged(env):
    e = env
    new = marker("plchpass")
    q = queue.Queue()
    sid = e.core.partyline.register_remote("dcc", "own", q)

    async def go():
        await e.core.partyline.handle_input(sid, f".chpass {new}")
        await e.core.partyline.handle_input(sid, f".chpass own {new}x")
    asyncio.run(go())
    replies = []
    while not q.empty():
        replies.append(str(q.get_nowait()))
    assert any("Password updated." in r for r in replies)
    assert asyncio.run(e.core.user.verify_password("own", f"{new}x"))
    e.log.assert_absent(new)


@pytest.mark.parametrize("cmd", ["chpass", "passwd", "botattr"])
def test_failing_credential_command_withholds_exception_message(env, monkeypatch, cmd):
    """An exception message can quote the argument; for credential-bearing
    commands it is withheld (type and frames are still logged)."""
    e = env
    secret = marker("cmdexc")
    target = commands_mod.ALIASES.get(cmd, cmd)

    async def boom(core, handle, session_id, arg, respond):
        raise ValueError(f"invalid literal for int() with base 10: {arg!r}")
    monkeypatch.setitem(commands_mod.COMMANDS, target, boom)
    out = send(e, pm(OWN, f".{target} {secret}"))
    assert any(f"Error executing .{target}" in line for line in out)

    q = queue.Queue()
    sid = e.core.partyline.register_remote("dcc", "own", q)
    asyncio.run(e.core.partyline.handle_input(sid, f".{target} {secret}"))

    e.log.assert_absent(secret)
    errs = [r for r in e.log.records if r[1] == logging.ERROR and f"Command '{target}' error" in r[2]]
    assert len(errs) == 2                                  # IRC path + partyline path
    assert all("ValueError" in r[2] and "withheld" in r[2] and "boom" in r[2] for r in errs)


def test_failing_ordinary_command_message_is_escaped(env, monkeypatch):
    e = env

    async def boom(core, handle, session_id, arg, respond):
        raise RuntimeError("bad\x1b[2Jthing\r\nFAKE-LOG-LINE")
    monkeypatch.setitem(commands_mod.COMMANDS, "whom", boom)
    send(e, pm(OWN, ".whom"))
    errs = e.log.lines("wbs.core", "Command 'whom' error")
    assert errs and "RuntimeError" in errs[0]
    assert "bad\\x1b[2Jthing\\x0d\\x0aFAKE-LOG-LINE" in errs[0]
    assert "\x1b" not in e.log.text() and "\r\nFAKE" not in e.log.text()


# ---------------------------------------------------------------------------
# Plugin and game handler errors on private text
# ---------------------------------------------------------------------------
def test_plugin_error_on_private_text_withholds_message(env):
    e = env
    e.probe.raise_on_text = True
    secret = marker("plugexc")
    send(e, pm(OWN, f"identify own {secret}"))
    e.log.assert_absent(secret)
    errs = e.log.lines("wbs.plugins", "Plugin probe.on_PRIVMSG error")
    assert errs and "ValueError" in errs[0] and "withheld" in errs[0]
    assert "_record" in errs[0]                           # frames kept


def test_game_error_on_private_text_withholds_message(capture):
    secret = marker("gameexc")

    class Boom:
        name = "boom"
        sessions: dict = {}

        async def on_privmsg(self, nick, text, event=None):
            raise ValueError(f"bad move {text}")

        async def on_NOTICE(self, session, nick, text, event=None):
            raise ValueError(f"bad move {text}")

        def get_session(self, scope, target):
            return object()

        async def on_PUBMSG(self, session, nick, text, event=None):
            raise ValueError(f"bad move {text}")

        def request_save(self):
            pass
    gm = GameManager(NS())
    game = Boom()
    game.sessions = {"x": object()}
    gm.games = {"boom": game}

    async def go():
        await gm.dispatch_privmsg("own", f"identify own {secret}")
        await gm.dispatch_notice("own", f"!kill {secret}")
    asyncio.run(go())
    capture.assert_absent(secret)
    assert capture.lines("wbs.games", "Game boom on_privmsg error: ValueError")
    assert capture.lines("wbs.games", "Game boom on_NOTICE error: ValueError")


# ---------------------------------------------------------------------------
# Public text, private NOTICE, control characters
# ---------------------------------------------------------------------------
def test_public_and_notice_text_not_logged_metadata_kept(env):
    e = env
    pub, note = marker("pub"), marker("notice")
    send(e, f":{RANDO} PRIVMSG #wbs :hello \x1b[31m{pub}\u202e",
         f":{OWN} NOTICE {BOT} :!vote {note}")
    assert ("PUBMSG", f"hello \x1b[31m{pub}\u202e") in e.probe.seen
    e.log.assert_absent(pub, note)
    assert_metadata(e, "PUBMSG", "rando", "channel=#wbs")
    assert_metadata(e, "NOTICE", "own", f"target={BOT}")
    text = e.log.text()
    assert "\x1b" not in text and "\u202e" not in text


# ---------------------------------------------------------------------------
# IRC process: library wire trace and outbound command logging
# ---------------------------------------------------------------------------
class FakeSock:
    def __init__(self, inbound: bytes = b""):
        self.inbound = inbound
        self.out: list[bytes] = []

    def recv(self, n):
        data, self.inbound = self.inbound, b""
        return data

    def send(self, data):
        self.out.append(data)
        return len(data)


def test_irc_library_wire_trace_never_logged(env):
    """`FROM SERVER:` / `TO SERVER:` / `command: ..., arguments: [...]` are
    dropped even with irc.client explicitly at DEBUG."""
    e = env
    ident, server_pw, reply = marker("wireid"), marker("serverpass"), marker("wireout")
    conn = e.irc.connection
    del conn.send_raw                         # the real ServerConnection.send_raw
    conn.buffer = conn.buffer_class()         # set by connect() at runtime
    conn.socket = FakeSock(f"{pm(OWN, f'identify own {ident}')}\r\n".encode())
    conn.process_data()                       # real read path -> FROM SERVER
    conn.send_raw(f"PASS {server_pw}")        # real write path -> TO SERVER
    e.irc.execute_command({"cmd": "msg", "target": "own", "text": reply})
    assert any(server_pw.encode() in b for b in conn.socket.out)   # really sent
    assert any(reply.encode() in b for b in conn.socket.out)
    logging.getLogger("irc.client").debug("FROM SERVER: %s", ident)  # direct probe
    # The fixture's identify already emitted (and cleared) the lazy
    # one-off wbs.* records; keep a wbs record so "capture wired" holds.
    logging.getLogger("wbs.irc").debug("wire-trace probe done")
    e.log.assert_absent(ident, server_pw, reply)


def test_irc_command_failure_logs_metadata_only(env):
    e = env
    text = marker("cmdfail")

    def broken(_line):
        raise OSError("socket gone")
    e.irc.connection.send_raw = broken
    e.irc.execute_command({"cmd": "msg", "target": "own", "text": text})
    e.log.assert_absent(text)
    errs = e.log.lines("wbs.irc", "Command failed (cmd=msg target=own len=")
    assert errs and "OSError" in errs[0]


def test_core_irc_queue_drop_logs_metadata_only(env):
    e = env
    text = marker("qdrop")

    class FullQ:
        def put_nowait(self, payload):
            raise queue.Full()
    e.core.irc_q = FullQ()
    e.core.send_cmd("msg", "own", f"your password is {text}")
    e.log.assert_absent(text)
    assert e.log.lines("wbs.core", "IRC queue write dropped: Full — cmd=msg target=own len=")


def test_non_dict_event_logs_type_only(env):
    e = env
    text = marker("nondict")
    asyncio.run(e.core.handle_event(["PRIVMSG", f"identify {text}"]))
    e.log.assert_absent(text)
    assert e.log.lines("wbs.core", "Invalid event type received: list")


# ---------------------------------------------------------------------------
# logsafe unit level
# ---------------------------------------------------------------------------
def test_safe_escapes_controls_and_bounds():
    from src.logsafe import safe
    assert safe("a\x1b[2Jb\r\n\x00\x7f\u202e\u200b\u2028") == \
        "a\\x1b[2Jb\\x0d\\x0a\\x00\\x7f\\u202e\\u200b\\u2028"
    assert safe("\\x1b") == "\\\\x1b"                  # an escape cannot be forged
    assert safe("x" * 100, 10) == "x" * 10 + "..."
    assert safe(None) == "-" and safe(42) == "42"
    assert safe("#wbs") == "#wbs" and safe("Nïck_ü") == "Nïck_ü"


def test_event_summary_is_allow_listed():
    from src.logsafe import event_summary
    ev = {"type": "PRIVMSG", "nick": "al\x1bice", "host": "al!u@h", "target": "wI1",
          "text": "identify al hunter2", "account": "acct", "ident": "u"}
    assert event_summary("PRIVMSG", ev) == "type=PRIVMSG nick=al\\x1bice target=wI1 len=19"
    kick = {"type": "KICK", "nick": "op", "channel": "#c", "kicked": "v", "reason": "pw!"}
    assert event_summary("KICK", kick) == "type=KICK nick=op channel=#c len=3"
    assert event_summary("X", ["identify", "pw"]) == "type=X event=<list>"
    long_nick = event_summary("JOIN", {"nick": "n" * 500, "channel": "#c"})
    assert len(long_nick) < 120 and long_nick.endswith("channel=#c")


def test_cmd_and_line_summaries_have_no_payload():
    from src.logsafe import irc_cmd_summary, line_summary
    assert irc_cmd_summary({"cmd": "msg", "target": "NickServ", "text": "IDENTIFY pw"}) == \
        "cmd=msg target=NickServ len=11"
    assert irc_cmd_summary({"cmd": "raw", "line": "PASS pw"}) == "cmd=raw len=7"
    assert irc_cmd_summary("junk") == "cmd=<str>"
    assert line_summary("CMD_ROUTE subnet 1 hub - x chpass bob hunter2") == \
        "CMD_ROUTE (9 fields, 45 chars)"
    assert line_summary("UPD\x1bATE x") == "UPD\\x1bATE (2 fields, 9 chars)"


def test_credential_command_set_covers_aliases():
    from src.commands import ALIASES, COMMANDS
    from src.logsafe import CREDENTIAL_COMMANDS
    for name in ("chpass", "botattr", "fixpass"):
        assert name in COMMANDS and name in CREDENTIAL_COMMANDS
    for alias, target in ALIASES.items():
        if target in CREDENTIAL_COMMANDS:
            assert alias in CREDENTIAL_COMMANDS, alias


# ---------------------------------------------------------------------------
# SAST-002 hygiene follow-ups: three more raw-input log lines, and .baway
# ---------------------------------------------------------------------------
def test_malformed_353_logs_metadata_not_raw_arguments(env):
    e = env
    tag = marker("n353")
    # (called directly: the irc library's own 353 handler unpacks the same
    # malformed arguments and raises before ours is reached)
    e.irc.on_namreply(None, NS(arguments=["=", f"#wbs\x1b[31m{tag}\u202e"]))
    lines = e.log.lines("wbs.irc", "Malformed 353")
    assert lines, e.log.text()
    assert " len=" in lines[0]
    e.log.assert_absent(tag)
    assert "\x1b" not in e.log.text() and "\u202e" not in e.log.text()


def test_dcc_raw_arguments_debug_line_logs_metadata_not_raw_arguments(env):
    e = env
    tag = marker("dcc")
    send(e, f":{RANDO} PRIVMSG {BOT} :\x01DCC SEND {tag}.txt 2130706433 4000 99\x01")
    lines = e.log.lines("wbs.irc", "DCC raw arguments from rando")
    assert lines, e.log.text()
    assert " len=" in lines[0]
    e.log.assert_absent(tag)


def test_invalid_botlink_logs_summary_not_raw_line(capture):
    from src.net import NetListener
    tag = marker("bl")
    listener = NetListener(NS(put_nowait=lambda ev: None), {"settings": {"dev_mode": True}}, None)
    ok = asyncio.run(listener._handle_botlink(
        f"BOTLINK {tag}\x1b[31m\u202e", ("192.0.2.1", 1), "192.0.2.1", None, None))
    assert ok is False
    lines = capture.lines("wbs.net", "Invalid BOTLINK from 192.0.2.1")
    assert lines and "BOTLINK (2 fields," in lines[0]
    capture.assert_absent(tag)
    assert "\x1b" not in capture.text() and "\u202e" not in capture.text()


def test_invalid_botlink_subnet_id_logs_summary_not_raw_line(capture):
    from src.net import NetListener
    tag = marker("sid")
    listener = NetListener(NS(put_nowait=lambda ev: None), {"settings": {"dev_mode": True}}, None)
    asyncio.run(listener._handle_botlink(
        f"BOTLINK h1 {tag}\x1b[31m\u202e notanint", ("192.0.2.1", 1), "192.0.2.1", None, None))
    lines = capture.lines("wbs.net", "Invalid BOTLINK subnet_id from 192.0.2.1")
    assert lines and "BOTLINK (4 fields," in lines[0]
    capture.assert_absent(tag)
    assert "\x1b" not in capture.text() and "\u202e" not in capture.text()


class _AwayQ:
    def __init__(self):
        self.items = []

    def put_nowait(self, payload):
        self.items.append(payload)


@pytest.mark.parametrize("reason", ["gone\rQUIT :pwned", "gone\r\nQUIT :pwned", "gone\nQUIT :pwned"])
def test_baway_reason_cannot_split_the_raw_line(reason):
    core = NS(irc_q=_AwayQ(), away=None)
    said = []

    async def respond(msg):
        said.append(msg)

    asyncio.run(commands_mod.cmd_baway(core, "own", 1, reason, respond))
    (item,) = core.irc_q.items
    assert item == {"cmd": "raw", "line": "AWAY :gone QUIT :pwned"}
    assert not any(c in item["line"] for c in "\r\n")
    assert core.away == "gone QUIT :pwned"
    assert said == ["Bot is now away: gone QUIT :pwned"]


def test_baway_blank_reason_defaults_and_long_reason_is_bounded():
    core = NS(irc_q=_AwayQ(), away=None)

    async def respond(msg):
        pass

    asyncio.run(commands_mod.cmd_baway(core, "own", 1, " \r ", respond))
    assert core.irc_q.items[-1]["line"] == "AWAY :Away"
    asyncio.run(commands_mod.cmd_baway(core, "own", 1, "x" * 1000, respond))
    assert len(core.irc_q.items[-1]["line"].encode()) <= len("AWAY :") + 255
