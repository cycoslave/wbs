"""
Offline regression tests for SAST-005: no silent IRC TLS downgrade.

No external network. Transport is exercised against a TLS server bound to
127.0.0.1 inside the test process, using a throwaway self-signed certificate
generated with the openssl CLI into pytest's tmp_path (tests needing it are
skipped when openssl is unavailable). No bot is started.
"""
import functools
import queue
import shutil
import socket
import ssl
import subprocess
import threading
from unittest.mock import patch

import irc.bot
import irc.client
import irc.connection
import pytest

from src import irc as wbs_irc
from src.irc import (
    IrcConfigError,
    IrcServerSpec,
    WbsIrcBot,
    build_server_specs,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def make_config(servers, **bot_extra):
    bot = {"nick": "WbsTest", "user": "wbsident", "realname": "WBS Test",
           "servers": servers}
    bot.update(bot_extra)
    return {"bot": bot, "db": {"path": ":memory:"}, "id": 7}


def make_bot(config):
    return WbsIrcBot(config, queue.Queue(), queue.Queue())


def drain(q):
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except queue.Empty:
            return out


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    """Self-signed cert valid for DNS:localhost only (not for 127.0.0.1)."""
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not available")
    d = tmp_path_factory.mktemp("tls")
    crt, key = d / "srv.crt", d / "srv.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "2",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign"],
        check=True, capture_output=True,
    )
    return str(crt), str(key)


class TlsServer:
    """One-shot loopback TLS server; records handshake result and IRC lines."""

    def __init__(self, crt, key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(crt, key)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.sock.settimeout(10)
        self.port = self.sock.getsockname()[1]
        self.handshake_ok = None
        self.lines: list[str] = []
        self.plaintext_bytes = b""
        self.done = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        try:
            raw, _ = self.sock.accept()
        except OSError:
            self.done.set()
            return
        raw.settimeout(10)
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            self.handshake_ok = False
            self.done.set()
            raw.close()
            return
        self.handshake_ok = True
        buf = b""
        try:
            while b"USER " not in buf or not buf.endswith(b"\r\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        self.lines = buf.decode(errors="replace").split("\r\n")
        self.done.set()
        conn.close()

    def close(self):
        self.done.wait(10)
        self.sock.close()


def close_bot(bot):
    try:
        if bot.connection.socket is not None:
            bot.connection.socket.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# audit repro: configured TLS endpoint is preserved, no legacy fallback
# ---------------------------------------------------------------------------
def test_tls_only_endpoint_preserved_not_default_plaintext():
    """The audit repro: this config used to become irc.wcksoft.com:6667."""
    cfg = make_config([{"host": "irc.invalid", "port": 6697, "ssl": True,
                        "password": "srvpass"}])
    specs = build_server_specs(cfg)
    assert len(specs) == 1
    sp = specs[0]
    assert (sp.host, sp.port, sp.password, sp.tls) == ("irc.invalid", 6697, "srvpass", True)

    bot = make_bot(cfg)
    listed = bot.servers.peek()
    assert isinstance(listed, IrcServerSpec)
    assert (listed.host, listed.port, listed.tls) == ("irc.invalid", 6697, True)
    assert "irc.wcksoft.com" not in repr(listed)


def test_legacy_top_level_server_keys_are_not_a_fallback():
    cfg = {"server": "irc.wcksoft.com", "port": 6667, "bot": {"nick": "x"},
           "db": {"path": ":memory:"}}
    with pytest.raises(IrcConfigError, match="bot.servers"):
        make_bot(cfg)


# ---------------------------------------------------------------------------
# TLS factory is actually applied at connect time
# ---------------------------------------------------------------------------
def test_connect_uses_per_server_tls_factory_with_verifying_context():
    cfg = make_config([{"host": "irc.invalid", "port": 6697, "ssl": True}])
    bot = make_bot(cfg)
    with patch.object(irc.client.ServerConnection, "connect") as conn:
        bot._connect()
    conn.assert_called_once()
    args, kwargs = conn.call_args
    assert args[:2] == ("irc.invalid", 6697)
    assert kwargs["username"] == "wbsident"
    factory = kwargs["connect_factory"]
    assert isinstance(factory, irc.connection.Factory)
    wrapper = factory.wrapper
    assert isinstance(wrapper, functools.partial)
    assert wrapper.keywords == {"server_hostname": "irc.invalid"}
    ctx = wrapper.func.__self__
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_plain_server_uses_identity_factory():
    cfg = make_config([{"host": "irc.invalid", "port": 6667, "ssl": False}])
    bot = make_bot(cfg)
    with patch.object(irc.client.ServerConnection, "connect") as conn:
        bot._connect()
    factory = conn.call_args.kwargs["connect_factory"]
    assert not isinstance(factory.wrapper, functools.partial)


def test_tls_handshake_and_username_end_to_end(cert):
    """Real bot._connect over loopback TLS: handshake OK, USER carries bot.user."""
    crt, key = cert
    srv = TlsServer(crt, key)
    cfg = make_config([{"host": "localhost", "port": srv.port, "ssl": True,
                        "ssl_ca_file": crt}])
    bot = make_bot(cfg)
    try:
        bot._connect()
        assert srv.done.wait(10)
        assert srv.handshake_ok is True
        assert isinstance(bot.connection.socket, ssl.SSLSocket)
        assert "NICK WbsTest" in srv.lines
        assert any(l.startswith("USER wbsident ") and l.endswith(":WBS Test")
                   for l in srv.lines), srv.lines
    finally:
        close_bot(bot)
        srv.close()
    assert not [e for e in drain(bot.core_q) if e.get("data") == "connect_fail"]


def test_username_falls_back_to_nick_when_user_unset():
    cfg = make_config([{"host": "irc.invalid", "port": 6697, "ssl": True}])
    del cfg["bot"]["user"]
    bot = make_bot(cfg)
    with patch.object(irc.client.ServerConnection, "connect") as conn:
        bot._connect()
    assert conn.call_args.kwargs["username"] is None  # library then uses nick


# ---------------------------------------------------------------------------
# invalid certificate / hostname fails closed (no plaintext retry)
# ---------------------------------------------------------------------------
def _assert_fails_closed(bot, srv):
    calls = []
    real = irc.client.ServerConnection.connect

    def spy(self, *a, **kw):
        calls.append(kw["connect_factory"])
        return real(self, *a, **kw)

    with patch.object(irc.client.ServerConnection, "connect", spy), \
         patch.object(bot.recon, "run") as recon:
        bot._connect()
    assert srv.done.wait(10)
    assert srv.handshake_ok is False
    assert len(calls) == 1 and isinstance(calls[0].wrapper, functools.partial)
    assert srv.lines == []  # nothing (e.g. PASS/NICK) sent in the clear
    assert not bot.connection.connected
    events = drain(bot.core_q)
    fails = [e for e in events if e.get("data") == "connect_fail"]
    assert len(fails) == 1 and "certificate verify failed" in fails[0]["error"].lower()
    recon.assert_called_once()  # normal reconnect path, not a downgrade


def test_untrusted_certificate_rejected(cert):
    crt, key = cert
    srv = TlsServer(crt, key)
    cfg = make_config([{"host": "localhost", "port": srv.port, "ssl": True,
                        "password": "srvpass"}])  # no ssl_ca_file -> system trust
    bot = make_bot(cfg)
    try:
        _assert_fails_closed(bot, srv)
    finally:
        close_bot(bot)
        srv.close()


def test_hostname_mismatch_rejected(cert):
    crt, key = cert
    srv = TlsServer(crt, key)
    # Trusted CA, but the cert is for 'localhost', not '127.0.0.1'.
    cfg = make_config([{"host": "127.0.0.1", "port": srv.port, "ssl": True,
                        "ssl_ca_file": crt}])
    bot = make_bot(cfg)
    try:
        _assert_fails_closed(bot, srv)
    finally:
        close_bot(bot)
        srv.close()


# ---------------------------------------------------------------------------
# malformed / insecure TLS config is fatal at construction
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("entry, match", [
    ({"host": "irc.invalid", "port": 6697, "ssl": True, "ssl_verify": False},
     "ssl_verify=false"),
    ({"host": "irc.invalid", "port": 6697, "ssl": "yes"}, "'ssl' must be"),
    ({"host": "irc.invalid", "port": 6697, "ssl": 1}, "'ssl' must be"),
    ({"host": "irc.invalid", "port": 6697, "ssl": True, "ssl_verify": "no"},
     "'ssl_verify' must be"),
    ({"host": "irc.invalid", "port": 6697, "ssl": True,
      "ssl_ca_file": "/nonexistent/ca.pem"}, "cannot load ssl_ca_file"),
    ({"host": "irc.invalid", "port": 6697, "ssl": True, "ssl_ca_file": ""},
     "ssl_ca_file"),
    ({"host": "irc.invalid", "port": 6697, "ssl_verify": True},
     "'ssl' is not true"),
    ({"host": "irc.invalid", "port": 6697, "tls": True}, "unknown key"),
    ({"host": "irc.invalid", "ssl": True}, "'port'"),
    ({"host": "irc.invalid", "port": 70000, "ssl": True}, "'port'"),
    ({"host": "irc.invalid", "port": True, "ssl": True}, "'port'"),
    ({"port": 6697, "ssl": True}, "'host'"),
    ({"host": "", "port": 6697, "ssl": True}, "'host'"),
    ({"host": "irc.invalid", "port": 6697, "ssl": True, "password": 123},
     "'password'"),
    ("irc.invalid:6697", "must be an object"),
])
def test_malformed_server_entry_rejected(entry, match):
    cfg = make_config([entry])
    with pytest.raises(IrcConfigError, match=match):
        build_server_specs(cfg)
    core_q = queue.Queue()
    with patch.object(irc.client.ServerConnection, "connect") as conn:
        with pytest.raises(IrcConfigError):
            WbsIrcBot(cfg, core_q, queue.Queue())
    conn.assert_not_called()
    events = drain(core_q)
    assert events and events[0]["data"] == "config_invalid"
    assert not any(e.get("type") == "REQUEST_BOTLINKS" for e in events)


@pytest.mark.parametrize("servers", [None, [], "irc.invalid", {"host": "x"}])
def test_missing_or_bad_server_list_rejected(servers):
    with pytest.raises(IrcConfigError, match="bot.servers"):
        build_server_specs(make_config(servers))


def test_bad_ca_file_contents_rejected(tmp_path):
    bad = tmp_path / "ca.pem"
    bad.write_text("not a certificate\n")
    cfg = make_config([{"host": "irc.invalid", "port": 6697, "ssl": True,
                        "ssl_ca_file": str(bad)}])
    with pytest.raises(IrcConfigError, match="cannot load ssl_ca_file"):
        build_server_specs(cfg)


def test_one_bad_entry_rejects_whole_list():
    cfg = make_config([
        {"host": "a.invalid", "port": 6697, "ssl": True},
        {"host": "b.invalid", "port": 6697, "ssl": True, "ssl_verify": False},
    ])
    with pytest.raises(IrcConfigError, match=r"bot\.servers\[1\]"):
        build_server_specs(cfg)


def test_verifying_context_guard(monkeypatch):
    """If the default context were ever non-verifying, refuse it."""
    def weak(**kw):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    monkeypatch.setattr(wbs_irc.ssl_lib, "create_default_context", weak)
    with pytest.raises(IrcConfigError, match="not verifying"):
        build_server_specs(make_config([{"host": "a.invalid", "port": 6697, "ssl": True}]))


def test_spec_refuses_tls_without_context():
    with pytest.raises(IrcConfigError):
        IrcServerSpec("a.invalid", 6697, tls=True, ssl_context=None)


def test_connect_refuses_spec_without_transport_policy():
    bot = make_bot(make_config([{"host": "a.invalid", "port": 6697, "ssl": True}]))
    import itertools, more_itertools
    bot.servers = more_itertools.peekable(itertools.cycle(
        [irc.bot.ServerSpec("irc.wcksoft.com", 6667)]))
    with patch.object(irc.client.ServerConnection, "connect") as conn:
        with pytest.raises(IrcConfigError, match="no transport policy"):
            bot._connect()
    conn.assert_not_called()


# ---------------------------------------------------------------------------
# mixed TLS / plaintext server policy is explicit
# ---------------------------------------------------------------------------
MIXED = [
    {"host": "tls.invalid", "port": 6697, "ssl": True},
    {"host": "plain.invalid", "port": 6667, "ssl": False},
]


def test_mixed_list_rejected_by_default():
    with pytest.raises(IrcConfigError, match="mixes TLS and plaintext"):
        build_server_specs(make_config(MIXED))


def test_mixed_list_flag_must_be_bool():
    with pytest.raises(IrcConfigError, match="allow_plaintext_fallback"):
        build_server_specs(make_config(MIXED, allow_plaintext_fallback="true"))


def test_mixed_list_opt_in_keeps_per_server_transport():
    bot = make_bot(make_config(MIXED, allow_plaintext_fallback=True))
    seen = []
    with patch.object(irc.client.ServerConnection, "connect") as conn:
        for _ in range(4):
            bot._connect()
            a, kw = conn.call_args
            seen.append((a[0], a[1], isinstance(kw["connect_factory"].wrapper,
                                                functools.partial)))
            next(bot.servers)
    assert seen == [
        ("tls.invalid", 6697, True), ("plain.invalid", 6667, False),
        ("tls.invalid", 6697, True), ("plain.invalid", 6667, False),
    ]


def test_all_tls_list_rotation_never_plaintext():
    cfg = make_config([
        {"host": "a.invalid", "port": 6697, "ssl": True},
        {"host": "b.invalid", "port": 7000, "ssl": True},
    ])
    bot = make_bot(cfg)
    with patch.object(irc.client.ServerConnection, "connect") as conn:
        for _ in range(4):
            bot._connect()
            kw = conn.call_args.kwargs
            assert kw["connect_factory"].wrapper.keywords["server_hostname"] == conn.call_args.args[0]
            next(bot.servers)
    assert [c.args[:2] for c in conn.call_args_list] == [
        ("a.invalid", 6697), ("b.invalid", 7000)] * 2


def test_all_plaintext_list_allowed_without_flag():
    specs = build_server_specs(make_config([
        {"host": "a.invalid", "port": 6667},
        {"host": "b.invalid", "port": "6668", "ssl": False, "password": None},
    ]))
    assert [(s.host, s.port, s.tls) for s in specs] == [
        ("a.invalid", 6667, False), ("b.invalid", 6668, False)]


# ---------------------------------------------------------------------------
# F-02: botnet outgoing link TLS -- ssl_ca_file, ssl_fingerprint, ssl_verify=false
# ---------------------------------------------------------------------------
import asyncio
import hashlib
import logging

from tests.test_botlink_auth import make_mgr as _link_mgr
from src.db import get_db


def _cert_fp(crt_path, colons=False):
    der = ssl.PEM_cert_to_DER_cert(open(crt_path).read())
    h = hashlib.sha256(der).hexdigest()
    return ":".join(h[i:i + 2] for i in range(0, 64, 2)).upper() if colons else h


async def _link_attempt(tmp_path, cert, settings):
    """connect_peer('beta') from alpha to a loopback TLS server.

    Returns (mgr, hello_lines, link_started). Nothing outside 127.0.0.1.
    """
    crt, key = cert
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(crt, key)
    got: list[bytes] = []

    async def handle(reader, writer):
        try:
            line = await asyncio.wait_for(reader.readline(), 3)
            if line:  # EOF (b"") means the client sent nothing
                got.append(line)
        except Exception:
            pass
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=sctx)
    port = server.sockets[0].getsockname()[1]
    try:
        mgr = await _link_mgr(tmp_path, "alpha", {"beta": "link-key-for-test-0123456789"},
                              settings=settings)
        async with get_db(mgr.db_path) as d:
            await d.execute("UPDATE bots SET address='localhost', port=? WHERE handle='beta'",
                            (port,))
            await d.commit()

        async def _nop(*a, **k):
            return None
        mgr.read_peer = _nop  # no read loop; we only care about connect + hello
        await mgr.connect_peer("beta")
        await asyncio.sleep(0.3)
        started = bool(mgr._handshakes)
        for w in list(mgr._handshakes):
            w.close()
        return mgr, got, started
    finally:
        server.close()
        await server.wait_closed()


def _attempt(tmp_path, cert, **settings):
    return asyncio.run(_link_attempt(tmp_path, cert, {"ssl": True, **settings}))


def test_botlink_default_still_rejects_untrusted_self_signed(tmp_path, cert):
    _, got, started = _attempt(tmp_path, cert)
    assert not started and got == []


def test_botlink_ca_file_verifies_and_links(tmp_path, cert):
    _, got, started = _attempt(tmp_path, cert, ssl_ca_file=cert[0])
    assert started
    assert got and got[0].startswith(b"BOTLINK alpha beta ")


def test_botlink_ca_file_keeps_verification_on(tmp_path, cert):
    # A CA that did not sign the peer cert must still be rejected.
    other = tmp_path / "other.crt"
    other_key = tmp_path / "other.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(other_key), "-out", str(other), "-days", "2",
         "-subj", "/CN=other", "-addext", "basicConstraints=critical,CA:TRUE"],
        check=True, capture_output=True)
    _, got, started = _attempt(tmp_path, cert, ssl_ca_file=str(other))
    assert not started and got == []


def test_botlink_bad_ca_file_refuses_link(tmp_path, cert, caplog):
    with caplog.at_level(logging.ERROR, logger="wbs.botnet"):
        _, got, started = _attempt(tmp_path, cert, ssl_ca_file=str(tmp_path / "missing.pem"))
    assert not started and got == []
    assert any("ssl_ca_file" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("colons", [False, True])
def test_botlink_pin_match_links_self_signed(tmp_path, cert, colons):
    _, got, started = _attempt(tmp_path, cert, ssl_fingerprint=_cert_fp(cert[0], colons))
    assert started
    assert got and got[0].startswith(b"BOTLINK alpha beta ")


def test_botlink_pin_mismatch_drops_link(tmp_path, cert, caplog):
    with caplog.at_level(logging.WARNING, logger="wbs.botnet"):
        mgr, got, started = _attempt(tmp_path, cert, ssl_fingerprint="00" * 32)
    assert not started and got == []
    assert "beta" not in mgr.peers
    assert any("beta" in r.getMessage() and "fingerprint" in r.getMessage()
               for r in caplog.records if r.levelno == logging.WARNING)


def test_botlink_pin_with_ca_file_checks_both(tmp_path, cert):
    _, got, started = _attempt(tmp_path, cert, ssl_ca_file=cert[0],
                               ssl_fingerprint=_cert_fp(cert[0]))
    assert started and got
    _, got, started = _attempt(tmp_path, cert, ssl_ca_file=cert[0],
                               ssl_fingerprint="11" * 32)
    assert not started and got == []


def test_botlink_malformed_pin_refuses_link(tmp_path, cert):
    _, got, started = _attempt(tmp_path, cert, ssl_fingerprint="not-a-digest")
    assert not started and got == []


def test_botlink_ssl_verify_false_still_links_and_warns(tmp_path, cert, caplog):
    with caplog.at_level(logging.WARNING, logger="wbs.botnet"):
        _, got, started = _attempt(tmp_path, cert, ssl_verify=False)
    assert started and got
    warns = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("beta" in m and "verification is OFF" in m for m in warns)


def test_botlink_ssl_verify_false_startup_warning(tmp_path, caplog):
    async def go():
        mgr = await _link_mgr(tmp_path, "alpha", {}, settings={"ssl": True, "ssl_verify": False})
        with caplog.at_level(logging.WARNING, logger="wbs.botnet"):
            await mgr.start()
    asyncio.run(go())
    assert any(r.levelno == logging.WARNING and "ssl_verify=false" in r.getMessage()
               and "OFF" in r.getMessage() for r in caplog.records)


def test_botlink_default_startup_has_no_tls_warning(tmp_path, caplog):
    async def go():
        mgr = await _link_mgr(tmp_path, "alpha", {}, settings={"ssl": True})
        with caplog.at_level(logging.WARNING, logger="wbs.botnet"):
            await mgr.start()
    asyncio.run(go())
    assert not any("ssl_verify" in r.getMessage() for r in caplog.records)
