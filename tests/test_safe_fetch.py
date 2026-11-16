"""
Offline regression tests for SAST-008: plugin SSRF, redirect and DNS gaps.

No external network and no production probes:
  * every hostname is answered by an in-process FakeResolver (unknown names
    fail); an autouse guard makes aiohttp's default resolver and
    socket.getaddrinfo refuse anything that is not a numeric loopback bind;
  * the only HTTP endpoint is an aiohttp test server bound to 127.0.0.1 in
    this process. It routes on the Host header, so "public.test" etc. are
    simulated public sites. Loopback is reachable only because these tests
    explicitly authorize 127.0.0.1/32 in their policy (allow_networks);
    the default policy denies it (asserted below).
No bot is started and no IRC connection is made.
"""
import asyncio
import gzip
import ipaddress
import socket
import urllib.parse
from types import SimpleNamespace as NS
from unittest.mock import patch

import aiohttp
import pytest
from aiohttp import web

from src import safehttp
from src.plugins import pubcom as pubcom_mod
from src.plugins.pubcom import YOUTUBE_HOSTS, pubcomPlugin
from src.plugins.url import urlPlugin
from src.safehttp import (
    FetchBlocked,
    FetchBusy,
    FetchTimeout,
    FetchTooLarge,
    SafeFetchPolicy,
    SafeHttpClient,
    ip_denial_reason,
    resolve_public,
)

LOOPBACK = "127.0.0.1"


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# network guards / fakes
# ---------------------------------------------------------------------------
_real_getaddrinfo = socket.getaddrinfo


def _guarded_getaddrinfo(host, *args, **kwargs):
    """Allow only numeric loopback lookups (the test server's own bind)."""
    try:
        if host is None or ipaddress.ip_address(host).is_loopback:
            return _real_getaddrinfo(host, *args, **kwargs)
    except ValueError:
        pass
    raise AssertionError(f"real DNS lookup attempted for {host!r}")


class _ForbiddenResolver(aiohttp.abc.AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        raise AssertionError(f"default resolver used for {host!r}")

    async def close(self):
        pass


@pytest.fixture(autouse=True)
def no_real_dns():
    with patch.object(socket, "getaddrinfo", _guarded_getaddrinfo), \
            patch.object(aiohttp, "DefaultResolver", _ForbiddenResolver):
        yield


class FakeResolver(aiohttp.abc.AbstractResolver):
    """Deterministic resolver. ``table[host]`` is a list of addresses, or a
    list of lists consumed one per call (to simulate DNS rebinding)."""

    def __init__(self, table):
        self.table = {k.lower(): v for k, v in table.items()}
        self.calls = []

    async def resolve(self, host, port=0, family=socket.AF_INET):
        host = host.lower().rstrip(".")
        self.calls.append(host)
        if host not in self.table:
            raise OSError(f"NXDOMAIN {host}")
        entry = self.table[host]
        if entry and isinstance(entry[0], list):
            addrs = entry.pop(0) if len(entry) > 1 else entry[0]
        else:
            addrs = entry
        out = []
        for a in addrs:
            fam = socket.AF_INET6 if ":" in a else socket.AF_INET
            out.append({"hostname": host, "host": a, "port": port, "family": fam,
                        "proto": 0, "flags": socket.AI_NUMERICHOST})
        return out

    async def close(self):
        pass


# ---------------------------------------------------------------------------
# mocked endpoint
# ---------------------------------------------------------------------------
HTML_OK = b"<html><head><title> Example  Domain </title></head><body>hi</body></html>"
HTML_META = (b'<html><head><meta property="og:title" content="Meta Only Title">'
             b"</head><body></body></html>")


class MockSite:
    """aiohttp server on 127.0.0.1; routes on Host header + path."""

    def __init__(self):
        self.requests = []   # (host, path)
        self.port = None
        self._runner = None

    async def __aenter__(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self.handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, LOOPBACK, 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        await self._runner.cleanup()

    def url(self, host, path="/"):
        return f"http://{host}:{self.port}{path}"

    async def handle(self, request):
        host = request.host.split(":")[0].lower()
        path = request.path
        self.requests.append((host, path))
        if path == "/title":
            return web.Response(body=HTML_OK, content_type="text/html")
        if path == "/meta":
            return web.Response(body=HTML_META, content_type="text/html")
        if path == "/json":
            return web.json_response({"ok": True})
        if path.startswith("/redirect/"):
            # /redirect/<target-host>/<target-path...>  (target '_abs' = raw)
            _, _, target_host, *rest = path.split("/")
            target = request.query.get("to") or \
                f"http://{target_host}:{self.port}/{'/'.join(rest)}"
            raise web.HTTPFound(target)
        if path == "/loop":
            raise web.HTTPFound(self.url(host, "/loop"))
        if path == "/huge":
            resp = web.StreamResponse(headers={"Content-Type": "text/html"})
            await resp.prepare(request)
            chunk = b"<p>" + b"A" * 65536 + b"</p>"
            try:
                for _ in range(200):  # ~13 MB if fully read
                    await resp.write(chunk)
            except (ConnectionResetError, RuntimeError):
                pass
            return resp
        if path == "/huge-declared":
            body = b"<title>x</title>" + b"B" * 3_000_000
            return web.Response(body=body, content_type="text/html")
        if path == "/gzip-bomb":
            raw = b"<html><head><title>bomb</title></head>" + b"\0" * 40_000_000
            return web.Response(body=gzip.compress(raw, 9),
                                headers={"Content-Type": "text/html",
                                         "Content-Encoding": "gzip"})
        if path == "/gzip-ok":
            return web.Response(body=gzip.compress(HTML_OK),
                                headers={"Content-Type": "text/html",
                                         "Content-Encoding": "gzip"})
        if path == "/slow":
            await asyncio.sleep(5)
            return web.Response(body=HTML_OK, content_type="text/html")
        if path == "/binary":
            return web.Response(body=b"\x89PNG" + b"0" * 100, content_type="image/png")
        return web.Response(status=404, text="nope")


def make_client(port, table, **policy_kw):
    """Client whose policy authorizes only 127.0.0.1/32 (the mock server)."""
    kw = dict(ports=frozenset({80, 443, port}), allow_networks=("127.0.0.1/32",),
              total_timeout=5.0, connect_timeout=2.0)
    kw.update(policy_kw)
    resolver = FakeResolver(table)
    return SafeHttpClient(SafeFetchPolicy(**kw), resolver=resolver), resolver


PUBLIC_TABLE = {
    "public.test": [LOOPBACK],
    "other.test": [LOOPBACK],
    "internal.test": ["10.0.0.7"],
    "metadata.test": ["169.254.169.254"],
    "mapped.test": ["::ffff:10.0.0.1"],
    "mixed.test": [LOOPBACK, "192.168.1.10"],
    "loop6.test": ["::1"],
}


# ---------------------------------------------------------------------------
# address / URL policy (pure, no I/O)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("addr", [
    "127.0.0.1", "127.8.9.10", "10.1.2.3", "172.16.5.4", "192.168.0.1",
    "169.254.169.254", "100.64.0.1", "0.0.0.0", "255.255.255.255",
    "224.0.0.1", "240.0.0.1", "192.0.2.5", "198.18.0.1", "192.0.0.8",
    "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "fec0::1", "ff02::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
    "::127.0.0.1", "2002:7f00:1::1", "2002:0a00:0001::1", "64:ff9b::a00:1",
    "64:ff9b:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:db8::1",
])
def test_internal_addresses_are_denied(addr):
    assert ip_denial_reason(ipaddress.ip_address(addr)) is not None
    assert SafeFetchPolicy().address_denial(addr) is not None


@pytest.mark.parametrize("addr", ["93.184.216.34", "1.1.1.1", "2606:4700::1111",
                                  "::ffff:93.184.216.34", "2002:5db8:d822::1"])
def test_public_addresses_are_allowed(addr):
    assert SafeFetchPolicy().address_denial(addr) is None


def test_allow_networks_is_explicit_and_narrow():
    pol = SafeFetchPolicy(allow_networks=("127.0.0.1/32",))
    assert pol.address_denial("127.0.0.1") is None
    assert pol.address_denial("127.0.0.2") is not None
    # a mapped form of the authorized address is NOT implicitly authorized
    assert pol.address_denial("::ffff:127.0.0.1") is not None
    assert SafeFetchPolicy().address_denial("127.0.0.1") is not None


@pytest.mark.parametrize("url", [
    "ftp://example.com/", "file:///etc/passwd", "gopher://example.com/",
    "http://localhost/", "http://LOCALHOST./", "http://foo.localhost/",
    "http://printer.local/", "http://metadata.google.internal/",
    "http://127.0.0.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
    "http://10.0.0.1/", "http://169.254.169.254/latest/meta-data/",
    "http://2130706433/", "http://0x7f000001/", "http://127.1/",
    "http://017700000001/", "http://0x7f.0.0.1/",
    "http://user:pw@example.com/", "http://example.com@10.0.0.1/",
    "http://example.com:22/", "http://example.com:6379/",
    "http:///nohost", "http://exa mple.com/",
])
def test_check_url_rejects_before_any_dns(url):
    with pytest.raises(FetchBlocked):
        SafeFetchPolicy().check_url(url)


def test_check_url_allowlist_is_exact():
    pol = SafeFetchPolicy()
    pol.check_url("https://www.youtube.com/watch?v=x", allowed_hosts=YOUTUBE_HOSTS)
    for bad in ("https://youtube.com.evil.test/", "https://evil-youtube.com/",
                "https://notyoutu.be/x", "https://www.youtube.com.attacker.net/",
                "https://youtube.com@evil.test/"):
        with pytest.raises(FetchBlocked):
            pol.check_url(bad, allowed_hosts=YOUTUBE_HOSTS)


# ---------------------------------------------------------------------------
# SafeHttpClient against the mocked endpoint
# ---------------------------------------------------------------------------
def test_public_title_fetch_works_through_pinned_connector():
    async def go():
        async with MockSite() as site:
            client, resolver = make_client(site.port, PUBLIC_TABLE)
            try:
                res = await client.fetch(site.url("public.test", "/title"))
            finally:
                await client.close()
            return res, resolver, site, client
    res, resolver, site, client = run(go())
    assert res.status == 200 and b"Example" in res.body
    assert resolver.calls == ["public.test"]
    assert site.requests == [("public.test", "/title")]
    assert client.dials == 1 and client.blocked_dials == 0


def test_default_policy_never_dials_loopback_even_via_dns():
    async def go():
        async with MockSite() as site:
            resolver = FakeResolver({"public.test": [LOOPBACK]})
            client = SafeHttpClient(SafeFetchPolicy(ports=frozenset({site.port})),
                                    resolver=resolver)
            try:
                with pytest.raises(FetchBlocked):
                    await client.fetch(site.url("public.test", "/title"))
            finally:
                await client.close()
            return site, client, resolver
    site, client, resolver = run(go())
    assert site.requests == [] and client.dials == 0
    assert resolver.calls == ["public.test"]


@pytest.mark.parametrize("host", ["internal.test", "metadata.test", "mapped.test",
                                  "mixed.test", "loop6.test"])
def test_hostnames_resolving_internal_are_never_dialled(host):
    async def go():
        async with MockSite() as site:
            client, _resolver = make_client(site.port, PUBLIC_TABLE)
            sock_calls = []
            real_socket = socket.socket

            def spy(*a, **k):
                sock_calls.append((a, k))
                return real_socket(*a, **k)
            try:
                with patch.object(safehttp.socket, "socket", spy):
                    with pytest.raises(FetchBlocked):
                        await client.fetch(site.url(host, "/title"))
            finally:
                await client.close()
            return site, client, sock_calls
    site, client, sock_calls = run(go())
    assert site.requests == []
    assert client.dials == 0
    assert sock_calls == []


@pytest.mark.parametrize("target", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.2:{port}/title",
    "http://[::ffff:127.0.0.1]:{port}/title",
    "http://localhost:{port}/title",
    "http://internal.test:{port}/title",
    "http://mapped.test:{port}/title",
    "http://2130706433:{port}/title",
    "file:///etc/passwd",
    "http://public.test:22/",
])
def test_redirects_to_internal_are_revalidated_and_not_dialled(target):
    async def go():
        async with MockSite() as site:
            client, _resolver = make_client(site.port, PUBLIC_TABLE)
            to = target.format(port=site.port)
            try:
                with pytest.raises(FetchBlocked):
                    await client.fetch(site.url("public.test", "/redirect/_abs")
                                       + "?to=" + urllib.parse.quote(to, safe=""))
            finally:
                await client.close()
            return site, client
    site, client = run(go())
    assert site.requests == [("public.test", "/redirect/_abs")]
    assert client.dials == 1   # only the first, public hop


def test_redirect_to_public_host_is_followed_and_bounded():
    async def go():
        async with MockSite() as site:
            client, _resolver = make_client(site.port, PUBLIC_TABLE)
            try:
                res = await client.fetch(site.url("public.test", "/redirect/other.test/title"))
                with pytest.raises(FetchBlocked, match="too many redirects"):
                    await client.fetch(site.url("public.test", "/loop"))
            finally:
                await client.close()
            return res, site
    res, site = run(go())
    assert res.status == 200 and res.redirects and "other.test" in res.url
    assert ("other.test", "/title") in site.requests
    assert site.requests.count(("public.test", "/loop")) == 4   # 1 + max_redirects


def test_dns_rebinding_cannot_reach_internal_address():
    """First answer public, later answers internal: the later connection is
    refused at resolution, and each connection resolves exactly once (the
    checked answer is the dialled answer; no second lookup)."""
    async def go():
        async with MockSite() as site:
            table = {"rebind.test": [[LOOPBACK], ["10.0.0.1"], ["10.0.0.1"]]}
            client, resolver = make_client(site.port, table)
            try:
                first = await client.fetch(site.url("rebind.test", "/title"))
                with pytest.raises(FetchBlocked):
                    await client.fetch(site.url("rebind.test", "/title"))
            finally:
                await client.close()
            return first, resolver, site, client
    first, resolver, site, client = run(go())
    assert first.status == 200
    assert resolver.calls == ["rebind.test", "rebind.test"]
    assert site.requests == [("rebind.test", "/title")]
    assert client.dials == 1


def test_socket_factory_refuses_denied_address_without_creating_socket():
    client = SafeHttpClient(SafeFetchPolicy())
    created = []
    with patch.object(safehttp.socket, "socket", lambda *a, **k: created.append(1)):
        for addr in ("10.0.0.1", "169.254.169.254", "::ffff:127.0.0.1", "::1"):
            fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
            with pytest.raises(safehttp.BlockedDestinationError):
                client._socket_factory((fam, socket.SOCK_STREAM, 6, "", (addr, 80)))
    assert created == [] and client.dials == 0 and client.blocked_dials == 4


def test_oversized_bodies_are_bounded():
    async def go():
        async with MockSite() as site:
            client, _ = make_client(site.port, PUBLIC_TABLE, max_bytes=100_000)
            try:
                trunc = await client.fetch(site.url("public.test", "/huge"), truncate=True)
                with pytest.raises(FetchTooLarge):
                    await client.fetch(site.url("public.test", "/huge"))
                with pytest.raises(FetchTooLarge):
                    await client.fetch(site.url("public.test", "/huge-declared"))
                bomb_t = await client.fetch(site.url("public.test", "/gzip-bomb"),
                                            truncate=True)
                with pytest.raises(FetchTooLarge):
                    await client.fetch(site.url("public.test", "/gzip-bomb"))
                ok = await client.fetch(site.url("public.test", "/gzip-ok"))
            finally:
                await client.close()
            return trunc, bomb_t, ok
    trunc, bomb_t, ok = run(go())
    assert trunc.truncated and len(trunc.body) == 100_000
    assert bomb_t.truncated and len(bomb_t.body) == 100_000
    assert bomb_t.body.startswith(b"<html><head><title>bomb")
    assert ok.body == HTML_OK and not ok.truncated


def test_time_and_concurrency_are_bounded():
    async def go():
        async with MockSite() as site:
            client, _ = make_client(site.port, PUBLIC_TABLE, total_timeout=0.5,
                                    max_concurrency=1, max_waiters=0)
            loop = asyncio.get_running_loop()
            try:
                t0 = loop.time()
                with pytest.raises(FetchTimeout):
                    await client.fetch(site.url("public.test", "/slow"))
                elapsed = loop.time() - t0
                slow = asyncio.create_task(client.fetch(site.url("public.test", "/slow")))
                await asyncio.sleep(0.05)
                with pytest.raises(FetchBusy):
                    await client.fetch(site.url("public.test", "/title"))
                with pytest.raises(FetchTimeout):
                    await slow
            finally:
                await client.close()
            return elapsed
    assert run(go()) < 2.0


def test_fetch_result_headers_are_case_insensitive():
    from multidict import CIMultiDict
    res = safehttp.FetchResult(url="https://x.test/", status=200,
                               headers=CIMultiDict({"content-type": "text/html; charset=latin-1"}),
                               body="caf\u00e9".encode("latin-1"))
    assert res.content_type == "text/html" and res.charset == "latin-1"
    assert res.text() == "caf\u00e9"


def test_resolve_public_for_raw_sockets():
    async def go():
        r = FakeResolver(PUBLIC_TABLE | {"pub.test": ["93.184.216.34"]})
        pol = SafeFetchPolicy()
        assert await resolve_public("pub.test", pol, resolver=r) == ["93.184.216.34"]
        assert await resolve_public("8.8.8.8", pol, resolver=r) == ["8.8.8.8"]
        for bad in ("internal.test", "mixed.test", "10.0.0.1", "127.1", "localhost",
                    "2130706433", "::ffff:127.0.0.1"):
            with pytest.raises(FetchBlocked):
                await resolve_public(bad, pol, resolver=r)
        return r.calls
    calls = run(go())
    assert calls == ["pub.test", "internal.test", "mixed.test"]


# ---------------------------------------------------------------------------
# plugins
# ---------------------------------------------------------------------------
def make_core():
    sent = []
    core = NS(botname="WbsBot", botnick="WbsBot", botnet=NS(peers={}),
              send_irc=lambda msg: sent.append(msg))
    return core, sent


def said(sent):
    return [m["text"] for m in sent if m.get("cmd") == "msg"]


def pub(text):
    return {"text": text, "channel": "#aibot", "nick": "someone", "uhost": "u@h"}


def test_url_plugin_titles_public_page_and_blocks_internal():
    async def go():
        async with MockSite() as site:
            client, _resolver = make_client(site.port, PUBLIC_TABLE)
            core, sent = make_core()
            plugin = urlPlugin(core, http=client)
            try:
                await plugin.on_PUBMSG(pub(f"look {site.url('public.test', '/title')} !"))
                await plugin.on_PUBMSG(pub(f"meta {site.url('other.test', '/meta')}"))
                for evil in (f"http://127.0.0.2:{site.port}/title",
                             f"http://[::ffff:127.0.0.1]:{site.port}/title",
                             f"http://localhost:{site.port}/title",
                             "http://169.254.169.254/latest/meta-data/",
                             site.url("internal.test", "/title"),
                             site.url("mapped.test", "/title"),
                             site.url("public.test", "/redirect/internal.test/title"),
                             site.url("public.test", "/redirect/_abs") + "?to=http%3A%2F%2F10.0.0.1%2F",
                             site.url("public.test", "/binary"),
                             "http://example.gov/"):
                    await plugin.on_PUBMSG(pub(f"see {evil}"))
            finally:
                await client.close()
            return sent, site, client
    sent, site, client = run(go())
    assert said(sent) == ["Title: Example Domain", "Title: Meta Only Title"]
    hosts = {h for h, _ in site.requests}
    assert hosts <= {"public.test", "other.test"}
    assert client.blocked_dials == 0   # denied before the socket layer


def test_url_plugin_is_safe_url_uses_policy():
    plugin = urlPlugin(make_core()[0])
    assert plugin._is_safe_url("https://example.com/x") == (True, "")
    for bad in ("http://127.0.0.1/", "http://[::ffff:10.0.0.1]/", "http://2130706433/",
                "http://foo.mil/", "http://example.com:25/"):
        ok, reason = plugin._is_safe_url(bad)
        assert not ok and reason


def test_pubcom_website_blocks_internal_and_bounds_response():
    async def go():
        async with MockSite() as site:
            client, _resolver = make_client(site.port, PUBLIC_TABLE)
            core, sent = make_core()
            plugin = pubcomPlugin(core, http=client)
            with patch.object(pubcom_mod, "PAGE_MAX_BYTES", 50_000):
                try:
                    await plugin.cmd_website("n", "u@h", "#aibot",
                                             site.url("public.test", "/title"))
                    blocked = []
                    for evil in (f"http://127.0.0.2:{site.port}/title",
                                 f"127.0.0.1:{site.port}/title",
                                 f"http://[::ffff:127.0.0.1]:{site.port}/",
                                 "http://169.254.169.254/latest/meta-data/",
                                 site.url("internal.test", "/"),
                                 site.url("public.test", "/redirect/metadata.test/x")):
                        before = len(site.requests)
                        await plugin.cmd_website("n", "u@h", "#aibot", evil)
                        blocked.append(len(site.requests) - before)
                    await plugin.cmd_website("n", "u@h", "#aibot",
                                             site.url("public.test", "/huge"))
                    await plugin.cmd_tech("n", "u@h", "#aibot", site.url("internal.test", "/"))
                    await plugin.cmd_waf("n", "u@h", "#aibot", "http://10.0.0.1/")
                finally:
                    await client.close()
            return sent, site, blocked
    sent, site, blocked = run(go())
    msgs = said(sent)
    assert msgs[0] == "Title: Example Domain"
    # internal targets: zero requests except the single public redirect hop
    assert blocked == [0, 0, 0, 0, 0, 1]
    assert all(m.startswith("Error fetching") for m in msgs[1:7]), msgs
    assert not any("internal.test" == h or "metadata.test" == h for h, _ in site.requests)
    assert msgs[-2].startswith("Error fetching") and msgs[-1].startswith("Error fetching")


def test_pubcom_youtube_exact_host_allowlist():
    async def go():
        async with MockSite() as site:
            table = PUBLIC_TABLE | {"www.youtube.com": [LOOPBACK],
                                    "youtube.com.evil.test": [LOOPBACK],
                                    "evil-youtube.com": [LOOPBACK]}
            client, resolver = make_client(site.port, table)
            core, sent = make_core()
            plugin = pubcomPlugin(core, http=client)
            try:
                for bad in (site.url("youtube.com.evil.test", "/title"),
                            site.url("evil-youtube.com", "/title"),
                            f"http://www.youtube.com@public.test:{site.port}/title",
                            site.url("public.test", "/title?youtube.com"),
                            f"ftp://www.youtube.com:{site.port}/"):
                    await plugin.cmd_youtube("n", "u@h", "#aibot", bad)
                calls_after_bad = list(resolver.calls)
                await plugin.cmd_youtube("n", "u@h", "#aibot",
                                         site.url("www.youtube.com", "/meta"))
                # an allowed YouTube URL that redirects off the allowlist
                await plugin.cmd_youtube("n", "u@h", "#aibot",
                                         site.url("www.youtube.com", "/redirect/public.test/title"))
            finally:
                await client.close()
            return sent, site, calls_after_bad
    sent, site, calls_after_bad = run(go())
    msgs = said(sent)
    assert msgs[:5] == ["Invalid YouTube URL"] * 5
    assert calls_after_bad == []
    assert msgs[5] == "Title: Meta Only Title"
    assert msgs[6].startswith("Error fetching YouTube")
    assert ("public.test", "/title") not in site.requests


def test_pubcom_provider_allowlist_applies_to_redirects():
    async def go():
        async with MockSite() as site:
            table = PUBLIC_TABLE | {"cve.circl.lu": [LOOPBACK]}
            client, _ = make_client(site.port, table)
            plugin = pubcomPlugin(make_core()[0], http=client)
            try:
                async with plugin._http_get(site.url("cve.circl.lu", "/json"),
                                            hosts=pubcom_mod.CVE_HOSTS) as resp:
                    data = await resp.json()
                with pytest.raises(pubcom_mod.PubcomFetchError) as ei:
                    async with plugin._http_get(
                            site.url("cve.circl.lu", "/redirect/public.test/title"),
                            hosts=pubcom_mod.CVE_HOSTS):
                        pass
            finally:
                await client.close()
            return data, ei.value, site
    data, err, site = run(go())
    assert data == {"ok": True}
    assert err.blocked and isinstance(err, aiohttp.ClientError)
    assert ("public.test", "/title") not in site.requests


def test_pubcom_portscan_pins_validated_address_and_denies_internal():
    async def go():
        table = {"pub.test": ["93.184.216.34"], "internal.test": ["10.0.0.9"],
                 "mixed.test": ["93.184.216.34", "127.0.0.1"]}
        client = SafeHttpClient(SafeFetchPolicy(), resolver=FakeResolver(table))
        core, sent = make_core()
        plugin = pubcomPlugin(core, http=client)
        dialled = []

        async def fake_open(host, port, *a, **k):
            dialled.append((host, port))
            raise ConnectionRefusedError()
        with patch.object(pubcom_mod.asyncio, "open_connection", fake_open):
            for tgt in ("internal.test", "mixed.test", "127.1", "2130706433",
                        "10.0.0.1", "localhost"):
                await plugin.cmd_portscan("n", "u@h", "#aibot", tgt)
            denied_dials = list(dialled)
            await plugin.cmd_portscan("n", "u@h", "#aibot", "pub.test")
        await client.close()
        return sent, denied_dials, dialled
    sent, denied_dials, dialled = run(go())
    assert denied_dials == []
    assert dialled and {h for h, _ in dialled} == {"93.184.216.34"}
    assert all(m.startswith("Scan denied") for m in said(sent)[:6]), said(sent)
