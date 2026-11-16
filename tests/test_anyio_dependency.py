"""
Offline regression tests for SAST-015: stale AnyIO in supported installs.

AnyIO is not imported by WBS itself. It reaches the bot only through
pubcom's !whois command: whoisit -> httpx -> httpcore -> anyio (httpcore's
asyncio network backend is AnyIOBackend). The legacy pip-compile
requirements.lock pinned anyio 4.13.0 (CVE-2026-63374, CVE-2026-64847;
fixed in 4.14.2).

Lock policy is shared with SAST-014/016 (tests/test_dependency_lock.py):
uv.lock is the single source of truth and requirements.lock is a
hash-pinned export of it. SAST-015 adds a resolver-level floor for this
transitive dependency, [tool.uv] constraint-dependencies in pyproject.toml,
which uv records in uv.lock's [manifest] so a re-lock cannot drop below it.

Acceptance cases covered here, all offline:
  * manifest: the constraint rejects every affected release and admits fixed;
  * uv.lock: re-locked against the constraint (manifest matches pyproject)
    and resolves a fixed anyio; requirements.lock pins the same version with
    hashes taken from uv.lock; neither artifact contains an affected anyio;
  * negative control: the checks reject the legacy anyio==4.13.0 pin;
  * installed test environment: anyio meets the floor and equals the lock;
  * dependent feature smoke test: pubcom !whois runs end-to-end through
    whoisit/httpx/httpcore/anyio against a 127.0.0.1 RDAP stub.

pip-audit needs the advisory database (network) and is not run here.
No bot is started and no IRC connection is made.
"""
from __future__ import annotations

import asyncio
import importlib.metadata
import json
import re
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
UV_LOCK = ROOT / "uv.lock"
REQ_LOCK = ROOT / "requirements.lock"

ANYIO_FIXED = Version("4.14.2")          # CVE-2026-63374, CVE-2026-64847
ANYIO_AFFECTED = ["4.0.0", "4.12.0", "4.13.0", "4.14.0", "4.14.1"]
ANYIO_OK = ["4.14.2", "4.15.1", "5.0.0"]


# ---------------------------------------------------------------------------
# artifact helpers
# ---------------------------------------------------------------------------
def _toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _anyio_constraint() -> SpecifierSet:
    constraints = _toml(PYPROJECT).get("tool", {}).get("uv", {}).get("constraint-dependencies", [])
    specs = [Requirement(c).specifier for c in constraints
             if canonicalize_name(Requirement(c).name) == "anyio"]
    assert len(specs) == 1, f"expected exactly one anyio constraint, got {constraints!r}"
    return specs[0]


def _uv_lock() -> dict:
    return _toml(UV_LOCK)


def _uv_package(name: str) -> list[dict]:
    return [p for p in _uv_lock()["package"] if canonicalize_name(p["name"]) == name]


def _req_lock_anyio(text: str) -> list[dict]:
    """Every anyio entry in a requirements-format lock: version + hashes."""
    entries, current = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash="):
            if current is not None:
                current["hashes"].add(line.split("=", 1)[1].rstrip(" \\"))
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;\\]+)", line)
        current = None
        if m and canonicalize_name(m[1]) == "anyio":
            current = {"version": m[2], "hashes": set()}
            entries.append(current)
        elif re.match(r"^anyio\b", line, re.I):
            # unpinned / ranged anyio line: version unknown -> unsafe
            current = {"version": None, "hashes": set()}
            entries.append(current)
    return entries


def _lock_violations(text: str) -> list[str]:
    """Same check the artifact tests apply, reusable on arbitrary text."""
    bad = []
    entries = _req_lock_anyio(text)
    if not entries:
        bad.append("anyio missing")
    for e in entries:
        if e["version"] is None:
            bad.append("anyio not pinned")
        elif Version(e["version"]) < ANYIO_FIXED:
            bad.append(f"anyio {e['version']} < {ANYIO_FIXED}")
        if not e["hashes"]:
            bad.append("anyio has no --hash")
    return bad


# ---------------------------------------------------------------------------
# manifest constraint
# ---------------------------------------------------------------------------
def test_constraint_rejects_affected_and_admits_fixed_anyio():
    spec = _anyio_constraint()
    for v in ANYIO_AFFECTED:
        assert not spec.contains(v, prereleases=True), f"constraint admits affected anyio {v}"
    for v in ANYIO_OK:
        assert spec.contains(v), f"constraint rejects fixed anyio {v}"


def test_anyio_is_not_a_direct_runtime_dependency():
    """Floor is a resolver constraint, not a new install requirement of WBS."""
    deps = {canonicalize_name(Requirement(d).name) for d in _toml(PYPROJECT)["project"]["dependencies"]}
    assert "anyio" not in deps


def test_uv_lock_manifest_records_the_constraint():
    """uv.lock was re-locked against pyproject's constraint (not stale)."""
    manifest = _uv_lock().get("manifest", {})
    recorded = {canonicalize_name(c["name"]): c.get("specifier", "")
                for c in manifest.get("constraints", [])}
    assert "anyio" in recorded, "uv.lock [manifest] has no anyio constraint; run `uv lock`"
    assert SpecifierSet(recorded["anyio"]) == _anyio_constraint()


# ---------------------------------------------------------------------------
# supported install artifacts
# ---------------------------------------------------------------------------
def test_uv_lock_resolves_single_fixed_anyio():
    pkgs = _uv_package("anyio")
    assert len(pkgs) == 1, f"expected one anyio in uv.lock, got {[p['version'] for p in pkgs]}"
    version = Version(pkgs[0]["version"])
    assert version >= ANYIO_FIXED
    assert _anyio_constraint().contains(version)


def test_uv_lock_anyio_is_reached_via_whoisit_httpx():
    """Documents the only path into WBS (keeps the smoke test honest)."""
    by_name = {canonicalize_name(p["name"]): p for p in _uv_lock()["package"]}
    dependents = {n for n, p in by_name.items()
                  if any(canonicalize_name(d["name"]) == "anyio" for d in p.get("dependencies", []))}
    assert dependents == {"httpx"}, dependents
    httpx_users = {n for n, p in by_name.items()
                   if any(canonicalize_name(d["name"]) == "httpx" for d in p.get("dependencies", []))}
    assert "whoisit" in httpx_users
    assert any(canonicalize_name(d["name"]) == "whoisit" for d in by_name["wbs"]["dependencies"])


def test_requirements_lock_has_no_affected_anyio():
    text = REQ_LOCK.read_text(encoding="utf-8")
    assert _lock_violations(text) == []
    assert "anyio==4.13.0" not in text


def test_requirements_lock_anyio_matches_uv_lock_hashes():
    (entry,) = _req_lock_anyio(REQ_LOCK.read_text(encoding="utf-8"))
    (pkg,) = _uv_package("anyio")
    assert entry["version"] == pkg["version"]
    uv_hashes = {w["hash"] for w in pkg.get("wheels", [])}
    if "sdist" in pkg:
        uv_hashes.add(pkg["sdist"]["hash"])
    assert entry["hashes"] and entry["hashes"] <= uv_hashes


LEGACY_EXCERPT = """\
# This file is autogenerated by pip-compile with Python 3.12
anyio==4.13.0
    # via httpx
"""


@pytest.mark.parametrize("text,expected", [
    (LEGACY_EXCERPT, ["anyio 4.13.0 < 4.14.2", "anyio has no --hash"]),
    ("anyio==4.14.1 \\\n    --hash=sha256:" + "0" * 64 + "\n", ["anyio 4.14.1 < 4.14.2"]),
    ("anyio>=4.0\n", ["anyio not pinned", "anyio has no --hash"]),
    ("httpx==0.28.1\n", ["anyio missing"]),
    ("anyio==4.14.2 \\\n    --hash=sha256:" + "0" * 64 + "\n", []),
])
def test_lock_check_negative_controls(text, expected):
    """The artifact check flags the legacy pin and other unsafe shapes."""
    assert _lock_violations(text) == expected


# ---------------------------------------------------------------------------
# installed test environment
# ---------------------------------------------------------------------------
def test_installed_anyio_is_fixed_and_matches_lock():
    import anyio

    installed = Version(importlib.metadata.version("anyio"))
    assert installed >= ANYIO_FIXED, f"installed anyio {installed} < {ANYIO_FIXED}"
    (pkg,) = _uv_package("anyio")
    assert str(installed) == pkg["version"], \
        "test environment is not synced to uv.lock (run: uv sync --frozen)"
    print(f"installed anyio {installed} at {Path(anyio.__file__).parent}")


def test_httpcore_asyncio_backend_is_anyio():
    """Under asyncio, httpx/httpcore do their network I/O through anyio."""
    from httpcore._backends.anyio import AnyIOBackend
    from httpcore._backends.auto import AutoBackend

    async def probe():
        backend = AutoBackend()
        await backend._init_backend()
        return backend._backend

    assert isinstance(asyncio.run(probe()), AnyIOBackend)


# ---------------------------------------------------------------------------
# dependent feature smoke test: pubcom !whois over a local RDAP stub
# ---------------------------------------------------------------------------
class _RdapStub(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):  # noqa: N802
        type(self).hits.append(self.path)
        if self.path.startswith("/rdap/domain/"):
            name = self.path.rsplit("/", 1)[1]
            body = {"objectClassName": "domain", "handle": "WBS-TEST", "ldhName": name,
                    "status": ["active"], "events": [], "entities": [], "links": []}
            payload, status = json.dumps(body).encode(), 200
        else:
            payload, status = b'{"errorCode": 404}', 404
        self.send_response(status)
        self.send_header("Content-Type", "application/rdap+json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def rdap_stub(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    _RdapStub.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RdapStub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/rdap/"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def whoisit_offline(rdap_stub):
    """whoisit bootstrapped from local data only, restored afterwards."""
    import whoisit

    whoisit.clear_bootstrapping()
    whoisit.clear_session()
    service = [[["test"], [rdap_stub]]]
    data = {"timestamp": 1_790_000_000,
            "asn": {"services": [[["1-4294967295"], [rdap_stub]]]},
            "dns": {"services": service},
            "ipv4": {"services": [[["0.0.0.0/0"], [rdap_stub]]]},
            "ipv6": {"services": [[["::/0"], [rdap_stub]]]},
            "object": {"services": [[["TEST"], [rdap_stub]]]}}
    whoisit.load_bootstrap_data(data, from_json=False, allow_insecure=True)
    try:
        yield whoisit
    finally:
        whoisit.clear_bootstrapping()
        whoisit.clear_session()


class _Core:
    def __init__(self):
        self.sent: list[dict] = []

    def send_irc(self, payload):
        self.sent.append(payload)


async def _run_whois(arg: str, whoisit) -> list[str]:
    from src.plugins.pubcom import pubcomPlugin

    core = _Core()
    plugin = pubcomPlugin(core)

    async def enabled(channel):
        return True

    plugin.is_pubcom_enabled = enabled
    try:
        await plugin.cmd_whois("nick", "nick!u@h", "#chan", arg)
    finally:
        client = whoisit.get_async_client()
        await client.aclose()
    return [p["text"] for p in core.sent if p.get("cmd") == "msg"]


def test_pubcom_whois_domain_smoke_through_anyio(whoisit_offline):
    import anyio  # noqa: F401  (must be the fixed, locked build)

    replies = asyncio.run(_run_whois("example.test", whoisit_offline))
    assert replies == ["WHOIS example.test: example.test"], replies
    assert _RdapStub.hits == ["/rdap/domain/example.test"]


def test_pubcom_whois_failure_is_reported_not_raised(whoisit_offline):
    """Unsupported TLD: the error path still answers on IRC, no exception."""
    replies = asyncio.run(_run_whois("example.invalid", whoisit_offline))
    assert len(replies) == 1 and replies[0].startswith("WHOIS error:"), replies
    assert _RdapStub.hits == []
