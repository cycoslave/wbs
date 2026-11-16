"""
Offline regression tests for SAST-014: vulnerable aiohttp in supported installs.

Covers the finding's acceptance cases without network access:
  * manifest floor: pyproject.toml refuses every aiohttp < 3.14.4
    (CVE-2026-69244 C response-parser OOB read is fixed in 3.14.3; F-07 mythos:
    8 further CVEs, e.g. CVE-2026-111065, are fixed in 3.14.4);
  * every supported install artifact (uv.lock, requirements.lock) resolves a
    fixed aiohttp, and the legacy requirements.lock is no longer a separately
    resolved pin set: it is a hash-pinned export of uv.lock (same versions,
    hashes that exist in uv.lock), so `pip install --require-hashes` is frozen
    and verified and cannot drift back to 3.13.5;
  * installed-version proof for the interpreter running the tests;
  * isolated malformed-response regression: canned malformed HTTP responses
    from a 127.0.0.1 socket are fed to aiohttp's C parser (and the pure-Python
    parser) in a child process, so a parser memory fault is a test failure
    (non-zero / signal exit) instead of a crashed pytest run.

pip-audit itself needs the advisory database (network), so it is not run
here; the floor table below encodes the audited fixed versions instead.
No bot is started and no IRC connection is made.
"""
from __future__ import annotations

import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
UV_LOCK = ROOT / "uv.lock"
REQ_LOCK = ROOT / "requirements.lock"
PROBE = Path(__file__).resolve().parent / "malformed_http_probe.py"

AIOHTTP_FIXED = Version("3.14.4")  # CVE-2026-69244 (PYSEC-2026-3545) fixed in 3.14.3; F-07: CVE-2026-111065 et al. fixed in 3.14.4
AIOHTTP_VULNERABLE = ["3.9.0", "3.13.5", "3.14.0", "3.14.1", "3.14.2", "3.14.3"]

# Minimum fixed versions for every advisory pip-audit reported against the
# legacy requirements.lock (shared lock policy with SAST-015/016; urllib3 was
# also flagged on the legacy lock). A supported artifact below any floor
# fails here, offline.
SECURITY_FLOORS = {
    "aiohttp": AIOHTTP_FIXED,        # SAST-014 + F-07, last fix 3.14.4
    "anyio": Version("4.14.2"),      # SAST-015
    "certifi": Version("2026.10.18"),  # F-08 (PYSEC-2026-4320 / GHSA-6q48-6c7w-9gw2)
    "soupsieve": Version("4.0.0"),   # SAST-016, F-09 (CVE-2026-126190/-126191/-126193)
    "urllib3": Version("2.8.0"),     # CVE-2026-97687/97688/97689
}


# ---------------------------------------------------------------------------
# artifact parsers
# ---------------------------------------------------------------------------
def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _manifest_requirement(name: str) -> Requirement:
    for dep in _pyproject()["project"]["dependencies"]:
        req = Requirement(dep)
        if canonicalize_name(req.name) == canonicalize_name(name):
            return req
    raise AssertionError(f"{name} not declared in pyproject.toml dependencies")


def _uv_packages() -> dict[str, dict]:
    data = tomllib.loads(UV_LOCK.read_text(encoding="utf-8"))
    return {canonicalize_name(p["name"]): p for p in data["package"]}


def _uv_hashes(pkg: dict) -> set[str]:
    hashes = set()
    if "sdist" in pkg and "hash" in pkg["sdist"]:
        hashes.add(pkg["sdist"]["hash"])
    for wheel in pkg.get("wheels", []):
        hashes.add(wheel["hash"])
    return hashes


_REQ_LINE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<spec>[^;\\\s]*)")


def _requirements_lock(text: str | None = None) -> dict[str, dict]:
    """Parse requirements.lock into {name: {spec, version, hashes, line}}."""
    entries: dict[str, dict] = {}
    current = None
    if text is None:
        text = REQ_LOCK.read_text(encoding="utf-8")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash="):
            assert current is not None, f"hash without requirement: {raw!r}"
            current["hashes"].add(line.split("=", 1)[1].rstrip(" \\"))
            continue
        assert not line.startswith("-"), f"unexpected pip option in lock: {raw!r}"
        m = _REQ_LINE.match(line)
        assert m, f"unparseable requirement line: {raw!r}"
        name = canonicalize_name(m["name"])
        assert name not in entries, f"duplicate entry for {name}"
        current = {"spec": m["spec"], "hashes": set(), "line": line}
        current["version"] = m["spec"][2:] if m["spec"].startswith("==") else None
        entries[name] = current
    return entries


# ---------------------------------------------------------------------------
# manifest floor
# ---------------------------------------------------------------------------
def test_manifest_floor_rejects_every_vulnerable_aiohttp():
    spec = _manifest_requirement("aiohttp").specifier
    for bad in AIOHTTP_VULNERABLE:
        assert not spec.contains(bad, prereleases=True), f"pyproject admits aiohttp {bad}"
    assert spec.contains(str(AIOHTTP_FIXED))
    assert spec.contains("3.15.0")


def test_uv_lock_metadata_matches_manifest_floor():
    """uv.lock was re-locked against the new floor (not a stale lock)."""
    wbs = _uv_packages()["wbs"]
    declared = {canonicalize_name(d["name"]): d.get("specifier", "")
                for d in wbs["metadata"]["requires-dist"]}
    assert declared["aiohttp"] == str(_manifest_requirement("aiohttp").specifier)


# ---------------------------------------------------------------------------
# supported install artifacts
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,floor", sorted(SECURITY_FLOORS.items()))
def test_uv_lock_resolves_fixed_versions(name, floor):
    pkgs = _uv_packages()
    assert name in pkgs, f"{name} missing from uv.lock"
    assert Version(pkgs[name]["version"]) >= floor, \
        f"uv.lock pins {name} {pkgs[name]['version']} < {floor}"


@pytest.mark.parametrize("name,floor", sorted(SECURITY_FLOORS.items()))
def test_requirements_lock_resolves_fixed_versions(name, floor):
    entries = _requirements_lock()
    assert name in entries, f"{name} missing from requirements.lock"
    assert Version(entries[name]["version"]) >= floor, \
        f"requirements.lock pins {name} {entries[name]['version']} < {floor}"


def test_requirements_lock_is_not_the_legacy_vulnerable_pin_set():
    text = REQ_LOCK.read_text(encoding="utf-8")
    assert "aiohttp==3.13.5" not in text
    assert "pip-compile" not in text, "legacy pip-compile lock must be retired"
    assert "uv export --frozen" in text, "requirements.lock must be exported from uv.lock"


def test_requirements_lock_is_fully_pinned_and_hash_verified():
    entries = _requirements_lock()
    assert entries, "requirements.lock is empty"
    for name, entry in entries.items():
        assert entry["spec"].startswith("=="), f"{name} not pinned: {entry['line']}"
        assert entry["hashes"], f"{name} has no --hash (pip --require-hashes would fail)"
        for h in entry["hashes"]:
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", h), f"{name}: bad hash {h}"


def test_requirements_lock_is_derived_from_uv_lock():
    """Single source of truth: same versions, hashes taken from uv.lock."""
    pkgs = _uv_packages()
    entries = _requirements_lock()
    for name, entry in entries.items():
        assert name in pkgs, f"{name} in requirements.lock but not in uv.lock"
        assert entry["version"] == pkgs[name]["version"], \
            f"{name}: requirements.lock {entry['version']} != uv.lock {pkgs[name]['version']}"
        stray = entry["hashes"] - _uv_hashes(pkgs[name])
        assert not stray, f"{name}: hashes not present in uv.lock: {sorted(stray)}"
    # Every runtime dependency of wbs is pinned in the export.
    runtime = {canonicalize_name(d["name"]) for d in pkgs["wbs"]["dependencies"]}
    assert runtime <= set(entries), f"missing runtime deps: {sorted(runtime - set(entries))}"


def test_requirements_lock_carries_no_dev_tooling():
    entries = _requirements_lock()
    for dev in ("pytest", "pytest-cov", "black", "ruff"):
        assert dev not in entries, f"dev-only package {dev} in production lock"


# Excerpt of the retired pip-compile lock (git HEAD requirements.lock).
LEGACY_LOCK_EXCERPT = """\
# This file is autogenerated by pip-compile with Python 3.12
aiohttp==3.13.5
    # via
    #   ipinfo
    #   wbs (pyproject.toml)
anyio==4.13.0
    # via httpx
certifi==2026.7.22
    # via requests
soupsieve==2.8.4
    # via beautifulsoup4
urllib3==2.7.0
    # via requests
"""


def test_checks_reject_the_legacy_lock_content():
    """Negative control: the artifact checks above would flag the old lock."""
    legacy = _requirements_lock(LEGACY_LOCK_EXCERPT)
    below = sorted(n for n, floor in SECURITY_FLOORS.items()
                   if Version(legacy[n]["version"]) < floor)
    assert below == ["aiohttp", "anyio", "certifi", "soupsieve", "urllib3"]
    assert all(not e["hashes"] for e in legacy.values()), "legacy lock had no hashes"
    assert not _manifest_requirement("aiohttp").specifier.contains(legacy["aiohttp"]["version"])


# ---------------------------------------------------------------------------
# installed-version proof (the interpreter running this suite)
# ---------------------------------------------------------------------------
def test_installed_aiohttp_is_fixed():
    import aiohttp

    dist = Version(importlib.metadata.version("aiohttp"))
    assert dist >= AIOHTTP_FIXED, f"installed aiohttp {dist} < {AIOHTTP_FIXED}"
    assert Version(aiohttp.__version__) == dist
    print(f"installed aiohttp {dist} at {Path(aiohttp.__file__).parent}")


@pytest.mark.parametrize("name,floor", sorted(SECURITY_FLOORS.items()))
def test_installed_versions_meet_security_floors(name, floor):
    try:
        installed = Version(importlib.metadata.version(name))
    except importlib.metadata.PackageNotFoundError:
        pytest.skip(f"{name} not installed in this environment")
    assert installed >= floor, f"installed {name} {installed} < {floor}"


def test_installed_aiohttp_matches_lock():
    locked = _uv_packages()[canonicalize_name("aiohttp")]["version"]
    assert importlib.metadata.version("aiohttp") == locked, \
        "test environment is not synced to uv.lock (run: uv sync --frozen)"


# ---------------------------------------------------------------------------
# isolated malformed-response regression
# ---------------------------------------------------------------------------
def _run_probe(no_extensions: bool) -> tuple[subprocess.CompletedProcess, dict | None]:
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
           and k != "AIOHTTP_NO_EXTENSIONS"}
    if no_extensions:
        env["AIOHTTP_NO_EXTENSIONS"] = "1"
    env["PYTHONPATH"] = str(ROOT)
    proc = subprocess.run([sys.executable, str(PROBE)], cwd=str(ROOT), env=env,
                          capture_output=True, text=True, timeout=120)
    report = None
    if proc.returncode == 0 and proc.stdout.strip():
        report = json.loads(proc.stdout.strip().splitlines()[-1])
    return proc, report


@pytest.fixture(scope="module", params=["c_parser", "python_parser"])
def probe_report(request):
    proc, report = _run_probe(no_extensions=request.param == "python_parser")
    assert proc.returncode == 0, (
        f"malformed-response probe died (exit {proc.returncode}; negative = signal, "
        f"e.g. -11 SIGSEGV from the C parser)\nstderr:\n{proc.stderr[-4000:]}")
    assert report is not None, f"probe produced no report\nstderr:\n{proc.stderr[-4000:]}"
    report["_variant"] = request.param
    return report


def test_probe_exercises_the_intended_parser(probe_report):
    assert Version(probe_report["aiohttp"]) >= AIOHTTP_FIXED
    if probe_report["_variant"] == "c_parser":
        assert probe_report["c_parser"] is True, \
            "aiohttp C response parser not active; the CVE path was not exercised"
    else:
        assert probe_report["c_parser"] is False


# The pure-Python fallback parser (only used when the C extension is
# unavailable) is lenient here: it takes the first Content-Length. That is
# a handled, bounded outcome, not a crash; the C parser rejects it.
PY_PARSER_LENIENT = frozenset({"duplicate_conflicting_content_length"})


def test_malformed_responses_fail_cleanly(probe_report):
    variant = probe_report["_variant"]
    results = probe_report["results"]
    malformed = {k: v for k, v in results.items() if v["expect"] == "error"}
    assert len(malformed) >= 15
    for name, res in malformed.items():
        for client in ("bare", "safe"):
            out = res[client]
            # Never an unexpected exception type escaping the client.
            assert out["outcome"] != "unexpected", f"[{variant}] {name} via {client}: {out}"
            if variant == "python_parser" and name in PY_PARSER_LENIENT:
                continue
            assert out["outcome"] == "error", f"[{variant}] {name} via {client}: {out}"
            if client == "safe":
                # SafeHttpClient maps parser failures to its IRC-safe FetchError.
                assert out["exc"] == "FetchError", f"[{variant}] {name}: {out}"


def test_well_formed_response_still_works_after_malformed_ones(probe_report):
    results = probe_report["results"]
    for key in ("control_well_formed", "control_well_formed_after"):
        for client in ("bare", "safe"):
            out = results[key][client]
            assert out == {"outcome": "ok", "status": 200, "len": 43}, f"{key} {client}: {out}"
