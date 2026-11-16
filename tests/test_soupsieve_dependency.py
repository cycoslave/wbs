"""
Offline regression tests for SAST-016: stale SoupSieve in supported installs.

SoupSieve is not imported by WBS. It is BeautifulSoup's CSS-selector engine
(beautifulsoup4 -> soupsieve) and is only exercised by Tag.select(),
select_one() and Tag.css. The retired pip-compile requirements.lock pinned
soupsieve 2.8.4 (CVE-2026-85999, CVE-2026-86000: selector regex complexity,
CWE-1333; fixed in 2.9.0). WBS's own BeautifulSoup use (url and pubcom
plugins) is fixed tag/attribute find() calls for <title> and og/twitter
meta titles; HTML from a fetched page is not a CSS selector, so no current
selector-injection path is claimed here.

Lock policy is shared with SAST-014/015 (tests/test_dependency_lock.py):
uv.lock is the single source of truth and requirements.lock is a hash-pinned
export of it. SAST-016 adds a resolver-level floor, [tool.uv]
constraint-dependencies "soupsieve>=4.0.0", recorded in uv.lock [manifest].

Acceptance cases covered here, all offline:
  * manifest: the constraint rejects every affected release, admits fixed;
  * uv.lock: re-locked against the constraint and resolves one fixed
    soupsieve; requirements.lock pins the same version with uv.lock hashes;
    neither supported artifact contains an affected soupsieve;
  * negative control: the checks reject the legacy soupsieve==2.8.4 pin;
  * installed test environment: soupsieve meets the floor, equals the lock,
    and is the engine bs4 actually uses;
  * isolated installation: beautifulsoup4 + soupsieve installed with
    --require-hashes from requirements.lock into a throwaway venv (uv,
    --offline, from the local uv cache) and the title/meta extraction run
    there;
  * BeautifulSoup title/meta regressions for the url and pubcom plugins;
  * guard: WBS source still has no CSS-selector call sites, so any future
    selector feature has to be reviewed (bound/deny untrusted selectors).

pip-audit needs the advisory database (network) and is not run here.
No bot is started and no IRC connection is made.
"""
from __future__ import annotations

import ast
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
PYPROJECT = ROOT / "pyproject.toml"
UV_LOCK = ROOT / "uv.lock"
REQ_LOCK = ROOT / "requirements.lock"

SOUPSIEVE_FIXED = Version("4.0.0")      # CVE-2026-85999, CVE-2026-86000; F-09: CVE-2026-126190/-126191/-126193
SOUPSIEVE_AFFECTED = ["2.5", "2.6", "2.7", "2.8", "2.8.4", "2.9.0", "2.10", "3.0", "3.0.2"]
SOUPSIEVE_OK = ["4.0.0", "4.1.1"]


# ---------------------------------------------------------------------------
# artifact helpers
# ---------------------------------------------------------------------------
def _toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _soupsieve_constraint() -> SpecifierSet:
    constraints = _toml(PYPROJECT).get("tool", {}).get("uv", {}).get("constraint-dependencies", [])
    specs = [Requirement(c).specifier for c in constraints
             if canonicalize_name(Requirement(c).name) == "soupsieve"]
    assert len(specs) == 1, f"expected exactly one soupsieve constraint, got {constraints!r}"
    return specs[0]


def _uv_lock() -> dict:
    return _toml(UV_LOCK)


def _uv_package(name: str) -> list[dict]:
    return [p for p in _uv_lock()["package"] if canonicalize_name(p["name"]) == name]


def _req_blocks(text: str) -> dict[str, dict]:
    """requirements-format lock -> {name: {version, hashes, block}}.

    ``block`` is the requirement line plus its --hash continuation lines, so
    a subset of the lock can be re-installed verbatim with --require-hashes.
    """
    entries: dict[str, dict] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash="):
            if current is not None:
                current["hashes"].add(line.split("=", 1)[1].rstrip(" \\"))
                current["block"].append(raw)
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==\s*([^\s;\\]+))?", line)
        current = None
        if m:
            current = {"version": m[3], "hashes": set(), "block": [raw]}
            entries.setdefault(canonicalize_name(m[1]), current)
    return entries


def _lock_violations(text: str) -> list[str]:
    """Same check the artifact tests apply, reusable on arbitrary text."""
    entry = _req_blocks(text).get("soupsieve")
    if entry is None:
        return ["soupsieve missing"]
    bad = []
    if entry["version"] is None:
        bad.append("soupsieve not pinned")
    elif Version(entry["version"]) < SOUPSIEVE_FIXED:
        bad.append(f"soupsieve {entry['version']} < {SOUPSIEVE_FIXED}")
    if not entry["hashes"]:
        bad.append("soupsieve has no --hash")
    return bad


# ---------------------------------------------------------------------------
# manifest constraint
# ---------------------------------------------------------------------------
def test_constraint_rejects_affected_and_admits_fixed_soupsieve():
    spec = _soupsieve_constraint()
    for v in SOUPSIEVE_AFFECTED:
        assert not spec.contains(v, prereleases=True), f"constraint admits affected soupsieve {v}"
    for v in SOUPSIEVE_OK:
        assert spec.contains(v), f"constraint rejects fixed soupsieve {v}"


def test_soupsieve_is_not_a_direct_runtime_dependency():
    """Floor is a resolver constraint, not a new install requirement of WBS."""
    deps = {canonicalize_name(Requirement(d).name) for d in _toml(PYPROJECT)["project"]["dependencies"]}
    assert "soupsieve" not in deps
    assert "beautifulsoup4" in deps


def test_uv_lock_manifest_records_the_constraint():
    """uv.lock was re-locked against pyproject's constraint (not stale)."""
    recorded = {canonicalize_name(c["name"]): c.get("specifier", "")
                for c in _uv_lock().get("manifest", {}).get("constraints", [])}
    assert "soupsieve" in recorded, "uv.lock [manifest] has no soupsieve constraint; run `uv lock`"
    assert SpecifierSet(recorded["soupsieve"]) == _soupsieve_constraint()
    # Earlier floors in the shared lock policy are still in force.
    assert "anyio" in recorded


# ---------------------------------------------------------------------------
# supported install artifacts
# ---------------------------------------------------------------------------
def test_uv_lock_resolves_single_fixed_soupsieve():
    pkgs = _uv_package("soupsieve")
    assert len(pkgs) == 1, f"expected one soupsieve in uv.lock, got {[p['version'] for p in pkgs]}"
    version = Version(pkgs[0]["version"])
    assert version >= SOUPSIEVE_FIXED
    assert _soupsieve_constraint().contains(version)


def test_uv_lock_soupsieve_is_reached_only_via_beautifulsoup4():
    by_name = {canonicalize_name(p["name"]): p for p in _uv_lock()["package"]}
    dependents = {n for n, p in by_name.items()
                  if any(canonicalize_name(d["name"]) == "soupsieve" for d in p.get("dependencies", []))}
    assert dependents == {"beautifulsoup4"}, dependents
    assert any(canonicalize_name(d["name"]) == "beautifulsoup4" for d in by_name["wbs"]["dependencies"])


def test_requirements_lock_has_no_affected_soupsieve():
    text = REQ_LOCK.read_text(encoding="utf-8")
    assert _lock_violations(text) == []
    assert "soupsieve==2.8.4" not in text
    assert "uv export --frozen" in text, "requirements.lock must be exported from uv.lock"


def test_requirements_lock_soupsieve_matches_uv_lock_hashes():
    entry = _req_blocks(REQ_LOCK.read_text(encoding="utf-8"))["soupsieve"]
    (pkg,) = _uv_package("soupsieve")
    assert entry["version"] == pkg["version"]
    uv_hashes = {w["hash"] for w in pkg.get("wheels", [])}
    if "sdist" in pkg:
        uv_hashes.add(pkg["sdist"]["hash"])
    assert entry["hashes"] and entry["hashes"] <= uv_hashes


LEGACY_EXCERPT = """\
# This file is autogenerated by pip-compile with Python 3.12
soupsieve==2.8.4
    # via beautifulsoup4
"""


@pytest.mark.parametrize("text,expected", [
    (LEGACY_EXCERPT, ["soupsieve 2.8.4 < 4.0.0", "soupsieve has no --hash"]),
    ("soupsieve==2.8.4 \\\n    --hash=sha256:" + "0" * 64 + "\n", ["soupsieve 2.8.4 < 4.0.0"]),
    ("soupsieve>=2.0\n", ["soupsieve not pinned", "soupsieve has no --hash"]),
    ("beautifulsoup4==4.15.0\n", ["soupsieve missing"]),
    ("soupsieve==4.0.0 \\\n    --hash=sha256:" + "0" * 64 + "\n", []),
])
def test_lock_check_negative_controls(text, expected):
    """The artifact check flags the legacy pin and other unsafe shapes."""
    assert _lock_violations(text) == expected


# ---------------------------------------------------------------------------
# installed test environment
# ---------------------------------------------------------------------------
def test_installed_soupsieve_is_fixed_matches_lock_and_backs_bs4():
    import bs4
    import soupsieve

    installed = Version(importlib.metadata.version("soupsieve"))
    assert installed >= SOUPSIEVE_FIXED, f"installed soupsieve {installed} < {SOUPSIEVE_FIXED}"
    (pkg,) = _uv_package("soupsieve")
    assert str(installed) == pkg["version"], \
        "test environment is not synced to uv.lock (run: uv sync --frozen)"
    # bs4's CSS support is the installed soupsieve (no vendored copy).
    from bs4 import css as bs4_css
    assert bs4_css.soupsieve is soupsieve
    soup = bs4.BeautifulSoup("<p class='a'>x</p>", "html.parser")
    assert [t.get_text() for t in soup.select("p.a")] == ["x"]
    print(f"installed soupsieve {installed} at {Path(soupsieve.__file__).parent}")


# ---------------------------------------------------------------------------
# BeautifulSoup title/meta regressions (url + pubcom plugins)
# ---------------------------------------------------------------------------
TITLE_CASES = [
    ("<html><head><title>  Hello\n  World </title></head></html>", "Hello World"),
    ("<title>A &amp; B</title>", "A & B"),
    ("<html><head></head><body>no title</body></html>", None),
    ("<title></title><meta property='og:title' content='OG'>", None),
]
META_CASES = [
    ('<meta property="og:title" content="OG Title">', "OG Title"),
    ('<meta property="twitter:title" content="TW prop">', "TW prop"),
    ('<meta name="twitter:title" content="TW name">', "TW name"),
    ('<meta property="og:title" content=""><meta name="twitter:title" content="Fallback">',
     "Fallback"),
    ('<meta name="description" content="nope">', None),
]


@pytest.fixture
def url_plugin():
    from types import SimpleNamespace as NS

    from src.plugins.url import urlPlugin
    return urlPlugin(NS(botname="WbsBot", send_irc=lambda m: None))


@pytest.fixture
def pubcom_plugin():
    from types import SimpleNamespace as NS

    from src.plugins.pubcom import pubcomPlugin
    return pubcomPlugin(NS(botname="WbsBot", send_irc=lambda m: None))


@pytest.mark.parametrize("html,expected", TITLE_CASES)
def test_url_plugin_title_extraction(url_plugin, html, expected):
    assert url_plugin._extract_title(html) == expected


@pytest.mark.parametrize("html,expected", META_CASES)
def test_url_plugin_meta_title_extraction(url_plugin, html, expected):
    assert url_plugin._extract_meta_title(html) == expected


def test_url_plugin_title_is_one_bounded_irc_line(url_plugin):
    html = "<title>evil\r\nPRIVMSG #x :hi\x00" + "A" * 1000 + "</title>"
    out = url_plugin._extract_title(html)
    assert "\r" not in out and "\n" not in out and "\x00" not in out
    assert len(out) <= 200


@pytest.mark.parametrize("html,expected", [
    ("<title>  Pub Title </title>", "Pub Title"),
    ("<p>none</p>", None),
])
def test_pubcom_title_extraction(pubcom_plugin, html, expected):
    assert pubcom_plugin._extract_title(html) == expected


@pytest.mark.parametrize("html,expected", [
    ('<meta property="og:title" content=" OG ">', "OG"),
    ('<meta name="twitter:title" content="TW">', "TW"),
    ("<p>none</p>", None),
])
def test_pubcom_meta_title_extraction(pubcom_plugin, html, expected):
    assert pubcom_plugin._extract_meta_title(html) == expected


# ---------------------------------------------------------------------------
# guard: no CSS-selector call sites in WBS
# ---------------------------------------------------------------------------
SELECTOR_ATTRS = {"select", "select_one", "css"}


def _selector_uses() -> list[str]:
    hits = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in SELECTOR_ATTRS:
                hits.append(f"{path.relative_to(ROOT)}:{node.lineno} .{node.attr}")
            elif isinstance(node, ast.Import):
                hits += [f"{path.relative_to(ROOT)}:{node.lineno} import {a.name}"
                         for a in node.names if a.name.split(".")[0] == "soupsieve"]
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "soupsieve":
                hits.append(f"{path.relative_to(ROOT)}:{node.lineno} from {node.module}")
    return hits


def test_wbs_source_has_no_css_selector_call_sites():
    """SAST-016 remediation: a selector feature must bound/deny untrusted input.

    If this fails, a CSS selector call was added; review whether the selector
    string can be influenced by IRC users before adjusting this guard.
    """
    assert _selector_uses() == []


# ---------------------------------------------------------------------------
# isolated installation from requirements.lock (offline, throwaway venv)
# ---------------------------------------------------------------------------
ISOLATED_PROBE = r"""
import importlib.metadata, json, sys
import bs4, soupsieve
from bs4 import BeautifulSoup
html = ('<html><head><title> Iso  Title </title>'
        '<meta property="og:title" content="Iso OG"></head></html>')
soup = BeautifulSoup(html, "html.parser")
print(json.dumps({
    "prefix": sys.prefix,
    "bs4_file": bs4.__file__,
    "soupsieve": importlib.metadata.version("soupsieve"),
    "bs4": importlib.metadata.version("beautifulsoup4"),
    "title": " ".join(soup.find("title").get_text().split()),
    "og": soup.find("meta", property="og:title").get("content"),
    "select": [t.get("content") for t in soup.select('meta[property="og:title"]')],
}))
"""


def test_isolated_hash_verified_install_from_requirements_lock(tmp_path):
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv not available for the isolated install")
    blocks = _req_blocks(REQ_LOCK.read_text(encoding="utf-8"))
    (bs4_pkg,) = _uv_package("beautifulsoup4")
    closure = ["beautifulsoup4"] + [canonicalize_name(d["name"]) for d in bs4_pkg.get("dependencies", [])]
    assert "soupsieve" in closure
    req = tmp_path / "req.txt"
    req.write_text("\n".join(line for n in closure for line in blocks[n]["block"]) + "\n")

    env = {k: v for k, v in os.environ.items()
           if k not in ("VIRTUAL_ENV", "PYTHONPATH", "UV_PROJECT_ENVIRONMENT")}
    venv = tmp_path / "venv"
    # --no-config + cwd outside the project: install exactly the exported lock
    # lines, not the project's [tool.uv] settings (as a pip user would).
    subprocess.run([uv, "venv", "--no-config", "--offline", "-q", "-p", sys.executable, str(venv)],
                   cwd=str(tmp_path), env=env, check=True, capture_output=True, text=True,
                   timeout=120)
    py = venv / "bin" / "python"
    inst = subprocess.run([uv, "pip", "install", "--no-config", "--offline", "--require-hashes",
                           "--no-deps", "-p", str(py), "-r", str(req)],
                          cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=300)
    if inst.returncode != 0 and re.search(r"offline|not found in the cache|network", inst.stderr, re.I):
        pytest.skip(f"locked wheels not in the local uv cache (offline run): {inst.stderr[-300:]}")
    assert inst.returncode == 0, inst.stderr

    run = subprocess.run([str(py), "-I", "-c", ISOLATED_PROBE], cwd=str(tmp_path),
                         env=env, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout.strip().splitlines()[-1])
    assert Path(report["bs4_file"]).resolve().is_relative_to(venv.resolve()), report
    assert report["soupsieve"] == blocks["soupsieve"]["version"]
    assert Version(report["soupsieve"]) >= SOUPSIEVE_FIXED
    assert report["bs4"] == blocks["beautifulsoup4"]["version"]
    assert report["title"] == "Iso Title"
    assert report["og"] == "Iso OG"
    assert report["select"] == ["Iso OG"]
