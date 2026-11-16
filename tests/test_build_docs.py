"""SYS-5/9/10: install docs, requirements.lock header and ruff config stay consistent."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
LOCK = (ROOT / "requirements.lock").read_text(encoding="utf-8")


def test_lock_header_command_matches_readme():
    m = re.search(r"^#\s+(uv export .+)$", LOCK, re.M)
    assert m, "requirements.lock has no 'uv export' header command"
    header_cmd = m.group(1).strip()
    readme_cmds = [ln.lstrip("- ").strip() for ln in README.splitlines()
                   if ln.lstrip("- ").strip().startswith("uv export ")]
    assert readme_cmds == [header_cmd]


def test_readme_install_lists_build_prerequisites_and_both_paths():
    for needle in ("python3.13-venv", "python3.13-dev", "build-essential",
                   "uv sync", "pip install --require-hashes -r requirements.lock",
                   "pip install --no-deps ."):
        assert needle in README, needle


def test_ruff_config_is_minimal_and_targets_py313():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["ruff"]
    assert cfg["target-version"] == "py313"
    assert cfg["lint"]["select"] == ["E", "F", "B", "I"]
    # the real-bug rules must never be switched off
    ignored = set(cfg["lint"].get("ignore", []))
    assert not ignored & {"F401", "F811", "B023", "E722"}
