"""WB3-001: config.json holds secrets and must be a private regular file.

Startup refuses a symlink, directory/FIFO, a file owned by someone else, or one
with any group/other permission bit; the message names the path and the fix
(`chmod 600`) and never echoes the file's contents.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from src import main as wbs_main
from src.main import ConfigAccessError, load_config, read_config_text

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")

SECRET = "hunter2-SECRET-marker-7731"
CONFIG = {
    "bot": {"nick": "WBSTest", "servers": [{"host": "irc.example.com", "port": 6697,
                                             "ssl": True}], "channels": ["#a"]},
    "users": [{"handle": "owner", "password": {"pass": SECRET, "encryption": "none"},
               "hosts": ["owner!u@h.example.com"], "access": [{"is_admin": 1}]}],
}


def _write(path: Path, mode: int) -> Path:
    path.write_text(json.dumps(CONFIG))
    path.chmod(mode)
    return path


def _run_main(cfg: Path, tmp_path: Path, *extra):
    return subprocess.run(
        [sys.executable, "-m", "src.main", "-c", str(cfg), "-f", "-d",
         str(tmp_path / "wbs.db"), "--logfile", str(tmp_path / "wbs.log"),
         "--pidfile", str(tmp_path / "wbs.pid"), *extra],
        cwd=ROOT, capture_output=True, text=True, timeout=60)


def test_accepted_at_0600(tmp_path):
    cfg = _write(tmp_path / "config.json", 0o600)
    assert load_config(cfg)["bot"]["nick"] == "WBSTest"
    assert json.loads(read_config_text(cfg)) == CONFIG


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o660, 0o604, 0o666, 0o610])
def test_rejected_when_group_or_other_bits_set(tmp_path, mode):
    cfg = _write(tmp_path / "config.json", mode)
    with pytest.raises(ConfigAccessError) as ei:
        load_config(cfg)
    msg = str(ei.value)
    assert str(cfg) in msg
    assert f"chmod 600 {cfg}" in msg
    assert f"{mode:04o}" in msg
    assert SECRET not in msg and "WBSTest" not in msg


def test_symlink_rejected_even_to_a_private_file(tmp_path):
    real = _write(tmp_path / "real.json", 0o600)
    link = tmp_path / "config.json"
    link.symlink_to(real)
    with pytest.raises(ConfigAccessError) as ei:
        load_config(link)
    assert "symbolic link" in str(ei.value) and str(link) in str(ei.value)
    assert SECRET not in str(ei.value)


def test_directory_rejected(tmp_path):
    d = tmp_path / "config.json"
    d.mkdir(mode=0o700)
    with pytest.raises(ConfigAccessError) as ei:
        load_config(d)
    assert "not a regular file" in str(ei.value)


def test_fifo_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "config.json"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ConfigAccessError) as ei:
        load_config(fifo)
    assert "not a regular file" in str(ei.value)


def test_wrong_owner_rejected(tmp_path, monkeypatch):
    cfg = _write(tmp_path / "config.json", 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(cfg).st_uid + 1)
    with pytest.raises(ConfigAccessError) as ei:
        load_config(cfg)
    assert "not owned" in str(ei.value)


def test_missing_file_is_still_plain_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.json")


def test_permission_checked_on_the_opened_descriptor(tmp_path, monkeypatch):
    """No path-based stat between the check and the read: fstat on the fd."""
    cfg = _write(tmp_path / "config.json", 0o600)
    calls = []
    real_fstat = os.fstat
    monkeypatch.setattr(os, "fstat", lambda fd: (calls.append(fd), real_fstat(fd))[1])
    read_config_text(cfg)
    assert len(calls) == 1


@pytest.mark.parametrize("mode", [0o640, 0o644])
def test_startup_exits_nonzero_without_printing_contents(tmp_path, mode):
    cfg = _write(tmp_path / "config.json", mode)
    r = _run_main(cfg, tmp_path)
    out = r.stdout + r.stderr
    assert r.returncode != 0
    assert str(cfg) in out and f"chmod 600 {cfg}" in out
    assert SECRET not in out and "WBSTest" not in out and "irc.example.com" not in out
    assert "Traceback" not in out


def test_startup_symlink_refused(tmp_path):
    real = _write(tmp_path / "real.json", 0o600)
    link = tmp_path / "config.json"
    link.symlink_to(real)
    r = _run_main(link, tmp_path)
    assert r.returncode != 0
    assert "symbolic link" in r.stderr + r.stdout
    assert SECRET not in r.stdout + r.stderr


def test_startup_accepts_0600(tmp_path):
    """A 0600 config gets past the permission gate (here: seeding, then exit)."""
    cfg = _write(tmp_path / "config.json", 0o600)
    r = _run_main(cfg, tmp_path, "--seed")
    out = r.stdout + r.stderr
    assert "refusing to use config file" not in out
    assert SECRET not in out


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


def test_plaintext_seed_passwords_warn_once_without_values(caplog):
    with caplog.at_level(logging.WARNING, logger="wbs"):
        wbs_main._warn_plaintext_seed_passwords(CONFIG)
    msgs = _warnings(caplog)
    assert len(msgs) == 1
    assert "encryption=none" in msgs[0]
    assert SECRET not in msgs[0] and "owner" not in msgs[0]


def test_bcrypt_seed_passwords_do_not_warn(caplog):
    cfg = {"users": [{"handle": "u", "password": {"pass": "$2b$12$abc", "encryption": "bcrypt"}},
                     {"handle": "v"}]}
    with caplog.at_level(logging.WARNING, logger="wbs"):
        wbs_main._warn_plaintext_seed_passwords(cfg)
        wbs_main._warn_plaintext_seed_passwords({})
        wbs_main._warn_plaintext_seed_passwords({"users": "bad"})
    assert _warnings(caplog) == []


def test_readme_install_command_creates_config_with_mode_600():
    assert "install -m 600 config.json.example config.json" in README
    assert "cp config.json.example config.json" not in README
    assert "chmod 600" in README and "--mkpasswd" in README


# ---------------------------------------------------------------------------
# F-05: a cleartext seed password is an explicit opt-in ("encryption": "none")
# ---------------------------------------------------------------------------
BCRYPT_HASH = "$2b$12$" + "a" * 53


def _hash(cfg, monkeypatch):
    import asyncio
    from src import db as dbmod

    async def fake_hash(raw):
        return "HASHED:" + raw
    monkeypatch.setattr(dbmod.crypto_exec, "hash_password", fake_hash)
    return asyncio.run(dbmod._hash_password(cfg))


def test_missing_encryption_key_defaults_to_bcrypt(monkeypatch):
    # a bcrypt hash with no "encryption" key is stored as-is (bcrypt default)
    assert _hash({"pass": BCRYPT_HASH}, monkeypatch) == BCRYPT_HASH
    # a cleartext value with no key is NOT silently hashed: it must opt in
    with pytest.raises(ValueError, match="bcrypt"):
        _hash({"pass": SECRET}, monkeypatch)


def test_explicit_none_still_hashes_cleartext(monkeypatch):
    assert _hash({"pass": SECRET, "encryption": "none"}, monkeypatch) == "HASHED:" + SECRET
    assert _hash({"pass": SECRET, "encryption": "NONE"}, monkeypatch) == "HASHED:" + SECRET


def test_explicit_bcrypt_unchanged(monkeypatch):
    assert _hash({"pass": BCRYPT_HASH, "encryption": "bcrypt"}, monkeypatch) == BCRYPT_HASH
    with pytest.raises(ValueError):
        _hash({"pass": SECRET, "encryption": "bcrypt"}, monkeypatch)


def test_missing_key_does_not_trigger_plaintext_warning(caplog):
    cfg = {"users": [{"handle": "u", "password": {"pass": BCRYPT_HASH}}]}
    with caplog.at_level(logging.WARNING, logger="wbs"):
        wbs_main._warn_plaintext_seed_passwords(cfg)
    assert _warnings(caplog) == []


def test_explicit_none_still_warns_without_leaking(caplog):
    cfg = {"users": [{"handle": "owner", "password": {"pass": SECRET, "encryption": "none"}}]}
    with caplog.at_level(logging.WARNING, logger="wbs"):
        wbs_main._warn_plaintext_seed_passwords(cfg)
    msgs = _warnings(caplog)
    assert len(msgs) == 1 and "encryption=none" in msgs[0]
    assert SECRET not in msgs[0]


def test_config_example_first_seed_user_uses_bcrypt():
    cfg = json.loads((ROOT / "config.json.example").read_text(encoding="utf-8"))
    for u in cfg["users"]:
        assert u["password"]["encryption"] == "bcrypt"
        assert u["password"]["pass"].startswith("$2b$")
