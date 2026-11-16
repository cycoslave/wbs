"""
Config shape validation and schema migrations (USR-14, USR-19).

USR-14  valid-JSON-but-wrong-shape configs used to end in raw tracebacks
        (KeyError 'nick', TypeError, AttributeError) or a silent half-start
        (no bot.servers).  One validator now runs at startup, reports every
        problem as ``[fatal] Config error in <file>: <path>: <message>`` and
        exits 1; an unknown logging level is a warning naming the fallback.
USR-19  only schema.sql (CREATE IF NOT EXISTS) ran at startup and
        ``PRAGMA user_version`` was never read, so a missing column was never
        added.  Ordered migrations keyed on user_version now repair it, keep
        the data, back the file up first, and are a no-op the second time.
"""
from __future__ import annotations

import asyncio
import glob
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from src import db as dbmod
from src.configcheck import validate_config, resolve_log_level

ROOT = Path(__file__).resolve().parent.parent

GOOD = {
    "bot": {"nick": "WBSTest", "servers": [{"host": "irc.example.com", "port": 6697,
                                             "ssl": True}],
            "channels": ["#a"]},
    "users": [{"handle": "owner", "password": {"pass": "x", "encryption": "none"},
               "hosts": ["owner!u@h.example.com"], "access": [{"is_admin": 1}]}],
    "logging": {"level": "INFO"},
}


def _cfg(**over):
    c = json.loads(json.dumps(GOOD))
    c.update(over)
    return c


def _run_main(tmp_path, config_text, *extra):
    """Run the real entry point on a config file; returns CompletedProcess."""
    cfg = tmp_path / "config.json"
    cfg.write_text(config_text)
    cfg.chmod(0o600)        # WB3-001: group/other-readable configs are refused
    return subprocess.run(
        [sys.executable, "-m", "src.main", "-c", str(cfg), "-f", "-d",
         str(tmp_path / "wbs.db"), "--logfile", str(tmp_path / "wbs.log"),
         "--pidfile", str(tmp_path / "wbs.pid"), *extra],
        cwd=ROOT, capture_output=True, text=True, timeout=60)


# ---------------------------------------------------------------------------
# USR-14: validator (unit)
# ---------------------------------------------------------------------------
def test_good_config_has_no_problems():
    assert validate_config(GOOD) == ([], [])


def test_example_config_is_valid():
    cfg = json.loads((ROOT / "config.json.example").read_text())
    errors, warnings = validate_config(cfg)
    assert errors == [] and warnings == []


@pytest.mark.parametrize("config, path", [
    ([], "$"),
    ("x", "$"),
    ({}, "bot"),
    ({"bot": "x"}, "bot"),
    ({"bot": None}, "bot"),
    ({"bot": {"servers": [{"host": "h", "port": 1, "ssl": True}]}}, "bot.nick"),
    ({"bot": {"nick": 5, "servers": [{"host": "h", "port": 1, "ssl": True}]}}, "bot.nick"),
    ({"bot": {"nick": "N"}}, "bot.servers"),
    ({"bot": {"nick": "N", "servers": []}}, "bot.servers"),
    ({"bot": {"nick": "N", "servers": "irc.x.org"}}, "bot.servers"),
    ({"bot": {"nick": "N", "servers": [{"port": 6667}]}}, "bot.servers"),
])
def test_bad_shape_reported_with_path(config, path):
    errors, _ = validate_config(config)
    assert path in [p for p, _ in errors], errors


def test_all_problems_reported_at_once():
    cfg = _cfg(users="nope", db=[], settings={"listen_port": "3333"},
               dcc={"enabled": "yes"})
    del cfg["bot"]["nick"]
    paths = [p for p, _ in validate_config(cfg)[0]]
    for expected in ("bot.nick", "users", "db", "settings.listen_port", "dcc.enabled"):
        assert expected in paths, paths


def test_nested_types_checked():
    cfg = _cfg(logging="loud", plugins="x", pubcom={"channels": [1]})
    cfg["users"] = [{"handle": "h", "password": "plain", "hosts": "x", "access": [3]}]
    paths = [p for p, _ in validate_config(cfg)[0]]
    for expected in ("logging", "plugins", "pubcom.channels[0]", "users[0].password",
                     "users[0].hosts", "users[0].access[0]"):
        assert expected in paths, paths


def test_unknown_log_level_is_a_warning_naming_fallback():
    errors, warnings = validate_config(_cfg(logging={"level": "LOUD"}))
    assert errors == []
    assert warnings and warnings[0][0] == "logging.level"
    assert "LOUD" in warnings[0][1] and "INFO" in warnings[0][1]
    assert resolve_log_level("LOUD") == (20, False)
    assert resolve_log_level("debug") == (10, True)


def test_empty_update_host_means_disabled_not_an_error():
    cfg = _cfg(update={"host": "", "auto_updates": False},
               settings={"listen_host": ""})
    assert validate_config(cfg) == ([], [])


def test_update_only_does_not_require_bot():
    assert validate_config({"update": {"host": "https://x"}}, require_bot=False)[0] == []


# ---------------------------------------------------------------------------
# USR-14: through the real entry point
# ---------------------------------------------------------------------------
BAD_CONFIGS = {
    "no_bot_key": ('{"users": []}', "bot: required section is missing"),
    "bot_is_string": ('{"bot": "x"}', "bot: must be an object, got string"),
    "empty_object": ("{}", "bot: required section is missing"),
    "json_array": ("[]", "$: config must be a JSON object, got array"),
    "no_servers": ('{"bot": {"nick": "N"}}', "bot.servers: required key is missing"),
    "empty_servers": ('{"bot": {"nick": "N", "servers": []}}', "bot.servers: must not be empty"),
    "no_nick": ('{"bot": {"servers": [{"host": "h", "port": 6697, "ssl": true}]}}',
                "bot.nick: required key is missing"),
}


@pytest.mark.parametrize("name", sorted(BAD_CONFIGS))
@pytest.mark.parametrize("extra", [(), ("--seed",)], ids=["start", "seed"])
def test_bad_config_clear_message_rc1_no_traceback(tmp_path, name, extra):
    text, expect = BAD_CONFIGS[name]
    r = _run_main(tmp_path, text, *extra)
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "Traceback" not in out, out
    assert f"[fatal] Config error in {tmp_path / 'config.json'}: {expect}" in out, out
    assert not (tmp_path / "wbs.db").exists()          # nothing seeded


def test_all_errors_listed_in_one_run(tmp_path):
    r = _run_main(tmp_path, '{"bot": {"servers": []}, "users": 3}')
    out = r.stdout + r.stderr
    assert r.returncode == 1 and "Traceback" not in out
    for frag in ("bot.nick", "bot.servers", "users: must be a list"):
        assert frag in out, out
    assert out.count("[fatal] Config error in") == 3


def test_unknown_log_level_warns_and_starts(tmp_path):
    cfg = _cfg(logging={"level": "LOUD"})
    r = _run_main(tmp_path, json.dumps(cfg), "--seed")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "Traceback" not in out
    assert "logging.level" in out and "LOUD" in out and "falling back to INFO" in out
    assert (tmp_path / "wbs.db").exists()


# ---------------------------------------------------------------------------
# USR-19: migrations
# ---------------------------------------------------------------------------
def _init(path):
    asyncio.run(dbmod.init_db(str(path)))


def _cols(path, table):
    con = sqlite3.connect(path)
    try:
        return [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
    finally:
        con.close()


def _version(path):
    con = sqlite3.connect(path)
    try:
        return con.execute("PRAGMA user_version").fetchone()[0]
    finally:
        con.close()


def _drop_column(path, table, column):
    con = sqlite3.connect(path)
    try:
        con.execute(f'ALTER TABLE "{table}" DROP COLUMN "{column}"')
        con.commit()
    finally:
        con.close()


def _backups(path):
    return sorted(glob.glob(f"{path}.*.bak"))


def test_fresh_db_is_stamped_current_and_not_backed_up(tmp_path):
    p = tmp_path / "w.db"
    _init(p)
    assert _version(p) == dbmod.SCHEMA_VERSION
    assert _backups(p) == []


def test_missing_column_added_data_preserved_and_backed_up(tmp_path):
    p = tmp_path / "w.db"
    _init(p)
    con = sqlite3.connect(p)
    con.execute("INSERT INTO users (handle, password, comment) VALUES ('boss','h','hi')")
    con.execute("INSERT INTO ignores (hostmask, comment, created_by) "
                "VALUES ('*!*@bad','spam','boss')")
    con.commit()
    con.close()
    # an old database: lower version, columns the code now needs are gone
    _drop_column(p, "users", "is_locked")
    _drop_column(p, "ignores", "created_by")
    con = sqlite3.connect(p)
    con.execute("PRAGMA user_version = 1")
    con.close()
    assert "is_locked" not in _cols(p, "users")

    _init(p)

    assert "is_locked" in _cols(p, "users")
    assert "created_by" in _cols(p, "ignores")
    con = sqlite3.connect(p)
    assert con.execute("SELECT handle, password, comment, is_locked FROM users "
                       "WHERE handle='boss'").fetchone() == ("boss", "h", "hi", 0)
    assert con.execute("SELECT hostmask, comment FROM ignores").fetchone() == ("*!*@bad", "spam")
    # the repaired column works for the queries that used to fail
    con.execute("UPDATE users SET is_locked = 1 WHERE handle='boss'")
    con.close()
    assert _version(p) == dbmod.SCHEMA_VERSION
    bak = _backups(p)
    assert len(bak) == 1
    # the backup is the pre-migration file: still lacks the column, still has data
    assert "is_locked" not in _cols(bak[0], "users")
    con = sqlite3.connect(bak[0])
    assert con.execute("SELECT count(*) FROM users").fetchone()[0] == 1
    con.close()


def test_second_startup_is_a_noop(tmp_path):
    p = tmp_path / "w.db"
    _init(p)
    _drop_column(p, "users", "is_locked")
    con = sqlite3.connect(p)
    con.execute("PRAGMA user_version = 1")
    con.close()
    _init(p)
    assert len(_backups(p)) == 1
    before = {t: _cols(p, t) for t in ("users", "ignores", "user_access")}

    _init(p)
    _init(p)

    assert len(_backups(p)) == 1                        # no new backup
    assert _version(p) == dbmod.SCHEMA_VERSION
    assert {t: _cols(p, t) for t in before} == before


def test_version_one_db_without_drift_is_bumped(tmp_path):
    """Existing v1 files (what every earlier build created) are upgraded."""
    p = tmp_path / "w.db"
    _init(p)
    con = sqlite3.connect(p)
    con.execute("PRAGMA user_version = 1")
    con.close()
    _init(p)
    assert _version(p) == dbmod.SCHEMA_VERSION
    assert len(_backups(p)) == 1


def test_newer_database_is_left_alone(tmp_path):
    p = tmp_path / "w.db"
    _init(p)
    con = sqlite3.connect(p)
    con.execute(f"PRAGMA user_version = {dbmod.SCHEMA_VERSION + 5}")
    con.close()
    _init(p)
    assert _version(p) == dbmod.SCHEMA_VERSION + 5
    assert _backups(p) == []


def test_failed_migration_rolls_back_and_keeps_version(tmp_path, monkeypatch):
    p = tmp_path / "w.db"
    _init(p)
    _drop_column(p, "users", "is_locked")
    con = sqlite3.connect(p)
    con.execute("PRAGMA user_version = 1")
    con.close()

    async def boom(db):
        await db.execute("ALTER TABLE users ADD COLUMN tmp_col TEXT")
        raise RuntimeError("step failed")

    monkeypatch.setattr(dbmod, "MIGRATIONS", [(2, "boom", boom)])
    with pytest.raises(RuntimeError):
        _init(p)
    assert _version(p) == 1
    assert "tmp_col" not in _cols(p, "users")
    assert len(_backups(p)) == 1


def test_added_column_with_non_constant_default_is_backfilled(tmp_path):
    p = tmp_path / "w.db"
    _init(p)
    con = sqlite3.connect(p)
    con.execute("INSERT INTO users (handle) VALUES ('boss')")
    con.commit()
    con.close()
    _drop_column(p, "users", "created_at")
    con = sqlite3.connect(p)
    con.execute("PRAGMA user_version = 1")
    con.close()
    _init(p)
    con = sqlite3.connect(p)
    ts = con.execute("SELECT created_at FROM users WHERE handle='boss'").fetchone()[0]
    con.close()
    assert isinstance(ts, int) and ts > 1_600_000_000


def test_startup_path_through_entry_point_repairs_column(tmp_path):
    """--seed on a drifted old database repairs it (the user-visible symptom
    was `no such column: is_locked` from .userinfo/.lockuser)."""
    r = _run_main(tmp_path, json.dumps(GOOD), "--seed")
    assert r.returncode == 0, r.stdout + r.stderr
    p = tmp_path / "wbs.db"
    _drop_column(p, "users", "is_locked")
    con = sqlite3.connect(p)
    con.execute("PRAGMA user_version = 1")
    con.close()
    r = _run_main(tmp_path, json.dumps(GOOD), "--seed")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "is_locked" in _cols(p, "users")
    con = sqlite3.connect(p)
    assert con.execute("SELECT count(*) FROM users WHERE handle='owner'").fetchone()[0] == 1
    con.close()
