"""
Regression tests: the first settings save for a NEW channel must persist the
supplied values.

Bug: chanlock._save_settings (and the identical limit/topiclock
_save_setting helpers) ran

    INSERT INTO <table>(channel) VALUES(?) ON CONFLICT(channel) DO UPDATE SET ...

For a channel with no row the INSERT succeeds with only `channel`, so the
ON CONFLICT branch never runs and every supplied value is dropped. A fresh
`.chanlock` therefore never persisted locked=1 and a restart/rejoin did not
restore the lock (probe: 1st save locked=0, 2nd save locked=1).

All rows here go through the real save paths -- nothing is seeded directly.
Throwaway sqlite under pytest's tmp_path; no network, no IRC, no bot process.
"""
import asyncio


from src.db import get_db
from src.plugins.chanlock import chanlockPlugin
from src.plugins.limit import limitPlugin
from src.plugins.topiclock import topicPlugin


class FakeCore:
    def __init__(self, db_path: str, botname: str = "WbsBot"):
        self.db_path = db_path
        self.botname = botname
        self.sent: list[dict] = []

    def send_irc(self, payload: dict) -> None:
        self.sent.append(payload)


def run(coro):
    return asyncio.run(coro)


def make(cls, tmp_path, name="settings.db"):
    core = FakeCore(str(tmp_path / name))
    p = cls(core)

    async def setup():
        async with get_db(core.db_path) as db:
            for sql in p.TABLE_SQL:
                await db.execute(sql)
            await db.commit()

    run(setup())
    return p


async def fetch_row(db_path, table, chan):
    async with get_db(db_path) as db:
        async with db.execute(
            f"SELECT * FROM {table} WHERE channel = ?", (chan,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


def mode_cmds(core):
    return [c for c in core.sent if c.get("cmd") == "mode"]


# --------------------------------------------------------------------- chanlock

def test_chanlock_first_save_persists_all_values(tmp_path):
    p = make(chanlockPlugin, tmp_path)
    run(p._save_settings("#new", locked=1, use_m=1, key="sekrit",
                         auto_unlock_secs=60, locked_by="op", locked_at=1234))
    row = run(fetch_row(p.core.db_path, "chanlock_settings", "#new"))
    assert row is not None
    assert {k: row[k] for k in ("locked", "use_m", "key", "auto_unlock_secs",
                                "locked_by", "locked_at")} == {
        "locked": 1, "use_m": 1, "key": "sekrit", "auto_unlock_secs": 60,
        "locked_by": "op", "locked_at": 1234}
    assert row["updated_at"] is not None


def test_chanlock_second_save_updates_only_supplied_columns(tmp_path):
    p = make(chanlockPlugin, tmp_path)
    run(p._save_settings("#new", locked=1, use_m=1, key="sekrit",
                         locked_by="op", locked_at=1234))
    run(p._save_settings("#new", key="other"))
    row = run(fetch_row(p.core.db_path, "chanlock_settings", "#new"))
    assert row["key"] == "other"
    # untouched columns keep their first-save values
    assert row["locked"] == 1 and row["use_m"] == 1
    assert row["locked_by"] == "op" and row["locked_at"] == 1234

    run(p._save_settings("#new", locked=0, locked_by=None, locked_at=None))
    row = run(fetch_row(p.core.db_path, "chanlock_settings", "#new"))
    assert row["locked"] == 0 and row["locked_by"] is None
    assert row["locked_at"] is None and row["key"] == "other"


def test_chanlock_first_set_on_new_channel_persists(tmp_path):
    p = make(chanlockPlugin, tmp_path)
    run(p.set("#new", "auto_unlock_secs", "90", "op"))
    assert run(p._load_settings("#new"))["auto_unlock_secs"] == 90


def test_chanlock_lock_persists_and_status_reports_locked(tmp_path):
    p = make(chanlockPlugin, tmp_path)
    run(p.lock("#new", "op", use_m=True, key="sekrit"))
    cfg = run(p._load_settings("#new"))
    assert cfg["locked"] == 1 and cfg["use_m"] == 1
    assert cfg["key"] == "sekrit" and cfg["locked_by"] == "op"
    assert "LOCKED" in run(p.status("#new"))


def test_chanlock_lock_survives_restart_and_own_join_restores(tmp_path):
    """Lock via the real `.chanlock` path, then simulate a restart (fresh
    plugin instance on the same DB) and the bot's own (re)join."""
    first = make(chanlockPlugin, tmp_path)
    run(first.lock("#new", "op", use_m=True, key="sekrit"))

    restarted = chanlockPlugin(FakeCore(first.core.db_path))
    run(restarted._restore_locked_state())
    assert "#new" in restarted._locked_channels

    run(restarted.on_NEWCHAN({"type": "NEWCHAN", "nick": "WbsBot",
                              "channel": "#new", "irc_data": {}}))
    assert mode_cmds(restarted.core) == [
        {"cmd": "mode", "channel": "#new", "modes": "+imk sekrit"}]


def test_chanlock_own_join_after_unlock_sends_nothing(tmp_path):
    p = make(chanlockPlugin, tmp_path)
    run(p.lock("#new", "op"))
    run(p.unlock("#new", "op"))
    p.core.sent.clear()
    run(p.on_NEWCHAN({"channel": "#new"}))
    assert mode_cmds(p.core) == []


# ------------------------------------------------------- same bug class: limit

def test_limit_first_set_on_new_channel_persists(tmp_path):
    p = make(limitPlugin, tmp_path)
    run(p.set("#new", "limitadd", "42", "op"))
    cfg = run(p._load_settings("#new"))
    assert cfg["limitadd"] == 42
    # schema defaults for columns not supplied
    assert cfg["enabled"] == 1 and cfg["limittol"] == 2

    run(p.set("#new", "enabled", "0", "op"))
    cfg = run(p._load_settings("#new"))
    assert cfg["enabled"] == 0 and cfg["limitadd"] == 42


# --------------------------------------------------- same bug class: topiclock

def test_topiclock_first_lock_on_new_channel_persists(tmp_path):
    p = make(topicPlugin, tmp_path)
    run(p.cmd_topiclock("#new", "op", "Welcome"))
    cfg = run(p._load_settings("#new"))
    assert cfg["enabled"] == 1 and cfg["topic"] == "Welcome"
    assert cfg["locked_by"] == "op" and cfg["locked_at"] > 0

    run(p.cmd_topiclock("#new", "op2", ""))   # toggle off
    cfg = run(p._load_settings("#new"))
    assert cfg["enabled"] == 0 and cfg["topic"] == "Welcome"
    assert cfg["locked_by"] == "op2"
