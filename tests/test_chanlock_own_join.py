"""
Regression tests: chanlock restores a channel lock when the bot itself joins.

Bug: chanlock.on_JOIN checked `self.core.irc.nick`, but Core (the process the
plugins run in) has no `irc` attribute -- the IRC client lives in a separate
process. Every JOIN raised AttributeError and locks were never re-enforced.
Core tracks its live nick in `core.botname` (READY, NICK, IRC timer sync).

Also: the IRC process reports the bot's OWN join as NEWCHAN, not JOIN
(irc.py on_join), so chanlock must restore the lock on NEWCHAN too.

Throwaway sqlite under pytest's tmp_path; no network, no IRC, no bot process.
"""
import asyncio

import pytest

from src.db import get_db
from src.plugins.chanlock import chanlockPlugin


class FakeCore:
    """Only what chanlock touches. Deliberately has NO `irc` attribute."""

    def __init__(self, db_path: str, botname: str = "WbsBot"):
        self.db_path = db_path
        self.botname = botname
        self.sent: list[dict] = []

    def send_irc(self, payload: dict) -> None:
        self.sent.append(payload)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def plugin(tmp_path):
    core = FakeCore(str(tmp_path / "chanlock.db"))
    p = chanlockPlugin(core)

    async def setup():
        async with get_db(core.db_path) as db:
            for sql in p.TABLE_SQL:
                await db.execute(sql)
            # Seeded directly to isolate the own-join logic; the real save
            # path is covered in test_plugin_settings_first_save.py.
            await db.execute(
                "INSERT INTO chanlock_settings(channel, locked, use_m, key, "
                "locked_by, locked_at) VALUES(?, 1, 1, ?, 'op', 1)",
                ("#locked", "sekrit"))
            await db.commit()

    run(setup())
    assert not hasattr(core, "irc")
    return p


def mode_cmds(core):
    return [c for c in core.sent if c.get("cmd") == "mode"]


def test_own_join_restores_lock(plugin):
    run(plugin.on_JOIN({"type": "JOIN", "nick": "WbsBot", "channel": "#locked",
                        "host": "WbsBot!b@h"}))
    assert mode_cmds(plugin.core) == [
        {"cmd": "mode", "channel": "#locked", "modes": "+imk sekrit"}]
    assert "#locked" in plugin._locked_channels


def test_own_join_nick_compare_is_case_insensitive(plugin):
    run(plugin.on_JOIN({"nick": "wbsbot", "channel": "#locked"}))
    assert len(mode_cmds(plugin.core)) == 1


def test_own_join_follows_nick_change(plugin):
    plugin.core.botname = "WbsBot_"   # core.on_nick / on_ready update this
    run(plugin.on_JOIN({"nick": "WbsBot", "channel": "#locked"}))
    assert mode_cmds(plugin.core) == []
    run(plugin.on_JOIN({"nick": "WbsBot_", "channel": "#locked"}))
    assert len(mode_cmds(plugin.core)) == 1


def test_other_nick_join_is_ignored(plugin):
    run(plugin.on_JOIN({"nick": "someone", "channel": "#locked"}))
    assert mode_cmds(plugin.core) == []
    assert "#locked" not in plugin._locked_channels


def test_own_join_unlocked_channel_sends_nothing(plugin):
    run(plugin.on_JOIN({"nick": "WbsBot", "channel": "#open"}))
    assert mode_cmds(plugin.core) == []


def test_join_without_known_botname_is_ignored(plugin):
    plugin.core.botname = None   # before READY
    run(plugin.on_JOIN({"nick": "WbsBot", "channel": "#locked"}))
    assert mode_cmds(plugin.core) == []


def test_newchan_own_join_restores_lock(plugin):
    run(plugin.on_NEWCHAN({"type": "NEWCHAN", "nick": "WbsBot",
                           "channel": "#locked", "irc_data": {}}))
    assert mode_cmds(plugin.core) == [
        {"cmd": "mode", "channel": "#locked", "modes": "+imk sekrit"}]
