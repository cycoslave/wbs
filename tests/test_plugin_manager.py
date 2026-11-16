"""
Regression tests for the plugin loader (PLG-1 .. PLG-5, prior D7/D8/D18).

PLG-1  PluginManager.dispatch iterated the live `plugins` dict while awaiting
       handlers; a `.load`/`.unload` meanwhile killed the Core with
       "dictionary changed size during iteration".
PLG-2  the loader skipped classes *named* `Plugin`, so the shipped example
       (`class Plugin(Plugin)`) could never load.
PLG-3  Plugin.unload() dropped every TABLE_SQL table: each reload wiped
       limit/chanlock/topiclock settings, stats and audit rows.
PLG-4  `.unload` bypassed the manager: loaded_modules kept autoload=1, so the
       plugin came back after a restart, and `.plugins` counted config only.
PLG-5  plugin names were not validated and the existence check was relative
       to the process CWD.

Throwaway sqlite DB per test, real plugin modules, no IRC, no sockets.
"""
import asyncio
import os
from types import SimpleNamespace as NS

import pytest

from src import commands
from src.core import Core
from src.db import get_db, init_db
from src import plugins as plugin_mod
from src.plugins import Plugin, PluginManager


class FakeCore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.botname = "WbsBot"
        self.config = {"bot": {"nick": "WbsBot"}, "plugins": []}
        self.sent: list[dict] = []
        self.timers: dict = {}
        self.chan = NS(getchans=self._getchans)
        self.plugin = PluginManager(self)
        self.game = NS(load_game=self._no_game)
        self.partyline = NS(sessions={})

    async def _getchans(self):
        return []

    async def _no_game(self, name):
        raise AssertionError("no games in these tests")

    def send_irc(self, payload: dict) -> None:
        self.sent.append(payload)

    async def register_timer(self, name, callback, interval, randomize=False):
        self.timers[name] = (callback, interval)

    def unregister_timer(self, name):
        self.timers.pop(name, None)


@pytest.fixture
def core(tmp_path):
    db = str(tmp_path / "wbs.db")
    asyncio.run(init_db(db))
    return FakeCore(db)


async def run_cmd(core, name, arg, session_id=None):
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    await commands.COMMANDS[name](core, "console", session_id, arg, respond)
    return out


async def scalar(core, sql, *params):
    async with get_db(core.db_path) as db:
        rows = await db.execute_fetchall(sql, params)
    return rows[0][0] if rows else None


async def autoload_flag(core, name):
    return await scalar(core, "SELECT autoload FROM loaded_modules "
                              "WHERE name=? AND type='plugin'", name)


# ---------------------------------------------------------------- PLG-1

class _Recorder(Plugin):
    def __init__(self, core, label, log):
        self.name = label
        super().__init__(core)
        self.label = label
        self.calls = log


def test_dispatch_survives_unload_and_load_inside_a_handler(core):
    """A handler that unloads one plugin and loads another while dispatch is
    iterating must not raise, and the unloaded plugin's handler is skipped."""
    mgr = core.plugin
    calls: list[str] = []

    class First(_Recorder):
        async def on_PUBMSG(self, event):
            calls.append(self.label)
            await asyncio.sleep(0)
            mgr.plugins.pop("b")                       # .unload b
            mgr.plugins["c"] = Late(core, "c", calls)  # .load c

    class Second(_Recorder):
        async def on_PUBMSG(self, event):
            calls.append(self.label)

    class Late(_Recorder):
        async def on_PUBMSG(self, event):
            calls.append(self.label)

    mgr.plugins["a"] = First(core, "a", calls)
    mgr.plugins["b"] = Second(core, "b", calls)

    asyncio.run(mgr.dispatch("PUBMSG", {"text": "hi"}))
    assert calls == ["a"]          # b was unloaded mid-dispatch: not called


def test_concurrent_dispatch_and_load_unload_loop_never_raises(core):
    """Real `.load`/`.unload` of real plugins in a loop while events flow."""
    names = ["limit", "stats", "topiclock", "chanlock", "example"]
    event = {"nick": "pown", "host": "u@h", "channel": "#wbs", "text": "hello :)",
             "target": "#wbs", "modes": "+o pown"}

    async def go():
        stop = asyncio.Event()
        errors: list[BaseException] = []
        dispatched = 0

        async def pump():
            nonlocal dispatched
            while not stop.is_set():
                for etype in ("PUBMSG", "MODE", "JOIN", "TOPIC"):
                    try:
                        await core.plugin.dispatch(etype, dict(event))
                    except BaseException as e:      # pragma: no cover - the bug
                        errors.append(e)
                        stop.set()
                        return
                    dispatched += 1
                await asyncio.sleep(0)

        async def churn():
            for _ in range(2):
                for n in names:
                    assert (await run_cmd(core, "load", n)) == [f"Loaded {n}"]
                    await asyncio.sleep(0)
                for n in names:
                    assert (await run_cmd(core, "unload", n)) == [f"Unloaded {n}"]
                    await asyncio.sleep(0)
            stop.set()

        pumps = [asyncio.create_task(pump()) for _ in range(3)]
        await churn()
        await asyncio.gather(*pumps)
        assert not errors, errors
        assert dispatched > 0
        assert core.plugin.plugins == {}

    asyncio.run(go())


# ---------------------------------------------------------------- PLG-2

def test_load_example_works(core):
    out = asyncio.run(run_cmd(core, "load", "example"))
    assert out == ["Loaded example"]
    plugin = core.plugin.plugins["example"]
    assert isinstance(plugin, Plugin) and type(plugin) is not Plugin
    assert plugin.name == "example"
    assert "example_core_timer" in core.timers
    assert {"cmd": "REGISTER_IRC_TIMER", "name": "example_irc_timer",
            "interval": 30} in core.sent
    out = asyncio.run(run_cmd(core, "unload", "example"))
    assert out == ["Unloaded example"]
    assert "example_core_timer" not in core.timers


@pytest.mark.parametrize("name", sorted(plugin_mod.plugin_files()))
def test_every_shipped_plugin_has_a_discoverable_class(name):
    cls = PluginManager._plugin_class(name)
    assert issubclass(cls, Plugin) and cls is not Plugin
    assert cls.name == name


def test_init_module_is_not_a_plugin(core):
    out = asyncio.run(run_cmd(core, "load", "__init__"))
    assert out == [plugin_mod.PLUGIN_NAME_RULE_TEXT]
    assert core.plugin.plugins == {}


# ---------------------------------------------------------------- PLG-3

SEED = {
    "limit": ("INSERT INTO limit_settings(channel, limitadd) VALUES('#wbs', 7)",
              ["limit_settings"]),
    "stats": ("INSERT INTO stats_nick(nick, messages) VALUES('pown', 59)",
              ["stats_nick"]),
    "topiclock": ("INSERT INTO topiclock(channel, enabled, topic) VALUES('#wbs', 1, 'LOCKED')",
                  ["topiclock"]),
    "chanlock": ("INSERT INTO chanlock_audit(channel, action) VALUES('#wbs', 'lock')",
                 ["chanlock_audit"]),
}


async def _count(core, table):
    return await scalar(core, f"SELECT COUNT(*) FROM {table}")


@pytest.mark.parametrize("name", sorted(SEED))
def test_unload_then_load_keeps_plugin_rows(core, name):
    sql, tables = SEED[name]

    async def go():
        assert (await run_cmd(core, "load", name)) == [f"Loaded {name}"]
        async with get_db(core.db_path) as db:
            await db.execute(sql)
        before = {t: await _count(core, t) for t in tables}
        assert all(v == 1 for v in before.values())

        assert (await run_cmd(core, "unload", name)) == [f"Unloaded {name}"]
        assert {t: await _count(core, t) for t in tables} == before
        assert (await run_cmd(core, "load", name)) == [f"Loaded {name}"]
        assert {t: await _count(core, t) for t in tables} == before

        await core.plugin.reload_plugin(name)
        assert {t: await _count(core, t) for t in tables} == before

    asyncio.run(go())


def test_limit_setting_is_used_after_reload(core):
    async def go():
        await core.plugin.load_plugin("limit")
        async with get_db(core.db_path) as db:
            await db.execute("INSERT INTO limit_settings(channel, limitadd) VALUES('#wbs', 7)")
        await core.plugin.unload_plugin("limit")
        await core.plugin.load_plugin("limit")
        cfg = await core.plugin.plugins["limit"]._load_settings("#wbs")
        assert cfg["limitadd"] == 7
    asyncio.run(go())


def test_plugin_purge_drops_tables_only_on_request(core):
    async def go():
        sid = 7
        core.partyline.sessions[sid] = {"type": "console", "handle": "console"}
        await core.plugin.load_plugin("stats")
        async with get_db(core.db_path) as db:
            await db.execute("INSERT INTO stats_nick(nick) VALUES('pown')")

        out = await run_cmd(core, "plugin", "purge stats", sid)
        assert out == ["stats is loaded; .unload stats first"]
        assert await _count(core, "stats_nick") == 1

        await run_cmd(core, "unload", "stats", sid)
        out = await run_cmd(core, "plugin", "purge stats", sid)
        assert out == ["Purged stats: dropped stats_nick, stats_nick_channel, stats_victims"]
        assert await scalar(core, "SELECT COUNT(*) FROM sqlite_master WHERE name='stats_nick'") == 0
        assert await autoload_flag(core, "stats") is None

        assert (await run_cmd(core, "plugin", "purge ../x", sid)) == [
            plugin_mod.PLUGIN_NAME_RULE_TEXT]
        assert (await run_cmd(core, "plugin", "wipe stats", sid)) == [
            "Usage: .plugin purge <plugin>"]
        # Loading again recreates empty tables.
        assert (await run_cmd(core, "load", "stats", sid)) == ["Loaded stats"]
        assert await _count(core, "stats_nick") == 0
    asyncio.run(go())


def test_seen_purge_covers_its_tables():
    assert PluginManager._plugin_class("seen").owned_tables() == ["seen", "seen_notify"]


# ---------------------------------------------------------------- PLG-4

def test_unload_persists_across_a_manager_restart(core):
    core.config["plugins"] = ["limit", "stats"]

    async def go():
        await Core._seed_and_autoload_modules(core)
        assert sorted(core.plugin.plugins) == ["limit", "stats"]

        assert (await run_cmd(core, "unload", "stats")) == ["Unloaded stats"]
        assert await autoload_flag(core, "stats") == 0
        assert await autoload_flag(core, "limit") == 1

        # "Restart": fresh manager, same DB and config.
        core.plugin = PluginManager(core)
        await Core._seed_and_autoload_modules(core)
        assert sorted(core.plugin.plugins) == ["limit"]

        # `.load` restores autoload, so the next restart loads it again.
        assert (await run_cmd(core, "load", "stats")) == ["Loaded stats"]
        assert await autoload_flag(core, "stats") == 1
        core.plugin = PluginManager(core)
        await Core._seed_and_autoload_modules(core)
        assert sorted(core.plugin.plugins) == ["limit", "stats"]
    asyncio.run(go())


def test_unload_goes_through_the_manager(core, monkeypatch):
    calls = []
    real = PluginManager.unload_plugin

    async def spy(self, name):
        calls.append(name)
        return await real(self, name)

    monkeypatch.setattr(PluginManager, "unload_plugin", spy)

    async def go():
        await run_cmd(core, "load", "topiclock")
        assert (await run_cmd(core, "unload", "topiclock")) == ["Unloaded topiclock"]
    asyncio.run(go())
    assert calls == ["topiclock"]


def test_plugins_listing_counts_autoload_from_db(core):
    async def go():
        for n in ("limit", "stats", "topiclock"):
            await run_cmd(core, "load", n)
        await run_cmd(core, "unload", "topiclock")
        out = "\n".join(await run_cmd(core, "plugins", ""))
        assert "Loaded (2): ['limit', 'stats']" in out
        assert "Auto-load (2): ['limit', 'stats']" in out
        assert "example" in out.split("On disk")[1]
        assert "__init__" not in out
    asyncio.run(go())


# ---------------------------------------------------------------- PLG-5

BAD_NAMES = ["../x", "..", "../plugins/seen", "../../.tmp/plg", "/etc/passwd",
             "seen;x", "a.b", "SEEN", "seen.py", "__pycache__/x", "__init__",
             "_x", "1abc", "a" * 33, "sée"]


@pytest.mark.parametrize("bad", BAD_NAMES)
def test_bad_names_refused_before_any_import(core, bad, monkeypatch):
    def boom(*a, **k):
        raise AssertionError(f"import attempted for {bad!r}")

    monkeypatch.setattr(plugin_mod.importlib, "import_module", boom)
    for cmd in ("load", "unload"):
        out = asyncio.run(run_cmd(core, cmd, bad))
        assert out == [plugin_mod.PLUGIN_NAME_RULE_TEXT], (cmd, out)
    with pytest.raises(RuntimeError, match="Invalid plugin name"):
        asyncio.run(core.plugin.load_plugin(bad))
    assert core.plugin.plugins == {}


def test_existence_check_uses_package_dir_not_cwd(core, tmp_path, monkeypatch):
    # From an unrelated CWD a real plugin still loads ...
    monkeypatch.chdir(tmp_path)
    assert asyncio.run(run_cmd(core, "load", "limit")) == ["Loaded limit"]
    # ... and a file that exists only relative to the CWD is not a plugin.
    (tmp_path / "src" / "plugins").mkdir(parents=True)
    (tmp_path / "src" / "plugins" / "evil.py").write_text("raise SystemExit\n")
    assert asyncio.run(run_cmd(core, "load", "evil")) == ["evil.py not found in src/plugins/"]
    assert "evil" not in core.plugin.plugins
    assert os.path.isdir(plugin_mod.PLUGINS_DIR)
