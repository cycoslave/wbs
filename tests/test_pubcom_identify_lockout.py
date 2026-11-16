"""
Offline regression tests for Mythos F-04 (CWE-307): failed `/msg identify`
attempts are counted in the AccessGuard (net.py record_failure) per
(host, target handle) and lock that pair after max_failures, exactly like the
botlink/partyline path.  Throwaway sqlite under tmp_path; no network.
"""
import asyncio

import pytest

from src.net import AccessGuard
from src.plugins.pubcom import pubcomPlugin

from test_pubcom_authz import FakeCore, build_db, host, identify, run

MAX = 3
BAD = "wrong-password"          # test-only value
GOOD_HOST = host("Boss", h="home.example")


def make(tmp_path, **cfg):
    db = asyncio.run(build_db(tmp_path))
    core = FakeCore(db)
    core.guard = AccessGuard(db, {"settings": {"max_failures": MAX,
                                               "lockout_seconds": 300, **cfg}})
    return core, pubcomPlugin(core)


async def drain():
    """Let record_success's fire-and-forget DB cleanup finish before the loop closes."""
    rest = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    if rest:
        await asyncio.gather(*rest, return_exceptions=True)


async def attempt(plugin, core, nick, handle, password, hostmask=None):
    core.reset()
    await identify(plugin, nick, handle, password, hostmask=hostmask)
    await drain()
    return core.notices()


def test_locked_after_n_failures_and_refused_even_with_correct_password(tmp_path):
    core, plugin = make(tmp_path)

    async def go():
        for _ in range(MAX):
            assert await attempt(plugin, core, "Boss", "gop", BAD) == ["Invalid credentials!"]
        assert core.guard.handle_locked("home.example", "gop")
        # Correct password while locked: same reply as a failure, no session.
        out = await attempt(plugin, core, "Boss", "gop", "correct-horse")
        assert out == ["Invalid credentials!"]
        assert plugin.auth_sessions == {}
    run(go())


def test_not_locked_before_threshold(tmp_path):
    core, plugin = make(tmp_path)

    async def go():
        for _ in range(MAX - 1):
            await attempt(plugin, core, "Boss", "gop", BAD)
        assert not core.guard.handle_locked("home.example", "gop")
        assert await attempt(plugin, core, "Boss", "gop", "correct-horse") == [
            "Logged in successfully!"]
    run(go())


def test_locked_reply_identical_to_failure_reply(tmp_path):
    core, plugin = make(tmp_path)

    async def go():
        fail_reply = await attempt(plugin, core, "Boss", "gop", BAD)
        for _ in range(MAX):
            await attempt(plugin, core, "Boss", "gop", BAD)
        assert await attempt(plugin, core, "Boss", "gop", BAD) == fail_reply
    run(go())


def test_failures_are_per_handle_and_per_host(tmp_path):
    core, plugin = make(tmp_path)

    async def go():
        for _ in range(MAX):
            await attempt(plugin, core, "Boss", "gop", BAD)
        # Other handle from the same host, and same handle from another host.
        assert await attempt(plugin, core, "Boss", "admin", "correct-horse") == [
            "Logged in successfully!"]
        other = host("Boss", h="elsewhere.example")
        assert await attempt(plugin, core, "Boss", "gop", "correct-horse",
                             hostmask=other) == ["Logged in successfully!"]
    run(go())


def test_unknown_handle_is_counted_and_locked_too(tmp_path):
    core, plugin = make(tmp_path)

    async def go():
        for _ in range(MAX):
            await attempt(plugin, core, "Boss", "nosuchuser", BAD)
        assert core.guard.handle_locked("home.example", "nosuchuser")
    run(go())


def test_success_clears_counter(tmp_path):
    core, plugin = make(tmp_path)

    async def go():
        for _ in range(MAX - 1):
            await attempt(plugin, core, "Boss", "gop", BAD)
        assert await attempt(plugin, core, "Boss", "gop", "correct-horse") == [
            "Logged in successfully!"]
        assert ("home.example", "gop") not in core.guard._handle_failures
        # A fresh run of MAX-1 failures does not lock: the counter restarted.
        for _ in range(MAX - 1):
            await attempt(plugin, core, "Boss", "gop", BAD)
        assert not core.guard.handle_locked("home.example", "gop")
    run(go())


def test_lock_expires_after_window(tmp_path):
    core, plugin = make(tmp_path, lockout_seconds=300)

    async def go():
        for _ in range(MAX):
            await attempt(plugin, core, "Boss", "gop", BAD)
        core.guard._handle_failures[("home.example", "gop")].last_at -= 301
        assert await attempt(plugin, core, "Boss", "gop", "correct-horse") == [
            "Logged in successfully!"]
    run(go())


def test_identify_without_guard_still_works(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    core = FakeCore(db)
    plugin = pubcomPlugin(core)

    async def go():
        for _ in range(MAX + 2):
            await attempt(plugin, core, "Boss", "gop", BAD)
        assert await attempt(plugin, core, "Boss", "gop", "correct-horse") == [
            "Logged in successfully!"]
    run(go())


# --- N-01: failing against other handles must not clear a handle's lock ------

def _block_address_via_other_handles(core, plugin, locked_handle="gop"):
    """5 failures on `locked_handle`, then 15 more on other names from the same
    host: the 20th failure auto-blocks the address (max_failures_ip = 4 * 5)."""
    async def go():
        for _ in range(5):
            await attempt(plugin, core, "Boss", locked_handle, BAD)
        assert core.guard.handle_locked("home.example", locked_handle)
        for i in range(15):
            await attempt(plugin, core, "Boss", f"other{i}", BAD)
        entry = await core.guard.denied_by(ip="home.example", host="home.example")
        assert entry is not None and entry.reason == "auth_failure"
    return go()


def test_lock_survives_address_auto_block_n01(tmp_path):
    core, plugin = make(tmp_path, max_failures=5, lockout_seconds=300)

    async def go():
        await _block_address_via_other_handles(core, plugin)
        # The pair record outlives the address block...
        assert core.guard.handle_locked("home.example", "gop")
        # ...and the correct password for it is still refused.
        assert await attempt(plugin, core, "Boss", "gop", "correct-horse") == [
            "Invalid credentials!"]
        assert plugin.auth_sessions == {}
    run(go())


def test_identify_refused_while_address_blocked_n01(tmp_path):
    core, plugin = make(tmp_path, max_failures=5, lockout_seconds=300)

    async def go():
        await _block_address_via_other_handles(core, plugin)
        # A handle with no failure record of its own: refused by the address block.
        assert not core.guard.handle_locked("home.example", "admin")
        assert await attempt(plugin, core, "Boss", "admin", "correct-horse") == [
            "Invalid credentials!"]
        assert plugin.auth_sessions == {}
        # Other hosts are unaffected.
        other = host("Boss", h="elsewhere.example")
        assert await attempt(plugin, core, "Boss", "admin", "correct-horse",
                             hostmask=other) == ["Logged in successfully!"]
    run(go())
