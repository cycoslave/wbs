"""
WB3-002: bcrypt must not run on the Core event loop.

Covered:
  * a slow verify/hash (fake and real bcrypt) leaves a concurrent asyncio
    ticker running with max gap < 50 ms; a control shows the same fake blocks
    the loop when called inline
  * at most MAX_CONCURRENT_BCRYPT jobs are in flight, however many are queued
  * behaviour is unchanged: same hash format, True/False, ValueError on a
    malformed hash, UserManager.verify_password still returns False for it
  * UserManager.set_password / verify_password / BotManager.set_password keep
    the loop responsive and stay correct

Every DB is a throwaway sqlite file under pytest's tmp_path.
"""
import asyncio
import threading
import time

import bcrypt
import pytest

from src import crypto_exec
from src.bot import BotManager
from src.db import get_db
from src.user import UserManager

from test_console_operator import build_db

MAX_GAP = 0.050     # seconds: longest tolerated stall of the ticker
SLOW = 0.30         # seconds: stand-in for ~290 ms of bcrypt CPU


async def _ticker(stop: asyncio.Event, gaps: list, interval: float = 0.005):
    last = time.perf_counter()
    while not stop.is_set():
        await asyncio.sleep(interval)
        now = time.perf_counter()
        gaps.append(now - last)
        last = now


async def _with_ticker(coro_factory):
    """Run coro_factory() while a ticker runs; return (result, max_gap, ticks, elapsed)."""
    stop, gaps = asyncio.Event(), []
    tick = asyncio.create_task(_ticker(stop, gaps))
    await asyncio.sleep(0.02)       # let the ticker settle
    gaps.clear()
    t0 = time.perf_counter()
    try:
        result = await coro_factory()
    finally:
        elapsed = time.perf_counter() - t0
        stop.set()
        await tick
    return result, max(gaps), len(gaps), elapsed


def _slow(monkeypatch, name, value):
    """Replace bcrypt.<name> with a CPU-blocking (GIL-releasing sleep) fake."""
    def fake(*_a, **_kw):
        time.sleep(SLOW)
        return value
    monkeypatch.setattr(bcrypt, name, fake)


# --- event loop stays responsive ------------------------------------------------

def test_control_inline_slow_call_blocks_loop(monkeypatch):
    """Sanity: the ticker really detects a blocked loop (this is the old behaviour)."""
    _slow(monkeypatch, "checkpw", True)

    async def go():
        async def inline():
            return bcrypt.checkpw(b"x", b"y")
        _, gap, _, _ = await _with_ticker(inline)
        assert gap >= SLOW * 0.9
    asyncio.run(go())


def test_verify_password_does_not_block_loop(monkeypatch):
    _slow(monkeypatch, "checkpw", True)

    async def go():
        ok, gap, ticks, elapsed = await _with_ticker(lambda: crypto_exec.verify_password("pw", "hash"))
        assert ok is True
        assert elapsed >= SLOW * 0.9
        assert ticks >= 10, ticks
        assert gap < MAX_GAP, gap
    asyncio.run(go())


def test_hash_password_does_not_block_loop(monkeypatch):
    _slow(monkeypatch, "hashpw", b"$2b$12$fakefakefakefakefakefakefake")

    async def go():
        out, gap, ticks, _ = await _with_ticker(lambda: crypto_exec.hash_password("pw"))
        assert out == "$2b$12$fakefakefakefakefakefakefake"
        assert ticks >= 10, ticks
        assert gap < MAX_GAP, gap
    asyncio.run(go())


def test_real_bcrypt_default_cost_does_not_block_loop():
    async def go():
        hashed, gap_h, _, _ = await _with_ticker(lambda: crypto_exec.hash_password("correct horse"))
        assert gap_h < MAX_GAP, gap_h
        ok, gap_v, _, _ = await _with_ticker(lambda: crypto_exec.verify_password("correct horse", hashed))
        assert ok is True
        assert gap_v < MAX_GAP, gap_v
        assert await crypto_exec.verify_password("wrong horse", hashed) is False
    asyncio.run(go())


# --- bounded concurrency --------------------------------------------------------

def test_semaphore_caps_concurrent_jobs(monkeypatch):
    lock = threading.Lock()
    state = {"now": 0, "max": 0, "calls": 0}

    def fake_checkpw(*_a, **_kw):
        with lock:
            state["now"] += 1
            state["calls"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(0.05)
        with lock:
            state["now"] -= 1
        return True
    monkeypatch.setattr(bcrypt, "checkpw", fake_checkpw)

    async def go():
        results = await asyncio.gather(*(crypto_exec.verify_password("pw", "h") for _ in range(12)))
        assert results == [True] * 12
    asyncio.run(go())
    assert crypto_exec.MAX_CONCURRENT_BCRYPT == 2
    assert state["calls"] == 12
    assert state["max"] == crypto_exec.MAX_CONCURRENT_BCRYPT


def test_cap_holds_and_loop_stays_responsive_under_a_flood(monkeypatch):
    """A login flood queues as coroutines: the loop keeps ticking while jobs wait."""
    _slow(monkeypatch, "checkpw", False)

    async def go():
        async def flood():
            return await asyncio.gather(*(crypto_exec.verify_password("pw", "h") for _ in range(6)))
        out, gap, _, elapsed = await _with_ticker(flood)
        assert out == [False] * 6
        assert elapsed >= 3 * SLOW * 0.9      # 6 jobs / 2 at a time
        assert gap < MAX_GAP, gap
    asyncio.run(go())


def test_semaphore_is_per_event_loop():
    """Separate asyncio.run() calls (one loop each) must not trip over a stale semaphore."""
    async def go():
        return await crypto_exec.verify_password("pw", bcrypt.hashpw(b"pw", bcrypt.gensalt(4)).decode())
    assert asyncio.run(go()) is True
    assert asyncio.run(go()) is True


def test_cancelled_waiter_releases_slot(monkeypatch):
    _slow(monkeypatch, "checkpw", True)

    async def go():
        tasks = [asyncio.create_task(crypto_exec.verify_password("pw", "h")) for _ in range(4)]
        await asyncio.sleep(0.05)
        for t in tasks[2:]:         # queued behind the two running jobs
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # both slots must be usable again
        assert await asyncio.gather(crypto_exec.verify_password("pw", "h"),
                                    crypto_exec.verify_password("pw", "h")) == [True, True]
    asyncio.run(go())


# --- behaviour unchanged --------------------------------------------------------

def test_hash_and_verify_semantics():
    async def go():
        h = await crypto_exec.hash_password("s3cret-pass")
        assert isinstance(h, str) and h.startswith("$2b$")
        assert bcrypt.checkpw(b"s3cret-pass", h.encode())           # plain bcrypt accepts it
        assert await crypto_exec.verify_password("s3cret-pass", h) is True
        assert await crypto_exec.verify_password("s3cret-pasS", h) is False
        # two hashes of one password differ (fresh salt each time)
        assert h != await crypto_exec.hash_password("s3cret-pass")
        # a hash made by plain bcrypt verifies
        plain = bcrypt.hashpw(b"abc", bcrypt.gensalt(4)).decode()
        assert await crypto_exec.verify_password("abc", plain) is True
        # primitives
        salt = await crypto_exec.gensalt()
        assert salt.startswith(b"$2b$")
        assert await crypto_exec.hashpw(b"abc", salt) == bcrypt.hashpw(b"abc", salt)
        assert await crypto_exec.checkpw(b"abc", plain.encode()) is True
    asyncio.run(go())


def test_malformed_hash_raises_like_bcrypt():
    async def go():
        with pytest.raises(ValueError):
            await crypto_exec.verify_password("pw", "$2b$12$x")
    asyncio.run(go())


# --- through the managers ---------------------------------------------------------

def test_usermanager_password_roundtrip_keeps_loop_responsive(tmp_path, monkeypatch):
    async def go():
        db = await build_db(tmp_path)
        um = UserManager(db)
        _slow(monkeypatch, "hashpw", b"$2b$12$" + b"a" * 53)
        ok, gap, _, _ = await _with_ticker(lambda: um.set_password("bob", "pw-12345678"))
        assert ok is True
        assert gap < MAX_GAP, gap
        async with get_db(db) as d:
            row = await (await d.execute("SELECT password FROM users WHERE handle='bob'")).fetchone()
        assert row[0] == "$2b$12$" + "a" * 53
        monkeypatch.undo()

        assert await um.set_password("bob", "pw-12345678") is True
        _slow(monkeypatch, "checkpw", True)
        ok, gap, _, _ = await _with_ticker(lambda: um.verify_password("bob", "pw-12345678"))
        assert ok is True
        assert gap < MAX_GAP, gap
        ok, gap, _, _ = await _with_ticker(lambda: um.authenticate("bob", "pw-12345678"))
        assert ok is True
        assert gap < MAX_GAP, gap
        monkeypatch.undo()

        # unchanged edge cases
        assert await um.verify_password("bob", "wrong-password") is False
        assert await um.verify_password("carol", "pw-12345678") is False      # locked
        assert await um.verify_password("nobody", "pw-12345678") is False
        assert await um.set_password("nobody", "pw-12345678") is False
        assert await um.set_password("bob", "") is True                         # clears the hash
        assert await um.verify_password("bob", "pw-12345678") is False
    asyncio.run(go())


def test_usermanager_malformed_stored_hash_is_false(tmp_path):
    async def go():
        um = UserManager(await build_db(tmp_path))          # fixture hash '$2b$12$x' is malformed
        assert await um.verify_password("bob", "anything-at-all") is False
    asyncio.run(go())


def test_botmanager_set_password_off_loop(tmp_path, monkeypatch):
    async def go():
        db = await build_db(tmp_path)
        bm = BotManager(db)
        real = bcrypt.gensalt
        monkeypatch.setattr(bcrypt, "gensalt", lambda rounds=4, prefix=b"2b": real(4, prefix))
        _slow(monkeypatch, "hashpw", b"$2b$04$" + b"b" * 53)
        _, gap, _, _ = await _with_ticker(lambda: bm.set_password("peerbot", "bot-pass-123"))
        assert gap < MAX_GAP, gap
        monkeypatch.undo()
        async with get_db(db) as d:
            row = await (await d.execute("SELECT password FROM bots WHERE handle='peerbot'")).fetchone()
        assert row[0] == "$2b$04$" + "b" * 53
        assert not await bm.set_password("ghost", "bot-pass-123")     # unknown bot: unchanged (no row)
    asyncio.run(go())
