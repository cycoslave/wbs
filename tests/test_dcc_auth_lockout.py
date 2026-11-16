"""
Offline regression tests for Mythos F-04b (CWE-307): DCC password failures
(socket challenge and the IRC `chatauth` fallback) feed the same AccessGuard
per-(host, handle) lockout as `/msg identify` (F-04), so they add up across
sockets.  The per-socket cap (auth_attempts) stays.  Sockets are mocked; throwaway
sqlite under tmp_path.
"""
import asyncio

import pytest

from src.net import AccessGuard
from test_dcc_negotiation import chat_args

from test_dcc_session_contract import (  # noqa: E402  (shared offline fakes)
    ALICE, PW, assert_no_session, assert_one_session, db, db_template, make,
    open_socket_mode, privmsg, reader_with, rnet, run, until,
)

MAX = 3
HOST = "home.example"
BAD = "wrong-password"       # test-only value


def guarded(db, **cfg):
    cfg.setdefault("rate_limit", 50)      # the per-host request limiter is not under test
    core, mgr = make(db, **cfg)
    core.guard = AccessGuard(db, {"settings": {"max_failures": MAX,
                                               "lockout_seconds": 300}})
    return core, mgr


def count_verifies(core):
    calls = []
    real = core.user.verify_password

    async def spy(handle, password):
        calls.append((handle, password))
        return await real(handle, password)
    core.user.verify_password = spy
    return calls


async def socket_attempt(mode, core, mgr, *answers):
    w = await open_socket_mode(mode, core, mgr, ALICE, reader_with(*answers, eof=True))
    await until(lambda: w.closed and not mgr._pending)
    return w


def test_socket_failures_add_up_across_two_sockets_to_a_lockout(db, rnet):
    core, mgr = guarded(db, mode="active", public_ip="198.51.100.7", auth_attempts=2)
    verifies = count_verifies(core)

    async def go():
        # Socket 1: both attempts used up (per-socket cap 2) -> count 2.
        w1 = await socket_attempt("active", core, mgr, BAD, BAD, PW["alice"])
        assert w1.data.count(b"Incorrect password.") == 2
        assert not core.guard.handle_locked(HOST, "alice")
        # Socket 2: a third failure locks the pair; the correct password that
        # follows is answered like any failure and is never checked.
        n = len(verifies)
        w2 = await socket_attempt("active", core, mgr, BAD, PW["alice"])
        assert core.guard.handle_locked(HOST, "alice")
        assert w2.data.count(b"Incorrect password.") == 2
        assert verifies[n:] == [("alice", BAD)]
        # Socket 3: locked from the first answer, no password check at all.
        n = len(verifies)
        w3 = await socket_attempt("active", core, mgr, PW["alice"])
        assert w3.data.count(b"Incorrect password.") == 1
        assert verifies[n:] == []
    run(rnet, go)
    assert_no_session(core, mgr)


def test_per_socket_cap_of_three_still_applies(db, rnet):
    core, mgr = guarded(db, mode="active", public_ip="198.51.100.7")

    async def go():
        w = await socket_attempt("active", core, mgr, BAD, BAD, BAD, PW["alice"])
        assert w.data.count(b"Enter your password.") == 3
    run(rnet, go)
    assert_no_session(core, mgr)


def test_lock_is_per_handle_and_per_host(db, rnet):
    core, mgr = guarded(db, mode="active", public_ip="198.51.100.7")

    async def go():
        await socket_attempt("active", core, mgr, BAD, BAD, BAD)
        assert core.guard.handle_locked(HOST, "alice")
        assert not core.guard.handle_locked("elsewhere.example", "alice")
        assert not core.guard.handle_locked(HOST, "carol")
    run(rnet, go)


def test_socket_success_resets_the_count(db, rnet):
    core, mgr = guarded(db, mode="active", public_ip="198.51.100.7")

    async def go():
        await socket_attempt("active", core, mgr, BAD, BAD)
        assert core.guard._handle_failures[(HOST, "alice")].count == 2
        reader = reader_with(PW["alice"])
        w = await open_socket_mode("active", core, mgr, ALICE, reader)
        await until(lambda: mgr._sessions)
        assert_one_session(core, mgr, "alice", w)
        await until(lambda: (HOST, "alice") not in core.guard._handle_failures)
        assert (HOST, "alice") not in core.guard._handle_failures
        reader.feed_eof()
        await until(lambda: not mgr._sessions)
        # Two more failures after the reset do not lock.
        await socket_attempt("active", core, mgr, BAD, BAD)
        assert not core.guard.handle_locked(HOST, "alice")
    run(rnet, go)


def test_irc_fallback_failures_are_recorded_and_lock(db, rnet):
    core, mgr = guarded(db, mode="irc")
    verifies = count_verifies(core)

    async def go():
        for i in range(MAX):
            await mgr.handle_request(*ALICE, chat_args())
            assert await mgr.on_privmsg(privmsg(ALICE, f"chatauth {BAD}")) is True
            assert core.guard._handle_failures[(HOST, "alice")].count == i + 1
        assert core.guard.handle_locked(HOST, "alice")
        # Locked: the correct password gets the ordinary failure notice, unchecked.
        n = len(verifies)
        core.sent.clear()
        await mgr.handle_request(*ALICE, chat_args())
        core.sent.clear()
        assert await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}")) is True
        assert core.notices("Alice") == ["DCC: authentication failed."]
        assert verifies[n:] == []
    run(rnet, go)
    assert_no_session(core, mgr)


def test_irc_fallback_success_resets_the_count(db, rnet):
    core, mgr = guarded(db, mode="irc")

    async def go():
        for _ in range(MAX - 1):
            await mgr.handle_request(*ALICE, chat_args())
            await mgr.on_privmsg(privmsg(ALICE, f"chatauth {BAD}"))
        assert core.guard._handle_failures[(HOST, "alice")].count == MAX - 1
        await mgr.handle_request(*ALICE, chat_args())
        await mgr.on_privmsg(privmsg(ALICE, f"chatauth {PW['alice']}"))
        await until(lambda: (HOST, "alice") not in core.guard._handle_failures)
        assert (HOST, "alice") not in core.guard._handle_failures
        assert len(mgr._sessions) == 1
        for sess in list(mgr._sessions.values()):
            sess.shutdown("test done")
    run(rnet, go)


def test_socket_and_irc_failures_share_one_counter(db, rnet):
    core, mgr = guarded(db, mode="active", public_ip="198.51.100.7")

    async def go():
        await socket_attempt("active", core, mgr, BAD, BAD)
        mgr.mode = "irc"  # DCCManager reads self.mode per request
        await mgr.handle_request(*ALICE, chat_args())
        await mgr.on_privmsg(privmsg(ALICE, f"chatauth {BAD}"))
        assert core.guard.handle_locked(HOST, "alice")
    run(rnet, go)


def test_dcc_login_without_guard_still_works(db, rnet):
    core, mgr = make(db, mode="active", public_ip="198.51.100.7")
    assert getattr(core, "guard", None) is None

    async def go():
        await socket_attempt("active", core, mgr, BAD, BAD, BAD)
        reader = reader_with(PW["alice"])
        w = await open_socket_mode("active", core, mgr, ALICE, reader)
        await until(lambda: mgr._sessions)
        assert_one_session(core, mgr, "alice", w)
        reader.feed_eof()
        await until(lambda: not mgr._sessions)
    run(rnet, go)
