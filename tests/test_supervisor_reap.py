"""Supervisor reaping: a fired sentinel does not mean the exit code is known.

Regression for `.rehash` then `.die` relaunching Core: the supervisor read
``proc.exitcode`` as None right after the sentinel fired (child fds closed,
not yet reapable) and took the crash-relaunch branch.
"""
from multiprocessing import Process
from multiprocessing.connection import wait as mp_wait

from src.main import reap_exitcode

EXIT_OK = 42  # Core's clean-exit code (.die), see src/main.py


class FakeProc:
    """Sentinel fired, but exitcode is None until join() reaps the child."""

    def __init__(self, final_code, reaped_by_join=True):
        self._final = final_code
        self._reaped = False
        self._reaped_by_join = reaped_by_join
        self.join_calls = []

    @property
    def exitcode(self):
        return self._final if self._reaped else None

    def join(self, timeout=None):
        self.join_calls.append(timeout)
        if self._reaped_by_join:
            self._reaped = True


def test_none_on_first_read_is_reaped_not_a_crash():
    proc = FakeProc(EXIT_OK)
    assert reap_exitcode(proc, timeout=1.0) == EXIT_OK
    assert proc.join_calls == [1.0]


def test_still_unknown_after_join_reports_none_for_retry():
    proc = FakeProc(EXIT_OK, reaped_by_join=False)
    assert reap_exitcode(proc, timeout=0.01) is None
    assert proc.join_calls == [0.01]


def test_known_code_needs_no_join():
    proc = FakeProc(43)
    proc._reaped = True
    assert reap_exitcode(proc) == 43
    assert proc.join_calls == []


def _exit_with(code):
    raise SystemExit(code)


def test_real_child_code_available_as_soon_as_sentinel_fires():
    for _ in range(20):
        p = Process(target=_exit_with, args=(EXIT_OK,))
        p.start()
        assert mp_wait([p.sentinel], timeout=10.0)
        assert reap_exitcode(p) == EXIT_OK
