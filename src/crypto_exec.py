# src/crypto_exec.py
"""
Bounded off-loop bcrypt (WB3-002).

bcrypt at the default cost takes ~290 ms of pure CPU per call.  Run on the
Core asyncio loop it freezes every socket (IRC, botlink, DCC, partyline) for
that long, once per login attempt.  Every coroutine-path bcrypt call goes
through this module instead:

  * the work runs on a small dedicated thread pool (bcrypt releases the GIL),
    so it neither blocks the loop nor starves the loop's default executor
    (DNS lookups etc.);
  * an asyncio.Semaphore caps how many bcrypt jobs are in flight (default 2),
    so a login flood queues as cheap coroutines instead of piling up threads.

Behaviour is that of the bcrypt calls it wraps: same hashes, same return
values, same exceptions (ValueError for a malformed hash, ...).  The
constant-time comparison stays inside bcrypt.checkpw.  bcrypt is looked up on
the module at call time so tests can patch bcrypt.gensalt / checkpw.
"""
import asyncio
import weakref
from concurrent.futures import ThreadPoolExecutor

import bcrypt

MAX_CONCURRENT_BCRYPT = 2   # config-free constant: in-flight bcrypt jobs (and pool threads)

_executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_BCRYPT, thread_name_prefix="wbs-bcrypt")
# One semaphore per event loop (a Semaphore binds to the loop that first waits on it).
_semaphores: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = weakref.WeakKeyDictionary()


def _semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    sem = _semaphores.get(loop)
    if sem is None:
        sem = _semaphores[loop] = asyncio.Semaphore(MAX_CONCURRENT_BCRYPT)
    return sem


async def _run(func, *args):
    async with _semaphore():
        return await asyncio.get_running_loop().run_in_executor(_executor, func, *args)


def _hash(password: bytes) -> bytes:
    return bcrypt.hashpw(password, bcrypt.gensalt())


async def gensalt() -> bytes:
    """bcrypt.gensalt(), off the event loop."""
    return await _run(bcrypt.gensalt)


async def hashpw(password: bytes, salt: bytes) -> bytes:
    """bcrypt.hashpw(password, salt), off the event loop."""
    return await _run(bcrypt.hashpw, password, salt)


async def checkpw(password: bytes, hashed: bytes) -> bool:
    """bcrypt.checkpw(password, hashed), off the event loop (constant-time compare kept)."""
    return await _run(bcrypt.checkpw, password, hashed)


async def hash_password(password: str) -> str:
    """Hash `password` with a fresh salt: bcrypt.hashpw(pw, bcrypt.gensalt()).decode(), off the loop."""
    return (await _run(_hash, password.encode())).decode()


async def verify_password(password: str, stored_hash: str) -> bool:
    """bool(bcrypt.checkpw(pw, stored_hash)), off the loop.  Raises like bcrypt on a malformed hash."""
    return bool(await checkpw(password.encode(), stored_hash.encode()))
