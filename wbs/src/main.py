# src/main.py
"""
WBS supervisor entry point (``wbs`` console script: ``src.main:main``).

Shared by the installed console script and the repository's ``./wbs``
launcher, which re-execs into the project venv and then delegates here.

Startup-only modules (psutil, the IRC and Core process launchers) are imported
lazily, so ``wbs --help`` needs only the standard library and never touches IRC.
"""
import argparse
import asyncio
import errno
import json
import logging
import logging.handlers
import os
import signal
import stat
import sys
import time
from pathlib import Path
from typing import Optional
from multiprocessing import Process, Queue
from multiprocessing.connection import wait as mp_wait

from . import __version__

log = logging.getLogger("wbs")

def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="wbs")
    parser.add_argument("-c", "--config", default="config.json",
                        help="Path to config file")
    parser.add_argument("-d", "--db-path",
                        help="Override database path from config")
    parser.add_argument("-f", "--foreground", action="store_true",
                        help="Run in foreground with console")
    parser.add_argument("-p", "--mkpasswd", action="store_true",
                        help="Interactively prompt for a password and print its bcrypt hash. "
                            "Use the output in config.json with encryption=bcrypt.")
    parser.add_argument("-s", "--seed", action="store_true",
                        help="Initialize the database and seed from config.json, then exit. "
                            "Must be run once before first launch.")
    parser.add_argument("-u", "--update", action="store_true",
                        help="Check for a newer WBS release and install it if available, then exit. "
                            "The bot does not need to be running. Requires update.host in config.json.")
    parser.add_argument("--pidfile", default=None,
                        help="Override pid file path (default: from config settings.pid_file)")
    parser.add_argument("--logfile", default=None,
                        help="Override log file path (default: from config logging.file)")
    return parser.parse_args(argv)

LOG_FILE_MODE = 0o640
PID_FILE_MODE = 0o644
DEFAULT_LOG_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_LOG_BACKUP_COUNT = 5
LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
# Seconds a child gets to exit after SIGTERM before the SIGKILL (SYS-2).
# Core's graceful shutdown (IRC QUIT, task stop, state save) takes ~2 s.
SHUTDOWN_GRACE = {"core": 10.0, "irc": 5.0}


class SharedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Size-rotated log file shared by the supervisor and its forked children.

    Core and IRC are forked and inherit this handler, so several processes
    write one file (SYS-6).  The size test uses the file's real size, not
    this process's write offset; a rotation takes an exclusive flock on the
    current file, and a process that finds the file already rotated by
    another one only reopens the new file.  New files get LOG_FILE_MODE.
    """

    def __init__(self, filename, maxBytes=DEFAULT_LOG_MAX_BYTES,
                 backupCount=DEFAULT_LOG_BACKUP_COUNT, file_mode=LOG_FILE_MODE):
        self.file_mode = file_mode
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        super().__init__(filename, mode='a', maxBytes=maxBytes,
                         backupCount=backupCount, encoding='utf-8')

    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                     self.file_mode)
        _tighten_mode(fd, self.file_mode)
        return os.fdopen(fd, 'a', encoding=self.encoding, errors=self.errors)

    def _rotated_elsewhere(self) -> bool:
        """True if baseFilename is no longer the file this process writes."""
        try:
            disk = os.stat(self.baseFilename)
            mine = os.fstat(self.stream.fileno())
        except (OSError, ValueError):
            return True
        return (disk.st_dev, disk.st_ino) != (mine.st_dev, mine.st_ino)

    def _reopen(self) -> None:
        old = self._stream_stat()
        if self.stream is not None:
            try:
                self.stream.close()
            except OSError:
                pass
        self.stream = self._open()
        self._follow_stdio(old)

    def _stream_stat(self):
        try:
            return os.fstat(self.stream.fileno()) if self.stream is not None else None
        except (OSError, ValueError):
            return None

    def _follow_stdio(self, old) -> None:
        """Daemon stdout/stderr point at the log file (stray prints and
        tracebacks); move them to the new file after a rotation."""
        if old is None or self.stream is None:
            return
        for fd in (1, 2):
            try:
                if os.path.samestat(os.fstat(fd), old):
                    os.dup2(self.stream.fileno(), fd)
            except OSError:
                pass

    def shouldRollover(self, record) -> bool:
        if os.path.exists(self.baseFilename) and not os.path.isfile(self.baseFilename):
            return False
        if self.stream is None or self._rotated_elsewhere():
            self._reopen()
        if self.maxBytes <= 0 or self.backupCount <= 0:
            return False
        size = os.fstat(self.stream.fileno()).st_size
        if not size:
            return False
        return size + len(self.format(record)) + 1 >= self.maxBytes

    def doRollover(self) -> None:
        # The lock is taken on a fresh open file description: forked
        # children share the stream's description, and flock on a shared
        # description would not exclude them from each other.
        import fcntl
        old = os.fstat(self.stream.fileno())
        try:
            lfd = os.open(self.baseFilename, os.O_RDONLY)
        except OSError:
            self._reopen()                  # gone: another process rotated
            return
        try:
            fcntl.flock(lfd, fcntl.LOCK_EX)
            if self._rotated_elsewhere() or not os.path.samestat(os.fstat(lfd), old):
                self._reopen()              # another process rotated first
                return
            super().doRollover()
            self._follow_stdio(old)
        finally:
            os.close(lfd)                   # releases the lock


def _tighten_mode(fd: int, mode: int) -> None:
    """Drop permission bits beyond ``mode`` from an existing file (SYS-6)."""
    try:
        cur = os.fstat(fd).st_mode & 0o777
        if cur & ~mode:
            os.fchmod(fd, cur & mode)
    except OSError:
        pass


def log_rotation(config: dict) -> tuple[int, int]:
    """``(max_bytes, backup_count)`` from config ``logging`` (SYS-6).

    ``max_bytes: 0`` turns rotation off.  Unset or invalid -> defaults
    (configcheck reports invalid values at startup).
    """
    cfg = (config or {}).get('logging') or {}

    def _get(key, default):
        val = cfg.get(key, default)
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            return default
        return val
    return _get('max_bytes', DEFAULT_LOG_MAX_BYTES), _get('backup_count', DEFAULT_LOG_BACKUP_COUNT)


def use_file_logging(logfile: str, config: dict, keep_console: bool = False) -> None:
    """Make the root logger write to ``logfile`` (rotated).

    Daemon mode and ``.detach`` (``keep_console=False``): handlers bound to
    the terminal streams are removed, so no line is logged twice (SYS-6).
    Foreground mode (``keep_console=True``): the console handler stays and
    the same rotated file handler is added next to it (live O-3).
    """
    root = logging.getLogger()
    target = os.path.abspath(logfile)
    have_file = False
    for h in list(root.handlers):
        if isinstance(h, SharedRotatingFileHandler) and h.baseFilename == target:
            have_file = True
        elif isinstance(h, logging.StreamHandler) and not keep_console:
            root.removeHandler(h)
            if isinstance(h, logging.FileHandler):
                h.close()
    if have_file:
        return
    max_bytes, backups = log_rotation(config)
    handler = SharedRotatingFileHandler(logfile, maxBytes=max_bytes, backupCount=backups)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root.addHandler(handler)


def daemonize(logfile: str = "logs/wbs.log") -> int:
    """Double-fork daemonize to fully detach from the terminal.

    The launching process waits until the daemon reports how its start went
    (``report_started``) and exits with that result: 0 once the daemon owns
    the pidfile, 1 with the daemon's message otherwise (SYS-1).  Returns the
    write end of that status pipe in the daemon.
    """
    rfd, wfd = os.pipe()
    if os.fork():
        os.close(wfd)
        chunks = []
        while True:
            data = os.read(rfd, 4096)
            if not data:
                break
            chunks.append(data)
        status = b"".join(chunks).decode(errors="replace")
        if status.startswith("OK"):
            os._exit(0)
        sys.stderr.write(status.strip() + "\n" if status.strip() else
                         f"ERROR: WBS failed to start (see {logfile})\n")
        sys.stderr.flush()
        os._exit(1)
    os.close(rfd)
    os.setsid()
    if os.fork():
        os._exit(0)
    # Not a session leader any more (cannot regain a terminal): stay so.
    detach_stdio(logfile, new_session=False)
    return wfd


def report_started(wfd: Optional[int], status: str) -> None:
    """Tell the waiting launcher how the daemon's start went (see daemonize)."""
    if wfd is None:
        return
    try:
        os.write(wfd, status.encode())
    except OSError:
        pass
    finally:
        try:
            os.close(wfd)
        except OSError:
            pass

def _child_signals() -> None:
    """Signal dispositions for a supervised child (USR-18).

    Children are forked from the supervisor and would otherwise inherit its
    SIGTERM/SIGINT handler (``_shutdown``), which then runs in the child and
    dies on ``proc.is_alive()`` ("can only test a child process").  The
    supervisor owns shutdown: a child dies on SIGTERM, ignores Ctrl+C (the
    whole foreground process group gets it) and ignores terminal hangup.
    """
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    # The supervisor alone owns the pidfile lock (SYS-1): a child that keeps
    # the fd would hold the lock after the supervisor is gone.
    _drop_pidfile_lock()


def _run_child(target, *args) -> None:
    """Process target: reset inherited signal handlers, then run ``target``."""
    _child_signals()
    target(*args)


def _run_fresh(modname: str, funcname: str, *args) -> None:
    """Process target for ``.rehash`` (USR-16): run ``modname.funcname`` from
    freshly imported code.

    The fork carries the supervisor's already-imported modules, so every
    module of this package is dropped first and ``modname`` is imported
    again; the result is what re-exec'ing Core would give, while keeping the
    queues to the running IRC process (which a real exec cannot carry over).
    """
    import importlib
    _child_signals()
    pkg = __package__ or "src"
    for name in [m for m in sys.modules if m == pkg or m.startswith(pkg + ".")]:
        del sys.modules[name]
    getattr(importlib.import_module(modname), funcname)(*args)


class ConfigAccessError(OSError):
    """config.json is not a private regular file owned by the running user."""


def _config_refusal(path, why: str) -> ConfigAccessError:
    # Names the path and the fix only; never any file content (WB3-001).
    return ConfigAccessError(
        f"refusing to use config file {path}: {why}. "
        f"It holds secrets; fix with: chmod 600 {path}")


def read_config_text(path) -> str:
    """Return the text of the config file after a permission check (WB3-001).

    The file must be a regular file (not a symlink, directory or FIFO), owned
    by the effective user, with no group/other permission bits.  The checks
    run on the descriptor that is then read (O_NOFOLLOW + fstat), so the file
    cannot be swapped between check and read.  ``FileNotFoundError`` and other
    plain ``OSError`` pass through; a refusal is a ``ConfigAccessError``.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise _config_refusal(path, "it is a symbolic link") from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _config_refusal(path, "it is not a regular file")
        if st.st_uid != os.geteuid():
            raise _config_refusal(path, "it is not owned by the user running wbs")
        if st.st_mode & 0o077:
            raise _config_refusal(
                path, f"mode is {stat.S_IMODE(st.st_mode):04o}, "
                      "group/other access is not allowed (need 0600)")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as f:
            return f.read()
    finally:
        os.close(fd)


def load_config(path) -> dict:
    """Read and parse the JSON config file (permission-checked)."""
    return json.loads(read_config_text(path))


def _warn_plaintext_seed_passwords(config: dict) -> None:
    """One-line startup warning when seed users use encryption=none."""
    users = config.get("users")
    if not isinstance(users, list):
        return
    n = 0
    for u in users:
        pw = u.get("password") if isinstance(u, dict) else None
        if isinstance(pw, dict) and pw.get("pass") and \
                str(pw.get("encryption", "bcrypt")).lower() != "bcrypt":
            n += 1
    if n:
        log.warning("config: %d seed user(s) use encryption=none (plaintext password "
                    "in config); hash with --mkpasswd, set encryption=bcrypt, and "
                    "remove them from the config after seeding", n)


def _foreground_holder(child_pid: int) -> int:
    """Body of the process the shell waits on in foreground (-f) mode.

    The supervisor runs in a forked child; this process only waits for it.
    It returns the supervisor's exit code, or exits 0 at once when the
    supervisor reports ``.detach`` (SIGUSR1): the shell gets its terminal
    back and the bot keeps running in the background (USR-9).
    """
    def _on_detached(signum, frame):
        os._exit(0)

    def _forward(signum, frame):
        try:
            os.kill(child_pid, signal.SIGTERM)
        except OSError:
            pass

    signal.signal(signal.SIGUSR1, _on_detached)
    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, signal.SIG_IGN)   # the supervisor gets it too
    try:
        _, status = os.waitpid(child_pid, 0)
    except ChildProcessError:
        return 0
    code = os.waitstatus_to_exitcode(status)
    return code if code >= 0 else 128 - code   # killed by signal N -> 128+N


def detach_stdio(logfile: str, config: Optional[dict] = None, new_session: bool = True) -> None:
    """Leave the terminal: stdin from /dev/null, stdout/stderr to ``logfile``.

    dup2 onto fds 0/1/2, so logging handlers already bound to sys.stdout
    follow, then start a new session (no controlling terminal) if allowed.
    With ``config``, a root handler bound to the terminal streams is
    replaced by the rotated log file handler (SYS-6).
    """
    os.makedirs(os.path.dirname(logfile) or '.', exist_ok=True)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass
    devnull = os.open(os.devnull, os.O_RDONLY)
    out = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, LOG_FILE_MODE)
    _tighten_mode(out, LOG_FILE_MODE)
    try:
        os.dup2(devnull, 0)
        os.dup2(out, 1)
        os.dup2(out, 2)
    finally:
        os.close(devnull)
        os.close(out)
    try:
        if new_session:
            os.setsid()
    except OSError:
        pass   # already a process-group leader; the fds are detached anyway
    if config is not None:
        use_file_logging(logfile, config)


# Open pidfile (flock'ed for the supervisor's lifetime), SYS-1.
_pidfile_fd: Optional[int] = None
_pidfile_path: Optional[str] = None


class AlreadyRunning(RuntimeError):
    def __init__(self, pid: Optional[int]):
        self.pid = pid
        super().__init__(f"WBS is already running (pid {pid if pid is not None else '?'})")


def _read_pidfile(path: str) -> tuple[Optional[int], Optional[float]]:
    try:
        parts = Path(path).read_text().strip().split()
        return int(parts[0]), (float(parts[1]) if len(parts) > 1 else None)
    except (OSError, ValueError, IndexError):
        return None, None


def _drop_pidfile_lock() -> None:
    """Forget the pidfile lock in a forked child (the parent keeps it)."""
    global _pidfile_fd, _pidfile_path
    if _pidfile_fd is not None:
        try:
            os.close(_pidfile_fd)
        except OSError:
            pass
    _pidfile_fd = None
    _pidfile_path = None


def acquire_pidfile(path: str) -> None:
    """Take the pidfile for this process: exclusive flock, then our pid.

    Raises AlreadyRunning if another live supervisor holds the lock.  The
    fd stays open (and locked) until release_pidfile() or process exit, so
    two concurrent starts can never both succeed.  A pidfile nobody holds
    the lock on is stale and is taken over.
    """
    import fcntl
    import psutil
    global _pidfile_fd, _pidfile_path
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    while True:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, PID_FILE_MODE)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise AlreadyRunning(_read_pidfile(path)[0])
        # The holder may have unlinked the file between our open and flock;
        # then we locked an orphan inode: retry on the current file.
        try:
            same = os.path.samestat(os.fstat(fd), os.stat(path))
        except FileNotFoundError:
            same = False
        if same:
            break
        os.close(fd)
    old_pid, _ = _read_pidfile(path)
    if old_pid is not None and old_pid != os.getpid():
        log.warning(f"Stale pidfile (pid {old_pid} not running) — taking it over")
    create_time = psutil.Process(os.getpid()).create_time()
    os.ftruncate(fd, 0)
    os.pwrite(fd, f"{os.getpid()} {create_time}\n".encode(), 0)
    os.set_inheritable(fd, False)
    _pidfile_fd, _pidfile_path = fd, path
    log.info(f"PID file written: {path} (pid {os.getpid()})")


def release_pidfile() -> None:
    """Remove the pidfile, only if this process owns it (SYS-1)."""
    global _pidfile_fd, _pidfile_path
    if _pidfile_fd is None:
        return
    try:
        if os.path.samestat(os.fstat(_pidfile_fd), os.stat(_pidfile_path)):
            os.remove(_pidfile_path)
    except OSError:
        pass
    _drop_pidfile_lock()


def remove_pidfile(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass

def check_already_running(pidfile: str) -> None:
    """Exit with status 1 if a live WBS already owns the pidfile (SYS-1).

    The pidfile lock decides: a held lock means a running supervisor.  A
    pidfile without a lock holder is stale (process dead, PID reused by
    another program) and is left for acquire_pidfile() to take over.  A
    live wbs process at the recorded pid (a supervisor from before the
    lock existed) still counts as running.  Safe to call from cron.
    """
    import fcntl
    import psutil
    pid, saved_create_time = _read_pidfile(pidfile)
    try:
        fd = os.open(pidfile, os.O_RDONLY)
    except FileNotFoundError:
        return  # No pidfile — proceed normally
    except OSError:
        fd = None
    if fd is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            _refuse(pid)
        finally:
            os.close(fd)
    if pid is None:
        return  # unreadable — acquire_pidfile() takes it over

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        log.warning(f"Stale pidfile (pid {pid} not found) — removing and continuing")
        remove_pidfile(pidfile)
        return

    # PID exists — check create_time to rule out reuse
    if saved_create_time is not None:
        if abs(proc.create_time() - saved_create_time) > 1.0:
            log.warning(f"PID {pid} reused by another process — ignoring stale pidfile")
            remove_pidfile(pidfile)
            return

    # Verify it's actually a wbs process
    try:
        cmdline = " ".join(proc.cmdline())
        if "wbs" not in cmdline or proc.status() == psutil.STATUS_ZOMBIE:
            log.warning(f"PID {pid} belongs to an unrelated process — ignoring stale pidfile")
            remove_pidfile(pidfile)
            return
    except psutil.AccessDenied:
        pass  # Can't read cmdline but PID + create_time match — trust it
    except psutil.NoSuchProcess:
        remove_pidfile(pidfile)
        return

    _refuse(pid)


def _refuse(pid: Optional[int]) -> None:
    msg = f"{AlreadyRunning(pid)}. Exiting."
    # Into the log file too, unless logging already goes to the terminal.
    if not any(type(h) is logging.StreamHandler for h in logging.getLogger().handlers):
        log.error(msg)
    print(msg, file=sys.stderr)
    sys.exit(1)


# How long the supervisor waits to reap a child whose sentinel already fired.
REAP_TIMEOUT = 5.0


def reap_exitcode(proc, timeout: float = REAP_TIMEOUT) -> Optional[int]:
    """Exit code of a child whose sentinel is ready, or None if not yet known.

    The multiprocessing sentinel becomes readable when the child's fds close,
    which the kernel does before the child is reapable: ``proc.exitcode``
    read right then can still be None. ``join`` blocks in waitpid until the
    exit status is really there, so the caller never mistakes a clean exit
    (``.die``) or a rehash for a crash. None means "still unknown, retry".
    """
    code = proc.exitcode
    if code is None:
        proc.join(timeout=timeout)
        code = proc.exitcode
    return code


def main(argv=None):
    args = parse_args(argv)
    _shutting_down = False
    _pending_full_restart = False

    if args.mkpasswd:
        import bcrypt, getpass
        pw = getpass.getpass("Password: ")
        print(bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode())
        return

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"ERROR: config file not found: {args.config}", file=sys.stderr)
        print("       Create it with: install -m 600 config.json.example config.json, then edit it.", file=sys.stderr)
        sys.exit(1)

    try:
        config = load_config(config_path)
    except ConfigAccessError as e:
        sys.exit(f"[fatal] {e}")
    except json.JSONDecodeError as e:
        sys.exit(f"[fatal] Config parse error in {args.config}: {e}")
    except OSError as e:
        sys.exit(f"[fatal] Cannot read config {args.config}: {e}")

    # One shape check for the whole file, before logging, seeding or any
    # child process (USR-14): every problem at once, rc=1, no traceback.
    from .configcheck import validate_config, format_problems, resolve_log_level
    _errors, _warnings = validate_config(config, require_bot=not args.update)
    for line in format_problems(args.config, [], _warnings):
        print(line, file=sys.stderr)
    if _errors:
        sys.exit("\n".join(format_problems(args.config, _errors)))

    _log_cfg = config.get('logging') or {}
    _level   = resolve_log_level(_log_cfg.get('level', 'INFO'))[0]
    _logfile = args.logfile or _log_cfg.get('file', 'logs/wbs.log')
    _irc_respawn_delay = 5.0
    _irc_last_respawn  = 0.0

    if args.foreground:
        logging.basicConfig(
            level=_level,
            format=LOG_FORMAT,
            stream=sys.stdout
        )
        # Console plus the same rotated log file as daemon mode (live O-3).
        use_file_logging(_logfile, config, keep_console=True)
    else:
        # One handler: the rotated log file (SYS-6).  stdout/stderr go to the
        # same file after daemonizing, but only for stray prints/tracebacks.
        logging.getLogger().setLevel(_level)
        use_file_logging(_logfile, config)

    _warn_plaintext_seed_passwords(config)

    if args.db_path:
        config.setdefault('db', {})['path'] = args.db_path

    db_path  = config.get('db', {}).get('path', 'db/wbs.db')
    settings = config.get('settings', {})
    pidfile  = args.pidfile or settings.get('pid_file', 'wbs.pid')
    logfile  = args.logfile or _log_cfg.get('file', 'logs/wbs.log')

    if args.update:
        from .update import run_standalone_update
        sys.exit(asyncio.run(run_standalone_update(config)))

    if args.seed:
        from .db import init_db, seed_db
        async def _seed():
            await init_db(db_path)
            await seed_db(db_path, config)
        asyncio.run(_seed())
        # --seed initializes the database, then exits (USR-15, README).
        log.info(f"Database seeded: {db_path}")
        print(f"Database seeded: {db_path}. Start the bot without --seed.")
        return

    if not Path(db_path).exists():
        print(f"ERROR: database not found at {db_path}", file=sys.stderr)
        print("       Run './wbs --seed' first to initialize.", file=sys.stderr)
        sys.exit(1)

    # Heavy runtime imports only once the bot is really starting (still before
    # daemonizing, so an import failure reaches the terminal).
    from .irc import irc_process_launcher
    from .core import core_process_launcher

    check_already_running(pidfile)
    log.info(f"Launching WBS {__version__}")
    holder_pid = None
    status_fd = None
    if args.foreground:
        # The shell waits on this process; the supervisor runs in a child so
        # that .detach can hand the terminal back without stopping the bot.
        child = os.fork()
        if child:
            sys.exit(_foreground_holder(child))
        holder_pid = os.getppid()
    else:
        # SYS-1: daemonize first, so the pidfile names the surviving
        # supervisor; the launcher waits for the daemon's verdict.
        status_fd = daemonize(logfile)
    try:
        acquire_pidfile(pidfile)
    except AlreadyRunning as e:
        # Lost a race against a concurrent start.
        if args.foreground:
            print(f"{e}. Exiting.", file=sys.stderr)
        else:
            log.error(f"{e}. Exiting.")
            report_started(status_fd, f"{e}. Exiting.")
        os._exit(1)
    except OSError as e:
        if args.foreground:
            print(f"ERROR: cannot write PID file {pidfile}: {e}", file=sys.stderr)
        else:
            log.error(f"Cannot write PID file {pidfile}: {e}")
            report_started(status_fd, f"ERROR: cannot write PID file {pidfile}: {e}")
        os._exit(1)
    report_started(status_fd, "OK")
    supervisor_pid = os.getpid()

    EXIT_OK = 42
    EXIT_REHASH = 43

    def _spawn_core(config, config_path, args, core_q, irc_q, sup_q, fresh=False) -> Process:
        launch_args = (config, config_path, args, core_q, irc_q, sup_q)
        if fresh:
            target = _run_fresh
            launch_args = (f"{__package__ or 'src'}.core", "core_process_launcher") + launch_args
        else:
            target = _run_child
            launch_args = (core_process_launcher,) + launch_args
        p = Process(
            target=target,
            args=launch_args,
            daemon=True,
            name="Core"
        )
        p.start()
        return p

    def _spawn_irc(config, core_q, irc_q) -> Process:
        p = Process(
            target=_run_child,
            args=(irc_process_launcher, config, core_q, irc_q),
            daemon=True,
            name="IRC"
        )
        p.start()
        return p

    core_q = Queue()
    irc_q  = Queue()
    sup_q = Queue()
    if args.foreground:
        try:
            config['_tty_fd'] = os.dup(sys.stdin.fileno())
        except Exception:
            config['_tty_fd'] = None

    core_proc = _spawn_core(config, str(config_path), args, core_q, irc_q, sup_q)
    irc_proc  = _spawn_irc(config, core_q, irc_q)

    procs = {"core": core_proc, "irc": irc_proc}
    _shutdown_running = False

    def _shutdown(signum=None, frame=None):
        nonlocal _shutting_down, _shutdown_running
        if os.getpid() != supervisor_pid:
            # A forked child must never run the supervisor's shutdown (it
            # cannot test or kill its siblings: USR-18).
            os._exit(0)
        if _shutdown_running:
            return          # a second ^C / SIGTERM while already stopping
        _shutdown_running = True
        _shutting_down = True
        log.info("Supervisor shutting down — stopping children")
        # SYS-2: Core first, with SIGTERM: its handler sends the IRC QUIT
        # (through the still-running IRC process), stops its tasks, saves
        # state and exits.  IRC is stopped after that, so the QUIT is out.
        # SIGKILL only when a child outlives its grace period.
        for name, proc in procs.items():
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=SHUTDOWN_GRACE.get(name, 5.0))
                if proc.is_alive():
                    log.warning(f"{name} did not terminate, sending SIGKILL")
                    proc.kill()
                    proc.join(timeout=2.0)
        release_pidfile()
        log.info("Supervisor stopped")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    sentinels = {
        core_proc.sentinel: ("core", core_proc),
        irc_proc.sentinel:  ("irc",  irc_proc),
    }

    def _detach():
        """Core's console ran .detach (USR-9): leave the terminal, keep running."""
        nonlocal holder_pid
        if holder_pid is None:
            log.info("Supervisor: detach requested but already in background")
            return
        log.info("Supervisor: detaching from the terminal, bot keeps running")
        detach_stdio(logfile, config)
        tty_fd = config.pop('_tty_fd', None)
        if tty_fd is not None:
            try:
                os.close(tty_fd)
            except OSError:
                pass
        # Every Core started from now on runs without a console.
        args.foreground = False
        try:
            os.kill(holder_pid, signal.SIGUSR1)
        except OSError:
            pass
        holder_pid = None

    try:
        while True:
            # Short timeout: sup_q requests (detach) need no child exit.
            ready = mp_wait(list(sentinels.keys()), timeout=1.0)

            while not sup_q.empty():
                try:
                    msg = sup_q.get_nowait()
                    cmd = msg.get('cmd')
                    if cmd == 'quit':
                        log.info(f"Core requested quit: {msg.get('message', '')}")
                        _shutdown()
                    elif cmd == 'detach':
                        _detach()
                    elif cmd == 'restart':
                        log.info("Supervisor: full restart requested by Core")
                        irc = procs.get("irc")
                        if irc and irc.is_alive():
                            irc.terminate()
                            irc.join(timeout=5.0)
                            if irc.is_alive():
                                log.warning("IRC did not terminate cleanly — sending SIGKILL")
                                irc.kill()
                                irc.join(timeout=2.0)
                        old_irc_sentinel = irc.sentinel if irc else None
                        if old_irc_sentinel and old_irc_sentinel in sentinels:
                            del sentinels[old_irc_sentinel]
                        _pending_full_restart = True
                    # future: 'rehash', 'alert', etc.
                except Exception:
                    pass            

            for s in ready:
                name, proc = sentinels.pop(s)
                code = reap_exitcode(proc)
                if code is None:
                    # Not reaped yet: never treat an unknown status as a
                    # crash (that would undo a .die); look again next round.
                    log.warning(f"{name} sentinel fired but exit status not yet "
                                "available — retrying")
                    sentinels[s] = (name, proc)
                    continue
                log.info(f"{name} exited with code {code}")

                if name == "core":
                    if _shutting_down:
                        log.info("Core exited during shutdown — not relaunching")
                        _shutdown()
                    elif code == EXIT_OK:
                        log.info("Core clean exit (code 42) — shutting down supervisor")
                        _shutdown()
                    elif code == EXIT_REHASH:
                        # .rehash (USR-16): new Core from re-read config and
                        # freshly imported code; IRC keeps its connection.
                        log.info("Rehash: starting a fresh Core, IRC preserved")
                        try:
                            new_config = load_config(config_path)
                            _errs, _ = validate_config(new_config)
                            if _errs:
                                raise ValueError("; ".join(f"{p}: {m}" for p, m in _errs))
                            if args.db_path:
                                new_config.setdefault('db', {})['path'] = args.db_path
                            if '_tty_fd' in config:
                                new_config['_tty_fd'] = config['_tty_fd']
                            config = new_config
                        except (OSError, ValueError) as e:
                            log.error(f"Rehash: cannot reload {config_path} ({e}); "
                                      "keeping the previous config")
                        core_proc = _spawn_core(config, str(config_path), args, core_q, irc_q,
                                                sup_q, fresh=True)
                        procs["core"] = core_proc
                        sentinels[core_proc.sentinel] = ("core", core_proc)
                    elif _pending_full_restart:
                        _pending_full_restart = False
                        log.info("Full restart: spawning fresh IRC process...")
                        irc_proc = _spawn_irc(config, core_q, irc_q)
                        procs["irc"] = irc_proc
                        sentinels[irc_proc.sentinel] = ("irc", irc_proc)
                        log.info("Full restart: spawning fresh Core process...")
                        core_proc = _spawn_core(config, str(config_path), args, core_q, irc_q, sup_q)
                        procs["core"] = core_proc
                        sentinels[core_proc.sentinel] = ("core", core_proc)
                        log.info("Full restart complete — both Core and IRC respawned")
                    else:
                        log.info(f"Relaunching Core (exit code={code})...")
                        core_proc = _spawn_core(config, str(config_path), args, core_q, irc_q, sup_q)
                        procs["core"] = core_proc
                        sentinels[core_proc.sentinel] = ("core", core_proc)

                elif name == "irc":
                    if _shutting_down:
                        log.info("IRC exited during shutdown — not relaunching")
                    else:
                        now = time.time()
                        if (now - _irc_last_respawn) < _irc_respawn_delay:
                            log.warning(f"IRC died too quickly — waiting {_irc_respawn_delay:.0f}s before respawn")
                            time.sleep(_irc_respawn_delay)
                        log.warning(f"IRC process died (code={code}), relaunching...")
                        _irc_last_respawn = time.time()
                        _irc_respawn_delay = min(_irc_respawn_delay * 2, 300.0)
                        irc_proc = _spawn_irc(config, core_q, irc_q)
                        procs["irc"] = irc_proc
                        sentinels[irc_proc.sentinel] = ("irc", irc_proc)

    finally:
        release_pidfile()

if __name__ == '__main__':
    main()

