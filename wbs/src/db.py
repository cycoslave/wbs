# src/db.py
"""
Unified async SQLite for WBS: bots/users/channels/seen.
Supports multi-process (WAL mode).
"""
import aiosqlite
import asyncio
import logging
import json
import re
import sqlite3
import time
from pathlib import Path
from contextlib import asynccontextmanager

from . import crypto_exec
from .idrules import valid_handle, valid_hostmask, wildcard_only_host
from .logsafe import guard_library_logs

SCHEMA_PATH = Path(__file__).parent.parent / "db" / "schema.sql"
log = logging.getLogger("wbs.db")
# aiosqlite logs every statement WITH its parameters at DEBUG; those include
# bot link keys and password hashes, so its records below WARNING are dropped
# whatever level is configured (NET-8, SAST-002).
guard_library_logs()
ALLOWED_TABLES = {'subnets', 'users', 'user_access', 'bots', 'bot_access', 'bot_subnets', 'servers', 'channels', 'channel_subnets', 'ignores', 
                  'loaded_modules', 'game_sessions', 'seen', 'seen_notify', 'chanlock', 'limit_settings', 'topiclock', 'stats_nick', 'stats_nick_channel',
                  'stats_victims', 'blackjack_settings', 'blackjack_cash', 'duckhunt_settings', 'duckhunt_scores', 'poker_settings', 'poker_cash', 
                  'werewolf_stats', 'lotto_settings', 'lotto_jackpot', 'lotto_tickets', 'lotto_cash', 'lotto_winners', 'fishing_settings', 'fishing_scores'}

DB_FILE_MODE = 0o600     # the database holds password hashes and link keys (SYS-6)


def private_file(path, mode: int = DB_FILE_MODE) -> None:
    """Create ``path`` if missing with ``mode`` and drop any wider bits.

    SQLite creates its -wal/-shm files with the database file's mode, so a
    0600 database keeps those private too.
    """
    import os
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, mode)
    try:
        cur = os.fstat(fd).st_mode & 0o777
        if cur & ~mode:
            os.fchmod(fd, cur & mode)
    finally:
        os.close(fd)


def get_schema_sql() -> str:
    """Load schema.sql (synchronous — call via asyncio.to_thread if needed)."""
    return SCHEMA_PATH.read_text(encoding="utf-8")

async def ensure_schema(db: aiosqlite.Connection) -> None:
    """Idempotent schema apply (CREATE ... IF NOT EXISTS; never alters columns)."""
    schema = await asyncio.to_thread(get_schema_sql)
    await db.executescript(schema)
    await db.commit()


# ---------------------------------------------------------------------------
# Schema migrations (USR-19)
#
# schema.sql only ever creates what is missing; it cannot change a table that
# already exists.  PRAGMA user_version records which migration step a database
# file has been through.  SCHEMA_VERSION is the version of the schema.sql in
# this tree; MIGRATIONS is the ordered list of (target_version, description,
# async fn(db)) steps that bring an older file up to it.  Steps must be
# idempotent (they inspect the live schema) and run inside one transaction
# together with the version bump.  A fresh database is stamped with
# SCHEMA_VERSION without running anything.  To change the schema: edit
# schema.sql, append a step here, raise SCHEMA_VERSION.
# ---------------------------------------------------------------------------
_CONST_DEFAULT = re.compile(r"""^(NULL|[-+]?\d+(\.\d+)?|'([^']|'')*'|TRUE|FALSE)$""", re.I)


async def _table_columns(db: aiosqlite.Connection, table: str) -> list[tuple]:
    """PRAGMA table_info rows: (cid, name, type, notnull, dflt_value, pk)."""
    async with db.execute(f'PRAGMA table_info("{table}")') as cur:
        return [tuple(r) for r in await cur.fetchall()]


async def _reference_columns() -> dict[str, list[tuple]]:
    """Columns every table has according to schema.sql (built in memory)."""
    schema = await asyncio.to_thread(get_schema_sql)
    async with aiosqlite.connect(":memory:") as ref:
        await ref.executescript(schema)
        async with ref.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        ) as cur:
            names = [r[0] for r in await cur.fetchall()]
        return {n: await _table_columns(ref, n) for n in names}


async def _mig_add_missing_columns(db: aiosqlite.Connection) -> None:
    """Add every column schema.sql defines that an existing table lacks.

    Data is preserved (ALTER TABLE ... ADD COLUMN).  SQLite cannot add a
    column with a non-constant default or a NOT NULL without a constant
    default, nor PRIMARY KEY/UNIQUE ones: those are added nullable and
    back-filled with the schema's default expression; a missing PK column is
    reported, not guessed.
    """
    for table, ref_cols in (await _reference_columns()).items():
        live = {c[1] for c in await _table_columns(db, table)}
        if not live:
            continue            # table absent: schema.sql creates it in full
        for _cid, name, ctype, notnull, dflt, pk in ref_cols:
            if name in live:
                continue
            if pk:
                log.error("migration: %s.%s is part of the primary key and cannot "
                          "be added to an existing table; rebuild it by hand",
                          table, name)
                continue
            constant = dflt is not None and _CONST_DEFAULT.match(dflt.strip())
            ddl = f'ALTER TABLE "{table}" ADD COLUMN "{name}" {ctype or ""}'
            if constant:
                ddl += f" DEFAULT {dflt}"
                if notnull and dflt.strip().upper() != "NULL":
                    ddl += " NOT NULL"
            await db.execute(ddl)
            if dflt is not None and not constant:
                await db.execute(f'UPDATE "{table}" SET "{name}" = {dflt}')
            log.warning("migration: added missing column %s.%s", table, name)


SCHEMA_VERSION = 2
MIGRATIONS = [
    (2, "add columns missing from existing tables", _mig_add_missing_columns),
]


def _backup_db(db_path: str, tag: str) -> str:
    """Consistent copy of the database file (sqlite online backup; WAL-safe)."""
    dest = f"{db_path}.{tag}.{time.strftime('%Y%m%d-%H%M%S')}.bak"
    private_file(dest)
    src = sqlite3.connect(db_path)
    try:
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    return dest


async def _user_tables(db: aiosqlite.Connection) -> list[str]:
    async with db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ) as cur:
        return [r[0] for r in await cur.fetchall()]


async def _get_version(db: aiosqlite.Connection) -> int:
    async with db.execute("PRAGMA user_version") as cur:
        return int((await cur.fetchone())[0])


async def migrate(db: aiosqlite.Connection, version: int) -> bool:
    """Apply pending MIGRATIONS to an existing database at ``version``.

    The caller backs the file up first.  Returns True if any step ran.
    Newer-than-known databases are left untouched.
    """
    if version > SCHEMA_VERSION:
        log.warning("database schema version %d is newer than this build "
                    "understands (%d); not migrating", version, SCHEMA_VERSION)
        return False
    pending = [m for m in MIGRATIONS if m[0] > version]
    if not pending:
        return False
    await db.execute("BEGIN IMMEDIATE")
    try:
        for target, desc, fn in pending:
            log.info("migration -> v%d: %s", target, desc)
            await fn(db)
        await db.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
        await db.commit()
    except BaseException:
        await db.rollback()
        log.error("migration failed; database left at v%d", version)
        raise
    return True

async def _hash_password(password_cfg) -> str | None:
    """
    Accept a password config block and return a bcrypt hash, or None.
      {"pass": "plaintext",  "encryption": "none"}   → bcrypt hash (explicit opt-in)
      {"pass": "$2b$...",    "encryption": "bcrypt"}  → validate + use as-is
      {"pass": "$2b$..."}  (no "encryption" key)      → same as bcrypt
      None / missing / {"pass": null}                 → return None (NULL in DB)
    """
    if not password_cfg:
        return None
    raw = password_cfg.get("pass") if isinstance(password_cfg, dict) else None
    if not raw:
        return None
    # Cleartext seed passwords are an explicit opt-in: only "encryption": "none"
    # (or another non-bcrypt value) hashes a plaintext; a missing key means bcrypt.
    enc = str(password_cfg.get("encryption", "bcrypt")).lower() if isinstance(password_cfg, dict) else "bcrypt"
    if enc == "bcrypt":
        if not raw.startswith(("$2b$", "$2a$", "$2y$")):
            raise ValueError("encryption=bcrypt (the default when 'encryption' is "
                             "omitted) but value is not a valid bcrypt hash; use "
                             "--mkpasswd, or set \"encryption\": \"none\" explicitly")
        return raw
    return await crypto_exec.hash_password(raw)

async def init_db(db_path: str, force: bool = False) -> None:
    """Unified init: schema file, WAL multi-process."""
    db_path_obj = Path(db_path)
    db_path_obj.parent.mkdir(parents=True, exist_ok=True)
    private_file(db_path_obj)          # 0600 before sqlite writes anything (SYS-6)

    async with aiosqlite.connect(db_path_obj) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.execute("PRAGMA foreign_keys = ON")
        await db.commit()

        if force:
            async with db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ) as cur:
                tables = await cur.fetchall()

            await db.execute("BEGIN")
            try:
                for (table,) in tables:
                    if table in ALLOWED_TABLES:
                        # Whitelist-validated — safe to concatenate
                        await db.execute("DROP TABLE IF EXISTS " + table)
                await db.commit()
            except Exception:
                await db.rollback()
                raise

        existing = bool(await _user_tables(db))
        version = await _get_version(db)
        if existing:
            # Back up (when a step is pending) before anything is altered.
            # schema.sql runs first so new tables exist, then column drift
            # is repaired; a current-version file is not touched at all.
            if version < SCHEMA_VERSION:
                backup = await asyncio.to_thread(_backup_db, db_path, f"v{version}")
                log.warning("database schema v%d -> v%d: backup written to %s",
                            version, SCHEMA_VERSION, backup)
            await ensure_schema(db)
            await migrate(db, version)
        else:
            await ensure_schema(db)
            await db.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
            await db.commit()
        log.info("DB init at %s %s", db_path, "(force)" if force else "(idempotent)")

async def seed_db(db_path: str, config: dict) -> None:
    """Seed from config.json: subnet, bot record, channels, users.
    Only called via './wbs --seed'. Never called on normal startup.
    """
    bot_config = config.get('bot', {})
    nick = bot_config['nick']

    subnet_cfg = config.get('subnet', {})
    subnet_id   = int(subnet_cfg.get('id', 1))
    subnet_name = subnet_cfg.get('name', 'default')

    async with aiosqlite.connect(db_path) as db:
        # Subnet
        await db.execute("""
            INSERT INTO subnets (id, name, created_by)
            VALUES (?, ?, 'config')
            ON CONFLICT(id) DO UPDATE SET name = excluded.name
        """, (subnet_id, subnet_name))

        # Self-bot record
        await db.execute("""
            INSERT INTO bots (handle, address, port, subnet_id, created_by)
            VALUES (?, '127.0.0.1', 3333, ?, 1)
            ON CONFLICT(handle) DO UPDATE SET
                subnet_id = excluded.subnet_id
        """, (nick, subnet_id))

        # Channels
        for ch in bot_config.get('channels', []):
            await db.execute("""
                INSERT INTO channels (name, created_by)
                VALUES (?, 'seed')
                ON CONFLICT(name) DO NOTHING
            """, (ch,))

            await db.execute("""
                INSERT INTO channel_subnets (channel_name, subnet_id, created_by)
                VALUES (?, ?, 'seed')
                ON CONFLICT(channel_name, subnet_id) DO NOTHING
            """, (ch, subnet_id))

        # Users — process the top-level users[] array
        for user_cfg in config.get('users', []):
            handle = user_cfg.get('handle')
            if not handle:
                log.warning("seed_db: skipping user entry with no handle")
                continue
            if not valid_handle(handle):
                log.error("seed_db: skipping user %r: invalid handle (1-20 chars of "
                          "A-Za-z0-9_-[]\\`^{}, ASCII)", handle)
                continue
            async with db.execute(
                "SELECT handle FROM users WHERE LOWER(handle) = LOWER(?) AND handle != ?",
                (handle, handle),
            ) as cur:
                clash = await cur.fetchone()
            if clash is not None:
                log.error("seed_db: skipping user %r: handle exists as %r "
                          "(handles are case-insensitive)", handle, clash[0])
                continue
            hosts = user_cfg.get('hosts', [])
            bad_hosts = [h for h in hosts if not valid_hostmask(h)]
            if bad_hosts:
                log.error("seed_db: user %r: ignoring invalid hostmask(s) %r "
                          "(need nick!user@host)", handle, bad_hosts)
                hosts = [h for h in hosts if valid_hostmask(h)]
            # mythos F-01b: a +n/+A user never takes a wildcard-only mask, on
            # this write path too.  Privilege = the seed config's access rows
            # or an access row the user already has in the database.
            wild_hosts = [h for h in hosts if wildcard_only_host(h)]
            if wild_hosts:
                privileged = any(a.get('is_owner') or a.get('is_admin')
                                 for a in user_cfg.get('access', []))
                if not privileged:
                    async with db.execute(
                        "SELECT 1 FROM user_access WHERE handle = ? AND deleted_at IS NULL "
                        "AND (COALESCE(is_admin, 0) = 1 OR COALESCE(is_owner, 0) = 1) LIMIT 1",
                        (handle,),
                    ) as cur:
                        privileged = await cur.fetchone() is not None
                if privileged:
                    log.error("seed_db: user %r: refusing wildcard-only hostmask(s) %r "
                              "for a +n/+A user (host part must name a host)",
                              handle, wild_hosts)
                    hosts = [h for h in hosts if not wildcard_only_host(h)]

            try:
                pw_hash = await _hash_password(user_cfg.get('password'))
            except ValueError as exc:
                log.error("seed_db: bad password config for '%s': %s", handle, exc)
                continue

            await db.execute("""
                INSERT INTO users (handle, password, created_by)
                VALUES (?, ?, 'seed')
                ON CONFLICT(handle) DO NOTHING
            """, (handle, pw_hash))

            # Derive access flags directly from config — single pass
            is_owner       = False
            is_admin       = False
            has_partyline  = False
            is_op          = False
            for acc in user_cfg.get('access', []):
                has_partyline = True
                if acc.get('is_owner'):
                    is_owner = True
                if acc.get('is_admin') or is_owner:
                    is_admin = True
                if acc.get('is_op'):
                    is_op = True

            await db.execute("""
                INSERT INTO user_access (
                    handle, channel, subnet_id,
                    has_partyline, is_admin, is_owner, is_op,
                    created_by
                )
                VALUES (?, NULL, ?, ?, ?, ?, ?, 'seed')
                ON CONFLICT(handle, channel, subnet_id) DO NOTHING
            """, (handle, subnet_id, int(has_partyline), int(is_admin), int(is_owner), int(is_op)))

            # Host masks (validated above)
            if hosts:
                await db.execute("""
                    UPDATE users SET hostmasks = ?
                    WHERE handle = ?
                """, (json.dumps(hosts), handle))

        await db.commit()
        log.info(
            "DB seeded: subnet=%s(id=%d), bot=%s, users=%d",
            subnet_name, subnet_id, nick, len(config.get('users', []))
        )

@asynccontextmanager
async def get_db(db_path: str):
    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
        await db.commit()
    except BaseException:
        try:
            await db.rollback()
        except Exception as rb_err:
            log.warning("get_db: rollback failed: %s", rb_err)
        raise
    finally:
        await db.close()