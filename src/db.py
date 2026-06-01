# src/db.py
"""
Unified async SQLite for WBS: bots/users/channels/seen.
Supports multi-process (WAL mode).
"""
import aiosqlite
import asyncio
import time
import logging
import bcrypt
import json
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

SCHEMA_PATH = Path(__file__).parent.parent / "db" / "schema.sql"
#logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("wbs.db")
ALLOWED_TABLES = {'subnets', 'users', 'user_access', 'bots', 'bot_access', 'bot_subnets', 'servers', 'channels', 'channel_subnets', 'runtime', 'ignores', 
                  'loaded_modules', 'game_sessions', 'blackjack_settings', 'blackjack_cash', 'duckhunt_settings', 'duckhunt_scores', 'poker_settings' , 
                  'poker_cash', 'werewolf_stats', 'chanlock', 'limit_settings', 'seen', 'stats_global', 'stats_channel', 'stats_history', 'topiclock'}

def get_schema_sql() -> str:
    """Load schema.sql (synchronous — call via asyncio.to_thread if needed)."""
    return SCHEMA_PATH.read_text(encoding="utf-8")

async def ensure_schema(db: aiosqlite.Connection) -> None:
    """Idempotent schema apply."""
    schema = await asyncio.to_thread(get_schema_sql)
    await db.executescript(schema)
    await db.commit()

def _hash_password(password_cfg) -> str | None:
    """
    Accept a password config block and return a bcrypt hash, or None.
      {"pass": "plaintext",  "encryption": "none"}   → bcrypt hash
      {"pass": "$2b$...",    "encryption": "bcrypt"}  → validate + use as-is
      None / missing / {"pass": null}                 → return None (NULL in DB)
    """
    if not password_cfg:
        return None
    raw = password_cfg.get("pass") if isinstance(password_cfg, dict) else None
    if not raw:
        return None
    enc = password_cfg.get("encryption", "none").lower() if isinstance(password_cfg, dict) else "none"
    if enc == "bcrypt":
        if not raw.startswith(("$2b$", "$2a$", "$2y$")):
            raise ValueError(f"encryption=bcrypt but value is not a valid bcrypt hash")
        return raw
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()

async def init_db(db_path: str, force: bool = False) -> None:
    """Unified init: schema file, WAL multi-process."""
    db_path_obj = Path(db_path)
    db_path_obj.parent.mkdir(parents=True, exist_ok=True)

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

        await ensure_schema(db)
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

            try:
                pw_hash = _hash_password(user_cfg.get('password'))
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

            # Host masks
            hosts = user_cfg.get('hosts', [])
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

async def init_runtime_state(db_path: str):
    """
    Initialize runtime state table on bot startup.
    Sets bot_start_time and other ephemeral counters.
    """
    async with aiosqlite.connect(db_path) as db:
        # Create runtime table if missing
        await db.execute("""
            CREATE TABLE IF NOT EXISTS runtime (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
        """)
        
        # Set bot start time
        start_time = int(time.time())
        await db.execute(
            "INSERT OR REPLACE INTO runtime (key, value) VALUES (?, ?)",
            ('bot_start_time', str(start_time))
        )
        
        await db.commit()
        log.info("Runtime state initialized: start_time=%d", start_time)

async def get_runtime(key: str, db_path: str) -> Optional[int]:
    """Get integer runtime value from DB. Returns None if key missing or value is non-integer."""
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT value FROM runtime WHERE key = ?", (key,)) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            try:
                return int(row[0])
            except (ValueError, TypeError):
                log.warning("get_runtime: non-integer value for key %r: %r", key, row[0])
                return None