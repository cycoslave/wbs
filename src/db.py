# src/db.py
"""
Unified async SQLite for WBS: bots/users/channels/seen.
Supports multi-process (WAL mode).
"""
import aiosqlite
import time
import logging
import bcrypt
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

SCHEMA_PATH = Path(__file__).parent.parent / "db" / "schema.sql"
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("wbs.db")
ALLOWED_TABLES = {'subnets', 'users', 'user_access', 'bots', 'bot_access', 'bot_subnets', 'servers', 'channels', 'channel_subnets', 'runtime', 'ignores', 
                  'loaded_modules', 'game_sessions', 'blackjack_settings', 'blackjack_cash', 'duckhunt_settings', 'duckhunt_scores', 'poker_settings' , 
                  'poker_cash', 'werewolf_stats', 'chanlock', 'limit_settings', 'seen', 'stats_global', 'stats_channel', 'stats_history', 'topiclock'}

async def get_schema_sql() -> str:
    """Load schema.sql."""
    return SCHEMA_PATH.read_text(encoding="utf-8")

async def ensure_schema(db: aiosqlite.Connection) -> None:
    """Idempotent schema apply."""
    schema = await get_schema_sql()
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

async def init_db(db_path: str, schema_path: str = str(SCHEMA_PATH), force: bool = False) -> None:
    """Unified init: config path, schema file, WAL multi-process."""
    db_path_obj = Path(db_path)
    db_path_obj.parent.mkdir(parents=True, exist_ok=True)
    
    async with aiosqlite.connect(db_path_obj) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")  # Multi-process safe
        await db.execute("PRAGMA synchronous=NORMAL")  # Perf
        await db.commit()
        
        if force:
            # Drop user tables
            async with db.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
                tables = await cur.fetchall()
            for (table,) in tables:
                if table in ALLOWED_TABLES:
                    await db.execute(f"DROP TABLE IF EXISTS {table}")
            await db.commit()
        
        await ensure_schema(db)
        log.info(f"DB init at {db_path} {'(force)' if force else '(idempotent)'}")

async def seed_db(db_path: str, config: dict):
    """Seed from config.json: subnet, bot record, channels, users.
    Only called via './wbs --seed'. Never called on normal startup.
    """
    bot_config = config.get('bot', {})
    nick = bot_config['nick']

    subnet_cfg = config.get('subnet', {})
    subnet_id  = int(subnet_cfg.get('id', 1))
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
            INSERT INTO bots (handle, address, port, subnet_id, is_online)
            VALUES (?, '127.0.0.1', 3333, ?, 1)
            ON CONFLICT(handle) DO UPDATE SET
                subnet_id = excluded.subnet_id,
                is_online = 1
        """, (nick, subnet_id))

        # Channels
        for ch in bot_config.get('channels', []):
            await db.execute("""
                INSERT INTO channels (name, subnet_id, settings)
                VALUES (?, ?, '{}')
                ON CONFLICT(name) DO NOTHING
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

            # Determine flags from access block
            flags = '+n'
            for acc in user_cfg.get('access', []):
                if acc.get('is_admin'):
                    flags = '+fhoimn'
                    break
                if acc.get('is_op'):
                    flags = '+omn'

            await db.execute("""
                INSERT INTO users (handle, flags, password)
                VALUES (?, ?, ?)
                ON CONFLICT(handle) DO NOTHING
            """, (handle, flags, pw_hash))  # pw_hash is None → NULL if no password

            # Host masks
            for hostmask in user_cfg.get('hosts', []):
                await db.execute("""
                    INSERT INTO user_access (handle, hostmask)
                    VALUES (?, ?)
                    ON CONFLICT DO NOTHING
                """, (handle, hostmask))

        await db.commit()
        log.info(
            "DB seeded: subnet=%s(id=%d), bot=%s, users=%d",
            subnet_name, subnet_id, nick, len(config.get('users', []))
        )

@asynccontextmanager
async def get_db(db_path: str):
    """Async context manager for DB connections."""
    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    try:
        yield db
        await db.commit()
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
        log.info(f"Runtime state initialized: start_time={start_time}")

async def get_runtime(key: str, db_path: str) -> Optional[int]:
    """Get typed runtime value from DB."""
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT value FROM runtime WHERE key = ?", (key,)) as cursor:
            row = await cursor.fetchone()
            return int(row[0]) if row else None