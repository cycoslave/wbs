# src/db.py
"""
Unified async SQLite for WBS: bots/users/channels/seen.
Supports multi-process (WAL mode).
"""
import aiosqlite
import time
import logging
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager


SCHEMA_PATH = Path(__file__).parent.parent / "db" / "schema.sql"
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)


async def get_schema_sql() -> str:
    """Load schema.sql."""
    return SCHEMA_PATH.read_text(encoding="utf-8")


async def ensure_schema(db: aiosqlite.Connection) -> None:
    """Idempotent schema apply."""
    schema = await get_schema_sql()
    await db.executescript(schema)
    await db.commit()


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
                if table not in {'sqlite_master', 'sqlite_sequence'}:
                    await db.execute(f"DROP TABLE IF EXISTS {table}")
            await db.commit()
        
        await ensure_schema(db)
        log.info(f"DB init at {db_path} {'(force)' if force else '(idempotent)'}")


async def seed_db(db_path: str, config: dict):
    """Seed from config.json: bot record, channels, users."""
    bot_config = config.get('bot', {})
    nick = bot_config['nick']
    
    async with aiosqlite.connect(db_path) as db:
        # Self-bot record (handle-based)
        await db.execute("""
            INSERT OR IGNORE INTO bots (handle, address, port, subnet_id, is_online)
            VALUES (?, '127.0.0.1', 3333, 1, 1)
        """, (nick,))
        
        # Channels
        for ch in bot_config.get('channels', []):
            await db.execute("""
                INSERT OR IGNORE INTO channels (name, subnet_id, settings)
                VALUES (?, 1, '{}')
            """, (ch,))
        
        # Owner user
        owner = bot_config.get('owners', ['owner'])[0]
        await db.execute("""
            INSERT OR IGNORE INTO users (handle, flags, password)
            VALUES (?, '+fhoimn', '')
        """, (owner,))
        
        await db.commit()
        log.info(f"DB seeded: bot={nick}, owner={owner}")


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
