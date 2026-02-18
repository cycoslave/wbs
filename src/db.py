import aiosqlite
import asyncio
from pathlib import Path
from typing import AsyncGenerator
from dataclasses import dataclass
from typing import Optional

DB_PATH = Path("wbs.db")
SCHEMA_PATH = Path(__file__).parent.parent.parent / "db" / "schema.sql"

@dataclass
class BotRecord:
    id: int
    name: str
    subnet_id: Optional[int]  # NULL if standalone
    is_active: bool
    last_seen: Optional[str]  # ISO timestamp

@dataclass
class BotLinkRecord:
    id: int
    bot_id: int
    linked_bot_id: int  # Self-links for botnet
    link_type: str  # 'subnet', 'full', etc.

async def get_schema_sql() -> str:
    """Load schema SQL from file."""
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    return schema


async def get_db(force_recreate: bool = False) -> AsyncGenerator[aiosqlite.Connection, None]:
    """
    Get DB connection context manager.
    
    Ensures directory exists, sets row_factory, and initializes schema idempotently
    unless force_recreate=True (drops all user tables first).
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    
    try:
        if force_recreate:
            await recreate_tables(db)
        else:
            await ensure_schema(db)
        yield db
    finally:
        await db.close()


async def recreate_tables(db: aiosqlite.Connection) -> None:
    """Drop all user tables (preserve sqlite_master/sqlite_sequence) and apply full schema."""
    async with db.execute("SELECT name FROM sqlite_master WHERE type='table';") as cur:
        tables = await cur.fetchall()
    
    for (table,) in tables:
        if table not in {'sqlite_sequence', 'sqlite_master'}:
            await db.execute(f"DROP TABLE IF EXISTS {table}")
    
    await db.commit()
    
    schema = await get_schema_sql()
    await db.executescript(schema)
    await db.commit()


async def ensure_schema(db: aiosqlite.Connection) -> None:
    """
    Apply schema idempotently: executes even if tables exist (CREATE TABLE IF NOT EXISTS).
    
    Safe to call multiple times. Assumes schema.sql uses IF NOT EXISTS for tables/indexes.
    """
    schema = await get_schema_sql()
    await db.executescript(schema)
    await db.commit()


async def init_db(force: bool = False) -> None:
    """Initialize DB (fresh recreate if force=True)."""
    status = "(fresh recreate)" if force else "(existing or created)"
    async with get_db(force_recreate=force) as db:
        print(f"DB initialized at {DB_PATH} {status}")
        # Future: await seed_initial_config(db)

@dataclass
class ChannelSettingsRow:
    channel: str
    settings: str  # e.g., "+enforcebans +dynamicbans"

@dataclass
class UserChanFlagsRow:
    handle: str
    channel: str
    flags: str  # e.g., "voipf"

async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    db = await aiosqlite.connect("pydrop.db")
    try:
        yield db
        await db.commit()
    finally:
        await db.close()

# Init DB (call once)
async def init_db():
    async with aiosqlite.connect("pydrop.db") as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                channel TEXT PRIMARY KEY,
                settings TEXT DEFAULT '+statuslog +userbans'
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS userchanflags (
                handle TEXT,
                channel TEXT,
                flags TEXT,
                PRIMARY KEY (handle, channel)
            )
        """)
        await db.commit()

# Run init
asyncio.run(init_db())