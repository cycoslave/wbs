# src/user.py
"""
Handles user management for WBS IRC bot.
"""
import json
import time
import logging
import fnmatch
from typing import List, Optional
from dataclasses import dataclass, asdict, field

from . import crypto_exec
from .db import get_db 
from .idrules import valid_handle, valid_hostmask, wildcard_only_host

log = logging.getLogger("wbs.user")
# THE flag table (USR-5): letter -> user_access column.  Case-sensitive (`A`
# admin, `a` autoop); every command, help text and display reads this table.
GLOBAL_FLAGS: dict[str, str] = {
    'p': 'has_partyline',
    'A': 'is_admin',
    'n': 'is_owner',
    'f': 'is_friend',
    'a': 'is_autoop',
    'o': 'is_op',
    'd': 'is_deop',
    'y': 'is_autohop',
    'l': 'is_hop',
    'r': 'is_dehop',
    'v': 'is_voice',
    'q': 'is_devoice',
    'k': 'is_autokick',
}
CHAN_FLAGS: dict[str, str] = dict(GLOBAL_FLAGS)
VALID_FLAG_COLUMNS: frozenset[str] = frozenset(GLOBAL_FLAGS.values())
# Word names for the same flags (USR-2), derived from the one flag table:
# is_admin -> admin, has_partyline -> partyline, is_autoop -> autoop ...
FLAG_WORDS: dict[str, str] = {
    col.removeprefix('is_').removeprefix('has_'): ch for ch, col in GLOBAL_FLAGS.items()
}
# Privileged flags: never replicated (share.py) and never granted by a
# peer; +n (owner) is only granted/removed by an owner or the console.
PRIVILEGED_FLAG_COLUMNS: tuple[str, ...] = ('is_admin', 'is_owner')
# Every other flag column, in table order.
ACCESS_FLAG_COLUMNS: tuple[str, ...] = tuple(
    col for col in GLOBAL_FLAGS.values() if col not in PRIVILEGED_FLAG_COLUMNS
)
# "A=admin n=owner p=partyline ..." for help text and error messages.
FLAG_LEGEND: str = ' '.join(
    f"{ch}={col.removeprefix('is_').removeprefix('has_')}" for ch, col in GLOBAL_FLAGS.items()
)


def unknown_flags(spec: str) -> list[str]:
    """Letters of a `+ab-c` flag spec that are not in GLOBAL_FLAGS (case-sensitive)."""
    return list(dict.fromkeys(ch for ch in spec if ch not in '+-' and ch not in GLOBAL_FLAGS))


def flag_string(row) -> str:
    """Flag letters set on an access row (mapping of column -> value), in table order."""
    return ''.join(ch for ch, col in GLOBAL_FLAGS.items() if row[col])


def expand_flag_words(spec: str) -> str:
    """Translate word flag names (`admin`, `op,voice`) to flag letters.

    Case-insensitive, comma separated; applies only when EVERY item is a known
    word, otherwise `spec` is returned untouched and read as letters.  A word
    wins over letters when both read (`op` is the word, not +o +p): the safer
    reading, it grants less.  Sign handling stays with the caller.
    """
    items = [i.lower() for i in spec.split(',')]
    if spec and all(i in FLAG_WORDS for i in items):
        return ''.join(dict.fromkeys(FLAG_WORDS[i] for i in items))
    return spec

@dataclass
class User:
    """Maps to the 'users' table."""
    handle: str
    password: Optional[str] = None      # bcrypt hash
    hostmasks: List[str] = field(default_factory=list)
    is_locked: bool = False
    comment: str = ''
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))
    deleted_at: Optional[int] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    deleted_by: Optional[str] = None

    def __post_init__(self):
        # Normalize hostmasks: DB stores as JSON string, dataclass expects list
        if isinstance(self.hostmasks, str):
            try:
                self.hostmasks = json.loads(self.hostmasks) if self.hostmasks else []
            except (json.JSONDecodeError, ValueError):
                self.hostmasks = []

@dataclass
class UserAccess:
    handle: str
    channel: Optional[str] = None
    subnet_id: Optional[int] = None
    has_partyline: bool = False
    is_admin: bool = False
    is_owner: bool = False
    is_friend: bool = False
    is_autoop: bool = False
    is_op: bool = False
    is_deop: bool = False
    is_autohop: bool = False
    is_hop: bool = False
    is_dehop: bool = False
    is_voice: bool = False
    is_devoice: bool = False
    is_autokick: bool = False
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    deleted_at: Optional[int] = None
    deleted_by: Optional[str] = None

class UserManager:
    def __init__(self, db_path):
        self.db_path = db_path

    @staticmethod
    async def _live_handle(db, handle: str) -> Optional[str]:
        """
        Stored spelling of the live (not soft-deleted) user `handle` names,
        case-insensitively (USR-7); None if there is none.  The exact
        spelling wins if legacy data holds several spellings.
        """
        if not handle or not isinstance(handle, str):
            return None
        async with db.execute(
            "SELECT handle FROM users WHERE LOWER(handle) = LOWER(?) AND deleted_at IS NULL "
            "ORDER BY (handle = ?) DESC LIMIT 1",
            (handle, handle),
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row else None

    async def adduser(self, handle: str, hostmask: str = None,
                      subnet_id: int = None, added_by: str = None) -> bool:
        """
        Add a user. subnet_id scopes their default access entry.
        None = global (partyline access on all subnets).

        Returns False for an invalid handle or hostmask (USR-7), or when a
        live user of that handle exists in any letter case.  A soft-deleted
        user of that handle (any case) is purged first, so the new user is
        clean: no old password, comment, lock flag, hostmasks or access rows
        (USR-17).
        """
        if not valid_handle(handle) or (hostmask is not None and not valid_hostmask(hostmask)):
            return False
        now = int(time.time())
        hostmasks = json.dumps([hostmask] if hostmask else [])

        async with get_db(self.db_path) as db:
            await db.execute("BEGIN IMMEDIATE")
            if await self._live_handle(db, handle) is not None:
                await db.rollback()
                return False
            stale = await db.execute_fetchall(
                "SELECT handle FROM users WHERE LOWER(handle) = LOWER(?)", (handle,))
            for (old,) in stale:        # soft-deleted tombstones only (live ones returned above)
                await db.execute("DELETE FROM user_access WHERE handle = ?", (old,))
                await db.execute("DELETE FROM users WHERE handle = ?", (old,))
            await db.execute(
                "INSERT INTO users (handle, hostmasks, created_at, created_by, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (handle, hostmasks, now, added_by, now)
            )

            # Create a default access entry scoped to subnet (or global if None).
            # +p (partyline/DCC) is granted by default (DCC-2): a user created
            # with a matching host must be offered the DCC password prompt.
            await db.execute(
                """INSERT INTO user_access
                   (handle, channel, subnet_id, has_partyline, created_by, updated_at)
                   VALUES (?, NULL, ?, 1, ?, ?)""",
                (handle, subnet_id, added_by, now)
            )
            await db.commit()
            return True

    async def deluser(self, handle: str, deleted_by: str = None) -> bool:
        """Soft-delete a user and their access entries."""
        now = int(time.time())
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            if handle is None:
                return False
            cur = await db.execute(
                "UPDATE users SET deleted_at = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (now, now, deleted_by, handle)
            )
            if cur.rowcount == 0:
                return False
            await db.execute(
                "UPDATE user_access SET deleted_at = ?, updated_at = ? WHERE handle = ?",
                (now, now, handle)
            )
            await db.commit()
            return True

    async def listusers(self) -> str:
        """List active users and bots."""
        async with get_db(self.db_path) as db:
            user_rows = await db.execute_fetchall(
                "SELECT handle, comment, is_locked FROM users "
                "WHERE deleted_at IS NULL ORDER BY handle"
            )
            bot_rows = await db.execute_fetchall(
                "SELECT handle, role, address, port FROM bots "
                "WHERE deleted_at IS NULL ORDER BY handle"
            )

        lines = []

        lines.append("Users:")
        if user_rows:
            for r in user_rows:
                lock = " [LOCKED]" if r["is_locked"] else ""
                lines.append(f"  {r['handle']}{lock} - {r['comment'] or ''}")
        else:
            lines.append("  (none)")

        lines.append("Bots:")
        if bot_rows:
            for r in bot_rows:
                role = f" [{r['role']}]" if r["role"] else ""
                addr = f" {r['address']}:{r['port']}" if r["address"] else ""
                lines.append(f"  {r['handle']}{role}{addr}")
        else:
            lines.append("  (none)")

        return "\n".join(lines)

    async def showuser(self, target_handle: str) -> str:
        """Show detailed info for specific user."""
        async with get_db(self.db_path) as db:
            stored = await self._live_handle(db, target_handle)   # deleted = not found
            user_cursor = await db.execute("""
                SELECT handle,
                    password IS NOT NULL AS has_pass,
                    hostmasks,
                    is_locked,
                    comment,
                    created_at,
                    updated_at
                FROM users
                WHERE handle = ? AND deleted_at IS NULL
            """, (stored,))

            user = await user_cursor.fetchone()
            await user_cursor.close()

            if user is None:
                return f"User '{target_handle}' not found."

            access_cursor = await db.execute(f"""
                SELECT channel,
                    subnet_id,
                    {', '.join(GLOBAL_FLAGS.values())},
                    created_at
                FROM user_access
                WHERE handle = ? AND deleted_at IS NULL
                ORDER BY channel ASC, subnet_id ASC
            """, (stored,))

            result = [f"User: {user['handle']}"]
            result.append(f"  Comment: {user['comment'] or 'None'}")
            result.append(f"  Password: {'Set' if user['has_pass'] else 'None'}")
            result.append(f"  Locked: {'Yes' if user['is_locked'] else 'No'}")
            result.append(f"  Hostmasks: {user['hostmasks']}")
            result.append("  Access:")

            has_access = False
            async for row in access_cursor:
                has_access = True
                # Letters straight from the one flag table (USR-5)
                subnet = "all subnets" if row['subnet_id'] is None else f"subnet {row['subnet_id']}"
                flag_str = flag_string(row) or '-'

                result.append(f"    {row['channel'] or '*'} ({subnet}): +{flag_str}")

            await access_cursor.close()

            if not has_access:
                result.append("    No access granted")

            return "\n".join(result)

    async def match_user(self, hostmask: str) -> Optional[str]:
        """
        Match a full nick!ident@host against stored glob-style hostmasks.
        Hostmasks are stored as a JSON array per user, e.g. ["*!*@*.bar.com"].
        """
        hostmask = hostmask.lower()
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                "SELECT handle, hostmasks FROM users WHERE deleted_at IS NULL"
            )
        for row in rows:
            masks = row['hostmasks']
            if isinstance(masks, str):
                try:
                    masks = json.loads(masks) if masks else []
                except (json.JSONDecodeError, ValueError):
                    masks = []
            for mask in masks:
                if fnmatch.fnmatch(hostmask, mask.lower()):
                    return row['handle']
        return None

    async def set_password(self, handle: str, password: str) -> bool:
        """Hash and store password for handle. Returns False if handle not found."""
        hashed = await crypto_exec.hash_password(password) if password else None
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            cur = await db.execute(
                "UPDATE users SET password = ? WHERE handle = ? AND deleted_at IS NULL",
                (hashed, handle)
            )
            await db.commit()
        return cur.rowcount > 0

    async def verify_password(self, handle: str, password: str) -> bool:
        """Verify a plaintext password against the stored bcrypt hash.
        Deleted and locked users never verify (SAST-004)."""
        try:
            async with get_db(self.db_path) as db:
                handle = await self._live_handle(db, handle)
                async with db.execute(
                    "SELECT password FROM users WHERE handle = ? AND deleted_at IS NULL "
                    "AND COALESCE(is_locked, 0) = 0",
                    (handle,)
                ) as cur:
                    row = await cur.fetchone()

            if not row:
                return False

            stored_hash = row["password"]
            if not stored_hash:
                return False

            return await crypto_exec.verify_password(password, stored_hash)
        except (ValueError, TypeError):
            return False

    # Audit columns that record which user did something; they follow a rename.
    _HANDLE_AUDIT_COLUMNS = ("created_by", "updated_by", "deleted_by", "added_by")

    async def change_handle(self, handle: str, new_handle: str,
                            changed_by: Optional[str] = None) -> Optional[str]:
        """
        Rename the live user `handle` (stored spelling, exact) to `new_handle`
        (USR-3, USR-4).  Returns None on success, else a user-facing reason.

        One transaction: the users row, every user_access row (FK to
        users.handle, no ON UPDATE CASCADE, so the check is deferred to
        COMMIT) and the *_by audit columns of every table.  Any failure rolls
        everything back.  `new_handle` must not name another user (deleted or
        not) or a bot, case-insensitively; a case-only change of the same
        user is allowed.
        """
        if not handle or not new_handle:
            return "Missing handle."
        if new_handle.lower() == "console":
            return "Handle 'console' is reserved."
        now = int(time.time())
        async with get_db(self.db_path) as db:
            await db.execute("BEGIN IMMEDIATE")
            async with db.execute(
                "SELECT 1 FROM users WHERE handle = ? AND deleted_at IS NULL", (handle,)
            ) as cur:
                if await cur.fetchone() is None:
                    await db.rollback()
                    return f"No such user: {handle}"
            if new_handle == handle:
                await db.rollback()
                return f"Handle is already {new_handle}."
            async with db.execute(
                "SELECT handle FROM users WHERE LOWER(handle) = LOWER(?) AND handle != ?",
                (new_handle, handle),
            ) as cur:
                taken = await cur.fetchone()
            if taken is None:
                async with db.execute(
                    "SELECT handle FROM bots WHERE LOWER(handle) = LOWER(?)", (new_handle,)
                ) as cur:
                    taken = await cur.fetchone()
            if taken is not None:
                await db.rollback()
                return f"Handle already in use: {taken[0]}"

            await db.execute("PRAGMA defer_foreign_keys = ON")
            await db.execute("UPDATE users SET handle = ?, updated_at = ? WHERE handle = ?",
                             (new_handle, now, handle))
            await db.execute("UPDATE user_access SET handle = ? WHERE handle = ?",
                             (new_handle, handle))
            tables = await db.execute_fetchall(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%'")
            for (table,) in tables:
                cols = {r[1] for r in await db.execute_fetchall(f'PRAGMA table_info("{table}")')}
                for col in self._HANDLE_AUDIT_COLUMNS:
                    if col in cols:   # names come from sqlite_master / a fixed tuple
                        await db.execute(
                            f'UPDATE "{table}" SET "{col}" = ? WHERE "{col}" = ?',
                            (new_handle, handle))
            # Re-point the audit stamp of the renamed row itself.
            await db.execute("UPDATE users SET updated_by = ? WHERE handle = ?",
                             (changed_by or new_handle, new_handle))
            await db.commit()   # deferred FK check runs here; failure rolls back
        log.info("User %s renamed to %s by %s", handle, new_handle, changed_by or handle)
        return None

    # ------------------------------------------------------------------
    # Authorization (SAST-004)
    #
    # Scope model (db/schema.sql: user_access.subnet_id NULL = all subnets):
    #   * A row with subnet_id NULL is a GLOBAL grant: it applies on every
    #     subnet.  This inheritance is intentional and is the only way a grant
    #     crosses subnets.
    #   * A row with subnet_id = k is LOCAL to subnet k and only counts when
    #     the check is made for subnet k.  It never acts as a global grant.
    #   * A check made without a subnet (subnet_id=None) sees global rows only.
    # Every check first requires the user to be active: present, not
    # soft-deleted and not locked.  Checks read the DB on every call, so a
    # lock, delete or flag removal takes effect on the next request of an
    # already-open session.
    # ------------------------------------------------------------------
    @staticmethod
    def _scope_clause(subnet_id: Optional[int]) -> tuple[str, list]:
        """SQL predicate selecting the access rows that apply in a subnet."""
        if subnet_id is None:
            return "subnet_id IS NULL", []
        return "(subnet_id IS NULL OR subnet_id = ?)", [int(subnet_id)]

    @staticmethod
    async def _is_active_db(db, handle: str) -> bool:
        async with db.execute(
            "SELECT 1 FROM users WHERE handle = ? AND deleted_at IS NULL "
            "AND COALESCE(is_locked, 0) = 0",
            (handle,),
        ) as cur:
            return await cur.fetchone() is not None

    async def is_active(self, handle: str) -> bool:
        """True if the user exists, is not soft-deleted and is not locked."""
        if not handle:
            return False
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            return handle is not None and await self._is_active_db(db, handle)

    async def resolve_handle(self, handle: str) -> Optional[str]:
        """Stored spelling of `handle` (case-insensitive), deleted or not; None if unknown.
        A live user wins over a deleted one, the exact spelling over another case."""
        if not handle:
            return None
        async with get_db(self.db_path) as db:
            return await self._local_handle(db, handle)

    async def access_scopes(self, handle: str) -> set[Optional[int]]:
        """Distinct subnet scopes (None = global) of a user's live access rows."""
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle) or handle
            rows = await db.execute_fetchall(
                "SELECT DISTINCT subnet_id FROM user_access "
                "WHERE handle = ? AND deleted_at IS NULL",
                (handle,),
            )
        return {r["subnet_id"] for r in rows}

    async def privileged_scopes(self, handle: str) -> set[Optional[int]]:
        """
        Subnet scopes (None = global) in which `handle` holds +A or +n on any
        live access row, channel rows included (SAST-020).  The user's own
        lock/delete state is deliberately ignored: a locked admin is still an
        admin account whose password only an owner may reset.
        """
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle) or handle
            rows = await db.execute_fetchall(
                "SELECT DISTINCT subnet_id FROM user_access "
                "WHERE handle = ? AND deleted_at IS NULL "
                "AND (COALESCE(is_admin, 0) = 1 OR COALESCE(is_owner, 0) = 1)",
                (handle,),
            )
        return {r["subnet_id"] for r in rows}

    async def matchattr(self, handle: str, flags: str, channel: Optional[str] = None, *,
                        subnet_id: Optional[int]) -> bool:
        """
        Eggdrop-style matchattr, evaluated in an explicit subnet scope.

        flags format: [+/-]<global>[|/&<channel>]
        +oA        → user has o AND A
        -k         → user does NOT have k
        o|o        → user has o AND channel o (channel arg required)
        *|o        → user has channel o only (skip the non-channel check)
        o&o        → same as o|o (& and | are interchangeable in this impl)
        +o|v       → has o AND channel v

        subnet_id (keyword, required): the subnet the request is evaluated
        for.  Rows granted globally (subnet_id NULL) or for exactly this
        subnet count; rows of any other subnet are ignored.  None means
        "no subnet context": only global rows count.

        Returns False for an unknown, soft-deleted or locked handle, whatever
        the flag spec (including negative specs).
        """
        if not flags or not handle:
            return False

        # Parse +/- prefix
        positive = True
        if flags.startswith('-'):
            positive = False
            flags = flags[1:]
        elif flags.startswith('+'):
            flags = flags[1:]

        # Split on | or & (only one separator allowed per Eggdrop spec)
        if '|' in flags:
            global_part, chan_part = flags.split('|', 1)
        elif '&' in flags:
            global_part, chan_part = flags.split('&', 1)
        else:
            global_part = flags
            chan_part = None

        # '*' as global_part means "skip global check, only check channel flags"
        skip_global = (global_part == '*')
        scope_sql, scope_params = self._scope_clause(subnet_id)

        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            if handle is None or not await self._is_active_db(db, handle):
                return False

            # --- Non-channel flag check (channel IS NULL rows in scope) ---
            if not skip_global and global_part:
                for char in global_part:
                    col = GLOBAL_FLAGS.get(char)
                    if col is None:
                        log.warning(f"matchattr: unknown global flag '{char}'")
                        return False
                    assert col in VALID_FLAG_COLUMNS, f"matchattr: col {col!r} not in allowlist"

                    async with db.execute(
                        f"SELECT 1 FROM user_access WHERE handle = ? AND channel IS NULL "
                        f"AND deleted_at IS NULL AND {scope_sql} AND {col} = 1 LIMIT 1",
                        (handle, *scope_params)
                    ) as cur:
                        row = await cur.fetchone()

                    has_flag = row is not None
                    if positive and not has_flag:
                        return False
                    if not positive and has_flag:
                        return False

            # --- Channel flag check ---
            if chan_part is not None:
                if not channel:
                    # Channel flags requested but no channel given → False
                    return False

                for char in chan_part:
                    col = CHAN_FLAGS.get(char)
                    if col is None:
                        log.warning(f"matchattr: unknown channel flag '{char}'")
                        return False
                    assert col in VALID_FLAG_COLUMNS, f"matchattr: col {col!r} not in allowlist"

                    async with db.execute(
                        f"""
                        SELECT 1 FROM user_access
                        WHERE handle = ?
                        AND LOWER(channel) = LOWER(?)
                        AND deleted_at IS NULL
                        AND {scope_sql}
                        AND {col} = 1
                        LIMIT 1
                        """,
                        (handle, channel, *scope_params)
                    ) as cur:
                        row = await cur.fetchone()
                    has_flag = row is not None
                    if positive and not has_flag:
                        return False
                    if not positive and has_flag:
                        return False

        return True

    async def list_users(self) -> List[User]:
        """Return all active users as User dataclasses."""
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(
                """
                SELECT handle, password, hostmasks, is_locked, comment,
                    created_at, updated_at, created_by, updated_by,
                    deleted_at, deleted_by
                FROM users
                WHERE deleted_at IS NULL
                ORDER BY handle
                """
            )
        return [User(**dict(r)) for r in rows]
    
    async def list_users_with_flag(self, flag: str) -> list[User]:
        """Return all active users who have the given flag set on any access row.

        Args:
            flag: A valid flag column name from VALID_FLAG_COLUMNS
                (e.g. 'is_admin', 'has_partyline').
        Raises:
            ValueError: If flag is not a recognized column name.
        """
        if flag not in VALID_FLAG_COLUMNS:
            raise ValueError(f"Invalid flag column: {flag!r}")

        # flag is allowlisted — safe to interpolate as column name
        query = f"""
            SELECT DISTINCT u.handle, u.password, u.hostmasks, u.is_locked, u.comment,
                u.created_at, u.updated_at, u.created_by, u.updated_by,
                u.deleted_at, u.deleted_by
            FROM users u
            JOIN user_access ua ON u.handle = ua.handle
            WHERE u.deleted_at IS NULL
            AND ua.deleted_at IS NULL
            AND ua.{flag} = 1
            ORDER BY u.handle
        """
        async with get_db(self.db_path) as db:
            rows = await db.execute_fetchall(query)
        return [User(**dict(r)) for r in rows] 
        
    async def exist(self, handle: str) -> bool:
        """Return True if a user with this handle exists and is not deleted."""
        async with get_db(self.db_path) as db:
            return await self._live_handle(db, handle) is not None

    def to_dict(self, user: User) -> dict:
        """Convert User to dict for DB INSERT/UPDATE."""
        data = asdict(user)
        data['hostmasks'] = json.dumps(data['hostmasks'])  # List -> JSON string
        return data

    def access_to_dict(self, access: UserAccess) -> dict:
        """Convert UserAccess to dict for DB INSERT/UPDATE."""
        return asdict(access)

    async def get(self, handle: str) -> Optional[User]:
        """
        Fetch a single active user by handle.
        Returns None if not found or soft-deleted.
        """
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            cursor = await db.execute(
                """
                SELECT handle, password, hostmasks, is_locked, comment,
                    created_at, updated_at, created_by, updated_by,
                    deleted_at, deleted_by
                FROM users
                WHERE handle = ?
                AND deleted_at IS NULL
                """,
                (handle,)
            )
            row = await cursor.fetchone()
            await cursor.close()

        if row is None:
            return None

        return User(**dict(row))
    
    async def get_deleted(self, handle: str) -> Optional[User]:
        """
        Fetch a user by handle regardless of deleted status.
        Use only for admin inspection — not for permission checks.
        """
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT handle, password, hostmasks, is_locked, comment,
                    created_at, updated_at, created_by, updated_by,
                    deleted_at, deleted_by
                FROM users
                WHERE LOWER(handle) = LOWER(?)
                ORDER BY (deleted_at IS NOT NULL), (handle = ?) DESC LIMIT 1
                """,
                (handle, handle)
            )
            row = await cursor.fetchone()
            await cursor.close()

        if row is None:
            return None

        return User(**dict(row))

    # ------------------------------------------------------------------
    # Botnet replication (SAST-003)
    #
    # Callers must pass records through share.ReplicationPolicy first; these
    # methods additionally never accept credentials (password) or global
    # privileges (is_admin / is_owner) from a peer, whatever the payload says,
    # and only write the fields a record actually carries.
    # ------------------------------------------------------------------
    _PEER_USER_FIELDS = ("hostmasks", "is_locked", "comment")
    _PEER_ACCESS_FLAGS = ACCESS_FLAG_COLUMNS

    @staticmethod
    async def _local_handle(db, handle: str) -> Optional[str]:
        async with db.execute(
            "SELECT handle FROM users WHERE LOWER(handle) = LOWER(?) "
            "ORDER BY (deleted_at IS NOT NULL), (handle = ?) DESC LIMIT 1",
            (handle, handle),
        ) as cur:
            row = await cur.fetchone()
        return row["handle"] if row else None

    @staticmethod
    async def _holds_privileged(db, handle: str) -> bool:
        """True when `handle` holds +n or +A on any live access row (any scope)."""
        async with db.execute(
            "SELECT 1 FROM user_access WHERE handle = ? AND deleted_at IS NULL "
            "AND (COALESCE(is_admin, 0) = 1 OR COALESCE(is_owner, 0) = 1) LIMIT 1",
            (handle,),
        ) as cur:
            return await cur.fetchone() is not None

    async def merge_from_peer(self, users: list[dict], from_bot: str) -> None:
        """Merge user records from a botnet peer. Last-write-wins on updated_at."""
        async with get_db(self.db_path) as db:
            for user in users:
                remote_updated = user.get('updated_at') or 0
                remote_deleted = user.get('deleted_at')
                local = await self._local_handle(db, user['handle'])

                if local is not None:
                    cur = await db.execute(
                        "SELECT updated_at, deleted_at FROM users WHERE handle = ?", (local,)
                    )
                    existing = await cur.fetchone()
                    if remote_updated <= (existing[0] or 0):
                        continue
                    final_deleted = remote_deleted
                    if remote_deleted is None and existing[1] and existing[1] > remote_updated:
                        final_deleted = existing[1]  # Keep more-recent local delete

                    fields = {k: user[k] for k in self._PEER_USER_FIELDS if k in user}
                    if 'hostmasks' in fields and not isinstance(fields['hostmasks'], str):
                        fields['hostmasks'] = json.dumps(fields['hostmasks'])
                    if 'hostmasks' in fields and await self._holds_privileged(db, local):
                        # mythos F-01b: a +n/+A user never takes a wildcard-only mask.
                        try:
                            incoming = json.loads(fields['hostmasks'] or '[]')
                        except (json.JSONDecodeError, ValueError, TypeError):
                            incoming = None
                        if isinstance(incoming, list):
                            kept = [m for m in incoming if not wildcard_only_host(m)]
                            if len(kept) != len(incoming):
                                log.warning(
                                    "merge_from_peer: dropped wildcard-only hostmask(s) %s "
                                    "for +n/+A user %s from %s",
                                    [m for m in incoming if wildcard_only_host(m)],
                                    local, from_bot)
                                fields['hostmasks'] = json.dumps(kept)
                    fields.update(updated_at=remote_updated, updated_by=from_bot,
                                  deleted_at=final_deleted)
                    set_clause = ", ".join(f"{k} = ?" for k in fields)  # fixed allowlist
                    await db.execute(
                        f"UPDATE users SET {set_clause} WHERE handle = ?",
                        (*fields.values(), local),
                    )
                else:
                    # New users arrive inert: no password, no access rows.
                    masks = user.get('hostmasks', '[]')
                    if not isinstance(masks, str):
                        masks = json.dumps(masks)
                    await db.execute(
                        """INSERT INTO users
                            (handle, password, hostmasks, is_locked, comment,
                            created_at, updated_at, created_by, deleted_at)
                        VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            user['handle'], masks,
                            user.get('is_locked', 0), user.get('comment', ''),
                            user.get('created_at', 0), remote_updated,
                            from_bot, remote_deleted
                        )
                    )
            await db.commit()
        log.info(f"UserManager.merge_from_peer: merged {len(users)} users from {from_bot}")

    async def merge_access_from_peer(self, access_list: list[dict], from_bot: str) -> None:
        """Merge user_access records from a botnet peer. Last-write-wins on updated_at."""
        async with get_db(self.db_path) as db:
            for acc in access_list:
                channel = acc.get('channel')
                subnet_id = acc.get('subnet_id')
                if subnet_id is None:
                    # Global rows are never accepted from a peer.
                    log.warning("merge_access_from_peer: rejecting global row for %s from %s",
                                acc.get('handle'), from_bot)
                    continue
                remote_updated = acc.get('updated_at') or 0
                remote_deleted = acc.get('deleted_at')

                handle = await self._local_handle(db, acc['handle'])
                if handle is None:
                    # Inert shell user (no password, no hostmasks); updated_at 0
                    # so the owner's next USERS record is not lost to LWW.
                    handle = acc['handle']
                    now = int(time.time())
                    await db.execute(
                        """INSERT OR IGNORE INTO users
                        (handle, hostmasks, created_at, updated_at, created_by)
                        VALUES (?, '[]', ?, 0, ?)""",
                        (handle, now, from_bot)
                    )

                cur = await db.execute(
                    """SELECT updated_at, deleted_at FROM user_access
                    WHERE handle = ?
                        AND (channel = ? OR (channel IS NULL AND ? IS NULL))
                        AND subnet_id = ?""",
                    (handle, channel, channel, subnet_id)
                )
                existing = await cur.fetchone()
                flags = {k: int(bool(acc[k])) for k in self._PEER_ACCESS_FLAGS if k in acc}
                if existing:
                    if remote_updated <= (existing[0] or 0):
                        continue
                    final_deleted = remote_deleted
                    if remote_deleted is None and existing[1] and existing[1] > remote_updated:
                        final_deleted = existing[1]
                    fields = dict(flags, updated_at=remote_updated, updated_by=from_bot,
                                  deleted_at=final_deleted)
                    set_clause = ", ".join(f"{k} = ?" for k in fields)  # fixed allowlist
                    await db.execute(
                        f"""UPDATE user_access SET {set_clause}
                        WHERE handle = ?
                            AND (channel = ? OR (channel IS NULL AND ? IS NULL))
                            AND subnet_id = ?""",
                        (*fields.values(), handle, channel, channel, subnet_id)
                    )
                else:
                    # is_admin / is_owner always start (and stay) 0 for peer rows.
                    cols = ["handle", "channel", "subnet_id", *flags,
                            "created_at", "updated_at", "created_by", "deleted_at"]
                    vals = [handle, channel, subnet_id, *flags.values(),
                            acc.get('created_at', 0), remote_updated, from_bot, remote_deleted]
                    await db.execute(
                        f"INSERT INTO user_access ({', '.join(cols)}) "
                        f"VALUES ({', '.join('?' * len(cols))})",
                        vals,
                    )
            await db.commit()
        log.info(f"UserManager.merge_access_from_peer: merged {len(access_list)} rows from {from_bot}")

    async def serialize_for_peer(self) -> list[dict]:
        """
        Return all users (including soft-deleted) as share candidates.
        Passwords (bcrypt hashes) are credentials and are never serialized
        for peers (SAST-003); ReplicationPolicy scopes what is actually sent.
        """
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                """SELECT handle, hostmasks, is_locked, comment,
                        created_at, updated_at, created_by, updated_by,
                        deleted_at, deleted_by
                FROM users"""
            )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def serialize_access_for_peer(self) -> list[dict]:
        """Return all user_access rows as share candidates (scoped by ReplicationPolicy)."""
        async with get_db(self.db_path) as db:
            cursor = await db.execute(
                """SELECT handle, channel, subnet_id,
                        has_partyline, is_admin, is_owner, is_friend,
                        is_autoop, is_op, is_deop,
                        is_autohop, is_hop, is_dehop,
                        is_voice, is_devoice, is_autokick,
                        created_at, updated_at, created_by, deleted_at
                FROM user_access"""
            )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def authenticate(self, handle: str, password: str) -> bool:
        """
        Canonical password login (SAST-011): True only for an existing,
        not deleted, not locked user whose stored bcrypt hash matches.
        Flag checks (e.g. +p) are the caller's job via matchattr().
        """
        if not handle or not isinstance(password, str) or not password:
            return False
        return await self.verify_password(handle, password) is True
    
    async def addhost(self, handle: str, hostmask: str, updated_by: str = None) -> str:
        """
        Add a hostmask to a user's hostmask list.

        Returns:
            "ok"           – hostmask added successfully
            "not_found"    – user does not exist or is deleted
            "duplicate"    – hostmask already present
            "invalid"      – hostmask is not a valid nick!user@host mask (USR-7)
            "wildcard_host" – the host part is only wildcards and the user
                              holds +n or +A (mythos F-01b)
        """
        if not valid_hostmask(hostmask):
            return "invalid"

        now = int(time.time())
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            cursor = await db.execute(
                "SELECT hostmasks FROM users WHERE handle = ? AND deleted_at IS NULL",
                (handle,),
            )
            row = await cursor.fetchone()
            if row is None:
                return "not_found"

            if wildcard_only_host(hostmask) and await self._holds_privileged(db, handle):
                log.warning("addhost: refused wildcard-only host %r for +n/+A user %s",
                            hostmask, handle)
                return "wildcard_host"

            try:
                masks: list[str] = json.loads(row["hostmasks"]) if row["hostmasks"] else []
            except (json.JSONDecodeError, ValueError):
                masks = []

            if hostmask in masks:
                return "duplicate"

            masks.append(hostmask)
            await db.execute(
                "UPDATE users SET hostmasks = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (json.dumps(masks), now, updated_by, handle),
            )
            await db.commit()
        return "ok"


    async def delhost(self, handle: str, hostmask: str, updated_by: str = None) -> str:
        """
        Remove a hostmask from a user's hostmask list.

        Returns:
            "ok"           – hostmask removed successfully
            "not_found"    – user does not exist or is deleted
            "no_such_host" – hostmask not in user's list
            "invalid"      – never returned: any stored mask may be removed
        """
        now = int(time.time())
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            cursor = await db.execute(
                "SELECT hostmasks FROM users WHERE handle = ? AND deleted_at IS NULL",
                (handle,),
            )
            row = await cursor.fetchone()
            if row is None:
                return "not_found"

            try:
                masks: list[str] = json.loads(row["hostmasks"]) if row["hostmasks"] else []
            except (json.JSONDecodeError, ValueError):
                masks = []

            if hostmask not in masks:
                return "no_such_host"

            masks.remove(hostmask)
            await db.execute(
                "UPDATE users SET hostmasks = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (json.dumps(masks), now, updated_by, handle),
            )
            await db.commit()
        return "ok"    
    
    async def set_comment(self, handle: str, comment: str, updated_by: str = None) -> str:
        """
        Set the comment field on a user record.

        Returns:
            "ok"         – comment updated
            "not_found"  – user does not exist or is deleted
        """
        now = int(time.time())
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            cur = await db.execute(
                "UPDATE users SET comment = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (comment, now, updated_by, handle),
            )
            await db.commit()
        return "ok" if cur.rowcount > 0 else "not_found"

    async def set_locked(self, handle: str, locked: bool, updated_by: str = None) -> str:
        """
        Lock or unlock a user account.

        Args:
            locked: True to lock, False to unlock.

        Returns:
            "ok"         – state updated
            "not_found"  – user does not exist or is deleted
            "no_change"  – user was already in the requested state
        """
        now = int(time.time())
        target = 1 if locked else 0
        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            # Check current state first to detect no-change
            cur = await db.execute(
                "SELECT is_locked FROM users WHERE handle = ? AND deleted_at IS NULL",
                (handle,),
            )
            row = await cur.fetchone()
            if row is None:
                return "not_found"
            if bool(row["is_locked"]) == locked:
                return "no_change"

            await db.execute(
                "UPDATE users SET is_locked = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (target, now, updated_by, handle),
            )
            await db.commit()
        return "ok"

    async def chattr(self, handle: str, flag_str: str,
                    channel: Optional[str] = None, *, subnet_id: Optional[int],
                    updated_by: Optional[str] = None) -> str:
        """
        Add or remove flags on the user's access row of exactly one scope.

        flag_str format: +<flags> and/or -<flags>  e.g. "+Ao-v"
        channel:   None = the non-channel row; otherwise that channel's row.
        subnet_id: keyword, required.  The scope of the row to change:
                   None = the GLOBAL row (applies on all subnets),
                   k    = the row local to subnet k.
                   Rows of any other scope are never touched (SAST-004).

        A missing row in the target scope is created on demand: the non-channel
        row always; a channel row (USR-8) when flags are added and the channel
        exists in that scope (bound to the subnet, or global).

        Returns:
            "ok"         – flags updated
            "not_found"  – user does not exist or is deleted
            "bad_flag"   – a letter not in GLOBAL_FLAGS (case-sensitive)
            "no_channel" – no such channel in this scope (no row was created)
            "no_access"  – no channel row to remove flags from
            "wildcard_host" – +n/+A requested for a user who has a hostmask
                           whose host part is only wildcards (mythos F-01b)
        """
        # Parse "+Ao-v" into adds={'is_admin','is_autoop'}, removes={'is_voice'}
        adds: set[str] = set()
        removes: set[str] = set()
        mode = "+"
        for ch in flag_str:
            if ch == "+":
                mode = "+"
            elif ch == "-":
                mode = "-"
            else:
                col = GLOBAL_FLAGS.get(ch)
                if col is None:
                    return "bad_flag" if await self.exist(handle) else "not_found"
                if mode == "+":
                    adds.add(col)
                    removes.discard(col)
                else:
                    removes.add(col)
                    adds.discard(col)

        return await self.set_access_columns(
            handle, adds, removes, channel=channel, subnet_id=subnet_id,
            updated_by=updated_by)

    async def set_access_columns(self, handle: str, adds: set[str], removes: set[str],
                                 channel: Optional[str] = None, *,
                                 subnet_id: Optional[int],
                                 updated_by: Optional[str] = None) -> str:
        """
        Set (adds) / clear (removes) allowlisted flag columns on the access row
        of exactly one scope: (handle, channel, subnet_id) where subnet_id None
        is the global row.  Same return values as chattr().
        """
        if not await self.exist(handle):
            return "not_found"
        if not adds and not removes:
            return "ok"

        # Safety: every column name must be in the allowlist
        for col in adds | removes:
            if col not in VALID_FLAG_COLUMNS:
                raise ValueError(f"set_access_columns: col {col!r} not in allowlist")
        if subnet_id is not None:
            subnet_id = int(subnet_id)

        set_parts = (
            [f"{col} = 1" for col in sorted(adds)] +
            [f"{col} = 0" for col in sorted(removes - adds)]
        )
        set_clause = ", ".join(set_parts)  # Only allowlisted column names — safe
        now = int(time.time())

        # Exact-scope row selection.  "IS ?" matches NULL = NULL, so the
        # global row (subnet_id NULL) and a subnet row are never confused.
        where = "handle = ? AND channel IS ? AND subnet_id IS ? AND deleted_at IS NULL"

        async with get_db(self.db_path) as db:
            handle = await self._live_handle(db, handle)
            if handle is None:
                return "not_found"
            if adds & set(PRIVILEGED_FLAG_COLUMNS):
                # mythos F-01b: no +n/+A for a user carrying a wildcard-only mask.
                async with db.execute(
                    "SELECT hostmasks FROM users WHERE handle = ?", (handle,)
                ) as cur:
                    urow = await cur.fetchone()
                try:
                    masks = json.loads(urow["hostmasks"] or "[]") if urow else []
                except (json.JSONDecodeError, ValueError, TypeError):
                    masks = []
                if any(wildcard_only_host(m) for m in masks):
                    log.warning("set_access_columns: refused +n/+A for %s: "
                                "wildcard-only hostmask on record", handle)
                    return "wildcard_host"
            canonical = None
            if channel is not None:
                # Channel rows use the channel's stored spelling (USR-8).
                canonical = await self._channel_in_scope(db, channel, subnet_id)
                channel = canonical or channel
            key = [handle, channel, subnet_id]
            async with db.execute(
                f"SELECT 1 FROM user_access WHERE {where} LIMIT 1", key
            ) as cur:
                exists = await cur.fetchone() is not None

            if not exists and channel is not None:
                # USR-8: a channel row is created on demand when the channel
                # exists in this scope; removing flags never creates one.
                if canonical is None:
                    return "no_channel"
                if not adds:
                    return "no_access"
            if not exists:
                # Create the row of this scope.  Not INSERT OR IGNORE: NULL
                # columns never collide in the primary key, so that would add
                # a duplicate non-channel row on every call.  A soft-deleted
                # channel row (same primary key) is revived with all flags
                # cleared instead of inserted.
                revived = 0
                if channel is not None:
                    cleared = ", ".join(f"{col} = 0" for col in GLOBAL_FLAGS.values())
                    cur = await db.execute(
                        f"UPDATE user_access SET {cleared}, deleted_at = NULL, deleted_by = NULL, "
                        f"created_at = ?, created_by = ? "
                        f"WHERE handle = ? AND channel IS ? AND subnet_id IS ?",
                        [now, updated_by, *key],
                    )
                    revived = cur.rowcount
                if not revived:
                    await db.execute(
                        """INSERT INTO user_access
                        (handle, channel, subnet_id, created_at, updated_at, created_by)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                        (handle, channel, subnet_id, now, now, updated_by),
                    )

            cur = await db.execute(
                f"UPDATE user_access SET {set_clause}, updated_at = ?, updated_by = ? "
                f"WHERE {where}",
                [now, updated_by, *key],
            )
            await db.commit()

        return "ok" if cur.rowcount > 0 else "no_access"

    @staticmethod
    async def _channel_in_scope(db, channel: str, subnet_id: Optional[int]) -> Optional[str]:
        """
        Stored name of `channel` if it is a live channel usable in this scope,
        else None.  A subnet row needs the channel bound to that subnet or
        unbound (global channel); a global row (subnet_id None) only needs
        the channel to exist.
        """
        async with db.execute(
            "SELECT name FROM channels WHERE LOWER(name) = LOWER(?) AND deleted_at IS NULL",
            (channel,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        name = row["name"]
        if subnet_id is None:
            return name
        bound = {r["subnet_id"] for r in await db.execute_fetchall(
            "SELECT subnet_id FROM channel_subnets WHERE channel_name = ?", (name,))}
        if bound and int(subnet_id) not in bound:
            return None
        return name
    
    async def delete_from_peer(self, payload: dict, from_bot: str) -> None:
        """
        Soft-delete a user received via botnet UPDATE USER DEL (after
        ReplicationPolicy approval).  A delete older than the local record's
        last update loses (last-write-wins); nothing is hard-deleted.
        """
        handle = (payload.get("handle") or "").strip()
        if not handle:
            log.warning("delete_from_peer: missing handle in payload from %s", from_bot)
            return
        remote_ts = payload.get("deleted_at") or payload.get("updated_at")
        now = int(time.time())
        async with get_db(self.db_path) as db:
            local = await self._local_handle(db, handle)
            if local is None:
                return
            cur = await db.execute("SELECT updated_at FROM users WHERE handle = ?", (local,))
            row = await cur.fetchone()
            if remote_ts and row and (row[0] or 0) > remote_ts:
                log.info("delete_from_peer: stale delete of '%s' from %s ignored", local, from_bot)
                return
            ts = remote_ts or now
            await db.execute(
                "UPDATE users SET deleted_at = ?, deleted_by = ?, updated_at = ?, updated_by = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (ts, from_bot, ts, from_bot, local))
            await db.execute(
                "UPDATE user_access SET deleted_at = ?, deleted_by = ?, updated_at = ? "
                "WHERE handle = ? AND deleted_at IS NULL",
                (ts, from_bot, ts, local))
        log.info("UserManager.delete_from_peer: deleted user '%s' from %s", local, from_bot)
