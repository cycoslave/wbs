# src/subnet.py
"""
Manages subnet definitions, membership, and scoped command routing.
Subnets are logical groupings of bots within the botnet; each subnet
can span multiple IRC networks and channels.
"""
import logging
import re
import aiosqlite
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

from .db import get_db
if TYPE_CHECKING:
    from .botnet import BotLink

log = logging.getLogger("wbs.subnet")

DEFAULT_LISTEN_PORT = 3333
DEFAULT_LISTEN_HOST = "127.0.0.1"   # loopback; wider binds need an explicit listen_host
_WILDCARD_HOSTS = ("", "0.0.0.0", "::", "*")


def botnet_config(config: Optional[dict]) -> dict:
    """
    The botnet settings section (NET-11): ``config['botnet']`` as an object
    (address, listen_host, listen_port, subnet_id, relay_from).  A legacy
    ``"botnet": true/false`` flag (the bool formerly kept in ``settings`` or at
    the top level) is not a section and yields {}.
    """
    sec = (config or {}).get('botnet')
    return sec if isinstance(sec, dict) else {}


def botnet_listen(config: Optional[dict]) -> tuple[str, int]:
    """
    (host, port) the botlink/partyline listener binds.  ``botnet.listen_host`` /
    ``botnet.listen_port`` win; the legacy ``settings.listen_host`` /
    ``settings.listen_port`` are still honoured; default 127.0.0.1:3333 (loopback only -- binding
    wider needs an explicit ``listen_host``, e.g. "0.0.0.0").
    """
    config = config or {}
    bn = botnet_config(config)
    st = config.get('settings')
    st = st if isinstance(st, dict) else {}
    host = bn.get('listen_host')
    if host is None:
        host = st.get('listen_host')
    port = bn.get('listen_port')
    if port is None:
        port = st.get('listen_port', DEFAULT_LISTEN_PORT)
    return (host or DEFAULT_LISTEN_HOST), int(port)


def _explicit_listen_host(config: Optional[dict]) -> bool:
    """True if the operator set a non-empty listen_host (botnet or legacy settings)."""
    config = config or {}
    st = config.get('settings')
    st = st if isinstance(st, dict) else {}
    host = botnet_config(config).get('listen_host')
    if host is None:
        host = st.get('listen_host')
    return bool(host)


def botnet_public_address(config: Optional[dict]) -> Optional[str]:
    """
    Address other bots should dial: ``botnet.address``, else a concrete
    (non-wildcard) listen host, else None (the operator must supply one).
    """
    addr = botnet_config(config).get('address')
    if isinstance(addr, str) and addr.strip():
        return addr.strip()
    host, _port = botnet_listen(config)
    if host == DEFAULT_LISTEN_HOST and not _explicit_listen_host(config):
        return None          # the loopback default is not an address a peer can dial
    return None if host in _WILDCARD_HOSTS else host


def local_subnet_id(config: Optional[dict]) -> int:
    """
    The local bot's subnet: botnet.subnet_id, else subnet.id (what seed_db
    stores), else 1.  Single source for every authorization scope decision
    (peer scope SAST-002/003, user flag scope SAST-004).
    """
    config = config or {}
    botnet = config.get('botnet')
    raw = botnet.get('subnet_id') if isinstance(botnet, dict) else None
    if raw is None:
        raw = (config.get('subnet') or {}).get('id', 1)
    try:
        return int(raw)
    except (TypeError, ValueError):
        log.error("Invalid local subnet id %r in config; using 1", raw)
        return 1


async def bot_target_scope(nick, *, local: int, own_names=(), peers=(), bots=None) -> Optional[bool]:
    """
    Subnet segregation for op/mode targets (SAST-002, NET-3 / D17).

    True  -> `nick` is this bot, or a bot whose stored scope includes `local`.
    False -> `nick` is a bot outside the local subnet, or of unknown scope
             (no stored subnet), or the lookup failed: deny.
    None  -> `nick` is not a known bot (a human): no subnet rule applies.

    A peer's scope only ever comes from our own DB (a live link's subnet_ids
    were loaded from it, `bots` is the BotManager reading it); nothing the
    peer announced counts.
    """
    key = (nick or '').lower()
    if not key:
        return False
    if key in {str(n).lower() for n in own_names if n}:
        return True
    for link in peers:
        if (getattr(link, 'nick', None) or getattr(link, 'name', None) or '').lower() == key:
            return local in (getattr(link, 'subnet_ids', None) or frozenset())
    if bots is None:
        log.error("No bot table to check subnet scope of %s; denying", nick)
        return False
    try:
        scope = await bots.get_subnet_scope(key)
    except Exception as exc:
        log.error("Could not load subnet scope for target %s: %s", nick, exc)
        return False
    if scope is None:
        return None
    return local in scope


# Subnet names start with a letter so a name can never be mistaken for an id
# (`.botattr <bot> subnet=<id|name>` reads all-digit values as ids).  Ids fit
# the 9-digit subnet token of the botlink hello.
SUBNET_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{0,31}\Z", re.ASCII)
SUBNET_NAME_RULE_TEXT = ("Invalid subnet name. Use 1-32 characters: a letter first, "
                         "then letters, digits, '_', '-' or '.'.")
SUBNET_ID_MAX = 999_999_999


def valid_subnet_name(name) -> bool:
    return isinstance(name, str) and SUBNET_NAME_RE.match(name) is not None


def parse_subnet_id(raw) -> Optional[int]:
    """A subnet id token (1..SUBNET_ID_MAX, plain digits) as int, else None."""
    if not isinstance(raw, str) or not raw.isascii() or not raw.isdigit() or len(raw) > 9:
        return None
    value = int(raw)
    return value if 1 <= value <= SUBNET_ID_MAX else None


@dataclass
class Subnet:
    """Runtime representation of a subnet row."""
    id: int
    name: str
    created_at: Optional[str] = None
    created_by: Optional[str] = None

@dataclass
class SubnetState:
    """Live runtime state for a subnet (peers, channels, networks)."""
    subnet: Subnet
    peer_handles: List[str] = field(default_factory=list)
    networks: Dict[str, bool] = field(default_factory=dict)
    channels: Dict[str, bool] = field(default_factory=dict)

class SubnetManager:
    """
    Manages subnet definitions and membership resolution.

    Responsibilities:
      - CRUD for subnet records in SQLite
      - Tracking which peers belong to which subnet at runtime
      - Resolving broadcast targets for subnet-scoped commands
      - Providing subnet membership checks used by BotnetManager
      - Merging incoming SHARE SUBNETS from peers
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        # subnet_id → SubnetState
        self._subnets: Dict[int, SubnetState] = {}

    async def load(self):
        """Load all subnets from DB into memory. Call at startup."""
        async with get_db(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT id, name, created_at, created_by FROM subnets"
            )
            rows = await cur.fetchall()

        self._subnets.clear()
        for row in rows:
            s = Subnet(
                id=row["id"],
                name=row["name"],
                created_at=row["created_at"],
                created_by=row["created_by"],
            )
            self._subnets[s.id] = SubnetState(subnet=s)

        log.info("Loaded %d subnets", len(self._subnets))

    async def create(self, name: str, created_by: str = "local",
                     subnet_id: Optional[int] = None) -> Subnet:
        """Create a new subnet (explicit id, or the next free one). Returns the new Subnet.

        Raises ValueError for an invalid name/id or when the name (case-
        insensitive) or the id is already taken.
        """
        if not valid_subnet_name(name):
            raise ValueError(SUBNET_NAME_RULE_TEXT)
        if subnet_id is not None and not (1 <= int(subnet_id) <= SUBNET_ID_MAX):
            raise ValueError(f"Invalid subnet id: use 1-{SUBNET_ID_MAX}.")
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT id, name FROM subnets WHERE LOWER(name) = LOWER(?)", (name,)
            ) as c:
                clash = await c.fetchone()
            if clash is not None:
                raise ValueError(f"Subnet name already in use: [{clash['id']}] {clash['name']}")
            if subnet_id is not None:
                async with db.execute(
                    "SELECT name FROM subnets WHERE id = ?", (int(subnet_id),)
                ) as c:
                    clash = await c.fetchone()
                if clash is not None:
                    raise ValueError(f"Subnet id {subnet_id} already in use: {clash['name']}")
                cur = await db.execute(
                    "INSERT INTO subnets (id, name, created_by) VALUES (?, ?, ?)",
                    (int(subnet_id), name, created_by),
                )
            else:
                cur = await db.execute(
                    "INSERT INTO subnets (name, created_by) VALUES (?, ?)",
                    (name, created_by),
                )
            await db.commit()
            subnet_id = cur.lastrowid

        s = Subnet(id=subnet_id, name=name, created_by=created_by)
        self._subnets[subnet_id] = SubnetState(subnet=s)
        log.info(f"Created subnet '{name}' (id={subnet_id})")
        return s

    # Tables whose rows point at a subnet id.  A referenced subnet is never
    # deleted: user_access.subnet_id is ON DELETE SET NULL, which would turn a
    # subnet-scoped grant into a GLOBAL one, and the CASCADE tables would
    # silently drop bindings.
    _REFERENCES = (
        ("bots", "SELECT handle FROM bots WHERE subnet_id = ?"),
        ("bot bindings", "SELECT bot_handle FROM bot_subnets WHERE subnet_id = ?"),
        ("channels", "SELECT channel_name FROM channel_subnets WHERE subnet_id = ?"),
        ("user access rows", "SELECT handle FROM user_access WHERE subnet_id = ?"),
        ("servers", "SELECT name FROM servers WHERE subnet_id = ?"),
    )

    async def references(self, subnet_id: int) -> dict[str, list[str]]:
        """{what: [names]} of every row that references subnet_id (empty = unused)."""
        refs: dict[str, list[str]] = {}
        async with get_db(self.db_path) as db:
            for what, sql in self._REFERENCES:
                async with db.execute(sql, (subnet_id,)) as cur:
                    names = sorted({str(r[0]) for r in await cur.fetchall()})
                if names:
                    refs[what] = names
        return refs

    async def delete(self, subnet_id: int, local_id: Optional[int] = None) -> tuple[bool, str]:
        """
        Delete an unused subnet by ID.  Returns (deleted, reason).

        Refuses this bot's own subnet (local_id) and any subnet still
        referenced by bots, bot/channel bindings, user access rows or servers.
        """
        if local_id is not None and subnet_id == local_id:
            return False, "it is this bot's own subnet"
        refs = await self.references(subnet_id)
        if refs:
            used = "; ".join(f"{what}: {', '.join(names[:5])}"
                             + (f" (+{len(names) - 5} more)" if len(names) > 5 else "")
                             for what, names in refs.items())
            return False, f"still in use ({used})"

        async with get_db(self.db_path) as db:
            cur = await db.execute(
                "DELETE FROM subnets WHERE id = ?", (subnet_id,)
            )
            await db.commit()
            deleted = cur.rowcount > 0

        if deleted:
            self._subnets.pop(subnet_id, None)
            log.info(f"Deleted subnet id={subnet_id}")
            return True, ""
        log.warning(f"Subnet id={subnet_id} not found for deletion")
        return False, "no such subnet"

    async def rename(self, subnet_id: int, new_name: str) -> bool:
        """Rename an existing subnet.  Raises ValueError for an invalid or taken name."""
        if not valid_subnet_name(new_name):
            raise ValueError(SUBNET_NAME_RULE_TEXT)
        async with get_db(self.db_path) as db:
            async with db.execute(
                "SELECT id, name FROM subnets WHERE LOWER(name) = LOWER(?) AND id != ?",
                (new_name, subnet_id),
            ) as c:
                clash = await c.fetchone()
            if clash is not None:
                raise ValueError(f"Subnet name already in use: [{clash['id']}] {clash['name']}")
            cur = await db.execute(
                "UPDATE subnets SET name = ?, updated_at = strftime('%s','now') WHERE id = ?",
                (new_name, subnet_id),
            )
            await db.commit()
            updated = cur.rowcount > 0

        if updated and subnet_id in self._subnets:
            self._subnets[subnet_id].subnet.name = new_name
            log.info(f"Renamed subnet id={subnet_id} → '{new_name}'")

        return updated

    async def get(self, subnet_id: int) -> Optional[Subnet]:
        """Fetch subnet by ID (memory-first, DB fallback)."""
        if subnet_id in self._subnets:
            return self._subnets[subnet_id].subnet

        async with get_db(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT id, name, created_at, created_by FROM subnets WHERE id = ?",
                (subnet_id,),
            )
            row = await cur.fetchone()

        if row:
            s = Subnet(
                id=row["id"],
                name=row["name"],
                created_at=row["created_at"],
                created_by=row["created_by"],
            )
            self._subnets[s.id] = SubnetState(subnet=s)
            return s

        return None

    async def get_by_name(self, name: str) -> Optional[Subnet]:
        """Fetch subnet by name (case-insensitive)."""
        for state in self._subnets.values():
            if state.subnet.name.lower() == name.lower():
                return state.subnet

        async with get_db(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT id, name, created_at, created_by FROM subnets "
                "WHERE LOWER(name) = LOWER(?)",
                (name,),
            )
            row = await cur.fetchone()

        if row:
            s = Subnet(
                id=row["id"],
                name=row["name"],
                created_at=row["created_at"],
                created_by=row["created_by"],
            )
            self._subnets[s.id] = SubnetState(subnet=s)
            return s

        return None

    def list_all(self) -> List[Subnet]:
        """Return all loaded subnets sorted by id."""
        return sorted(
            (state.subnet for state in self._subnets.values()),
            key=lambda s: s.id,
        )

    def register_peer(self, handle: str, subnet_id: int | None):
        """
        Mark a peer as belonging to a subnet at runtime.
        Call from BotnetManager when LINKREADY/LINKAUTH completes.
        """
        handle = handle.lower()

        if subnet_id is None:
            subnet_id = 1
            log.info("Assigned default subnet_id=1 to '%s'", handle)

        state = self._subnets.get(subnet_id)
        if state is None and subnet_id != 1:
            log.info(
                "Unknown subnet_id=%s for '%s'; falling back to default subnet_id=1",
                subnet_id,
                handle,
            )
            subnet_id = 1
            state = self._subnets.get(subnet_id)

        if state is None:
            log.warning(
                "Default subnet_id=1 is missing; cannot register peer '%s'",
                handle,
            )
            return

        if handle not in state.peer_handles:
            state.peer_handles.append(handle)
            log.debug(
                "Peer '%s' registered in subnet '%s'",
                handle,
                state.subnet.name,
            )

    def unregister_peer(self, handle: str):
        """
        Remove a peer from all subnets.
        Call from BotnetManager on disconnect.
        """
        handle = handle.lower()
        for state in self._subnets.values():
            if handle in state.peer_handles:
                state.peer_handles.remove(handle)
                log.debug(
                    f"Peer '{handle}' unregistered from "
                    f"subnet '{state.subnet.name}'"
                )

    def peers_in_subnet(self, subnet_id: int) -> List[str]:
        """Return handles of peers currently linked in a given subnet."""
        state = self._subnets.get(subnet_id)
        if state is None:
            return []
        return list(state.peer_handles)

    def subnet_of_peer(self, handle: str) -> Optional[int]:
        """Return the subnet_id a peer belongs to, or None."""
        handle = handle.lower()
        for sid, state in self._subnets.items():
            if handle in state.peer_handles:
                return sid
        return None

    def is_same_subnet(self, handle_a: str, handle_b: str) -> bool:
        """Return True if both peers are in the same subnet."""
        sid_a = self.subnet_of_peer(handle_a)
        return sid_a is not None and sid_a == self.subnet_of_peer(handle_b)

    def resolve_targets(
        self,
        peers: Dict[str, "BotLink"],
        scope: str,
        subnet_id: Optional[int] = None,
        exclude: Optional[str] = None,
    ) -> List["BotLink"]:
        """
        Resolve the BotLink objects a command should be sent to.

        scope:
          'all'    — every authed+connected peer
          'subnet' — only peers whose subnet_id matches the given subnet_id
          'bot'    — single-bot targeting; caller handles; returns []

        exclude: handle to skip (e.g. the originating peer).
        """
        exclude_lc = exclude.lower() if exclude else None
        targets: List["BotLink"] = []
        snapshot = list(peers.items())
        for handle, link in snapshot:
            if not (link.authed and link.connected):
                continue
            if exclude_lc and handle == exclude_lc:
                continue

            if scope == "all":
                targets.append(link)
            elif scope == "subnet":
                if subnet_id is not None and link.subnet_id == subnet_id:
                    targets.append(link)
            # scope == 'bot': caller resolves directly, nothing added here

        return targets
    
    async def merge_from_peer(self, subnets: list, from_bot: str):
        """
        Merge subnet list received via SHARE SUBNETS.
        Only inserts subnets that don't exist locally (by id OR name).
        Updates in-memory cache only after a successful commit.
        """
        inserted = 0
        new_entries: list[Subnet] = []

        async with get_db(self.db_path) as db:
            for subnet in subnets:
                sid = subnet.get("id")
                name = subnet.get("name", "").strip()

                if not isinstance(sid, int) or sid <= 0:
                    log.warning(
                        "merge_from_peer: invalid subnet id=%r from %s — skipped",
                        sid, from_bot,
                    )
                    continue
                if not name or len(name) > 64:
                    log.warning(
                        "merge_from_peer: invalid subnet name=%r from %s — skipped",
                        name, from_bot,
                    )
                    continue
                if sid == 1:
                    log.warning(
                        "merge_from_peer: peer %s tried to overwrite default subnet id=1 — skipped",
                        from_bot,
                    )
                    continue

                cur = await db.execute(
                    "INSERT OR IGNORE INTO subnets (id, name, created_at, created_by) "
                    "VALUES (?, ?, ?, ?)",
                    (sid, name, subnet.get("created_at"), from_bot),
                )
                if cur.rowcount > 0:
                    new_entries.append(Subnet(
                        id=sid,
                        name=name,
                        created_at=subnet.get("created_at"),
                        created_by=from_bot,
                    ))
                    inserted += 1
                else:
                    log.debug(
                        "merge_from_peer: subnet '%s' (id=%s) already exists — kept local",
                        name, sid,
                    )

            await db.commit()

        for s in new_entries:
            self._subnets[s.id] = SubnetState(subnet=s)

        log.info(
            "merge_from_peer: %s sent %d subnets — %d inserted, %d skipped",
            from_bot, len(subnets), inserted, len(subnets) - inserted,
        )

    async def serialize_for_peer(self, scope: str = 'full', subnet_id: Optional[int] = None) -> list[dict]:
        """Return subnet rows for botnet share. scope='subnet' sends only the given subnet_id."""
        async with get_db(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if scope == 'subnet' and subnet_id is not None:
                cur = await db.execute(
                    "SELECT id, name, created_at, created_by FROM subnets WHERE id = ?",
                    (subnet_id,)
                )
            else:
                cur = await db.execute(
                    "SELECT id, name, created_at, created_by FROM subnets"
                )
            rows = await cur.fetchall()
        return [dict(row) for row in rows]        