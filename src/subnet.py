# src/subnet.py
"""
Manages subnet definitions, membership, and scoped command routing.
Subnets are logical groupings of bots within the botnet; each subnet
can span multiple IRC networks and channels.
"""
import logging
import aiosqlite
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

from .db import get_db
from .botnet import BotLink, BotnetManager

log = logging.getLogger("wbs.subnet")


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

        log.info(f"Loaded {len(self._subnets)} subnets")

    async def create(self, name: str, created_by: str = "local") -> Subnet:
        """Create a new subnet. Returns the new Subnet."""
        async with get_db(self.db_path) as db:
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

    async def delete(self, subnet_id: int) -> bool:
        """
        Delete a subnet by ID.
        Refuses to delete subnet id=1 (default/fallback subnet).
        """
        if subnet_id == 1:
            log.error("Cannot delete default subnet (id=1)")
            return False

        async with get_db(self.db_path) as db:
            cur = await db.execute(
                "DELETE FROM subnets WHERE id = ?", (subnet_id,)
            )
            await db.commit()
            deleted = cur.rowcount > 0

        if deleted:
            self._subnets.pop(subnet_id, None)
            log.info(f"Deleted subnet id={subnet_id}")
        else:
            log.warning(f"Subnet id={subnet_id} not found for deletion")

        return deleted

    async def rename(self, subnet_id: int, new_name: str) -> bool:
        """Rename an existing subnet."""
        async with get_db(self.db_path) as db:
            cur = await db.execute(
                "UPDATE subnets SET name = ? WHERE id = ?",
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

        for handle, link in peers.items():
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
        Updates in-memory cache for newly inserted entries.
        """
        inserted = 0
        async with get_db(self.db_path) as db:
            for subnet in subnets:
                sid = subnet["id"]
                name = subnet["name"]

                cur = await db.execute(
                    "SELECT id FROM subnets "
                    "WHERE id = ? OR LOWER(name) = LOWER(?)",
                    (sid, name),
                )
                if await cur.fetchone():
                    log.debug(
                        f"Subnet '{name}' (id={sid}) already exists — kept local"
                    )
                    continue

                await db.execute(
                    "INSERT INTO subnets (id, name, created_at, created_by) "
                    "VALUES (?, ?, ?, ?)",
                    (sid, name, subnet.get("created_at"), from_bot),
                )
                s = Subnet(
                    id=sid,
                    name=name,
                    created_at=subnet.get("created_at"),
                    created_by=from_bot,
                )
                self._subnets[sid] = SubnetState(subnet=s)
                inserted += 1

            await db.commit()

        log.info(
            f"Merged subnets from {from_bot}: "
            f"{inserted} inserted, {len(subnets) - inserted} skipped"
        )

    async def serialize_for_peer(self, scope: str = 'full', subnet_id: int = None) -> list[dict]:
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