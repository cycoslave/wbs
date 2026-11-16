"""
Offline regression tests for SAST-004: user flag checks enforce active-user
state and subnet scope; mutations touch exactly one scope; locks and deletes
revoke already-open partyline sessions.

Scope model under test (db/schema.sql: user_access.subnet_id NULL = all):
    global row  (subnet_id NULL) -> applies on every subnet (intentional)
    local row   (subnet_id = k)  -> applies only when checking subnet k
    check with subnet_id=None    -> global rows only

The local bot is on subnet 1.  Every DB is a throwaway sqlite file under
pytest's tmp_path; no network, no IRC, no bot process.
"""
import asyncio
import os
import shutil
import tempfile
from types import SimpleNamespace as NS

import pytest

from src import commands
from src.db import get_db, init_db
from src.partyline import Partyline
from src.user import UserManager

LOCAL_SUBNET = 1
FAKE_HASH = "$2b$12$" + "x" * 53          # bcrypt-shaped placeholder, not a secret

_TEMPLATE_DB: str | None = None


async def _fresh_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-sast004-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


# users and their access rows: (channel, subnet_id, {flag columns})
USERS = {
    "gadmin":   [(None, None, {"has_partyline", "is_admin"})],          # global admin
    "ladmin":   [(None, 1, {"has_partyline", "is_admin"})],             # subnet-1 admin
    "fadmin":   [(None, 2, {"has_partyline", "is_admin"})],             # subnet-2 admin only
    "lockedA":  [(None, 2, {"has_partyline", "is_admin"}),              # the audit repro
                 (None, None, {"has_partyline", "is_admin"})],
    "deletedA": [(None, None, {"has_partyline", "is_admin", "is_owner"})],
    "mixed":    [(None, None, {"has_partyline"}),                       # global +p
                 (None, 2, {"is_op"}),                                  # +o on subnet 2 only
                 ("#one", 1, {"is_voice"}),                             # +v on #one, subnet 1
                 ("#one", 2, {"is_op"})],                               # +o on #one, subnet 2
    "plain1":   [(None, 1, {"has_partyline"})],
    "plain2":   [(None, 2, {"has_partyline"})],
    "victim":   [(None, 1, {"has_partyline", "is_op"})],
}


async def build_db(tmp_path) -> str:
    db = str(tmp_path / "wbs.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        for handle, rows in USERS.items():
            await d.execute("INSERT INTO users(handle, password, hostmasks) VALUES (?, ?, '[]')",
                            (handle, FAKE_HASH))
            for channel, sid, cols in rows:
                names = ["handle", "channel", "subnet_id", *sorted(cols)]
                vals = [handle, channel, sid, *([1] * len(cols))]
                await d.execute(
                    f"INSERT INTO user_access ({', '.join(names)}) "
                    f"VALUES ({', '.join('?' * len(names))})", vals)
        await d.execute("UPDATE users SET is_locked = 1 WHERE handle = 'lockedA'")
        await d.execute("UPDATE users SET deleted_at = 1 WHERE handle = 'deletedA'")
        await d.commit()
    return db


def run(coro):
    return asyncio.run(coro)


async def rows(db: str, handle: str) -> list[dict]:
    async with get_db(db) as d:
        return [dict(r) for r in await d.execute_fetchall(
            "SELECT channel, subnet_id, has_partyline, is_admin, is_owner, is_op, is_voice "
            "FROM user_access WHERE handle = ? ORDER BY channel, subnet_id", (handle,))]


class FakeCore:
    """Just enough of Core for commands.py + Partyline, fully offline."""

    def __init__(self, db: str, local_subnet: int = LOCAL_SUBNET):
        self.db_path = db
        self.config = {"bot": {"nick": "beta"}, "botnet": {"subnet_id": local_subnet}}
        self.user = UserManager(db)
        self.botname = "beta"
        self.irc_q = None
        self.botnet = NS(peers={})
        self.synced: list = []

        async def sync_user(action, payload):
            self.synced.append(("user", action, payload))

        async def sync_user_access(payload):
            self.synced.append(("access", payload))

        self.botnet.sync_user = sync_user
        self.botnet.sync_user_access = sync_user_access
        self.party_sessions = {}
        self.partyline = Partyline(self)


def open_session(core: FakeCore, handle: str, stype: str = "dcc"):
    q = asyncio.Queue()
    sid = core.partyline.register_remote(stype, handle, q)
    return sid, q


def drain(q: asyncio.Queue) -> list[str]:
    out = []
    while not q.empty():
        out.append(q.get_nowait()["text"])
    return out


async def cmd(core: FakeCore, name: str, caller: str, arg: str, session_id=None) -> list[str]:
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    await commands.COMMANDS[name](core, caller, session_id, arg, respond)
    await asyncio.sleep(0)            # let fire-and-forget sync tasks run
    return out


# ---------------------------------------------------------------------------
# matchattr: active-user enforcement
# ---------------------------------------------------------------------------
def test_locked_user_denied_everywhere(tmp_path):
    """Audit repro: locked user with +A on subnet 2 (and globally) -> always False."""
    async def main():
        um = UserManager(await build_db(tmp_path))
        for sid in (None, 1, 2):
            for spec in ("+A", "A", "+p", "p", "-k", "-n", "*|o"):
                assert await um.matchattr("lockedA", spec, "#one", subnet_id=sid) is False, (spec, sid)
        assert await um.is_active("lockedA") is False
    run(main())


def test_deleted_user_denied_everywhere(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        for sid in (None, 1, 2):
            for spec in ("+A", "+n", "+p", "-k"):
                assert await um.matchattr("deletedA", spec, subnet_id=sid) is False
        assert await um.matchattr("nosuchuser", "-A", subnet_id=1) is False
        assert await um.is_active("deletedA") is False
    run(main())


def test_verify_password_rejects_deleted_user(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        await um.set_password("plain1", "correct-horse-1")
        assert await um.verify_password("plain1", "correct-horse-1") is True
        await um.deluser("plain1")
        assert await um.verify_password("plain1", "correct-horse-1") is False
    run(main())


def test_subnet_scope_is_required_keyword(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        with pytest.raises(TypeError):
            await um.matchattr("gadmin", "+A")          # no implicit scope
        with pytest.raises(TypeError):
            await um.chattr("plain1", "+o")
    run(main())


# ---------------------------------------------------------------------------
# matchattr: subnet scope
# ---------------------------------------------------------------------------
def test_foreign_subnet_grant_is_not_global(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        # subnet-2-only admin
        assert await um.matchattr("fadmin", "+A", subnet_id=2) is True
        assert await um.matchattr("fadmin", "+A", subnet_id=1) is False
        assert await um.matchattr("fadmin", "+A", subnet_id=None) is False
        assert await um.matchattr("fadmin", "+p", subnet_id=1) is False
        # negative spec sees the same scope
        assert await um.matchattr("fadmin", "-A", subnet_id=1) is True
        assert await um.matchattr("fadmin", "-A", subnet_id=2) is False
        # subnet-1 admin is local, not global
        assert await um.matchattr("ladmin", "+A", subnet_id=1) is True
        assert await um.matchattr("ladmin", "+A", subnet_id=2) is False
        assert await um.matchattr("ladmin", "+A", subnet_id=None) is False
    run(main())


def test_global_grant_inherited_on_every_subnet(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        for sid in (None, 1, 2, 99):
            assert await um.matchattr("gadmin", "+pA", subnet_id=sid) is True
            assert await um.matchattr("mixed", "+p", subnet_id=sid) is True
    run(main())


def test_global_and_local_rows_combine_only_in_matching_subnet(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        # +p global + +o local(2)
        assert await um.matchattr("mixed", "+po", subnet_id=2) is True
        assert await um.matchattr("mixed", "+po", subnet_id=1) is False
        assert await um.matchattr("mixed", "+o", subnet_id=None) is False
    run(main())


def test_channel_flags_are_subnet_scoped(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        assert await um.matchattr("mixed", "*|v", "#one", subnet_id=1) is True
        assert await um.matchattr("mixed", "*|o", "#one", subnet_id=1) is False
        assert await um.matchattr("mixed", "*|o", "#one", subnet_id=2) is True
        assert await um.matchattr("mixed", "*|v", "#one", subnet_id=2) is False
        assert await um.matchattr("mixed", "*|v", "#one", subnet_id=None) is False
        assert await um.matchattr("mixed", "p|v", "#one", subnet_id=1) is True
    run(main())


# ---------------------------------------------------------------------------
# chattr / set_access_columns: exact-scope mutation
# ---------------------------------------------------------------------------
def test_chattr_changes_only_target_subnet_row(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        um = UserManager(db)
        before = await rows(db, "mixed")
        assert await um.chattr("mixed", "-o", subnet_id=2) == "ok"
        after = await rows(db, "mixed")
        changed = [(b, a) for b, a in zip(before, after) if b != a]
        assert changed == [(
            {"channel": None, "subnet_id": 2, "has_partyline": 0, "is_admin": 0,
             "is_owner": 0, "is_op": 1, "is_voice": 0},
            {"channel": None, "subnet_id": 2, "has_partyline": 0, "is_admin": 0,
             "is_owner": 0, "is_op": 0, "is_voice": 0},
        )]
        # the global row's +p survives, subnet-2 +o is gone
        assert await um.matchattr("mixed", "+p", subnet_id=2) is True
        assert await um.matchattr("mixed", "+o", subnet_id=2) is False
    run(main())


def test_chattr_global_vs_local_rows_are_distinct(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        um = UserManager(db)
        # removing -p on subnet 1 must not touch mixed's global +p row
        assert await um.chattr("mixed", "-p", subnet_id=1) == "ok"
        assert await um.matchattr("mixed", "+p", subnet_id=None) is True
        # a subnet-1 grant creates a subnet-1 row, never a global one
        assert await um.chattr("plain2", "+A", subnet_id=1) == "ok"
        assert await um.matchattr("plain2", "+A", subnet_id=1) is True
        assert await um.matchattr("plain2", "+A", subnet_id=2) is False
        assert await um.matchattr("plain2", "+A", subnet_id=None) is False
        # repeated global grants reuse the one global row (no NULL-PK duplicates)
        for _ in range(3):
            assert await um.chattr("plain1", "+f", subnet_id=None) == "ok"
        glob = [r for r in await rows(db, "plain1") if r["subnet_id"] is None]
        assert len(glob) == 1
        # removing the global row's flag leaves the local row intact
        assert await um.chattr("gadmin", "-A", subnet_id=None) == "ok"
        assert await um.matchattr("gadmin", "+A", subnet_id=1) is False
    run(main())


def test_chattr_channel_row_scoped(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        um = UserManager(db)
        assert await um.chattr("mixed", "-o", "#one", subnet_id=2) == "ok"
        r = {(x["channel"], x["subnet_id"]): x for x in await rows(db, "mixed")}
        assert r[("#one", 2)]["is_op"] == 0
        assert r[("#one", 1)]["is_voice"] == 1          # other scope untouched
        # #one is not a channel in this db (no channels row): no row is
        # created, nothing changes (USR-8 creates rows only for real channels)
        before = await rows(db, "victim")
        assert await um.chattr("victim", "+o", "#one", subnet_id=1) == "no_channel"
        assert await rows(db, "victim") == before
    run(main())


def test_chattr_bad_flag_and_unknown_user(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        assert await um.chattr("plain1", "+Z", subnet_id=1) == "bad_flag"
        assert await um.chattr("nobody", "+o", subnet_id=1) == "not_found"
        assert await um.chattr("deletedA", "+o", subnet_id=1) == "not_found"
    run(main())


# ---------------------------------------------------------------------------
# partyline choke point (existing-session revocation, scoped command gate)
# ---------------------------------------------------------------------------
def test_partyline_uses_local_subnet_scope(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        sid_f, q_f = open_session(core, "fadmin")
        sid_l, q_l = open_session(core, "ladmin")
        await core.partyline.handle_input(sid_f, ".lockuser victim")
        assert any("Access denied for .lockuser" in m for m in drain(q_f))
        assert await core.user.is_active("victim") is True
        await core.partyline.handle_input(sid_l, ".lockuser victim")
        assert any("has been locked" in m for m in drain(q_l))
        assert await core.user.is_active("victim") is False
    run(main())


def test_lock_revokes_existing_session(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        sid_v, q_v = open_session(core, "victim")
        sid_a, q_a = open_session(core, "gadmin")
        await core.partyline.handle_input(sid_v, ".whoami")
        assert not any("denied" in m.lower() for m in drain(q_v))

        await core.partyline.handle_input(sid_a, ".lockuser victim")
        assert sid_v not in core.partyline.sessions          # revoked immediately
        assert any("Session closed" in m for m in drain(q_v))
        # any late input on the revoked session does nothing
        await core.partyline.handle_input(sid_v, ".lockuser gadmin")
        assert await core.user.is_active("gadmin") is True
    run(main())


def test_out_of_band_lock_revokes_on_next_input(tmp_path):
    """Lock written straight to the DB (e.g. replication) -> next request is refused."""
    async def main():
        db = await build_db(tmp_path)
        core = FakeCore(db)
        sid, q = open_session(core, "ladmin")
        async with get_db(db) as d:
            await d.execute("UPDATE users SET is_locked = 1 WHERE handle = 'ladmin'")
            await d.commit()
        await core.partyline.handle_input(sid, ".lockuser victim")
        assert await core.user.is_active("victim") is True
        assert sid not in core.partyline.sessions
        assert any("Session closed" in m for m in drain(q))
    run(main())


def test_flag_removal_takes_effect_in_open_session(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        sid_l, q_l = open_session(core, "ladmin")
        sid_g, q_g = open_session(core, "gadmin")
        await core.partyline.handle_input(sid_g, ".delaccess ladmin -A")
        assert any("Removed -A from ladmin (subnet 1)" in m for m in drain(q_g))
        await core.partyline.handle_input(sid_l, ".lockuser victim")
        assert any("Access denied for .lockuser" in m for m in drain(q_l))
        assert await core.user.is_active("victim") is True
    run(main())


def test_delete_revokes_existing_session(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        sid_v, q_v = open_session(core, "victim")
        sid_a, _ = open_session(core, "gadmin")
        await core.partyline.handle_input(sid_a, ".-user victim")
        assert sid_v not in core.partyline.sessions
        assert any("deleted" in m for m in drain(q_v))
    run(main())


def test_replicated_lock_or_delete_revokes_session(tmp_path):
    """An in-scope peer's USER UPDATE/DEL that locks/deletes a user ends open sessions."""
    from src.botnet import BotnetManager

    async def main():
        core = FakeCore(await build_db(tmp_path))
        mgr = NS(core=core, user=core.user)
        mgr._revoke_inactive_sessions = (
            lambda recs: BotnetManager._revoke_inactive_sessions(mgr, recs))
        sid_1, q_1 = open_session(core, "plain1")
        sid_v, _ = open_session(core, "victim")
        sid_o, _ = open_session(core, "ladmin")
        far = 2_000_000_000
        await BotnetManager._apply_replication(
            mgr, "users", "UPDATE",
            [{"handle": "PLAIN1", "is_locked": 1, "updated_at": far}], "peer")
        assert sid_1 not in core.partyline.sessions
        assert any("Session closed" in m for m in drain(q_1))
        await BotnetManager._apply_replication(
            mgr, "users", "DEL", [{"handle": "victim", "deleted_at": far}], "peer")
        assert sid_v not in core.partyline.sessions
        assert sid_o in core.partyline.sessions            # unrelated session untouched
    run(main())


def test_console_session_not_revoked(tmp_path):
    """The console pseudo-user has no users row; is_active() must not revoke it."""
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out: list[str] = []
        sid = core.partyline.register_console("console", out.append)
        assert core.partyline.revoke_handle("console", "x") == 0
        await core.partyline.handle_input(sid, ".whoami")
        await core.partyline.handle_input(sid, "hello")
        assert sid in core.partyline.sessions
        assert not any("Session closed" in m for m in out)
    run(main())


# ---------------------------------------------------------------------------
# command callers: who may mutate which scope
# ---------------------------------------------------------------------------
def test_local_admin_cannot_grant_global_or_foreign(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        core = FakeCore(db)
        before = await rows(db, "plain1")
        out = await cmd(core, "addaccess", "ladmin", "plain1 +A *")
        assert any("need global +A" in m for m in out)
        out = await cmd(core, "addaccess", "ladmin", "plain1 +A two")
        assert any("need global +A" in m for m in out)
        out = await cmd(core, "chattr", "ladmin", "plain1 +a *")
        assert any("need global +A" in m for m in out)
        assert await rows(db, "plain1") == before
        # self-promotion to global admin is refused too
        await cmd(core, "addaccess", "ladmin", "ladmin +A *")
        assert await core.user.matchattr("ladmin", "+A", subnet_id=None) is False
    run(main())


def test_local_admin_grants_default_to_local_subnet(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        core = FakeCore(db)
        out = await cmd(core, "addaccess", "ladmin", "plain1 +o")
        assert any("Added +o to plain1 (subnet 1)" in m for m in out)
        assert await core.user.matchattr("plain1", "+o", subnet_id=1) is True
        assert await core.user.matchattr("plain1", "+o", subnet_id=2) is False
        assert await core.user.matchattr("plain1", "+o", subnet_id=None) is False
        # legacy .chattr path also stays in the local scope
        out = await cmd(core, "chattr", "ladmin", "plain1 +v")
        assert any("(subnet 1)" in m for m in out)
        assert await core.user.matchattr("plain1", "+v", subnet_id=None) is False
    run(main())


def test_foreign_admin_cannot_mutate_here(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        core = FakeCore(db)
        before = await rows(db, "plain1")
        for name, arg in (("addaccess", "plain1 +A"), ("delaccess", "plain1 -p"),
                          ("lockuser", "plain1"), ("chusercomment", "plain1 hi")):
            out = await cmd(core, name, "fadmin", arg)
            assert any("denied" in m.lower() for m in out), (name, out)
        # the audit repro user (locked, has +A) is refused as well
        out = await cmd(core, "addaccess", "lockedA", "plain1 +A *")
        assert any("denied" in m.lower() for m in out)
        assert await rows(db, "plain1") == before
        assert await core.user.is_active("plain1") is True
    run(main())


def test_global_admin_manages_all_scopes(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        core = FakeCore(db)
        out = await cmd(core, "addaccess", "gadmin", "plain2 +A two")
        assert any("(subnet 2)" in m for m in out)
        assert await core.user.matchattr("plain2", "+A", subnet_id=2) is True
        assert await core.user.matchattr("plain2", "+A", subnet_id=1) is False
        out = await cmd(core, "addaccess", "gadmin", "plain2 +f *")
        assert await core.user.matchattr("plain2", "+f", subnet_id=1) is True
        out = await cmd(core, "lockuser", "gadmin", "plain2")
        assert any("has been locked" in m for m in out)
    run(main())


def test_local_admin_cannot_manage_user_with_foreign_access(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        for target in ("plain2", "mixed", "gadmin"):
            out = await cmd(core, "lockuser", "ladmin", target)
            assert any("outside subnet 1" in m for m in out), (target, out)
            assert await core.user.is_active(target) is True
        out = await cmd(core, "-user", "ladmin", "gadmin")
        assert any("outside subnet 1" in m for m in out)
        assert await core.user.is_active("gadmin") is True
        out = await cmd(core, "chpass", "ladmin", "gadmin newpassword123")
        assert any("outside subnet 1" in m for m in out)
        # a user confined to subnet 1 is manageable
        out = await cmd(core, "lockuser", "ladmin", "plain1")
        assert any("has been locked" in m for m in out)
    run(main())


def test_adduser_scope_rules(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await cmd(core, "+user", "ladmin", "newg *!*@x *")
        assert any("need global +A" in m for m in out)
        assert await core.user.exist("newg") is False
        out = await cmd(core, "+user", "ladmin", "newl *!*@y")
        assert any("added" in m for m in out)
        assert await core.user.access_scopes("newl") == {1}
        out = await cmd(core, "+user", "gadmin", "newg *!*@x *")
        assert await core.user.access_scopes("newg") == {None}
    run(main())


def test_delaccess_warns_about_inherited_global_flag(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await cmd(core, "delaccess", "gadmin", "mixed -p")
        assert any("still has +p from a global" in m for m in out)
        assert await core.user.matchattr("mixed", "+p", subnet_id=1) is True
        out = await cmd(core, "delaccess", "gadmin", "mixed -p *")
        assert await core.user.matchattr("mixed", "+p", subnet_id=1) is False
    run(main())
