"""
Offline regression tests for SAST-020: password resets enforce the
operator-approved owner/admin hierarchy (decision 2026-09-30).

    * only an OWNER (+n) may reset the password of another admin or owner;
    * admins (+A) may reset regular users' passwords and their own;
    * anyone else is denied; the local console session (operator) may
      reset any account but has no password of its own.

Scope model (SAST-004): user_access.subnet_id NULL = global grant, k = local
to subnet k.  The local bot is on subnet 1.  A target whose +A/+n grants are
all local to subnet 1 needs +n here; a target with a global or foreign
privileged grant needs a GLOBAL +n.  Every DB is a throwaway sqlite file
under pytest's tmp_path; no network, no IRC, no bot process.
"""
import asyncio
import logging
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
NEW_PW = "N3w-pass-word"                      # test-only value, never a real secret
_TEMPLATE_DB: str | None = None

P, A, N = "has_partyline", "is_admin", "is_owner"

# handle -> [(channel, subnet_id, {flag columns})]
USERS = {
    "gowner":   [(None, None, {P, A, N})],              # global owner
    "lowner":   [(None, 1, {P, A, N})],                 # subnet-1 owner
    "lowner2":  [(None, 1, {P, A, N})],                 # second subnet-1 owner
    "fowner":   [(None, 2, {P, A, N})],                 # subnet-2 owner only
    "gadmin":   [(None, None, {P, A})],                 # global admin
    "gadmin2":  [(None, None, {P, A})],
    "ladmin":   [(None, 1, {P, A})],                    # subnet-1 admin
    "ladmin2":  [(None, 1, {P, A})],
    "fadmin":   [(None, 2, {P, A})],                    # subnet-2 admin only
    "gA_ln":    [(None, None, {P, A}), (None, 1, {N})],  # global +A, owner on subnet 1 only
    "gA_fn":    [(None, None, {P, A}), (None, 2, {N})],  # global +A, owner on subnet 2 only
    "chanA":    [(None, 1, {P}), ("#one", 1, {A})],      # +A only on a channel row
    "lockedA":  [(None, 1, {P, A})],                     # locked subnet-1 admin
    "nopwA":    [(None, 1, {P, A})],                     # admin without password
    "nopwU":    [(None, 1, {P})],                        # user without password
    "plain1":   [(None, 1, {P})],
    "plain1b":  [(None, 1, {P})],
    "plain2":   [(None, 2, {P})],
    "gplain":   [(None, None, {P})],
    "deletedU": [(None, 1, {P})],
}
NO_PASSWORD = {"nopwA", "nopwU"}


@pytest.fixture(autouse=True)
def _cheap_bcrypt(monkeypatch):
    """Minimum bcrypt cost keeps the offline matrix fast; semantics unchanged."""
    import bcrypt
    real = bcrypt.gensalt
    monkeypatch.setattr(bcrypt, "gensalt", lambda rounds=4, prefix=b"2b": real(4, prefix))


def placeholder_hash(handle: str) -> str:
    """Unique bcrypt-shaped placeholder per user (not a secret)."""
    body = (handle + "x" * 53)[:53]
    return "$2b$12$" + body


async def _fresh_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-sast020-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


async def build_db(tmp_path) -> str:
    db = str(tmp_path / "wbs.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one'), (2, 'two')")
        for handle, rows in USERS.items():
            pw = None if handle in NO_PASSWORD else placeholder_hash(handle)
            await d.execute("INSERT INTO users(handle, password, hostmasks) VALUES (?, ?, '[]')",
                            (handle, pw))
            for channel, sid, cols in rows:
                names = ["handle", "channel", "subnet_id", *sorted(cols)]
                vals = [handle, channel, sid, *([1] * len(cols))]
                await d.execute(
                    f"INSERT INTO user_access ({', '.join(names)}) "
                    f"VALUES ({', '.join('?' * len(names))})", vals)
        await d.execute("UPDATE users SET is_locked = 1 WHERE handle = 'lockedA'")
        await d.execute("UPDATE users SET deleted_at = 1 WHERE handle = 'deletedU'")
        await d.commit()
    return db


def run(coro):
    return asyncio.run(coro)


async def stored_hash(db: str, handle: str):
    async with get_db(db) as d:
        rows = await d.execute_fetchall("SELECT password FROM users WHERE handle = ?", (handle,))
    return rows[0]["password"] if rows else None


async def changed(db: str, handle: str) -> bool:
    """True if the user's stored hash is no longer the seeded placeholder."""
    h = await stored_hash(db, handle)
    seeded = None if handle in NO_PASSWORD else placeholder_hash(handle)
    return h != seeded


async def password_is(core, handle: str, pw: str) -> bool:
    import bcrypt
    h = await stored_hash(core.db_path, handle)
    return bool(h) and bcrypt.checkpw(pw.encode(), h.encode())


class FakeCore:
    """Just enough of Core for commands.py + Partyline, fully offline."""

    def __init__(self, db: str, local_subnet: int = LOCAL_SUBNET):
        self.db_path = db
        self.config = {"bot": {"nick": "beta"}, "botnet": {"subnet_id": local_subnet}}
        self.user = UserManager(db)
        self.botname = "beta"
        self.irc_q = None
        self.botnet = NS(peers={})
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
    await asyncio.sleep(0)
    return out


async def chpass(core, caller, target, session_id=None):
    return await cmd(core, "chpass", caller, f"{target} {NEW_PW}", session_id)


# ---------------------------------------------------------------------------
# caller x target hierarchy matrix
# ---------------------------------------------------------------------------
ALLOWED = "allowed"

# (caller, target, expected): expected is ALLOWED or a substring of the denial
MATRIX = [
    # global owner: may reset everyone, owners and admins included
    ("gowner", "lowner", ALLOWED),
    ("gowner", "gadmin", ALLOWED),
    ("gowner", "ladmin", ALLOWED),
    ("gowner", "fadmin", ALLOWED),
    ("gowner", "fowner", ALLOWED),
    ("gowner", "lockedA", ALLOWED),
    ("gowner", "chanA", ALLOWED),
    ("gowner", "plain1", ALLOWED),
    ("gowner", "plain2", ALLOWED),
    # subnet-1 owner: owners/admins/users confined to subnet 1 only
    ("lowner", "lowner2", ALLOWED),
    ("lowner", "ladmin", ALLOWED),
    ("lowner", "lockedA", ALLOWED),
    ("lowner", "plain1", ALLOWED),
    ("lowner", "gowner", "outside subnet 1"),
    ("lowner", "gadmin", "outside subnet 1"),
    ("lowner", "fadmin", "outside subnet 1"),
    ("lowner", "plain2", "outside subnet 1"),
    ("lowner", "gplain", "outside subnet 1"),
    # global admin (no +n): regular users anywhere, never admins/owners
    ("gadmin", "plain1", ALLOWED),
    ("gadmin", "plain2", ALLOWED),
    ("gadmin", "gplain", ALLOWED),
    ("gadmin", "gadmin2", "need global +n"),
    ("gadmin", "gowner", "need global +n"),
    ("gadmin", "fadmin", "need global +n"),
    ("gadmin", "fowner", "need global +n"),
    ("gadmin", "ladmin", "need +n"),
    ("gadmin", "lowner", "need +n"),
    ("gadmin", "lockedA", "need +n"),
    ("gadmin", "chanA", "need +n"),
    # subnet-1 admin: regular subnet-1 users only
    ("ladmin", "plain1", ALLOWED),
    ("ladmin", "ladmin2", "need +n"),
    ("ladmin", "lowner", "need +n"),
    ("ladmin", "lockedA", "need +n"),
    ("ladmin", "chanA", "need +n"),
    ("ladmin", "gadmin", "outside subnet 1"),
    ("ladmin", "gowner", "outside subnet 1"),
    ("ladmin", "plain2", "outside subnet 1"),
    # wrong-scope owner grants
    ("gA_ln", "ladmin", ALLOWED),          # local +n covers a local admin
    ("gA_ln", "lowner", ALLOWED),
    ("gA_ln", "gadmin", "need global +n"),  # local +n never covers a global admin
    ("gA_ln", "fadmin", "need global +n"),  # ... nor a foreign one
    ("gA_ln", "plain2", ALLOWED),
    ("gA_fn", "ladmin", "need +n"),          # subnet-2 +n is not +n here
    ("gA_fn", "fadmin", "need global +n"),   # nor global +n
    ("gA_fn", "plain1", ALLOWED),
    # foreign-only admin/owner: no +A on this subnet at all
    ("fowner", "plain1", "need +A"),
    ("fowner", "fadmin", "need +A"),
    ("fadmin", "plain2", "need +A"),
    # regular users: never another account
    ("plain1", "plain1b", "need +A"),
    ("plain1", "ladmin", "need +A"),
    ("plain1", "gowner", "need +A"),
    ("gplain", "plain1", "need +A"),
    # locked admin / owner callers have no rights at all
    ("lockedA", "plain1", "need +A"),
]


@pytest.mark.parametrize("caller,target,expected", MATRIX,
                         ids=[f"{c}->{t}" for c, t, _ in MATRIX])
def test_reset_hierarchy_matrix(tmp_path, caller, target, expected):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await chpass(core, caller, target)
        if expected == ALLOWED:
            assert out == [f"Password updated for {target}."], out
            assert await password_is(core, target, NEW_PW)
        else:
            assert len(out) == 1 and "Access denied" in out[0], out
            assert expected in out[0], out
            assert not await changed(core.db_path, target), "denied reset changed the password"
    run(main())


def test_owner_denial_message_names_policy(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await chpass(core, "ladmin", "ladmin2")
        assert out == ["Access denied (need +n: only an owner may change the password "
                       "of an admin or owner)."]
    run(main())


# ---------------------------------------------------------------------------
# self-reset policy
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("caller", ["plain1", "ladmin", "gadmin", "lowner", "gowner", "chanA"])
def test_self_reset_one_arg(tmp_path, caller):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await cmd(core, "chpass", caller, NEW_PW)
        assert out == ["Password updated."]
        assert await password_is(core, caller, NEW_PW)
    run(main())


@pytest.mark.parametrize("caller,spelling", [("ladmin", "ladmin"), ("ladmin", "LADMIN"),
                                             ("plain1", "plain1"), ("gadmin", "GAdmin")])
def test_self_reset_naming_self_is_allowed(tmp_path, caller, spelling):
    """'.chpass <own handle> <pw>' is a self-reset, not an admin-on-admin reset."""
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await chpass(core, caller, spelling)
        assert out == ["Password updated."]
        assert await password_is(core, caller, NEW_PW)
    run(main())


def test_self_reset_short_password_rejected(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await cmd(core, "chpass", "ladmin", "short")
        assert out == ["Password must be at least 8 characters."]
        assert not await changed(core.db_path, "ladmin")
    run(main())


def test_short_password_rejected_even_when_authorized(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await cmd(core, "chpass", "gowner", "ladmin short")
        assert out == ["Password must be at least 8 characters."]
        assert not await changed(core.db_path, "ladmin")
    run(main())


# ---------------------------------------------------------------------------
# console (operator) policy
# ---------------------------------------------------------------------------
def test_console_may_reset_any_account(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        sid = core.partyline.register_console("console", lambda *_: None)
        for target in ("gowner", "lowner", "gadmin", "fadmin", "plain2"):
            out = await chpass(core, "console", target, sid)
            assert out == [f"Password updated for {target}."], (target, out)
            assert await password_is(core, target, NEW_PW)
    run(main())


def test_console_has_no_password(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        sid = core.partyline.register_console("console", lambda *_: None)
        assert await cmd(core, "chpass", "console", NEW_PW, sid) == \
            ["ERROR: Console user does not have a password."]
        assert await chpass(core, "console", "console", sid) == \
            ["ERROR: Console user does not have a password."]
        # nobody can target the console pseudo-user
        assert await chpass(core, "gowner", "console") == \
            ["ERROR: Console user does not have a password."]
    run(main())


def test_handle_named_console_without_console_session_is_not_operator(tmp_path):
    """Console rights come from the session type, never from the handle string."""
    async def main():
        core = FakeCore(await build_db(tmp_path))
        sid, _q = open_session(core, "console", "telnet")
        out = await chpass(core, "console", "plain1", sid)
        assert any("Access denied" in m for m in out), out
        assert not await changed(core.db_path, "plain1")
    run(main())


# ---------------------------------------------------------------------------
# unknown / deleted targets, session revocation, audit logging
# ---------------------------------------------------------------------------
def test_unknown_and_deleted_targets(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        assert await chpass(core, "gowner", "nosuchuser") == ["User not found: nosuchuser"]
        out = await chpass(core, "gowner", "deletedU")
        assert out == ["User not found: deletedU"]
        assert not await changed(core.db_path, "deletedU")
    run(main())


def test_reset_of_other_user_revokes_their_sessions(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        vsid, vq = open_session(core, "plain1")
        asid, _aq = open_session(core, "gadmin")
        out = await chpass(core, "gadmin", "plain1", asid)
        assert out == ["Password updated for plain1."]
        assert vsid not in core.partyline.sessions
        assert any("Session closed" in m and "password was changed" in m for m in drain(vq))
        assert asid in core.partyline.sessions
    run(main())


def test_denied_reset_does_not_revoke_sessions(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        vsid, _vq = open_session(core, "ladmin2")
        out = await chpass(core, "ladmin", "ladmin2")
        assert "Access denied" in out[0]
        assert vsid in core.partyline.sessions
    run(main())


def test_self_reset_keeps_own_session(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        sid, _q = open_session(core, "ladmin")
        assert await cmd(core, "chpass", "ladmin", NEW_PW, sid) == ["Password updated."]
        assert sid in core.partyline.sessions
    run(main())


def test_audit_logs_never_contain_password(tmp_path, caplog):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        await chpass(core, "gowner", "ladmin")          # allowed
        await chpass(core, "ladmin", "ladmin2")         # denied: hierarchy
        await chpass(core, "ladmin", "gadmin")          # denied: scope
        await chpass(core, "plain1", "plain1b")         # denied: no +A
    with caplog.at_level(logging.INFO, logger="wbs"):
        run(main())
    text = caplog.text
    assert NEW_PW not in text
    assert "chpass: gowner changed password for ladmin" in text
    assert "chpass denied: ladmin -> ladmin2" in text
    assert "chpass denied: ladmin -> gadmin" in text
    assert "chpass denied: plain1 -> plain1b" in text


# ---------------------------------------------------------------------------
# end-to-end through the partyline dispatcher (+p gate, then hierarchy)
# ---------------------------------------------------------------------------
def test_partyline_dispatch_enforces_hierarchy(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        sid, q = open_session(core, "ladmin")
        await core.partyline.handle_input(sid, f".chpass ladmin2 {NEW_PW}")
        assert any("only an owner may change the password" in m for m in drain(q))
        assert not await changed(core.db_path, "ladmin2")
        await core.partyline.handle_input(sid, f".chpass plain1 {NEW_PW}")
        assert "Password updated for plain1." in drain(q)
        assert await password_is(core, "plain1", NEW_PW)

        osid, oq = open_session(core, "lowner")
        await core.partyline.handle_input(osid, f".chpass ladmin2 {NEW_PW}")
        assert "Password updated for ladmin2." in drain(oq)
    run(main())


# ---------------------------------------------------------------------------
# .fixpass is a bulk password reset and follows the same hierarchy
# ---------------------------------------------------------------------------
def test_fixpass_admin_skips_admin_accounts(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await cmd(core, "fixpass", "ladmin", "")
        assert out[0] == "Set random passwords for 1 user(s):"
        assert any(m.startswith("  nopwU: ") for m in out)
        assert not any(m.startswith("  nopwA: ") for m in out)
        assert any("Skipped 1 user(s)" in m and "nopwA" in m for m in out)
        assert await stored_hash(core.db_path, "nopwA") is None
        assert await stored_hash(core.db_path, "nopwU")
    run(main())


def test_fixpass_owner_sets_admin_accounts(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        out = await cmd(core, "fixpass", "lowner", "")
        assert out[0] == "Set random passwords for 2 user(s):"
        assert not any("Skipped" in m for m in out)
        assert await stored_hash(core.db_path, "nopwA")
        assert await stored_hash(core.db_path, "nopwU")
    run(main())


def test_fixpass_scope_limits_subnet_admin(tmp_path):
    async def main():
        db = await build_db(tmp_path)
        async with get_db(db) as d:          # a passwordless user on subnet 2
            await d.execute("UPDATE users SET password = NULL WHERE handle = 'plain2'")
            await d.commit()
        core = FakeCore(db)
        out = await cmd(core, "fixpass", "ladmin", "")
        assert any("Skipped" in m and "plain2" in m for m in out)
        assert await stored_hash(db, "plain2") is None
    run(main())


def test_fixpass_revokes_sessions_of_changed_users(tmp_path):
    async def main():
        core = FakeCore(await build_db(tmp_path))
        vsid, _vq = open_session(core, "nopwU")
        await cmd(core, "fixpass", "gowner", "")
        assert vsid not in core.partyline.sessions
    run(main())


# ---------------------------------------------------------------------------
# UserManager.privileged_scopes
# ---------------------------------------------------------------------------
def test_privileged_scopes(tmp_path):
    async def main():
        um = UserManager(await build_db(tmp_path))
        assert await um.privileged_scopes("gowner") == {None}
        assert await um.privileged_scopes("ladmin") == {1}
        assert await um.privileged_scopes("fadmin") == {2}
        assert await um.privileged_scopes("gA_ln") == {None, 1}
        assert await um.privileged_scopes("chanA") == {1}        # channel-row +A counts
        assert await um.privileged_scopes("lockedA") == {1}      # lock does not demote
        assert await um.privileged_scopes("plain1") == set()
        assert await um.privileged_scopes("nosuch") == set()
    run(main())
