"""
Offline regression tests for USR-1: the local foreground console session is the
operator and passes every flag check (first-admin bootstrap), while an ordinary
+p user is still refused by the same commands.

The console has no user row (handle `console`), so a matchattr() on its handle
can never succeed; the bypass lives in ONE place, helper._require_flag, keyed on
the session type (never on the handle string).  Side effects (restart, rehash,
backup copy, botnet link) are mocked; each DB is a throwaway sqlite file.
"""
import asyncio
import os
import shutil
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import pytest

from src import commands
from src.bot import BotManager
from src.db import get_db, init_db
from src.partyline import Partyline
from src.user import UserManager

_TEMPLATE_DB: str | None = None


async def _fresh_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-usr1-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


async def build_db(tmp_path) -> str:
    db = str(tmp_path / "wbs.db")
    await _fresh_db(db)
    async with get_db(db) as d:
        await d.execute("INSERT INTO subnets(id, name) VALUES (1, 'one')")
        for handle in ("plainp", "bob", "carol"):
            await d.execute("INSERT INTO users(handle, password, hostmasks) "
                            "VALUES (?, '$2b$12$x', '[]')", (handle,))
            await d.execute("INSERT INTO user_access (handle, channel, subnet_id, has_partyline) "
                            "VALUES (?, NULL, 1, 1)", (handle,))
        await d.execute("UPDATE users SET is_locked = 1 WHERE handle = 'carol'")
        await d.execute("INSERT INTO bots (handle, hostmasks, address, port) "
                        "VALUES ('peerbot', '[]', 'localhost', 3333)")
        await d.commit()
    return db


class FakeCore:
    def __init__(self, db: str, tmp_path):
        self.db_path = db
        self.config_path = str(tmp_path / "config.json")
        self.config = {"bot": {"nick": "beta"}, "botnet": {"subnet_id": 1}}
        self.user = UserManager(db)
        self.bot = BotManager(db)
        self.botname = "beta"
        self.connected = True
        # `.op someone #chan`: #chan is one of this bot's configured channels.
        self.chan = NS(getchans=AsyncMock(return_value=["#chan"]))
        self.irc_q = asyncio.Queue()
        self.party_sessions = {}
        self.copies: list = []
        self.do_restart = AsyncMock()
        self.do_rehash = AsyncMock()
        link = NS(writer=None, host="127.0.0.1", port=3333, connected=True)
        self.botnet = NS(peers={"peerbot": link}, connect_peer=AsyncMock(),
                         sync_user=AsyncMock(), remove_peer=MagicMock(),
                         broadcast_chat=AsyncMock())
        self.partyline = Partyline(self)


@pytest.fixture
def core(tmp_path, monkeypatch):
    db = asyncio.run(build_db(tmp_path))
    c = FakeCore(db, tmp_path)
    # cmd_backup copies with copyfile (not copy2) so backups stay 0600 (SYS-6).
    monkeypatch.setattr(commands.shutil, "copyfile", lambda src, dst: c.copies.append((src, dst)))
    return c


def console_sid(core):
    return core.partyline.register_console("console", lambda m: None)


def plain_sid(core):
    return core.partyline.register_remote("dcc", "plainp", asyncio.Queue())


async def run_cmd(core, name, handle, sid, arg=""):
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    await commands.COMMANDS[name](core, handle, sid, arg, respond)
    await asyncio.sleep(0)
    return out


async def db_value(core, sql, *params):
    async with get_db(core.db_path) as d:
        rows = await d.execute_fetchall(sql, params)
    return rows[0][0] if rows else None


def denied(out):
    return any("Access denied" in line for line in out)


# name, arg, substring proving the command ran, async "did it take effect" check
async def eff_restart(c):   return c.do_restart.await_count == 1
async def eff_rehash(c):    return c.do_rehash.await_count == 1
async def eff_backup(c):    return len(c.copies) == 2
async def eff_lock(c):      return await db_value(c, "SELECT is_locked FROM users WHERE handle='bob'") == 1
async def eff_unlock(c):    return await db_value(c, "SELECT is_locked FROM users WHERE handle='carol'") == 0
async def eff_comment(c):   return await db_value(c, "SELECT comment FROM users WHERE handle='bob'") == "hello"
async def eff_addaccess(c): return await db_value(
    c, "SELECT is_admin FROM user_access WHERE handle='bob' AND channel IS NULL AND subnet_id=1") == 1
async def eff_delaccess(c): return await db_value(
    c, "SELECT has_partyline FROM user_access WHERE handle='bob' AND channel IS NULL AND subnet_id=1") == 0
async def eff_link(c):      return c.botnet.connect_peer.await_count == 1
async def eff_unlink(c):    return c.botnet.remove_peer.call_count == 1
async def eff_chaddr(c):    return await db_value(c, "SELECT port FROM bots WHERE handle='peerbot'") == 4000
async def eff_op(c):        return not c.irc_q.empty()


CASES = [
    ("restart",       "",                          "Restarting",   eff_restart),
    ("rehash",        "",                          "Rehashing",    eff_rehash),
    ("backup",        "",                          "Backup complete", eff_backup),
    ("lockuser",      "bob",                       "has been locked", eff_lock),
    ("unlockuser",    "carol",                     "has been unlocked", eff_unlock),
    ("chusercomment", "bob hello",                 "omment",       eff_comment),
    ("addaccess",     "bob +A",                    "Added +A",     eff_addaccess),
    ("delaccess",     "bob -p",                    "Removed -p",   eff_delaccess),
    ("link",          "peerbot",                   "Initiating link", eff_link),
    ("unlink",        "peerbot",                   "Unlinked from", eff_unlink),
    ("chaddr",        "peerbot 127.0.0.1 4000",    "Updated peerbot", eff_chaddr),
    ("op",            "someone #chan",             None,           eff_op),
]
IDS = [c[0] for c in CASES]


@pytest.mark.parametrize("name,arg,ok_text,effect", CASES, ids=IDS)
def test_console_passes_flag_check(core, name, arg, ok_text, effect):
    async def go():
        out = await run_cmd(core, name, "console", console_sid(core), arg)
        assert not denied(out), out
        assert ok_text is None or any(ok_text in line for line in out), out
        assert await effect(core)
    asyncio.run(go())


@pytest.mark.parametrize("name,arg,ok_text,effect", CASES, ids=IDS)
def test_plain_partyline_user_still_denied(core, name, arg, ok_text, effect):
    async def go():
        out = await run_cmd(core, name, "plainp", plain_sid(core), arg)
        assert denied(out), out
        assert not await effect(core)
    asyncio.run(go())


def test_console_bypass_is_session_based_not_handle_based(core):
    """A remote session whose handle is spelled `console` gets no bypass."""
    async def go():
        sid = core.partyline.register_remote("dcc", "console", asyncio.Queue())
        out = await run_cmd(core, "backup", "console", sid)
        assert denied(out), out
        assert core.copies == []
        # session_id omitted (e.g. IRC-fallback caller) never counts as console
        out = await run_cmd(core, "backup", "console", None)
        assert denied(out), out
    asyncio.run(go())


def test_console_creates_first_admin_flow(core):
    """README first-user flow: console grants +A, that user can then back up."""
    async def go():
        sid = console_sid(core)
        bob_sid = core.partyline.register_remote("dcc", "bob", asyncio.Queue())
        assert denied(await run_cmd(core, "backup", "bob", bob_sid))
        out = await run_cmd(core, "addaccess", "console", sid, "bob +A")
        assert not denied(out), out
        out = await run_cmd(core, "backup", "bob", bob_sid)
        assert not denied(out), out
        assert len(core.copies) == 2
    asyncio.run(go())
