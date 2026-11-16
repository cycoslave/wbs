"""
Live O-2: bot handles are case-insensitive.

`.+bot wbstestB ...` stores the handle lowercased; `.botattr wbstestB` used to
answer "Bot not found" because the lookup compared case-sensitively.  Every
bot-handle lookup must match whatever case the operator types.

Real command handlers + BotManager on a throwaway sqlite file, console session.
"""
import asyncio
import os
import shutil
import tempfile
from types import SimpleNamespace as NS

import pytest

from src import commands
from src.bot import BotManager
from src.db import get_db, init_db

CONSOLE_SID = 1
_TEMPLATE_DB: str | None = None


async def _fresh_db(path: str) -> None:
    global _TEMPLATE_DB
    if _TEMPLATE_DB is None:
        tpl = os.path.join(tempfile.mkdtemp(prefix="wbs-o2-"), "template.db")
        await init_db(tpl)
        _TEMPLATE_DB = tpl
    shutil.copyfile(_TEMPLATE_DB, path)


class Linked:
    def __init__(self):
        self.connected: list[str] = []
        self.unlinked: list[str] = []
        self.peers: dict = {}

    async def sync_bot_access(self, *a, **k):
        pass

    async def connect_peer(self, handle):
        self.connected.append(handle)

    async def unlink_peer(self, handle, reason=""):
        self.unlinked.append(handle)
        return False


async def make_core(tmp_path):
    db = str(tmp_path / "o2.db")
    await _fresh_db(db)
    core = NS(
        db_path=db,
        config={"bot": {"nick": "alpha"}, "settings": {"ssl": False}},
        botname="alpha",
        bot_sessions={},
        send_irc=lambda *a, **k: None,
        partyline=NS(broadcast=lambda *a, **k: None,
                     sessions={CONSOLE_SID: {"type": "console", "handle": "console"}}),
        botnet=Linked(),
    )
    core.bot = BotManager(db)
    return core


async def run_cmd(core, name: str, arg: str) -> list[str]:
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    await commands.COMMANDS[name](core, "console", CONSOLE_SID, arg, respond)
    for _ in range(3):  # let fire-and-forget sync tasks finish
        rest = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
        if not rest:
            break
        await asyncio.wait(rest, timeout=5)
    return out


async def count_bots(core) -> int:
    async with get_db(core.db_path) as d:
        cur = await d.execute("SELECT COUNT(*) AS n FROM bots WHERE handle != 'alpha'")
        return (await cur.fetchone())["n"]


def joined(out):
    return "\n".join(out)


def test_add_then_botattr_any_case(tmp_path):
    async def go():
        core = await make_core(tmp_path)
        out = await run_cmd(core, "+bot", "MixedCase *!bot@host.example 192.0.2.5 3333")
        assert "added" in joined(out), out
        for typed in ("MixedCase", "mixedcase", "MIXEDCASE"):
            out = await run_cmd(core, "botattr", typed)
            assert "not found" not in joined(out).lower(), (typed, out)
        # modify through a different case than the one used to add it
        out = await run_cmd(core, "botattr", "MIXEDCASE comment=hello")
        assert "not found" not in joined(out).lower(), out
        async with get_db(core.db_path) as d:
            cur = await d.execute("SELECT comment FROM bots WHERE LOWER(handle) = 'mixedcase'")
            assert (await cur.fetchone())["comment"] == "hello"
    asyncio.run(go())


def test_delbot_any_case(tmp_path):
    async def go():
        core = await make_core(tmp_path)
        await run_cmd(core, "+bot", "MixedCase *!bot@host.example 192.0.2.5 3333")
        before = await count_bots(core)
        out = await run_cmd(core, "-bot", "MIXEDCASE")
        assert "NOT deleted" not in joined(out), out
        assert "deleted" in joined(out), out
        assert await count_bots(core) == before - 1
        out = await run_cmd(core, "botattr", "mixedcase")
        assert "not found" in joined(out).lower()
    asyncio.run(go())


def test_duplicate_add_differing_case_refused(tmp_path):
    async def go():
        core = await make_core(tmp_path)
        await run_cmd(core, "+bot", "MixedCase *!bot@host.example 192.0.2.5 3333")
        before = await count_bots(core)
        out = await run_cmd(core, "+bot", "MIXEDcase *!bot@host.example 192.0.2.5 3333")
        assert "already exists" in joined(out), out
        assert await count_bots(core) == before
    asyncio.run(go())


def test_link_and_chaddr_any_case(tmp_path):
    async def go():
        core = await make_core(tmp_path)
        await run_cmd(core, "+bot", "MixedCase *!bot@host.example 192.0.2.5 3333")
        out = await run_cmd(core, "link", "MIXEDCASE")
        assert "not found" not in joined(out).lower(), out
        assert core.botnet.connected, out
        out = await run_cmd(core, "chaddr", "MixedCase 192.0.2.9 4000")
        assert "not found" not in joined(out).lower(), out
        async with get_db(core.db_path) as d:
            cur = await d.execute("SELECT address, port FROM bots WHERE LOWER(handle) = 'mixedcase'")
            row = await cur.fetchone()
        assert (row["address"], row["port"]) == ("192.0.2.9", 4000)
    asyncio.run(go())


def test_botmanager_lookups_any_case(tmp_path):
    async def go():
        core = await make_core(tmp_path)
        await core.bot.addbot("MixedCase", "*!b@h.example", "192.0.2.5", 3333)
        assert await core.bot.exist("MIXEDCASE")
        bot = await core.bot.get("mIxEdCaSe")
        assert bot.handle == "mixedcase"
        assert await core.bot.set_password("MIXEDCASE", "secretkey123")
        await _subnet(core, 1)
        assert await core.bot.bind_to_subnet("MixedCase", 1)
        assert await core.bot.get_subnet_ids("MIXEDCASE") == [1]
        assert await core.bot.unbind_from_subnet("MIXEDCASE", 1)
        assert await core.bot.delbot("MIXEDCASE")
        assert not await core.bot.exist("mixedcase")
    asyncio.run(go())


async def _subnet(core, sid: int) -> None:
    async with get_db(core.db_path) as d:
        await d.execute("INSERT OR IGNORE INTO subnets(id, name) VALUES (?, ?)", (sid, f"net{sid}"))
        await d.commit()
