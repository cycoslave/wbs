"""DCC-1 regression: .+host / .-host must await UserManager.get and persist."""
import asyncio
import warnings

from src import commands
from src.user import UserManager

from tests.test_user_scope import FakeCore, build_db


def _run_cmd(core, name, caller, arg):
    out = []

    async def respond(msg):
        out.append(msg)

    asyncio.run(commands.COMMANDS[name](core, caller, None, arg, respond))
    return out


def test_addhost_delhost_persist(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    core = FakeCore(db)
    mask = "*!*x@*"

    async def masks():
        return list((await UserManager(db).get("plain1")).hostmasks)

    assert asyncio.run(masks()) == []
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        assert _run_cmd(core, "+host", "plain1", mask) == [f"Added host: {mask}"]
        assert asyncio.run(masks()) == [mask]
        assert _run_cmd(core, "+host", "plain1", mask) == [f"Host already exists: {mask}"]
        assert _run_cmd(core, "-host", "plain1", mask) == [f"Removed host: {mask}"]
        assert asyncio.run(masks()) == []
        assert _run_cmd(core, "-host", "plain1", mask) == [f"Host not found: {mask}"]


def test_host_unknown_user_and_bad_mask(tmp_path):
    db = asyncio.run(build_db(tmp_path))
    core = FakeCore(db)
    assert _run_cmd(core, "+host", "nobody", "*!*x@*") == ["User not found."]
    assert _run_cmd(core, "+host", "plain1", "nomask")[0].startswith("Invalid hostmask")
