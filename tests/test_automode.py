"""
Regression tests for IRC-6 (auto-op / auto-voice / autokick / bitch were
stored and shown but never enforced) and IRC-14 (owner/admin imply op rights
for .op/.mode/... instead of needing an explicit +o).

Raw server lines go through the real WbsIrcBot reactor into the real Core
(helpers shared with test_irc_channel_sync); what the bot sends back is the
real IRC-side output of the payloads Core queued.  Throwaway sqlite DB per
test.
"""
import asyncio

import pytest

from src.commands import cmd_deop, cmd_devoice, cmd_mode, cmd_op, cmd_voice
from src.db import get_db
from src.plugins.pubcom import ROLE_CHANOP, pubcomPlugin

from test_irc_channel_sync import (BOT, SRV, build_db, make_core, make_irc,  # noqa: E402
                                   pump, run_cmd)

# handle -> (hostmask, global flag columns)
USERS = {
    "aop":   ("*!*aop@aop.example", {"has_partyline", "is_autoop"}),
    "vce":   ("*!*vce@vce.example", {"has_partyline", "is_voice"}),
    "kik":   ("*!*kik@kik.example", {"is_autokick"}),
    "oper":  ("*!*oper@oper.example", {"has_partyline", "is_op"}),
    "own":   ("*!*own@own.example", {"has_partyline", "is_owner"}),
    "adm":   ("*!*adm@adm.example", {"has_partyline", "is_admin"}),
    "pee":   ("*!*pee@pee.example", {"has_partyline"}),
    "nope":  ("*!*nope@nope.example", {"is_autoop", "is_deop"}),
}


@pytest.fixture
def env(tmp_path):
    db = str(tmp_path / "wbs.db")

    async def setup():
        await build_db(db)
        async with get_db(db) as d:
            for handle, (mask, cols) in USERS.items():
                await d.execute("INSERT INTO users(handle, hostmasks) VALUES (?, ?)",
                                (handle, f'["{mask}"]'))
                names = ["handle", "channel", "subnet_id", *sorted(cols)]
                await d.execute(
                    f"INSERT INTO user_access ({', '.join(names)}) "
                    f"VALUES ({', '.join('?' * len(names))})",
                    [handle, None, 1, *([1] * len(cols))])
            await d.commit()
    asyncio.run(setup())
    core = make_core(db)
    core.connected = True
    irc, sent = make_irc(db)
    return core, irc, sent


def set_chan(core, **cols):
    async def go():
        async with get_db(core.db_path) as d:
            for col, val in cols.items():
                await d.execute(f"UPDATE channels SET {col} = ? WHERE name = '#wbs'", (val,))
            await d.commit()
    asyncio.run(go())


def flush(core, irc, sent) -> list[str]:
    """Run Core's queued IRC payloads through the IRC process; raw lines out."""
    sent.clear()
    for p in core.irc_q.items:
        irc.execute_command(p)
    core.irc_q.items.clear()
    return list(sent)


def join_synced(core, irc, sent, bot_prefix="@", present=""):
    """The bot joins #wbs (op or not) and completes its WHO sync.  `present`
    are extra 'nick!ident@host' members already in the channel."""
    members = [m for m in present.split() if m]
    names = " ".join([f"{bot_prefix}{BOT}"] + [m.split("!")[0] for m in members])
    who = []
    for m in members:
        nick, _, uh = m.partition("!")
        ident, _, host = uh.partition("@")
        who.append(f"{SRV} 352 {BOT} #wbs {ident} {host} irc.example.net {nick} H :0 x")
    flag = "H@" if bot_prefix == "@" else "H"
    pump(core, irc,
         f":{BOT}!~wbs@bot.example JOIN #wbs",
         f"{SRV} 353 {BOT} = #wbs :{names}",
         f"{SRV} 366 {BOT} #wbs :End of /NAMES list.",
         f"{SRV} 352 {BOT} #wbs ~wbs bot.example irc.example.net {BOT} {flag} :0 bot",
         *who,
         f"{SRV} 315 {BOT} #wbs :End of /WHO list.")
    assert core.get_chan("#wbs").synced
    return flush(core, irc, sent)


def joins(core, irc, sent, *who) -> list[str]:
    flush(core, irc, sent)
    pump(core, irc, *[f":{w} JOIN #wbs" for w in who])
    return flush(core, irc, sent)


# ---------------------------------------------------------------------------
# IRC-6: on join
# ---------------------------------------------------------------------------
def test_join_autoop_autovoice_autokick(env):
    core, irc, sent = env
    set_chan(core, is_autovoice=1)
    join_synced(core, irc, sent)
    assert joins(core, irc, sent, "aop!~aop@aop.example") == ["MODE #wbs +o aop"]
    assert joins(core, irc, sent, "vce!~vce@vce.example") == ["MODE #wbs +v vce"]
    assert joins(core, irc, sent, "kik!~kik@kik.example") == ["KICK #wbs kik :Autokick"]
    # Strangers, plain users, +o without channel autoop, +a with +d: nothing.
    assert joins(core, irc, sent, "rando!~r@stranger.example",
                 "pee!~pee@pee.example", "oper!~oper@oper.example",
                 "nope!~nope@nope.example") == []


def test_autovoice_needs_channel_setting(env):
    core, irc, sent = env
    join_synced(core, irc, sent)
    assert joins(core, irc, sent, "vce!~vce@vce.example") == []


def test_channel_autoop_ops_users_with_op_rights_only(env):
    core, irc, sent = env
    set_chan(core, is_autoop=1)
    join_synced(core, irc, sent)
    out = joins(core, irc, sent, "oper!~oper@oper.example", "own!~own@own.example",
                "adm!~adm@adm.example", "pee!~pee@pee.example",
                "rando!~r@stranger.example", "vce!~vce@vce.example")
    assert out == ["MODE #wbs +o oper", "MODE #wbs +o own", "MODE #wbs +o adm"], out


def test_channel_access_row_counts(env):
    """A channel row's +a applies on that channel only."""
    core, irc, sent = env

    async def grant():
        async with get_db(core.db_path) as d:
            await d.execute("INSERT INTO user_access(handle, channel, subnet_id, is_autoop) "
                            "VALUES ('pee', '#wbs', 1, 1)")
            await d.commit()
    asyncio.run(grant())
    join_synced(core, irc, sent)
    assert joins(core, irc, sent, "pee!~pee@pee.example") == ["MODE #wbs +o pee"]


def test_no_modes_when_bot_not_opped(env):
    core, irc, sent = env
    set_chan(core, is_autovoice=1, is_autoop=1)
    assert join_synced(core, irc, sent, bot_prefix="") == []
    assert joins(core, irc, sent, "aop!~aop@aop.example", "vce!~vce@vce.example",
                 "kik!~kik@kik.example") == []


def test_enforcebans_bans_before_autokick(env):
    core, irc, sent = env
    set_chan(core, is_enforcebans=1)
    join_synced(core, irc, sent)
    assert joins(core, irc, sent, "kik!~kik@kik.example") == [
        "MODE #wbs +b *!*@kik.example", "KICK #wbs kik :Autokick"]


def test_inactive_channel_is_left_alone(env):
    core, irc, sent = env
    set_chan(core, is_inactive=1)
    join_synced(core, irc, sent)
    assert joins(core, irc, sent, "aop!~aop@aop.example", "kik!~kik@kik.example") == []


# ---------------------------------------------------------------------------
# IRC-6: users already present (bot restart / reconnect / getting op)
# ---------------------------------------------------------------------------
PRESENT = ("aop!~aop@aop.example vce!~vce@vce.example kik!~kik@kik.example "
           "rando!~r@stranger.example pee!~pee@pee.example")


def test_sync_after_bot_join_enforces_for_present_users(env):
    core, irc, sent = env
    set_chan(core, is_autovoice=1)
    out = join_synced(core, irc, sent, present=PRESENT)
    assert sorted(out) == sorted(["KICK #wbs kik :Autokick", "MODE #wbs +o aop",
                                  "MODE #wbs +v vce"]), out
    # A second WHO end (e.g. a manual resync request) does not repeat it.
    pump(core, irc, f"{SRV} 315 {BOT} #wbs :End of /WHO list.")
    assert flush(core, irc, sent) == []


def test_restart_sync_new_core(env):
    """A new Core (relaunch / .rehash) gets the state from the IRC process
    and enforces once the resync completes."""
    core, irc, sent = env
    set_chan(core, is_autovoice=1)
    join_synced(core, irc, sent, present=PRESENT)
    pump(core, irc, ":kik!~kik@kik.example PART #wbs")   # kicked earlier

    fresh = make_core(core.db_path)
    irc.execute_command({"cmd": "state"})
    sent.clear()
    pump(fresh, irc)                                      # IRC_STATE
    pump(fresh, irc,
         f"{SRV} 353 {BOT} = #wbs :@{BOT} aop vce rando pee",
         f"{SRV} 366 {BOT} #wbs :End of /NAMES list.",
         f"{SRV} 352 {BOT} #wbs ~wbs bot.example irc.example.net {BOT} H@ :0 b",
         f"{SRV} 352 {BOT} #wbs ~aop aop.example irc.example.net aop H :0 a",
         f"{SRV} 352 {BOT} #wbs ~vce vce.example irc.example.net vce H :0 v",
         f"{SRV} 352 {BOT} #wbs ~r stranger.example irc.example.net rando H :0 r",
         f"{SRV} 352 {BOT} #wbs ~pee pee.example irc.example.net pee H :0 p",
         f"{SRV} 315 {BOT} #wbs :End of /WHO list.")
    assert sorted(flush(fresh, irc, sent)) == ["MODE #wbs +o aop", "MODE #wbs +v vce"]


def test_reconnect_resync_enforces(env):
    core, irc, sent = env
    join_synced(core, irc, sent)
    asyncio.run(core.handle_event({"type": "DISCONNECT"}))
    pump(core, irc, f"{SRV} 001 {BOT} :Welcome")
    out = join_synced(core, irc, sent, present="aop!~aop@aop.example")
    assert out == ["MODE #wbs +o aop"], out


def test_bot_getting_op_enforces_for_present_users(env):
    core, irc, sent = env
    set_chan(core, is_autovoice=1)
    assert join_synced(core, irc, sent, bot_prefix="", present=PRESENT) == []
    pump(core, irc, f":ChanServ!s@services. MODE #wbs +o {BOT}")
    out = flush(core, irc, sent)
    assert sorted(out) == sorted(["KICK #wbs kik :Autokick", "MODE #wbs +o aop",
                                  "MODE #wbs +v vce"]), out


def test_already_opped_or_voiced_untouched(env):
    core, irc, sent = env
    set_chan(core, is_autovoice=1)
    join_synced(core, irc, sent, bot_prefix="",
                present="aop!~aop@aop.example vce!~vce@vce.example")
    pump(core, irc, ":x!~x@x.example MODE #wbs +ov aop vce")
    flush(core, irc, sent)
    pump(core, irc, f":x!~x@x.example MODE #wbs +o {BOT}")   # sweep runs now
    assert flush(core, irc, sent) == []


# ---------------------------------------------------------------------------
# IRC-6: +bitch
# ---------------------------------------------------------------------------
def test_bitch_deops_unentitled(env):
    core, irc, sent = env
    set_chan(core, is_bitch=1)
    join_synced(core, irc, sent, present="rando!~r@stranger.example "
                                         "oper!~oper@oper.example pee!~pee@pee.example "
                                         "own!~own@own.example")
    pump(core, irc, ":rando!~r@stranger.example MODE #wbs +ooo pee oper own")
    assert flush(core, irc, sent) == ["MODE #wbs -o pee"]
    # Without bitch, nothing.
    set_chan(core, is_bitch=0)
    pump(core, irc, ":rando!~r@stranger.example MODE #wbs +o rando")
    assert flush(core, irc, sent) == []


# ---------------------------------------------------------------------------
# IRC-14: owner/admin imply op rights
# ---------------------------------------------------------------------------
OP_CMDS = [(cmd_op, "x #wbs", "MODE #wbs +o x"), (cmd_deop, "x #wbs", "MODE #wbs -o x"),
           (cmd_voice, "x #wbs", "MODE #wbs +v x"), (cmd_devoice, "x #wbs", "MODE #wbs -v x"),
           (cmd_mode, "#wbs +m", "MODE #wbs +m")]


@pytest.mark.parametrize("handle", ["own", "adm", "oper"])
@pytest.mark.parametrize("func,arg,line", OP_CMDS)
def test_owner_admin_op_can_use_op_commands(env, handle, func, arg, line):
    core, irc, sent = env
    run_cmd(core, func, arg, handle=handle)
    assert flush(core, irc, sent) == [line]


@pytest.mark.parametrize("handle", ["pee", "aop", "vce"])
@pytest.mark.parametrize("func,arg,line", OP_CMDS)
def test_plain_user_cannot_use_op_commands(env, handle, func, arg, line):
    core, irc, sent = env
    out = run_cmd(core, func, arg, handle=handle)
    assert out == ["Access denied (need +o, or +A/+n)."]
    assert flush(core, irc, sent) == []


@pytest.mark.parametrize("handle,ok", [("own", True), ("adm", True), ("oper", True),
                                       ("pee", False)])
def test_partyline_gate_op_for_owner_admin(env, handle, ok):
    core, irc, sent = env
    out: list[str] = []
    sid = 7
    core.partyline.sessions[sid] = {"type": "telnet", "handle": handle}
    core.partyline.send_to_session = lambda s, msg: out.append(msg)
    asyncio.run(core.partyline._handle_command(sid, handle, ".op x #wbs"))
    if ok:
        assert flush(core, irc, sent) == ["MODE #wbs +o x"], out
    else:
        assert out == ["Access denied for .op (need +o)."]
        assert flush(core, irc, sent) == []


@pytest.mark.parametrize("handle,ok", [("own", True), ("adm", True), ("pee", False)])
def test_pubcom_chanop_role_for_owner_admin(env, handle, ok):
    core, _, _ = env
    plugin = pubcomPlugin(core)
    assert asyncio.run(plugin.authorize(handle, ROLE_CHANOP, "#wbs")) is ok
