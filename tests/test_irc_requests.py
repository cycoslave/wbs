"""
Regression tests for IRC-5 (channel names were never validated), IRC-8 (.mode
/ .op / ... answered "done" for anything queued) and IRC-11 (.nick sent an
unchecked raw NICK; 432 was handled like 433, giving nicks such as 'wI157').

Raw server lines go through the real WbsIrcBot reactor into the real Core
(helpers shared with test_irc_channel_sync / test_automode).
"""
import asyncio

import pytest

from src.commands import (cmd_addchan, cmd_mode, cmd_nick, cmd_op,
                          cmd_voice)
from src.idrules import valid_channel, valid_nick, validate_mode_string
from src.ircreq import IrcRequests

from test_automode import env, flush, join_synced  # noqa: F401  (fixture)
from test_irc_channel_sync import BOT, SRV, pump

PRESENT = "x!~x@x.example"


def start(core, func, arg, handle="own"):
    """Run a command; replies land in the returned list, also later ones."""
    out: list[str] = []

    async def respond(msg):
        out.append(msg)
    asyncio.run(func(core, handle, 1, arg, respond))
    return out


# ---------------------------------------------------------------------------
# IRC-5: channel names
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["#wbs", "&local", "#a", "#" + "x" * 49, "#Ünï", "#a-b.c_d"])
def test_valid_channel_names(name):
    assert valid_channel(name)


@pytest.mark.parametrize("name", ["", "#", "wbs", "+wbs", "#a b", "#a,b", "#a\x07b",
                                  "#" + "x" * 50, "#a\nb", "#a\tb", None, 5])
def test_invalid_channel_names(name):
    assert not valid_channel(name)


def test_addchan_rejects_bad_names_and_case_duplicates(env):
    core, irc, sent = env
    for bad in ("nohash", "#a,#b", "#" + "x" * 60):
        out = start(core, cmd_addchan, bad)
        assert any("Invalid channel name" in l for l in out), (bad, out)
    assert core.irc_q.items == []
    out = start(core, cmd_addchan, "#WBS")
    assert any("already exists" in l for l in out), out
    out = start(core, cmd_addchan, "#New")
    assert any("added" in l for l in out), out
    assert {"cmd": "join", "channel": "#New"} in core.irc_q.items


def test_mode_on_unknown_channel_is_refused(env):
    core, irc, sent = env
    out = start(core, cmd_mode, "#nowhere +m")
    assert any("Unknown channel" in l for l in out), out
    out = start(core, cmd_mode, "nohash +m")
    assert any("Invalid channel name" in l for l in out), out
    assert flush(core, irc, sent) == []


# ---------------------------------------------------------------------------
# IRC-8: mode validation and real outcomes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("modes,ok", [
    ("+m", True), ("+o x", True), ("-o+v x y", True), ("+l 10", True), ("-l", True),
    ("+k key", True), ("+b *!*@h", True),
    ("m", False), ("+", False), ("+o", False), ("+l ten", False), ("+m extra", False),
    ("+o b@d", False), ("", False), ("+k", False),
])
def test_validate_mode_string(modes, ok):
    err, changes = validate_mode_string(modes)
    assert (err is None) is ok, (modes, err)


def test_mode_reports_the_servers_confirmation(env):
    core, irc, sent = env
    join_synced(core, irc, sent, present=PRESENT)
    out = start(core, cmd_op, "x #wbs")
    assert out == []                                   # nothing claimed yet
    assert flush(core, irc, sent) == ["MODE #wbs +o x"]
    pump(core, irc, f":{BOT}!~wbs@bot.example MODE #wbs +o x")
    assert out == ["Gave op to x on #wbs"]
    assert core.ircreq.pending == []


def test_mode_reports_server_refusal(env):
    core, irc, sent = env
    join_synced(core, irc, sent, bot_prefix="", present=PRESENT)
    out = start(core, cmd_op, "x #wbs")
    flush(core, irc, sent)
    pump(core, irc, f"{SRV} 482 {BOT} #wbs :You're not channel operator")
    assert len(out) == 1 and out[0].startswith("Could not op x on #wbs"), out
    assert "482" in out[0] and "not a channel operator" in out[0]
    assert core.ircreq.pending == []


def test_mode_refusal_goes_to_the_right_request(env):
    core, irc, sent = env
    join_synced(core, irc, sent, present=PRESENT + " y!~y@y.example")
    a = start(core, cmd_op, "x #wbs")
    b = start(core, cmd_voice, "y #wbs")
    flush(core, irc, sent)
    pump(core, irc, f"{SRV} 441 {BOT} y #wbs :They aren't on that channel")
    assert a == [] and len(b) == 1 and "y is not on #wbs" in b[0], (a, b)
    pump(core, irc, f":{BOT}!~wbs@bot.example MODE #wbs +o x")
    assert a == ["Gave op to x on #wbs"]


def test_unknown_mode_letter_reported(env):
    core, irc, sent = env
    join_synced(core, irc, sent)
    out = start(core, cmd_mode, "#wbs +Y")
    flush(core, irc, sent)
    pump(core, irc, f"{SRV} 472 {BOT} Y :is unknown mode char to me")
    assert len(out) == 1 and "does not know mode 'Y'" in out[0], out


def test_mode_without_answer_times_out(env):
    core, irc, sent = env
    join_synced(core, irc, sent, present=PRESENT)
    out = start(core, cmd_op, "x #wbs")
    asyncio.run(core.ircreq.expire(now=core.ircreq.pending[0].deadline - 1))
    assert out == []
    asyncio.run(core.ircreq.expire(now=core.ircreq.pending[0].deadline + 1))
    assert len(out) == 1 and "No confirmation" in out[0], out
    assert core.ircreq.pending == []


def test_partial_confirmation_is_not_success(env):
    core, irc, sent = env
    join_synced(core, irc, sent, present=PRESENT)
    out = start(core, cmd_mode, "#wbs +ov x x")
    flush(core, irc, sent)
    pump(core, irc, f":{BOT}!~wbs@bot.example MODE #wbs +o x")
    assert out == []
    asyncio.run(core.ircreq.expire(now=core.ircreq.pending[0].deadline + 1))
    assert len(out) == 1 and "only +o" in out[0], out


def test_someone_elses_mode_does_not_confirm(env):
    core, irc, sent = env
    join_synced(core, irc, sent, present=PRESENT)
    out = start(core, cmd_op, "x #wbs")
    pump(core, irc, ":rando!~r@stranger.example MODE #wbs +o x")
    assert out == [] and len(core.ircreq.pending) == 1


def test_op_checks_live_state_first(env):
    core, irc, sent = env
    join_synced(core, irc, sent, present=PRESENT)
    assert "not on #wbs" in start(core, cmd_op, "ghost #wbs")[0]
    pump(core, irc, f":{BOT}!~wbs@bot.example MODE #wbs +o x")        # not in pending: no-op
    pump(core, irc, ":rando!~r@stranger.example MODE #wbs +o x")
    assert "already opped" in start(core, cmd_op, "x #wbs")[0]
    assert "Invalid nick" in start(core, cmd_op, "b@d #wbs")[0]
    assert flush(core, irc, sent) == []


# ---------------------------------------------------------------------------
# IRC-11: .nick and the 432/433 numerics
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("nick", ["9lives", "-x", "a!b", "a\x07", "x" * 40, "ñ"])
def test_nick_rejects_bad_syntax_before_sending(env, nick):
    core, irc, sent = env
    out = start(core, cmd_nick, nick)
    assert out and "Invalid nick" in out[0], out
    assert core.irc_q.items == []
    assert not getattr(core, "ircreq", None) or core.ircreq.pending == []


def test_nick_change_is_confirmed_by_the_servers_echo(env):
    core, irc, sent = env
    out = start(core, cmd_nick, "newbot")
    assert out == []
    assert flush(core, irc, sent) == ["NICK newbot"]
    pump(core, irc, f":{BOT}!~wbs@bot.example NICK :newbot")
    assert out == ["Nick is now newbot"] and core.botname == "newbot"


def test_nick_in_use_keeps_the_current_nick_and_tells_the_caller(env):
    core, irc, sent = env
    irc._irc_ready = True
    out = start(core, cmd_nick, "taken")
    assert flush(core, irc, sent) == ["NICK taken"]
    pump(core, irc, f"{SRV} 433 {BOT} taken :Nickname is already in use.")
    assert flush(core, irc, sent) == []              # no 'taken42' retry
    assert len(out) == 1 and "already in use" in out[0], out
    assert core.botname == BOT


def test_nick_refused_by_server_432_is_not_retried_with_digits(env):
    core, irc, sent = env
    irc._irc_ready = True
    out = start(core, cmd_nick, "badnick")
    flush(core, irc, sent)
    pump(core, irc, f"{SRV} 432 {BOT} badnick :Erroneous Nickname")
    assert flush(core, irc, sent) == []
    assert sent == [] and len(out) == 1 and "refused" in out[0], out


def test_nick_longer_than_server_nicklen_is_refused_by_irc_process(env):
    core, irc, sent = env
    irc.server_caps._parsed["NICKLEN"] = 9
    out = start(core, cmd_nick, "abcdefghijkl")          # valid syntax, 12 > 9
    assert out == []
    pump_out = flush(core, irc, sent)
    assert pump_out == []                                # never sent to the server
    pump(core, irc)                                      # deliver the IRC process's answer
    assert len(out) == 1 and "NICKLEN=9" in out[0] and "abcdefghijkl" in out[0], out
    assert core.botname == BOT


def test_registration_432_is_cleaned_not_digit_suffixed():
    from test_irc_channel_sync import make_irc
    irc, sent = make_irc(":memory:")
    irc._irc_ready = False
    irc._nick_attempt = irc._nick_adjusted = "bad|nick!"
    irc.connection._process_line(f"{SRV} 432 * bad|nick! :Erroneous Nickname")
    assert sent == ["NICK bad|nick"], sent
    # unusable beyond repair: falls back to wbs + digits, and is bounded
    irc._nick_attempt = "!!!"
    sent.clear()
    irc.connection._process_line(f"{SRV} 432 * !!! :Erroneous Nickname")
    assert len(sent) == 1 and sent[0].startswith("NICK wbs") and len(sent[0]) == 10
    for _ in range(10):
        irc.connection._process_line(f"{SRV} 432 * !!! :Erroneous Nickname")
    assert len(sent) <= 1 + irc._NICK_ERR_LIMIT


def test_registration_433_still_appends_digits():
    from test_irc_channel_sync import make_irc
    irc, sent = make_irc(":memory:")
    irc._irc_ready = False
    irc._nick_attempt = irc._nick_adjusted = "wbs"
    irc.connection._process_line(f"{SRV} 433 * wbs :Nickname is already in use.")
    assert len(sent) == 1 and sent[0].startswith("NICK wbs") and len(sent[0]) == 10, sent


def test_nick_valid_helper():
    assert valid_nick("wbs[1]") and valid_nick("_x") and not valid_nick("1x")
    assert not valid_nick("abcdefghij", 9)


def test_requests_are_independent_of_a_dead_session():
    async def go():
        reqs = IrcRequests()

        async def dead(_msg):
            raise RuntimeError("session closed")
        reqs.add_mode("#c", [("+", "o", "x")], "op x on #c", "ok", dead)
        await reqs.on_mode("#c", [("+", "o", "x")])
        assert reqs.pending == []
    asyncio.run(go())
