"""
Regression tests for PLG-7 / PLG-8 / PLG-8b: the IRC events plugins consume.

PLG-7   seen read `uhost`, PART/QUIT `message` and KICK `kicked_uhost`, which
        the IRC layer never sent: hostmask was always '' and part/quit/kick
        reasons were never stored.  Every user event now carries `nick`,
        `host` (nick!user@host) and `uhost` (user@host); the reason is
        `reason` everywhere; Core adds `kicked_uhost` to KICK.
PLG-8   no ACTION event (/me counted as 0 actions) and no OP/DEOP/VOICE/
        DEVOICE/HALFOP/DEHALFOP/BAN/UNBAN events (counters always 0); the bot
        and the server became rows in !topstats.
PLG-8b  topiclock never restored the topic: a live change arrives as TOPIC
        (no handler) and its restore payload ('TOPIC') was not a command the
        IRC process knows.

Raw server lines go through the real WbsIrcBot reactor and Core.handle_event
into the real seen/stats/topiclock plugins (throwaway sqlite DB).
"""
import asyncio
import queue

import pytest

from src import commands
from src import plugins as plugin_mod
from src.db import get_db
from src.partyline import COMMAND_MIN_FLAGS

from test_irc_channel_sync import BOT, SRV, JOIN_BURST, WHO_BURST, env  # noqa: F401


@pytest.fixture(autouse=True)
def clean_registry():
    yield
    for name in list(plugin_mod.PLUGIN_COMMANDS):
        commands.COMMANDS.pop(name, None)
        COMMAND_MIN_FLAGS.pop(name, None)
    plugin_mod.PLUGIN_COMMANDS.clear()


async def feed(core, irc, *lines) -> list[dict]:
    """Raw lines -> IRC reactor -> emitted events -> Core.handle_event."""
    events = []
    for line in lines:
        irc.connection._process_line(line)
        while True:
            try:
                events.append(irc.core_q.get_nowait())
            except queue.Empty:
                break
    for ev in events:
        await core.handle_event(ev)
    return events


def run(core, irc, sent, body, plugins=("seen", "stats", "topiclock")):
    """Join #wbs (synced, bot opped), load the plugins, then run body()."""
    core.handlers["TOPIC"] = core.on_topic

    async def go():
        core.connected = True
        await feed(core, irc, *JOIN_BURST, *WHO_BURST,
                   f":op!~op@op.example MODE #wbs +o {BOT}")
        for name in plugins:
            await core.plugin.load_plugin(name)
        core.irc_q.items.clear()
        sent.clear()
        return await body()
    return asyncio.run(go())


async def seen_row(core, nick):
    async with get_db(core.db_path) as db:
        async with db.execute("SELECT * FROM seen WHERE nick = ? COLLATE NOCASE",
                              (nick,)) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def stats_rows(core, table="stats_nick"):
    async with get_db(core.db_path) as db:
        rows = await db.execute_fetchall(f"SELECT * FROM {table}")
    return {r["nick"]: dict(r) for r in rows}


# ---------------------------------------------------------------------------
# PLG-7: event fields + seen
# ---------------------------------------------------------------------------
def test_user_events_carry_uhost_and_reason(env):
    core, irc, sent = env

    async def body():
        evs = await feed(core, irc,
                         ":alice!~al@a.example JOIN #wbs",
                         ":alice!~al@a.example PRIVMSG #wbs :hi",
                         ":alice!~al@a.example PART #wbs :bye bye now",
                         ":bob!~bo@b.example QUIT :gone fishing",
                         f":op!~op@op.example KICK #wbs plain1 :out")
        return {e["type"]: e for e in evs}
    by = run(core, irc, sent, body, plugins=())
    assert by["JOIN"]["uhost"] == "~al@a.example"
    assert by["JOIN"]["host"] == "alice!~al@a.example"
    assert by["PUBMSG"]["uhost"] == "~al@a.example"
    assert by["PART"]["uhost"] == "~al@a.example" and by["PART"]["reason"] == "bye bye now"
    assert by["QUIT"]["uhost"] == "~bo@b.example" and by["QUIT"]["reason"] == "gone fishing"
    assert by["KICK"]["uhost"] == "~op@op.example" and by["KICK"]["kicked"] == "plain1"
    # Core adds the victim's user@host from the live member list (WHO).
    assert by["KICK"]["kicked_uhost"] == "~p1@p.example"


def test_seen_stores_hostmask_and_part_quit_kick_reasons(env):
    core, irc, sent = env

    async def body():
        await feed(core, irc,
                   ":alice!~al@a.example JOIN #wbs",
                   ":alice!~al@a.example PART #wbs :bye bye now",
                   f":carol!~ca@c.example JOIN #wbs",
                   ":carol!~ca@c.example QUIT :lost in the netsplit",
                   ":op!~op@op.example KICK #wbs plain1 :behave")
        seen = core.plugin.plugins["seen"]
        return ([await seen_row(core, n) for n in ("alice", "carol", "plain1")],
                await seen._query_seen("alice"))
    (alice, carol, plain1), reply = run(core, irc, sent, body)
    assert alice["hostmask"] == "~al@a.example"
    assert alice["action"] == "parted #wbs (bye bye now)"
    assert carol["hostmask"] == "~ca@c.example"
    assert carol["action"] == "quit (lost in the netsplit)"
    assert carol["channel"] == "#wbs"         # resolved from Core's live channels
    assert plain1["hostmask"] == "~p1@p.example"
    assert plain1["action"] == "was kicked from #wbs by op (behave)"
    assert "(~al@a.example)" in reply and 'stating "bye bye now"' in reply


# ---------------------------------------------------------------------------
# PLG-8: ACTION, mode events, stats
# ---------------------------------------------------------------------------
def test_action_event_emitted_and_counted(env):
    core, irc, sent = env

    async def body():
        evs = await feed(core, irc,
                         ":alice!~al@a.example JOIN #wbs",
                         ":alice!~al@a.example PRIVMSG #wbs :\x01ACTION does a thing\x01",
                         ":alice!~al@a.example PRIVMSG #wbs :plain line")
        return evs, await stats_rows(core), await stats_rows(core, "stats_nick_channel")
    evs, glob, chan = run(core, irc, sent, body)
    action = [e for e in evs if e["type"] == "ACTION"]
    assert len(action) == 1
    assert action[0]["text"] == "does a thing" and action[0]["channel"] == "#wbs"
    assert action[0]["nick"] == "alice" and action[0]["uhost"] == "~al@a.example"
    assert glob["alice"]["actions"] == 1 and glob["alice"]["messages"] == 1
    assert chan["alice"]["actions"] == 1


def test_mode_emits_op_voice_ban_events_with_setter_and_target(env):
    core, irc, sent = env

    async def body():
        return await feed(core, irc,
                          ":op!~op@op.example MODE #wbs +ovb-h plain1 plain2 *!*@bad.example half",
                          ":op!~op@op.example MODE #wbs -o-v-b+h plain1 plain2 *!*@bad.example half")
    evs = run(core, irc, sent, body, plugins=())
    got = [(e["type"], e["nick"], e["target"]) for e in evs if e["type"] != "MODE"]
    assert got == [
        ("OP", "op", "plain1"), ("VOICE", "op", "plain2"), ("BAN", "op", "*!*@bad.example"),
        ("DEHALFOP", "op", "half"),
        ("DEOP", "op", "plain1"), ("DEVOICE", "op", "plain2"),
        ("UNBAN", "op", "*!*@bad.example"), ("HALFOP", "op", "half"),
    ]
    ban = next(e for e in evs if e["type"] == "BAN")
    assert ban["mask"] == "*!*@bad.example" and ban["uhost"] == "~op@op.example"
    assert ban["channel"] == "#wbs"


def test_stats_counts_op_deop_voice_ban_unban_halfop(env):
    core, irc, sent = env

    async def body():
        await feed(core, irc,
                   ":op!~op@op.example MODE #wbs +ov plain1 plain2",
                   ":op!~op@op.example MODE #wbs -o+b plain1 *!*@bad.example",
                   ":op!~op@op.example MODE #wbs -b+h-v *!*@bad.example plain1 plain2",
                   ":op!~op@op.example MODE #wbs -h plain1")
        return await stats_rows(core), await stats_rows(core, "stats_nick_channel")
    glob, chan = run(core, irc, sent, body)
    want = {"ops_given": 1, "deops_given": 1, "voices_given": 1, "devoices_given": 1,
            "bans_given": 1, "unbans_given": 1, "halfops_given": 1, "dehalfops_given": 1}
    assert {k: glob["op"][k] for k in want} == want
    assert {k: chan["op"][k] for k in want} == want


def test_stats_excludes_bot_and_server(env):
    core, irc, sent = env

    async def body():
        await feed(core, irc,
                   f":{BOT}!~wbs@bot.example PRIVMSG #wbs :bot talking",
                   f":{BOT}!~wbs@bot.example MODE #wbs +v plain1",
                   f":{BOT}!~wbs@bot.example KICK #wbs plain2 :bye",
                   f"{SRV} MODE #wbs +o plain1",
                   f"{SRV} MODE #wbs +nt",
                   f"{SRV} TOPIC #wbs :server topic",
                   ":alice!~al@a.example PRIVMSG #wbs :hello")
        stats = core.plugin.plugins["stats"]
        return (await stats_rows(core), await stats_rows(core, "stats_nick_channel"),
                await stats.get_top_nicks(channel="#wbs", limit=10))
    glob, chan, top = run(core, irc, sent, body)
    assert set(glob) == {"alice"}, glob
    assert set(chan) == {"alice"}, chan
    assert [r["nick"] for r in top] == ["alice"]


# ---------------------------------------------------------------------------
# PLG-8b: topiclock
# ---------------------------------------------------------------------------
async def lock(core, topic="LOCKED TOPIC", chan="#wbs"):
    async with get_db(core.db_path) as db:
        await db.execute("INSERT OR REPLACE INTO topiclock(channel, enabled, topic) "
                         "VALUES (?, 1, ?)", (chan, topic))
        await db.commit()


def flush(core, irc, sent) -> list[str]:
    sent.clear()
    for p in core.irc_q.items:
        irc.execute_command(p)
    core.irc_q.items.clear()
    return list(sent)


def test_topiclock_reverts_user_change_once_without_loop(env):
    core, irc, sent = env

    async def body():
        await lock(core)
        await feed(core, irc, ":plain1!~p1@p.example TOPIC #wbs :hacked by pown")
        first = flush(core, irc, sent)
        # The server echoes the bot's own restore: no second restore, no notice.
        await feed(core, irc, f":{BOT}!~wbs@bot.example TOPIC #wbs :LOCKED TOPIC")
        second = flush(core, irc, sent)
        return first, second
    first, second = run(core, irc, sent, body)
    topics = [l for l in first if l.startswith("TOPIC")]
    assert topics == ["TOPIC #wbs :LOCKED TOPIC"], first
    assert any(l.startswith("PRIVMSG plain1 :[topiclock]") or
               l.startswith("NOTICE plain1 :[topiclock]") for l in first), first
    assert second == []
    assert core.get_chan("#wbs").topic == "LOCKED TOPIC"


def test_topiclock_also_ignores_bot_change_to_other_topic(env):
    core, irc, sent = env

    async def body():
        await lock(core)
        await feed(core, irc, f":{BOT}!~wbs@bot.example TOPIC #wbs :bot set this")
        return flush(core, irc, sent)
    assert run(core, irc, sent, body) == []


def test_topiclock_ignores_owner_admin_change(env):
    core, irc, sent = env

    async def body():
        await lock(core)
        # boss: hostmask *!*boss@boss.example, owner + admin (test_irc_channel_sync)
        await feed(core, irc, ":boss!~boss@boss.example JOIN #wbs",
                   ":boss!~boss@boss.example TOPIC #wbs :new official topic")
        return flush(core, irc, sent)
    assert [l for l in run(core, irc, sent, body) if "TOPIC" in l or "topiclock" in l] == []


def test_topiclock_applies_locked_topic_on_join(env):
    core, irc, sent = env

    async def body():
        await core.plugin.load_plugin("topiclock")
        await lock(core)
        core.connected = True
        core.handlers["TOPIC"] = core.on_topic
        await feed(core, irc, *JOIN_BURST)          # 332 "welcome to wbs"
        out = [l for l in flush(core, irc, sent) if l.startswith("TOPIC")]
        # Same lock already in place: nothing to do.
        await feed(core, irc, f"{SRV} 332 {BOT} #wbs :LOCKED TOPIC")
        again = [l for l in flush(core, irc, sent) if l.startswith("TOPIC")]
        # 331: no topic at all -> apply the lock.
        await feed(core, irc, f"{SRV} 331 {BOT} #wbs :No topic is set.")
        notopic = [l for l in flush(core, irc, sent) if l.startswith("TOPIC")]
        return out, again, notopic
    out, again, notopic = asyncio.run(body())
    assert out == ["TOPIC #wbs :LOCKED TOPIC"]
    assert again == []
    assert notopic == ["TOPIC #wbs :LOCKED TOPIC"]


def test_topic_command_strips_line_breaks(env):
    core, irc, sent = env
    sent.clear()
    irc.execute_command({"cmd": "topic", "channel": "#wbs", "topic": "a\r\nQUIT :x"})
    assert sent == ["TOPIC #wbs :a QUIT :x"]
