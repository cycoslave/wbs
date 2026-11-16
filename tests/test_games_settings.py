"""
Regression tests for game settings and text accuracy (GAM-5, GAM-9, GAM-10, GAM-12).

GAM-5   `.gstart <game> channel <#c> k=v` was stored raw and ignored (the DB
        settings overwrote it); `!duckset` only applied after a restart;
        `!duckstatus` printed '~0m-0h' for sub-minute delays.
GAM-9   only the channel scope exists; `.gstart` and `.games` now say so.
GAM-10  help/prompt text named commands that do not exist (!cast, !reel,
        !fishing stop, !horsestop, !pull, !roulette stop).
GAM-12  `!roulettebet straight 17 10` was refused; notices must keep order.

Throwaway sqlite DB per test, real game modules, fake IRC (recorded payloads).
"""
import ast
import asyncio
import re
from pathlib import Path

import pytest

from src import commands
from src.core import Core
from src.db import init_db
from src.games import Game, GameManager, SUPPORTED_SCOPES
import src.games.duckhunt as duckhunt_mod
import src.games.roulette as roulette_mod

GAMES_DIR = Path(__file__).resolve().parent.parent / "src" / "games"
ALL_GAMES = (
    "blackjack", "duckhunt", "fishing", "horseracing", "lottery",
    "poker", "roulette", "russianroulette", "slots", "werewolf",
)
CHAN = "#games"


class FakeCore:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        self.sent: list[dict] = []
        self.config = {"games": []}
        self.ops: set[str] = {"op"}
        self.game = GameManager(self)

    def send_irc(self, payload):
        self.sent.append(payload)

    def nick_isop(self, nick, channel):
        return nick in self.ops

    def texts(self, target=None, cmd=None):
        return [p["text"] for p in self.sent
                if (target is None or p.get("target") == target)
                and (cmd is None or p.get("cmd") == cmd)]


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "games.db"
    run(init_db(str(path)))
    return path


@pytest.fixture(autouse=True)
def fast_saves(monkeypatch):
    monkeypatch.setattr(Game, "SAVE_DEBOUNCE", 0.01)


async def responses(coro_fn, core, arg):
    out: list[str] = []

    async def respond(msg):
        out.append(msg)

    await coro_fn(core, "admin", 1, arg, respond)
    return out


# --- GAM-5: start args -------------------------------------------------------

def test_gstart_args_override_stored_settings_for_the_session(db_path):
    async def scenario():
        core = FakeCore(db_path)
        # The stored settings (what used to overwrite the args).
        await core.game.load_game("duckhunt")
        out = await responses(commands.cmd_gstart, core,
                              f"duckhunt channel {CHAN} min_delay=5 max_delay=8 "
                              "duck_timeout=10 reload_time=0.5")
        session = core.game.games["duckhunt"].get_session("channel", CHAN)
        data = {k: session.data[k] for k in
                ("min_delay", "max_delay", "duck_timeout", "reload_time")}
        await core.game.unload_game("duckhunt")
        return out, data

    out, data = run(scenario())
    assert out[0].startswith("Started duckhunt"), out
    assert data == {"min_delay": 5, "max_delay": 8, "duck_timeout": 10,
                    "reload_time": 0.5}


def test_gstart_args_survive_a_restart(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("duckhunt", "channel", CHAN, owner="a",
                                   min_delay=5, max_delay=8)
        await core.game.games["duckhunt"].flush_sessions()
        # New manager = restart: the session is restored from game_sessions.
        core2 = FakeCore(db_path)
        await Core._autoload_games(core2)
        session = core2.game.games["duckhunt"].get_session("channel", CHAN)
        got = (session.data["min_delay"], session.data["max_delay"]) if session else None
        await core.game.unload_game("duckhunt")
        await core2.game.unload_game("duckhunt")
        return got

    assert run(scenario()) == (5, 8)


def test_unknown_start_key_is_refused_with_the_valid_list(db_path):
    async def scenario():
        core = FakeCore(db_path)
        out = await responses(commands.cmd_gstart, core,
                              f"duckhunt channel {CHAN} bogus=1")
        sessions = core.game.games["duckhunt"].sessions if "duckhunt" in core.game.games else {}
        return out, dict(sessions)

    out, sessions = run(scenario())
    assert out == [out[0]] and out[0].startswith("Failed to start duckhunt")
    assert "unknown setting bogus" in out[0]
    for key in ("min_delay", "max_delay", "duck_timeout", "reload_time"):
        assert key in out[0]
    assert not sessions


@pytest.mark.parametrize("arg, fragment", [
    ("min_delay=abc", "min_delay must be a number"),
    ("min_delay=0", "between"),
    ("min_delay=1.5", "whole number"),
    ("min_delay=90 max_delay=30", "must not be above"),
    ("reload_time=-1", "between"),
])
def test_bad_start_values_are_refused(db_path, arg, fragment):
    async def scenario():
        core = FakeCore(db_path)
        out = await responses(commands.cmd_gstart, core, f"duckhunt channel {CHAN} {arg}")
        game = core.game.games.get("duckhunt")
        return out, bool(game and game.sessions)

    out, started = run(scenario())
    assert out[0].startswith("Failed to start duckhunt"), out
    assert fragment in out[0]
    assert not started


def test_start_args_are_validated_per_game():
    for name in ALL_GAMES:
        game_cls = GameManager._game_class(name)
        assert isinstance(game_cls.SETTINGS, dict)
        with pytest.raises(ValueError, match="unknown setting"):
            game_cls.parse_start_args({"nope": 1})
        for key, (kind, lo, hi) in game_cls.SETTINGS.items():
            assert game_cls.parse_start_args({key: lo}) == {key: lo}
            with pytest.raises(ValueError):
                game_cls.parse_start_args({key: hi + 1})
            with pytest.raises(ValueError):
                game_cls.parse_start_args({key: "x"})
    # Settings that exist are really read: slots takes min_bet from the args.
    assert "min_bet" in GameManager._game_class("slots").SETTINGS


def test_start_args_reach_a_table_game(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("slots", "channel", CHAN, owner="a",
                                   min_bet=7, max_bet=70)
        session = core.game.games["slots"].get_session("channel", CHAN)
        cfg = dict(session.data["cfg"])
        await core.game.unload_game("slots")
        return cfg

    cfg = run(scenario())
    assert cfg["min_bet"] == 7 and cfg["max_bet"] == 70


# --- GAM-5: !duckset is live, status formatting -------------------------------

def test_duckset_applies_to_the_running_loop_at_once(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("duckhunt", "channel", CHAN, owner="a")
        game = core.game.games["duckhunt"]
        session = game.get_session("channel", CHAN)
        assert session.data["min_delay"] >= 180        # the default is slow
        spawned = asyncio.Event()

        async def fake_spawn(sess, probe=False):
            spawned.set()
        game._spawn_duck = fake_spawn

        for text in ("!duckset min_delay 1", "!duckset max_delay 1"):
            await game.on_PUBMSG(session, "op", text)
        # With the old code the loop slept 180-7200 s; now it re-draws.
        await asyncio.wait_for(spawned.wait(), timeout=10)
        shown = (session.data["min_delay"], session.data["max_delay"])
        await core.game.unload_game("duckhunt")
        return shown

    assert run(scenario()) == (1, 1)


def test_duckset_refuses_bad_values_with_a_notice(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("duckhunt", "channel", CHAN, owner="a")
        game = core.game.games["duckhunt"]
        session = game.get_session("channel", CHAN)
        before = session.data["min_delay"]
        for text in ("!duckset min_delay abc", "!duckset min_delay 0",
                     "!duckset max_delay 5", "!duckset nosuch 5"):
            await game.on_PUBMSG(session, "op", text)
        after = (session.data["min_delay"], session.data["max_delay"])
        notices = core.texts(cmd="notice")
        await core.game.unload_game("duckhunt")
        return before, after, notices

    before, after, notices = run(scenario())
    assert after[0] == before                       # nothing changed
    # abc, 0 and max_delay 5 (below min_delay) are refused; "nosuch" shows usage
    # in the channel instead of a notice.
    assert len(notices) == 3 and all("rejected" in n for n in notices)
    assert after[1] != 5


@pytest.mark.parametrize("secs, text", [
    (0, "0s"), (5, "5s"), (45, "45s"), (60, "1m"), (90, "1m30s"),
    (180, "3m"), (3600, "1h"), (7200, "2h"), (5400, "1h30m"),
])
def test_duck_status_time_format(secs, text):
    assert duckhunt_mod.DuckhuntGame._fmt_secs(secs) == text


def test_duckstatus_shows_sub_minute_delays(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("duckhunt", "channel", CHAN, owner="a",
                                   min_delay=5, max_delay=8)
        game = core.game.games["duckhunt"]
        session = game.get_session("channel", CHAN)
        core.sent.clear()
        await game.on_PUBMSG(session, "alice", "!duckstatus")
        out = core.texts(CHAN)
        await core.game.unload_game("duckhunt")
        return out

    out = run(scenario())
    assert any("5s–8s" in t for t in out), out
    assert not any("0m" in t for t in out)


# --- GAM-9: channel scope only ------------------------------------------------

def test_only_the_channel_scope_exists():
    assert SUPPORTED_SCOPES == ("channel",)
    for name in ALL_GAMES:
        assert GameManager._game_class(name).scopes == {"channel"}


@pytest.mark.parametrize("scope", ["user", "subnet", "botnet"])
def test_gstart_names_the_channel_only_rule(db_path, scope):
    async def scenario():
        core = FakeCore(db_path)
        return await responses(commands.cmd_gstart, core, f"slots {scope} someone")

    out = run(scenario())
    assert len(out) == 1
    assert "not supported" in out[0] and "channels only" in out[0]


def test_gstart_usage_and_help_and_games_say_channel_only(db_path):
    async def scenario():
        core = FakeCore(db_path)
        usage = await responses(commands.cmd_gstart, core, "")
        await core.game.load_game("slots")
        games = await responses(commands.cmd_games, core, "")
        await core.game.unload_game("slots")
        return usage, games

    usage, games = run(scenario())
    assert "channel" in usage[0] and "channels only" in usage[0]
    assert any("channels only" in line for line in games)
    src = Path(commands.__file__).read_text()
    assert "Only the \"channel\" scope exists" in src


# --- GAM-10: help / prompt text names real commands --------------------------

def _string_constants(tree):
    """(text, is_whole_literal_command) for every string in the module."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value


def _handled_commands(tree):
    """Commands the game compares against: string constants that are exactly
    a command word (`"!fishcast"`) anywhere in a comparison / membership /
    mapping (so tuples and sets of aliases count)."""
    handled = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            parts = [node.left, *node.comparators]
            for part in parts:
                for sub in ast.walk(part):
                    if (isinstance(sub, ast.Constant) and isinstance(sub.value, str)
                            and re.fullmatch(r"![a-z]+", sub.value)):
                        handled.add(sub.value)
        elif isinstance(node, ast.Dict):
            for key in node.keys:
                if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                        and re.fullmatch(r"![a-z]+", key.value)):
                    handled.add(key.value)
    return handled


# `!game stop` style is handled by the first word; these are the word pairs
# a game answers.  Anything else mentioned must be a real command.
def _mentioned(tree):
    out = set()
    for text in _string_constants(tree):
        for m in re.finditer(r"!([a-z]{2,})\b", text):
            out.add("!" + m.group(1))
    return out


@pytest.mark.parametrize("name", ALL_GAMES)
def test_every_command_in_help_and_prompts_is_handled(name):
    tree = ast.parse((GAMES_DIR / f"{name}.py").read_text())
    handled = _handled_commands(tree)
    # Not commands: negation inside prose ("!=" never matches the regex).
    missing = sorted(_mentioned(tree) - handled)
    assert not missing, f"{name}: text mentions commands it does not handle: {missing}"


def _fishing_core(db_path):
    return FakeCore(db_path)


def test_fishing_reel_alias_and_bite_text(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("fishing", "channel", CHAN, owner="a")
        game = core.game.games["fishing"]
        session = game.get_session("channel", CHAN)
        calls = []

        async def fake_reel(sess, nick):
            calls.append((nick, "reel"))
        game._do_reel = fake_reel
        await game.on_PUBMSG(session, "alice", "!reel")
        await game.on_PUBMSG(session, "alice", "!fishreel")
        core.sent.clear()
        await game.on_PUBMSG(session, "alice", "!fishhelp")
        helptext = " ".join(core.texts(CHAN))
        await core.game.unload_game("fishing")
        return calls, helptext

    calls, helptext = run(scenario())
    assert len(calls) == 2
    for real in ("!fishcast", "!fishreel", "!fishstop"):
        assert real in helptext
    for stale in ("!cast", "!fishing stop"):
        assert stale not in helptext.replace("!fishcast", "")


def test_stale_command_texts_are_gone():
    def src(name):
        return (GAMES_DIR / f"{name}.py").read_text()

    assert "!horsestop" not in src("horseracing")
    assert "!horserace stop" in src("horseracing")
    assert "!pull" not in src("russianroulette").replace("!rrpull", "")
    assert "!roulette stop" not in src("roulette")
    assert "!roulettestop" in src("roulette")
    assert "!fishing stop" not in src("fishing")


# --- GAM-12: roulette bet names ------------------------------------------------

CFG = {"min_bet": 5, "max_bet": 1000}


@pytest.mark.parametrize("parts, kind, params", [
    (["straight", "17", "10"], "straight", 17),
    (["STRAIGHT", "0", "10"], "straight", 0),
    (["17", "10"], "straight", 17),
    (["split", "14-17", "10"], "split", (14, 17)),
    (["street", "4", "10"], "street", 4),
    (["corner", "1", "10"], "corner", 1),
    (["red", "10"], "red", None),
    (["black", "10"], "black", None),
    (["odd", "10"], "odd", None),
    (["even", "10"], "even", None),
    (["high", "10"], "high", None),
    (["low", "10"], "low", None),
    (["dozen2", "10"], "dozen2", None),
    (["col3", "10"], "col3", None),
])
def test_roulette_bet_names_parse(parts, kind, params):
    bet, err = roulette_mod._parse_bet(parts, CFG)
    assert err is None, err
    assert bet.kind == kind and bet.params == params and bet.amount == 10


@pytest.mark.parametrize("parts", [
    ["straight", "37", "10"], ["straight", "-1", "10"], ["straight", "x", "10"],
    ["straight", "10"], ["straight", "1", "2", "10"],
])
def test_roulette_bad_straight_is_refused_with_usage(parts):
    bet, err = roulette_mod._parse_bet(parts, CFG)
    assert bet is None and "straight" in err.lower()


def test_roulette_straight_bet_in_a_round_and_notices_in_order(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("roulette", "channel", CHAN, owner="a")
        game = core.game.games["roulette"]
        session = game.get_session("channel", CHAN)
        await game.on_PUBMSG(session, "alice", "!roulette")
        core.sent.clear()
        for text in ("!roulettebet straight 17 10",
                     "!roulettebet straight 37 10",       # error 1
                     "!roulettebet red abc",              # error 2
                     "!roulettebet bogus 10",             # error 3
                     "!roulettebet red 99999",            # error 4
                     "!roulettebet black 10"):
            await game.on_PUBMSG(session, "alice", text)
        sent = list(core.sent)
        bets = session.data["bets"]["alice"]
        await core.game.unload_game("roulette")
        return sent, bets

    sent, bets = run(scenario())
    assert [(b.kind, b.params, b.amount) for b in bets] == [("straight", 17, 10), ("black", None, 10)]
    # One payload per input line, in the order the commands were typed:
    # confirm, error, error, error, error, confirm.
    kinds = [p["cmd"] for p in sent]
    assert kinds == ["msg", "notice", "notice", "notice", "notice", "msg"]
    assert "straight 17" in sent[0]["text"]
    assert "0-36" in sent[1]["text"] or "straight" in sent[1]["text"].lower()
    assert "whole number" in sent[2]["text"]
    assert "Unknown bet type" in sent[3]["text"]
    assert "Maximum bet" in sent[4]["text"]
    assert "black" in sent[5]["text"]


def test_bjset_is_a_real_command_and_validates(db_path):
    async def scenario():
        core = FakeCore(db_path)
        await core.game.start_game("blackjack", "channel", CHAN, owner="a")
        game = core.game.games["blackjack"]
        session = game.get_session("channel", CHAN)
        await game.on_PUBMSG(session, "nobody", "!bjset min_bet 9")     # not an op
        await game.on_PUBMSG(session, "op", "!bjset min_bet abc")
        await game.on_PUBMSG(session, "op", "!bjset min_bet 9")
        got = session.data["cfg"]["min_bet"]
        notices = core.texts(cmd="notice")
        await core.game.unload_game("blackjack")
        return got, notices

    got, notices = run(scenario())
    assert got == 9
    assert "Only a chan-op" in notices[0] and "rejected" in notices[1]
