"""
Regression tests for IRC-9 (CTCP TIME/FINGER/CLIENTINFO/USERINFO/SOURCE were
not answered), IRC-10 (.swhois/.swhowas never showed the server's answer),
IRC-12 (.whom Bot column hard-coded '*') and IRC-13 (public !whois: whoisit
never bootstrapped).

Raw server lines go through the real WbsIrcBot reactor into the real Core
(helpers shared with test_irc_channel_sync / test_automode).  The RDAP side of
!whois uses fakes for whoisit; nothing touches the network.
"""
import asyncio
import re


from src import ircreq
from src.commands import cmd_swhois, cmd_swhowas, cmd_whom
from src.plugins import pubcom
from src.plugins.pubcom import pubcomPlugin

from test_automode import env, flush  # noqa: F401  (fixture)
from test_irc_channel_sync import BOT, SRV, pump

RANDO = "rando!~r@stranger.example"


# ---------------------------------------------------------------------------
# IRC-9: CTCP coverage
# ---------------------------------------------------------------------------
def ctcp(core, irc, sent, request, source=RANDO):
    sent.clear()
    pump(core, irc, f":{source} PRIVMSG {BOT} :\x01{request}\x01")
    return list(sent)


def test_ctcp_time_is_a_local_time_string(env):
    core, irc, sent = env
    out = ctcp(core, irc, sent, "TIME")
    assert len(out) == 1 and out[0].startswith("NOTICE rando :\x01TIME "), out
    assert out[0].endswith("\x01")
    assert re.search(r"TIME \w{3} \w{3} \d\d \d\d:\d\d:\d\d \d{4}", out[0]), out


def test_ctcp_finger_names_the_bot_and_idle(env):
    core, irc, sent = env
    out = ctcp(core, irc, sent, "FINGER")
    assert len(out) == 1, out
    assert out[0].startswith(f"NOTICE rando :\x01FINGER {BOT} (")
    assert re.search(r"Idle \d+ seconds\x01$", out[0]), out


def test_ctcp_userinfo_clientinfo_source(env):
    core, irc, sent = env
    assert ctcp(core, irc, sent, "USERINFO") == ["NOTICE rando :\x01USERINFO WBS Bot\x01"]
    assert ctcp(core, irc, sent, "SOURCE") == \
        ["NOTICE rando :\x01SOURCE https://github.com/cycoslave/wbs\x01"]
    info = ctcp(core, irc, sent, "CLIENTINFO")
    assert len(info) == 1
    listed = info[0].strip("\x01").split()[2:]
    for name in ("CLIENTINFO", "FINGER", "PING", "SOURCE", "TIME", "USERINFO", "VERSION"):
        assert name in listed, (name, info)


def test_every_listed_ctcp_gets_an_answer(env):
    core, irc, sent = env
    from src.irc import CTCP_SUPPORTED
    irc.ctcp_rate = None
    for name in CTCP_SUPPORTED:
        arg = f"{name} 123" if name == "PING" else name
        out = ctcp(core, irc, sent, arg)
        assert len(out) == 1 and f"\x01{name} " in out[0], (name, out)


def test_ctcp_replies_obey_the_flood_limit(env):
    core, irc, sent = env
    replies = []
    for req in ("TIME", "FINGER", "CLIENTINFO", "USERINFO", "SOURCE", "TIME"):
        replies += ctcp(core, irc, sent, req)
    assert len(replies) == 3, replies          # default 3:60, then silence


# ---------------------------------------------------------------------------
# IRC-10: .swhois / .swhowas
# ---------------------------------------------------------------------------
def start(core, func, arg, handle="boss"):
    out: list[str] = []

    async def respond(msg):
        out.append(msg)
    asyncio.run(func(core, handle, 1, arg, respond))
    return out


def start_pending(core, func, arg):
    """Run the command and keep the reply list alive for later answers."""
    out: list[str] = []

    async def respond(msg):
        out.append(msg)
    asyncio.run(func(core, "boss", 1, arg, respond))
    return out


WHOIS_REPLY = [
    f"{SRV} 311 {BOT} x ~xu x.example * :Ex Real",
    f"{SRV} 312 {BOT} x irc.example.net :Example Server",
    f"{SRV} 313 {BOT} x :is an IRC Operator",
    f"{SRV} 317 {BOT} x 42 1700000000 :seconds idle, signon time",
    f"{SRV} 319 {BOT} x :@#wbs +#other",
    f"{SRV} 330 {BOT} x xacct :is logged in as",
]


def test_swhois_returns_the_server_reply_to_the_caller(env):
    core, irc, sent = env
    out = start_pending(core, cmd_swhois, "x")
    assert "WHOIS sent for x" in out[0]
    assert flush(core, irc, sent) == ["WHOIS x"]
    pump(core, irc, *WHOIS_REPLY)
    assert len(out) == 1                       # nothing before the end numeric
    pump(core, irc, f"{SRV} 318 {BOT} x :End of /WHOIS list.")
    text = "\n".join(out[1:])
    assert "x is ~xu@x.example * Ex Real" in text
    assert "x using irc.example.net (Example Server)" in text
    assert "x is an IRC Operator" in text
    assert "x idle 42s, signed on 2023-11-14 22:13:20 UTC" in text
    assert "x on @#wbs +#other" in text
    assert "x is logged in as xacct" in text
    assert core.ircreq.pending == []


def test_swhois_replies_go_to_the_requesting_session(env):
    core, irc, sent = env
    a = start_pending(core, cmd_swhois, "x")
    b = start_pending(core, cmd_swhois, "y")
    flush(core, irc, sent)
    pump(core, irc, f"{SRV} 311 {BOT} y ~yu y.example * :Why",
         f"{SRV} 318 {BOT} y :End of /WHOIS list.",
         f"{SRV} 311 {BOT} x ~xu x.example * :Ex",
         f"{SRV} 318 {BOT} x :End of /WHOIS list.")
    assert any("y is ~yu@y.example" in l for l in b) and not any("~xu" in l for l in b)
    assert any("x is ~xu@x.example" in l for l in a) and not any("~yu" in l for l in a)


def test_swhois_no_such_nick(env):
    core, irc, sent = env
    out = start_pending(core, cmd_swhois, "ghost")
    flush(core, irc, sent)
    pump(core, irc, f"{SRV} 401 {BOT} ghost :No such nick/channel",
         f"{SRV} 318 {BOT} ghost :End of /WHOIS list.")
    text = "\n".join(out[1:])
    assert "No such nick: ghost" in text, out
    assert core.ircreq.pending == []


def test_swhowas_returns_the_server_reply(env):
    core, irc, sent = env
    out = start_pending(core, cmd_swhowas, "old")
    assert flush(core, irc, sent) == ["WHOWAS old"]
    pump(core, irc, f"{SRV} 314 {BOT} old ~ou o.example * :Old Real",
         f"{SRV} 312 {BOT} old irc.example.net :Mon Oct  5 2026",
         f"{SRV} 369 {BOT} old :End of WHOWAS")
    text = "\n".join(out[1:])
    assert "old was ~ou@o.example * Old Real" in text, out
    assert core.ircreq.pending == []


def test_swhowas_unknown_nick_406(env):
    core, irc, sent = env
    out = start_pending(core, cmd_swhowas, "never")
    flush(core, irc, sent)
    pump(core, irc, f"{SRV} 406 {BOT} never :There was no such nickname",
         f"{SRV} 369 {BOT} never :End of WHOWAS")
    assert any("No such nick: never" in l for l in out), out
    assert core.ircreq.pending == []


def test_swhois_without_answer_says_no_reply(env):
    core, irc, sent = env
    out = start_pending(core, cmd_swhois, "x")
    asyncio.run(core.ircreq.expire(now=core.ircreq.pending[0].deadline - 1))
    assert len(out) == 1
    asyncio.run(core.ircreq.expire(now=core.ircreq.pending[0].deadline + 1))
    assert any("No reply" in l for l in out[1:]), out
    assert ircreq.TIMEOUT == 10.0
    assert core.ircreq.pending == []


def test_swhois_partial_reply_then_timeout(env):
    core, irc, sent = env
    out = start_pending(core, cmd_swhois, "x")
    flush(core, irc, sent)
    pump(core, irc, WHOIS_REPLY[0])
    asyncio.run(core.ircreq.expire(now=core.ircreq.pending[0].deadline + 1))
    assert any("x is ~xu@x.example" in l for l in out)
    assert any("No reply" in l and "incomplete" in l for l in out)


def test_swhois_input_validation_and_connection(env):
    core, irc, sent = env
    assert start(core, cmd_swhois, "")[0].startswith("Usage: .swhois")
    assert "Invalid nick" in start(core, cmd_swhois, "bad!nick")[0]
    assert "Invalid nick" in start(core, cmd_swhowas, "1bad")[0]
    core.connected = False
    assert start(core, cmd_swhois, "x") == ["Not connected to IRC."]
    assert core.irc_q.items == []


def test_unsolicited_whois_numerics_are_ignored(env):
    core, irc, sent = env
    pump(core, irc, *WHOIS_REPLY)              # nobody asked: no crash, no state
    assert getattr(core, "ircreq", None) is None or core.ircreq.pending == []


# ---------------------------------------------------------------------------
# IRC-12: .whom Bot column
# ---------------------------------------------------------------------------
def test_whom_shows_the_real_bot_per_session(env):
    core, irc, sent = env
    core.partyline.sessions.clear()
    core.partyline.sessions[0] = {"type": "console", "handle": "boss", "queue": None}
    core.partyline.next_id = 1
    core.partyline.register_remote("telnet", "tel")
    core.partyline.sessions[7] = {"type": "relay", "handle": "far", "queue": None,
                                  "origin": "otherbot", "rid": "r"}
    out = start(core, cmd_whom, "")
    rows = {}
    for l in out[2:-1]:                        # skip the two header lines and the total
        parts = l.lstrip("* ").split()
        rows[parts[0]] = parts
    assert rows["boss"][-2:] == [BOT, "localhost"], (rows, out)
    assert rows["tel"][-2:] == [BOT, "telnet"], out
    assert rows["far"][-2:] == ["otherbot", "relay"], out
    assert all(p[1] != "*" for p in rows.values()), out
    assert out[-1] == "Total users: 3"


# ---------------------------------------------------------------------------
# IRC-13: !whois (RDAP) bootstrap
# ---------------------------------------------------------------------------
class _Core:
    def __init__(self):
        self.sent: list[dict] = []

    def send_irc(self, payload):
        self.sent.append(payload)

    def say(self):
        return [p["text"] for p in self.sent if p.get("cmd") == "msg"]


class FakeWhoisit:
    """Stands in for the whoisit module (module attributes are patched)."""
    def __init__(self, monkeypatch, bootstrap=None):
        self.ready = False
        self.bootstrap_calls = 0
        self.queries: list = []
        self._bootstrap = bootstrap
        monkeypatch.setattr(pubcom.whoisit, "is_bootstrapped", lambda: self.ready)
        monkeypatch.setattr(pubcom.whoisit, "bootstrap_async", self.bootstrap_async)
        monkeypatch.setattr(pubcom.whoisit, "domain_async", self.domain_async)
        monkeypatch.setattr(pubcom.whoisit, "asn_async", self.asn_async)

    async def bootstrap_async(self, *a, **kw):
        self.bootstrap_calls += 1
        if self._bootstrap is not None:
            await self._bootstrap()
        self.ready = True

    async def domain_async(self, name, **kw):
        if not self.ready:
            raise RuntimeError("You need to load bootstrap data before making any queries")
        self.queries.append(("domain", name))
        return {"domain": name}

    async def asn_async(self, n, **kw):
        if not self.ready:
            raise RuntimeError("You need to load bootstrap data before making any queries")
        self.queries.append(("asn", n))
        return {"asn": n, "name": "TEST-AS"}


def make_plugin():
    core = _Core()
    plugin = pubcomPlugin(core)

    async def enabled(channel):
        return True
    plugin.is_pubcom_enabled = enabled
    return core, plugin


def whois(plugin, arg):
    asyncio.run(plugin.cmd_whois("nick", "nick!u@h", "#chan", arg))


def test_whois_bootstraps_whoisit_before_the_first_query(monkeypatch):
    fake = FakeWhoisit(monkeypatch)
    core, plugin = make_plugin()
    whois(plugin, "example.org")
    assert core.say() == ["WHOIS example.org: example.org"]
    assert fake.bootstrap_calls == 1
    whois(plugin, "65000")
    assert core.say()[-1] == "WHOIS 65000: AS65000 TEST-AS"
    assert fake.bootstrap_calls == 1               # bootstrapped once


def test_load_bootstraps_in_the_background(monkeypatch):
    fake = FakeWhoisit(monkeypatch)
    core, plugin = make_plugin()

    async def base_load(self):          # plugin-table setup needs a database
        return None
    monkeypatch.setattr(pubcom.Plugin, "load", base_load)
    monkeypatch.setattr(pubcom.Plugin, "unload", base_load)
    async def go():
        await plugin.load()
        await plugin._rdap_task
        await plugin.unload()
    asyncio.run(go())
    assert fake.ready and fake.bootstrap_calls == 1


def test_whois_offline_gives_a_clear_error_and_backs_off(monkeypatch):
    async def offline():
        raise OSError("network unreachable")
    fake = FakeWhoisit(monkeypatch, bootstrap=offline)
    core, plugin = make_plugin()
    whois(plugin, "example.org")
    whois(plugin, "example.org")
    out = core.say()
    assert len(out) == 2 and all(l.startswith("WHOIS unavailable:") for l in out), out
    assert "cannot load RDAP bootstrap data" in out[0] and "network unreachable" in out[0]
    assert "need to load bootstrap" not in "".join(out)
    assert fake.bootstrap_calls == 1               # second call inside the back-off
    assert fake.queries == []


def test_whois_retries_after_the_backoff(monkeypatch):
    state = {"fail": True}

    async def flaky():
        if state["fail"]:
            raise OSError("down")
    fake = FakeWhoisit(monkeypatch, bootstrap=flaky)
    core, plugin = make_plugin()
    whois(plugin, "example.org")
    assert core.say()[0].startswith("WHOIS unavailable")
    state["fail"] = False
    plugin._rdap_failed_at -= pubcom.RDAP_RETRY_SECONDS + 1
    whois(plugin, "example.org")
    assert core.say()[-1] == "WHOIS example.org: example.org"
    assert fake.bootstrap_calls == 2


def test_whois_bootstrap_times_out(monkeypatch):
    async def hang():
        await asyncio.sleep(30)
    monkeypatch.setattr(pubcom, "RDAP_BOOTSTRAP_TIMEOUT", 0.05)
    fake = FakeWhoisit(monkeypatch, bootstrap=hang)
    core, plugin = make_plugin()
    whois(plugin, "example.org")
    assert len(core.say()) == 1
    assert core.say()[0].startswith("WHOIS unavailable: the RDAP bootstrap service did not answer")
    assert fake.queries == []
