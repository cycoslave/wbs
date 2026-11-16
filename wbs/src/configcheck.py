# src/configcheck.py
"""
Config shape validation (USR-14).

``validate_config`` is run once at startup, before anything is seeded or
launched.  It reports *every* problem it finds (not just the first) as
``(path, message)`` pairs, so the operator can fix the file in one go instead
of peeling off one traceback at a time.  Unknown keys are ignored (plugins and
newer configs add their own); only keys the bot actually reads are checked.

Pure stdlib and import-light on purpose: ``wbs --help`` must not pull in IRC.
"""
from __future__ import annotations

import logging

ROOT = "$"          # path used for problems with the document itself

_LEVELS = {"DEBUG", "INFO", "WARNING", "WARN", "ERROR", "CRITICAL", "FATAL"}
DEFAULT_LEVEL = "INFO"


def resolve_log_level(value) -> tuple[int, bool]:
    """Return ``(level, recognised)``; unknown or non-string -> INFO."""
    if isinstance(value, str) and value.strip().upper() in _LEVELS:
        return getattr(logging, value.strip().upper()), True
    return logging.INFO, False


def _tname(v) -> str:
    return {type(None): "null", bool: "boolean", int: "number", float: "number",
            str: "string", list: "array", dict: "object"}.get(type(v), type(v).__name__)


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# Types of the keys each section reads.  "str" non-empty, "num" int/float,
# "int" integer, "bool" strict boolean, "strs" list of strings.
_SETTINGS = {
    "pid_file": "str", "botnet": "bool", "listen_host": "strany", "listen_port": "int",
    "ssl": "bool", "ssl_verify": "bool", "certfile": "str", "keyfile": "str",
    "auto_update": "bool", "allow_plaintext": "bool", "irc_throttle_ms": "num",
    "access_mode": "str", "max_failures": "int", "max_failures_ip": "int", "lockout_seconds": "num",
    "handshake_timeout": "num", "max_connections": "int",
}
_DCC = {
    "enabled": "bool", "mode": "str", "public_ip": "strany", "listen_host": "strany",
    "port_min": "int",
    "port_max": "int", "max_sessions": "int", "max_pending": "int",
    "rate_limit": "num", "global_rate_limit": "num", "allow_networks": "strs",
    "auth_timeout": "num", "auth_attempts": "int",
}
_UPDATE = {"host": "strany", "signing_keys": "strs", "auto_updates": "bool"}
_BOT = {"user": "str", "realname": "str", "channels": "strs",
        "allow_plaintext_fallback": "bool"}
_LOGGING = {"file": "str", "max_bytes": "int", "backup_count": "int"}
# config["botnet"] (NET-11): the one section for botnet settings.
_BOTNET = {"address": "strany", "listen_host": "strany", "listen_port": "int",
           "subnet_id": "int"}


class _Collector:
    def __init__(self):
        self.errors: list[tuple[str, str]] = []
        self.warnings: list[tuple[str, str]] = []

    def err(self, path, msg):
        self.errors.append((path, msg))

    def warn(self, path, msg):
        self.warnings.append((path, msg))

    def check(self, path, value, kind):
        """Type-check ``value`` against ``kind``; report and return ok."""
        if kind == "str":
            ok = isinstance(value, str) and bool(value.strip())
            want = "a non-empty string"
        elif kind == "strany":
            ok = isinstance(value, str)
            want = "a string"
        elif kind == "int":
            ok = isinstance(value, int) and not isinstance(value, bool)
            want = "an integer"
        elif kind == "num":
            ok = _is_num(value)
            want = "a number"
        elif kind == "bool":
            ok = isinstance(value, bool)
            want = "true or false"
        elif kind == "strs":
            if not isinstance(value, list):
                self.err(path, f"must be a list of strings, got {_tname(value)}")
                return False
            for i, item in enumerate(value):
                if not isinstance(item, str):
                    self.err(f"{path}[{i}]", f"must be a string, got {_tname(item)}")
            return all(isinstance(i, str) for i in value)
        else:                                   # pragma: no cover
            raise ValueError(kind)
        if not ok:
            self.err(path, f"must be {want}, got {_tname(value)}")
        return ok

    def section(self, config, name, spec, *, required=False):
        """Return the section dict (or None); type-check the keys in ``spec``."""
        if name not in config:
            if required:
                self.err(name, "required section is missing")
            return None
        sec = config[name]
        if not isinstance(sec, dict):
            self.err(name, f"must be an object, got {_tname(sec)}")
            return None
        for key, kind in spec.items():
            if key in sec and sec[key] is not None:
                self.check(f"{name}.{key}", sec[key], kind)
        return sec


def validate_config(config, *, require_bot: bool = True):
    """Check the parsed config document.

    Returns ``(errors, warnings)``, each a list of ``(path, message)``.
    ``require_bot=False`` skips the bot section (``--update`` only needs
    ``update``).
    """
    c = _Collector()
    if not isinstance(config, dict):
        c.err(ROOT, f"config must be a JSON object, got {_tname(config)}")
        return c.errors, c.warnings

    # --- bot --------------------------------------------------------------
    if require_bot:
        bot = c.section(config, "bot", _BOT, required=True)
        if bot is not None:
            nick = bot.get("nick")
            if "nick" not in bot:
                c.err("bot.nick", "required key is missing")
            else:
                c.check("bot.nick", nick, "str")
            if "servers" not in bot:
                c.err("bot.servers", "required key is missing "
                                     "(a non-empty list of {host, port, ssl})")
            else:
                servers = bot["servers"]
                if not isinstance(servers, list):
                    c.err("bot.servers", f"must be a list, got {_tname(servers)}")
                elif not servers:
                    c.err("bot.servers", "must not be empty "
                                         "(need at least one {host, port, ssl})")
                else:
                    _check_servers(c, config)
    else:
        c.section(config, "bot", _BOT)

    # --- users ------------------------------------------------------------
    users = config.get("users")
    if users is not None:
        if not isinstance(users, list):
            c.err("users", f"must be a list, got {_tname(users)}")
        else:
            for i, u in enumerate(users):
                _check_user(c, f"users[{i}]", u)

    # --- plain sections ---------------------------------------------------
    sub = c.section(config, "subnet", {"name": "str"})
    if sub is not None and sub.get("id") is not None:
        c.check("subnet.id", sub["id"], "int")
    c.section(config, "db", {"path": "str"})
    log_sec = c.section(config, "logging", _LOGGING)
    if log_sec is not None:
        for key in ("max_bytes", "backup_count"):
            val = log_sec.get(key)
            if _is_num(val) and val < 0:
                c.err(f"logging.{key}", f"must be 0 or more, got {val}")
    if log_sec is not None and log_sec.get("level") is not None:
        lvl = log_sec["level"]
        if not isinstance(lvl, str):
            c.err("logging.level", f"must be a string, got {_tname(lvl)}")
        elif not resolve_log_level(lvl)[1]:
            c.warn("logging.level",
                   f"unknown level {lvl!r}; falling back to {DEFAULT_LEVEL} "
                   f"(use one of DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    settings = c.section(config, "settings", _SETTINGS)
    if settings is not None:
        from .flood import parse_rate          # stdlib-only module
        for key in ("flood_msg", "flood_ctcp"):
            if settings.get(key) is not None:
                try:
                    parse_rate(settings[key])
                except ValueError:
                    c.err(f"settings.{key}",
                          f"must be \"N:S\" (N messages in S seconds, e.g. \"5:60\") "
                          f"or 0 to disable, got {settings[key]!r}")
    c.section(config, "dcc", _DCC)
    c.section(config, "update", _UPDATE)
    _check_botnet(c, config)
    c.section(config, "pubcom", {"channels": "strs"})
    if "plugins" in config and config["plugins"] is not None:
        c.check("plugins", config["plugins"], "strs")
    return c.errors, c.warnings


def _check_botnet(c: _Collector, config: dict) -> None:
    """``botnet`` is an object (address, listen_host, listen_port, subnet_id,
    relay_from).  A bare ``"botnet": true/false`` and the ``settings`` copies of
    listen_host/listen_port still work but are deprecated (NET-11)."""
    sec = config.get("botnet")
    if isinstance(sec, bool):
        c.warn("botnet", "a true/false flag is deprecated: use an object "
                         "{\"listen_port\": 3333, \"address\": \"your.host\", ...}")
        return
    sec = c.section(config, "botnet", _BOTNET)
    if sec is None:
        return
    port = sec.get("listen_port")
    if isinstance(port, int) and not isinstance(port, bool) and not 1 <= port <= 65535:
        c.err("botnet.listen_port", f"must be 1-65535, got {port}")
    relay = sec.get("relay_from")
    if relay is not None:
        if not isinstance(relay, dict):
            c.err("botnet.relay_from", f"must be an object, got {_tname(relay)}")
        else:
            for peer, handles in relay.items():
                c.check(f"botnet.relay_from.{peer}", handles, "strs")
    settings = config.get("settings")
    if isinstance(settings, dict):
        if settings.get("listen_port") is not None:
            if sec.get("listen_port") is not None and sec["listen_port"] != settings["listen_port"]:
                c.warn("settings.listen_port",
                       "differs from botnet.listen_port; botnet.listen_port is used")
            elif sec.get("listen_port") is None:
                c.warn("settings.listen_port",
                       "deprecated here: move it to botnet.listen_port")


def _check_servers(c: _Collector, config: dict) -> None:
    """Entry-level checks: reuse the IRC layer's own validator (single source
    of truth for what a usable bot.servers entry is)."""
    try:
        from .irc import build_server_specs, IrcConfigError
    except Exception:                           # IRC deps unavailable: skip
        return
    try:
        build_server_specs(config)
    except IrcConfigError as exc:
        c.err("bot.servers", str(exc))


def _check_user(c: _Collector, path: str, u) -> None:
    if not isinstance(u, dict):
        c.err(path, f"must be an object, got {_tname(u)}")
        return
    if "handle" in u and u["handle"] is not None:
        c.check(f"{path}.handle", u["handle"], "str")
    pw = u.get("password")
    if pw is not None:
        if not isinstance(pw, dict):
            c.err(f"{path}.password",
                  f"must be an object like {{\"pass\": ..., \"encryption\": ...}}, "
                  f"got {_tname(pw)}")
        else:
            if pw.get("pass") is not None:
                c.check(f"{path}.password.pass", pw["pass"], "str")
            if pw.get("encryption") is not None:
                c.check(f"{path}.password.encryption", pw["encryption"], "str")
    if u.get("hosts") is not None:
        c.check(f"{path}.hosts", u["hosts"], "strs")
    acc = u.get("access")
    if acc is not None:
        if not isinstance(acc, list):
            c.err(f"{path}.access", f"must be a list, got {_tname(acc)}")
        else:
            for j, a in enumerate(acc):
                if not isinstance(a, dict):
                    c.err(f"{path}.access[{j}]",
                          f"must be an object, got {_tname(a)}")


def format_problems(filename: str, errors, warnings=()):
    """Render lines in the same style as the existing parse error."""
    lines = [f"[fatal] Config error in {filename}: {p}: {m}" for p, m in errors]
    lines += [f"[warning] Config warning in {filename}: {p}: {m}" for p, m in warnings]
    return lines
