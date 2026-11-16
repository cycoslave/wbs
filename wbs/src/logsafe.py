"""
Log-safe rendering of untrusted IRC/botnet data (SAST-002).

IRC text (PRIVMSG, NOTICE, COMMAND, PUBMSG ...) can carry credentials:
``/msg <bot> identify [handle] <password>``, the IRC-fallback DCC
``chatauth`` answer, ``.chpass``/``.botattr pass=`` and friends.  It can
also carry terminal control sequences, bidi overrides and line breaks that
make a log unreliable (CWE-117).  No log line may contain that raw text, at
any level.

This module is the one place that turns such data into log text:

* :func:`event_summary` - an IRC event dict as allow-listed metadata
  (type, nick, channel/target, kind) plus the *length* of its text.
* :func:`irc_cmd_summary` - an outbound IRC command dict, the same way.
* :func:`line_summary` - a raw protocol line as its verb and its size.
* :func:`safe` - one bounded, control-character-escaped value.
* :func:`command_error` / :func:`handler_error` - log a failing command or
  event handler without ``exc_info``; the exception message is escaped, and
  withheld for credential-bearing commands and private-text events (it can
  quote the input).
* :func:`guard_library_logs` - the ``irc`` library traces every raw line
  it sends or receives (``FROM SERVER``/``TO SERVER``, including the server
  ``PASS``) and ``aiosqlite`` every SQL parameter (link keys, password
  hashes) at DEBUG; those records are dropped.
"""

from __future__ import annotations

import logging
import traceback
import unicodedata
from typing import Any, Mapping

__all__ = [
    "SAFE_EVENT_FIELDS",
    "SAFE_CMD_FIELDS",
    "CREDENTIAL_COMMANDS",
    "PRIVATE_TEXT_EVENTS",
    "MAX_FIELD",
    "safe",
    "event_summary",
    "irc_cmd_summary",
    "line_summary",
    "log_failure",
    "command_error",
    "handler_error",
    "guard_library_logs",
]

# Longest rendering of one metadata value (nick, channel, ...).
MAX_FIELD = 64

# Event keys that are routing metadata, never message text.  Everything
# else (text, message, reason, topic, arguments, data ...) is reported only
# as a length.
SAFE_EVENT_FIELDS = ("nick", "channel", "target", "kind")

# Outbound IRC command keys that are routing metadata.
SAFE_CMD_FIELDS = ("cmd", "target", "channel", "nick")

# Event keys whose string length is reported (message bodies).
_TEXT_FIELDS = ("text", "message", "reason", "topic")

# Commands whose argument is (or contains) a credential.  Aliases included:
# the IRC command path does not resolve aliases before logging.
CREDENTIAL_COMMANDS = frozenset({
    "identify", "chatauth", "chpass", "passwd", "botattr", "fixpass",
})

# Event types whose text is private input to the bot (may be a password).
PRIVATE_TEXT_EVENTS = frozenset({"PRIVMSG", "NOTICE", "COMMAND"})

_CONTROL_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"})


def _escape_char(ch: str) -> str:
    code = ord(ch)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def safe(value: Any, limit: int = MAX_FIELD) -> str:
    """``value`` as one log-safe token.

    Control, format (bidi overrides, zero-width), separator, surrogate,
    private-use and unassigned code points are escaped (``\\x1b``,
    ``\\u202e`` ...); a backslash is doubled so an escape cannot be forged.
    At most ``limit`` source characters are kept; a cut is marked ``...``.
    """
    if value is None:
        return "-"
    text = value if isinstance(value, str) else str(value)
    cut = len(text) > limit
    if cut:
        text = text[:limit]
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif unicodedata.category(ch) in _CONTROL_CATEGORIES:
            out.append(_escape_char(ch))
        else:
            out.append(ch)
    rendered = "".join(out)
    return rendered + "..." if cut else rendered


def _text_len(value: Any) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, (list, tuple)):
        return sum(len(v) for v in value if isinstance(v, str))
    return 0


def event_summary(etype: Any, event: Any) -> str:
    """One-line metadata of an IRC/internal event, without any of its text.

    ``type=PRIVMSG nick=alice target=wbs len=23``.  Only
    :data:`SAFE_EVENT_FIELDS` are rendered (escaped, bounded); message
    bodies are counted, never shown.
    """
    if not isinstance(event, Mapping):
        return f"type={safe(etype)} event=<{type(event).__name__}>"
    parts = [f"type={safe(etype if etype is not None else event.get('type'))}"]
    for key in SAFE_EVENT_FIELDS:
        val = event.get(key)
        if val not in (None, ""):
            parts.append(f"{key}={safe(val)}")
    length = sum(_text_len(event.get(k)) for k in _TEXT_FIELDS)
    length += _text_len(event.get("arguments"))
    if length:
        parts.append(f"len={length}")
    return " ".join(parts)


def irc_cmd_summary(cmd_data: Any) -> str:
    """One-line metadata of an outbound IRC command dict (no text)."""
    if not isinstance(cmd_data, Mapping):
        return f"cmd=<{type(cmd_data).__name__}>"
    parts = []
    for key in SAFE_CMD_FIELDS:
        val = cmd_data.get(key)
        if val not in (None, ""):
            parts.append(f"{key}={safe(val)}")
    length = sum(_text_len(cmd_data.get(k))
                 for k in ("text", "message", "reason", "topic", "line"))
    if length:
        parts.append(f"len={length}")
    return " ".join(parts) or "cmd=-"


def line_summary(line: Any) -> str:
    """A raw protocol line as ``VERB (n fields, m chars)``; no payload."""
    if not isinstance(line, str):
        return f"<{type(line).__name__}>"
    fields = line.split()
    verb = safe(fields[0], 24) if fields else "-"
    return f"{verb} ({len(fields)} fields, {len(line)} chars)"


def log_failure(logger: logging.Logger, label: str, exc: BaseException, *,
                withhold: bool = False) -> None:
    """Log ``label`` failing with ``exc``: exception type, message and the
    traceback frames (source lines, never local values).

    The message is escaped and bounded; with ``withhold`` it is left out
    entirely, because it may quote the input (``invalid literal for int()
    ...: 'hunter2'``).  ``exc_info`` is not used: the stdlib formatter
    would print the raw, unescaped message as the traceback's last line.
    """
    frames = "".join(traceback.format_tb(exc.__traceback__)).rstrip()
    detail = "(message withheld: may quote private input)" if withhold else safe(exc, 300)
    logger.error("%s: %s: %s\nTraceback (most recent call last):\n%s",
                 label, type(exc).__name__, detail, frames)


def command_error(logger: logging.Logger, cmd: str, exc: BaseException) -> None:
    """Log that command ``cmd`` raised ``exc``; the exception message is
    withheld for :data:`CREDENTIAL_COMMANDS`."""
    log_failure(logger, f"Command '{safe(cmd, 32)}' error", exc,
                withhold=(cmd or "").lower() in CREDENTIAL_COMMANDS)


def handler_error(logger: logging.Logger, label: str, etype: Any,
                  exc: BaseException) -> None:
    """Log that an event handler (plugin, game) raised ``exc`` while
    handling an ``etype`` event; the message is withheld for
    :data:`PRIVATE_TEXT_EVENTS`, whose text may be a credential."""
    log_failure(logger, label, exc,
                withhold=str(etype).upper() in PRIVATE_TEXT_EVENTS)


class _WireTraceFilter(logging.Filter):
    """Drop a library's sub-WARNING records: they are raw data traces.

    * ``irc``: ``FROM SERVER: ... PRIVMSG bot :identify pw``, ``TO SERVER:
      PASS ...``, ``command: ..., arguments: [...]``.
    * ``aiosqlite``: ``executing functools.partial(..., 'UPDATE bots SET
      password = ?', ('<botlink key>', ...))`` - every SQL parameter.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING


_WIRE_TRACE_LOGGERS = ("irc", "irc.client", "irc.client_aio", "irc.bot",
                       "irc.connection", "irc.schedule", "irc.events",
                       "aiosqlite", "aiosqlite.core")
_WIRE_FILTER = _WireTraceFilter()


def guard_library_logs() -> None:
    """Keep the ``irc`` and ``aiosqlite`` libraries' raw-data DEBUG/INFO
    tracing out of every log, whatever level the root logger or an operator
    sets.  Idempotent."""
    for name in _WIRE_TRACE_LOGGERS:
        lg = logging.getLogger(name)
        if lg.level == logging.NOTSET or lg.level < logging.WARNING:
            lg.setLevel(logging.WARNING)
        if _WIRE_FILTER not in lg.filters:
            lg.addFilter(_WIRE_FILTER)
