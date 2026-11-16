# src/idrules.py
"""
Identity input rules shared by .+user, .+host and `--seed` (USR-7): one
definition of a valid user handle and a valid hostmask.  Pure functions, no
imports from the rest of the project (db.py and user.py both need them).
"""
import ipaddress
import re

# 1..20 ASCII characters from the IRC-safe set.  `\Z` (not `$`) so a trailing
# newline is not accepted.
HANDLE_RE = re.compile(r"^[A-Za-z0-9_\-\[\]\\`^{}]{1,20}\Z", re.ASCII)

# nick!user@host, wildcards (* ?) allowed.  Each part is non-empty, has no
# whitespace/control characters and none of the separators `!` `@`.
HOSTMASK_RE = re.compile(r"^[^\s!@\x00-\x1f\x7f]+![^\s!@\x00-\x1f\x7f]+@[^\s!@\x00-\x1f\x7f]+\Z")
HOSTMASK_MAX = 200

HANDLE_RULE_TEXT = ("Invalid handle. Use 1-20 characters: letters, digits and "
                    "_ - [ ] \\ ` ^ { } (ASCII only).")
HOSTMASK_RULE_TEXT = "Invalid hostmask format. Use: nick!user@host (wildcards allowed)"


def valid_handle(handle) -> bool:
    return isinstance(handle, str) and HANDLE_RE.match(handle) is not None


def valid_hostmask(mask) -> bool:
    return (isinstance(mask, str) and len(mask) <= HOSTMASK_MAX
            and HOSTMASK_RE.match(mask) is not None)


def wildcard_only_host(mask) -> bool:
    """True when the host part (after the last `@`) of `mask` is only `*`/`?`
    wildcards (and dots), e.g. `*!*@*`, `*!*@*.*`, `a!b@??`.  Such a mask
    matches any host, so it must never identify a +n/+A user (mythos F-01b)."""
    if not isinstance(mask, str) or "@" not in mask:
        return False
    host = mask.rpartition("@")[2]
    return bool(host) and any(c in "*?" for c in host) \
        and all(c in "*?." for c in host)


# Bot link address (NET-5): an IP literal or an RFC 1123 host name.
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)
ADDRESS_RULE_TEXT = "Invalid address. Use a host name or an IP address."
PORT_RULE_TEXT = "Invalid port. Use a number from 1 to 65535."


def valid_address(addr) -> bool:
    if not isinstance(addr, str) or not addr or len(addr) > 253:
        return False
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        pass
    labels = addr.rstrip(".").split(".")
    if addr.endswith("..") or not all(_HOST_LABEL_RE.match(x) for x in labels):
        return False
    # an all-numeric dotted name is a malformed IP, not a host name
    return not all(x.isdigit() for x in labels)


def parse_port(text):
    """int 1..65535 from `text` (decimal digits only), else None."""
    if isinstance(text, bool) or text is None:
        return None
    s = str(text)
    if not (s.isascii() and s.isdigit()) or len(s) > 5:
        return None
    n = int(s)
    return n if 1 <= n <= 65535 else None


# IRC channel names (IRC-5): `#` or `&`, then 1..49 characters that are not
# whitespace, a comma (the list separator) or BEL (the old ^G separator).
CHANNEL_RE = re.compile(r"^[#&][^\s,\x07]{1,49}\Z")
CHANNEL_RULE_TEXT = ("Invalid channel name. Use # or & followed by 1-49 characters "
                     "(no spaces, commas or ^G).")

# IRC nicknames (IRC-11), RFC 2812 shape: a letter or one of [ ] \ ` _ ^ { | }
# first, then those plus digits and `-`.  The real length limit is the
# server's NICKLEN, which only the IRC process knows; 30 is the longest
# common one.
NICK_RE = re.compile(r"^[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}\-]*\Z", re.ASCII)
NICK_MAX = 30
NICK_RULE_TEXT = ("Invalid nick. Use 1-30 characters: letters, digits and "
                  "[ ] \\ ` _ ^ { | } -, not starting with a digit or -.")

# Channel MODE change (IRC-8): sign first, letters only; parameters are the
# following words.
_MODE_FLAGS_RE = re.compile(r"^(?:[+-][A-Za-z]+)+\Z")
_MODE_NEEDS_ARG = {"+": frozenset("qaohvbeIkl"), "-": frozenset("qaohvbeIk")}
_MODE_NO_ARG = frozenset("ntpsimrcCDRMNOSTzZ")
NICK_MODES = frozenset("qaohv")          # modes whose parameter is a nick


def valid_channel(name) -> bool:
    return isinstance(name, str) and CHANNEL_RE.match(name) is not None


def valid_nick(nick, maxlen: int = NICK_MAX) -> bool:
    return (isinstance(nick, str) and len(nick) <= maxlen
            and NICK_RE.match(nick) is not None)


def validate_mode_string(modes):
    """Check a channel MODE change such as '+o nick', '+m' or '-k+l key 10'.

    Returns (error, changes): error is None when valid; changes is the list
    of (sign, letter, arg_or_None).  A sign comes first, letters only, every
    mode that needs a parameter (+qaohvbeIkl, -qaohvbeIk) has one, +l takes a
    number, and surplus words are refused unless the string holds a letter
    this check does not know (a server-specific mode may take parameters).
    """
    words = modes.split() if isinstance(modes, str) else []
    if not words:
        return "No modes given.", []
    if not _MODE_FLAGS_RE.match(words[0]):
        return (f"Invalid mode string '{words[0]}': start with + or -, then mode "
                "letters (e.g. +m, -o nick)."), []
    params = words[1:]
    changes, sign, used, unknown = [], "+", 0, False
    for ch in words[0]:
        if ch in "+-":
            sign = ch
            continue
        arg = None
        if ch in _MODE_NEEDS_ARG[sign]:
            if used >= len(params):
                return f"Mode {sign}{ch} needs a parameter.", []
            arg = params[used]
            used += 1
            if sign == "+" and ch == "l" and not (arg.isascii() and arg.isdigit()):
                return f"Mode +l needs a number, not '{arg}'.", []
            if ch in NICK_MODES and not valid_nick(arg, 64):
                return f"Invalid nick '{arg}' for mode {sign}{ch}.", []
        elif ch not in _MODE_NO_ARG:
            unknown = True
        changes.append((sign, ch, arg))
    if used < len(params) and not unknown:
        return f"Too many parameters for '{words[0]}'.", []
    return None, changes
