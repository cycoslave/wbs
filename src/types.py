"""Event types for queues."""
from enum import Enum

class EventType(Enum):
    PUBMSG = "PUBMSG"
    PRIVMSG = "PRIVMSG"
    JOIN = "JOIN"
    PART = "PART"
    NICK = "NICK"
    MODE = "MODE"
    COMMAND = "COMMAND"
    READY = "READY"
    ERROR = "ERROR"
    WHOIS_USER = "WHOIS_USER"
