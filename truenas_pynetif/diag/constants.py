from __future__ import annotations

from enum import IntEnum

__all__ = (
    "NETLINK_SOCK_DIAG",
    "SOCK_DIAG_BY_FAMILY",
    "SS_ALL",
    "SockState",
)

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20


class SockState(IntEnum):
    UNKNOWN = 0
    ESTABLISHED = 1
    SYN_SENT = 2
    SYN_RECV = 3
    FIN_WAIT1 = 4
    FIN_WAIT2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTEN = 10
    CLOSING = 11
    MAX = 12


SS_ALL = (1 << SockState.MAX) - 1
