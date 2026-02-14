from __future__ import annotations

import socket
import struct
from contextlib import contextmanager
from collections.abc import Generator

from truenas_pynetif.diag.constants import (
    NETLINK_SOCK_DIAG,
    SOCK_DIAG_BY_FAMILY,
    SS_ALL,
)
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    pack_nlmsg,
    recv_msgs,
)
from truenas_pynetif.netlink.dataclass_types import InetDiagSockInfo

__all__ = (
    "get_inet_diag",
    "netlink_diag",
)

IPPROTO_TCP = 6

# inet_diag_msg fixed header size (before NLA attributes)
_INET_DIAG_MSG_SIZE = 72


@contextmanager
def netlink_diag() -> Generator[socket.socket, None, None]:
    """Context manager for a NETLINK_SOCK_DIAG socket."""
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        sock.bind((0, 0))
        yield sock


def _build_inet_diag_req(
    family: int,
    protocol: int,
    states: int,
) -> bytes:
    # inet_diag_req_v2:
    #   sdiag_family(u8) + sdiag_protocol(u8) + idiag_ext(u8) + pad(u8) + idiag_states(u32)
    header = struct.pack("BBBxI", family, protocol, 0, states)
    # inet_diag_sockid (all zeroes = no filter):
    #   sport(be16) + dport(be16) + src(be32[4]) + dst(be32[4]) + if(u32) + cookie(u64)
    sockid = struct.pack("!HH4I4I", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) + struct.pack(
        "IQ", 0, 0
    )
    return header + sockid


def _parse_inet_diag_msg(family: int, payload: bytes) -> InetDiagSockInfo | None:
    if len(payload) < _INET_DIAG_MSG_SIZE:
        return None

    state = payload[1]
    sport, dport = struct.unpack_from("!HH", payload, 4)

    if family == socket.AF_INET:
        src = socket.inet_ntop(socket.AF_INET, payload[8:12])
        dst = socket.inet_ntop(socket.AF_INET, payload[24:28])
    else:
        src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])

    uid, inode = struct.unpack_from("II", payload, 64)

    return InetDiagSockInfo(
        family=family,
        state=state,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        uid=uid,
        inode=inode,
    )


def get_inet_diag(
    sock: socket.socket,
    family: int = socket.AF_INET,
    protocol: int = IPPROTO_TCP,
    states: int = SS_ALL,
) -> list[InetDiagSockInfo]:
    """Query the kernel for inet socket diagnostic information.

    Sends a SOCK_DIAG_BY_FAMILY netlink request and returns all matching
    sockets as InetDiagSockInfo entries. Each entry contains the socket's
    source/destination endpoints, TCP state, owning UID, and inode."""
    req = _build_inet_diag_req(family, protocol, states)
    msg = pack_nlmsg(
        SOCK_DIAG_BY_FAMILY,
        NLMsgFlags.REQUEST | NLMsgFlags.ROOT | NLMsgFlags.MATCH,
        req,
    )
    sock.send(msg)

    results: list[InetDiagSockInfo] = []
    for msg_type, payload in recv_msgs(sock):
        if msg_type != SOCK_DIAG_BY_FAMILY:
            continue
        if entry := _parse_inet_diag_msg(family, payload):
            results.append(entry)

    return results
