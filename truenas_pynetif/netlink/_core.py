import socket
import struct
from contextlib import contextmanager
from typing import Generator

from truenas_pynetif.netlink._exceptions import (
    DeviceNotFound,
    DumpInterrupted,
    NetlinkError,
    OperationNotSupported,
)

# Netlink protocols
NETLINK_ROUTE = 0
NETLINK_GENERIC = 16

# Generic netlink
GENL_ID_CTRL = 0x10

# Socket options
SOL_NETLINK = 270


class NetlinkSockOpt:
    GET_STRICT_CHK = 12


class NLAttrFlags:
    NESTED = 0x8000


class NLMsgFlags:
    REQUEST = 0x01
    MULTI = 0x02
    ACK = 0x04
    EXCL = 0x200
    CREATE = 0x400
    ROOT = 0x100
    MATCH = 0x200
    DUMP = ROOT | MATCH
    DUMP_INTR = 0x10
    REPLACE = 0x100


class NLMsgType:
    NOOP = 0x01
    ERROR = 0x02
    DONE = 0x03


@contextmanager
def netlink_route() -> Generator[socket.socket, None, None]:
    """Context manager for NETLINK_ROUTE socket."""
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
    sock.bind((0, 0))
    try:
        yield sock
    finally:
        sock.close()


@contextmanager
def netlink_generic() -> Generator[socket.socket, None, None]:
    """Context manager for NETLINK_GENERIC socket."""
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    sock.bind((0, 0))
    try:
        yield sock
    finally:
        sock.close()


def pack_nlattr(attr_type: int, data: bytes) -> bytes:
    """Pack a netlink attribute."""
    nla_len = 4 + len(data)
    padded_len = (nla_len + 3) & ~3
    padding = padded_len - nla_len
    return struct.pack("HH", nla_len, attr_type) + data + b"\x00" * padding


def pack_nlattr_str(attr_type: int, s: str) -> bytes:
    """Pack a string netlink attribute."""
    return pack_nlattr(attr_type, s.encode() + b"\x00")


def pack_nlattr_u8(attr_type: int, val: int) -> bytes:
    """Pack a u8 netlink attribute."""
    return pack_nlattr(attr_type, struct.pack("B", val))


def pack_nlattr_u16(attr_type: int, val: int) -> bytes:
    """Pack a u16 netlink attribute."""
    return pack_nlattr(attr_type, struct.pack("H", val))


def pack_nlattr_u32(attr_type: int, val: int) -> bytes:
    """Pack a u32 netlink attribute."""
    return pack_nlattr(attr_type, struct.pack("I", val))


def pack_nlattr_nested(attr_type: int, attrs: bytes) -> bytes:
    """Pack nested netlink attributes."""
    return pack_nlattr(attr_type | NLAttrFlags.NESTED, attrs)


def pack_nlmsg(msg_type: int, flags: int, payload: bytes, seq: int = 1) -> bytes:
    """Pack a netlink message."""
    nlmsg_len = 16 + len(payload)
    return struct.pack("IHHII", nlmsg_len, msg_type, flags, seq, 0) + payload


def pack_genlmsg(
    family_id: int, cmd: int, version: int, attrs: bytes, seq: int = 1
) -> bytes:
    """Pack a generic netlink message."""
    genlhdr = struct.pack("BBH", cmd, version, 0)
    payload = genlhdr + attrs
    return pack_nlmsg(family_id, NLMsgFlags.REQUEST | NLMsgFlags.ACK, payload, seq)


def recv_msgs(sock: socket.socket) -> list[tuple[int, bytes]]:
    """Receive and parse netlink messages from socket."""
    messages = []
    while True:
        data = sock.recv(65536)
        offset = 0
        done = False
        while offset < len(data):
            if offset + 16 > len(data):
                break
            nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = (
                struct.unpack_from("IHHII", data, offset)
            )
            if nlmsg_len < 16:
                break
            if nlmsg_flags & NLMsgFlags.DUMP_INTR:
                raise DumpInterrupted("Netlink dump was interrupted")
            if nlmsg_type == NLMsgType.ERROR:
                if offset + 20 <= len(data):
                    error = struct.unpack_from("i", data, offset + 16)[0]
                    if error < 0:
                        error = -error
                        if error == 19:  # ENODEV
                            raise DeviceNotFound("No such device")
                        elif error == 95:  # EOPNOTSUPP
                            raise OperationNotSupported("Operation not supported")
                        raise NetlinkError(f"Netlink error: {error}", error_code=error)
                done = True
            elif nlmsg_type == NLMsgType.DONE:
                done = True
            else:
                payload = data[offset + 16 : offset + nlmsg_len]
                messages.append((nlmsg_type, payload))
            offset += (nlmsg_len + 3) & ~3
        if done:
            break
    return messages


def parse_attrs(data: bytes, offset: int = 0) -> dict[int, bytes]:
    """Parse netlink attributes from data."""
    attrs = {}
    while offset + 4 <= len(data):
        nla_len, nla_type = struct.unpack_from("HH", data, offset)
        if nla_len < 4:
            break
        nla_type_base = nla_type & 0x7FFF
        attr_data = data[offset + 4 : offset + nla_len]
        attrs[nla_type_base] = attr_data
        offset += (nla_len + 3) & ~3
    return attrs


def format_address(family: int, data: bytes) -> str | None:
    """Format raw address bytes as string."""
    AF_INET = 2
    AF_INET6 = 10
    if family == AF_INET and len(data) >= 4:
        return socket.inet_ntop(socket.AF_INET, data[:4])
    elif family == AF_INET6 and len(data) >= 16:
        return socket.inet_ntop(socket.AF_INET6, data[:16])
    return None


def resolve_ifname(index: int, cache: dict[int, str | None]) -> str | None:
    """Resolve interface index to name, using cache."""
    if index not in cache:
        try:
            cache[index] = socket.if_indextoname(index)
        except OSError:
            cache[index] = None
    return cache[index]
