import socket
import struct
from contextvars import ContextVar
from dataclasses import dataclass, field

from .constants import (
    NETLINK_ROUTE,
    SOL_NETLINK,
    AddressFamily,
    IFAAttr,
    IFLAAttr,
    IFOperState,
    NetlinkSockOpt,
    NLAttrFlags,
    NLMsgFlags,
    NLMsgType,
    RTEXTFilter,
    RTMType,
)
from ..exceptions import (
    DeviceNotFound,
    DumpInterrupted,
    NetlinkError,
    OperationNotSupported,
)

__all__ = (
    "AddressInfo",
    "AddressNetlink",
    "DeviceNotFound",
    "DumpInterrupted",
    "IFOperState",
    "LinkInfo",
    "NetlinkError",
    "OperationNotSupported",
    "close_address_netlink",
    "get_address_netlink",
)

_address_ctx: ContextVar["AddressNetlink | None"] = ContextVar(
    "address_netlink", default=None
)


@dataclass(slots=True, frozen=True, kw_only=True)
class AddressInfo:
    # Fields used for equality and hashing
    family: int
    prefixlen: int
    address: str
    broadcast: str | None = None
    # Fields below are informational only - not used for equality/hashing
    flags: int = field(default=0, compare=False, hash=False)
    scope: int = field(default=0, compare=False, hash=False)
    index: int = field(default=0, compare=False, hash=False)
    local: str | None = field(default=None, compare=False, hash=False)
    label: str | None = field(default=None, compare=False, hash=False)


@dataclass(slots=True, frozen=True, kw_only=True)
class LinkInfo:
    index: int
    flags: int
    mtu: int
    operstate: int
    address: str | None
    perm_address: str | None


@dataclass(slots=True)
class AddressNetlink:
    _sock: socket.socket | None = field(default=None, init=False)
    _seq: int = field(default=0, init=False)
    _pid: int | None = field(default=None, init=False)

    def __enter__(self):
        self._connect()
        return self

    def __exit__(self, *args):
        self.close()

    def _connect(self):
        self._sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        self._sock.bind((0, 0))
        self._pid = self._sock.getsockname()[0]

    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None

    def _pack_nlattr(self, attr_type: int, data: bytes) -> bytes:
        nla_len = 4 + len(data)
        padded_len = (nla_len + 3) & ~3
        padding = padded_len - nla_len
        return struct.pack("HH", nla_len, attr_type) + data + b"\x00" * padding

    def _pack_nlattr_str(self, attr_type: int, s: str) -> bytes:
        return self._pack_nlattr(attr_type, s.encode() + b"\x00")

    def _pack_nlattr_u32(self, attr_type: int, val: int) -> bytes:
        return self._pack_nlattr(attr_type, struct.pack("I", val))

    def _pack_nlattr_nested(self, attr_type: int, attrs: bytes) -> bytes:
        return self._pack_nlattr(attr_type | NLAttrFlags.NESTED, attrs)

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _pack_nlmsg(self, msg_type: int, flags: int, payload: bytes) -> bytes:
        seq = self._next_seq()
        nlmsg_len = 16 + len(payload)
        return struct.pack("IHHII", nlmsg_len, msg_type, flags, seq, 0) + payload

    def _recv_msgs(self) -> list[tuple[int, bytes]]:
        messages = []
        while True:
            data = self._sock.recv(65536)
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
                            raise NetlinkError(f"Netlink error: {error}")
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

    def _parse_attrs(self, data: bytes, offset: int = 0) -> dict[int, bytes]:
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

    def _parse_nested_attrs(self, data: bytes) -> dict[int, bytes]:
        return self._parse_attrs(data, 0)

    def _parse_link_payload(self, payload: bytes) -> tuple[str, LinkInfo] | None:
        """Parse a NEWLINK payload into (ifname, LinkInfo). Returns None if invalid."""
        if len(payload) < 16:
            return None

        # Parse ifinfomsg header
        ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change = struct.unpack_from(
            "BxHiII", payload, 0
        )
        # Parse attributes after ifinfomsg (16 bytes)
        attrs = self._parse_attrs(payload, 16)

        ifname = None
        if IFLAAttr.IFNAME in attrs:
            ifname = (
                attrs[IFLAAttr.IFNAME]
                .rstrip(b"\x00")
                .decode("utf-8", errors="replace")
            )
        if not ifname:
            return None

        mtu = 0
        operstate = 0
        address = None
        perm_address = None

        if IFLAAttr.MTU in attrs:
            mtu = struct.unpack("I", attrs[IFLAAttr.MTU][:4])[0]
        if IFLAAttr.OPERSTATE in attrs:
            operstate = attrs[IFLAAttr.OPERSTATE][0]
        if IFLAAttr.ADDRESS in attrs:
            address = attrs[IFLAAttr.ADDRESS].hex(":")
        if IFLAAttr.PERM_ADDRESS in attrs:
            perm_address = attrs[IFLAAttr.PERM_ADDRESS].hex(":")

        return ifname, LinkInfo(
            index=ifi_index,
            flags=ifi_flags,
            mtu=mtu,
            operstate=operstate,
            address=address,
            perm_address=perm_address,
        )

    def get_links(self) -> dict[str, LinkInfo]:
        """Get all network interfaces."""
        # Build ifinfomsg: family(1) + pad(1) + type(2) + index(4) + flags(4) + change(4) = 16 bytes
        ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, 0, 0, 0)
        # Add IFLA_EXT_MASK to request extended info but skip stats
        ext_mask = self._pack_nlattr_u32(
            IFLAAttr.EXT_MASK, RTEXTFilter.VF | RTEXTFilter.SKIP_STATS
        )
        payload = ifinfomsg + ext_mask
        msg = self._pack_nlmsg(
            RTMType.GETLINK, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, payload
        )
        self._sock.send(msg)

        links: dict[str, LinkInfo] = {}
        for msg_type, payload in self._recv_msgs():
            if msg_type != RTMType.NEWLINK:
                continue
            if result := self._parse_link_payload(payload):
                ifname, link_info = result
                links[ifname] = link_info

        return links

    def get_link(self, name: str) -> LinkInfo:
        """Get link info for a single interface by name."""
        try:
            index = socket.if_nametoindex(name)
        except OSError:
            raise DeviceNotFound(f"No such device: {name}")

        # Build ifinfomsg with specific index
        # Use ACK flag to get a terminating response (no DUMP = single interface)
        ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)
        msg = self._pack_nlmsg(
            RTMType.GETLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg
        )
        self._sock.send(msg)

        for msg_type, payload in self._recv_msgs():
            if msg_type != RTMType.NEWLINK:
                continue
            if result := self._parse_link_payload(payload):
                return result[1]

        raise DeviceNotFound(f"No such device: {name}")

    def _parse_address_payload(self, payload: bytes) -> AddressInfo | None:
        """Parse a NEWADDR payload into AddressInfo. Returns None if invalid."""
        if len(payload) < 8:
            return None

        # Parse ifaddrmsg header
        ifa_family, ifa_prefixlen, ifa_flags, ifa_scope, ifa_index = (
            struct.unpack_from("BBBBI", payload, 0)
        )
        # Parse attributes after ifaddrmsg (8 bytes)
        attrs = self._parse_attrs(payload, 8)

        # Get address - prefer IFA_ADDRESS, fall back to IFA_LOCAL
        address = None
        if IFAAttr.ADDRESS in attrs:
            address = self._format_address(ifa_family, attrs[IFAAttr.ADDRESS])
        elif IFAAttr.LOCAL in attrs:
            address = self._format_address(ifa_family, attrs[IFAAttr.LOCAL])
        if not address:
            return None

        local = None
        broadcast = None
        label = None

        if IFAAttr.LOCAL in attrs:
            local = self._format_address(ifa_family, attrs[IFAAttr.LOCAL])
        if IFAAttr.BROADCAST in attrs:
            broadcast = self._format_address(ifa_family, attrs[IFAAttr.BROADCAST])
        if IFAAttr.LABEL in attrs:
            label = (
                attrs[IFAAttr.LABEL]
                .rstrip(b"\x00")
                .decode("utf-8", errors="replace")
            )

        return AddressInfo(
            family=ifa_family,
            prefixlen=ifa_prefixlen,
            address=address,
            broadcast=broadcast,
            flags=ifa_flags,
            scope=ifa_scope,
            index=ifa_index,
            local=local,
            label=label,
        )

    def get_addresses(self) -> list[AddressInfo]:
        """Get all addresses for all interfaces."""
        # Build ifaddrmsg: family(1) + prefixlen(1) + flags(1) + scope(1) + index(4) = 8 bytes
        ifaddrmsg = struct.pack("BBBBI", AddressFamily.UNSPEC, 0, 0, 0, 0)
        msg = self._pack_nlmsg(
            RTMType.GETADDR, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, ifaddrmsg
        )
        self._sock.send(msg)

        addresses: list[AddressInfo] = []
        for msg_type, payload in self._recv_msgs():
            if msg_type != RTMType.NEWADDR:
                continue
            if addr_info := self._parse_address_payload(payload):
                addresses.append(addr_info)

        return addresses

    def get_link_addresses(self, name: str) -> list[AddressInfo]:
        """Get addresses for a single interface by name."""
        try:
            index = socket.if_nametoindex(name)
        except OSError:
            raise DeviceNotFound(f"No such device: {name}")

        # Enable strict checking so kernel filters by interface index
        self._sock.setsockopt(SOL_NETLINK, NetlinkSockOpt.GET_STRICT_CHK, 1)

        # Build ifaddrmsg with specific index - kernel will filter with strict check enabled
        ifaddrmsg = struct.pack("BBBBI", AddressFamily.UNSPEC, 0, 0, 0, index)
        msg = self._pack_nlmsg(
            RTMType.GETADDR, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, ifaddrmsg
        )
        self._sock.send(msg)

        addresses: list[AddressInfo] = []
        for msg_type, payload in self._recv_msgs():
            if msg_type != RTMType.NEWADDR:
                continue
            if addr_info := self._parse_address_payload(payload):
                addresses.append(addr_info)

        return addresses

    def _format_address(self, family: int, data: bytes) -> str | None:
        if family == AddressFamily.INET and len(data) >= 4:
            return socket.inet_ntop(socket.AF_INET, data[:4])
        elif family == AddressFamily.INET6 and len(data) >= 16:
            return socket.inet_ntop(socket.AF_INET6, data[:16])
        return None


def get_address_netlink() -> AddressNetlink:
    nl = _address_ctx.get()
    needs_reconnect = False
    if nl is None:
        needs_reconnect = True
    elif nl._sock is None:
        needs_reconnect = True
    else:
        try:
            if nl._sock.fileno() == -1:
                needs_reconnect = True
        except OSError:
            needs_reconnect = True
    if needs_reconnect:
        if nl is not None:
            try:
                nl.close()
            except OSError:
                pass
        nl = AddressNetlink()
        nl._connect()
        _address_ctx.set(nl)
    return nl


def close_address_netlink() -> None:
    nl = _address_ctx.get()
    if nl is not None:
        nl.close()
        _address_ctx.set(None)
