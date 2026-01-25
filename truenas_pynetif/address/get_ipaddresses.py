"""IP address query functions."""

import socket
import struct

from truenas_pynetif.address.constants import (
    AddressFamily,
    IFAAttr,
    RTMType,
)
from truenas_pynetif.netlink import AddressInfo, DeviceNotFound
from truenas_pynetif.netlink._core import (
    SOL_NETLINK,
    NetlinkSockOpt,
    NLMsgFlags,
    format_address,
    pack_nlmsg,
    parse_attrs,
    recv_msgs,
    resolve_ifname,
)

__all__ = ("get_addresses", "get_link_addresses")


def _parse_address_payload(
    payload: bytes, ifname_cache: dict[int, str | None] | None = None
) -> AddressInfo | None:
    """Parse a NEWADDR payload into AddressInfo. Returns None if invalid."""
    if len(payload) < 8:
        return None

    # Parse ifaddrmsg header
    ifa_family, ifa_prefixlen, ifa_flags, ifa_scope, ifa_index = struct.unpack_from(
        "BBBBI", payload, 0
    )
    # Parse attributes after ifaddrmsg (8 bytes)
    attrs = parse_attrs(payload, 8)

    # Get address - prefer IFA_ADDRESS, fall back to IFA_LOCAL
    address = None
    if IFAAttr.ADDRESS in attrs:
        address = format_address(ifa_family, attrs[IFAAttr.ADDRESS])
    elif IFAAttr.LOCAL in attrs:
        address = format_address(ifa_family, attrs[IFAAttr.LOCAL])
    if not address:
        return None

    local = None
    broadcast = None
    label = None
    ifname = None

    if IFAAttr.LOCAL in attrs:
        local = format_address(ifa_family, attrs[IFAAttr.LOCAL])
    if IFAAttr.BROADCAST in attrs:
        broadcast = format_address(ifa_family, attrs[IFAAttr.BROADCAST])
    if IFAAttr.LABEL in attrs:
        label = attrs[IFAAttr.LABEL].rstrip(b"\x00").decode("utf-8", errors="replace")

    if ifname_cache is not None:
        ifname = resolve_ifname(ifa_index, ifname_cache)

    # Extended fields
    proto = None
    valid_lft = None
    preferred_lft = None

    if IFAAttr.PROTO in attrs:
        proto = attrs[IFAAttr.PROTO][0]

    if IFAAttr.CACHEINFO in attrs and len(attrs[IFAAttr.CACHEINFO]) >= 8:
        ifa_prefered, ifa_valid = struct.unpack("II", attrs[IFAAttr.CACHEINFO][:8])
        preferred_lft = None if ifa_prefered == 0xFFFFFFFF else ifa_prefered
        valid_lft = None if ifa_valid == 0xFFFFFFFF else ifa_valid

    return AddressInfo(
        family=ifa_family,
        prefixlen=ifa_prefixlen,
        address=address,
        broadcast=broadcast,
        flags=ifa_flags,
        scope=ifa_scope,
        index=ifa_index,
        ifname=ifname,
        local=local,
        label=label,
        proto=proto,
        valid_lft=valid_lft,
        preferred_lft=preferred_lft,
    )


def get_addresses(sock: socket.socket) -> list[AddressInfo]:
    """Get all addresses for all interfaces."""
    ifaddrmsg = struct.pack("BBBBI", AddressFamily.UNSPEC, 0, 0, 0, 0)
    msg = pack_nlmsg(RTMType.GETADDR, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, ifaddrmsg)
    sock.send(msg)

    addresses: list[AddressInfo] = []
    ifname_cache: dict[int, str | None] = {}
    for msg_type, payload in recv_msgs(sock):
        if msg_type != RTMType.NEWADDR:
            continue
        if addr_info := _parse_address_payload(payload, ifname_cache):
            addresses.append(addr_info)

    return addresses


def get_link_addresses(sock: socket.socket, name: str) -> list[AddressInfo]:
    """Get addresses for a single interface by name."""
    try:
        index = socket.if_nametoindex(name)
    except OSError:
        raise DeviceNotFound(f"No such device: {name}")

    # Enable strict checking so kernel filters by interface index
    sock.setsockopt(SOL_NETLINK, NetlinkSockOpt.GET_STRICT_CHK, 1)
    try:
        ifaddrmsg = struct.pack("BBBBI", AddressFamily.UNSPEC, 0, 0, 0, index)
        msg = pack_nlmsg(
            RTMType.GETADDR, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, ifaddrmsg
        )
        sock.send(msg)

        ifname_cache: dict[int, str | None] = {index: name}
        addresses: list[AddressInfo] = []
        for msg_type, payload in recv_msgs(sock):
            if msg_type != RTMType.NEWADDR:
                continue
            if addr_info := _parse_address_payload(payload, ifname_cache):
                addresses.append(addr_info)

        return addresses
    finally:
        sock.setsockopt(SOL_NETLINK, NetlinkSockOpt.GET_STRICT_CHK, 0)
