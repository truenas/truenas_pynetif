import socket
import struct

from truenas_pynetif.address.constants import (
    AddressFamily,
    RTAAttr,
    RTMFlags,
    RTMType,
    RTNType,
    RTProtocol,
    RTScope,
    RTTable,
)
from truenas_pynetif.netlink import DeviceNotFound, RouteInfo
from truenas_pynetif.netlink._core import (
    SOL_NETLINK,
    NetlinkSockOpt,
    NLMsgFlags,
    format_address,
    pack_nlattr_u32,
    pack_nlmsg,
    parse_attrs,
    recv_msgs,
    resolve_ifname,
)

__all__ = ("get_routes", "get_link_routes", "get_default_route")


def _parse_route_payload(
    payload: bytes, ifname_cache: dict[int, str | None] | None = None
) -> RouteInfo | None:
    """Parse a NEWROUTE payload into RouteInfo. Returns None if invalid."""
    if len(payload) < 12:
        return None

    # Parse rtmsg header (12 bytes)
    (
        rtm_family,
        rtm_dst_len,
        rtm_src_len,
        rtm_tos,
        rtm_table,
        rtm_protocol,
        rtm_scope,
        rtm_type,
        rtm_flags,
    ) = struct.unpack_from("BBBBBBBBI", payload, 0)

    # Skip cloned routes
    if rtm_flags & RTMFlags.CLONED:
        return None

    # Parse attributes after rtmsg (12 bytes)
    attrs = parse_attrs(payload, 12)

    dst = None
    gateway = None
    prefsrc = None
    oif = None
    oif_name = None
    priority = None
    table = rtm_table

    if RTAAttr.DST in attrs:
        dst = format_address(rtm_family, attrs[RTAAttr.DST])
    if RTAAttr.GATEWAY in attrs:
        gateway = format_address(rtm_family, attrs[RTAAttr.GATEWAY])
    if RTAAttr.PREFSRC in attrs:
        prefsrc = format_address(rtm_family, attrs[RTAAttr.PREFSRC])
    if RTAAttr.OIF in attrs and len(attrs[RTAAttr.OIF]) >= 4:
        oif = struct.unpack("I", attrs[RTAAttr.OIF][:4])[0]
        if ifname_cache is not None:
            oif_name = resolve_ifname(oif, ifname_cache)
    if RTAAttr.PRIORITY in attrs and len(attrs[RTAAttr.PRIORITY]) >= 4:
        priority = struct.unpack("I", attrs[RTAAttr.PRIORITY][:4])[0]
    if RTAAttr.TABLE in attrs and len(attrs[RTAAttr.TABLE]) >= 4:
        table = struct.unpack("I", attrs[RTAAttr.TABLE][:4])[0]

    return RouteInfo(
        family=rtm_family,
        dst_len=rtm_dst_len,
        table=table,
        protocol=rtm_protocol,
        scope=rtm_scope,
        route_type=rtm_type,
        flags=rtm_flags,
        dst=dst,
        gateway=gateway,
        prefsrc=prefsrc,
        oif=oif,
        oif_name=oif_name,
        priority=priority,
    )


def get_routes(
    sock: socket.socket,
    family: int = AddressFamily.UNSPEC,
    table: int = RTTable.MAIN,
) -> list[RouteInfo]:
    """Get routing table entries.

    Args:
        sock: Netlink socket from netlink_route() context manager
        family: Address family (UNSPEC=all, INET=IPv4, INET6=IPv6)
        table: Routing table ID (default: MAIN=254)

    Returns:
        List of RouteInfo objects
    """
    rtmsg = struct.pack(
        "BBBBBBBBI",
        family,
        0,  # rtm_dst_len
        0,  # rtm_src_len
        0,  # rtm_tos
        RTTable.UNSPEC,
        RTProtocol.UNSPEC,
        RTScope.UNIVERSE,
        RTNType.UNSPEC,
        0,  # rtm_flags
    )

    table_attr = pack_nlattr_u32(RTAAttr.TABLE, table)
    payload = rtmsg + table_attr

    msg = pack_nlmsg(RTMType.GETROUTE, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, payload)
    sock.send(msg)

    routes: list[RouteInfo] = []
    ifname_cache: dict[int, str | None] = {}
    for msg_type, payload in recv_msgs(sock):
        if msg_type != RTMType.NEWROUTE:
            continue
        if route_info := _parse_route_payload(payload, ifname_cache):
            routes.append(route_info)

    return routes


def get_link_routes(
    sock: socket.socket,
    name: str,
    family: int = AddressFamily.UNSPEC,
    table: int = RTTable.MAIN,
) -> list[RouteInfo]:
    """Get routes for a single interface by name.

    Args:
        sock: Netlink socket from netlink_route() context manager
        name: Interface name (e.g., "eth0", "vlan1")
        family: Address family (UNSPEC=all, INET=IPv4, INET6=IPv6)
        table: Routing table ID (default: MAIN=254)

    Returns:
        List of RouteInfo objects for the specified interface
    """
    try:
        index = socket.if_nametoindex(name)
    except OSError:
        raise DeviceNotFound(f"No such device: {name}")

    sock.setsockopt(SOL_NETLINK, NetlinkSockOpt.GET_STRICT_CHK, 1)
    try:
        rtmsg = struct.pack(
            "BBBBBBBBI",
            family,
            0,
            0,
            0,
            RTTable.UNSPEC,
            RTProtocol.UNSPEC,
            RTScope.UNIVERSE,
            RTNType.UNSPEC,
            0,
        )

        table_attr = pack_nlattr_u32(RTAAttr.TABLE, table)
        oif_attr = pack_nlattr_u32(RTAAttr.OIF, index)
        payload = rtmsg + table_attr + oif_attr

        msg = pack_nlmsg(
            RTMType.GETROUTE, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, payload
        )
        sock.send(msg)

        ifname_cache: dict[int, str | None] = {index: name}
        routes: list[RouteInfo] = []
        for msg_type, payload in recv_msgs(sock):
            if msg_type != RTMType.NEWROUTE:
                continue
            if route_info := _parse_route_payload(payload, ifname_cache):
                routes.append(route_info)

        return routes
    finally:
        sock.setsockopt(SOL_NETLINK, NetlinkSockOpt.GET_STRICT_CHK, 0)


def get_default_route(
    sock: socket.socket,
    family: int = AddressFamily.INET,
    table: int = RTTable.MAIN,
) -> RouteInfo | None:
    """Get the default route for a given address family.

    Args:
        sock: Netlink socket from netlink_route() context manager
        family: Address family (INET=IPv4, INET6=IPv6)
        table: Routing table ID (default: MAIN=254)

    Returns:
        RouteInfo for the default route, or None if not found
    """
    for route in get_routes(sock, family=family, table=table):
        if route.dst is None and route.dst_len == 0:
            return route
    return None
