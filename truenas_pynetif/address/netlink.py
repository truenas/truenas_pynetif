import socket
import struct

from truenas_pynetif.address.constants import (
    AddressFamily,
    IFAAttr,
    IFLAAttr,
    IFOperState,
    RTAAttr,
    RTEXTFilter,
    RTMFlags,
    RTMType,
    RTNType,
    RTProtocol,
    RTScope,
    RTTable,
)
from truenas_pynetif.netlink import AddressInfo, DeviceNotFound, LinkInfo, RouteInfo
from truenas_pynetif.netlink._core import (
    SOL_NETLINK,
    NetlinkSockOpt,
    NLMsgFlags,
    netlink_route,
    pack_nlattr_u32,
    pack_nlmsg,
    parse_attrs,
    recv_msgs,
    format_address,
    resolve_ifname,
)

__all__ = (
    "AddressInfo",
    "DeviceNotFound",
    "IFOperState",
    "LinkInfo",
    "RouteInfo",
    "get_addresses",
    "get_link",
    "get_link_addresses",
    "get_link_routes",
    "get_links",
    "get_routes",
    "link_exists",
    "netlink_route",
)


def _parse_link_payload(payload: bytes) -> tuple[str, LinkInfo] | None:
    """Parse a NEWLINK payload into (ifname, LinkInfo). Returns None if invalid."""
    if len(payload) < 16:
        return None

    # Parse ifinfomsg header
    ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change = struct.unpack_from(
        "BxHiII", payload, 0
    )
    # Parse attributes after ifinfomsg (16 bytes)
    attrs = parse_attrs(payload, 16)

    ifname = None
    if IFLAAttr.IFNAME in attrs:
        ifname = attrs[IFLAAttr.IFNAME].rstrip(b"\x00").decode("utf-8", errors="replace")
    if not ifname:
        return None

    # Core fields
    mtu = 0
    operstate = 0
    address = None
    perm_address = None
    broadcast = None

    if IFLAAttr.MTU in attrs:
        mtu = struct.unpack("I", attrs[IFLAAttr.MTU][:4])[0]
    if IFLAAttr.OPERSTATE in attrs:
        operstate = attrs[IFLAAttr.OPERSTATE][0]
    if IFLAAttr.ADDRESS in attrs:
        address = attrs[IFLAAttr.ADDRESS].hex(":")
    if IFLAAttr.PERM_ADDRESS in attrs:
        perm_address = attrs[IFLAAttr.PERM_ADDRESS].hex(":")
    if IFLAAttr.BROADCAST in attrs:
        broadcast = attrs[IFLAAttr.BROADCAST].hex(":")

    # Extended fields
    txqlen = 0
    min_mtu = 0
    max_mtu = 0
    carrier = False
    carrier_changes = 0
    num_tx_queues = 1
    num_rx_queues = 1

    if IFLAAttr.TXQLEN in attrs:
        txqlen = struct.unpack("I", attrs[IFLAAttr.TXQLEN][:4])[0]
    if IFLAAttr.MIN_MTU in attrs:
        min_mtu = struct.unpack("I", attrs[IFLAAttr.MIN_MTU][:4])[0]
    if IFLAAttr.MAX_MTU in attrs:
        max_mtu = struct.unpack("I", attrs[IFLAAttr.MAX_MTU][:4])[0]
    if IFLAAttr.CARRIER in attrs:
        carrier = attrs[IFLAAttr.CARRIER][0] != 0
    if IFLAAttr.CARRIER_CHANGES in attrs:
        carrier_changes = struct.unpack("I", attrs[IFLAAttr.CARRIER_CHANGES][:4])[0]
    if IFLAAttr.NUM_TX_QUEUES in attrs:
        num_tx_queues = struct.unpack("I", attrs[IFLAAttr.NUM_TX_QUEUES][:4])[0]
    if IFLAAttr.NUM_RX_QUEUES in attrs:
        num_rx_queues = struct.unpack("I", attrs[IFLAAttr.NUM_RX_QUEUES][:4])[0]

    # Parent device info (for USB detection, etc.)
    parentbus = None
    parentdev = None

    if IFLAAttr.PARENT_DEV_BUS_NAME in attrs:
        parentbus = (
            attrs[IFLAAttr.PARENT_DEV_BUS_NAME]
            .rstrip(b"\x00")
            .decode("utf-8", errors="replace")
        )
    if IFLAAttr.PARENT_DEV_NAME in attrs:
        parentdev = (
            attrs[IFLAAttr.PARENT_DEV_NAME]
            .rstrip(b"\x00")
            .decode("utf-8", errors="replace")
        )

    # Alternate names from IFLA_PROP_LIST
    altnames: list[str] = []
    if IFLAAttr.PROP_LIST in attrs:
        offset = 0
        prop_data = attrs[IFLAAttr.PROP_LIST]
        while offset + 4 <= len(prop_data):
            nla_len, nla_type = struct.unpack_from("HH", prop_data, offset)
            if nla_len < 4:
                break
            nla_type_base = nla_type & 0x7FFF
            if nla_type_base == IFLAAttr.ALT_IFNAME:
                attr_data = prop_data[offset + 4 : offset + nla_len]
                altnames.append(
                    attr_data.rstrip(b"\x00").decode("utf-8", errors="replace")
                )
            offset += (nla_len + 3) & ~3

    return ifname, LinkInfo(
        index=ifi_index,
        flags=ifi_flags,
        mtu=mtu,
        operstate=operstate,
        address=address,
        perm_address=perm_address,
        broadcast=broadcast,
        txqlen=txqlen,
        min_mtu=min_mtu,
        max_mtu=max_mtu,
        carrier=carrier,
        carrier_changes=carrier_changes,
        num_tx_queues=num_tx_queues,
        num_rx_queues=num_rx_queues,
        parentbus=parentbus,
        parentdev=parentdev,
        altnames=tuple(altnames),
    )


def link_exists(name: str) -> bool:
    """Check if a network interface exists (fast syscall, no netlink)."""
    try:
        socket.if_nametoindex(name)
        return True
    except OSError:
        return False


def get_links(sock: socket.socket) -> dict[str, LinkInfo]:
    """Get all network interfaces."""
    # Build ifinfomsg: family(1) + pad(1) + type(2) + index(4) + flags(4) + change(4) = 16 bytes
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, 0, 0, 0)
    # Add IFLA_EXT_MASK to request extended info but skip stats
    ext_mask = pack_nlattr_u32(IFLAAttr.EXT_MASK, RTEXTFilter.VF | RTEXTFilter.SKIP_STATS)
    payload = ifinfomsg + ext_mask
    msg = pack_nlmsg(RTMType.GETLINK, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, payload)
    sock.send(msg)

    links: dict[str, LinkInfo] = {}
    for msg_type, payload in recv_msgs(sock):
        if msg_type != RTMType.NEWLINK:
            continue
        if result := _parse_link_payload(payload):
            ifname, link_info = result
            links[ifname] = link_info

    return links


def get_link(sock: socket.socket, name: str) -> LinkInfo:
    """Get link info for a single interface by name."""
    try:
        index = socket.if_nametoindex(name)
    except OSError:
        raise DeviceNotFound(f"No such device: {name}")

    # Build ifinfomsg with specific index
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)
    msg = pack_nlmsg(RTMType.GETLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg)
    sock.send(msg)

    for msg_type, payload in recv_msgs(sock):
        if msg_type != RTMType.NEWLINK:
            continue
        if result := _parse_link_payload(payload):
            return result[1]

    raise DeviceNotFound(f"No such device: {name}")


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
        msg = pack_nlmsg(RTMType.GETADDR, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, ifaddrmsg)
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

        msg = pack_nlmsg(RTMType.GETROUTE, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, payload)
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
