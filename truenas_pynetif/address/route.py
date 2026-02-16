from __future__ import annotations

import errno
import ipaddress
import socket
import struct

from truenas_pynetif.address.constants import (
    AddressFamily,
    RTAAttr,
    RTMType,
    RTNType,
    RTProtocol,
    RTScope,
    RTTable,
)
from truenas_pynetif.address.get_routes import get_routes
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    pack_nlattr,
    pack_nlattr_u32,
    pack_nlmsg,
    recv_msgs,
)
from truenas_pynetif.netlink._exceptions import (
    NetlinkError,
    RouteAlreadyExists,
    RouteDoesNotExist,
)

__all__ = ("add_route", "change_route", "delete_route", "flush_routes")


def _build_route_msg(
    dst: str | None,
    dst_len: int,
    gateway: str | None,
    *,
    name: str | None,
    index: int | None,
    table: int,
    protocol: int,
    scope: int | None,
    route_type: RTNType,
    prefsrc: str | None,
    priority: int | None,
) -> bytes:
    if dst is not None:
        if "/" in dst:
            dst_obj = ipaddress.ip_address(dst.split("/")[0])
        else:
            dst_obj = ipaddress.ip_address(dst)
    else:
        dst_obj = None
    if gateway is not None:
        gw_obj = ipaddress.ip_address(gateway)
    else:
        gw_obj = None

    first_addr = dst_obj or gw_obj
    if first_addr is None:
        raise ValueError("At least one of dst or gateway must be provided")

    if first_addr.version == 4:
        family = AddressFamily.INET
    else:
        family = AddressFamily.INET6

    if scope is None:
        if route_type in (RTNType.BLACKHOLE, RTNType.UNREACHABLE, RTNType.PROHIBIT):
            scope = RTScope.UNIVERSE
        elif gw_obj:
            scope = RTScope.UNIVERSE
        else:
            scope = RTScope.LINK

    rtmsg = struct.pack(
        "BBBBBBBBI",
        family,
        dst_len,
        0,
        0,
        RTTable.UNSPEC,
        protocol,
        scope,
        route_type,
        0,
    )

    attrs = b""

    if dst_obj is not None:
        attrs += pack_nlattr(RTAAttr.DST, dst_obj.packed)

    if gw_obj is not None:
        attrs += pack_nlattr(RTAAttr.GATEWAY, gw_obj.packed)

    if name is not None and index is None:
        index = socket.if_nametoindex(name)
    if index is not None:
        attrs += pack_nlattr_u32(RTAAttr.OIF, index)

    attrs += pack_nlattr_u32(RTAAttr.TABLE, table)

    if prefsrc is not None:
        attrs += pack_nlattr(RTAAttr.PREFSRC, ipaddress.ip_address(prefsrc).packed)

    if priority is not None:
        attrs += pack_nlattr_u32(RTAAttr.PRIORITY, priority)

    return rtmsg + attrs


def add_route(
    sock: socket.socket,
    dst: str | None = None,
    dst_len: int = 0,
    gateway: str | None = None,
    *,
    name: str | None = None,
    index: int | None = None,
    table: int = RTTable.MAIN,
    protocol: int = RTProtocol.STATIC,
    scope: int | None = None,
    route_type: RTNType = RTNType.UNICAST,
    prefsrc: str | None = None,
    priority: int | None = None,
) -> None:
    """Add a route to the kernel routing table.

    At least one of dst or gateway must be provided. Address family is
    auto-detected from whichever is given. Scope defaults to UNIVERSE
    when a gateway is set, LINK otherwise.

    Args:
        sock: Netlink socket from netlink_route()
        dst: Destination address (e.g. "192.168.1.0"). None for default route.
        dst_len: Destination prefix length (e.g. 24 for /24, 0 for default)
        gateway: Gateway address (e.g. "10.0.0.1")
        name: Output interface name (mutually exclusive with index)
        index: Output interface index (mutually exclusive with name)
        table: Routing table ID (default: MAIN=254)
        protocol: Route origin marker (default: STATIC)
        scope: Route scope. Auto-detected if None.
        route_type: Route type (default: UNICAST).
        prefsrc: Preferred source address for this route
        priority: Route priority/metric

    Raises:
        NetlinkError: If the route already exists (errno 17 EEXIST)
        ValueError: If neither dst nor gateway is provided
    """
    payload = _build_route_msg(
        dst,
        dst_len,
        gateway,
        name=name,
        index=index,
        table=table,
        protocol=protocol,
        scope=scope,
        route_type=route_type,
        prefsrc=prefsrc,
        priority=priority,
    )
    msg = pack_nlmsg(
        RTMType.NEWROUTE,
        NLMsgFlags.REQUEST | NLMsgFlags.ACK | NLMsgFlags.CREATE | NLMsgFlags.EXCL,
        payload,
    )
    sock.send(msg)
    try:
        recv_msgs(sock)
    except NetlinkError as e:
        if e.errno == errno.EEXIST:
            raise RouteAlreadyExists() from e
        raise


def change_route(
    sock: socket.socket,
    dst: str | None = None,
    dst_len: int = 0,
    gateway: str | None = None,
    *,
    name: str | None = None,
    index: int | None = None,
    table: int = RTTable.MAIN,
    protocol: int = RTProtocol.STATIC,
    scope: int | None = None,
    route_type: RTNType = RTNType.UNICAST,
    prefsrc: str | None = None,
    priority: int | None = None,
) -> None:
    """Replace an existing route or create it if it doesn't exist.

    Takes the same arguments as add_route. Uses NLM_F_REPLACE so the
    route is atomically replaced if it exists, or created if it doesn't.
    """
    payload = _build_route_msg(
        dst,
        dst_len,
        gateway,
        name=name,
        index=index,
        table=table,
        protocol=protocol,
        scope=scope,
        route_type=route_type,
        prefsrc=prefsrc,
        priority=priority,
    )
    msg = pack_nlmsg(
        RTMType.NEWROUTE,
        NLMsgFlags.REQUEST | NLMsgFlags.ACK | NLMsgFlags.CREATE | NLMsgFlags.REPLACE,
        payload,
    )
    sock.send(msg)
    recv_msgs(sock)


def delete_route(
    sock: socket.socket,
    dst: str | None = None,
    dst_len: int = 0,
    gateway: str | None = None,
    *,
    name: str | None = None,
    index: int | None = None,
    table: int = RTTable.MAIN,
    protocol: int = RTProtocol.STATIC,
    scope: int | None = None,
    route_type: RTNType = RTNType.UNICAST,
    prefsrc: str | None = None,
    priority: int | None = None,
) -> None:
    """Delete a route from the kernel routing table.

    The route is identified by the combination of dst, dst_len, gateway,
    output interface, and table. Takes the same arguments as add_route.

    Raises:
        RouteDoesNotExist: If the route does not exist
    """
    payload = _build_route_msg(
        dst,
        dst_len,
        gateway,
        name=name,
        index=index,
        table=table,
        protocol=protocol,
        scope=scope,
        route_type=route_type,
        prefsrc=prefsrc,
        priority=priority,
    )
    msg = pack_nlmsg(
        RTMType.DELROUTE,
        NLMsgFlags.REQUEST | NLMsgFlags.ACK,
        payload,
    )
    sock.send(msg)
    try:
        recv_msgs(sock)
    except NetlinkError as e:
        if e.errno == errno.ESRCH:
            raise RouteDoesNotExist() from e
        raise


def flush_routes(sock: socket.socket, table: int) -> None:
    """Delete all non-kernel routes from a routing table.

    Queries all routes in the given table and deletes each one,
    skipping kernel-managed routes (protocol=KERNEL). Errors on
    individual route deletions are silently ignored.

    Args:
        sock: Netlink socket from netlink_route()
        table: Routing table ID to flush
    """
    for route in get_routes(sock, table=table):
        # Skip kernel-managed routes
        if route.protocol == RTProtocol.KERNEL:
            continue
        try:
            delete_route(
                sock,
                dst=route.dst,
                dst_len=route.dst_len,
                gateway=route.gateway,
                index=route.oif,
                table=table,
                scope=route.scope,
            )
        except Exception:
            pass
