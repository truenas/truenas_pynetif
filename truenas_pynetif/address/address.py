import ipaddress
import socket
import struct

from truenas_pynetif.address._link_helpers import _resolve_index
from truenas_pynetif.address.constants import (
    AddressFamily,
    IFAAttr,
    RTMType,
)
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    pack_nlattr,
    pack_nlmsg,
    recv_msgs,
)

__all__ = ("add_address", "remove_address")


def _parse_address_params(
    address: str, name: str | None, index: int | None
) -> tuple[int, int, ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse and validate address parameters.

    Returns:
        Tuple of (interface_index, address_family, address_object)
    """
    ifindex = _resolve_index(name, index)

    try:
        addr_obj = ipaddress.ip_address(address)
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {address}") from e

    if isinstance(addr_obj, ipaddress.IPv4Address):
        family = AddressFamily.INET
    else:
        family = AddressFamily.INET6

    return ifindex, family, addr_obj


def add_address(
    sock: socket.socket,
    address: str,
    prefixlen: int,
    name: str | None = None,
    *,
    index: int | None = None,
    broadcast: str | None = None,
) -> None:
    """Add an IP address to an interface.

    Args:
        sock: Netlink socket from netlink_route()
        address: IP address string (e.g., "192.168.1.10" or "2001:db8::1")
        prefixlen: Prefix length (e.g., 24 for /24)
        name: Interface name (mutually exclusive with index)
        index: Interface index (mutually exclusive with name)
        broadcast: Broadcast address for IPv4 (auto-calculated if None)
    """
    ifindex, family, addr_obj = _parse_address_params(address, name, index)
    addr_bytes = addr_obj.packed

    if isinstance(addr_obj, ipaddress.IPv4Address):
        # Calculate broadcast if not provided
        if broadcast is None:
            network = ipaddress.IPv4Network(f"{address}/{prefixlen}", strict=False)
            bcast_bytes = network.broadcast_address.packed
        else:
            bcast_bytes = ipaddress.IPv4Address(broadcast).packed
    else:
        bcast_bytes = None

    # Build ifaddrmsg header
    ifaddrmsg = struct.pack("BBBBI", family, prefixlen, 0, 0, ifindex)

    # Build attributes
    attrs = b""
    attrs += pack_nlattr(IFAAttr.LOCAL, addr_bytes)
    attrs += pack_nlattr(IFAAttr.ADDRESS, addr_bytes)
    if bcast_bytes:
        attrs += pack_nlattr(IFAAttr.BROADCAST, bcast_bytes)

    # Send message
    msg = pack_nlmsg(
        RTMType.NEWADDR,
        NLMsgFlags.REQUEST | NLMsgFlags.ACK | NLMsgFlags.CREATE | NLMsgFlags.EXCL,
        ifaddrmsg + attrs,
    )
    sock.send(msg)
    recv_msgs(sock)


def remove_address(
    sock: socket.socket,
    address: str,
    prefixlen: int,
    name: str | None = None,
    *,
    index: int | None = None,
) -> None:
    """Remove an IP address from an interface.

    Args:
        sock: Netlink socket from netlink_route()
        address: IP address string (e.g., "192.168.1.10" or "2001:db8::1")
        prefixlen: Prefix length (e.g., 24 for /24)
        name: Interface name (mutually exclusive with index)
        index: Interface index (mutually exclusive with name)
    """
    ifindex, family, addr_obj = _parse_address_params(address, name, index)
    addr_bytes = addr_obj.packed

    # Build ifaddrmsg header
    ifaddrmsg = struct.pack("BBBBI", family, prefixlen, 0, 0, ifindex)

    # Build attributes
    attrs = b""
    attrs += pack_nlattr(IFAAttr.LOCAL, addr_bytes)
    attrs += pack_nlattr(IFAAttr.ADDRESS, addr_bytes)

    # Send message
    msg = pack_nlmsg(
        RTMType.DELADDR,
        NLMsgFlags.REQUEST | NLMsgFlags.ACK,
        ifaddrmsg + attrs,
    )
    sock.send(msg)
    recv_msgs(sock)
