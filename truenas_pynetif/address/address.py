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

__all__ = ("add_address",)


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
    ifindex = _resolve_index(name, index)

    # Parse address to determine family
    try:
        addr_obj = ipaddress.ip_address(address)
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {address}") from e

    if isinstance(addr_obj, ipaddress.IPv4Address):
        family = AddressFamily.INET
        addr_bytes = addr_obj.packed

        # Calculate broadcast if not provided
        if broadcast is None:
            network = ipaddress.IPv4Network(f"{address}/{prefixlen}", strict=False)
            bcast_bytes = network.broadcast_address.packed
        else:
            bcast_bytes = ipaddress.IPv4Address(broadcast).packed
    else:
        family = AddressFamily.INET6
        addr_bytes = addr_obj.packed
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
