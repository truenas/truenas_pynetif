import socket
import struct

from truenas_pynetif.address._link_helpers import _resolve_index, _set_link_flags
from truenas_pynetif.address.constants import AddressFamily, IFFlags, IFLAAttr, RTMType
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    pack_nlattr_u32,
    pack_nlmsg,
    recv_msgs,
)

__all__ = ("set_link_up", "set_link_down", "set_link_mtu", "delete_link")


def set_link_up(
    sock: socket.socket, name: str | None = None, *, index: int | None = None
) -> None:
    """Bring a network interface up."""
    _set_link_flags(sock, IFFlags.UP, IFFlags.UP, name=name, index=index)


def set_link_down(
    sock: socket.socket, name: str | None = None, *, index: int | None = None
) -> None:
    """Bring a network interface down."""
    _set_link_flags(sock, 0, IFFlags.UP, name=name, index=index)


def set_link_mtu(
    sock: socket.socket,
    mtu: int,
    name: str | None = None,
    *,
    index: int | None = None,
) -> None:
    """Set the MTU of a network interface.

    Args:
        sock: Netlink socket from netlink_route()
        mtu: Maximum transmission unit size in bytes
        name: Interface name (mutually exclusive with index)
        index: Interface index (mutually exclusive with name)
    """
    index = _resolve_index(name, index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)
    attrs = pack_nlattr_u32(IFLAAttr.MTU, mtu)
    msg = pack_nlmsg(RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs)
    sock.send(msg)
    recv_msgs(sock)


def delete_link(
    sock: socket.socket, name: str | None = None, *, index: int | None = None
) -> None:
    """Delete a virtual interface (vlan, bond, dummy, etc)."""
    index = _resolve_index(name, index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)
    msg = pack_nlmsg(RTMType.DELLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg)
    sock.send(msg)
    recv_msgs(sock)
