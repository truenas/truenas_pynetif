"""Link state manipulation functions."""

import socket
import struct

from truenas_pynetif.address._link_helpers import _set_link_flags
from truenas_pynetif.address.constants import AddressFamily, IFFlags, RTMType
from truenas_pynetif.netlink import DeviceNotFound
from truenas_pynetif.netlink._core import NLMsgFlags, pack_nlmsg, recv_msgs

__all__ = ("set_link_up", "set_link_down", "delete_link")


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


def delete_link(
    sock: socket.socket, name: str | None = None, *, index: int | None = None
) -> None:
    """Delete a virtual interface (vlan, bond, dummy, etc)."""
    if index is None:
        if name is None:
            raise ValueError("Either name or index must be provided")
        try:
            index = socket.if_nametoindex(name)
        except OSError:
            raise DeviceNotFound(f"No such device: {name}")

    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)
    msg = pack_nlmsg(RTMType.DELLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg)
    sock.send(msg)
    recv_msgs(sock)
