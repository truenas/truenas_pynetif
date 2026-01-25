"""Bridge interface creation and management."""

import socket
import struct

from truenas_pynetif.address._link_helpers import _create_link
from truenas_pynetif.address.constants import (
    AddressFamily,
    IFLAAttr,
    IFLABridgeAttr,
    RTMType,
)
from truenas_pynetif.netlink import DeviceNotFound
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    pack_nlattr_u32,
    pack_nlmsg,
    recv_msgs,
)

__all__ = ("create_bridge", "bridge_add_member")


def create_bridge(
    sock: socket.socket,
    name: str,
    members: list[str] | None = None,
    *,
    members_index: list[int] | None = None,
    stp: bool | None = None,
) -> None:
    """Create a bridge interface.

    Args:
        sock: Netlink socket from netlink_route()
        name: Name for the new bridge interface
        members: List of interface names to add as bridge members (mutually exclusive with members_index)
        members_index: List of interface indexes to add as bridge members (mutually exclusive with members)
        stp: Enable or disable Spanning Tree Protocol
    """
    if members and members_index:
        raise ValueError("members and members_index are mutually exclusive")

    info_data = b""
    if stp is not None:
        info_data += pack_nlattr_u32(IFLABridgeAttr.STP_STATE, 1 if stp else 0)

    _create_link(sock, name, "bridge", info_data=info_data)

    if members or members_index:
        bridge_index = socket.if_nametoindex(name)
        if members:
            for member in members:
                bridge_add_member(sock, member, master_index=bridge_index)
        else:
            for idx in members_index:
                bridge_add_member(sock, index=idx, master_index=bridge_index)


def bridge_add_member(
    sock: socket.socket,
    name: str | None = None,
    *,
    index: int | None = None,
    master: str | None = None,
    master_index: int | None = None,
) -> None:
    """Add an interface as a member of a bridge.

    Args:
        sock: Netlink socket from netlink_route()
        name: Name of interface to add (mutually exclusive with index)
        index: Index of interface to add (mutually exclusive with name)
        master: Name of the bridge interface (mutually exclusive with master_index)
        master_index: Index of the bridge interface (mutually exclusive with master)
    """
    if index is None:
        if name is None:
            raise ValueError("Either name or index must be provided")
        try:
            index = socket.if_nametoindex(name)
        except OSError:
            raise DeviceNotFound(f"No such device: {name}")

    if master_index is None:
        if master is None:
            raise ValueError("Either master or master_index must be provided")
        try:
            master_index = socket.if_nametoindex(master)
        except OSError:
            raise DeviceNotFound(f"No such device: {master}")

    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)
    attrs = pack_nlattr_u32(IFLAAttr.MASTER, master_index)
    msg = pack_nlmsg(
        RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs
    )
    sock.send(msg)
    recv_msgs(sock)
