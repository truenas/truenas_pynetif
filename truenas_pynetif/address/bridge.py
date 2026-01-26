import socket
import struct

from truenas_pynetif.address._link_helpers import _create_link, _resolve_index
from truenas_pynetif.address.constants import (
    AddressFamily,
    IFLAAttr,
    IFLABridgeAttr,
    IFLAInfoAttr,
    RTMType,
)
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    pack_nlattr_nested,
    pack_nlattr_str,
    pack_nlattr_u16,
    pack_nlattr_u32,
    pack_nlmsg,
    recv_msgs,
)

__all__ = (
    "create_bridge",
    "bridge_add_member",
    "bridge_rem_member",
    "set_bridge_priority",
    "set_bridge_stp",
)


def create_bridge(
    sock: socket.socket,
    name: str,
    members: list[str] | None = None,
    *,
    members_index: list[int] | None = None,
    stp: bool | None = True,
    priority: int | None = 32768,
) -> None:
    """Create a bridge interface.

    Args:
        sock: Netlink socket from netlink_route()
        name: Name for the new bridge interface
        members: List of interface names to add as bridge members (mutually exclusive with members_index)
        members_index: List of interface indexes to add as bridge members (mutually exclusive with members)
        stp: Enable or disable Spanning Tree Protocol
        priority: Bridge priority for STP (0-65535, lower = higher priority, default 32768)
    """
    if members and members_index:
        raise ValueError("members and members_index are mutually exclusive")

    info_data = b""
    if stp is not None:
        info_data += pack_nlattr_u32(IFLABridgeAttr.STP_STATE, 1 if stp else 0)
    if priority is not None:
        info_data += pack_nlattr_u16(IFLABridgeAttr.PRIORITY, priority)

    _create_link(sock, name, "bridge", info_data=info_data)

    if members or members_index:
        bridge_index = socket.if_nametoindex(name)
        if members:
            for member in members:
                bridge_add_member(sock, member, master_index=bridge_index)
        elif members_index:
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
    index = _resolve_index(name, index)
    master_index = _resolve_index(master, master_index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)
    attrs = pack_nlattr_u32(IFLAAttr.MASTER, master_index)
    msg = pack_nlmsg(
        RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs
    )
    sock.send(msg)
    recv_msgs(sock)


def bridge_rem_member(
    sock: socket.socket,
    name: str | None = None,
    *,
    index: int | None = None,
) -> None:
    """Remove an interface from its bridge.

    Args:
        sock: Netlink socket from netlink_route()
        name: Name of interface to remove (mutually exclusive with index)
        index: Index of interface to remove (mutually exclusive with name)
    """
    index = _resolve_index(name, index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)
    attrs = pack_nlattr_u32(IFLAAttr.MASTER, 0)
    msg = pack_nlmsg(
        RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs
    )
    sock.send(msg)
    recv_msgs(sock)


def set_bridge_priority(
    sock: socket.socket,
    priority: int,
    name: str | None = None,
    *,
    index: int | None = None,
) -> None:
    """Set the STP priority of a bridge interface.

    Args:
        sock: Netlink socket from netlink_route()
        priority: Bridge priority (0-65535, lower = higher priority, default 32768)
        name: Bridge interface name (mutually exclusive with index)
        index: Bridge interface index (mutually exclusive with name)
    """
    index = _resolve_index(name, index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)

    info_data = pack_nlattr_u16(IFLABridgeAttr.PRIORITY, priority)
    linkinfo = pack_nlattr_str(IFLAInfoAttr.KIND, "bridge")
    linkinfo += pack_nlattr_nested(IFLAInfoAttr.DATA, info_data)
    attrs = pack_nlattr_nested(IFLAAttr.LINKINFO, linkinfo)

    msg = pack_nlmsg(
        RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs
    )
    sock.send(msg)
    recv_msgs(sock)


def set_bridge_stp(
    sock: socket.socket,
    stp: bool,
    name: str | None = None,
    *,
    index: int | None = None,
) -> None:
    """Enable or disable Spanning Tree Protocol on a bridge interface.

    Args:
        sock: Netlink socket from netlink_route()
        stp: True to enable STP, False to disable
        name: Bridge interface name (mutually exclusive with index)
        index: Bridge interface index (mutually exclusive with name)
    """
    index = _resolve_index(name, index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)

    info_data = pack_nlattr_u32(IFLABridgeAttr.STP_STATE, 1 if stp else 0)
    linkinfo = pack_nlattr_str(IFLAInfoAttr.KIND, "bridge")
    linkinfo += pack_nlattr_nested(IFLAInfoAttr.DATA, info_data)
    attrs = pack_nlattr_nested(IFLAAttr.LINKINFO, linkinfo)

    msg = pack_nlmsg(
        RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs
    )
    sock.send(msg)
    recv_msgs(sock)
