import errno
import socket
import struct

from truenas_pynetif.address._link_helpers import _create_link, _resolve_index
from truenas_pynetif.address.constants import (
    AddressFamily,
    BondLacpRate,
    BondMode,
    BondXmitHashPolicy,
    IFLAAttr,
    IFLABondAttr,
    IFLAInfoAttr,
    RTMType,
)
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    pack_nlattr_nested,
    pack_nlattr_str,
    pack_nlattr_u8,
    pack_nlattr_u32,
    pack_nlmsg,
    recv_msgs,
)
from truenas_pynetif.netlink._exceptions import BondHasMembers, NetlinkError

__all__ = (
    "create_bond",
    "bond_add_member",
    "bond_rem_member",
    "set_bond_mode",
    "set_bond_primary",
    "set_bond_xmit_hash_policy",
    "set_lacpdu_rate",
    "BondHasMembers",
    "BondMode",
    "BondLacpRate",
    "BondXmitHashPolicy",
)


def create_bond(
    sock: socket.socket,
    name: str,
    mode: BondMode | None = None,
    members: list[str] | None = None,
    *,
    members_index: list[int] | None = None,
    xmit_hash_policy: BondXmitHashPolicy | None = None,
    lacpdu_rate: BondLacpRate | None = None,
    miimon: int | None = None,
    primary: str | None = None,
    primary_index: int | None = None,
) -> None:
    """Create a bond interface.

    Args:
        sock: Netlink socket from netlink_route()
        name: Name for the new bond interface
        mode: Bond mode (default: BALANCE_RR). Options include:
            - BondMode.BALANCE_RR (0): Round-robin
            - BondMode.ACTIVE_BACKUP (1): Failover
            - BondMode.BALANCE_XOR (2): XOR
            - BondMode.BROADCAST (3): Broadcast
            - BondMode.LACP (4): 802.3ad
            - BondMode.BALANCE_TLB (5): Adaptive transmit load balancing
            - BondMode.BALANCE_ALB (6): Adaptive load balancing
        members: List of interface names to add as bond members (mutually exclusive with members_index)
        members_index: List of interface indexes to add as bond members (mutually exclusive with members)
        xmit_hash_policy: Transmit hash policy for BALANCE_XOR and LACP modes
        lacpdu_rate: LACPDU packet rate for LACP mode (SLOW=every 30s, FAST=every 1s)
        miimon: MII link monitoring interval in milliseconds
        primary: Primary interface name for ACTIVE_BACKUP mode (mutually exclusive with primary_index)
        primary_index: Primary interface index for ACTIVE_BACKUP mode (mutually exclusive with primary)
    """
    if members and members_index:
        raise ValueError("members and members_index are mutually exclusive")
    if primary and primary_index:
        raise ValueError("primary and primary_index are mutually exclusive")

    info_data = b""
    if mode is not None:
        info_data += pack_nlattr_u8(IFLABondAttr.MODE, mode)
    if xmit_hash_policy is not None:
        info_data += pack_nlattr_u8(IFLABondAttr.XMIT_HASH_POLICY, xmit_hash_policy)
    if lacpdu_rate is not None:
        info_data += pack_nlattr_u8(IFLABondAttr.AD_LACP_RATE, lacpdu_rate)
    if miimon is not None:
        info_data += pack_nlattr_u32(IFLABondAttr.MIIMON, miimon)

    _create_link(sock, name, "bond", info_data=info_data)

    # Add members after bond is created
    if members or members_index:
        bond_index = socket.if_nametoindex(name)
        if members:
            for member in members:
                bond_add_member(sock, member, master_index=bond_index)
        elif members_index:
            for idx in members_index:
                bond_add_member(sock, index=idx, master_index=bond_index)

    # Set primary after members are added
    if primary or primary_index:
        set_bond_primary(sock, primary, primary_index=primary_index, name=name)


def set_bond_primary(
    sock: socket.socket,
    primary: str | None = None,
    *,
    primary_index: int | None = None,
    name: str | None = None,
    index: int | None = None,
) -> None:
    """Set the primary interface for a bond.

    Args:
        sock: Netlink socket from netlink_route()
        primary: Name of the primary interface (mutually exclusive with primary_index)
        primary_index: Index of the primary interface (mutually exclusive with primary)
        name: Bond interface name (mutually exclusive with index)
        index: Bond interface index (mutually exclusive with name)
    """
    bond_index = _resolve_index(name, index)
    primary_index = _resolve_index(primary, primary_index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, bond_index, 0, 0)

    info_data = pack_nlattr_u32(IFLABondAttr.PRIMARY, primary_index)
    linkinfo = pack_nlattr_str(IFLAInfoAttr.KIND, "bond")
    linkinfo += pack_nlattr_nested(IFLAInfoAttr.DATA, info_data)
    attrs = pack_nlattr_nested(IFLAAttr.LINKINFO, linkinfo)

    msg = pack_nlmsg(
        RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs
    )
    sock.send(msg)
    recv_msgs(sock)


def bond_add_member(
    sock: socket.socket,
    name: str | None = None,
    *,
    index: int | None = None,
    master: str | None = None,
    master_index: int | None = None,
) -> None:
    """Add an interface as a member of a bond.

    Args:
        sock: Netlink socket from netlink_route()
        name: Name of interface to add (mutually exclusive with index)
        index: Index of interface to add (mutually exclusive with name)
        master: Name of the bond interface (mutually exclusive with master_index)
        master_index: Index of the bond interface (mutually exclusive with master)
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


def bond_rem_member(
    sock: socket.socket,
    name: str | None = None,
    *,
    index: int | None = None,
) -> None:
    """Remove an interface from its bond.

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


def set_bond_mode(
    sock: socket.socket,
    mode: BondMode,
    name: str | None = None,
    *,
    index: int | None = None,
) -> None:
    """Set the mode of a bond interface.

    Note:
        A bond's mode cannot be changed while members are attached.
        Remove all members first using bond_rem_member().

    Args:
        sock: Netlink socket from netlink_route()
        mode: Bond mode to set (see BondMode enum)
        name: Bond interface name (mutually exclusive with index)
        index: Bond interface index (mutually exclusive with name)

    Raises:
        BondHasMembers: If the bond has members attached.
    """
    index = _resolve_index(name, index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)

    info_data = pack_nlattr_u8(IFLABondAttr.MODE, mode)
    linkinfo = pack_nlattr_str(IFLAInfoAttr.KIND, "bond")
    linkinfo += pack_nlattr_nested(IFLAInfoAttr.DATA, info_data)
    attrs = pack_nlattr_nested(IFLAAttr.LINKINFO, linkinfo)

    msg = pack_nlmsg(
        RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs
    )
    sock.send(msg)
    try:
        recv_msgs(sock)
    except NetlinkError as e:
        if str(errno.ENOTEMPTY) in str(e):
            raise BondHasMembers(
                "Cannot change bond mode while members are attached. "
                "Remove members first with bond_rem_member()."
            ) from e
        raise


def set_bond_xmit_hash_policy(
    sock: socket.socket,
    xmit_hash_policy: BondXmitHashPolicy,
    name: str | None = None,
    *,
    index: int | None = None,
) -> None:
    """Set the transmit hash policy of a bond interface.

    Args:
        sock: Netlink socket from netlink_route()
        xmit_hash_policy: Transmit hash policy to set (see BondXmitHashPolicy enum)
        name: Bond interface name (mutually exclusive with index)
        index: Bond interface index (mutually exclusive with name)
    """
    index = _resolve_index(name, index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)

    info_data = pack_nlattr_u8(IFLABondAttr.XMIT_HASH_POLICY, xmit_hash_policy)
    linkinfo = pack_nlattr_str(IFLAInfoAttr.KIND, "bond")
    linkinfo += pack_nlattr_nested(IFLAInfoAttr.DATA, info_data)
    attrs = pack_nlattr_nested(IFLAAttr.LINKINFO, linkinfo)

    msg = pack_nlmsg(
        RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs
    )
    sock.send(msg)
    recv_msgs(sock)


def set_lacpdu_rate(
    sock: socket.socket,
    lacpdu_rate: BondLacpRate,
    name: str | None = None,
    *,
    index: int | None = None,
) -> None:
    """Set the LACPDU rate of a bond interface.

    Args:
        sock: Netlink socket from netlink_route()
        lacpdu_rate: LACPDU rate to set (SLOW=every 30s, FAST=every 1s)
        name: Bond interface name (mutually exclusive with index)
        index: Bond interface index (mutually exclusive with name)
    """
    index = _resolve_index(name, index)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)

    info_data = pack_nlattr_u8(IFLABondAttr.AD_LACP_RATE, lacpdu_rate)
    linkinfo = pack_nlattr_str(IFLAInfoAttr.KIND, "bond")
    linkinfo += pack_nlattr_nested(IFLAInfoAttr.DATA, info_data)
    attrs = pack_nlattr_nested(IFLAAttr.LINKINFO, linkinfo)

    msg = pack_nlmsg(
        RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg + attrs
    )
    sock.send(msg)
    recv_msgs(sock)
