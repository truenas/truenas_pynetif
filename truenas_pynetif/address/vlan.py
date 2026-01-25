"""VLAN interface creation."""

import socket

from truenas_pynetif.address._link_helpers import _create_link
from truenas_pynetif.address.constants import IFLAAttr, IFLAVlanAttr
from truenas_pynetif.netlink import DeviceNotFound
from truenas_pynetif.netlink._core import pack_nlattr_u16, pack_nlattr_u32

__all__ = ("create_vlan",)


def create_vlan(
    sock: socket.socket,
    name: str,
    vlan_id: int,
    parent: str | None = None,
    *,
    parent_index: int | None = None,
) -> None:
    """Create a VLAN interface.

    Args:
        sock: Netlink socket from netlink_route()
        name: Name for the new VLAN interface
        vlan_id: VLAN ID (1-4094)
        parent: Parent interface name (mutually exclusive with parent_index)
        parent_index: Parent interface index (mutually exclusive with parent)
    """
    if parent_index is None:
        if parent is None:
            raise ValueError("Either parent or parent_index must be provided")
        try:
            parent_index = socket.if_nametoindex(parent)
        except OSError:
            raise DeviceNotFound(f"No such device: {parent}")

    info_data = pack_nlattr_u16(IFLAVlanAttr.ID, vlan_id)
    extra_attrs = pack_nlattr_u32(IFLAAttr.LINK, parent_index)
    _create_link(sock, name, "vlan", info_data=info_data, extra_attrs=extra_attrs)
