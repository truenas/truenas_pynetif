from __future__ import annotations

from dataclasses import dataclass
import errno
import socket

from truenas_pynetif.address.vlan import create_vlan
from truenas_pynetif.address.get_links import get_link, get_links
from truenas_pynetif.address.link import delete_link, set_link_up, set_link_mtu
from truenas_pynetif.netlink import LinkInfo, NetlinkError, ParentInterfaceNotFound

__all__ = ("VlanConfig", "configure_vlan")


@dataclass(slots=True, frozen=True, kw_only=True)
class VlanConfig:
    name: str
    parent: str
    tag: int
    mtu: int | None = None


def configure_vlan(
    sock: socket.socket,
    config: VlanConfig,
    links: dict[str, LinkInfo] | None = None,
) -> None:
    """Configure a VLAN interface.

    Args:
        sock: Netlink socket from netlink_route()
        config: VLAN configuration
        links: Optional dict of cached LinkInfo objects

    Raises:
        ParentInterfaceNotFound: If parent interface does not exist
    """
    if links is None:
        links = get_links(sock)

    # Verify parent interface exists
    try:
        parent_idx = socket.if_nametoindex(config.parent)
    except OSError:
        raise ParentInterfaceNotFound(config.parent)

    # Get parent link to validate MTU
    parent_link = links.get(config.parent)
    if not parent_link:
        parent_link = get_link(sock, name=config.parent)
        links[config.parent] = parent_link

    # Try to create VLAN (avoid TOCTOU by catching EEXIST)
    try:
        create_vlan(sock, config.name, config.tag, parent=config.parent)
        links[config.name] = get_link(sock, name=config.name)
    except NetlinkError as e:
        if e.errno == errno.EEXIST:
            links[config.name] = get_link(sock, name=config.name)
        else:
            raise

    link = links[config.name]

    # Check if parent or tag changed (requires recreation)
    if link.vlan_parent != parent_idx or link.vlan_id != config.tag:
        delete_link(sock, index=link.index)
        create_vlan(sock, config.name, config.tag, parent=config.parent)
        links[config.name] = get_link(sock, name=config.name)
        link = links[config.name]

    # Set MTU if specified and different
    if config.mtu and link.mtu != config.mtu:
        # TODO: Validate VLAN MTU <= parent MTU, either log warning or raise ValueError
        if config.mtu <= parent_link.mtu:
            set_link_mtu(sock, config.mtu, index=link.index)

    # Bring up parent interface
    set_link_up(sock, index=parent_link.index)

    # Bring up VLAN interface
    set_link_up(sock, index=link.index)
