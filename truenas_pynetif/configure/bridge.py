from __future__ import annotations

from dataclasses import dataclass
import errno
import socket

from truenas_pynetif.address.bridge import (
    bridge_add_member,
    bridge_rem_member,
    create_bridge,
    get_bridge_members,
    set_bridge_learning,
    set_bridge_priority,
    set_bridge_stp,
)
from truenas_pynetif.address.get_links import get_link, get_links
from truenas_pynetif.address.link import set_link_mtu, set_link_up
from truenas_pynetif.netlink import LinkInfo, NetlinkError

__all__ = ("BridgeConfig", "configure_bridge")


@dataclass(slots=True, frozen=True, kw_only=True)
class BridgeConfig:
    name: str
    members: list[str]
    stp: bool = True
    priority: int = 32768
    mtu: int | None = None
    enable_learning: bool = True
    preserve_member_prefixes: tuple[str, ...] = ()
    """Interfaces matching these prefixes will not be removed from the bridge
    even if they are not in the members list. This is used for dynamically
    attached interfaces like "vnet*" which libvirt creates when VMs start.
    Removing these would disconnect the VM's network interface."""


def configure_bridge(
    sock: socket.socket,
    config: BridgeConfig,
    links: dict[str, LinkInfo] | None = None,
) -> None:
    """Configure a bridge interface.

    Args:
        sock: Netlink socket from netlink_route()
        config: Bridge configuration
        links: Optional dict of cached LinkInfo objects
    """
    if links is None:
        links = get_links(sock)

    # Try to create bridge (avoid TOCTOU by catching EEXIST)
    try:
        create_bridge(sock, config.name, stp=config.stp, priority=config.priority)
        links[config.name] = get_link(sock, name=config.name)
    except NetlinkError as e:
        if e.errno == errno.EEXIST:
            links[config.name] = get_link(sock, name=config.name)
        else:
            raise

    link = links[config.name]

    # Update bridge settings if changed
    if link.bridge_stp_state != (1 if config.stp else 0):
        set_bridge_stp(sock, config.stp, index=link.index)

    if link.bridge_priority != config.priority:
        set_bridge_priority(sock, config.priority, index=link.index)

    # Manage bridge members
    current_members = [m[0] for m in get_bridge_members(links, index=link.index)]
    current_members_set = set(current_members)
    desired_members_set = set(config.members)

    for member in current_members_set - desired_members_set:
        if member.startswith(config.preserve_member_prefixes):
            continue
        bridge_rem_member(sock, index=links[member].index)

    for member in desired_members_set - current_members_set:
        bridge_add_member(sock, index=links[member].index, master_index=link.index)

    # Set MTU if specified
    if config.mtu and link.mtu != config.mtu:
        set_link_mtu(sock, config.mtu, index=link.index)

    # Set learning and bring up all members
    for member in config.members:
        set_bridge_learning(sock, config.enable_learning, index=links[member].index)
        set_link_up(sock, index=links[member].index)

    # Bring up bridge
    set_link_up(sock, index=link.index)
