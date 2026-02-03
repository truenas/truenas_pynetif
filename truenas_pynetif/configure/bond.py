from __future__ import annotations

from dataclasses import dataclass
import errno
import socket
from typing import Literal

from truenas_pynetif.address.bond import (
    bond_add_member,
    bond_rem_member,
    create_bond,
    get_bond_members,
    set_bond_miimon,
    set_bond_mode,
    set_bond_primary,
    set_bond_xmit_hash_policy,
    set_lacpdu_rate,
    BondMode,
)
from truenas_pynetif.address.get_links import get_link, get_links
from truenas_pynetif.address.link import (
    delete_link,
    set_link_down,
    set_link_mtu,
    set_link_up,
)
from truenas_pynetif.netlink import LinkInfo, NetlinkError

__all__ = ("BondConfig", "configure_bond")


@dataclass(slots=True, frozen=True, kw_only=True)
class BondConfig:
    name: str
    mode: Literal["LACP", "FAILOVER", "LOADBALANCE"]
    members: list[str]
    xmit_hash_policy: str | None = None
    lacpdu_rate: str | None = None
    miimon: int = 100
    primary: str | None = None
    mtu: int = 1500


def configure_bond(
    sock: socket.socket,
    config: BondConfig,
    links: dict[str, LinkInfo] | None = None,
) -> None:
    if links is None:
        links = get_links(sock)

    mode_map = {
        "LACP": BondMode.LACP,
        "FAILOVER": BondMode.ACTIVE_BACKUP,
        "LOADBALANCE": BondMode.BALANCE_XOR,
    }
    target_mode = mode_map[config.mode]

    # Try to create bond (avoid TOCTOU by catching EEXIST)
    try:
        create_bond(
            sock,
            config.name,
            mode=target_mode,
            xmit_hash_policy=config.xmit_hash_policy,
            lacpdu_rate=config.lacpdu_rate,
            miimon=config.miimon,
            primary=config.primary,
        )
        links[config.name] = get_link(sock, name=config.name)
    except NetlinkError as e:
        if e.errno == errno.EEXIST:
            # Interface already exists, fetch it
            links[config.name] = get_link(sock, name=config.name)
        else:
            raise

    link = links[config.name]

    # Check if first member changed (requires recreate)
    current_members = [m[0] for m in get_bond_members(links, index=link.index)]
    if current_members and config.members and current_members[0] != config.members[0]:
        delete_link(sock, index=link.index)
        create_bond(
            sock,
            config.name,
            mode=target_mode,
            xmit_hash_policy=config.xmit_hash_policy,
            lacpdu_rate=config.lacpdu_rate,
            miimon=config.miimon,
            primary=config.primary,
        )
        links[config.name] = get_link(sock, name=config.name)
        link = links[config.name]
        current_members = []

    # Update bond settings if changed
    needs_down = False
    if link.bond_mode != target_mode:
        needs_down = True
    if (
        config.xmit_hash_policy
        and link.bond_xmit_hash_policy != config.xmit_hash_policy
    ):
        needs_down = True
    if config.lacpdu_rate and link.bond_lacpdu_rate != config.lacpdu_rate:
        needs_down = True
    if config.primary and link.bond_primary != socket.if_nametoindex(config.primary):
        needs_down = True
    if config.miimon and link.bond_miimon != config.miimon:
        needs_down = True

    if needs_down:
        set_link_down(sock, index=link.index)

        # Remove all members before changing mode
        if link.bond_mode != target_mode:
            for member in current_members:
                bond_rem_member(sock, index=links[member].index)
            set_bond_mode(sock, target_mode, index=link.index)
            current_members = []

        if config.xmit_hash_policy:
            set_bond_xmit_hash_policy(sock, config.xmit_hash_policy, index=link.index)
        if config.lacpdu_rate:
            set_lacpdu_rate(sock, config.lacpdu_rate, index=link.index)
        if config.miimon:
            set_bond_miimon(sock, config.miimon, index=link.index)
        if config.primary:
            set_bond_primary(sock, config.primary, index=link.index)

        set_link_up(sock, index=link.index)
        links[config.name] = get_link(sock, name=config.name)

    # Update members
    current_members = [m[0] for m in get_bond_members(links, index=link.index)]
    current_members_set = set(current_members)
    desired_members_set = set(config.members)

    for member in current_members_set - desired_members_set:
        bond_rem_member(sock, index=links[member].index)

    for member in desired_members_set - current_members_set:
        bond_add_member(sock, index=links[member].index, master_index=link.index)

    # Bring up all members
    for member in config.members:
        set_link_up(sock, index=links[member].index)

    # Set MTU if specified
    if config.mtu:
        set_link_mtu(sock, config.mtu, index=link.index)

    # Bring up bond
    set_link_up(sock, index=link.index)
