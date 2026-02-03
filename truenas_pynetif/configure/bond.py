from __future__ import annotations

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

__all__ = ("configure_bond",)


def configure_bond(
    sock: socket.socket,
    name: str,
    mode: Literal["LACP", "FAILOVER", "LOADBALANCE"],
    members: list[str],
    links: dict[str, LinkInfo] | None = None,
    *,
    xmit_hash_policy: str | None = None,
    lacpdu_rate: str | None = None,
    miimon: int | None = 100,
    primary: str | None = None,
    mtu: int | None = 1500,
) -> None:
    if links is None:
        links = get_links(sock)

    mode_map = {
        "LACP": BondMode.LACP,
        "FAILOVER": BondMode.ACTIVE_BACKUP,
        "LOADBALANCE": BondMode.BALANCE_XOR,
    }
    target_mode = mode_map[mode]

    # Try to create bond (avoid TOCTOU by catching EEXIST)
    try:
        create_bond(
            sock,
            name,
            mode=target_mode,
            xmit_hash_policy=xmit_hash_policy,
            lacpdu_rate=lacpdu_rate,
            miimon=miimon,
            primary=primary,
        )
        links[name] = get_link(sock, name=name)
    except NetlinkError as e:
        if e.errno == errno.EEXIST:
            # Interface already exists, fetch it
            links[name] = get_link(sock, name=name)
        else:
            raise

    link = links[name]

    # Check if first member changed (requires recreate)
    current_members = [m[0] for m in get_bond_members(links, index=link.index)]
    if current_members and members and current_members[0] != members[0]:
        delete_link(sock, index=link.index)
        create_bond(
            sock,
            name,
            mode=target_mode,
            xmit_hash_policy=xmit_hash_policy,
            lacpdu_rate=lacpdu_rate,
            miimon=miimon,
            primary=primary,
        )
        links[name] = get_link(sock, name=name)
        link = links[name]
        current_members = []

    # Update bond settings if changed
    needs_down = False
    if link.bond_mode != target_mode:
        needs_down = True
    if xmit_hash_policy and link.bond_xmit_hash_policy != xmit_hash_policy:
        needs_down = True
    if lacpdu_rate and link.bond_lacpdu_rate != lacpdu_rate:
        needs_down = True
    if primary and link.bond_primary != socket.if_nametoindex(primary):
        needs_down = True
    if miimon and link.bond_miimon != miimon:
        needs_down = True

    if needs_down:
        set_link_down(sock, index=link.index)

        # Remove all members before changing mode
        if link.bond_mode != target_mode:
            for member in current_members:
                bond_rem_member(sock, index=links[member].index)
            set_bond_mode(sock, target_mode, index=link.index)
            current_members = []

        if xmit_hash_policy:
            set_bond_xmit_hash_policy(sock, xmit_hash_policy, index=link.index)
        if lacpdu_rate:
            set_lacpdu_rate(sock, lacpdu_rate, index=link.index)
        if miimon:
            set_bond_miimon(sock, miimon, index=link.index)
        if primary:
            set_bond_primary(sock, primary, index=link.index)

        set_link_up(sock, index=link.index)
        links[name] = get_link(sock, name=name)

    # Update members
    current_members = [m[0] for m in get_bond_members(links, index=link.index)]
    current_members_set = set(current_members)
    desired_members_set = set(members)

    for member in current_members_set - desired_members_set:
        bond_rem_member(sock, index=links[member].index)

    for member in desired_members_set - current_members_set:
        bond_add_member(sock, index=links[member].index, master_index=link.index)

    # Bring up all members
    for member in members:
        set_link_up(sock, index=links[member].index)

    # Set MTU if specified
    if mtu:
        set_link_mtu(sock, mtu, index=link.index)

    # Bring up bond
    set_link_up(sock, index=link.index)
