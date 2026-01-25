"""Public API for netlink-based network interface operations.

This module re-exports functions from submodules for backwards compatibility.
"""

from truenas_pynetif.address.bond import (
    BondLacpRate,
    BondMode,
    BondXmitHashPolicy,
    bond_add_member,
    create_bond,
)
from truenas_pynetif.address.bridge import bridge_add_member, create_bridge
from truenas_pynetif.address.constants import IFOperState
from truenas_pynetif.address.dummy import create_dummy
from truenas_pynetif.address.get_ipaddresses import get_addresses, get_link_addresses
from truenas_pynetif.address.get_links import get_link, get_links, link_exists
from truenas_pynetif.address.get_routes import (
    get_default_route,
    get_link_routes,
    get_routes,
)
from truenas_pynetif.address.link import delete_link, set_link_down, set_link_up
from truenas_pynetif.address.vlan import create_vlan
from truenas_pynetif.netlink import AddressInfo, DeviceNotFound, LinkInfo, RouteInfo
from truenas_pynetif.netlink._core import netlink_route

__all__ = (
    "AddressInfo",
    "BondLacpRate",
    "BondMode",
    "BondXmitHashPolicy",
    "DeviceNotFound",
    "IFOperState",
    "LinkInfo",
    "RouteInfo",
    "bond_add_member",
    "bridge_add_member",
    "create_bond",
    "create_bridge",
    "create_dummy",
    "create_vlan",
    "delete_link",
    "get_addresses",
    "get_default_route",
    "get_link",
    "get_link_addresses",
    "get_link_routes",
    "get_links",
    "get_routes",
    "link_exists",
    "netlink_route",
    "set_link_down",
    "set_link_up",
)
