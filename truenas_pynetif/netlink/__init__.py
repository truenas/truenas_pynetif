from truenas_pynetif.netlink.dataclass_types import AddressInfo, LinkInfo, RouteInfo
from truenas_pynetif.netlink._core import netlink_route, netlink_generic
from truenas_pynetif.netlink._exceptions import (
    DeviceNotFound,
    DumpInterrupted,
    NetlinkError,
    OperationNotSupported,
)

__all__ = (
    "AddressInfo",
    "DeviceNotFound",
    "DumpInterrupted",
    "LinkInfo",
    "NetlinkError",
    "OperationNotSupported",
    "RouteInfo",
    "netlink_generic",
    "netlink_route",
)
