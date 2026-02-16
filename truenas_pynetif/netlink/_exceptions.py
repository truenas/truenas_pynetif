from __future__ import annotations

import errno

__all__ = [
    "AddressAlreadyExists",
    "AddressDoesNotExist",
    "NetlinkError",
    "DeviceNotFound",
    "OperationNotSupported",
    "DumpInterrupted",
    "BondHasMembers",
    "InterfaceAlreadyExists",
    "ParentInterfaceNotFound",
    "RouteAlreadyExists",
    "RouteDoesNotExist",
]


class NetlinkError(Exception):
    def __init__(self, message: str, error_code: int | None = None):
        super().__init__(message)
        self.errno = error_code


class DeviceNotFound(NetlinkError):
    pass


class OperationNotSupported(NetlinkError):
    pass


class DumpInterrupted(NetlinkError):
    pass


class BondHasMembers(NetlinkError):
    pass


class InterfaceAlreadyExists(NetlinkError):
    def __init__(self, name: str):
        super().__init__(f"Interface {name!r} already exists")
        self.errno = errno.EEXIST
        self.name = name


class ParentInterfaceNotFound(NetlinkError):
    def __init__(self, parent: str):
        super().__init__(f"Parent interface {parent!r} not found")
        self.errno = errno.ENOENT
        self.parent = parent


class RouteAlreadyExists(NetlinkError):
    def __init__(self) -> None:
        super().__init__("Route already exists")
        self.errno = errno.EEXIST


class RouteDoesNotExist(NetlinkError):
    def __init__(self) -> None:
        super().__init__("Route does not exist")
        self.errno = errno.ESRCH


class AddressAlreadyExists(NetlinkError):
    def __init__(self, address: str):
        super().__init__(f"Address {address!r} already exists on interface")
        self.errno = errno.EEXIST
        self.address = address


class AddressDoesNotExist(NetlinkError):
    def __init__(self, address: str):
        super().__init__(f"Address {address!r} does not exist on interface")
        self.errno = errno.EADDRNOTAVAIL
        self.address = address
