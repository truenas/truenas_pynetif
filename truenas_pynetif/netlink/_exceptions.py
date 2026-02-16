import errno

__all__ = [
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
        super().__init__("Route already exists", error_code=errno.EEXIST)


class RouteDoesNotExist(NetlinkError):
    def __init__(self) -> None:
        super().__init__("Route does not exist", error_code=errno.ESRCH)
