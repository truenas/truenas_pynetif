import errno

__all__ = [
    "NetlinkError",
    "DeviceNotFound",
    "OperationNotSupported",
    "DumpInterrupted",
    "BondHasMembers",
    "InterfaceAlreadyExists",
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
