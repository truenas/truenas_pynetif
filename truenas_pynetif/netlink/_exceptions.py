__all__ = ['NetlinkError', 'DeviceNotFound', 'OperationNotSupported', 'DumpInterrupted', 'BondHasMembers']


class NetlinkError(Exception):
    pass


class DeviceNotFound(NetlinkError):
    pass


class OperationNotSupported(NetlinkError):
    pass


class DumpInterrupted(NetlinkError):
    pass


class BondHasMembers(NetlinkError):
    pass
