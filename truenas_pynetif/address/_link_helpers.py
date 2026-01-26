import socket
import struct

from truenas_pynetif.address.constants import (
    AddressFamily,
    IFLAAttr,
    IFLAInfoAttr,
    RTMType,
)
from truenas_pynetif.netlink import DeviceNotFound
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    pack_nlattr_nested,
    pack_nlattr_str,
    pack_nlmsg,
    recv_msgs,
)


def _resolve_index(name: str | None = None, index: int | None = None) -> int:
    """Resolve interface name to index, or return index if provided.

    Args:
        name: Interface name (mutually exclusive with index)
        index: Interface index (mutually exclusive with name)

    Returns:
        Interface index

    Raises:
        ValueError: If neither name nor index is provided
        DeviceNotFound: If the named interface does not exist
    """
    if index is not None:
        return index
    if name is None:
        raise ValueError("Either name or index must be provided")
    try:
        return socket.if_nametoindex(name)
    except OSError:
        raise DeviceNotFound(f"No such device: {name}")


def _create_link(
    sock: socket.socket,
    name: str,
    kind: str,
    *,
    info_data: bytes = b"",
    extra_attrs: bytes = b"",
) -> None:
    """Create a virtual interface via RTM_NEWLINK."""
    # ifinfomsg: family(1) + pad(1) + type(2) + index(4) + flags(4) + change(4)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, 0, 0, 0)

    # Build IFLA_LINKINFO nested attribute
    linkinfo_attrs = pack_nlattr_str(IFLAInfoAttr.KIND, kind)
    if info_data:
        linkinfo_attrs += pack_nlattr_nested(IFLAInfoAttr.DATA, info_data)

    attrs = pack_nlattr_str(IFLAAttr.IFNAME, name)
    attrs += extra_attrs
    attrs += pack_nlattr_nested(IFLAAttr.LINKINFO, linkinfo_attrs)

    flags = NLMsgFlags.REQUEST | NLMsgFlags.ACK | NLMsgFlags.EXCL | NLMsgFlags.CREATE
    msg = pack_nlmsg(RTMType.NEWLINK, flags, ifinfomsg + attrs)
    sock.send(msg)
    recv_msgs(sock)


def _set_link_flags(
    sock: socket.socket,
    flags: int,
    change: int,
    *,
    name: str | None = None,
    index: int | None = None,
) -> None:
    """Set interface flags via RTM_NEWLINK."""
    index = _resolve_index(name, index)

    # ifinfomsg: family(1) + pad(1) + type(2) + index(4) + flags(4) + change(4)
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, flags, change)
    msg = pack_nlmsg(RTMType.NEWLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg)
    sock.send(msg)
    recv_msgs(sock)
