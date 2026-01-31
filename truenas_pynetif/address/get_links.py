import socket
import struct

from truenas_pynetif.address.constants import (
    AddressFamily,
    IFLAAttr,
    IFLABondAttr,
    IFLABridgeAttr,
    IFLAInfoAttr,
    IFLAVlanAttr,
    RTEXTFilter,
    RTMType,
)
from truenas_pynetif.netlink import DeviceNotFound, LinkInfo
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    pack_nlattr_u32,
    pack_nlmsg,
    parse_attrs,
    recv_msgs,
)

__all__ = ("get_links", "get_link", "link_exists")


def _parse_link_payload(payload: bytes) -> tuple[str, LinkInfo] | None:
    """Parse a NEWLINK payload into (ifname, LinkInfo). Returns None if invalid."""
    if len(payload) < 16:
        return None

    # Parse ifinfomsg header
    ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change = struct.unpack_from(
        "BxHiII", payload, 0
    )
    # Parse attributes after ifinfomsg (16 bytes)
    attrs = parse_attrs(payload, 16)

    ifname = None
    if IFLAAttr.IFNAME in attrs:
        ifname = (
            attrs[IFLAAttr.IFNAME].rstrip(b"\x00").decode("utf-8", errors="replace")
        )
    if not ifname:
        return None

    # Core fields
    mtu = 0
    operstate = 0
    address = None
    perm_address = None
    broadcast = None

    if IFLAAttr.MTU in attrs:
        mtu = struct.unpack("I", attrs[IFLAAttr.MTU][:4])[0]
    if IFLAAttr.OPERSTATE in attrs:
        operstate = attrs[IFLAAttr.OPERSTATE][0]
    if IFLAAttr.ADDRESS in attrs:
        address = attrs[IFLAAttr.ADDRESS].hex(":")
    if IFLAAttr.PERM_ADDRESS in attrs:
        perm_address = attrs[IFLAAttr.PERM_ADDRESS].hex(":")
    if IFLAAttr.BROADCAST in attrs:
        broadcast = attrs[IFLAAttr.BROADCAST].hex(":")

    # Extended fields
    txqlen = 0
    min_mtu = 0
    max_mtu = 0
    carrier = False
    carrier_changes = 0
    num_tx_queues = 1
    num_rx_queues = 1

    if IFLAAttr.TXQLEN in attrs:
        txqlen = struct.unpack("I", attrs[IFLAAttr.TXQLEN][:4])[0]
    if IFLAAttr.MIN_MTU in attrs:
        min_mtu = struct.unpack("I", attrs[IFLAAttr.MIN_MTU][:4])[0]
    if IFLAAttr.MAX_MTU in attrs:
        max_mtu = struct.unpack("I", attrs[IFLAAttr.MAX_MTU][:4])[0]
    if IFLAAttr.CARRIER in attrs:
        carrier = attrs[IFLAAttr.CARRIER][0] != 0
    if IFLAAttr.CARRIER_CHANGES in attrs:
        carrier_changes = struct.unpack("I", attrs[IFLAAttr.CARRIER_CHANGES][:4])[0]
    if IFLAAttr.NUM_TX_QUEUES in attrs:
        num_tx_queues = struct.unpack("I", attrs[IFLAAttr.NUM_TX_QUEUES][:4])[0]
    if IFLAAttr.NUM_RX_QUEUES in attrs:
        num_rx_queues = struct.unpack("I", attrs[IFLAAttr.NUM_RX_QUEUES][:4])[0]

    # Master device index (for bond members, bridge ports, etc.)
    master = None
    if IFLAAttr.MASTER in attrs:
        master = struct.unpack("I", attrs[IFLAAttr.MASTER][:4])[0]

    # Parent device info (for USB detection, etc.)
    parentbus = None
    parentdev = None

    if IFLAAttr.PARENT_DEV_BUS_NAME in attrs:
        parentbus = (
            attrs[IFLAAttr.PARENT_DEV_BUS_NAME]
            .rstrip(b"\x00")
            .decode("utf-8", errors="replace")
        )
    if IFLAAttr.PARENT_DEV_NAME in attrs:
        parentdev = (
            attrs[IFLAAttr.PARENT_DEV_NAME]
            .rstrip(b"\x00")
            .decode("utf-8", errors="replace")
        )

    # Alternate names from IFLA_PROP_LIST
    altnames: list[str] = []
    if IFLAAttr.PROP_LIST in attrs:
        offset = 0
        prop_data = attrs[IFLAAttr.PROP_LIST]
        while offset + 4 <= len(prop_data):
            nla_len, nla_type = struct.unpack_from("HH", prop_data, offset)
            if nla_len < 4:
                break
            nla_type_base = nla_type & 0x7FFF
            if nla_type_base == IFLAAttr.ALT_IFNAME:
                attr_data = prop_data[offset+4:offset+nla_len]
                altnames.append(
                    attr_data.rstrip(b"\x00").decode("utf-8", errors="replace")
                )
            offset += (nla_len + 3) & ~3

    # Parse IFLA_LINKINFO for bond/bridge/vlan details
    kind = None
    bond_mode = None
    bond_miimon = None
    bond_xmit_hash_policy = None
    bond_lacpdu_rate = None
    bond_primary = None
    bridge_stp_state = None
    bridge_priority = None
    vlan_id = None
    vlan_parent = None

    if IFLAAttr.LINKINFO in attrs:
        linkinfo_attrs = parse_attrs(attrs[IFLAAttr.LINKINFO])
        if IFLAInfoAttr.KIND in linkinfo_attrs:
            kind = (
                linkinfo_attrs[IFLAInfoAttr.KIND]
                .rstrip(b"\x00")
                .decode("utf-8", errors="replace")
            )

        if IFLAInfoAttr.DATA in linkinfo_attrs:
            info_data = parse_attrs(linkinfo_attrs[IFLAInfoAttr.DATA])

            if kind == "bond":
                if IFLABondAttr.MODE in info_data:
                    bond_mode = info_data[IFLABondAttr.MODE][0]
                if IFLABondAttr.MIIMON in info_data:
                    bond_miimon = struct.unpack(
                        "I", info_data[IFLABondAttr.MIIMON][:4]
                    )[0]
                if IFLABondAttr.XMIT_HASH_POLICY in info_data:
                    bond_xmit_hash_policy = info_data[IFLABondAttr.XMIT_HASH_POLICY][0]
                if IFLABondAttr.AD_LACP_RATE in info_data:
                    bond_lacpdu_rate = info_data[IFLABondAttr.AD_LACP_RATE][0]
                if IFLABondAttr.PRIMARY in info_data:
                    bond_primary = struct.unpack(
                        "I", info_data[IFLABondAttr.PRIMARY][:4]
                    )[0]

            elif kind == "bridge":
                if IFLABridgeAttr.STP_STATE in info_data:
                    bridge_stp_state = struct.unpack(
                        "I", info_data[IFLABridgeAttr.STP_STATE][:4]
                    )[0]
                if IFLABridgeAttr.PRIORITY in info_data:
                    bridge_priority = struct.unpack(
                        "H", info_data[IFLABridgeAttr.PRIORITY][:2]
                    )[0]

            elif kind == "vlan":
                if IFLAVlanAttr.ID in info_data:
                    vlan_id = struct.unpack("H", info_data[IFLAVlanAttr.ID][:2])[0]

    # Parse IFLA_LINK for vlan parent interface index
    if IFLAAttr.LINK in attrs and kind == "vlan":
        vlan_parent = struct.unpack("I", attrs[IFLAAttr.LINK][:4])[0]

    return ifname, LinkInfo(
        index=ifi_index,
        flags=ifi_flags,
        mtu=mtu,
        operstate=operstate,
        address=address,
        perm_address=perm_address,
        broadcast=broadcast,
        txqlen=txqlen,
        min_mtu=min_mtu,
        max_mtu=max_mtu,
        carrier=carrier,
        carrier_changes=carrier_changes,
        num_tx_queues=num_tx_queues,
        num_rx_queues=num_rx_queues,
        master=master,
        parentbus=parentbus,
        parentdev=parentdev,
        altnames=tuple(altnames),
        kind=kind,
        bond_mode=bond_mode,
        bond_miimon=bond_miimon,
        bond_xmit_hash_policy=bond_xmit_hash_policy,
        bond_lacpdu_rate=bond_lacpdu_rate,
        bond_primary=bond_primary,
        bridge_stp_state=bridge_stp_state,
        bridge_priority=bridge_priority,
        vlan_id=vlan_id,
        vlan_parent=vlan_parent,
    )


def link_exists(name: str) -> bool:
    """Check if a network interface exists (fast syscall, no netlink)."""
    try:
        socket.if_nametoindex(name)
        return True
    except OSError:
        return False


def get_links(sock: socket.socket) -> dict[str, LinkInfo]:
    """Get all network interfaces."""
    # Build ifinfomsg: family(1) + pad(1) + type(2) + index(4) + flags(4) + change(4) = 16 bytes
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, 0, 0, 0)
    # Add IFLA_EXT_MASK to request extended info but skip stats
    ext_mask = pack_nlattr_u32(
        IFLAAttr.EXT_MASK, RTEXTFilter.VF | RTEXTFilter.SKIP_STATS
    )
    payload = ifinfomsg + ext_mask
    msg = pack_nlmsg(RTMType.GETLINK, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, payload)
    sock.send(msg)

    links: dict[str, LinkInfo] = {}
    for msg_type, payload in recv_msgs(sock):
        if msg_type != RTMType.NEWLINK:
            continue
        if result := _parse_link_payload(payload):
            ifname, link_info = result
            links[ifname] = link_info

    return links


def get_link(sock: socket.socket, name: str) -> LinkInfo:
    """Get link info for a single interface by name."""
    try:
        index = socket.if_nametoindex(name)
    except OSError:
        raise DeviceNotFound(f"No such device: {name}")

    # Build ifinfomsg with specific index
    ifinfomsg = struct.pack("BxHiII", AddressFamily.UNSPEC, 0, index, 0, 0)
    msg = pack_nlmsg(RTMType.GETLINK, NLMsgFlags.REQUEST | NLMsgFlags.ACK, ifinfomsg)
    sock.send(msg)

    for msg_type, payload in recv_msgs(sock):
        if msg_type != RTMType.NEWLINK:
            continue
        if result := _parse_link_payload(payload):
            return result[1]

    raise DeviceNotFound(f"No such device: {name}")
