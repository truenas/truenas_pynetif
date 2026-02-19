import socket
import struct
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import IntEnum
from types import MappingProxyType
from typing import Self, TypedDict

from truenas_pynetif.ethtool.constants import (
    GENL_ID_CTRL,
    NETLINK_GENERIC,
    NLA_F_NESTED,
    CtrlAttr,
    CtrlCmd,
    EthSS,
    EthtoolABitset,
    EthtoolABitsetBit,
    EthtoolABitsetBits,
    EthtoolAFec,
    EthtoolAFeatures,
    EthtoolAHeader,
    EthtoolALinkinfo,
    EthtoolALinkmodes,
    EthtoolALinkstate,
    EthtoolAString,
    EthtoolAStringset,
    EthtoolAStringsets,
    EthtoolAStrings,
    EthtoolAStrset,
    EthtoolMsg,
    NLMsgFlags,
    NLMsgType,
)
from truenas_pynetif.netlink import DeviceNotFound, NetlinkError, OperationNotSupported

__all__ = [
    "DeviceNotFound",
    "Duplex",
    "EthtoolNetlink",
    "FeaturesInfo",
    "FecMode",
    "LinkInfo",
    "LinkModesInfo",
    "NetlinkError",
    "OperationNotSupported",
    "PortType",
    "PORT_TYPE_NAMES",
    "Transceiver",
    "close_ethtool",
    "get_ethtool",
]


class LinkModesInfo(TypedDict):
    """Information about link modes from ethtool."""
    speed: int | None
    duplex: str
    autoneg: bool
    supported_modes: list[str]


class LinkInfo(TypedDict):
    """Information about physical link properties from ethtool."""
    port: str
    port_num: int
    transceiver: str
    phyaddr: int | None


class FeaturesInfo(TypedDict):
    """Information about network features from ethtool."""
    enabled: list[str]
    disabled: list[str]
    supported: list[str]


_link_mode_names: MappingProxyType[int, str] | None = None
_feature_names: MappingProxyType[int, str] | None = None
_cache_init_lock = threading.Lock()
_ethtool_ctx: ContextVar["EthtoolNetlink | None"] = ContextVar("ethtool", default=None)


class PortType(IntEnum):
    TP = 0x00
    AUI = 0x01
    MII = 0x02
    FIBRE = 0x03
    BNC = 0x04
    DA = 0x05
    NONE = 0xEF
    OTHER = 0xFF


PORT_TYPE_NAMES: MappingProxyType[PortType, str] = MappingProxyType({
    PortType.TP: "Twisted Pair",
    PortType.AUI: "AUI",
    PortType.MII: "MII",
    PortType.FIBRE: "Fibre",
    PortType.BNC: "BNC",
    PortType.DA: "Direct Attach Copper",
    PortType.NONE: "None",
    PortType.OTHER: "Other",
})


class Duplex(IntEnum):
    HALF = 0
    FULL = 1
    UNKNOWN = 0xFF


class Transceiver(IntEnum):
    INTERNAL = 0
    EXTERNAL = 1


# ETHTOOL_A_FEC_ACTIVE carries a link mode bit index, not a bitmask.
# These are ETHTOOL_LINK_MODE_FEC_*_BIT values from ethtool_link_mode_bit_indices.
class FecMode(IntEnum):
    """FEC link mode bit indices as reported by ETHTOOL_A_FEC_ACTIVE."""
    OFF = 49     # ETHTOOL_LINK_MODE_FEC_NONE_BIT
    RS = 50      # ETHTOOL_LINK_MODE_FEC_RS_BIT
    BASER = 51   # ETHTOOL_LINK_MODE_FEC_BASER_BIT
    LLRS = 74    # ETHTOOL_LINK_MODE_FEC_LLRS_BIT


@dataclass(slots=True)
class EthtoolNetlink:
    _sock: socket.socket | None = field(default=None, init=False)
    _family_id: int | None = field(default=None, init=False)
    _seq: int = field(default=0, init=False)
    _pid: int | None = field(default=None, init=False)
    _feature_names: dict[int, str] | MappingProxyType[int, str] | None = field(default=None, init=False)
    _link_mode_names: dict[int, str] | MappingProxyType[int, str] | None = field(default=None, init=False)

    def __enter__(self) -> Self:
        self._connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _connect(self) -> None:
        self._sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        self._sock.bind((0, 0))
        self._pid = self._sock.getsockname()[0]
        self._family_id = self._resolve_family("ethtool")

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None
        self._feature_names = None
        self._link_mode_names = None

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _pack_nlattr(self, attr_type: int, data: bytes) -> bytes:
        nla_len = 4 + len(data)
        padded_len = (nla_len + 3) & ~3
        padding = padded_len - nla_len
        return struct.pack("HH", nla_len, attr_type) + data + b"\x00" * padding

    def _pack_nlattr_str(self, attr_type: int, s: str) -> bytes:
        return self._pack_nlattr(attr_type, s.encode() + b"\x00")

    def _pack_nlattr_u32(self, attr_type: int, val: int) -> bytes:
        return self._pack_nlattr(attr_type, struct.pack("I", val))

    def _pack_nlattr_nested(self, attr_type: int, attrs: bytes) -> bytes:
        return self._pack_nlattr(attr_type | NLA_F_NESTED, attrs)

    def _pack_nlmsg(self, msg_type: int, flags: int, payload: bytes) -> bytes:
        seq = self._next_seq()
        nlmsg_len = 16 + len(payload)
        return struct.pack("IHHII", nlmsg_len, msg_type, flags, seq, 0) + payload

    def _pack_genlmsg(self, family_id: int, cmd: int, version: int, attrs: bytes) -> bytes:
        genlhdr = struct.pack("BBH", cmd, version, 0)
        payload = genlhdr + attrs
        return self._pack_nlmsg(family_id, NLMsgFlags.REQUEST | NLMsgFlags.ACK, payload)

    def _recv_msgs(self) -> list[tuple[int, bytes]]:
        messages = []
        while True:
            if self._sock is None:
                raise NetlinkError("Socket not connected")
            data = self._sock.recv(65536)
            offset = 0
            done = False
            while offset < len(data):
                if offset + 16 > len(data):
                    break
                nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = (
                    struct.unpack_from("IHHII", data, offset)
                )
                if nlmsg_len < 16:
                    break
                if nlmsg_type == NLMsgType.ERROR:
                    if offset + 20 <= len(data):
                        error = struct.unpack_from("i", data, offset + 16)[0]
                        if error < 0:
                            error = -error
                            if error == 19:
                                raise DeviceNotFound("No such device")
                            elif error == 95:
                                raise OperationNotSupported("Operation not supported")
                            raise NetlinkError(f"Netlink error: {error}")
                    done = True
                elif nlmsg_type == 0x03:
                    done = True
                else:
                    payload = data[offset + 16 : offset + nlmsg_len]
                    messages.append((nlmsg_type, payload))
                offset += (nlmsg_len + 3) & ~3
            if done:
                break
        return messages

    def _parse_attrs(self, data: bytes, offset: int = 0) -> dict[int, bytes]:
        attrs = {}
        while offset + 4 <= len(data):
            nla_len, nla_type = struct.unpack_from("HH", data, offset)
            if nla_len < 4:
                break
            nla_type_base = nla_type & 0x7FFF
            attr_data = data[offset + 4 : offset + nla_len]
            attrs[nla_type_base] = attr_data
            offset += (nla_len + 3) & ~3
        return attrs

    def _parse_nested_attrs(self, data: bytes) -> dict[int, bytes]:
        return self._parse_attrs(data, 0)

    def _resolve_family(self, name: str) -> int:
        attrs = self._pack_nlattr_str(CtrlAttr.FAMILY_NAME, name)
        msg = self._pack_genlmsg(GENL_ID_CTRL, CtrlCmd.GETFAMILY, 1, attrs)
        if self._sock is None:
            raise NetlinkError("Socket not connected")
        self._sock.send(msg)
        for msg_type, payload in self._recv_msgs():
            if msg_type == GENL_ID_CTRL:
                parsed_attrs = self._parse_attrs(payload, 4)
                if CtrlAttr.FAMILY_ID in parsed_attrs:
                    family_id: int = struct.unpack("H", parsed_attrs[CtrlAttr.FAMILY_ID][:2])[0]
                    return family_id
        raise NetlinkError(f"Could not resolve family: {name}")

    def _make_header(self, ifname: str, flags: int = 0) -> bytes:
        name_attr = self._pack_nlattr_str(EthtoolAHeader.DEV_NAME, ifname)
        if flags:
            name_attr += self._pack_nlattr_u32(EthtoolAHeader.FLAGS, flags)
        return self._pack_nlattr_nested(EthtoolAHeader.HEADER, name_attr)

    def _pack_compact_bitset(self, value_bits: set[int], mask_bits: set[int], size: int) -> bytes:
        byte_count = (size + 7) // 8
        value_bytes = bytearray(byte_count)
        mask_bytes = bytearray(byte_count)
        for bit in value_bits:
            value_bytes[bit // 8] |= 1 << (bit % 8)
        for bit in mask_bits:
            mask_bytes[bit // 8] |= 1 << (bit % 8)
        result = self._pack_nlattr_u32(EthtoolABitset.SIZE, size)
        result += self._pack_nlattr(EthtoolABitset.VALUE, bytes(value_bytes))
        result += self._pack_nlattr(EthtoolABitset.MASK, bytes(mask_bytes))
        return result

    def _parse_bitset(self, data: bytes) -> tuple[int, set[int], set[int]]:
        attrs = self._parse_nested_attrs(data)
        size = 0
        if EthtoolABitset.SIZE in attrs:
            size = struct.unpack("I", attrs[EthtoolABitset.SIZE][:4])[0]
        value_bits: set[int] = set()
        mask_bits: set[int] = set()
        if EthtoolABitset.VALUE in attrs:
            value_data = attrs[EthtoolABitset.VALUE]
            for byte_idx, byte_val in enumerate(value_data):
                for bit in range(8):
                    if byte_val & (1 << bit):
                        value_bits.add(byte_idx * 8 + bit)
        if EthtoolABitset.MASK in attrs:
            mask_data = attrs[EthtoolABitset.MASK]
            for byte_idx, byte_val in enumerate(mask_data):
                for bit in range(8):
                    if byte_val & (1 << bit):
                        mask_bits.add(byte_idx * 8 + bit)
        if EthtoolABitset.BITS in attrs:
            bits_data = attrs[EthtoolABitset.BITS]
            offset = 0
            while offset + 4 <= len(bits_data):
                nla_len, nla_type = struct.unpack_from("HH", bits_data, offset)
                if nla_len < 4:
                    break
                if (nla_type & 0x7FFF) == EthtoolABitsetBits.BIT:
                    bit_data = bits_data[offset + 4 : offset + nla_len]
                    bit_attrs = self._parse_nested_attrs(bit_data)
                    bit_index = None
                    bit_value = True
                    if EthtoolABitsetBit.INDEX in bit_attrs:
                        bit_index = struct.unpack("I", bit_attrs[EthtoolABitsetBit.INDEX][:4])[0]
                    if EthtoolABitsetBit.VALUE in bit_attrs:
                        val_data = bit_attrs[EthtoolABitsetBit.VALUE]
                        if len(val_data) > 0:
                            bit_value = val_data[0] != 0
                    if bit_index is not None and bit_value:
                        value_bits.add(bit_index)
                    if bit_index is not None:
                        mask_bits.add(bit_index)
                offset += (nla_len + 3) & ~3
        return size, value_bits, mask_bits

    def get_link_modes(self, ifname: str) -> LinkModesInfo:
        link_mode_names = self._get_link_mode_names()
        header = self._make_header(ifname)
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.LINKMODES_GET, 1, header)
        if self._sock is None:
            raise NetlinkError("Socket not connected")
        self._sock.send(msg)
        result: LinkModesInfo = {
            "speed": None,
            "duplex": "Unknown",
            "autoneg": False,
            "supported_modes": [],
        }
        for msg_type, payload in self._recv_msgs():
            if msg_type == self._family_id:
                attrs = self._parse_attrs(payload, 4)
                if EthtoolALinkmodes.SPEED in attrs:
                    speed = struct.unpack("I", attrs[EthtoolALinkmodes.SPEED][:4])[0]
                    if speed != 0xFFFFFFFF:
                        result["speed"] = speed
                if EthtoolALinkmodes.DUPLEX in attrs:
                    duplex = attrs[EthtoolALinkmodes.DUPLEX][0]
                    if duplex == Duplex.FULL:
                        result["duplex"] = "Full"
                    elif duplex == Duplex.HALF:
                        result["duplex"] = "Half"
                if EthtoolALinkmodes.AUTONEG in attrs:
                    result["autoneg"] = attrs[EthtoolALinkmodes.AUTONEG][0] == 1
                if EthtoolALinkmodes.OURS in attrs:
                    _, value_bits, _ = self._parse_bitset(attrs[EthtoolALinkmodes.OURS])
                    modes = []
                    for bit in sorted(value_bits):
                        if bit in link_mode_names:
                            modes.append(link_mode_names[bit])
                    result["supported_modes"] = modes
        return result

    def get_link_info(self, ifname: str) -> LinkInfo:
        header = self._make_header(ifname)
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.LINKINFO_GET, 1, header)
        if self._sock is None:
            raise NetlinkError("Socket not connected")
        self._sock.send(msg)
        result: LinkInfo = {
            "port": "Unknown",
            "port_num": 0,
            "transceiver": "internal",
            "phyaddr": None,
        }
        for msg_type, payload in self._recv_msgs():
            if msg_type == self._family_id:
                attrs = self._parse_attrs(payload, 4)
                if EthtoolALinkinfo.PORT in attrs:
                    port = attrs[EthtoolALinkinfo.PORT][0]
                    result["port_num"] = port
                    try:
                        port_type = PortType(port)
                        result["port"] = PORT_TYPE_NAMES.get(port_type, f"Unknown({port})")
                    except ValueError:
                        result["port"] = f"Unknown({port})"
                if EthtoolALinkinfo.TRANSCEIVER in attrs:
                    xcvr = attrs[EthtoolALinkinfo.TRANSCEIVER][0]
                    result["transceiver"] = "external" if xcvr == Transceiver.EXTERNAL else "internal"
                if EthtoolALinkinfo.PHYADDR in attrs:
                    result["phyaddr"] = attrs[EthtoolALinkinfo.PHYADDR][0]
        return result

    def get_fec(self, ifname: str) -> str | None:
        """
        Get the active FEC (Forward Error Correction) mode for an interface.

        Returns one of: "AUTO", "OFF", "RS", "BASER", "LLRS", or None if unsupported.
        ETHTOOL_A_FEC_AUTO indicates the driver auto-selects the mode; when set,
        "AUTO" is returned regardless of the actual active encoding.
        """
        header = self._make_header(ifname)
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.FEC_GET, 1, header)
        if self._sock is None:
            raise NetlinkError("Socket not connected")

        try:
            self._sock.send(msg)
        except OSError:
            # Interface might not support FEC
            return None

        is_auto = False
        active_fec = None
        for msg_type, payload in self._recv_msgs():
            if msg_type == self._family_id:
                attrs = self._parse_attrs(payload, 4)
                if EthtoolAFec.AUTO in attrs:
                    is_auto = attrs[EthtoolAFec.AUTO][0] != 0
                if EthtoolAFec.ACTIVE in attrs:
                    # ACTIVE is a link mode bit index, not a bitmask
                    link_mode_bit = struct.unpack('I', attrs[EthtoolAFec.ACTIVE])[0]
                    try:
                        active_fec = FecMode(link_mode_bit).name
                    except ValueError:
                        pass
        if is_auto:
            return "AUTO"
        return active_fec

    def set_fec(self, ifname: str, mode: str) -> None:
        """
        Set the FEC mode for an interface.

        mode must be one of: "AUTO", "OFF", "RS", "BASER", "LLRS"
        """
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        if self._sock is None:
            raise NetlinkError("Socket not connected")

        header = self._make_header(ifname)

        if mode == "AUTO":
            fec_auto = self._pack_nlattr(EthtoolAFec.AUTO, struct.pack('B', 1))
            attrs = header + fec_auto
        else:
            try:
                fec_mode = FecMode[mode]
            except KeyError:
                raise ValueError(f"Invalid FEC mode: {mode!r}")
            all_fec_bits = {m.value for m in FecMode}
            bitset_size = max(all_fec_bits) + 1
            bitset = self._pack_compact_bitset({fec_mode.value}, all_fec_bits, bitset_size)
            modes = self._pack_nlattr_nested(EthtoolAFec.MODES, bitset)
            fec_auto = self._pack_nlattr(EthtoolAFec.AUTO, struct.pack('B', 0))
            attrs = header + modes + fec_auto

        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.FEC_SET, 1, attrs)
        self._sock.send(msg)
        self._recv_msgs()

    def get_link_state(self, ifname: str) -> bool:
        header = self._make_header(ifname)
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.LINKSTATE_GET, 1, header)
        if self._sock is None:
            raise NetlinkError("Socket not connected")
        self._sock.send(msg)
        for msg_type, payload in self._recv_msgs():
            if msg_type == self._family_id:
                attrs = self._parse_attrs(payload, 4)
                if EthtoolALinkstate.LINK in attrs:
                    return attrs[EthtoolALinkstate.LINK][0] == 1
        return False

    def _query_string_set(self, string_set_id: int, ifname: str = "lo") -> dict[int, str]:
        stringset_id = self._pack_nlattr_u32(EthtoolAStringset.ID, string_set_id)
        stringset = self._pack_nlattr_nested(EthtoolAStringsets.STRINGSET, stringset_id)
        stringsets = self._pack_nlattr_nested(EthtoolAStrset.STRINGSETS, stringset)
        header = self._make_header(ifname)
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.STRSET_GET, 1, header + stringsets)
        if self._sock is None:
            raise NetlinkError("Socket not connected")
        self._sock.send(msg)
        names: dict[int, str] = {}
        for msg_type, payload in self._recv_msgs():
            if msg_type == self._family_id:
                attrs = self._parse_attrs(payload, 4)
                if EthtoolAStrset.STRINGSETS in attrs:
                    self._parse_stringsets(attrs[EthtoolAStrset.STRINGSETS], names)
        return names

    def _get_feature_names(self) -> dict[int, str] | MappingProxyType[int, str]:
        if self._feature_names is not None:
            return self._feature_names
        self._feature_names = self._query_string_set(EthSS.FEATURES)
        return self._feature_names

    def _get_link_mode_names(self) -> dict[int, str] | MappingProxyType[int, str]:
        if self._link_mode_names is not None:
            return self._link_mode_names
        self._link_mode_names = self._query_string_set(EthSS.LINK_MODES)
        return self._link_mode_names

    def _parse_stringsets(self, data: bytes, names: dict[int, str]) -> None:
        offset = 0
        while offset + 4 <= len(data):
            nla_len, nla_type = struct.unpack_from("HH", data, offset)
            if nla_len < 4:
                break
            if (nla_type & 0x7FFF) == EthtoolAStringsets.STRINGSET:
                self._parse_stringset(data[offset + 4 : offset + nla_len], names)
            offset += (nla_len + 3) & ~3

    def _parse_stringset(self, data: bytes, names: dict[int, str]) -> None:
        attrs = self._parse_nested_attrs(data)
        if EthtoolAStringset.STRINGS in attrs:
            self._parse_strings(attrs[EthtoolAStringset.STRINGS], names)

    def _parse_strings(self, data: bytes, names: dict[int, str]) -> None:
        offset = 0
        while offset + 4 <= len(data):
            nla_len, nla_type = struct.unpack_from("HH", data, offset)
            if nla_len < 4:
                break
            if (nla_type & 0x7FFF) == EthtoolAStrings.STRING:
                string_attrs = self._parse_nested_attrs(data[offset + 4 : offset + nla_len])
                if EthtoolAString.INDEX in string_attrs and EthtoolAString.VALUE in string_attrs:
                    idx = struct.unpack("I", string_attrs[EthtoolAString.INDEX][:4])[0]
                    val = string_attrs[EthtoolAString.VALUE].rstrip(b"\x00").decode("utf-8", errors="replace")
                    names[idx] = val
            offset += (nla_len + 3) & ~3

    def get_features(self, ifname: str) -> FeaturesInfo:
        feature_names = self._get_feature_names()
        header = self._make_header(ifname)
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.FEATURES_GET, 1, header)
        if self._sock is None:
            raise NetlinkError("Socket not connected")
        self._sock.send(msg)
        result: FeaturesInfo = {"enabled": [], "disabled": [], "supported": []}
        hw_bits: set[int] = set()
        active_bits: set[int] = set()
        nochange_bits: set[int] = set()
        for msg_type, payload in self._recv_msgs():
            if msg_type == self._family_id:
                attrs = self._parse_attrs(payload, 4)
                if EthtoolAFeatures.HW in attrs:
                    _, hw_bits, _ = self._parse_bitset(attrs[EthtoolAFeatures.HW])
                if EthtoolAFeatures.ACTIVE in attrs:
                    _, active_bits, _ = self._parse_bitset(attrs[EthtoolAFeatures.ACTIVE])
                if EthtoolAFeatures.NOCHANGE in attrs:
                    _, nochange_bits, _ = self._parse_bitset(attrs[EthtoolAFeatures.NOCHANGE])
        for idx in hw_bits:
            name = feature_names.get(idx, f"feature-{idx}")
            if idx not in nochange_bits:
                result["supported"].append(name)
            if idx in active_bits:
                result["enabled"].append(name)
            else:
                result["disabled"].append(name)
        return result


def _ensure_global_caches() -> tuple[MappingProxyType[int, str], MappingProxyType[int, str]]:
    global _link_mode_names, _feature_names
    if _link_mode_names is not None and _feature_names is not None:
        return _link_mode_names, _feature_names
    with _cache_init_lock:
        if _link_mode_names is not None and _feature_names is not None:
            return _link_mode_names, _feature_names
        with EthtoolNetlink() as eth:
            _link_mode_names = MappingProxyType(eth._query_string_set(EthSS.LINK_MODES))
            _feature_names = MappingProxyType(eth._query_string_set(EthSS.FEATURES))
        return _link_mode_names, _feature_names


def get_ethtool() -> EthtoolNetlink:
    eth = _ethtool_ctx.get()
    needs_reconnect = False
    if eth is None:
        needs_reconnect = True
    elif eth._sock is None:
        needs_reconnect = True
    else:
        try:
            if eth._sock.fileno() == -1:
                needs_reconnect = True
        except OSError:
            needs_reconnect = True
    if needs_reconnect:
        if eth is not None:
            try:
                eth.close()
            except OSError:
                pass
        link_modes, features = _ensure_global_caches()
        eth = EthtoolNetlink()
        eth._connect()
        eth._link_mode_names = link_modes
        eth._feature_names = features
        _ethtool_ctx.set(eth)
    if eth is None:
        raise NetlinkError("Socket not available")
    return eth


def close_ethtool() -> None:
    eth = _ethtool_ctx.get()
    if eth is not None:
        eth.close()
        _ethtool_ctx.set(None)
