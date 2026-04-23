import socket
import struct
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import IntEnum
from types import MappingProxyType
from typing import Iterable, Literal, Self, TypedDict

from truenas_pynetif.ethtool.constants import (
    GENL_ID_CTRL,
    NETLINK_GENERIC,
    CtrlAttr,
    CtrlCmd,
    EthSS,
    EthtoolABitset,
    EthtoolABitsetBit,
    EthtoolABitsetBits,
    EthtoolAFec,
    EthtoolAFeatures,
    EthtoolAFlow,
    EthtoolAHeader,
    EthtoolALinkinfo,
    EthtoolALinkmodes,
    EthtoolALinkstate,
    EthtoolAPrivflags,
    EthtoolARss,
    EthtoolAString,
    EthtoolAStringset,
    EthtoolAStringsets,
    EthtoolAStrings,
    EthtoolAStrset,
    EthtoolFlags,
    EthtoolMsg,
    RxHashField,
)
from truenas_pynetif.netlink import DeviceNotFound, NetlinkError, OperationNotSupported
from truenas_pynetif.netlink._core import (
    pack_genlmsg,
    pack_nlattr,
    pack_nlattr_nested,
    pack_nlattr_str,
    pack_nlattr_u32,
    parse_attrs,
    recv_msgs,
)

__all__ = [
    "DeviceNotFound",
    "Duplex",
    "EthtoolNetlink",
    "FeaturesInfo",
    "FecMode",
    "FecModeName",
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


FecModeName = Literal["AUTO", "OFF", "RS", "BASER", "LLRS"]


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


PORT_TYPE_NAMES: MappingProxyType[PortType, str] = MappingProxyType(
    {
        PortType.TP: "Twisted Pair",
        PortType.AUI: "AUI",
        PortType.MII: "MII",
        PortType.FIBRE: "Fibre",
        PortType.BNC: "BNC",
        PortType.DA: "Direct Attach Copper",
        PortType.NONE: "None",
        PortType.OTHER: "Other",
    }
)


class Duplex(IntEnum):
    HALF = 0
    FULL = 1
    UNKNOWN = 0xFF


class Transceiver(IntEnum):
    INTERNAL = 0
    EXTERNAL = 1


# These are ETHTOOL_LINK_MODE_FEC_*_BIT values from ethtool_link_mode_bit_indices.
class FecMode(IntEnum):
    """FEC link mode bit indices as reported by ETHTOOL_A_FEC_ACTIVE."""

    OFF = 49  # ETHTOOL_LINK_MODE_FEC_NONE_BIT
    RS = 50  # ETHTOOL_LINK_MODE_FEC_RS_BIT
    BASER = 51  # ETHTOOL_LINK_MODE_FEC_BASER_BIT
    LLRS = 74  # ETHTOOL_LINK_MODE_FEC_LLRS_BIT


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

    def _pack_genlmsg(self, family_id: int, cmd: int, version: int, attrs: bytes) -> bytes:
        return pack_genlmsg(family_id, cmd, version, attrs, seq=self._next_seq())

    def _recv_msgs(self) -> list[tuple[int, bytes]]:
        if self._sock is None:
            raise NetlinkError("Socket not connected")
        return recv_msgs(self._sock)

    def _resolve_family(self, name: str) -> int:
        attrs = pack_nlattr_str(CtrlAttr.FAMILY_NAME, name)
        msg = self._pack_genlmsg(GENL_ID_CTRL, CtrlCmd.GETFAMILY, 1, attrs)
        if self._sock is None:
            raise NetlinkError("Socket not connected")
        self._sock.send(msg)
        for msg_type, payload in self._recv_msgs():
            if msg_type == GENL_ID_CTRL:
                parsed_attrs = parse_attrs(payload, 4)
                if CtrlAttr.FAMILY_ID in parsed_attrs:
                    family_id: int = struct.unpack("H", parsed_attrs[CtrlAttr.FAMILY_ID][:2])[0]
                    return family_id
        raise NetlinkError(f"Could not resolve family: {name}")

    def _make_header(self, ifname: str, flags: int = 0) -> bytes:
        name_attr = pack_nlattr_str(EthtoolAHeader.DEV_NAME, ifname)
        if flags:
            name_attr += pack_nlattr_u32(EthtoolAHeader.FLAGS, flags)
        return pack_nlattr_nested(EthtoolAHeader.HEADER, name_attr)

    def _pack_compact_bitset(self, value_bits: Iterable[int], mask_bits: Iterable[int], size: int) -> bytes:
        byte_count = ((size + 31) // 32) * 4  # kernel requires u32-word-aligned VALUE/MASK
        value_bytes = bytearray(byte_count)
        mask_bytes = bytearray(byte_count)
        for bit in value_bits:
            value_bytes[bit // 8] |= 1 << (bit % 8)
        for bit in mask_bits:
            mask_bytes[bit // 8] |= 1 << (bit % 8)
        result = pack_nlattr_u32(EthtoolABitset.SIZE, size)
        result += pack_nlattr(EthtoolABitset.VALUE, bytes(value_bytes))
        result += pack_nlattr(EthtoolABitset.MASK, bytes(mask_bytes))
        return result

    def _parse_bitset(self, data: bytes) -> tuple[int, set[int], set[int]]:
        attrs = parse_attrs(data)
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
                    bit_attrs = parse_attrs(bit_data)
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
        header = self._make_header(ifname, flags=EthtoolFlags.COMPACT_BITSETS)
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
                attrs = parse_attrs(payload, 4)
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
                    # OURS is packed val=advertising, mask=supported. Take
                    # mask_bits for the "supported" list.
                    _, _, mask_bits = self._parse_bitset(attrs[EthtoolALinkmodes.OURS])
                    modes = []
                    for bit in sorted(mask_bits):
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
                attrs = parse_attrs(payload, 4)
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

    def get_fec(self, ifname: str) -> FecModeName | None:
        """
        Get the FEC (Forward Error Correction) mode for an interface.

        Returns one of: "AUTO", "OFF", "RS", "BASER", "LLRS", or None if unsupported.
        When the link is up, returns the active (hardware-negotiated) FEC mode.
        Returns "AUTO" only when auto-selection is enabled but no active mode is
        reported (e.g. link is down). Falls back to the configured mode otherwise.
        """
        header = self._make_header(ifname, flags=EthtoolFlags.COMPACT_BITSETS)
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.FEC_GET, 1, header)
        if self._sock is None:
            raise NetlinkError("Socket not connected")

        try:
            self._sock.send(msg)
        except OSError:
            return None

        is_auto = False
        active_fec: FecModeName | None = None
        configured_fec: FecModeName | None = None
        for msg_type, payload in self._recv_msgs():
            if msg_type != self._family_id:
                continue

            attrs = parse_attrs(payload, 4)
            if EthtoolAFec.AUTO in attrs:
                is_auto = attrs[EthtoolAFec.AUTO][0] != 0
            if EthtoolAFec.ACTIVE in attrs:
                # ACTIVE is a plain u32 bit index (nla_put_u32), not a bitset
                active_bit = struct.unpack_from("I", attrs[EthtoolAFec.ACTIVE])[0]
                try:
                    active_fec = FecMode(active_bit).name  # type: ignore[assignment]
                except ValueError:
                    pass
            if EthtoolAFec.MODES in attrs:
                # MODES is the configured FEC — used as fallback when link is down
                _, modes_bits, _ = self._parse_bitset(attrs[EthtoolAFec.MODES])
                for bit in sorted(modes_bits):
                    try:
                        configured_fec = FecMode(bit).name  # type: ignore[assignment]
                        break
                    except ValueError:
                        pass

        # ACTIVE takes precedence: AUTO=1 + ACTIVE=RS is a normal state meaning
        # "auto mode, hardware negotiated RS". Report what the hardware is actually using.
        if active_fec is not None:
            return active_fec
        if is_auto:
            return "AUTO"
        return configured_fec

    def set_fec(self, ifname: str, mode: FecModeName) -> None:
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
            fec_auto = pack_nlattr(EthtoolAFec.AUTO, struct.pack("B", 1))
            attrs = header + fec_auto
        else:
            try:
                fec_mode = FecMode[mode]
            except KeyError:
                raise ValueError(f"Invalid FEC mode: {mode!r}")

            all_fec_bits = [m.value for m in FecMode]
            bitset_size = max(all_fec_bits) + 1
            bitset = self._pack_compact_bitset([fec_mode.value], all_fec_bits, bitset_size)
            modes = pack_nlattr_nested(EthtoolAFec.MODES, bitset)
            fec_auto = pack_nlattr(EthtoolAFec.AUTO, struct.pack("B", 0))
            attrs = header + modes + fec_auto

        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.FEC_SET, 1, attrs)
        self._sock.send(msg)
        self._recv_msgs()

    def get_fec_modes(self, ifname: str) -> list[FecModeName]:
        """Return the configured FEC modes for the interface.

        Returns an empty list if the interface does not support FEC.
        AUTO is included when the driver reports that auto-selection is active.
        Note: the MODES bitset reflects what the driver has configured (fec.fec),
        not necessarily the full set of hardware-capable modes.
        """
        header = self._make_header(ifname, flags=EthtoolFlags.COMPACT_BITSETS)
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.FEC_GET, 1, header)
        if self._sock is None:
            raise NetlinkError("Socket not connected")

        try:
            self._sock.send(msg)
        except OSError:
            return []

        modes: list[FecModeName] = []
        try:
            for msg_type, payload in self._recv_msgs():
                if msg_type != self._family_id:
                    continue

                attrs = parse_attrs(payload, 4)
                if EthtoolAFec.AUTO in attrs and attrs[EthtoolAFec.AUTO][0] != 0:
                    modes.append("AUTO")
                if EthtoolAFec.MODES in attrs:
                    _, value_bits, _ = self._parse_bitset(attrs[EthtoolAFec.MODES])
                    for bit in sorted(value_bits):
                        try:
                            modes.append(FecMode(bit).name)  # type: ignore[arg-type]
                        except ValueError:
                            pass

        except (DeviceNotFound, OperationNotSupported):
            return []

        return modes

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
                attrs = parse_attrs(payload, 4)
                if EthtoolALinkstate.LINK in attrs:
                    return attrs[EthtoolALinkstate.LINK][0] == 1
        return False

    def _query_string_set(self, string_set_id: int, ifname: str = "lo") -> dict[int, str]:
        stringset_id = pack_nlattr_u32(EthtoolAStringset.ID, string_set_id)
        stringset = pack_nlattr_nested(EthtoolAStringsets.STRINGSET, stringset_id)
        stringsets = pack_nlattr_nested(EthtoolAStrset.STRINGSETS, stringset)
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
                attrs = parse_attrs(payload, 4)
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
        attrs = parse_attrs(data)
        if EthtoolAStringset.STRINGS in attrs:
            self._parse_strings(attrs[EthtoolAStringset.STRINGS], names)

    def _parse_strings(self, data: bytes, names: dict[int, str]) -> None:
        offset = 0
        while offset + 4 <= len(data):
            nla_len, nla_type = struct.unpack_from("HH", data, offset)
            if nla_len < 4:
                break
            if (nla_type & 0x7FFF) == EthtoolAStrings.STRING:
                string_attrs = parse_attrs(data[offset + 4 : offset + nla_len])
                if EthtoolAString.INDEX in string_attrs and EthtoolAString.VALUE in string_attrs:
                    idx = struct.unpack("I", string_attrs[EthtoolAString.INDEX][:4])[0]
                    val = string_attrs[EthtoolAString.VALUE].rstrip(b"\x00").decode("utf-8", errors="replace")
                    names[idx] = val
            offset += (nla_len + 3) & ~3

    def get_features(self, ifname: str) -> FeaturesInfo:
        feature_names = self._get_feature_names()
        header = self._make_header(ifname, flags=EthtoolFlags.COMPACT_BITSETS)
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
                attrs = parse_attrs(payload, 4)
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

    def get_priv_flags(self, ifname: str) -> dict[str, bool]:
        """Get driver private flags for an interface.

        Returns a mapping of priv-flag name -> enabled state. The set of
        available names is driver-specific (e.g. i40e exposes
        "disable-fw-lldp", "link-down-on-close"; bnxt_en has a different
        set). Returns an empty dict if the interface / driver does not
        support priv-flags.
        """
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        if self._sock is None:
            raise NetlinkError("Socket not connected")

        names = self._query_string_set(EthSS.PRIV_FLAGS, ifname)
        if not names:
            return {}

        header = self._make_header(ifname, flags=EthtoolFlags.COMPACT_BITSETS)
        msg = self._pack_genlmsg(self._family_id, EthtoolMsg.PRIVFLAGS_GET, 1, header)
        try:
            self._sock.send(msg)
        except OSError:
            return {}

        enabled_bits: set[int] = set()
        mask_bits: set[int] = set()
        try:
            for msg_type, payload in self._recv_msgs():
                if msg_type != self._family_id:
                    continue
                attrs = parse_attrs(payload, 4)
                if EthtoolAPrivflags.FLAGS in attrs:
                    _, enabled_bits, mask_bits = self._parse_bitset(
                        attrs[EthtoolAPrivflags.FLAGS]
                    )
        except (DeviceNotFound, OperationNotSupported):
            return {}

        result: dict[str, bool] = {}
        for idx, name in names.items():
            if idx in mask_bits or idx in enabled_bits:
                result[name] = idx in enabled_bits
        return result

    def set_priv_flags(self, ifname: str, flags: dict[str, bool]) -> None:
        """Set driver private flags for an interface.

        `flags` is a name -> desired-state mapping. Only the listed flags
        are changed; others are left untouched. Names are driver-specific;
        call `get_priv_flags()` first to discover what is available.

        Raises ValueError if a requested name is not supported by the
        driver on this interface.
        """
        if not flags:
            return
        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        if self._sock is None:
            raise NetlinkError("Socket not connected")

        names = self._query_string_set(EthSS.PRIV_FLAGS, ifname)
        name_to_idx = {v: k for k, v in names.items()}

        value_bits: list[int] = []
        mask_bits: list[int] = []
        for name, enabled in flags.items():
            idx = name_to_idx.get(name)
            if idx is None:
                raise ValueError(f"{ifname}: unknown priv-flag {name!r}")
            mask_bits.append(idx)
            if enabled:
                value_bits.append(idx)

        bitset_size = max(name_to_idx.values()) + 1 if name_to_idx else 0
        bitset = self._pack_compact_bitset(value_bits, mask_bits, bitset_size)
        flags_attr = pack_nlattr_nested(EthtoolAPrivflags.FLAGS, bitset)
        header = self._make_header(ifname)
        msg = self._pack_genlmsg(
            self._family_id, EthtoolMsg.PRIVFLAGS_SET, 1, header + flags_attr
        )
        self._sock.send(msg)
        self._recv_msgs()

    def set_rx_flow_hash(self, ifname: str, flow_type: str, hash_spec: str) -> None:
        """Configure RX flow hash fields for a given flow type.

        Uses `ETHTOOL_MSG_RSS_SET` (available since Linux v6.17).

        `flow_type` is an ethtool flow-type name (e.g. "tcp4", "udp4").
        `hash_spec` is the same short-form letter code used by
        `ethtool -N <iface> rx-flow-hash <flow_type> <spec>` — e.g. "sdfn" =
        src-IP + dst-IP + src-port + dst-port.

        Raises ValueError for unknown flow-type / hash-spec input, and
        NetlinkError if the kernel rejects the request (e.g. EOPNOTSUPP on
        drivers that don't implement `set_rxfh_fields`).
        """
        flow_attr = _RX_FLOW_TYPE_BY_NAME.get(flow_type)
        if flow_attr is None:
            raise ValueError(f"unknown rx-flow-hash flow_type {flow_type!r}")
        mask = 0
        for ch in hash_spec:
            bit = _RX_FLOW_HASH_SPEC_BITS.get(ch)
            if bit is None:
                raise ValueError(f"unknown rx-flow-hash spec character {ch!r}")
            mask |= int(bit)

        if self._family_id is None:
            raise NetlinkError("Family ID not resolved")
        if self._sock is None:
            raise NetlinkError("Socket not connected")

        header = self._make_header(ifname)
        flow_hash_nest = pack_nlattr_nested(
            EthtoolARss.FLOW_HASH, pack_nlattr_u32(int(flow_attr), mask)
        )
        msg = self._pack_genlmsg(
            self._family_id, EthtoolMsg.RSS_SET, 1, header + flow_hash_nest
        )
        self._sock.send(msg)
        self._recv_msgs()


# `ethtool -N` hash-spec letter codes → RXH_* bit.
_RX_FLOW_HASH_SPEC_BITS: dict[str, RxHashField] = {
    "s": RxHashField.IP_SRC,
    "d": RxHashField.IP_DST,
    "f": RxHashField.L4_B_0_1,
    "n": RxHashField.L4_B_2_3,
    "v": RxHashField.VLAN,
    "t": RxHashField.L3_PROTO,
    "m": RxHashField.L2DA,
    "r": RxHashField.IP6_FL,
}


_RX_FLOW_TYPE_BY_NAME: dict[str, EthtoolAFlow] = {
    "ether": EthtoolAFlow.ETHER,
    "ip4": EthtoolAFlow.IP4,
    "ip6": EthtoolAFlow.IP6,
    "tcp4": EthtoolAFlow.TCP4,
    "tcp6": EthtoolAFlow.TCP6,
    "udp4": EthtoolAFlow.UDP4,
    "udp6": EthtoolAFlow.UDP6,
    "sctp4": EthtoolAFlow.SCTP4,
    "sctp6": EthtoolAFlow.SCTP6,
    "ah4": EthtoolAFlow.AH4,
    "ah6": EthtoolAFlow.AH6,
    "esp4": EthtoolAFlow.ESP4,
    "esp6": EthtoolAFlow.ESP6,
    "ah-esp4": EthtoolAFlow.AH_ESP4,
    "ah-esp6": EthtoolAFlow.AH_ESP6,
}


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
