from enum import IntEnum, IntFlag

# Netlink protocol
NETLINK_GENERIC = 16

# Generic netlink control
GENL_ID_CTRL = 0x10

# Netlink attribute flag
NLA_F_NESTED = 0x8000


class NLMsgFlags(IntFlag):
    REQUEST = 0x01
    ACK = 0x04


class EthtoolFlags(IntFlag):
    """ETHTOOL_A_HEADER_FLAGS bits.

    COMPACT_BITSETS asks the kernel for VALUE/MASK bitmaps instead of
    per-bit list entries. List-format semantics vary per attribute (some
    bitsets flag "on" via NLA_FLAG VALUE, others enumerate only the "on"
    bits with no VALUE flag), so _parse_bitset cannot interpret list form
    reliably.
    """

    COMPACT_BITSETS = 1


class NLMsgType(IntEnum):
    ERROR = 0x02


class CtrlCmd(IntEnum):
    GETFAMILY = 3


class CtrlAttr(IntEnum):
    FAMILY_ID = 1
    FAMILY_NAME = 2


class EthtoolMsg(IntEnum):
    STRSET_GET = 1
    LINKINFO_GET = 2
    LINKMODES_GET = 4
    LINKSTATE_GET = 6
    FEATURES_GET = 11
    PRIVFLAGS_GET = 13
    PRIVFLAGS_SET = 14
    FEC_GET = 29
    FEC_SET = 30
    RSS_GET = 38
    RSS_SET = 48


class EthtoolAHeader(IntEnum):
    HEADER = 1
    DEV_NAME = 2
    FLAGS = 3


class EthtoolALinkmodes(IntEnum):
    AUTONEG = 2
    OURS = 3
    SPEED = 5
    DUPLEX = 6


class EthtoolABitset(IntEnum):
    SIZE = 2
    BITS = 3
    VALUE = 4
    MASK = 5


class EthtoolABitsetBits(IntEnum):
    BIT = 1


class EthtoolABitsetBit(IntEnum):
    INDEX = 1
    VALUE = 3


class EthtoolALinkinfo(IntEnum):
    PORT = 2
    PHYADDR = 3
    TRANSCEIVER = 6


class EthtoolALinkstate(IntEnum):
    LINK = 2


class EthtoolAFeatures(IntEnum):
    HW = 2
    ACTIVE = 4
    NOCHANGE = 5


class EthtoolAStrset(IntEnum):
    STRINGSETS = 2


class EthtoolAStringsets(IntEnum):
    STRINGSET = 1


class EthtoolAStringset(IntEnum):
    ID = 1
    STRINGS = 3


class EthtoolAStrings(IntEnum):
    STRING = 1


class EthtoolAString(IntEnum):
    INDEX = 1
    VALUE = 2


class EthtoolAFec(IntEnum):
    MODES = 2
    AUTO = 3
    ACTIVE = 4


class EthtoolAPrivflags(IntEnum):
    HEADER = 1
    FLAGS = 2


class EthSS(IntEnum):
    PRIV_FLAGS = 2
    FEATURES = 4
    LINK_MODES = 9


class EthtoolARss(IntEnum):
    HEADER = 1
    CONTEXT = 2
    HFUNC = 3
    INDIR = 4
    HKEY = 5
    INPUT_XFRM = 6
    START_CONTEXT = 7
    FLOW_HASH = 8


# ETHTOOL_A_FLOW_* values (nested inside ETHTOOL_A_RSS_FLOW_HASH). Each
# nested attribute's TYPE is the flow-type enum and its payload is the
# NLA_UINT hash-field bitmask (RXH_* bits below).
class EthtoolAFlow(IntEnum):
    ETHER = 1
    IP4 = 2
    IP6 = 3
    TCP4 = 4
    TCP6 = 5
    UDP4 = 6
    UDP6 = 7
    SCTP4 = 8
    SCTP6 = 9
    AH4 = 10
    AH6 = 11
    ESP4 = 12
    ESP6 = 13
    AH_ESP4 = 14
    AH_ESP6 = 15


# RSS flow-hash field bits (<linux/ethtool.h> RXH_*).
class RxHashField(IntFlag):
    L2DA = 1 << 1
    VLAN = 1 << 2
    L3_PROTO = 1 << 3
    IP_SRC = 1 << 4
    IP_DST = 1 << 5
    L4_B_0_1 = 1 << 6  # src port for TCP/UDP/SCTP
    L4_B_2_3 = 1 << 7  # dst port for TCP/UDP/SCTP
    GTP_TEID = 1 << 8
    IP6_FL = 1 << 9
