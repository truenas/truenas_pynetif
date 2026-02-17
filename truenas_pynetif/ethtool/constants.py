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
    FEC_GET = 17


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


class EthSS(IntEnum):
    FEATURES = 4
    LINK_MODES = 9
