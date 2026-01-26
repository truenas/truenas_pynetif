from enum import IntEnum, IntFlag

# Netlink protocol
NETLINK_ROUTE = 0

# Netlink socket option level
SOL_NETLINK = 270


class NetlinkSockOpt(IntEnum):
    GET_STRICT_CHK = 12


class NLAttrFlags(IntFlag):
    NESTED = 0x8000


class NLMsgFlags(IntFlag):
    REQUEST = 0x01
    MULTI = 0x02
    ACK = 0x04
    ROOT = 0x100
    MATCH = 0x200
    DUMP = ROOT | MATCH
    DUMP_INTR = 0x10


class NLMsgType(IntEnum):
    NOOP = 0x01
    ERROR = 0x02
    DONE = 0x03


class RTMType(IntEnum):
    NEWLINK = 16
    DELLINK = 17
    GETLINK = 18
    NEWADDR = 20
    DELADDR = 21
    GETADDR = 22
    NEWROUTE = 24
    DELROUTE = 25
    GETROUTE = 26


class AddressFamily(IntEnum):
    UNSPEC = 0
    INET = 2
    INET6 = 10
    LINK = 17  # AF_PACKET on Linux


class IFLAAttr(IntEnum):
    UNSPEC = 0
    ADDRESS = 1
    BROADCAST = 2
    IFNAME = 3
    MTU = 4
    LINK = 5
    QDISC = 6
    STATS = 7
    COST = 8
    PRIORITY = 9
    MASTER = 10
    WIRELESS = 11
    PROTINFO = 12
    TXQLEN = 13
    MAP = 14
    WEIGHT = 15
    OPERSTATE = 16
    LINKMODE = 17
    LINKINFO = 18
    NET_NS_PID = 19
    IFALIAS = 20
    NUM_VF = 21
    VFINFO_LIST = 22
    STATS64 = 23
    VF_PORTS = 24
    PORT_SELF = 25
    AF_SPEC = 26
    GROUP = 27
    NET_NS_FD = 28
    EXT_MASK = 29
    PROMISCUITY = 30
    NUM_TX_QUEUES = 31
    NUM_RX_QUEUES = 32
    CARRIER = 33
    PHYS_PORT_ID = 34
    CARRIER_CHANGES = 35
    PHYS_SWITCH_ID = 36
    LINK_NETNSID = 37
    PHYS_PORT_NAME = 38
    PROTO_DOWN = 39
    GSO_MAX_SEGS = 40
    GSO_MAX_SIZE = 41
    PAD = 42
    XDP = 43
    EVENT = 44
    NEW_NETNSID = 45
    IF_NETNSID = 46
    CARRIER_UP_COUNT = 47
    CARRIER_DOWN_COUNT = 48
    NEW_IFINDEX = 49
    MIN_MTU = 50
    MAX_MTU = 51
    PROP_LIST = 52
    ALT_IFNAME = 53
    PERM_ADDRESS = 54
    PROTO_DOWN_REASON = 55
    PARENT_DEV_NAME = 56
    PARENT_DEV_BUS_NAME = 57


class IFLAInfoAttr(IntEnum):
    """IFLA_LINKINFO nested attributes"""

    UNSPEC = 0
    KIND = 1
    DATA = 2
    XSTATS = 3
    SLAVE_KIND = 4
    SLAVE_DATA = 5


class IFLAVlanAttr(IntEnum):
    """IFLA_INFO_DATA attributes for vlan"""

    UNSPEC = 0
    ID = 1


class IFLABondAttr(IntEnum):
    """IFLA_INFO_DATA attributes for bond"""

    UNSPEC = 0
    MODE = 1
    ACTIVE_SLAVE = 2
    MIIMON = 3
    UPDELAY = 4
    DOWNDELAY = 5
    USE_CARRIER = 6
    ARP_INTERVAL = 7
    ARP_IP_TARGET = 8
    ARP_VALIDATE = 9
    ARP_ALL_TARGETS = 10
    PRIMARY = 11
    PRIMARY_RESELECT = 12
    FAIL_OVER_MAC = 13
    XMIT_HASH_POLICY = 14
    RESEND_IGMP = 15
    NUM_PEER_NOTIF = 16
    ALL_SLAVES_ACTIVE = 17
    MIN_LINKS = 18
    LP_INTERVAL = 19
    PACKETS_PER_SLAVE = 20
    AD_LACP_RATE = 21
    AD_SELECT = 22


class BondMode(IntEnum):
    """Bond interface modes"""

    BALANCE_RR = 0  # Round-robin
    ACTIVE_BACKUP = 1  # Failover
    BALANCE_XOR = 2
    BROADCAST = 3
    LACP = 4  # 802.3ad
    BALANCE_TLB = 5
    BALANCE_ALB = 6


class BondXmitHashPolicy(IntEnum):
    """Bond transmit hash policy"""

    LAYER2 = 0
    LAYER34 = 1
    LAYER23 = 2
    ENCAP23 = 3
    ENCAP34 = 4


class BondLacpRate(IntEnum):
    """LACP rate for 802.3ad mode"""

    SLOW = 0
    FAST = 1


class IFAAttr(IntEnum):
    UNSPEC = 0
    ADDRESS = 1
    LOCAL = 2
    LABEL = 3
    BROADCAST = 4
    ANYCAST = 5
    CACHEINFO = 6
    MULTICAST = 7
    FLAGS = 8
    RT_PRIORITY = 9
    TARGET_NETNSID = 10
    PROTO = 11


class IFAFlags(IntFlag):
    SECONDARY = 0x01
    TEMPORARY = 0x01
    NODAD = 0x02
    OPTIMISTIC = 0x04
    DADFAILED = 0x08
    HOMEADDRESS = 0x10
    DEPRECATED = 0x20
    TENTATIVE = 0x40
    PERMANENT = 0x80
    MANAGETEMPADDR = 0x100
    NOPREFIXROUTE = 0x200
    MCAUTOJOIN = 0x400
    STABLE_PRIVACY = 0x800


class RTScope(IntEnum):
    UNIVERSE = 0
    SITE = 200
    LINK = 253
    HOST = 254
    NOWHERE = 255


class IFFlags(IntFlag):
    UP = 0x1
    BROADCAST = 0x2
    DEBUG = 0x4
    LOOPBACK = 0x8
    POINTOPOINT = 0x10
    NOTRAILERS = 0x20
    RUNNING = 0x40
    NOARP = 0x80
    PROMISC = 0x100
    ALLMULTI = 0x200
    MASTER = 0x400
    SLAVE = 0x800
    MULTICAST = 0x1000
    PORTSEL = 0x2000
    AUTOMEDIA = 0x4000
    DYNAMIC = 0x8000
    LOWER_UP = 0x10000
    DORMANT = 0x20000
    ECHO = 0x40000


class IFOperState(IntEnum):
    UNKNOWN = 0
    NOTPRESENT = 1
    DOWN = 2
    LOWERLAYERDOWN = 3
    TESTING = 4
    DORMANT = 5
    UP = 6


class RTEXTFilter(IntFlag):
    VF = 1 << 0
    BRVLAN = 1 << 1
    BRVLAN_COMPRESSED = 1 << 2
    SKIP_STATS = 1 << 3
    MRP = 1 << 4
    CFM_CONFIG = 1 << 5
    CFM_STATUS = 1 << 6
    MST = 1 << 7


class RTAAttr(IntEnum):
    """Route attributes (RTA_*)"""

    UNSPEC = 0
    DST = 1
    SRC = 2
    IIF = 3
    OIF = 4
    GATEWAY = 5
    PRIORITY = 6
    PREFSRC = 7
    METRICS = 8
    MULTIPATH = 9
    PROTOINFO = 10
    FLOW = 11
    CACHEINFO = 12
    SESSION = 13
    MP_ALGO = 14
    TABLE = 15
    MARK = 16
    MFC_STATS = 17
    VIA = 18
    NEWDST = 19
    PREF = 20
    ENCAP_TYPE = 21
    ENCAP = 22
    EXPIRES = 23
    PAD = 24
    UID = 25
    TTL_PROPAGATE = 26
    IP_PROTO = 27
    SPORT = 28
    DPORT = 29
    NH_ID = 30


class RTTable(IntEnum):
    """Routing table IDs"""

    UNSPEC = 0
    COMPAT = 252
    DEFAULT = 253
    MAIN = 254
    LOCAL = 255


class RTProtocol(IntEnum):
    """Route origin (how route was learned)"""

    UNSPEC = 0
    REDIRECT = 1
    KERNEL = 2
    BOOT = 3
    STATIC = 4
    GATED = 8
    RA = 9
    MRT = 10
    ZEBRA = 11
    BIRD = 12
    DNROUTED = 13
    XORP = 14
    NTK = 15
    DHCP = 16
    MROUTED = 17
    KEEPALIVED = 18
    BABEL = 42
    BGP = 186
    ISIS = 187
    OSPF = 188
    RIP = 189
    EIGRP = 192


class RTNType(IntEnum):
    """Route types"""

    UNSPEC = 0
    UNICAST = 1
    LOCAL = 2
    BROADCAST = 3
    ANYCAST = 4
    MULTICAST = 5
    BLACKHOLE = 6
    UNREACHABLE = 7
    PROHIBIT = 8
    THROW = 9
    NAT = 10
    XRESOLVE = 11


class RTMFlags(IntFlag):
    """Route message flags"""

    NOTIFY = 0x100
    CLONED = 0x200
    EQUALIZE = 0x400
    PREFIX = 0x800
    LOOKUP_TABLE = 0x1000
    FIB_MATCH = 0x2000
    OFFLOAD = 0x4000
    TRAP = 0x8000
    OFFLOAD_FAILED = 0x20000000
