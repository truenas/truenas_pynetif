# -*- coding=utf-8 -*-
import enum
import logging

logger = logging.getLogger(__name__)

__all__ = ['AddressFamily']


class AddressFamily(enum.IntEnum):
    UNIX = 1
    INET = 2
    # IMPLINK = defs.AF_IMPLINK
    # PUP = defs.AF_PUP
    # CHAOS = defs.AF_CHAOS
    # NETBIOS = defs.AF_NETBIOS
    # ISO = defs.AF_ISO
    # OSI = defs.AF_OSI
    # ECMA = defs.AF_ECMA
    # DATAKIT = defs.AF_DATAKIT
    # CCITT = defs.AF_CCITT
    # SNA = defs.AF_SNA
    # DECnet = defs.AF_DECnet
    # DLI = defs.AF_DLI
    # LAT = defs.AF_LAT
    # HYLINK = defs.AF_HYLINK
    # APPLETALK = defs.AF_APPLETALK
    # ROUTE = defs.AF_ROUTE
    LINK = 17
    # COIP = defs.AF_COIP
    # CNT = defs.AF_CNT
    # IPX = defs.AF_IPX
    # SIP = defs.AF_SIP
    # ISDN = defs.AF_ISDN
    # E164 = defs.AF_E164
    INET6 = 10
    # NATM = defs.AF_NATM
    # ATM = defs.AF_ATM
    # NETGRAPH = defs.AF_NETGRAPH
    # SLOW = defs.AF_SLOW
    # SCLUSTER = defs.AF_SCLUSTER
    # ARP = defs.AF_ARP
    # BLUETOOTH = defs.AF_BLUETOOTH
    # IEEE80211 = defs.AF_IEEE80211
    # INET_SDP = defs.AF_INET_SDP
    # INET6_SDP = defs.AF_INET6_SDP
