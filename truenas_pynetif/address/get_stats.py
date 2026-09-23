from __future__ import annotations

import socket
import struct

from truenas_pynetif.address.constants import AddressFamily, IFLAStatsAttr, RTMType
from truenas_pynetif.netlink import LinkStats
from truenas_pynetif.netlink._core import NLMsgFlags, pack_nlmsg, parse_attrs, recv_msgs

__all__ = ("get_link_stats",)


def get_link_stats(sock: socket.socket) -> dict[int, LinkStats]:
    """Get counters for all interfaces, keyed by ifindex."""
    ifstatsmsg = struct.pack("BxxxII", AddressFamily.UNSPEC, 0, 1 << (IFLAStatsAttr.LINK_64 - 1))
    msg = pack_nlmsg(RTMType.GETSTATS, NLMsgFlags.REQUEST | NLMsgFlags.DUMP, ifstatsmsg)
    sock.send(msg)

    stats: dict[int, LinkStats] = {}
    for msg_type, payload in recv_msgs(sock):
        if msg_type != RTMType.NEWSTATS:
            continue
        data = parse_attrs(payload, 12).get(IFLAStatsAttr.LINK_64)
        if data is None:
            continue
        rx_packets, tx_packets, rx_bytes, tx_bytes, rx_errors, tx_errors, rx_dropped, tx_dropped = (
            struct.unpack_from("8Q", data)
        )
        stats[struct.unpack_from("I", payload, 4)[0]] = LinkStats(
            rx_packets=rx_packets,
            tx_packets=tx_packets,
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
            rx_errors=rx_errors,
            tx_errors=tx_errors,
            rx_dropped=rx_dropped,
            tx_dropped=tx_dropped,
        )

    return stats
