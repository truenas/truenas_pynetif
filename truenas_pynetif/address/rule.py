from __future__ import annotations

import ipaddress
import socket
import struct

from truenas_pynetif.address.constants import (
    AddressFamily,
    FRAAttr,
    FRAction,
    RTMType,
    RTTable,
)
from truenas_pynetif.netlink._core import (
    NLMsgFlags,
    format_address,
    pack_nlattr,
    pack_nlattr_u32,
    pack_nlmsg,
    parse_attrs,
    recv_msgs,
)
from truenas_pynetif.netlink.dataclass_types import RuleInfo

__all__ = ("get_rules", "add_rule", "delete_rule")


def get_rules(
    sock: socket.socket,
    family: int = AddressFamily.UNSPEC,
) -> list[RuleInfo]:
    """Query FIB rules from the kernel.

    Args:
        sock: Netlink socket from netlink_route()
        family: Address family filter (UNSPEC returns both IPv4 and IPv6)

    Returns:
        List of RuleInfo objects for all matching rules.
    """
    fib_rule_hdr = struct.pack(
        "BBBBBBBBI",
        family,
        0,
        0,
        0,
        RTTable.UNSPEC,
        0,
        0,
        FRAction.TO_TBL,
        0,
    )

    msg = pack_nlmsg(
        RTMType.GETRULE,
        NLMsgFlags.REQUEST | NLMsgFlags.DUMP,
        fib_rule_hdr,
    )
    sock.send(msg)

    rules: list[RuleInfo] = []
    for msg_type, payload in recv_msgs(sock):
        if msg_type != RTMType.NEWRULE:
            continue
        if len(payload) < 12:
            continue

        (
            rule_family,
            rule_dst_len,
            rule_src_len,
            rule_tos,
            rule_table,
            rule_res1,
            rule_res2,
            rule_action,
            rule_flags,
        ) = struct.unpack_from("BBBBBBBBI", payload, 0)

        attrs = parse_attrs(payload, 12)

        table = rule_table
        if FRAAttr.TABLE in attrs and len(attrs[FRAAttr.TABLE]) >= 4:
            table = struct.unpack("I", attrs[FRAAttr.TABLE][:4])[0]

        priority = None
        if FRAAttr.PRIORITY in attrs and len(attrs[FRAAttr.PRIORITY]) >= 4:
            priority = struct.unpack("I", attrs[FRAAttr.PRIORITY][:4])[0]

        src = None
        if FRAAttr.SRC in attrs:
            src = format_address(rule_family, attrs[FRAAttr.SRC])

        dst = None
        if FRAAttr.DST in attrs:
            dst = format_address(rule_family, attrs[FRAAttr.DST])

        iifname = None
        if FRAAttr.IIFNAME in attrs:
            iifname = attrs[FRAAttr.IIFNAME].rstrip(b"\x00").decode()

        fwmark = None
        if FRAAttr.FWMARK in attrs and len(attrs[FRAAttr.FWMARK]) >= 4:
            fwmark = struct.unpack("I", attrs[FRAAttr.FWMARK][:4])[0]

        protocol = None
        if FRAAttr.PROTOCOL in attrs and len(attrs[FRAAttr.PROTOCOL]) >= 1:
            protocol = attrs[FRAAttr.PROTOCOL][0]

        rules.append(
            RuleInfo(
                family=rule_family,
                src_len=rule_src_len,
                dst_len=rule_dst_len,
                table=table,
                action=rule_action,
                priority=priority,
                src=src,
                dst=dst,
                iifname=iifname,
                fwmark=fwmark,
                protocol=protocol,
            )
        )

    return rules


def add_rule(
    sock: socket.socket,
    table: int,
    priority: int,
    *,
    src: str | None = None,
    family: int = AddressFamily.INET,
) -> None:
    """Add a FIB rule that directs matching traffic to a routing table.

    Args:
        sock: Netlink socket from netlink_route()
        table: Routing table ID to direct traffic to
        priority: Rule priority (lower values are evaluated first)
        src: Source network in CIDR notation (e.g. "192.168.1.0/24").
             When provided, family is auto-detected from the address.
        family: Address family (default: INET). Ignored when src is provided.

    Raises:
        NetlinkError: If a rule with this priority already exists (errno 17 EEXIST)
    """
    src_len = 0
    src_bytes = b""
    if src is not None:
        network = ipaddress.ip_network(src, strict=False)
        src_len = network.prefixlen
        src_bytes = network.network_address.packed
        family = AddressFamily.INET if network.version == 4 else AddressFamily.INET6

    fib_rule_hdr = struct.pack(
        "BBBBBBBBI",
        family,
        0,
        src_len,
        0,
        RTTable.UNSPEC,
        0,
        0,
        FRAction.TO_TBL,
        0,
    )

    attrs = b""
    attrs += pack_nlattr_u32(FRAAttr.TABLE, table)
    attrs += pack_nlattr_u32(FRAAttr.PRIORITY, priority)
    if src_bytes:
        attrs += pack_nlattr(FRAAttr.SRC, src_bytes)

    msg = pack_nlmsg(
        RTMType.NEWRULE,
        NLMsgFlags.REQUEST | NLMsgFlags.ACK | NLMsgFlags.CREATE | NLMsgFlags.EXCL,
        fib_rule_hdr + attrs,
    )
    sock.send(msg)
    recv_msgs(sock)


def delete_rule(
    sock: socket.socket,
    priority: int,
    *,
    family: int = AddressFamily.INET,
) -> None:
    """Delete a FIB rule by priority.

    Args:
        sock: Netlink socket from netlink_route()
        priority: Priority of the rule to delete
        family: Address family of the rule (default: INET)

    Raises:
        NetlinkError: If no rule with this priority exists (errno 2 ENOENT)
    """
    fib_rule_hdr = struct.pack(
        "BBBBBBBBI",
        family,
        0,
        0,
        0,
        RTTable.UNSPEC,
        0,
        0,
        FRAction.TO_TBL,
        0,
    )
    attrs = pack_nlattr_u32(FRAAttr.PRIORITY, priority)
    msg = pack_nlmsg(
        RTMType.DELRULE,
        NLMsgFlags.REQUEST | NLMsgFlags.ACK,
        fib_rule_hdr + attrs,
    )
    sock.send(msg)
    recv_msgs(sock)
