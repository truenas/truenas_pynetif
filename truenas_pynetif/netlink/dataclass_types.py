from dataclasses import dataclass, field


@dataclass(slots=True, frozen=True, kw_only=True)
class AddressInfo:
    """Network address information."""

    # Fields used for equality and hashing
    family: int
    prefixlen: int
    address: str
    broadcast: str | None = None
    # Fields below are informational only - not used for equality/hashing
    flags: int = field(default=0, compare=False, hash=False)
    scope: int = field(default=0, compare=False, hash=False)
    index: int = field(default=0, compare=False, hash=False)
    ifname: str | None = field(default=None, compare=False, hash=False)
    local: str | None = field(default=None, compare=False, hash=False)
    label: str | None = field(default=None, compare=False, hash=False)
    # Extended fields from IFA_PROTO and IFA_CACHEINFO
    proto: int | None = field(default=None, compare=False, hash=False)
    valid_lft: int | None = field(default=None, compare=False, hash=False)
    preferred_lft: int | None = field(default=None, compare=False, hash=False)

    def asdict(self, stats: bool = False) -> dict[str, str | int]:
        """Convert to dict format compatible with InterfaceAddress.asdict()."""
        if self.family == 2:  # ipv4 AF_INET
            af_name = "INET"
        elif self.family == 10:  # ipv6 AF_INET6
            af_name = "INET6"
        else:
            af_name = "LINK"

        result: dict[str, str | int] = {
            "type": af_name,
            "address": self.address,
        }
        if self.prefixlen:
            result["netmask"] = self.prefixlen
        if self.broadcast:
            result["broadcast"] = self.broadcast
        return result


@dataclass(slots=True, frozen=True, kw_only=True)
class LinkInfo:
    """Network link/interface information."""

    # Core fields
    index: int
    flags: int
    mtu: int
    operstate: int
    address: str | None = None
    perm_address: str | None = None
    broadcast: str | None = None
    # Extended fields
    txqlen: int = 0
    min_mtu: int = 0
    max_mtu: int = 0
    carrier: bool = False
    carrier_changes: int = 0
    num_tx_queues: int = 1
    num_rx_queues: int = 1
    # Master device index (for bond members, bridge ports, etc.)
    master: int | None = None
    # Parent device info (for USB detection, etc.)
    parentbus: str | None = None
    parentdev: str | None = None
    # Alternate names
    altnames: tuple[str, ...] = ()


@dataclass(slots=True, frozen=True, kw_only=True)
class RouteInfo:
    """Routing table entry information."""

    family: int
    dst_len: int
    table: int
    protocol: int
    scope: int
    route_type: int
    flags: int
    dst: str | None = None
    gateway: str | None = None
    prefsrc: str | None = None
    oif: int | None = None
    oif_name: str | None = None
    priority: int | None = None
