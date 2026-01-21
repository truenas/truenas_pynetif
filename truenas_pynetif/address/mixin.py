import socket
import time

from truenas_pynetif.address.constants import AddressFamily
from truenas_pynetif.address.netlink import AddressInfo, get_addresses, netlink_route
from truenas_pynetif.netlink import DumpInterrupted
from truenas_pynetif.utils import run

__all__ = ("AddressMixin",)


class AddressMixin:
    def add_address(self, address: AddressInfo):
        self._address_op("add", address)

    def flush(self):
        # Remove all configured ip addresses
        run(["ip", "addr", "flush", "dev", self.name, "scope", "global"])

    def remove_address(self, address: AddressInfo):
        self._address_op("del", address)

    def replace_address(self, address: AddressInfo):
        self._address_op("replace", address)

    def _address_op(self, op: str, address: AddressInfo):
        if address.family == AddressFamily.INET:
            cmd = ["ip", "addr", op, f"{address.address}/{address.prefixlen}"]
            if op == "add":
                cmd.extend(["brd", "+"])
            cmd.extend(["dev", self.name])
            run(cmd)
        elif address.family == AddressFamily.INET6:
            cmd = [
                "ip",
                "addr",
                op,
                f"{address.address}/{address.prefixlen}",
                "dev",
                self.name,
            ]
            run(cmd)

    def _get_addresses(self) -> list[AddressInfo]:
        try:
            if_index = socket.if_nametoindex(self.name)
        except OSError:
            return []

        all_addresses = list()
        with netlink_route() as sock:
            for addr in get_addresses(sock):
                if addr.index != if_index:
                    continue
                if addr.family not in (AddressFamily.INET, AddressFamily.INET6):
                    continue
                all_addresses.append(addr)
        return all_addresses

    @property
    def addresses(self) -> list[AddressInfo]:
        retries = 5
        while True:
            try:
                return self._get_addresses()
            except DumpInterrupted:
                # low-grade hardware can produce this which
                # isn't necessarily fatal and the request
                # should be retried
                retries -= 1
                if retries == 0:
                    raise

                time.sleep(0.2)
