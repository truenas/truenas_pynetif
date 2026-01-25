"""Dummy interface creation."""

import socket

from truenas_pynetif.address._link_helpers import _create_link

__all__ = ("create_dummy",)


def create_dummy(sock: socket.socket, name: str) -> None:
    """Create a dummy interface.

    Args:
        sock: Netlink socket from netlink_route()
        name: Name for the new dummy interface
    """
    _create_link(sock, name, "dummy")
