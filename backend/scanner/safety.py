"""Target safety. Every network probe MUST pass through this module first.

Blocks private, loopback, link-local, carrier-grade NAT, multicast and reserved addresses so
the scanner cannot be turned against internal infrastructure (SSRF) or cloud metadata services.
Connect to the returned IP, not the hostname, so DNS cannot change between check and use.
"""

import ipaddress
import socket
from collections.abc import Callable

GetAddrInfo = Callable[..., list]


class UnsafeTarget(Exception):
    pass


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve_public(host: str, getaddrinfo: GetAddrInfo = socket.getaddrinfo) -> list[str]:
    """Resolve `host` and return its addresses, raising if ANY address is not public."""
    try:
        infos = getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTarget(f"cannot resolve {host}") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsafeTarget(f"{host} has no addresses")
    blocked = [a for a in addresses if not is_public_ip(a)]
    if blocked:
        raise UnsafeTarget(f"{host} resolves to non-public address(es): {', '.join(blocked)}")
    return addresses
