import socket

import pytest

from scanner.safety import UnsafeTarget, is_public_ip, resolve_public


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "not-an-ip",
    ],
)
def test_non_public_addresses_are_blocked(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(ip):
    assert is_public_ip(ip)


def _fake(*addresses):
    def getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addresses]

    return getaddrinfo


def test_resolve_public_returns_addresses():
    assert resolve_public("x.example", _fake("8.8.8.8")) == ["8.8.8.8"]


def test_resolve_public_rejects_if_any_address_is_internal():
    with pytest.raises(UnsafeTarget):
        resolve_public("rebind.example", _fake("8.8.8.8", "10.0.0.1"))


def test_resolve_public_rejects_metadata_service():
    with pytest.raises(UnsafeTarget):
        resolve_public("meta.example", _fake("169.254.169.254"))
