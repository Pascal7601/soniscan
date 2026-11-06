"""The test suite must be hermetic: a test that reaches for the real network fails loudly."""

import socket

import dns.exception
import pytest

from scanner.dns import DnsPythonResolver
from scanner.safety import resolve_public


def test_connecting_to_a_remote_host_name_is_refused():
    with pytest.raises(RuntimeError, match="tests must not use the network"):
        socket.create_connection(("example.com", 443), timeout=1)


def test_connecting_to_a_remote_ip_is_refused():
    with pytest.raises(RuntimeError, match="tests must not use the network"):
        socket.create_connection(("93.184.216.34", 443), timeout=1)


def test_sending_udp_to_a_remote_server_is_refused():
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock,
        pytest.raises(RuntimeError, match="tests must not use the network"),
    ):
        sock.sendto(b"x", ("8.8.8.8", 53))


def test_a_real_dns_resolver_cannot_leak_a_lookup():
    # dnspython catches the refusal per server and reports a timeout, but nothing was sent.
    with pytest.raises(dns.exception.DNSException) as failure:
        DnsPythonResolver(timeout=1, canary=None).txt("_dmarc.example.com")
    assert "tests must not use the network" in str(failure.value)


def test_resolving_a_real_name_through_the_safety_guard_is_refused():
    with pytest.raises(RuntimeError, match="tests must not use the network"):
        resolve_public("example.com")


def test_loopback_still_works_for_local_test_servers():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=2) as client:
            conn, _ = server.accept()
            client.sendall(b"ping")
            assert conn.recv(4) == b"ping"
            conn.close()


def test_a_function_that_captured_getaddrinfo_early_cannot_escape():
    """The bug the guard found: a reference taken before patching must not bypass it."""
    captured = socket.getaddrinfo  # already the guarded version here, so also check the low level
    with pytest.raises(RuntimeError, match="tests must not use the network"):
        socket._socket.getaddrinfo("example.com", 443)
    assert callable(captured)