import dns.exception
import dns.resolver
import pytest

from scanner.dns import DnsPythonResolver, ResolverUnhealthy


class FakeRdata:
    def __init__(self, *strings):
        self.strings = strings


def raising(exc):
    def resolve(name, rtype):
        raise exc()

    return resolve


@pytest.fixture
def resolver():
    """Canary disabled: these tests are about how a single lookup is interpreted."""
    return DnsPythonResolver(timeout=1, nameservers=["9.9.9.9"], canary=None)


def test_multi_string_txt_records_are_joined(resolver, monkeypatch):
    answer = [FakeRdata(b"v=DMARC1; ", b"p=reject")]
    monkeypatch.setattr(resolver._resolver, "resolve", lambda name, rtype: answer)
    assert resolver.txt("_dmarc.acme.example") == ["v=DMARC1; p=reject"]


@pytest.mark.parametrize("exc", [dns.resolver.NXDOMAIN, dns.resolver.NoAnswer])
def test_missing_records_are_an_empty_list(resolver, monkeypatch, exc):
    monkeypatch.setattr(resolver._resolver, "resolve", raising(exc))
    assert resolver.txt("_dmarc.acme.example") == []


@pytest.mark.parametrize("exc", [dns.exception.Timeout, dns.resolver.NoNameservers])
def test_failures_raise_instead_of_looking_like_missing_records(resolver, monkeypatch, exc):
    """A timeout must never be mistaken for 'no DMARC record', which would be a false finding."""
    monkeypatch.setattr(resolver._resolver, "resolve", raising(exc))
    with pytest.raises(dns.exception.DNSException):
        resolver.txt("_dmarc.acme.example")


def test_custom_nameservers_are_used():
    assert DnsPythonResolver(nameservers=["1.1.1.1"])._resolver.nameservers == ["1.1.1.1"]


# ---- the canary: never trust a resolver that cannot resolve a name that must exist ---------------


def test_a_resolver_that_answers_nxdomain_for_everything_is_refused():
    """Captive portals and egress blocks do this. Without the canary it reads as 'no DMARC'."""
    sinkhole = DnsPythonResolver(canary="a.root-servers.net")
    sinkhole._resolver.resolve = raising(dns.resolver.NXDOMAIN)

    with pytest.raises(ResolverUnhealthy, match="refusing to trust"):
        sinkhole.txt("_dmarc.acme.example")


def test_the_canary_is_a_dns_error_so_callers_already_handle_it():
    assert issubclass(ResolverUnhealthy, dns.exception.DNSException)


def test_a_healthy_resolver_still_reports_genuinely_missing_records():
    calls = []

    def resolve(name, rtype):
        calls.append((name, rtype))
        if name == "a.root-servers.net":
            return [FakeRdata(b"x")]
        raise dns.resolver.NXDOMAIN

    healthy = DnsPythonResolver(canary="a.root-servers.net")
    healthy._resolver.resolve = resolve

    assert healthy.txt("_dmarc.acme.example") == []  # canary fine, record truly absent
    assert calls[0] == ("a.root-servers.net", "A")


def test_the_canary_is_checked_once_per_resolver():
    calls = []

    def resolve(name, rtype):
        calls.append(name)
        return [FakeRdata(b"v=DMARC1; p=reject")]

    resolver = DnsPythonResolver(canary="a.root-servers.net")
    resolver._resolver.resolve = resolve
    resolver.txt("_dmarc.a.example")
    resolver.txt("_dmarc.b.example")
    assert calls.count("a.root-servers.net") == 1


def test_a_canary_timeout_is_retried_next_time_not_cached_as_healthy():
    state = {"fail": True}

    def resolve(name, rtype):
        if name == "a.root-servers.net" and state["fail"]:
            raise dns.exception.Timeout
        return [FakeRdata(b"ok")]

    resolver = DnsPythonResolver(canary="a.root-servers.net")
    resolver._resolver.resolve = resolve
    with pytest.raises(dns.exception.Timeout):
        resolver.txt("x.example")
    state["fail"] = False
    assert resolver.txt("x.example") == ["ok"]