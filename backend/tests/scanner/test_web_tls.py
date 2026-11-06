from datetime import UTC, datetime, timedelta

import pytest

from scanner.checks.web_tls import SOON_DAYS, URGENT_DAYS, TlsCheck, evaluate_tls
from scanner.types import CapabilityMissing, CheckContext, TlsObservation

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


def keys(results):
    return [r.check_key for r in results]


def trusted(days_left: float, **kwargs) -> TlsObservation:
    return TlsObservation(not_after=NOW + timedelta(days=days_left), protocol="TLSv1.3", **kwargs)


def evaluate(observed):
    return evaluate_tls("acme.example", observed, NOW)


# ---- reachability ------------------------------------------------------------------------------


def test_a_host_with_no_public_address_has_nothing_to_judge():
    assert evaluate(TlsObservation(resolved=False, reachable=False)) == []


def test_a_host_that_refuses_https_is_reported():
    results = evaluate(TlsObservation(reachable=False))
    assert keys(results) == ["TLS_NOT_AVAILABLE"]
    assert results[0].severity == "medium"


# ---- certificate problems ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("problem", "key", "severity"),
    [
        ("expired", "TLS_CERT_EXPIRED", "high"),
        ("self_signed", "TLS_CERT_SELF_SIGNED", "high"),
        ("hostname_mismatch", "TLS_CERT_HOSTNAME_MISMATCH", "high"),
        ("untrusted_chain", "TLS_CERT_UNTRUSTED_CHAIN", "medium"),
    ],
)
def test_each_certificate_problem_has_its_own_finding(problem, key, severity):
    results = evaluate(TlsObservation(cert_problem=problem))
    assert keys(results) == [key]
    assert results[0].severity == severity


def test_an_unknown_problem_name_fails_loudly_instead_of_being_guessed():
    with pytest.raises(KeyError):
        evaluate(TlsObservation(cert_problem="something_new"))


def test_a_certificate_problem_means_the_expiry_date_is_not_judged():
    observed = TlsObservation(cert_problem="self_signed", not_after=NOW + timedelta(days=1))
    assert keys(evaluate(observed)) == ["TLS_CERT_SELF_SIGNED"]


# ---- expiry ------------------------------------------------------------------------------------


def test_a_certificate_with_plenty_of_time_left_is_fine():
    assert evaluate(trusted(90)) == []
    assert evaluate(trusted(SOON_DAYS + 1)) == []


@pytest.mark.parametrize(
    ("days", "severity", "days_left"),
    [
        (SOON_DAYS, "medium", 30),
        (URGENT_DAYS + 1, "medium", 8),
        (URGENT_DAYS, "high", 7),
        (0.5, "high", 0),
    ],
)
def test_expiring_soon_escalates_as_the_date_approaches(days, severity, days_left):
    results = evaluate(trusted(days))
    assert keys(results) == ["TLS_CERT_EXPIRING_SOON"]
    assert results[0].severity == severity
    assert results[0].evidence["days_left"] == days_left


def test_a_certificate_whose_date_has_passed_is_expired():
    results = evaluate(trusted(-0.1))
    assert keys(results) == ["TLS_CERT_EXPIRED"]
    assert results[0].evidence["days_left"] == -1


# ---- legacy protocols --------------------------------------------------------------------------


def test_legacy_protocols_alongside_modern_ones_are_medium():
    results = evaluate(trusted(90, legacy_protocols=("TLSv1", "TLSv1.1")))
    assert keys(results) == ["TLS_LEGACY_PROTOCOL"]
    assert results[0].severity == "medium"
    assert results[0].evidence == {"protocols": ["TLSv1", "TLSv1.1"], "modern_tls": True}


def test_a_server_with_nothing_newer_than_tls_1_1_is_high():
    observed = TlsObservation(modern_tls=False, legacy_protocols=("TLSv1",))
    results = evaluate(observed)
    assert keys(results) == ["TLS_LEGACY_PROTOCOL"]
    assert results[0].severity == "high"


def test_problems_are_reported_together():
    observed = trusted(3, legacy_protocols=("TLSv1",))
    assert keys(evaluate(observed)) == ["TLS_CERT_EXPIRING_SOON", "TLS_LEGACY_PROTOCOL"]


# ---- the check ---------------------------------------------------------------------------------


class Probe:
    def __init__(self, observed):
        self.observed, self.hosts = observed, []

    def probe(self, host):
        self.hosts.append(host)
        return self.observed


def test_the_check_probes_the_domain_and_uses_its_clock():
    probe = Probe(trusted(3))
    check = TlsCheck(clock=lambda: NOW)
    results = check.run(CheckContext("acme.example", resolver=None, tls=probe))
    assert probe.hosts == ["acme.example"]
    assert keys(results) == ["TLS_CERT_EXPIRING_SOON"]


def test_the_check_refuses_to_run_without_a_probe():
    with pytest.raises(CapabilityMissing):
        TlsCheck().run(CheckContext("acme.example", resolver=None))


def test_a_probe_failure_propagates_so_the_check_fails_instead_of_reporting():
    class Failing:
        def probe(self, host):
            raise TimeoutError("handshake timed out")

    with pytest.raises(TimeoutError):
        TlsCheck().run(CheckContext("acme.example", resolver=None, tls=Failing()))


def test_every_emitted_key_is_declared():
    assert set(TlsCheck.emits) == {
        "TLS_NOT_AVAILABLE", "TLS_CERT_EXPIRED", "TLS_CERT_EXPIRING_SOON", "TLS_CERT_SELF_SIGNED",
        "TLS_CERT_HOSTNAME_MISMATCH", "TLS_CERT_UNTRUSTED_CHAIN", "TLS_LEGACY_PROTOCOL",
    }  # fmt: skip