import pytest

from scanner.checks.spf import MAX_LOOKUPS, SpfCheck, count_lookups, evaluate_spf, spf_records
from scanner.types import CheckContext


class Dns:
    """A tiny fake DNS: name -> TXT records."""

    def __init__(self, zone=None):
        self.zone = zone or {}
        self.queries = []

    def txt(self, name):
        self.queries.append(name)
        return self.zone.get(name, [])


def keys(results):
    return [r.check_key for r in results]


def evaluate(records, zone=None):
    return evaluate_spf("acme.example", records, Dns(zone).txt)


# ---- the main rules ----------------------------------------------------------------------------


def test_no_spf_record_is_reported():
    assert keys(evaluate([])) == ["EMAIL_SPF_MISSING"]
    assert keys(evaluate(["google-site-verification=abc"])) == ["EMAIL_SPF_MISSING"]


def test_two_spf_records_are_an_error():
    results = evaluate(["v=spf1 -all", "v=spf1 include:_spf.google.com ~all"])
    assert keys(results) == ["EMAIL_SPF_MULTIPLE"]
    assert results[0].evidence == {"count": 2}


@pytest.mark.parametrize("ending", ["-all", "~all"])
def test_a_proper_record_has_no_findings(ending):
    assert evaluate([f"v=spf1 include:_spf.google.com {ending}"]) == []


@pytest.mark.parametrize("ending", ["+all", "all"])
def test_a_record_that_allows_everyone_is_high_severity(ending):
    results = evaluate([f"v=spf1 mx {ending}"])
    assert keys(results) == ["EMAIL_SPF_ALLOWS_ANYONE"]
    assert results[0].severity == "high"
    assert results[0].evidence == {"mechanism": ending}


def test_neutral_all_is_weak():
    results = evaluate(["v=spf1 mx ?all"])
    assert keys(results) == ["EMAIL_SPF_WEAK"]
    assert results[0].evidence["reason"] == "neutral"


def test_a_record_with_no_closing_rule_is_weak():
    results = evaluate(["v=spf1 ip4:203.0.113.5"])
    assert keys(results) == ["EMAIL_SPF_WEAK"]
    assert results[0].evidence == {"reason": "no_all"}


def test_a_redirect_replaces_the_need_for_all():
    assert (
        evaluate(["v=spf1 redirect=_spf.acme.example"], {"_spf.acme.example": ["v=spf1 -all"]})
        == []
    )


def test_matching_ignores_case_and_surrounding_whitespace():
    assert evaluate(["  V=SPF1 MX -ALL  "]) == []
    assert spf_records(["v=spf10 -all", "v=spf1"]) == ["v=spf1"]  # v=spf10 is not SPF


# ---- counting DNS lookups ----------------------------------------------------------------------


def test_only_lookup_mechanisms_are_counted():
    record = (
        "v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 a mx exists:x.example include:a.example -all"
    )
    assert count_lookups(record, Dns({"a.example": ["v=spf1 ip4:1.2.3.4 -all"]}).txt) == 4


def test_nested_includes_are_followed():
    zone = {
        "a.example": ["v=spf1 include:b.example mx -all"],  # 2 own + b
        "b.example": ["v=spf1 a a -all"],  # 2
    }
    assert count_lookups("v=spf1 include:a.example -all", Dns(zone).txt) == 1 + 2 + 2


def test_too_many_lookups_through_nested_includes_is_reported():
    zone = {f"p{i}.example": ["v=spf1 a mx -all"] for i in range(1, 7)}  # 6 providers x (1+2) = 18
    record = "v=spf1 " + " ".join(f"include:p{i}.example" for i in range(1, 7)) + " -all"
    results = evaluate([record], zone)
    assert keys(results) == ["EMAIL_SPF_TOO_MANY_LOOKUPS"]
    assert results[0].evidence == {"lookups": 18, "limit": MAX_LOOKUPS}


def test_exactly_ten_lookups_is_allowed():
    record = "v=spf1 " + " ".join(["a"] * 10) + " -all"
    assert evaluate([record]) == []


def test_an_include_loop_terminates():
    zone = {
        "a.example": ["v=spf1 include:b.example -all"],
        "b.example": ["v=spf1 include:a.example -all"],
    }
    assert count_lookups("v=spf1 include:a.example -all", Dns(zone).txt) < 10


def test_macros_are_not_followed():
    dns = Dns()
    count_lookups("v=spf1 include:%{d}._spf.example -all", dns.txt)
    assert dns.queries == []


def test_a_weak_record_can_also_have_too_many_lookups():
    record = "v=spf1 " + " ".join(["a"] * 11) + " ?all"
    assert keys(evaluate([record])) == ["EMAIL_SPF_WEAK", "EMAIL_SPF_TOO_MANY_LOOKUPS"]


# ---- the check ---------------------------------------------------------------------------------


def test_the_check_reads_the_domain_and_follows_includes():
    dns = Dns({
        "acme.example": ["v=spf1 include:mail.example ?all"],
        "mail.example": ["v=spf1 ip4:203.0.113.5 -all"],
    })  # fmt: skip
    results = SpfCheck().run(CheckContext("acme.example", dns))
    assert keys(results) == ["EMAIL_SPF_WEAK"]
    assert "mail.example" in dns.queries


def test_a_dns_failure_propagates_so_the_check_fails_instead_of_reporting():
    class Failing:
        def txt(self, name):
            raise TimeoutError("dns down")

    with pytest.raises(TimeoutError):
        SpfCheck().run(CheckContext("acme.example", Failing()))


def test_every_emitted_key_is_declared():
    assert set(SpfCheck.emits) == {
        "EMAIL_SPF_MISSING", "EMAIL_SPF_MULTIPLE", "EMAIL_SPF_ALLOWS_ANYONE",
        "EMAIL_SPF_WEAK", "EMAIL_SPF_TOO_MANY_LOOKUPS",
    }  # fmt: skip