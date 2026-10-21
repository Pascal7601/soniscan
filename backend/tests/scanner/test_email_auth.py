from scanner.checks.email_auth import DmarcCheck, evaluate_dmarc, parse_dmarc
from scanner.registry import passive_checks
from scanner.types import CheckContext


class FakeResolver:
    def __init__(self, records):
        self.records = records

    def txt(self, name):
        return self.records.get(name, [])


def keys(results):
    return [r.check_key for r in results]


def test_missing_dmarc():
    assert keys(evaluate_dmarc("a.example", [])) == ["EMAIL_DMARC_MISSING"]


def test_monitor_only_policy_is_flagged():
    assert keys(evaluate_dmarc("a.example", ["v=DMARC1; p=none; rua=mailto:x@a.example"])) == [
        "EMAIL_DMARC_MONITOR_ONLY"
    ]


def test_enforcing_policy_has_no_finding():
    assert evaluate_dmarc("a.example", ["v=DMARC1; p=reject"]) == []


def test_multiple_records_flagged():
    assert keys(evaluate_dmarc("a.example", ["v=DMARC1; p=none", "v=DMARC1; p=reject"])) == [
        "EMAIL_DMARC_MULTIPLE"
    ]


def test_parse_ignores_whitespace_and_case():
    assert parse_dmarc("v=DMARC1 ;  P=Quarantine ; pct=50")["p"] == "Quarantine"


def test_check_reads_from_the_dmarc_subdomain():
    ctx = CheckContext("a.example", FakeResolver({"_dmarc.a.example": ["v=DMARC1; p=none"]}))
    assert keys(DmarcCheck().run(ctx)) == ["EMAIL_DMARC_MONITOR_ONLY"]


def test_dmarc_is_registered_as_passive():
    assert any(c.key == "EMAIL_DMARC" for c in passive_checks())
