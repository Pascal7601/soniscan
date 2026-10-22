"""Email authentication checks (DMARC first; SPF and DKIM follow the same pattern)."""

from scanner.registry import register
from scanner.types import CheckContext, CheckResult, Severity


def parse_dmarc(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            name, _, value = part.partition("=")
            tags[name.strip().lower()] = value.strip()
    return tags


def evaluate_dmarc(domain: str, records: list[str]) -> list[CheckResult]:
    """Pure function: DNS TXT strings in, findings out. Easy to unit test."""
    dmarc = [r for r in records if r.strip().lower().startswith("v=dmarc1")]
    if not dmarc:
        return [CheckResult("EMAIL_DMARC_MISSING", Severity.MEDIUM, 0.8, domain)]
    if len(dmarc) > 1:
        return [
            CheckResult("EMAIL_DMARC_MULTIPLE", Severity.MEDIUM, 0.5, domain, {"count": len(dmarc)})
        ]
    policy = parse_dmarc(dmarc[0]).get("p", "").lower()
    if policy == "none":
        return [CheckResult("EMAIL_DMARC_MONITOR_ONLY", Severity.MEDIUM, 0.8, domain)]
    return []


class DmarcCheck:
    key = "EMAIL_DMARC"
    requires_verification = False
    emits: tuple[str, ...] = (
        "EMAIL_DMARC_MISSING",
        "EMAIL_DMARC_MULTIPLE",
        "EMAIL_DMARC_MONITOR_ONLY",
    )

    def run(self, ctx: CheckContext) -> list[CheckResult]:
        return evaluate_dmarc(ctx.domain, ctx.resolver.txt(f"_dmarc.{ctx.domain}"))


register(DmarcCheck())
