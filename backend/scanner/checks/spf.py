"""SPF: the public list of servers allowed to send email for a domain (RFC 7208).

`evaluate_spf` is a pure function: TXT strings in, findings out. The only I/O is the `lookup`
callable it is given, used to follow `include:` and `redirect=` when counting DNS lookups.
"""

import re
from collections.abc import Callable

from scanner.registry import register
from scanner.types import CheckContext, CheckResult, Severity

TxtLookup = Callable[[str], list[str]]

MAX_LOOKUPS = 10  # RFC 7208 section 4.6.4: more than this is a permanent error
_MAX_DEPTH = 10
_LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
_SPF_RE = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)


def spf_records(records: list[str]) -> list[str]:
    return [r.strip() for r in records if _SPF_RE.match(r.strip())]


def _terms(record: str) -> list[str]:
    return record.split()[1:]  # drop the "v=spf1" version token


def _name(term: str) -> str:
    """The mechanism or modifier name: no qualifier, no argument. '-all' -> 'all'."""
    body = term.lstrip("+-~?").lower()
    return re.split(r"[:/=]", body, maxsplit=1)[0]


def _target(term: str) -> str:
    body = term.lstrip("+-~?")
    match = re.search(r"[:=]", body)
    return body[match.end() :].split("/")[0] if match else ""


def count_lookups(
    record: str, lookup: TxtLookup, *, _seen: set[str] | None = None, _depth: int = 0
) -> int:
    """DNS lookups an SPF evaluation of `record` needs, following include: and redirect=."""
    seen = _seen if _seen is not None else set()
    total = 0
    for term in _terms(record):
        name = _name(term)
        if name not in _LOOKUP_MECHANISMS:
            continue
        total += 1
        if name in ("include", "redirect") and _depth < _MAX_DEPTH:
            target = _target(term).lower()
            if target and "%" not in target and target not in seen:  # macros cannot be followed
                seen.add(target)
                nested = spf_records(lookup(target))
                if len(nested) == 1:
                    total += count_lookups(nested[0], lookup, _seen=seen, _depth=_depth + 1)
        if total > MAX_LOOKUPS * 4:  # far past the limit; stop following
            break
    return total


def evaluate_spf(domain: str, records: list[str], lookup: TxtLookup) -> list[CheckResult]:
    spf = spf_records(records)
    if not spf:
        return [CheckResult("EMAIL_SPF_MISSING", Severity.MEDIUM, 0.8, domain)]
    if len(spf) > 1:
        return [
            CheckResult("EMAIL_SPF_MULTIPLE", Severity.MEDIUM, 0.5, domain, {"count": len(spf)})
        ]

    record = spf[0]
    terms = _terms(record)
    results: list[CheckResult] = []
    evidence: dict[str, object]

    all_term = next((t for t in terms if _name(t) == "all"), None)
    if all_term is not None:
        qualifier = all_term[0] if all_term[0] in "+-~?" else "+"  # a bare "all" means "+all"
        if qualifier == "+":
            evidence = {"mechanism": all_term}
            results.append(
                CheckResult("EMAIL_SPF_ALLOWS_ANYONE", Severity.HIGH, 0.9, domain, evidence)
            )
        elif qualifier == "?":
            evidence = {"reason": "neutral", "mechanism": all_term}
            results.append(CheckResult("EMAIL_SPF_WEAK", Severity.MEDIUM, 0.5, domain, evidence))
    elif not any(_name(t) == "redirect" for t in terms):
        results.append(
            CheckResult("EMAIL_SPF_WEAK", Severity.MEDIUM, 0.5, domain, {"reason": "no_all"})
        )

    lookups = count_lookups(record, lookup)
    if lookups > MAX_LOOKUPS:
        evidence = {"lookups": lookups, "limit": MAX_LOOKUPS}
        results.append(
            CheckResult("EMAIL_SPF_TOO_MANY_LOOKUPS", Severity.MEDIUM, 0.5, domain, evidence)
        )
    return results


class SpfCheck:
    key = "EMAIL_SPF"
    requires_verification = False
    emits: tuple[str, ...] = (
        "EMAIL_SPF_MISSING",
        "EMAIL_SPF_MULTIPLE",
        "EMAIL_SPF_ALLOWS_ANYONE",
        "EMAIL_SPF_WEAK",
        "EMAIL_SPF_TOO_MANY_LOOKUPS",
    )

    def run(self, ctx: CheckContext) -> list[CheckResult]:
        return evaluate_spf(ctx.domain, ctx.resolver.txt(ctx.domain), ctx.resolver.txt)


register(SpfCheck())