"""HTTPS redirect and security headers.

Two requests are made, both ordinary page loads: `http://<domain>/` (does it send visitors to
HTTPS?) and `https://<domain>/` (following redirects within the same site, at most four).
`evaluate_web` is a pure function of the two responses.

Header findings are only raised from a successful page (status below 400): an error or
bot-protection page tells us nothing reliable about the real site.
"""

import re
import urllib.parse

from scanner.registry import register
from scanner.types import (
    CapabilityMissing,
    CheckContext,
    CheckResult,
    Severity,
    WebClient,
    WebResponse,
)

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 4
MIN_HSTS_SECONDS = 15_552_000  # 180 days
_HSTS_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)
_VERSION_IN_HEADER = re.compile(r"\d+\.\d+|/\d")


def same_site(host: str, domain: str) -> bool:
    """The domain itself or its `www.` twin (in either direction); nothing else."""
    bare = domain.lower().removeprefix("www.")
    return host.lower().rstrip(".") in (bare, f"www.{bare}")


def _redirect_target(response: WebResponse, domain: str) -> urllib.parse.SplitResult | None:
    """Where a same-site redirect points, or None if it is not a redirect we should follow."""
    location = response.headers.get("location")
    if response.status not in REDIRECT_STATUSES or not location:
        return None
    parts = urllib.parse.urlsplit(urllib.parse.urljoin(response.url, location))
    if not parts.hostname or not same_site(parts.hostname, domain):
        return None
    return parts


def redirects_to_https(response: WebResponse, domain: str) -> bool:
    target = _redirect_target(response, domain)
    return target is not None and target.scheme == "https"


def fetch_https(web: WebClient, domain: str) -> WebResponse | None:
    """GET the site over HTTPS, following same-site HTTPS redirects. None if nothing answers."""
    url, last = f"https://{domain}/", None
    for _ in range(MAX_REDIRECTS + 1):
        response = web.get(url)
        if response is None:
            return last
        last = response
        target = _redirect_target(response, domain)
        if target is None or target.scheme != "https" or target.port not in (None, 443):
            return response
        url = target.geturl()
    return last


def evaluate_web(
    domain: str, plain: WebResponse | None, secure: WebResponse | None
) -> list[CheckResult]:
    if secure is None:
        return []  # no HTTPS service; the TLS check reports that

    results: list[CheckResult] = []
    if plain is not None and plain.status < 400 and not redirects_to_https(plain, domain):
        results.append(
            CheckResult(
                "WEB_NO_HTTPS_REDIRECT", Severity.MEDIUM, 0.6, domain, {"status": plain.status}
            )
        )
    if secure.status >= 400:
        return results

    headers = secure.headers

    hsts = headers.get("strict-transport-security")
    if hsts is None:
        results.append(CheckResult("WEB_HSTS_MISSING", Severity.MEDIUM, 0.4, domain))
    else:
        match = _HSTS_MAX_AGE.search(hsts)
        max_age = int(match.group(1)) if match else None
        if max_age is None or max_age < MIN_HSTS_SECONDS:
            evidence: dict[str, object] = {"max_age": max_age, "minimum": MIN_HSTS_SECONDS}
            results.append(CheckResult("WEB_HSTS_WEAK", Severity.LOW, 0.3, domain, evidence))

    csp = headers.get("content-security-policy", "")
    if not csp:
        results.append(CheckResult("WEB_CSP_MISSING", Severity.LOW, 0.3, domain))

    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        results.append(CheckResult("WEB_NOSNIFF_MISSING", Severity.LOW, 0.2, domain))

    framing_blocked = (
        headers.get("x-frame-options", "").strip().lower() in ("deny", "sameorigin")
        or "frame-ancestors" in csp.lower()
    )
    if not framing_blocked:
        results.append(CheckResult("WEB_CLICKJACKING_UNPROTECTED", Severity.LOW, 0.3, domain))

    disclosed = {
        name: headers[name][:100]
        for name in ("server", "x-powered-by")
        if name in headers and _VERSION_IN_HEADER.search(headers[name])
    }
    if disclosed:
        results.append(
            CheckResult("WEB_VERSION_DISCLOSURE", Severity.LOW, 0.3, domain, {"headers": disclosed})
        )
    return results


class WebHeadersCheck:
    key = "WEB_HEADERS"
    requires_verification = False
    emits: tuple[str, ...] = (
        "WEB_NO_HTTPS_REDIRECT",
        "WEB_HSTS_MISSING",
        "WEB_HSTS_WEAK",
        "WEB_CSP_MISSING",
        "WEB_NOSNIFF_MISSING",
        "WEB_CLICKJACKING_UNPROTECTED",
        "WEB_VERSION_DISCLOSURE",
    )

    def run(self, ctx: CheckContext) -> list[CheckResult]:
        if ctx.web is None:
            raise CapabilityMissing("WEB_HEADERS needs a web client in the check context")
        secure = fetch_https(ctx.web, ctx.domain)
        plain = ctx.web.get(f"http://{ctx.domain}/")
        return evaluate_web(ctx.domain, plain, secure)


register(WebHeadersCheck())