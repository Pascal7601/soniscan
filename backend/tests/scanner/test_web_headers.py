import pytest

from scanner.checks.web_headers import (
    MAX_REDIRECTS,
    WebHeadersCheck,
    evaluate_web,
    fetch_https,
    redirects_to_https,
    same_site,
)
from scanner.types import CapabilityMissing, CheckContext, WebResponse

HARDENED = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "SAMEORIGIN",
}


def resp(status=200, url="https://acme.example/", **headers):
    return WebResponse(
        status=status, headers={k.replace("_", "-"): v for k, v in headers.items()}, url=url
    )


def secure(**overrides):
    headers = {**HARDENED, **overrides}
    return WebResponse(
        status=200,
        headers={k: v for k, v in headers.items() if v is not None},
        url="https://acme.example/",
    )


def redirect(to, status=301, url="http://acme.example/"):
    return WebResponse(status=status, headers={"location": to}, url=url)


def keys(results):
    return [r.check_key for r in results]


def evaluate(plain, https):
    return evaluate_web("acme.example", plain, https)


# ---- a hardened site ---------------------------------------------------------------------------


def test_a_fully_hardened_site_has_no_findings():
    assert evaluate(redirect("https://acme.example/"), secure()) == []


def test_nothing_is_reported_when_there_is_no_https_service():
    assert evaluate(resp(200, url="http://acme.example/"), None) == []


# ---- the HTTPS redirect ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target", ["https://acme.example/", "https://www.acme.example/", "https://ACME.example/path"]
)
def test_redirects_to_the_secure_site_are_fine(target):
    assert redirects_to_https(redirect(target), "acme.example")


def test_a_relative_redirect_from_a_plain_http_page_stays_on_plain_http():
    assert not redirects_to_https(redirect("/login"), "acme.example")


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_every_redirect_status_counts(status):
    assert evaluate(redirect("https://acme.example/", status), secure()) == []


def test_serving_the_page_over_plain_http_is_reported():
    results = evaluate(resp(200, url="http://acme.example/"), secure())
    assert keys(results) == ["WEB_NO_HTTPS_REDIRECT"]
    assert results[0].evidence == {"status": 200}


@pytest.mark.parametrize("target", ["http://acme.example/other", "https://evil.example/"])
def test_redirects_that_do_not_lead_to_the_secure_site_are_reported(target):
    assert keys(evaluate(redirect(target), secure())) == ["WEB_NO_HTTPS_REDIRECT"]


def test_a_redirect_without_a_location_is_not_a_redirect():
    broken = WebResponse(status=301, headers={}, url="http://acme.example/")
    assert keys(evaluate(broken, secure())) == ["WEB_NO_HTTPS_REDIRECT"]


def test_a_closed_port_80_is_fine():
    assert evaluate(None, secure()) == []


def test_an_error_page_on_port_80_is_not_judged():
    assert evaluate(resp(404, url="http://acme.example/"), secure()) == []


# ---- individual headers ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "finding"),
    [
        ("strict-transport-security", "WEB_HSTS_MISSING"),
        ("content-security-policy", "WEB_CSP_MISSING"),
        ("x-content-type-options", "WEB_NOSNIFF_MISSING"),
        ("x-frame-options", "WEB_CLICKJACKING_UNPROTECTED"),
    ],
)
def test_each_missing_header_has_its_own_finding(header, finding):
    results = evaluate(redirect("https://acme.example/"), secure(**{header: None}))
    assert keys(results) == [finding]


@pytest.mark.parametrize(
    ("value", "max_age"),
    [("max-age=3600", 3600), ("max-age=15551999", 15551999), ("includeSubDomains", None)],
)
def test_a_short_or_unreadable_hsts_policy_is_weak(value, max_age):
    results = evaluate(None, secure(**{"strict-transport-security": value}))
    assert keys(results) == ["WEB_HSTS_WEAK"]
    assert results[0].evidence["max_age"] == max_age


@pytest.mark.parametrize(
    "value", ["max-age=15552000", 'max-age="31536000"', "MAX-AGE=63072000; preload"]
)
def test_a_long_enough_hsts_policy_is_fine(value):
    assert evaluate(None, secure(**{"strict-transport-security": value})) == []


def test_nosniff_must_have_the_right_value():
    results = evaluate(None, secure(**{"x-content-type-options": "sniff"}))
    assert keys(results) == ["WEB_NOSNIFF_MISSING"]


def test_framing_is_blocked_by_a_csp_frame_ancestors_rule_alone():
    headers = secure(
        **{"x-frame-options": None, "content-security-policy": "frame-ancestors 'self'"}
    )
    assert evaluate(None, headers) == []


@pytest.mark.parametrize("value", ["DENY", "sameorigin", " SAMEORIGIN "])
def test_x_frame_options_values_that_block_framing(value):
    assert evaluate(None, secure(**{"x-frame-options": value})) == []


def test_an_x_frame_options_value_that_allows_framing_is_reported():
    results = evaluate(None, secure(**{"x-frame-options": "ALLOW-FROM https://x.example"}))
    assert keys(results) == ["WEB_CLICKJACKING_UNPROTECTED"]


# ---- version disclosure ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["Apache/2.4.49 (Ubuntu)", "nginx/1.18.0", "PHP/7.4.3", "Microsoft-IIS/10.0"]
)
def test_software_versions_in_headers_are_reported(value):
    results = evaluate(None, secure(server=value))
    assert keys(results) == ["WEB_VERSION_DISCLOSURE"]
    assert results[0].evidence == {"headers": {"server": value}}


@pytest.mark.parametrize("value", ["nginx", "cloudflare", "Apache", "gws"])
def test_a_server_name_without_a_version_is_fine(value):
    assert evaluate(None, secure(server=value)) == []


def test_several_disclosing_headers_make_one_finding():
    results = evaluate(None, secure(server="nginx/1.18.0", **{"x-powered-by": "PHP/7.4.3"}))
    assert keys(results) == ["WEB_VERSION_DISCLOSURE"]
    assert set(results[0].evidence["headers"]) == {"server", "x-powered-by"}


# ---- error pages are not judged ----------------------------------------------------------------


def test_an_error_page_gives_no_header_findings_but_the_redirect_is_still_judged():
    error_page = WebResponse(status=403, headers={}, url="https://acme.example/")
    assert evaluate(redirect("https://acme.example/"), error_page) == []
    plain_page = resp(200, url="http://acme.example/")
    assert keys(evaluate(plain_page, error_page)) == ["WEB_NO_HTTPS_REDIRECT"]


# ---- same_site ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "domain", "expected"),
    [
        ("acme.example", "acme.example", True),
        ("www.acme.example", "acme.example", True),
        ("acme.example", "www.acme.example", True),
        ("ACME.example.", "acme.example", True),
        ("evil.example", "acme.example", False),
        ("acme.example.evil.example", "acme.example", False),
        ("shop.acme.example", "acme.example", False),
    ],
)
def test_same_site(host, domain, expected):
    assert same_site(host, domain) is expected


# ---- following redirects over HTTPS ------------------------------------------------------------


class FakeWeb:
    def __init__(self, pages):
        self.pages, self.urls = pages, []

    def get(self, url):
        self.urls.append(url)
        page = self.pages.get(url)
        if isinstance(page, BaseException):
            raise page
        return page


def page(url, status=200, location=None, **headers):
    all_headers = {**headers, **({"location": location} if location else {})}
    return WebResponse(status=status, headers=all_headers, url=url)


def test_a_redirect_to_the_www_twin_is_followed():
    web = FakeWeb({
        "https://acme.example/": page("https://acme.example/", 301, "https://www.acme.example/"),
        "https://www.acme.example/": page("https://www.acme.example/", **HARDENED),
    })  # fmt: skip
    assert fetch_https(web, "acme.example").url == "https://www.acme.example/"


def test_a_redirect_to_another_site_is_not_followed():
    web = FakeWeb(
        {"https://acme.example/": page("https://acme.example/", 302, "https://evil.example/")}
    )
    result = fetch_https(web, "acme.example")
    assert result.status == 302
    assert web.urls == ["https://acme.example/"]


def test_a_redirect_down_to_plain_http_is_not_followed():
    web = FakeWeb(
        {"https://acme.example/": page("https://acme.example/", 301, "http://acme.example/")}
    )
    assert fetch_https(web, "acme.example").status == 301
    assert web.urls == ["https://acme.example/"]


def test_a_redirect_to_a_custom_port_is_not_followed():
    web = FakeWeb(
        {"https://acme.example/": page("https://acme.example/", 301, "https://acme.example:8443/")}
    )
    assert fetch_https(web, "acme.example").status == 301
    assert len(web.urls) == 1


def test_a_redirect_loop_stops_after_the_limit():
    web = FakeWeb({
        "https://acme.example/": page("https://acme.example/", 302, "https://www.acme.example/"),
        "https://www.acme.example/": page("https://www.acme.example/", 302, "https://acme.example/"),
    })  # fmt: skip
    result = fetch_https(web, "acme.example")
    assert result.status == 302
    assert len(web.urls) == MAX_REDIRECTS + 1


def test_relative_redirects_are_resolved():
    web = FakeWeb({
        "https://acme.example/": page("https://acme.example/", 301, "/home"),
        "https://acme.example/home": page("https://acme.example/home", **HARDENED),
    })  # fmt: skip
    assert fetch_https(web, "acme.example").url == "https://acme.example/home"


def test_nothing_answering_returns_none_and_a_vanishing_target_returns_the_last_response():
    assert fetch_https(FakeWeb({}), "acme.example") is None
    web = FakeWeb(
        {"https://acme.example/": page("https://acme.example/", 301, "https://www.acme.example/")}
    )
    assert fetch_https(web, "acme.example").status == 301  # www vanished mid-chain


# ---- the check ---------------------------------------------------------------------------------


def test_the_check_makes_both_requests_and_judges_them():
    web = FakeWeb({
        "https://acme.example/": page("https://acme.example/", 200),
        "http://acme.example/": page("http://acme.example/", 200),
    })  # fmt: skip
    results = WebHeadersCheck().run(CheckContext("acme.example", resolver=None, web=web))
    assert web.urls == ["https://acme.example/", "http://acme.example/"]
    assert "WEB_NO_HTTPS_REDIRECT" in keys(results)
    assert "WEB_HSTS_MISSING" in keys(results)


def test_the_check_refuses_to_run_without_a_web_client():
    with pytest.raises(CapabilityMissing):
        WebHeadersCheck().run(CheckContext("acme.example", resolver=None))


def test_a_timeout_fails_the_check_instead_of_reporting():
    web = FakeWeb({"https://acme.example/": TimeoutError("timed out")})
    with pytest.raises(TimeoutError):
        WebHeadersCheck().run(CheckContext("acme.example", resolver=None, web=web))


def test_every_emitted_key_is_declared():
    assert set(WebHeadersCheck.emits) == {
        "WEB_NO_HTTPS_REDIRECT", "WEB_HSTS_MISSING", "WEB_HSTS_WEAK", "WEB_CSP_MISSING",
        "WEB_NOSNIFF_MISSING", "WEB_CLICKJACKING_UNPROTECTED", "WEB_VERSION_DISCLOSURE",
    }  # fmt: skip