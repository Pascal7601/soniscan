# scanner

The scanning engine: the checks that look at a domain, the rules for running them safely, and the
scoring formula. It is a **plain Python package with no framework dependencies**.

## The one rule

`scanner` must not import Django, Django REST Framework, Celery, or any code from `apps/` or
`config/`. The contract `scanner-is-framework-free` in `backend/.importlinter` fails CI if it does.

Why: checks can be unit-tested with no database, the engine can move to separate workers (or another
runtime) later, and the riskiest code stays small and easy to review. Everything the engine needs
from the outside (DNS, the clock, the target) is **passed in**, never reached for.

```
apps/runner  --calls-->  scanner   (never the other way round)
apps/findings --uses-->  scanner.scoring
```

## Breakdown

| File | Responsibility |
|---|---|
| `__init__.py` | `__version__`, stored on each scan so results can be traced to the code that produced them. |
| `types.py` | `Severity`, `CheckResult`, `CheckContext`, and the `Check` and `Resolver` protocols. |
| `registry.py` | `register()`, `all_checks()`, `passive_checks()`. |
| `runner.py` | `select_checks()` and `run_checks()`: run checks with failure isolation and the verification guard. |
| `dns.py` | `DnsPythonResolver`: the production DNS resolver, with the health canary. |
| `safety.py` | `is_public_ip()`, `resolve_public()`: the guard every network probe must pass. |
| `net.py` | `StdlibTlsProbe` and `StdlibWebClient`: the only code that opens connections to a customer's site, with the safety rules built in. |
| `checks/web_tls.py` | The TLS and certificate check: availability, trust, expiry and legacy protocols. |
| `checks/web_headers.py` | The HTTPS-redirect and security-headers check. |
| `scoring.py` | The scoring formulas, parameters and grade logic. |
| `checks/__init__.py` | Importing the package registers every check. List new check modules here. |
| `checks/email_auth.py` | The DMARC check. |

## Core concepts

### A check

A check is any object with this shape (the `Check` protocol in `types.py`):

```python
class SomeCheck:
    key = "EMAIL_SPF"                 # identifies the check
    requires_verification = False     # True = may only run on a domain whose ownership is proven
    emits = ("EMAIL_SPF_MISSING",)    # EVERY finding key this check can produce

    def run(self, ctx: CheckContext) -> list[CheckResult]: ...
```

`emits` is not decoration. The runner uses it to know which findings a **completed** check is
allowed to mark as fixed, and a test fails CI if any key in `emits` has no plain-language text in
the check library.

### What goes in and out

- **`CheckContext`**: `domain` (the host name), `resolver` (how to do DNS), `verified` (has the
  customer proven they own it).
- **`CheckResult`**: `check_key` (a finding key), `severity`, `exploitability` (0 to 1), `asset`
  (what it applies to, for example `acme.example`), optional `evidence` (a dictionary shown to
  analysts), and `exposure` (default `1.0`).
- **`Severity`**: `critical`, `high`, `medium`, `low`, `info`.

`exposure` says how reachable the affected thing is: `1.0` core internet-facing asset (main site,
mail, VPN), `0.7` other internet-facing service, `0.4` low-value or non-production subdomain.

### The registry

`register(check)` adds a check (duplicate keys raise `ValueError`). `all_checks()` returns every
registered check; `passive_checks()` returns only those with `requires_verification = False`, safe
to run against **any** domain.

## Running checks (`runner.py`)

```python
checks  = select_checks(active=False, verified=False)   # passive scan
outcome = run_checks(checks, CheckContext(domain, resolver, verified=False))
# outcome.results, outcome.covered_keys, outcome.completed, outcome.failures
```

Guarantees:

1. **A failing check is isolated.** If `run()` raises, the failure is recorded in
   `outcome.failures` and the check contributes **no results and no `covered_keys`**. The other
   checks still run.
2. **Coverage means "completed".** `covered_keys` is the union of `emits` of checks that finished.
   Only those findings may later be marked fixed, so a flaky lookup can never close a real finding.
3. **The verification guard.** A check with `requires_verification = True` raises
   `VerificationRequired` if the context is not verified, and `select_checks(active=True,
   verified=False)` refuses outright. This mirrors the database trigger in `apps/scans`: the rule is
   enforced at every layer.

## DNS and the health canary (`dns.py`)

`DnsPythonResolver.txt(name)` returns the TXT strings for a name:

| DNS answer | Behaviour |
|---|---|
| Record exists | Returns the strings (multi-part records are joined). |
| Name or record genuinely missing (`NXDOMAIN`, no answer) | Returns `[]`. |
| Timeout, `SERVFAIL`, no reachable servers | **Raises.** "We could not find out" must never look like "there is no record". |

**The canary.** Before its first lookup the resolver resolves `a.root-servers.net`, a name that
must exist. If that fails with `NXDOMAIN`, the resolver raises `ResolverUnhealthy` and every check
that uses it fails. This exists because a captive portal, filtering resolver or egress block can
answer `NXDOMAIN` for *everything*, which would otherwise read as "this customer has no DMARC
record" and produce false findings (and could wrongly close real ones). It was found for real while
testing in a network-restricted environment. A canary timeout is not cached, so it is retried; a
success is cached for the life of that resolver instance (one per scan).

Constructor: `DnsPythonResolver(timeout=5.0, nameservers=None, canary="a.root-servers.net")`.
The Django settings `SCANNER_DNS_TIMEOUT`, `SCANNER_DNS_SERVERS` and `SCANNER_DNS_CANARY` feed it
(see `apps/runner/README.md`).

To add a new kind of lookup (A, MX, CNAME...), extend the `Resolver` protocol in `types.py` and
`DnsPythonResolver`, and give the new method the same missing-versus-failed semantics.

## Target safety (`safety.py`)

Every check that **connects to a target** (TLS handshake, port probe, HTTP request) must resolve
the host through this module first. It stops the scanner being aimed at internal infrastructure
(SSRF), including cloud metadata services such as `169.254.169.254`.

- `is_public_ip(value)` is true only for globally routable addresses. It rejects private,
  loopback, link-local, carrier-grade NAT (`100.64.0.0/10`), multicast, reserved and unspecified
  ranges, and unwraps IPv4-mapped IPv6 (`::ffff:127.0.0.1`).
- `resolve_public(host)` resolves a host and returns its addresses, raising `UnsafeTarget` if it
  cannot resolve **or if any address is not public**. Requiring all addresses defeats a name that
  mixes a public address with an internal one.
- **Connect to the returned IP address, not the host name**, so DNS cannot change between the check
  and the connection (DNS rebinding).

The shipped DMARC check only does DNS lookups, so it does not need this module yet. It becomes
mandatory with the first check that opens a connection.

## Network access (`net.py`)

Checks never open sockets themselves. They receive two capabilities through the check context and
use only those:

| Capability | Implementation | What it does |
|---|---|---|
| `ctx.tls` (`TlsProbe`) | `StdlibTlsProbe` | One verified TLS handshake plus a legacy-protocol probe; returns a `TlsObservation`. |
| `ctx.web` (`WebClient`) | `StdlibWebClient` | One page request; returns a `WebResponse` (status and lower-cased headers). |

**Rules every connection follows** (each is covered by a test against a real local server):

1. The host is resolved through `safety.resolve_public`; private and internal addresses are
   refused, so the scanner cannot be aimed at internal infrastructure.
2. We connect to **the address that guard approved**, never to the host name again. The host name is
   still used for the TLS server name and the HTTP `Host` header. The host is resolved once per
   probe, so DNS cannot change in between (DNS rebinding).
3. Only ports 80 and 443 (tests may allow others).
4. Every operation has a timeout (`SCANNER_NET_TIMEOUT`, default 5 seconds).
5. We identify ourselves: `User-Agent: PostureScanner/<version>`.
6. Page bodies are never read, and redirects are never followed by the client; the check decides
   whether a redirect is worth following and each hop goes through the guard again.

**"Nothing there" versus "could not tell".** A host with no public address, or a port that refuses
connections, is a normal answer (`resolved=False`, or `reachable=False` / `None`). A **timeout, a
handshake failure, or any unclassified error raises**, so the check fails instead of guessing.

**Certificate problems** are read from OpenSSL's verification result, not by parsing certificates:

| OpenSSL result | Reported as |
|---|---|
| expired (code 10) | `expired` |
| self-signed certificate (18) | `self_signed` |
| host name mismatch (62) | `hostname_mismatch` |
| unknown issuer, private authority or missing intermediate (2, 19, 20, 21) | `untrusted_chain` |
| anything else, such as "not yet valid" | the probe **raises** `TlsProbeError`; unclassified problems are never guessed |

When the chain is trusted, the certificate's expiry date and the negotiated protocol are recorded.
Web pages are fetched **without certificate verification** so security headers can still be judged
on a site with a bad certificate; the TLS check reports the certificate separately, and nothing
secret is ever sent.

**Legacy protocols.** After the main handshake the probe tries TLS 1.0 and TLS 1.1 separately,
with certificate checks off (it asks about the protocol, not the certificate). A server that
**only** speaks old TLS makes the modern handshake fail; the probe notices the version mismatch,
tries the old versions, and reports `modern_tls=False` instead of losing the worst case as an
error. Limitation: if the scanner's own TLS library cannot speak a version at all, that version is
treated as not accepted, which can only hide a finding, never invent one.

## Scoring (`scoring.py`)

Pure functions, no database. The constants live in a versioned database row
(`findings.ScoringModel`) so old reports stay reproducible; `DEFAULT_PARAMS` is version 1 and a test
asserts the two stay equal.

### Per finding

```
score = severity weight x exploitability x exposure          (0 to 10, rounded to 2 places)
```

| Severity | critical | high | medium | low | info |
|---|---|---|---|---|---|
| Weight | 10 | 7 | 4 | 2 | 0 |

Tier of a score: **7 or more** `fix_now`, **4 or more** `fix_this_month`, otherwise `plan_later`.

### Overall posture

```
T       = sum of finding scores        (repeats of the same check count at 50% after the first)
posture = round half up ( 100 x e^( -T / 40 ) )
```

- **Repeats**: if one check fires on several assets, the highest-scoring instance counts fully and
  the rest count at `repeat_factor` (0.5).
- **Diminishing returns**: the exponential means thirty minor findings cannot push a business to
  zero, while one serious problem still matters.
- **Caps**: any open **critical** finding limits the score to **69**; otherwise any open **high**
  finding limits it to **79**. `capped_by` reports when a cap actually lowered the score.
- **Grades**: A 90 and above, B 80, C 70, D 60, F below 60.
- Only **open** findings are scored; fixed and accepted-risk findings are excluded by the caller.

### Worked examples

| Open findings | Total risk | Result |
|---|---|---|
| Open remote desktop (10.0) + DMARC monitor-only (3.2) + expiring certificate (2.0) | 15.2 | 100 x e^(-15.2/40) = 68, grade **D** |
| The same, after the remote desktop is fixed | 5.2 | 88, grade **B** |
| A single critical finding scoring 1.2 | 1.2 | raw 97, **capped to 69**, grade **D** |
| Nothing open | 0 | 100, grade **A** |

### Parameters

`ScoringParams.from_dict()` validates everything and raises `ScoringError` for: missing or extra
severities, negative weights, `decay_k <= 0`, `repeat_factor` outside 0 to 1, grade bands that do
not descend from A to D, caps for unknown severities, and tier thresholds out of order. Bad
constants fail loudly instead of producing silently wrong scores.

## The existing check: DMARC (`checks/email_auth.py`)

`DmarcCheck` (key `EMAIL_DMARC`, passive) reads the TXT records at `_dmarc.<domain>` and applies
`evaluate_dmarc()`, a **pure function** of the record strings:

| Situation | Finding | Severity | Exploitability |
|---|---|---|---|
| No record starting `v=DMARC1` | `EMAIL_DMARC_MISSING` | medium | 0.8 |
| More than one such record | `EMAIL_DMARC_MULTIPLE` (evidence: `count`) | medium | 0.5 |
| One record with policy `p=none` | `EMAIL_DMARC_MONITOR_ONLY` | medium | 0.8 |
| One record with `p=quarantine` or `p=reject` | none | | |

Matching ignores case and surrounding whitespace. Tags such as `sp`, `pct` and `rua` are parsed but
not yet evaluated.

### TLS and certificates (`checks/web_tls.py`, key `WEB_TLS`)

Asks `ctx.tls` to probe the domain and applies `evaluate_tls(domain, observation, now)`.

| Situation | Finding | Severity | Exploitability |
|---|---|---|---|
| The host has no public address | none (no website to judge) | | |
| It has an address but refuses HTTPS connections | `TLS_NOT_AVAILABLE` | medium | 0.6 |
| Certificate expired (or its date has passed) | `TLS_CERT_EXPIRED` | high | 1.0 |
| Certificate is self-signed | `TLS_CERT_SELF_SIGNED` | high | 0.8 |
| Certificate is for a different address | `TLS_CERT_HOSTNAME_MISMATCH` | high | 0.8 |
| Untrusted or incomplete chain | `TLS_CERT_UNTRUSTED_CHAIN` | medium | 0.6 |
| Trusted, 8 to 30 days left | `TLS_CERT_EXPIRING_SOON` | medium | 0.7 |
| Trusted, 7 days or fewer left | `TLS_CERT_EXPIRING_SOON` | high | 0.9 |
| TLS 1.0 or 1.1 also accepted | `TLS_LEGACY_PROTOCOL` | medium | 0.4 |
| Nothing newer than TLS 1.1 accepted | `TLS_LEGACY_PROTOCOL` | high | 0.5 |

Expiry is only judged when the chain is trusted. The current time is injected
(`TlsCheck(clock=...)`), so the boundaries (exactly 30 days, exactly 7) are tested without waiting.

### Web: redirect and headers (`checks/web_headers.py`, key `WEB_HEADERS`)

Makes two ordinary page requests, `http://<domain>/` and `https://<domain>/`, and applies
`evaluate_web()`. The HTTPS request follows redirects **only** to the domain itself or its `www`
twin, over HTTPS on port 443, at most four times; it never leaves the customer's site.

| Situation | Finding | Severity | Exploitability |
|---|---|---|---|
| The plain `http://` page is served (status below 400) instead of redirecting to the secure site | `WEB_NO_HTTPS_REDIRECT` | medium | 0.6 |
| No `Strict-Transport-Security` header | `WEB_HSTS_MISSING` | medium | 0.4 |
| HSTS `max-age` under 15552000 (180 days), or unreadable | `WEB_HSTS_WEAK` | low | 0.3 |
| No `Content-Security-Policy` header | `WEB_CSP_MISSING` | low | 0.3 |
| `X-Content-Type-Options` is not `nosniff` | `WEB_NOSNIFF_MISSING` | low | 0.2 |
| Neither `X-Frame-Options` (`DENY` or `SAMEORIGIN`) nor a CSP `frame-ancestors` rule | `WEB_CLICKJACKING_UNPROTECTED` | low | 0.3 |
| `Server` or `X-Powered-By` reveals a version number | `WEB_VERSION_DISCLOSURE` (evidence: the headers) | low | 0.3 |

Design choices worth knowing:

- **No HTTPS service, no header findings.** The TLS check reports the missing HTTPS; judging
  headers of a site that cannot be reached would only be noise.
- **Error pages are not judged.** Header findings come only from a page with status below 400; a
  403 or a bot-protection page says nothing reliable about the real site. The redirect rule still
  applies.
- **A closed port 80 is fine**; only a plain page that stays on `http://` is a problem.
- **Only the redirect and header rules, not content.** The page body is never read.

## Writing a new check

Example: an SPF check. Work through these in order; each step has a test that fails if skipped.

1. **Write the evaluation as a pure function** that takes plain data and returns results. It is the
   part with the logic, and it needs no mocking.
2. **Wrap it in a check class** with `key`, `requires_verification` and a complete `emits`.

   ```python
   from scanner.registry import register
   from scanner.types import CheckContext, CheckResult, Severity

   def evaluate_spf(domain: str, records: list[str]) -> list[CheckResult]:
       ...  # pure: strings in, results out

   class SpfCheck:
       key = "EMAIL_SPF"
       requires_verification = False
       emits: tuple[str, ...] = ("EMAIL_SPF_MISSING", "EMAIL_SPF_TOO_PERMISSIVE")

       def run(self, ctx: CheckContext) -> list[CheckResult]:
           return evaluate_spf(ctx.domain, ctx.resolver.txt(ctx.domain))

   register(SpfCheck())
   ```
3. **Register the module** by importing it in `checks/__init__.py`.
4. **Write the customer text** for every key in `emits` in `apps/findings/library/*.toml`.
   CI fails until you do (`test_every_key_a_registered_check_can_emit_has_library_text`), and the
   `requires_verification` flag in the library must match the check.
5. **Test the pure function** with plain strings, and the class with a fake resolver (see
   `tests/scanner/test_email_auth.py`).
6. **Deploy**: `sync_check_library` publishes the new text.

Conventions:

- Never touch the database, the filesystem or global state. Use only what is in `ctx`.
- A check that needs the **network** beyond DNS must resolve its target through `safety.py`.
- A check that **probes** the target (ports, services, anything beyond reading public records) must
  set `requires_verification = True`.
- Raise on "could not find out"; return findings only for facts you established. Do not catch your
  own network errors and turn them into findings.
- Choose `exposure` honestly: 1.0 only for core assets.

## Tests

| File | What it proves |
|---|---|
| `tests/scanner/test_email_auth.py` | DMARC parsing and every finding rule; the check reads `_dmarc.<domain>`. |
| `tests/scanner/test_runner.py` | Failure isolation, coverage, and the verification guard. |
| `tests/scanner/test_dns.py` | Missing versus failed lookups, and the canary refusing a sinkhole resolver. |
| `tests/scanner/test_safety.py` | Every blocked address range and the DNS-rebinding case. |
| `tests/scanner/test_scoring.py` | Formulas, caps, tiers, grades, parameter validation, and properties (adding a finding never improves the score; score always within 0 to 100). |
| `tests/findings/test_library.py` | Every emitted key has library text. |
| `tests/scanner/test_web_tls.py` | Every certificate and expiry rule, including the exact 30 and 7 day boundaries, legacy protocols, and the check's behaviour without a probe. |
| `tests/scanner/test_web_headers.py` | Every redirect and header rule, `same_site`, following redirects safely, and error pages not being judged. |
| `tests/scanner/test_net.py` | The network layer against **real** TLS servers on loopback with real OpenSSL certificates (trusted, expired, self-signed, wrong name, unknown issuer), legacy protocols, IP pinning, refusal of internal addresses, and timeouts. Needs the `openssl` command. |
| `tests/test_network_guard.py` | The test suite itself cannot reach the real network. |