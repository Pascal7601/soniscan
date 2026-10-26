import dns.exception
import dns.resolver

# A name that must exist (a DNS root server). If the resolver cannot resolve it, the resolver is
# broken or hijacked, and none of its answers can be trusted.
DEFAULT_CANARY = "a.root-servers.net"


class ResolverUnhealthy(dns.exception.DNSException):
    """The resolver cannot resolve a name that must exist, so its answers are untrustworthy."""


class DnsPythonResolver:
    """Production resolver. Tests use fakes implementing the same Resolver protocol.

    Missing names (NXDOMAIN / no TXT records) return []. Every other failure (timeout, SERVFAIL,
    unreachable servers) RAISES: "we could not find out" must never look like "there is no record",
    or a flaky network would create false findings such as "DMARC missing".

    Before the first lookup the resolver is checked against a canary name that must exist. A
    captive portal, filtering resolver or egress block often answers NXDOMAIN for EVERYTHING, which
    would otherwise read as "no records anywhere" and flood customers with false findings.
    """

    def __init__(
        self,
        timeout: float = 5.0,
        nameservers: list[str] | None = None,
        canary: str | None = DEFAULT_CANARY,
    ) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = nameservers
        self._canary = canary
        self._healthy = False

    def _ensure_healthy(self) -> None:
        if self._healthy or self._canary is None:
            return
        try:
            self._resolver.resolve(self._canary, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
            raise ResolverUnhealthy(
                f"cannot resolve {self._canary}; refusing to trust this resolver"
            ) from exc
        self._healthy = True  # other failures (timeouts) propagate and are retried next time

    def txt(self, name: str) -> list[str]:
        self._ensure_healthy()
        try:
            answer = self._resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]