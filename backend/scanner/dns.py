import dns.exception
import dns.resolver


class DnsPythonResolver:
    """Production resolver. Tests use fakes implementing the same Resolver protocol."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout

    def txt(self, name: str) -> list[str]:
        try:
            answer = self._resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException:
            raise
        return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]
