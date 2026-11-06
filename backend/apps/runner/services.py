# from scanner.net import StdlibTlsProbe, StdlibWebClient
# from scanner.types import Check, CheckContext, Resolver, TlsProbe, WebClient

# def default_tls_probe() -> TlsProbe:
#     return StdlibTlsProbe(timeout=settings.SCANNER_NET_TIMEOUT)


# def default_web_client() -> WebClient:
#     return StdlibWebClient(timeout=settings.SCANNER_NET_TIMEOUT)

# def execute_scan(
#     *,
#     tenant_id: UUID,
#     scan_id: UUID,
#     resolver: Resolver | None = None,
#     checks: Sequence[Check] | None = None,
#     tls: TlsProbe | None = None,
#     web: WebClient | None = None,
# ) -> ExecutionResult:
#         ctx = CheckContext(
#         job.fqdn,
#         resolver or default_resolver(),
#         verified=job.verified,
#         tls=tls or default_tls_probe(),
#         web=web or default_web_client(),
#     )