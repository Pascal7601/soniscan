from uuid import UUID

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts.api.base import TenantScopedAPIView
from apps.core import audit
from apps.domains import selectors as domain_selectors
from apps.domains.models import Domain
from apps.scans import selectors, services

from .serializers import ScanCreateSerializer, ScanErrorSerializer, ScanSerializer

_ERRORS: dict[type[services.ScanError], tuple[int, str]] = {
    services.DomainNotVerified: (status.HTTP_409_CONFLICT, "domain_not_verified"),
    services.ActiveScansNotInPlan: (status.HTTP_403_FORBIDDEN, "plan_limit"),
    services.ScanQuotaExceeded: (status.HTTP_429_TOO_MANY_REQUESTS, "quota_exceeded"),
}


def _domain_or_404(request: Request, domain_id: UUID) -> Domain:
    domain = domain_selectors.get_domain(
        tenant_id=request.tenant_id,
        domain_id=domain_id,
    )
    if domain is None:
        raise NotFound
    return domain


class DomainScanListCreateView(TenantScopedAPIView):
    @extend_schema(responses=ScanSerializer(many=True))
    def get(self, request: Request, domain_id: UUID) -> Response:
        domain = _domain_or_404(request, domain_id)
        scans = selectors.list_scans(tenant_id=domain.tenant_id, domain_id=domain.id)
        return Response(ScanSerializer(scans, many=True).data)

    @extend_schema(
        request=ScanCreateSerializer,
        responses={
            201: ScanSerializer,
            403: ScanErrorSerializer,
            409: ScanErrorSerializer,
            429: ScanErrorSerializer,
        },
    )
    def post(self, request: Request, domain_id: UUID) -> Response:
        domain = _domain_or_404(request, domain_id)
        body = ScanCreateSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        mode = body.validated_data["mode"]
        try:
            scan = services.request_scan(domain=domain, mode=mode, actor_id=request.user.id)
        except services.ScanError as exc:
            http_status, code = _ERRORS.get(type(exc), (status.HTTP_400_BAD_REQUEST, "scan_error"))
            # Return a normal Response (do not raise): DRF rolls the request transaction back on
            # exceptions, which would discard this audit row.
            audit.record(
                action="scan.refused",
                actor_id=request.user.id,
                tenant_id=domain.tenant_id,
                target_type="domain",
                target_id=domain.id,
                metadata={"reason": code, "mode": mode},
                **audit.request_meta(request),
            )
            return Response({"detail": str(exc), "code": code}, status=http_status)
        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)


class ScanDetailView(TenantScopedAPIView):
    @extend_schema(responses=ScanSerializer)
    def get(self, request: Request, scan_id: UUID) -> Response:
        scan = selectors.get_scan(
            tenant_id=request.tenant_id,
            scan_id=scan_id,
        )
        if scan is None:
            raise NotFound
        return Response(ScanSerializer(scan).data)