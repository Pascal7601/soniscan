import logging
import re
from uuid import UUID

from django.http import HttpResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle, ScopedRateThrottle

from apps.accounts.api.base import TenantScopedAPIView
from apps.accounts.models import Membership
from apps.core import audit
from apps.domains import selectors as domain_selectors
from apps.domains.models import Domain
from apps.reports import selectors, services
from apps.reports.pdf import render_pdf

from .serializers import ReportErrorSerializer, ReportSerializer

logger = logging.getLogger(__name__)


def _domain_or_404(request: Request, domain_id: UUID) -> Domain:
    domain = domain_selectors.get_domain(
        tenant_id=request.tenant_id,  # type: ignore[attr-defined]
        domain_id=domain_id,
    )
    if domain is None:
        raise NotFound
    return domain


class DomainReportListCreateView(TenantScopedAPIView):
    throttle_scope = "report_generate"

    def get_throttles(self) -> list[BaseThrottle]:
        # Only generating is expensive; listing keeps the default per-user limit.
        if self.request.method == "POST":
            return [ScopedRateThrottle()]
        return super().get_throttles()

    @extend_schema(responses=ReportSerializer(many=True))
    def get(self, request: Request, domain_id: UUID) -> Response:
        domain = _domain_or_404(request, domain_id)
        reports = selectors.list_reports(tenant_id=domain.tenant_id, domain_id=domain.id)
        return Response(ReportSerializer(reports, many=True).data)

    @extend_schema(
        request=None,
        responses={201: ReportSerializer, 403: None, 409: ReportErrorSerializer},
    )
    def post(self, request: Request, domain_id: UUID) -> Response:
        membership: Membership = request.membership  # type: ignore[attr-defined]
        if membership.role not in (Membership.Role.OWNER, Membership.Role.ADMIN):
            raise PermissionDenied("Only owners and admins can generate a report.")
        domain = _domain_or_404(request, domain_id)
        try:
            report = services.generate_report(domain=domain, actor_id=request.user.id)
        except services.NoCompletedScan as exc:
            return Response(
                {"detail": str(exc), "code": "no_completed_scan"}, status=status.HTTP_409_CONFLICT
            )
        return Response(ReportSerializer(report).data, status=status.HTTP_201_CREATED)


class ReportDetailView(TenantScopedAPIView):
    @extend_schema(responses=ReportSerializer)
    def get(self, request: Request, report_id: UUID) -> Response:
        report = selectors.get_report(
            tenant_id=request.tenant_id,  # type: ignore[attr-defined]
            report_id=report_id,
        )
        if report is None:
            raise NotFound
        return Response(ReportSerializer(report).data)


class ReportPdfView(TenantScopedAPIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "report_download"

    @extend_schema(
        responses={(200, "application/pdf"): OpenApiTypes.BINARY, 500: ReportErrorSerializer}
    )
    def get(self, request: Request, report_id: UUID) -> Response | HttpResponse:
        report = selectors.get_report(
            tenant_id=request.tenant_id,  # type: ignore[attr-defined]
            report_id=report_id,
            with_snapshot=True,
        )
        if report is None:
            raise NotFound
        try:
            services.verify_integrity(report)
        except services.IntegrityError:
            logger.error("report %s failed its integrity check", report.id)
            return Response(
                {"detail": "This report cannot be produced.", "code": "report_integrity"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        audit.record(
            action="report.downloaded",
            actor_id=request.user.id,
            tenant_id=report.tenant_id,
            target_type="report",
            target_id=report.id,
            metadata={"domain": report.snapshot["domain"]},
            **audit.request_meta(request),
        )
        safe_domain = re.sub(r"[^a-z0-9.-]", "-", report.snapshot["domain"].lower())
        filename = f"security-report-{safe_domain}-{report.generated_at:%Y-%m-%d}.pdf"
        response = HttpResponse(render_pdf(report.snapshot), content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        response["Cache-Control"] = "private, no-store"  # a security report must not be cached
        return response