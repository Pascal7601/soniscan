from uuid import UUID

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.exceptions import NotAuthenticated, NotFound, PermissionDenied, ValidationError
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts.api.base import TenantScopedAPIView
from apps.accounts.models import Membership, User
from apps.domains import selectors as domain_selectors
from apps.domains.models import Domain
from apps.findings import selectors, services
from apps.findings.models import Finding
from scanner import scoring

from .serializers import (
    AcceptRiskSerializer,
    FindingSerializer,
    FixFirstItemSerializer,
    PostureSerializer,
)

_STATUSES = {*Finding.Status.values, "all"}


def _domain_or_404(request: Request, domain_id: UUID) -> Domain:
    domain = domain_selectors.get_domain(
        tenant_id=request.tenant_id,  # type: ignore[attr-defined]
        domain_id=domain_id,
    )
    if domain is None:
        raise NotFound
    return domain


def _params() -> scoring.ScoringParams:
    return scoring.ScoringParams.from_dict(selectors.current_scoring_model().params)


class DomainFindingListView(TenantScopedAPIView):
    @extend_schema(
        parameters=[
            OpenApiParameter("status", OpenApiTypes.STR, enum=sorted(_STATUSES), default="open")
        ],
        responses=FindingSerializer(many=True),
    )
    def get(self, request: Request, domain_id: UUID) -> Response:
        domain = _domain_or_404(request, domain_id)
        status = request.query_params.get("status", "open")
        if status not in _STATUSES:
            raise ValidationError({"status": [f"Must be one of: {', '.join(sorted(_STATUSES))}"]})
        findings = selectors.list_findings(
            tenant_id=domain.tenant_id,
            domain_id=domain.id,
            status=None if status == "all" else status,
        )
        return Response(FindingSerializer(findings, many=True, context={"params": _params()}).data)


class DomainPostureView(TenantScopedAPIView):
    @extend_schema(responses=PostureSerializer)
    def get(self, request: Request, domain_id: UUID) -> Response:
        domain = _domain_or_404(request, domain_id)
        result = services.compute_posture(tenant_id=domain.tenant_id, domain_id=domain.id)
        payload = {
            "score": result.score,
            "grade": result.grade,
            "total_risk": result.total_risk,
            "capped_by": result.capped_by,
            "open_findings": sum(result.counts_by_tier.values()),
            "counts_by_tier": dict(result.counts_by_tier),
        }
        return Response(PostureSerializer(payload).data)


class DomainFixFirstView(TenantScopedAPIView):
    @extend_schema(responses=FixFirstItemSerializer(many=True))
    def get(self, request: Request, domain_id: UUID) -> Response:
        domain = _domain_or_404(request, domain_id)
        params = _params()
        items = [
            {
                "rank": rank,
                "finding_id": f.id,
                "check_key": f.check_definition.check_key,
                "asset": f.asset,
                "title": f.check_definition.title,
                "plain_explanation": f.check_definition.plain_explanation,
                "why_it_matters": f.check_definition.why_it_matters,
                "fix_steps": f.check_definition.fix_steps,
                "effort": f.check_definition.effort,
                "owner_hint": f.check_definition.owner_hint,
                "severity": f.severity,
                "score": float(f.score),
                "tier": scoring.tier(float(f.score), params),
            }
            for rank, f in enumerate(
                selectors.fix_first(tenant_id=domain.tenant_id, domain_id=domain.id), start=1
            )
        ]
        return Response(FixFirstItemSerializer(items, many=True).data)


class FindingAcceptRiskView(TenantScopedAPIView):
    @extend_schema(request=AcceptRiskSerializer, responses=FindingSerializer)
    def post(self, request: Request, finding_id: UUID) -> Response:
        user = request.user
        if not isinstance(user, User):
            raise NotAuthenticated
        membership: Membership = request.membership  # type: ignore[attr-defined]
        if membership.role not in (Membership.Role.OWNER, Membership.Role.ADMIN):
            raise PermissionDenied("Only owners and admins can accept a risk.")
        finding = selectors.get_finding(
            tenant_id=request.tenant_id,  # type: ignore[attr-defined]
            finding_id=finding_id,
        )
        if finding is None:
            raise NotFound
        body = AcceptRiskSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        try:
            finding = services.accept_risk(
                finding=finding,
                actor_id=user.id,
                reason=body.validated_data["reason"],
                until=body.validated_data["until"],
            )
        except services.FindingError as exc:
            raise ValidationError({"detail": [str(exc)]}) from exc
        return Response(FindingSerializer(finding, context={"params": _params()}).data)