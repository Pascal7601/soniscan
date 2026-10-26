from uuid import UUID

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from apps.accounts.api.base import TenantScopedAPIView
from apps.domains import selectors, services

from .serializers import (
    DomainCreateSerializer,
    DomainSerializer,
    ErrorSerializer,
    VerificationCheckSerializer,
    VerificationInstructionsSerializer,
)


class DomainListCreateView(TenantScopedAPIView):
    @extend_schema(responses=DomainSerializer(many=True))
    def get(self, request: Request) -> Response:
        domains = selectors.list_domains(request.tenant_id)
        return Response(DomainSerializer(domains, many=True).data)

    @extend_schema(request=DomainCreateSerializer, responses={201: DomainSerializer})
    def post(self, request: Request) -> Response:
        body = DomainCreateSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        try:
            domain = services.add_domain(
                tenant_id=request.tenant_id,
                fqdn=body.validated_data["fqdn"],
            )
        except services.DomainError as exc:
            raise ValidationError({"fqdn": [str(exc)]}) from exc
        return Response(DomainSerializer(domain).data, status=status.HTTP_201_CREATED)


class DomainVerificationStartView(TenantScopedAPIView):
    @extend_schema(request=None, responses={201: VerificationInstructionsSerializer})
    def post(self, request: Request, domain_id: UUID) -> Response:
        domain = selectors.get_domain(
            tenant_id=request.tenant_id,
            domain_id=domain_id,
        )
        if domain is None:
            raise NotFound
        verification, token = services.start_verification(domain=domain)
        payload = {
            "method": verification.method,
            "record_name": services.verification_record_name(domain),
            "record_value": f"{services.TXT_PREFIX}{token}",
            "expires_at": verification.expires_at,
        }
        return Response(
            VerificationInstructionsSerializer(payload).data, status=status.HTTP_201_CREATED
        )


class DomainVerificationCheckView(TenantScopedAPIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "verification_check"

    @extend_schema(request=None, responses={202: VerificationCheckSerializer, 409: ErrorSerializer})
    def post(self, request: Request, domain_id: UUID) -> Response:
        domain = selectors.get_domain(
            tenant_id=request.tenant_id,
            domain_id=domain_id,
        )
        if domain is None:
            raise NotFound
        if domain.is_verified_now():
            return Response({"status": "already_verified"}, status=status.HTTP_200_OK)
        try:
            services.request_verification_check(domain=domain, actor_id=request.user.id)
        except services.NoPendingVerification as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        return Response({"status": "queued"}, status=status.HTTP_202_ACCEPTED)