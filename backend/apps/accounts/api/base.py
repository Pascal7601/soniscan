"""Base class for every authenticated, tenant-scoped API view.

After DRF authenticates the request, this resolves which organisation the caller is acting for
(X-Tenant-ID header, validated against their memberships) and activates the database context so
row-level security applies to everything the view does.
"""

from uuid import UUID

from rest_framework.exceptions import ParseError, PermissionDenied
from rest_framework.request import Request
from rest_framework.views import APIView

from apps.accounts.models import Membership
from apps.core.tenancy import activate

TENANT_HEADER = "X-Tenant-ID"


class TenantScopedAPIView(APIView):
    require_tenant = True  # set False for user-level endpoints such as /me/

    def perform_authentication(self, request: Request) -> None:
        super().perform_authentication(request)
        user = request.user
        if not user.is_authenticated:
            return
        # Lets the memberships policy match the caller's own rows before a tenant is chosen.
        activate(user_id=user.id)
        if not self.require_tenant:
            return
        membership = self._resolve_membership(request, user.id)
        request.tenant_id = membership.tenant_id  # type: ignore[attr-defined]
        request.membership = membership  # type: ignore[attr-defined]
        activate(tenant_id=membership.tenant_id)

    @staticmethod
    def _resolve_membership(request: Request, user_id: UUID) -> Membership:
        header = request.headers.get(TENANT_HEADER)
        memberships = Membership.objects.filter(user_id=user_id)
        if header:
            try:
                tenant_id = UUID(header)
            except ValueError as exc:
                raise ParseError(f"{TENANT_HEADER} must be a UUID") from exc
            membership = memberships.filter(tenant_id=tenant_id).first()
            if membership is None:
                raise PermissionDenied("You are not a member of this organisation.")
            return membership
        only = list(memberships[:2])
        if len(only) == 1:
            return only[0]
        raise ParseError(f"{TENANT_HEADER} header is required.")
