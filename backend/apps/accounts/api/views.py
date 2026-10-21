from drf_spectacular.utils import extend_schema
from rest_framework.exceptions import NotAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts import selectors
from apps.accounts.models import User

from .base import TenantScopedAPIView
from .serializers import MeSerializer


class MeView(TenantScopedAPIView):
    require_tenant = False

    @extend_schema(responses=MeSerializer)
    def get(self, request: Request) -> Response:
        user = request.user
        if not isinstance(user, User):
            raise NotAuthenticated
        payload = {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "memberships": selectors.memberships_for_user(user.id),
        }
        return Response(MeSerializer(payload).data)
