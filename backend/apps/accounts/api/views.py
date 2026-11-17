from drf_spectacular.utils import extend_schema
from rest_framework.exceptions import NotAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from django.middleware.csrf import get_token
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

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
            "mfa_enabled": user.mfa_enabled,
            "memberships": selectors.memberships_for_user(user.id),
        }
        return Response(MeSerializer(payload).data)

class AuthCsrfView(APIView):
    """Sets the `csrftoken` cookie. The browser app calls this once before its first sign-in or
    sign-up request, because those are POSTs and Django rejects a POST without the token."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(responses={204: None})
    def get(self, request: Request) -> Response:
        get_token(request)  # marks the cookie to be set on this response
        return Response(status=204)