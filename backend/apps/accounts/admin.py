from django.conf import settings
from django.contrib import admin
from django.shortcuts import redirect

from .models import Membership, Tenant, User

admin.site.register(Tenant)
admin.site.register(User)
admin.site.register(Membership)


def _sign_in_through_the_app(request):
    return redirect(f"{settings.FRONTEND_URL}/login")


# Django's own password form knows nothing about MFA, so it would be a way around it. Staff sign
# in through the app (password, then second factor) and then open /admin/ with that session.
# Assigned here, before config.urls builds the admin URLs.
admin.site.login = _sign_in_through_the_app