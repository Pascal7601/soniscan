from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("apps.accounts.api.urls")),
    path("api/v1/", include("apps.domains.api.urls")),
    path("api/v1/", include("apps.scans.api.urls")),
    path("api/v1/", include("apps.findings.api.urls")),
    path("api/v1/", include("apps.reports.api.urls")),
    path("api/auth/", include("allauth.headless.urls")),
    # Social-login callbacks (Google or Microsoft send the browser back here).
    path("api/auth/accounts/", include("allauth.urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="docs"),
]
