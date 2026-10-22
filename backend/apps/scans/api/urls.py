from django.urls import path

from .views import DomainScanListCreateView, ScanDetailView

urlpatterns = [
    path(
        "domains/<uuid:domain_id>/scans/", DomainScanListCreateView.as_view(), name="domain-scans"
    ),
    path("scans/<uuid:scan_id>/", ScanDetailView.as_view(), name="scan-detail"),
]