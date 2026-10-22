from django.urls import path

from .views import (
    DomainFindingListView,
    DomainFixFirstView,
    DomainPostureView,
    FindingAcceptRiskView,
)

urlpatterns = [
    path(
        "domains/<uuid:domain_id>/findings/",
        DomainFindingListView.as_view(),
        name="domain-findings",
    ),
    path("domains/<uuid:domain_id>/posture/", DomainPostureView.as_view(), name="domain-posture"),
    path(
        "domains/<uuid:domain_id>/fix-first/", DomainFixFirstView.as_view(), name="domain-fix-first"
    ),
    path(
        "findings/<uuid:finding_id>/accept-risk/",
        FindingAcceptRiskView.as_view(),
        name="finding-accept-risk",
    ),
]