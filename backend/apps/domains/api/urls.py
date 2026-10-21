from django.urls import path

from .views import DomainListCreateView, DomainVerificationStartView

urlpatterns = [
    path("domains/", DomainListCreateView.as_view(), name="domain-list"),
    path(
        "domains/<uuid:domain_id>/verification/",
        DomainVerificationStartView.as_view(),
        name="domain-verification-start",
    ),
]
