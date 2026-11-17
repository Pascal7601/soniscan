from django.urls import path

from .views import DomainReportListCreateView, ReportDetailView, ReportPdfView

urlpatterns = [
    path(
        "domains/<uuid:domain_id>/reports/",
        DomainReportListCreateView.as_view(),
        name="domain-reports",
    ),
    path("reports/<uuid:report_id>/", ReportDetailView.as_view(), name="report-detail"),
    path("reports/<uuid:report_id>/pdf/", ReportPdfView.as_view(), name="report-pdf"),
]