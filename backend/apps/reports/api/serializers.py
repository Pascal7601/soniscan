from rest_framework import serializers

from apps.reports.models import Report


class ReportSerializer(serializers.ModelSerializer):
    domain_id = serializers.UUIDField()
    scan_id = serializers.UUIDField()

    class Meta:
        model = Report
        fields = ["id", "domain_id", "scan_id", "generated_at", "score", "grade", "open_findings"]
        read_only_fields = fields


class ReportErrorSerializer(serializers.Serializer):
    detail = serializers.CharField()
    code = serializers.CharField()