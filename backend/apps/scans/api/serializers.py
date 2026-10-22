from rest_framework import serializers

from apps.scans.models import Scan


class ScanSerializer(serializers.ModelSerializer):
    domain_id = serializers.UUIDField()

    class Meta:
        model = Scan
        fields = [
            "id",
            "domain_id",
            "mode",
            "status",
            "trigger_type",
            "queued_at",
            "started_at",
            "finished_at",
        ]
        read_only_fields = fields


class ScanCreateSerializer(serializers.Serializer):
    mode = serializers.ChoiceField(choices=Scan.Mode.choices, default=Scan.Mode.PASSIVE)


class ScanErrorSerializer(serializers.Serializer):
    detail = serializers.CharField()
    code = serializers.CharField()