from rest_framework import serializers

from apps.domains.models import Domain


class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = ["id", "fqdn", "status", "verified_at", "reverify_due"]
        read_only_fields = fields


class DomainCreateSerializer(serializers.Serializer):
    fqdn = serializers.CharField(max_length=253)


class VerificationInstructionsSerializer(serializers.Serializer):
    method = serializers.CharField()
    record_name = serializers.CharField()
    record_value = serializers.CharField(help_text="Shown once. Store it before leaving the page.")
    expires_at = serializers.DateTimeField()

class VerificationCheckSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=["queued", "already_verified"])

class ErrorSerializer(serializers.Serializer):
    detail = serializers.CharField()