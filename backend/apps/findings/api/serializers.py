from datetime import timedelta

from django.utils import timezone
from rest_framework import serializers

from apps.findings.models import Finding
from apps.findings.services import MAX_RISK_ACCEPTANCE_DAYS
from scanner import scoring


class FindingSerializer(serializers.ModelSerializer):
    check_key = serializers.CharField(source="check_definition.check_key")
    title = serializers.CharField(source="check_definition.title")
    score = serializers.FloatField()
    tier = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = [
            "id", "check_key", "title", "asset", "severity", "score", "tier", "status",
            "first_seen_at", "last_seen_at", "reopened_count", "accepted_until",
        ]  # fmt: skip
        read_only_fields = fields

    def get_tier(self, obj: Finding) -> str:
        return scoring.tier(float(obj.score), self.context["params"])


class FixFirstItemSerializer(serializers.Serializer):
    rank = serializers.IntegerField()
    finding_id = serializers.UUIDField()
    check_key = serializers.CharField()
    asset = serializers.CharField()
    title = serializers.CharField()
    plain_explanation = serializers.CharField()
    why_it_matters = serializers.CharField()
    fix_steps = serializers.ListField(child=serializers.CharField())
    effort = serializers.CharField()
    owner_hint = serializers.CharField(allow_blank=True)
    severity = serializers.CharField()
    score = serializers.FloatField()
    tier = serializers.CharField()


class PostureSerializer(serializers.Serializer):
    score = serializers.IntegerField(min_value=0, max_value=100)
    grade = serializers.ChoiceField(choices=["A", "B", "C", "D", "F"])
    total_risk = serializers.FloatField()
    capped_by = serializers.CharField(allow_null=True)
    open_findings = serializers.IntegerField()
    counts_by_tier = serializers.DictField(child=serializers.IntegerField())


class AcceptRiskSerializer(serializers.Serializer):
    reason = serializers.CharField(min_length=10, max_length=2000)
    until = serializers.DateTimeField(
        help_text=f"Review date; at most {MAX_RISK_ACCEPTANCE_DAYS} days away."
    )

    def validate_until(self, value):
        now = timezone.now()
        if value <= now:
            raise serializers.ValidationError("Must be in the future.")
        if value - now > timedelta(days=MAX_RISK_ACCEPTANCE_DAYS):
            raise serializers.ValidationError(
                f"Cannot be more than {MAX_RISK_ACCEPTANCE_DAYS} days away."
            )
        return value