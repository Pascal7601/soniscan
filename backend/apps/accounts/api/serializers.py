from rest_framework import serializers

from apps.accounts.models import Membership


class MembershipSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField()
    tenant_name = serializers.CharField(source="tenant.name")

    class Meta:
        model = Membership
        fields = ["tenant_id", "tenant_name", "role"]


class MeSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    email = serializers.EmailField()
    display_name = serializers.CharField()
    memberships = MembershipSerializer(many=True)
