from django.db import migrations

from apps.core.db import composite_tenant_fk, enable_tenant_rls


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
        ("domains", "0001_initial"),
    ]

    operations = [
        enable_tenant_rls("domains"),
        enable_tenant_rls("domain_verifications"),
        composite_tenant_fk(
            table="domain_verifications",
            column="domain_id",
            parent_table="domains",
            name="domain_verifications_domain_tenant_fk",
        ),
    ]
