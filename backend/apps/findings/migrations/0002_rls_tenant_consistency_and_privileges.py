from django.db import migrations

from apps.core.db import composite_tenant_fk, enable_tenant_rls


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
        ("findings", "0001_initial"),
    ]

    operations = [
        enable_tenant_rls("findings"),
        enable_tenant_rls("finding_observations"),
        composite_tenant_fk(
            table="findings",
            column="domain_id",
            parent_table="domains",
            name="findings_domain_tenant_fk",
        ),
        # References to scans block deleting a scan that findings still point at, but still allow
        # deleting a whole domain (which removes its scans and findings in one statement).
        composite_tenant_fk(
            table="findings",
            column="first_seen_scan_id",
            parent_table="scans",
            name="findings_first_scan_tenant_fk",
            on_delete="NO ACTION",
        ),
        composite_tenant_fk(
            table="findings",
            column="last_seen_scan_id",
            parent_table="scans",
            name="findings_last_scan_tenant_fk",
            on_delete="NO ACTION",
        ),
        composite_tenant_fk(
            table="finding_observations",
            column="finding_id",
            parent_table="findings",
            name="observations_finding_tenant_fk",
        ),
        composite_tenant_fk(
            table="finding_observations",
            column="scan_id",
            parent_table="scans",
            name="observations_scan_tenant_fk",
        ),
        # The check library and scoring constants are global and security-relevant: the
        # application role may read them but never change them (only the owner role, during
        # deploys, via `sync_check_library` and migrations).
        migrations.RunSQL(
            sql="""
            DO $$
            BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_api') THEN
                REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON check_definitions, scoring_models FROM app_api;
              END IF;
            END $$;
            """,
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]