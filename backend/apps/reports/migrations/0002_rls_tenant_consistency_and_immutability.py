from django.db import migrations

from apps.core.db import composite_tenant_fk, enable_tenant_rls

# A report is evidence of what the customer was told, so it must not change after the fact.
# The only permitted UPDATE is the one Django issues when a user account is deleted
# (generated_by -> NULL, ON DELETE SET NULL); every other column must stay identical.
IMMUTABLE_FORWARD = """
CREATE FUNCTION reports_are_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.generated_by_id IS NULL
     AND (to_jsonb(NEW) - 'generated_by_id' - 'updated_at')
       = (to_jsonb(OLD) - 'generated_by_id' - 'updated_at') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'reports are immutable' USING ERRCODE = 'check_violation';
END $$;

CREATE TRIGGER reports_no_update
  BEFORE UPDATE ON reports
  FOR EACH ROW EXECUTE FUNCTION reports_are_immutable();
"""

IMMUTABLE_REVERSE = """
DROP TRIGGER reports_no_update ON reports;
DROP FUNCTION reports_are_immutable();
"""


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
        ("domains", "0002_rls_and_tenant_consistency"),
        ("scans", "0002_rls_guard_and_tenant_consistency"),
        ("reports", "0001_initial"),
    ]

    operations = [
        enable_tenant_rls("reports"),
        composite_tenant_fk(
            table="reports",
            column="domain_id",
            parent_table="domains",
            name="reports_domain_tenant_fk",
        ),
        # Blocks deleting a scan a report points at, but still allows deleting a whole domain
        # (which removes its scans and reports in one statement), like the findings references.
        composite_tenant_fk(
            table="reports",
            column="scan_id",
            parent_table="scans",
            name="reports_scan_tenant_fk",
            on_delete="NO ACTION",
        ),
        migrations.RunSQL(IMMUTABLE_FORWARD, IMMUTABLE_REVERSE),
    ]