from django.db import migrations

from apps.core.db import composite_tenant_fk, enable_tenant_rls


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
        ("scans", "0001_initial"),
    ]

    operations = [
        enable_tenant_rls("scans"),
        composite_tenant_fk(
            table="scans",
            column="domain_id",
            parent_table="domains",
            name="scans_domain_tenant_fk",
        ),
        # Defence in depth: an active scan can only be queued or run while the domain is verified
        # and its verification has not lapsed. The service layer checks first for a friendly
        # error; this trigger makes the rule impossible to bypass from any code path.
        migrations.RunSQL(
            sql="""
            CREATE FUNCTION enforce_active_scan_requires_verification() RETURNS trigger
            LANGUAGE plpgsql AS $$
            DECLARE
              d_status text;
              d_due    timestamptz;
            BEGIN
              IF NEW.mode = 'active' AND NEW.status IN ('queued', 'running') THEN
                SELECT status, reverify_due INTO d_status, d_due
                  FROM domains WHERE id = NEW.domain_id;
                IF d_status IS DISTINCT FROM 'verified' OR d_due IS NULL OR d_due <= now() THEN
                  RAISE EXCEPTION 'active scan refused: domain % is not currently verified',
                    NEW.domain_id USING ERRCODE = 'check_violation';
                END IF;
              END IF;
              RETURN NEW;
            END $$;

            CREATE TRIGGER scans_active_guard
              BEFORE INSERT OR UPDATE OF mode, status ON scans
              FOR EACH ROW EXECUTE FUNCTION enforce_active_scan_requires_verification();
            """,
            reverse_sql="""
            DROP TRIGGER scans_active_guard ON scans;
            DROP FUNCTION enforce_active_scan_requires_verification();
            """,
        ),
    ]