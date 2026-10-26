from django.db import migrations

# The scanner worker is a separate, least-privilege database role. It can only touch what a scan
# needs, and only specific columns of the tables it updates. The `scanner_worker` role must exist
# BEFORE migrating (infra/postgres/init.sql); if it does not, this migration is a no-op.

FORWARD = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanner_worker') THEN
    GRANT SELECT ON domains, domain_verifications, scans, check_definitions, scoring_models
      TO scanner_worker;
    GRANT UPDATE (status, started_at, finished_at, scanner_version, error, updated_at)
      ON scans TO scanner_worker;
    GRANT UPDATE (status, verified_at, verified_method, reverify_due, updated_at)
      ON domains TO scanner_worker;
    GRANT UPDATE (result, checked_at, updated_at) ON domain_verifications TO scanner_worker;
    GRANT SELECT, INSERT, UPDATE ON findings TO scanner_worker;
    GRANT SELECT, INSERT ON finding_observations TO scanner_worker;
    GRANT INSERT ON audit_log TO scanner_worker;

    -- Read-only, cross-tenant visibility of UNFINISHED scans, so the reaper can find stuck work.
    -- Every write still happens inside one tenant's context (the tenant_isolation policy).
    CREATE POLICY scanner_worker_unfinished ON scans FOR SELECT TO scanner_worker
      USING (status IN ('queued', 'running'));
  END IF;
END $$;
"""

REVERSE = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanner_worker') THEN
    DROP POLICY IF EXISTS scanner_worker_unfinished ON scans;
    REVOKE ALL ON domains, domain_verifications, scans, check_definitions, scoring_models,
      findings, finding_observations, audit_log FROM scanner_worker;
  END IF;
END $$;
"""


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0003_audit_log_append_only_and_rls"),
        ("domains", "0002_rls_and_tenant_consistency"),
        ("scans", "0002_rls_guard_and_tenant_consistency"),
        ("findings", "0003_seed_scoring_model_v1"),
    ]

    operations = [migrations.RunSQL(FORWARD, REVERSE)]