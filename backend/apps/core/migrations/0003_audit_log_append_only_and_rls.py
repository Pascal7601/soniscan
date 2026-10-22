from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("core", "0002_audit_log")]

    operations = [
        migrations.RunSQL(
            sql="""
            CREATE FUNCTION audit_log_reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              RAISE EXCEPTION 'audit_log is append-only';
            END $$;

            CREATE TRIGGER audit_log_no_update_delete
              BEFORE UPDATE OR DELETE ON audit_log
              FOR EACH ROW EXECUTE FUNCTION audit_log_reject_change();

            CREATE TRIGGER audit_log_no_truncate
              BEFORE TRUNCATE ON audit_log
              FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_change();

            -- Tenants can read their own events; the application and workers may append.
            ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
            ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
            CREATE POLICY audit_read_own ON audit_log FOR SELECT
              USING (tenant_id = current_tenant());
            CREATE POLICY audit_append ON audit_log FOR INSERT WITH CHECK (true);
            """,
            reverse_sql="""
            DROP POLICY audit_append ON audit_log;
            DROP POLICY audit_read_own ON audit_log;
            ALTER TABLE audit_log NO FORCE ROW LEVEL SECURITY;
            ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY;
            DROP TRIGGER audit_log_no_truncate ON audit_log;
            DROP TRIGGER audit_log_no_update_delete ON audit_log;
            DROP FUNCTION audit_log_reject_change();
            """,
        ),
    ]