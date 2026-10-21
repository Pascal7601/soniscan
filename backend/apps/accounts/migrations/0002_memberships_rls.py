from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
        ("accounts", "0001_initial"),
    ]

    operations = [
        # memberships is the one table with a custom policy: a user must be able to read their
        # OWN memberships before choosing a tenant (to discover which tenants they belong to).
        # Writes still require the tenant context to match.
        migrations.RunSQL(
            sql="""
            ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
            ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
            CREATE POLICY memberships_access ON memberships
              USING (tenant_id = current_tenant() OR user_id = current_app_user())
              WITH CHECK (tenant_id = current_tenant());
            """,
            reverse_sql="""
            DROP POLICY memberships_access ON memberships;
            ALTER TABLE memberships NO FORCE ROW LEVEL SECURITY;
            ALTER TABLE memberships DISABLE ROW LEVEL SECURITY;
            """,
        ),
    ]
