from django.db import migrations


class Migration(migrations.Migration):
    initial = True
    dependencies: list[tuple[str, str]] = []

    operations = [
        migrations.RunSQL(
            sql="""
            CREATE FUNCTION current_tenant() RETURNS uuid LANGUAGE sql STABLE AS $$
              SELECT nullif(current_setting('app.current_tenant', true), '')::uuid
            $$;
            CREATE FUNCTION current_app_user() RETURNS uuid LANGUAGE sql STABLE AS $$
              SELECT nullif(current_setting('app.current_user', true), '')::uuid
            $$;
            """,
            reverse_sql="DROP FUNCTION current_app_user(); DROP FUNCTION current_tenant();",
        ),
    ]
