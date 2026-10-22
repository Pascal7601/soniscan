"""Migration helpers for database features Django cannot express natively."""

from django.db import migrations


def enable_tenant_rls(table: str, policy_name: str = "tenant_isolation") -> migrations.RunSQL:
    """Enable forced row-level security keyed on tenant_id = current_tenant().

    Fails closed: when no tenant is set, no rows are visible or writable.
    `table` is a code constant from a migration, never user input.
    """
    forward = f"""
        ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
        ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
        CREATE POLICY {policy_name} ON {table}
          USING (tenant_id = current_tenant())
          WITH CHECK (tenant_id = current_tenant());
    """
    reverse = f"""
        DROP POLICY {policy_name} ON {table};
        ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;
    """
    return migrations.RunSQL(forward, reverse)


def composite_tenant_fk(
    *, table: str, column: str, parent_table: str, name: str, on_delete: str = "CASCADE"
) -> migrations.RunSQL:
    """Add FOREIGN KEY (column, tenant_id) -> parent(id, tenant_id).

    Guarantees a child row can never point at a parent owned by another tenant.
    The parent needs UNIQUE (id, tenant_id). Use on_delete="NO ACTION" for references that must
    block deleting the parent but still allow a cascade that removes both in one statement.
    """
    if on_delete not in ("CASCADE", "NO ACTION", "RESTRICT"):
        raise ValueError(f"unsupported on_delete: {on_delete}")
    forward = f"""
        ALTER TABLE {table} ADD CONSTRAINT {name}
          FOREIGN KEY ({column}, tenant_id) REFERENCES {parent_table} (id, tenant_id)
          ON DELETE {on_delete};
    """
    reverse = f"ALTER TABLE {table} DROP CONSTRAINT {name};"
    return migrations.RunSQL(forward, reverse)
