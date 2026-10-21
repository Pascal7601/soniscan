-- Runs once when the local database is first created.
-- Migrations run as app_owner (superuser in local dev only). The application connects as
-- app_api, which is NOT a superuser and has no BYPASSRLS, so row-level security always applies.
-- In production, app_owner must also be a non-superuser role that owns the schema.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_api') THEN
    CREATE ROLE app_api LOGIN PASSWORD 'app_api_dev';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanner_worker') THEN
    CREATE ROLE scanner_worker LOGIN PASSWORD 'scanner_worker_dev';
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO app_api, scanner_worker;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_api;
-- scanner_worker gets narrower, per-table grants added by the migrations that create scan tables.
