-- TrustVault Dual Database Roles & Audit Immutability Trigger
-- Execute this script as PostgreSQL superuser (postgres) on database 'trustvault'

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'trustvault_app') THEN
    CREATE USER trustvault_app WITH PASSWORD 'app_secure_password';
  END IF;
END
$$;

GRANT CONNECT ON DATABASE trustvault TO trustvault_app;
GRANT USAGE ON SCHEMA public TO trustvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO trustvault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO trustvault_app;

-- If AuditLog table exists, enforce strict immutability rules:
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'AuditLog') THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON "AuditLog" FROM trustvault_app;
    GRANT SELECT, INSERT ON "AuditLog" TO trustvault_app;

    -- Create or replace trigger function
    CREATE OR REPLACE FUNCTION reject_audit_mutation()
    RETURNS TRIGGER AS $func$
    BEGIN
      RAISE EXCEPTION 'AuditLog rows are strictly immutable. UPDATE and DELETE operations are prohibited.';
    END;
    $func$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS trg_prevent_audit_mutation ON "AuditLog";
    CREATE TRIGGER trg_prevent_audit_mutation
    BEFORE UPDATE OR DELETE ON "AuditLog"
    FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
  END IF;
END
$$;
