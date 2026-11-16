-- Run as the migration administrator against an isolated test catalog.
BEGIN;
INSERT INTO dse.tenants (id, slug) VALUES
('00000000-0000-7000-8000-000000000001', 'test-tenant-a'),
('00000000-0000-7000-8000-000000000002', 'test-tenant-b');
SET LOCAL ROLE dse_runtime;
DO $$
BEGIN
    IF EXISTS (SELECT FROM dse.tenants) THEN RAISE EXCEPTION 'missing tenant context leaked rows'; END IF;
END $$;
SET LOCAL dse.tenant_id = '00000000-0000-7000-8000-000000000001';
INSERT INTO dse.objects (tenant_id, namespace) VALUES (dse.current_tenant(), 'test');
DO $$
BEGIN
    IF (SELECT count(*) FROM dse.tenants) <> 1 THEN RAISE EXCEPTION 'tenant isolation failed'; END IF;
    BEGIN
        INSERT INTO dse.objects (tenant_id, namespace) VALUES ('00000000-0000-7000-8000-000000000002', 'test');
        RAISE EXCEPTION 'cross-tenant write succeeded';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    IF has_table_privilege(current_user, 'dse.versions', 'UPDATE')
       OR has_table_privilege(current_user, 'dse.versions', 'DELETE') THEN
        RAISE EXCEPTION 'runtime may mutate historical versions';
    END IF;
END $$;
SET LOCAL dse.tenant_id = '00000000-0000-7000-8000-000000000002';
DO $$ BEGIN
    IF EXISTS (SELECT FROM dse.objects) THEN RAISE EXCEPTION 'cross-tenant object visible'; END IF;
END $$;
ROLLBACK;
