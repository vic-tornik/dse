-- Apply to a fresh PostgreSQL 18 database as the migration owner.
BEGIN;
CREATE SCHEMA dse;
CREATE TABLE dse.tenants (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    slug text NOT NULL UNIQUE
);
CREATE TABLE dse.objects (
    tenant_id uuid NOT NULL REFERENCES dse.tenants,
    id uuid NOT NULL DEFAULT uuidv7(),
    namespace text NOT NULL CHECK (namespace ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    current_version_id uuid,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE dse.versions (
    tenant_id uuid NOT NULL,
    object_id uuid NOT NULL,
    id uuid NOT NULL DEFAULT uuidv7(),
    ordinal bigint NOT NULL CHECK (ordinal > 0),
    manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
    wrapped_dek bytea NOT NULL,
    kek_ref text NOT NULL,
    PRIMARY KEY (tenant_id, object_id, id),
    UNIQUE (tenant_id, object_id, ordinal),
    FOREIGN KEY (tenant_id, object_id) REFERENCES dse.objects
);
ALTER TABLE dse.objects ADD FOREIGN KEY (tenant_id, id, current_version_id)
    REFERENCES dse.versions (tenant_id, object_id, id);

-- Role membership is provisioned separately for the authenticated API service.
CREATE ROLE dse_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA dse TO dse_runtime;
GRANT SELECT ON dse.tenants TO dse_runtime;
GRANT SELECT, INSERT ON dse.objects, dse.versions TO dse_runtime;
GRANT UPDATE (current_version_id) ON dse.objects TO dse_runtime;

CREATE FUNCTION dse.current_tenant() RETURNS uuid LANGUAGE sql STABLE
    RETURN NULLIF(current_setting('dse.tenant_id', true), '')::uuid;

ALTER TABLE dse.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE dse.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON dse.tenants USING (id = dse.current_tenant());
ALTER TABLE dse.objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE dse.objects FORCE ROW LEVEL SECURITY;
CREATE POLICY object_scope ON dse.objects USING (tenant_id = dse.current_tenant())
    WITH CHECK (tenant_id = dse.current_tenant());
ALTER TABLE dse.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dse.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY version_scope ON dse.versions USING (tenant_id = dse.current_tenant())
    WITH CHECK (tenant_id = dse.current_tenant());
COMMIT;
