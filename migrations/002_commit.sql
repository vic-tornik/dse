-- Apply once, after 001_atlas.sql, as the migration administrator.
BEGIN;
CREATE ROLE dse_client NOLOGIN;
GRANT USAGE ON SCHEMA dse TO dse_client;

CREATE TABLE dse.client_bindings (
    login name PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES dse.tenants,
    signer_id text NOT NULL
);
GRANT SELECT ON dse.client_bindings TO dse_runtime;

-- The append-only event also records the expected parent and the local placement.
CREATE TABLE dse.commits (
    tenant_id uuid NOT NULL,
    object_id uuid NOT NULL,
    version_id uuid NOT NULL,
    parent_id uuid,
    store_root text NOT NULL CHECK (store_root <> ''),
    committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, object_id, version_id),
    FOREIGN KEY (tenant_id, object_id, version_id) REFERENCES dse.versions,
    FOREIGN KEY (tenant_id, object_id, parent_id) REFERENCES dse.versions
);
ALTER TABLE dse.commits ENABLE ROW LEVEL SECURITY;
ALTER TABLE dse.commits FORCE ROW LEVEL SECURITY;
CREATE POLICY commit_scope ON dse.commits USING (tenant_id = dse.current_tenant())
    WITH CHECK (tenant_id = dse.current_tenant());
GRANT SELECT, INSERT ON dse.commits TO dse_runtime;

CREATE FUNCTION dse.bind_client(p_tenant uuid, p_signer text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM dse.client_bindings WHERE login = session_user
                   AND tenant_id = p_tenant AND signer_id = p_signer) THEN
        RAISE EXCEPTION 'Login and keyring do not match a provisioned tenant' USING ERRCODE = '42501';
    END IF;
    PERFORM set_config('dse.tenant_id', p_tenant::text, true);
END $$;

CREATE FUNCTION dse.object_head(p_tenant uuid, p_signer text, p_object uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM dse.bind_client(p_tenant, p_signer);
    RETURN (SELECT current_version_id FROM dse.objects WHERE tenant_id = p_tenant AND id = p_object);
END $$;

CREATE FUNCTION dse.commit_version(p_tenant uuid, p_signer text, p_manifest jsonb,
    p_digest bytea, p_wrapped bytea, p_parent uuid, p_store text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    obj uuid := (p_manifest->>'object_id')::uuid;
    ver uuid := (p_manifest->>'version_id')::uuid;
    ns text := p_manifest->>'namespace';
    current_ver uuid;
    object_ns text;
    seq bigint;
    previous dse.commits%ROWTYPE;
BEGIN
    PERFORM dse.bind_client(p_tenant, p_signer);
    IF (p_manifest->>'tenant_ref') IS DISTINCT FROM p_tenant::text
       OR (p_manifest #>> '{signatures,0,key_id}') IS DISTINCT FROM p_signer THEN
        RAISE EXCEPTION 'Manifest identity mismatch' USING ERRCODE = '22023';
    END IF;
    INSERT INTO dse.objects (tenant_id, id, namespace) VALUES (p_tenant, obj, ns)
        ON CONFLICT (tenant_id, id) DO NOTHING;
    SELECT current_version_id, namespace INTO STRICT current_ver, object_ns FROM dse.objects
        WHERE tenant_id = p_tenant AND id = obj FOR UPDATE;
    SELECT * INTO previous FROM dse.commits
        WHERE tenant_id = p_tenant AND object_id = obj AND version_id = ver;
    IF FOUND THEN
        SELECT ordinal INTO seq FROM dse.versions WHERE tenant_id = p_tenant AND object_id = obj
            AND id = ver AND manifest_digest = p_digest AND manifest = p_manifest AND wrapped_dek = p_wrapped;
        IF seq IS NULL OR previous.parent_id IS DISTINCT FROM p_parent OR previous.store_root IS DISTINCT FROM p_store THEN
            RAISE EXCEPTION 'Version already committed with different inputs' USING ERRCODE = 'DS002';
        END IF;
        RETURN seq;
    END IF;
    IF current_ver IS DISTINCT FROM p_parent THEN
        RAISE EXCEPTION 'Current version differs from expected parent' USING ERRCODE = 'DS001';
    END IF;
    IF object_ns <> ns THEN
        RAISE EXCEPTION 'Object namespace differs from manifest' USING ERRCODE = '22023';
    END IF;
    SELECT COALESCE(MAX(ordinal), 0) + 1 INTO seq FROM dse.versions WHERE tenant_id = p_tenant AND object_id = obj;
    INSERT INTO dse.versions (tenant_id, object_id, id, ordinal, manifest, manifest_digest, wrapped_dek, kek_ref)
        VALUES (p_tenant, obj, ver, seq, p_manifest, p_digest, p_wrapped, 'dev-keyring:' || p_tenant::text);
    INSERT INTO dse.commits (tenant_id, object_id, version_id, parent_id, store_root)
        VALUES (p_tenant, obj, ver, p_parent, p_store);
    UPDATE dse.objects SET current_version_id = ver WHERE tenant_id = p_tenant AND id = obj;
    RETURN seq;
END $$;

REVOKE ALL ON FUNCTION dse.bind_client(uuid,text), dse.object_head(uuid,text,uuid),
    dse.commit_version(uuid,text,jsonb,bytea,bytea,uuid,text) FROM PUBLIC;
ALTER FUNCTION dse.bind_client(uuid,text) OWNER TO dse_runtime;
ALTER FUNCTION dse.object_head(uuid,text,uuid) OWNER TO dse_runtime;
ALTER FUNCTION dse.commit_version(uuid,text,jsonb,bytea,bytea,uuid,text) OWNER TO dse_runtime;
GRANT EXECUTE ON FUNCTION dse.object_head(uuid,text,uuid),
    dse.commit_version(uuid,text,jsonb,bytea,bytea,uuid,text) TO dse_client;
COMMIT;
