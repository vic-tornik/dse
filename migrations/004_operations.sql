BEGIN;
CREATE TABLE dse.outbox_events (
    tenant_id uuid NOT NULL,
    object_id uuid NOT NULL,
    version_id uuid NOT NULL,
    event_type text NOT NULL DEFAULT 'version.committed',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, object_id, version_id),
    FOREIGN KEY (tenant_id, object_id, version_id) REFERENCES dse.versions
);
ALTER TABLE dse.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE dse.outbox_events FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_scope ON dse.outbox_events USING (tenant_id = dse.current_tenant())
    WITH CHECK (tenant_id = dse.current_tenant());
GRANT SELECT, INSERT ON dse.outbox_events TO dse_runtime;
CREATE FUNCTION dse.record_version_event() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO dse.outbox_events (tenant_id, object_id, version_id)
        VALUES (NEW.tenant_id, NEW.object_id, NEW.id);
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION dse.record_version_event() FROM PUBLIC;
CREATE TRIGGER version_event AFTER INSERT ON dse.versions
    FOR EACH ROW EXECUTE FUNCTION dse.record_version_event();

CREATE TABLE dse.operations (
    tenant_id uuid NOT NULL REFERENCES dse.tenants,
    id uuid NOT NULL DEFAULT uuidv7(),
    principal_id text NOT NULL,
    idempotency_key uuid NOT NULL,
    object_id uuid NOT NULL,
    version_id uuid NOT NULL,
    parent_id uuid,
    namespace text NOT NULL,
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
    state text NOT NULL DEFAULT 'READY' CHECK (state IN ('READY','RUNNING','SUCCEEDED','FAILED')),
    attempts integer NOT NULL DEFAULT 0,
    run_after timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_token uuid,
    lease_until timestamptz,
    error_code text,
    result jsonb,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, principal_id, idempotency_key)
);
CREATE INDEX operations_queue ON dse.operations (tenant_id, principal_id, state, run_after);
ALTER TABLE dse.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE dse.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY operation_scope ON dse.operations USING (tenant_id = dse.current_tenant())
    WITH CHECK (tenant_id = dse.current_tenant());
GRANT SELECT, INSERT, UPDATE ON dse.operations TO dse_runtime;

CREATE FUNCTION dse.enqueue_commit(p_tenant uuid, p_signer text, p_principal text,
    p_key uuid, p_object uuid, p_version uuid, p_parent uuid, p_namespace text, p_digest bytea)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE op dse.operations%ROWTYPE;
BEGIN
    PERFORM dse.bind_client(p_tenant, p_signer);
    INSERT INTO dse.operations (tenant_id, principal_id, idempotency_key, object_id, version_id,
                                parent_id, namespace, manifest_digest)
        VALUES (p_tenant, p_principal, p_key, p_object, p_version, p_parent, p_namespace, p_digest)
        ON CONFLICT (tenant_id, principal_id, idempotency_key) DO NOTHING;
    SELECT * INTO STRICT op FROM dse.operations WHERE tenant_id = p_tenant
        AND principal_id = p_principal AND idempotency_key = p_key;
    IF (op.object_id, op.version_id, op.parent_id, op.namespace, op.manifest_digest)
       IS DISTINCT FROM (p_object, p_version, p_parent, p_namespace, p_digest) THEN
        RAISE EXCEPTION 'Idempotency key reused with different inputs' USING ERRCODE = 'DS003';
    END IF;
    RETURN op.id;
END $$;

CREATE FUNCTION dse.operation_info(p_tenant uuid, p_signer text, p_principal text, p_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM dse.bind_client(p_tenant, p_signer);
    RETURN (SELECT to_jsonb(o) - 'lease_token' - 'manifest_digest' FROM dse.operations o
        WHERE tenant_id = p_tenant AND principal_id = p_principal AND id = p_id);
END $$;

CREATE FUNCTION dse.claim_operation(p_tenant uuid, p_signer text, p_principal text, p_seconds integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE op dse.operations%ROWTYPE;
BEGIN
    PERFORM dse.bind_client(p_tenant, p_signer);
    IF p_seconds NOT BETWEEN 5 AND 3600 THEN
        RAISE EXCEPTION 'Invalid lease duration' USING ERRCODE = '22023';
    END IF;
    UPDATE dse.operations SET state = 'FAILED', error_code = 'RETRY_EXHAUSTED',
        lease_token = NULL, lease_until = NULL
        WHERE tenant_id = p_tenant AND principal_id = p_principal AND attempts >= 5
          AND ((state = 'RUNNING' AND lease_until <= clock_timestamp()) OR state = 'READY');
    SELECT * INTO op FROM dse.operations WHERE tenant_id = p_tenant AND principal_id = p_principal
        AND attempts < 5 AND ((state = 'READY' AND run_after <= clock_timestamp())
            OR (state = 'RUNNING' AND lease_until <= clock_timestamp()))
        ORDER BY run_after, id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN NULL; END IF;
    UPDATE dse.operations SET state = 'RUNNING', attempts = attempts + 1,
        lease_token = uuidv7(), lease_until = clock_timestamp() + make_interval(secs => p_seconds)
        WHERE tenant_id = p_tenant AND id = op.id RETURNING * INTO op;
    RETURN to_jsonb(op) || jsonb_build_object('manifest_digest', encode(op.manifest_digest, 'hex'));
END $$;

CREATE FUNCTION dse.complete_operation(p_tenant uuid, p_signer text, p_principal text,
    p_id uuid, p_lease uuid, p_manifest jsonb, p_digest bytea, p_wrapped bytea, p_store text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE op dse.operations%ROWTYPE; seq bigint; receipt jsonb;
BEGIN
    PERFORM dse.bind_client(p_tenant, p_signer);
    SELECT * INTO op FROM dse.operations WHERE tenant_id = p_tenant AND principal_id = p_principal
        AND id = p_id FOR UPDATE;
    IF NOT FOUND OR op.state <> 'RUNNING' OR op.lease_token IS DISTINCT FROM p_lease
       OR op.lease_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'Lease lost' USING ERRCODE = 'DS004';
    END IF;
    IF op.manifest_digest IS DISTINCT FROM p_digest
       OR op.object_id::text IS DISTINCT FROM p_manifest->>'object_id'
       OR op.version_id::text IS DISTINCT FROM p_manifest->>'version_id'
       OR op.namespace IS DISTINCT FROM p_manifest->>'namespace' THEN
        RAISE EXCEPTION 'Operation input mismatch' USING ERRCODE = '22023';
    END IF;
    seq := dse.commit_version(p_tenant, p_signer, p_manifest, p_digest, p_wrapped, op.parent_id, p_store);
    receipt := jsonb_build_object('object_id', op.object_id, 'version_id', op.version_id, 'ordinal', seq);
    UPDATE dse.operations SET state = 'SUCCEEDED', result = receipt, error_code = NULL,
        lease_token = NULL, lease_until = NULL WHERE tenant_id = p_tenant AND id = p_id;
    RETURN receipt;
END $$;

CREATE FUNCTION dse.fail_operation(p_tenant uuid, p_signer text, p_principal text,
    p_id uuid, p_lease uuid, p_error text, p_retry boolean)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM dse.bind_client(p_tenant, p_signer);
    UPDATE dse.operations SET state = CASE WHEN p_retry AND attempts < 5 THEN 'READY' ELSE 'FAILED' END,
        run_after = clock_timestamp() + make_interval(secs => LEAST(60, power(2, attempts)::integer)),
        error_code = p_error, lease_token = NULL, lease_until = NULL
        WHERE tenant_id = p_tenant AND principal_id = p_principal AND id = p_id
          AND state = 'RUNNING' AND lease_token = p_lease AND lease_until > clock_timestamp();
    RETURN FOUND;
END $$;

REVOKE ALL ON FUNCTION dse.enqueue_commit(uuid,text,text,uuid,uuid,uuid,uuid,text,bytea),
    dse.operation_info(uuid,text,text,uuid), dse.claim_operation(uuid,text,text,integer),
    dse.complete_operation(uuid,text,text,uuid,uuid,jsonb,bytea,bytea,text),
    dse.fail_operation(uuid,text,text,uuid,uuid,text,boolean) FROM PUBLIC;
ALTER FUNCTION dse.enqueue_commit(uuid,text,text,uuid,uuid,uuid,uuid,text,bytea) OWNER TO dse_runtime;
ALTER FUNCTION dse.operation_info(uuid,text,text,uuid) OWNER TO dse_runtime;
ALTER FUNCTION dse.claim_operation(uuid,text,text,integer) OWNER TO dse_runtime;
ALTER FUNCTION dse.complete_operation(uuid,text,text,uuid,uuid,jsonb,bytea,bytea,text) OWNER TO dse_runtime;
ALTER FUNCTION dse.fail_operation(uuid,text,text,uuid,uuid,text,boolean) OWNER TO dse_runtime;
GRANT EXECUTE ON FUNCTION dse.enqueue_commit(uuid,text,text,uuid,uuid,uuid,uuid,text,bytea),
    dse.operation_info(uuid,text,text,uuid), dse.claim_operation(uuid,text,text,integer),
    dse.complete_operation(uuid,text,text,uuid,uuid,jsonb,bytea,bytea,text),
    dse.fail_operation(uuid,text,text,uuid,uuid,text,boolean) TO dse_client;
COMMIT;
