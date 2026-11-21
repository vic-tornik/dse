-- Apply once after 002_commit.sql.
BEGIN;
CREATE FUNCTION dse.version_info(p_tenant uuid, p_signer text, p_object uuid, p_version uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM dse.bind_client(p_tenant, p_signer);
    RETURN (
        SELECT jsonb_build_object('manifest', v.manifest, 'ordinal', v.ordinal,
                                  'store_root', c.store_root,
                                  'manifest_digest', encode(v.manifest_digest, 'hex'))
        FROM dse.objects o
        JOIN dse.versions v ON (v.tenant_id, v.object_id) = (o.tenant_id, o.id)
        JOIN dse.commits c ON (c.tenant_id, c.object_id, c.version_id) = (v.tenant_id, v.object_id, v.id)
        WHERE o.tenant_id = p_tenant AND o.id = p_object
          AND v.id = COALESCE(p_version, o.current_version_id)
    );
END $$;
REVOKE ALL ON FUNCTION dse.version_info(uuid,text,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION dse.version_info(uuid,text,uuid,uuid) OWNER TO dse_runtime;
GRANT EXECUTE ON FUNCTION dse.version_info(uuid,text,uuid,uuid) TO dse_client;
COMMIT;
