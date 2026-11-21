"""Tenant-scoped durable commit queue backed by PostgreSQL."""
from . import catalog, dcf


def enqueue(principal, key, manifest, expected):
    dcf.identifier(key, 7)
    parent = None if expected == "none" else dcf.identifier(expected, 7)
    result = catalog._query("SELECT dse.enqueue_commit(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (principal.keyring.tenant, principal.keyring.signer_id, principal.id, key,
         manifest["object_id"], manifest["version_id"], parent, manifest["namespace"],
         dcf.digest(dcf.canonical(manifest))), dsn=principal.dsn)
    return str(result)


def get(principal, operation_id):
    dcf.identifier(operation_id, 7)
    return catalog._query("SELECT dse.operation_info(%s,%s,%s,%s)",
        (principal.keyring.tenant, principal.keyring.signer_id, principal.id, operation_id), dsn=principal.dsn)


def claim(principal, seconds=300):
    return catalog._query("SELECT dse.claim_operation(%s,%s,%s,%s)",
        (principal.keyring.tenant, principal.keyring.signer_id, principal.id, seconds), dsn=principal.dsn)


def complete(principal, job, manifest, wrapped, store):
    return catalog._query("SELECT dse.complete_operation(%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)",
        (principal.keyring.tenant, principal.keyring.signer_id, principal.id, job["id"], job["lease_token"],
         dcf.canonical(manifest).decode(), dcf.digest(dcf.canonical(manifest)), wrapped, str(store.resolve())),
        dsn=principal.dsn)


def fail(principal, job, error, retry=False):
    return catalog._query("SELECT dse.fail_operation(%s,%s,%s,%s,%s,%s,%s)",
        (principal.keyring.tenant, principal.keyring.signer_id, principal.id, job["id"],
         job["lease_token"], error, retry), dsn=principal.dsn)
