"""Promote an already published, verified capsule in a single Atlas transaction."""
import os

from . import capsule, dcf


class Conflict(ValueError):
    pass


class IdempotencyConflict(Conflict):
    pass


class LeaseLost(ValueError):
    pass


def _query(sql, params, *, dsn=None):
    try:
        import psycopg
    except ImportError as exc:
        raise ValueError('Install the catalog extra with pip install -e ".[catalog]"') from exc
    try:
        # Empty conninfo uses libpq PG* variables, password files and service definitions.
        with psycopg.connect(dsn if dsn is not None else os.environ.get("DSE_DATABASE_URL", ""),
                             connect_timeout=5, options="-c statement_timeout=15000 -c lock_timeout=5000") as conn:
            return conn.execute(sql, params).fetchone()[0]
    except psycopg.Error as exc:
        if exc.sqlstate == "DS003":
            raise IdempotencyConflict("Idempotency key reused with different inputs") from exc
        if exc.sqlstate == "DS004":
            raise LeaseLost("Operation lease lost") from exc
        if exc.sqlstate in {"DS001", "DS002"}:
            raise Conflict(exc.diag.message_primary) from exc
        if exc.sqlstate in {"42501", "22023"}:
            raise ValueError(exc.diag.message_primary) from exc
        raise ValueError(f"Catalog operation failed ({exc.sqlstate or 'connection error'}). "
                         "Check the PostgreSQL connection, migrations and login.") from exc


def head(keys, object_id, *, dsn=None):
    obj = dcf.identifier(object_id, 7)
    version = _query("SELECT dse.object_head(%s,%s,%s)", (keys.tenant, keys.signer_id, obj), dsn=dsn)
    return {"object_id": obj, "current_version_id": str(version) if version else None}


def commit(store, keys, obj, version, expected, *, dsn=None):
    parent = None if expected == "none" else dcf.identifier(expected, 7)
    root = store.resolve(strict=True)
    manifest, wrapped = capsule.catalog_material(root, keys, obj, version)
    payload = dcf.canonical(manifest)
    ordinal = _query("SELECT dse.commit_version(%s,%s,%s::jsonb,%s,%s,%s,%s)",
                     (keys.tenant, keys.signer_id, payload.decode(), dcf.digest(payload),
                      wrapped, parent, str(root)), dsn=dsn)
    return {"object_id": obj, "version_id": version, "ordinal": ordinal}


def describe(keys, obj, version=None, *, dsn=None):
    dcf.identifier(obj, 7)
    if version is not None:
        dcf.identifier(version, 7)
    return _query("SELECT dse.version_info(%s,%s,%s,%s)",
                  (keys.tenant, keys.signer_id, obj, version), dsn=dsn)
