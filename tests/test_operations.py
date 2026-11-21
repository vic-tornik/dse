from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from dse import capsule, catalog, dcf, keys, operations
from dse.access import Principal, Settings
from dse.worker import process_one


@unittest.skipUnless(os.environ.get("DSE_TEST_ADMIN_DSN") and importlib.util.find_spec("fastapi"),
                     "requires PostgreSQL and the api/test extras")
class DurableOperationTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        keys.initialize(self.base / "keys")
        key = keys.load(self.base / "keys")
        self.admin = self.enterContext(psycopg.connect(os.environ["DSE_TEST_ADMIN_DSN"], autocommit=True))
        login = "dse_jobs_" + secrets.token_hex(8)
        password = secrets.token_urlsafe(32)
        self.admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} IN ROLE dse_client").format(
            sql.Identifier(login), sql.Literal(password)))
        self.addCleanup(self.admin.execute, sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))
        self.addCleanup(self.admin.execute, "DELETE FROM dse.client_bindings WHERE login=%s", (login,))
        self.admin.execute("INSERT INTO dse.tenants (id,slug) VALUES (%s,%s)", (key.tenant, login))
        self.admin.execute("INSERT INTO dse.client_bindings VALUES (%s,%s,%s)", (login, key.tenant, key.signer_id))
        self.token = secrets.token_urlsafe(32)
        self.principal = Principal(login, hashlib.sha256(self.token.encode()).hexdigest(), key,
            make_conninfo(os.environ["DSE_TEST_ADMIN_DSN"], user=login, password=password),
            frozenset({"read", "write"}), frozenset({"default"}))
        self.settings = Settings(self.base / "store", self.base / "temporary", (self.principal,))
        self.store = self.settings.store / key.tenant
        self.config = self.base / "api.json"
        self.config.write_text(json.dumps({
            "store": "store", "temporary": "temporary", "principals": [{
                "id": login, "token_sha256": self.principal.token_sha256, "keyring": "keys",
                "database_env": "DSE_JOB_TEST_DSN", "actions": ["read", "write"], "namespaces": ["default"]}]}))

    def sealed(self, data=b"durable"):
        source = self.base / "source"
        source.write_bytes(data)
        result = capsule.seal(source, self.store, self.principal.keyring)
        manifest, wrapped = capsule.catalog_material(self.store, self.principal.keyring,
                                                     result["object_id"], result["version_id"])
        return result, manifest, wrapped

    def count_events(self):
        return self.admin.execute("SELECT count(*) FROM dse.outbox_events WHERE tenant_id=%s",
                                  (self.principal.keyring.tenant,)).fetchone()[0]

    def expire(self, operation_id):
        self.admin.execute("UPDATE dse.operations SET lease_until=clock_timestamp()-interval '1 second' "
                           "WHERE tenant_id=%s AND id=%s", (self.principal.keyring.tenant, operation_id))

    def test_api_replay_restart_and_worker_entrypoint(self):
        from fastapi.testclient import TestClient
        from dse.api import create_app
        headers = {"Authorization": "Bearer " + self.token}
        record, _, _ = self.sealed()
        url = f"/v1/objects/{record['object_id']}/versions/{record['version_id']}/commit-operations"
        headers.update({"Idempotency-Key": dcf.uuid7(), "If-None-Match": "*"})
        with TestClient(create_app(self.settings)) as client:
            queued = client.post(url, headers=headers)
            self.assertEqual(queued.status_code, 202, queued.text)
            operation_id = queued.json()["operation_id"]
            self.assertEqual(client.post(url, headers=headers).json(), queued.json())
            changed = dict(headers)
            changed.pop("If-None-Match")
            changed["If-Match"] = '"' + dcf.uuid7() + '"'
            self.assertEqual(client.post(url, headers=changed).status_code, 409)
        with TestClient(create_app(self.settings)) as client:
            status_url = "/v1/operations/" + operation_id
            self.assertEqual(client.get(status_url, headers=headers).json()["state"], "READY")
            alias = replace(self.principal, id="another-application")
            self.assertIsNone(operations.get(alias, operation_id))
            env = dict(os.environ, DSE_API_CONFIG=str(self.config), DSE_JOB_TEST_DSN=self.principal.dsn)
            run = subprocess.run([sys.executable, "-m", "dse.worker", "--once"], env=env,
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            status = client.get(status_url, headers=headers).json()
            self.assertEqual(status["state"], "SUCCEEDED", status)
            self.assertEqual(status["result"]["version_id"], record["version_id"])
            self.assertEqual(client.post(url, headers=headers).json()["operation_id"], operation_id)
            self.assertEqual(self.count_events(), 1)

    def test_expired_worker_and_interrupted_completion(self):
        import psycopg
        record, manifest, wrapped = self.sealed()
        operation_id = operations.enqueue(self.principal, dcf.uuid7(), manifest, "none")
        job = operations.claim(self.principal, 5)
        connection = psycopg.connect(self.principal.dsn)
        try:
            payload = dcf.canonical(manifest)
            connection.execute("SELECT dse.complete_operation(%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)",
                (self.principal.keyring.tenant, self.principal.keyring.signer_id, self.principal.id,
                 operation_id, job["lease_token"], payload.decode(), dcf.digest(payload), wrapped,
                 str(self.store.resolve())))
        finally:
            connection.close()  # Simulated process loss before transaction commit.
        self.assertIsNone(catalog.head(self.principal.keyring, record["object_id"], dsn=self.principal.dsn)["current_version_id"])
        self.assertEqual(self.count_events(), 0)
        self.expire(operation_id)
        reclaimed = operations.claim(self.principal, 30)
        self.assertEqual(reclaimed["attempts"], 2)
        with self.assertRaises(catalog.LeaseLost):
            operations.complete(self.principal, job, manifest, wrapped, self.store)
        self.assertFalse(operations.fail(self.principal, job, "STALE_WORKER"))
        operations.complete(self.principal, reclaimed, manifest, wrapped, self.store)
        self.assertEqual(operations.get(self.principal, operation_id)["state"], "SUCCEEDED")
        self.assertEqual(self.count_events(), 1)

    def test_competing_claims_retry_and_policy_revocation(self):
        _, manifest, _ = self.sealed()
        operation_id = operations.enqueue(self.principal, dcf.uuid7(), manifest, "none")
        barrier = threading.Barrier(2)

        def claim():
            barrier.wait(timeout=10)
            return operations.claim(self.principal, 30)

        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = list(pool.map(lambda _: claim(), range(2)))
        self.assertEqual(sum(job is not None for job in jobs), 1)
        self.expire(operation_id)
        with patch("dse.worker.capsule.catalog_material", side_effect=OSError("transient")):
            self.assertTrue(process_one(self.settings, self.principal))
        status = operations.get(self.principal, operation_id)
        self.assertEqual(status["state"], "READY")
        self.assertEqual(status["error_code"], "TRANSIENT_STORAGE_ERROR")
        self.admin.execute("UPDATE dse.operations SET run_after=clock_timestamp() WHERE tenant_id=%s AND id=%s",
                           (self.principal.keyring.tenant, operation_id))
        revoked = replace(self.principal, actions=frozenset({"read"}))
        self.assertTrue(process_one(self.settings, revoked))
        self.assertEqual(operations.get(self.principal, operation_id)["error_code"], "POLICY_DENIED")
        self.assertEqual(self.count_events(), 0)

    def test_corruption_and_retry_exhaustion(self):
        record, manifest, _ = self.sealed()
        operation_id = operations.enqueue(self.principal, dcf.uuid7(), manifest, "none")
        (self.store / record["version_id"] / "chunks/00000000.bin").write_bytes(b"corrupted")
        self.assertTrue(process_one(self.settings, self.principal))
        self.assertEqual(operations.get(self.principal, operation_id)["error_code"], "INTEGRITY_FAILURE")
        _, manifest, _ = self.sealed(b"second")
        operation_id = operations.enqueue(self.principal, dcf.uuid7(), manifest, "none")
        operations.claim(self.principal, 5)
        self.expire(operation_id)
        self.admin.execute("UPDATE dse.operations SET attempts=5 WHERE tenant_id=%s AND id=%s",
                           (self.principal.keyring.tenant, operation_id))
        self.assertIsNone(operations.claim(self.principal))
        self.assertEqual(operations.get(self.principal, operation_id)["error_code"], "RETRY_EXHAUSTED")
        self.assertEqual(self.count_events(), 0)
