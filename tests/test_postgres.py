"""Live CLI acceptance tests. Run against a disposable migrated PostgreSQL 18 DB."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import unittest

from dse import capsule, dcf, keys


@unittest.skipUnless(os.environ.get("DSE_TEST_ADMIN_DSN"), "requires a disposable PostgreSQL catalog")
class PostgresCommitTests(unittest.TestCase):
    def test_commit_lifecycle(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        store, secret, source = base / "store", base / "key", base / "input"
        keys.initialize(secret)
        key = keys.load(secret)
        dsn = os.environ["DSE_TEST_ADMIN_DSN"]
        admin = self.enterContext(psycopg.connect(dsn, autocommit=True))
        login = "dse_test_" + secrets.token_hex(8)
        password = secrets.token_urlsafe(24)
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} IN ROLE dse_client").format(
            sql.Identifier(login), sql.Literal(password)))
        self.addCleanup(admin.execute, sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))
        self.addCleanup(admin.execute, "DELETE FROM dse.client_bindings WHERE login=%s", (login,))
        admin.execute("INSERT INTO dse.tenants (id,slug) VALUES (%s,%s)", (key.tenant, login))
        admin.execute("INSERT INTO dse.client_bindings VALUES (%s,%s,%s)", (login, key.tenant, key.signer_id))
        client = make_conninfo(dsn, user=login, password=password)
        env = dict(os.environ, DSE_DATABASE_URL=client)

        def cli(*args, expected=0):
            run = subprocess.run([sys.executable, "-m", "dse", "--keyring", str(secret), *args],
                                 capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(run.returncode, expected, run.stderr)
            return json.loads(run.stdout) if run.stdout else None

        source.write_bytes(b"first")
        record = cli("seal", str(source), "--store", str(store))
        obj, first = record["object_id"], record["version_id"]

        def commit(ver, parent, expected=0):
            return cli("commit", "--store", str(store), "--object", obj, "--version", ver,
                       "--expect", parent, expected=expected)

        def head():
            return cli("head", "--object", obj)["current_version_id"]

        self.assertIsNone(head())  # Sealing process has exited; bytes exist, no catalog head.
        with psycopg.connect(client) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with connection.transaction():
                    connection.execute("SELECT dse.object_head(%s,%s,%s)", (dcf.uuid7(), key.signer_id, obj))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with connection.transaction():
                    connection.execute("SELECT * FROM dse.versions")

        # Disconnect inside the first promotion, after SQL writes but before COMMIT.
        manifest, wrapped = capsule.catalog_material(store, key, obj, first)
        payload = dcf.canonical(manifest)
        connection = psycopg.connect(client)
        try:
            connection.execute("SELECT dse.commit_version(%s,%s,%s::jsonb,%s,%s,NULL,%s)",
                               (key.tenant, key.signer_id, payload.decode(), dcf.digest(payload),
                                wrapped, str(store.resolve())))
        finally:
            connection.close()
        self.assertIsNone(head())
        receipt = commit(first, "none")
        self.assertEqual(receipt["ordinal"], 1)

        candidates = []
        for data in (b"writer one", b"writer two"):
            source.write_bytes(data)
            candidates.append(cli("seal", str(source), "--object", obj, "--store", str(store))["version_id"])
        barrier = threading.Barrier(2)

        def compete(version):
            barrier.wait(timeout=15)
            return subprocess.run([sys.executable, "-m", "dse", "--keyring", str(secret), "commit",
                                   "--store", str(store), "--object", obj, "--version", version,
                                   "--expect", first], text=True, capture_output=True, env=env, timeout=30)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(compete, candidates))
        self.assertEqual(sorted(r.returncode for r in outcomes), [0, 3], [r.stderr for r in outcomes])
        winner = json.loads(next(r.stdout for r in outcomes if r.returncode == 0))
        self.assertEqual(winner["ordinal"], 2)
        self.assertEqual(commit(winner["version_id"], first), winner)
        self.assertEqual(commit(first, "none"), receipt)  # delayed retry after a later commit
        commit(winner["version_id"], "none", expected=3)
        self.assertEqual(head(), winner["version_id"])
        for table in ("versions", "commits"):
            count = admin.execute(sql.SQL("SELECT count(*) FROM dse.{} WHERE tenant_id=%s").format(
                sql.Identifier(table)), (key.tenant,)).fetchone()[0]
            self.assertEqual(count, 2)
