import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest

from dse import dcf, keys
from dse.access import Settings


@unittest.skipUnless(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx"),
                     "install the api and test extras")
class ApiPermissionTests(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from dse.api import create_app
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        keys.initialize(self.base / "key")
        self.token = secrets.token_urlsafe(32)
        config = {"store": "store", "temporary": "temporary", "max_upload_bytes": 8,
                  "principals": [{"id": "reader", "keyring": "key", "database_env": "DSE_TEST_CONFIG_DSN",
                                  "token_sha256": hashlib.sha256(self.token.encode()).hexdigest(),
                                  "actions": ["read"], "namespaces": ["default"]}]}
        self.config = self.base / "config.json"
        self.config.write_text(json.dumps(config))
        from unittest.mock import patch
        self.enterContext(patch.dict(os.environ, {"DSE_TEST_CONFIG_DSN": "dbname=unused"}))
        self.settings = Settings.load(self.config)
        self.client = self.enterContext(TestClient(create_app(self.settings)))
        self.auth = {"Authorization": "Bearer " + self.token}

    def test_missing_and_invalid_credentials_fail(self):
        for headers in ({}, {"Authorization": "Bearer invalid"}):
            response = self.client.get("/health/ready", headers=headers)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.headers["www-authenticate"], "Bearer")

    def test_reader_cannot_seal_or_commit(self):
        response = self.client.post("/v1/objects", content=b"x",
                                    headers={**self.auth, "Content-Type": "application/octet-stream"})
        self.assertEqual(response.status_code, 403)
        response = self.client.post(f"/v1/objects/{dcf.uuid7()}/versions/{dcf.uuid7()}/commit",
                                    headers={**self.auth, "If-None-Match": "*"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(list(self.settings.store.iterdir()), [])

    def test_config_rejects_unknown_permissions_and_duplicate_credentials(self):
        config = json.loads(self.config.read_text())
        config["principals"][0]["actions"] = ["admin"]
        self.config.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            Settings.load(self.config)
        config["principals"][0]["actions"] = ["read"]
        config["principals"].append(dict(config["principals"][0], id="duplicate"))
        self.config.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            Settings.load(self.config)

    def test_download_disconnect_removes_plaintext_and_releases_slot(self):
        import asyncio
        from dse.api import TemporaryDownload
        folder = self.settings.temporary / "disconnect"
        folder.mkdir()
        content = folder / "content"
        content.write_bytes(b"private")
        released = []
        response = TemporaryDownload(content, folder, lambda: released.append(True))

        async def broken_send(message):
            raise RuntimeError("connection closed")

        async def receive():
            return {"type": "http.disconnect"}

        with self.assertRaisesRegex(RuntimeError, "connection closed"):
            asyncio.run(response({"type": "http", "method": "GET", "headers": []}, receive, broken_send))
        self.assertFalse(folder.exists())
        self.assertEqual(released, [True])


@unittest.skipUnless(os.environ.get("DSE_TEST_ADMIN_DSN") and importlib.util.find_spec("fastapi")
                     and importlib.util.find_spec("httpx"), "requires PostgreSQL and the api/test extras")
class ApiPostgresTests(unittest.TestCase):
    def test_authenticated_object_workflow(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from fastapi.testclient import TestClient
        from dse.access import Principal
        from dse.api import create_app

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        dsn = os.environ["DSE_TEST_ADMIN_DSN"]
        admin = self.enterContext(psycopg.connect(dsn, autocommit=True))
        principals, tokens = [], []
        for index in range(2):
            path = base / f"key{index}"
            keys.initialize(path)
            keyring = keys.load(path)
            login = "dse_api_" + secrets.token_hex(8)
            password, token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} IN ROLE dse_client").format(
                sql.Identifier(login), sql.Literal(password)))
            self.addCleanup(admin.execute, sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))
            self.addCleanup(admin.execute, "DELETE FROM dse.client_bindings WHERE login=%s", (login,))
            admin.execute("INSERT INTO dse.tenants (id,slug) VALUES (%s,%s)", (keyring.tenant, login))
            admin.execute("INSERT INTO dse.client_bindings VALUES (%s,%s,%s)",
                          (login, keyring.tenant, keyring.signer_id))
            principals.append(Principal(login, hashlib.sha256(token.encode()).hexdigest(), keyring,
                                        make_conninfo(dsn, user=login, password=password),
                                        frozenset({"read", "write"}), frozenset({"default"})))
            tokens.append(token)
        settings = Settings(base / "store", base / "temporary", tuple(principals), max_upload_bytes=16)
        client = self.enterContext(TestClient(create_app(settings)))
        headers = {"Authorization": "Bearer " + tokens[0], "Content-Type": "application/octet-stream"}
        self.assertEqual(client.get("/health/ready", headers=headers).status_code, 200)

        def seal(data=b"first", obj=None):
            if obj is None:
                response = client.post("/v1/objects", content=data, headers=headers)
            else:
                response = client.put("/v1/objects/" + obj, content=data, headers=headers)
            self.assertEqual(response.status_code, 201, response.text)
            return response.json()

        def commit(record, precondition):
            url = f"/v1/objects/{record['object_id']}/versions/{record['version_id']}/commit"
            return client.post(url, headers={**headers, **precondition})

        first = seal()
        obj, ver = first["object_id"], first["version_id"]
        content_url = f"/v1/objects/{obj}/versions/{ver}/content"
        self.assertEqual(client.get(content_url, headers=headers).status_code, 404)
        self.assertEqual(commit(first, {}).status_code, 428)
        self.assertEqual(commit(first, {"If-None-Match": "*"}).status_code, 200)
        self.assertEqual(commit(first, {"If-None-Match": "*"}).json()["ordinal"], 1)
        response = client.get(content_url, headers=headers)
        self.assertEqual(response.content, b"first")
        self.assertEqual(response.headers["etag"], '"' + ver + '"')
        self.assertEqual(list(settings.temporary.iterdir()), [])
        metadata = client.get("/v1/objects/" + obj, headers=headers)
        self.assertEqual(metadata.status_code, 200)
        self.assertNotIn("store_root", metadata.json())
        other = {"Authorization": "Bearer " + tokens[1]}
        self.assertEqual(client.get("/v1/objects/" + obj, headers=other).status_code, 404)
        self.assertEqual(client.get(content_url, headers=other).status_code, 404)
        self.assertEqual(client.post(f"/v1/objects/{obj}/versions/{ver}/commit",
                                    headers={**other, "If-None-Match": "*"}).status_code, 404)
        self.assertEqual(client.post("/v1/objects?namespace=denied", content=b"x",
                                    headers=headers).status_code, 403)
        self.assertEqual(client.post("/v1/objects", content=b"x" * 17, headers=headers).status_code, 413)
        self.assertEqual(client.post("/v1/objects", content=iter([b"x" * 9, b"x" * 8]),
                                    headers=headers).status_code, 413)
        self.assertEqual(client.post("/v1/objects", content=b"x",
                                    headers={**headers, "Content-Type": "text/plain"}).status_code, 415)
        second, third = seal(b"second", obj), seal(b"third", obj)
        self.assertEqual(commit(second, {"If-Match": '"' + ver + '"'}).status_code, 200)
        self.assertEqual(commit(third, {"If-Match": '"' + ver + '"'}).status_code, 412)
        self.assertEqual(commit(first, {"If-None-Match": "*"}).json()["ordinal"], 1)
        directory = settings.store / principals[0].keyring.tenant / ver
        (directory / "chunks/00000000.bin").write_bytes(b"corrupt")
        response = client.get(content_url, headers=headers)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"first", response.content)
        self.assertEqual(list(settings.temporary.iterdir()), [])
        self.check_http_factory(base, settings, principals[0], tokens[0], obj, second["version_id"])

    def check_http_factory(self, base, settings, principal, token, obj, version):
        import threading
        import time
        from urllib.request import Request, urlopen
        from unittest.mock import patch
        import uvicorn

        config = base / "http-config.json"
        config.write_text(json.dumps({
            "store": str(settings.store), "temporary": str(settings.temporary),
            "principals": [{"id": principal.id, "token_sha256": principal.token_sha256,
                            "keyring": "key0", "database_env": "DSE_API_TEST_DSN",
                            "actions": ["read"], "namespaces": ["default"]}]}))
        self.enterContext(patch.dict(os.environ, {"DSE_API_CONFIG": str(config),
                                                 "DSE_API_TEST_DSN": principal.dsn}))
        server = uvicorn.Server(uvicorn.Config("dse.api:create_app", factory=True,
                                               host="127.0.0.1", port=0, log_level="error", access_log=False))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 15
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(server.started, "Uvicorn factory did not start")
            port = server.servers[0].sockets[0].getsockname()[1]
            request = Request(f"http://127.0.0.1:{port}/v1/objects/{obj}/versions/{version}/content",
                              headers={"Authorization": "Bearer " + token})
            with urlopen(request, timeout=15) as response:
                self.assertEqual(response.read(), b"second")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
        finally:
            server.should_exit = True
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive(), "Uvicorn test server did not stop")
