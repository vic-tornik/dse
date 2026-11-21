"""Authenticated local DSE service. Start with uvicorn dse.api:create_app --factory."""
import asyncio
from contextlib import asynccontextmanager
import os
from pathlib import Path
import shutil
import tempfile
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool

from . import capsule, catalog, dcf, operations
from .access import Settings


def create_app(settings=None):
    settings = settings or Settings.load(os.environ["DSE_API_CONFIG"])
    settings.store.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings.temporary.mkdir(mode=0o700, parents=True, exist_ok=True)
    app = FastAPI(title="DSE Local Service", version="0.4.0")
    bearer = HTTPBearer(auto_error=False)
    transfers = asyncio.Semaphore(settings.max_active_transfers)

    @app.middleware("http")
    async def private_responses(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def authenticate(credential: HTTPAuthorizationCredentials | None = Depends(bearer)):
        principal = settings.authenticate(credential.credentials) if credential else None
        if principal is None:
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
        return principal

    def authorize(principal, action, namespace):
        if not principal.allows(action, namespace):
            raise HTTPException(403, "Operation denied")

    def identifier(value):
        try:
            return dcf.identifier(str(value), 7)
        except ValueError as exc:
            raise HTTPException(422, "Expected a UUIDv7 identifier") from exc

    def store_for(principal):
        return settings.store / principal.keyring.tenant

    def expected_parent(if_match, if_none_match):
        if if_match is not None and if_none_match is not None:
            raise HTTPException(400, "Use one precondition header")
        if if_none_match == "*":
            return "none"
        if if_match is not None and len(if_match) == 38 and if_match[0] == if_match[-1] == '"':
            return identifier(if_match[1:-1])
        raise HTTPException(428, 'Supply If-None-Match: * or If-Match: "version-uuid"')

    def candidate(principal, obj, ver):
        if "write" not in principal.actions:
            raise HTTPException(403, "Operation denied")
        try:
            manifest = capsule.verified_manifest(store_for(principal) / ver, ver, principal.keyring, obj)
        except FileNotFoundError as exc:
            raise HTTPException(404, "Sealed version unavailable") from exc
        authorize(principal, "write", manifest["namespace"])
        return manifest

    def lookup(principal, obj, version=None):
        record = catalog.describe(principal.keyring, obj, version, dsn=principal.dsn)
        if record is None:
            raise HTTPException(404, "Object version unavailable")
        return record

    @asynccontextmanager
    async def transfer():
        if transfers.locked():
            raise HTTPException(429, "Transfer limit reached", headers={"Retry-After": "1"})
        async with transfers:
            yield

    @app.exception_handler(ValueError)
    async def catalog_error(request, exc):
        return JSONResponse({"detail": "Storage operation failed"}, status_code=503)

    @app.exception_handler(OSError)
    async def storage_error(request, exc):
        return JSONResponse({"detail": "Storage unavailable"}, status_code=503)

    @app.get("/health/live")
    def live():
        return {"status": "live"}

    @app.get("/health/ready")
    def ready(principal=Depends(authenticate)):
        catalog.head(principal.keyring, dcf.uuid7(), dsn=principal.dsn)
        return {"status": "ready"}

    async def seal_upload(request, principal, namespace, obj=None):
        authorize(principal, "write", namespace)
        if request.headers.get("content-type", "").split(";")[0].lower() != "application/octet-stream":
            raise HTTPException(415, "Send application/octet-stream")
        length = request.headers.get("content-length")
        if length is not None:
            try:
                size = int(length)
            except ValueError as exc:
                raise HTTPException(400, "Invalid content length") from exc
            if size < 0 or size > settings.max_upload_bytes:
                raise HTTPException(413, "Upload exceeds byte limit")
        async with transfer():
            with tempfile.TemporaryDirectory(dir=settings.temporary) as folder:
                source = Path(folder) / "upload"
                count = 0
                with source.open("xb") as stream:
                    async for block in request.stream():
                        count += len(block)
                        if count > settings.max_upload_bytes:
                            raise HTTPException(413, "Upload exceeds byte limit")
                        await run_in_threadpool(stream.write, block)
                result = await run_in_threadpool(capsule.seal, source, store_for(principal),
                                                 principal.keyring, namespace, obj)
        return JSONResponse({**result, "state": "SEALED"}, status_code=201)

    @app.post("/v1/objects", summary="Seal a new object without publishing it",
              openapi_extra={"requestBody": {"required": True, "content": {
                  "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}})
    async def create(request: Request, namespace: str = "default", principal=Depends(authenticate)):
        return await seal_upload(request, principal, namespace)

    @app.put("/v1/objects/{object_id}", summary="Seal a candidate version without publishing it",
             openapi_extra={"requestBody": {"required": True, "content": {
                 "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}})
    async def update(object_id: UUID, request: Request, principal=Depends(authenticate)):
        obj = identifier(object_id)
        if "write" not in principal.actions:
            raise HTTPException(403, "Operation denied")
        record = await run_in_threadpool(lookup, principal, obj)
        return await seal_upload(request, principal, record["manifest"]["namespace"], obj)

    @app.post("/v1/objects/{object_id}/versions/{version_id}/commit")
    async def commit(object_id: UUID, version_id: UUID,
                     if_match: str | None = Header(default=None),
                     if_none_match: str | None = Header(default=None), principal=Depends(authenticate)):
        obj, ver = identifier(object_id), identifier(version_id)
        if "write" not in principal.actions:
            raise HTTPException(403, "Operation denied")
        expected = expected_parent(if_match, if_none_match)
        async with transfer():
            await run_in_threadpool(candidate, principal, obj, ver)
            try:
                receipt = await run_in_threadpool(catalog.commit, store_for(principal),
                                                  principal.keyring, obj, ver, expected, dsn=principal.dsn)
            except catalog.Conflict as exc:
                raise HTTPException(412, "Version precondition failed") from exc
        return JSONResponse({**receipt, "state": "COMMITTED"}, headers={"ETag": '"' + ver + '"'})

    @app.post("/v1/objects/{object_id}/versions/{version_id}/commit-operations", status_code=202)
    async def enqueue_commit(object_id: UUID, version_id: UUID,
                             idempotency_key: str = Header(),
                             if_match: str | None = Header(default=None),
                             if_none_match: str | None = Header(default=None), principal=Depends(authenticate)):
        obj, ver = identifier(object_id), identifier(version_id)
        if "write" not in principal.actions:
            raise HTTPException(403, "Operation denied")
        key = identifier(idempotency_key)
        expected = expected_parent(if_match, if_none_match)
        async with transfer():
            manifest = await run_in_threadpool(candidate, principal, obj, ver)
            try:
                operation_id = await run_in_threadpool(operations.enqueue, principal, key, manifest, expected)
            except catalog.IdempotencyConflict as exc:
                raise HTTPException(409, "Idempotency key reused with different inputs") from exc
        return JSONResponse({"operation_id": operation_id}, status_code=202,
                            headers={"Location": "/v1/operations/" + operation_id})

    @app.get("/v1/operations/{operation_id}")
    def operation_status(operation_id: UUID, principal=Depends(authenticate)):
        result = operations.get(principal, identifier(operation_id))
        if result is None:
            raise HTTPException(404, "Operation unavailable")
        if not (principal.allows("read", result["namespace"]) or principal.allows("write", result["namespace"])):
            raise HTTPException(403, "Operation denied")
        return {"operation_id": result["id"], "state": result["state"], "attempts": result["attempts"],
                "error_code": result["error_code"], "result": result["result"]}

    def metadata(principal, obj, version=None):
        if "read" not in principal.actions:
            raise HTTPException(403, "Operation denied")
        record = lookup(principal, obj, version)
        authorize(principal, "read", record["manifest"]["namespace"])
        return record

    @app.get("/v1/objects/{object_id}")
    def describe(object_id: UUID, principal=Depends(authenticate)):
        record = metadata(principal, identifier(object_id))
        manifest = record["manifest"]
        return JSONResponse({"object_id": manifest["object_id"], "version_id": manifest["version_id"],
                             "namespace": manifest["namespace"], "bytes": int(manifest["media"]["logical_size"]),
                             "ordinal": record["ordinal"]}, headers={"ETag": '"' + manifest["version_id"] + '"'})

    @app.get("/v1/objects/{object_id}/versions/{version_id}/content")
    async def content(object_id: UUID, version_id: UUID, principal=Depends(authenticate)):
        obj, ver = identifier(object_id), identifier(version_id)
        if transfers.locked():
            raise HTTPException(429, "Transfer limit reached", headers={"Retry-After": "1"})
        await transfers.acquire()
        folder = None
        try:
            record = await run_in_threadpool(metadata, principal, obj, ver)
            store = store_for(principal)
            if Path(record["store_root"]).resolve() != store.resolve():
                raise HTTPException(503, "Placement unavailable on this server")
            folder = Path(tempfile.mkdtemp(dir=settings.temporary))
            destination = folder / "content"
            local = await run_in_threadpool(capsule.verified_manifest, store / ver, ver, principal.keyring, obj)
            if dcf.digest(dcf.canonical(local)).hex() != record["manifest_digest"]:
                raise dcf.InvalidData("Catalog manifest mismatch")
            await run_in_threadpool(capsule.recover, store, principal.keyring, obj, ver, destination)
        except BaseException:
            if folder is not None:
                shutil.rmtree(folder)
            transfers.release()
            raise
        return TemporaryDownload(destination, folder, transfers.release,
                                 headers={"ETag": '"' + ver + '"', "Cache-Control": "no-store",
                                          "X-Content-Type-Options": "nosniff"})

    return app


class TemporaryDownload(FileResponse):
    def __init__(self, path, directory, release, **kwargs):
        super().__init__(path, media_type="application/octet-stream", filename="content.bin", **kwargs)
        self.directory = directory
        self.release = release

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                shutil.rmtree(self.directory)
            finally:
                self.release()
