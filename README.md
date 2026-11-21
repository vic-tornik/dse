# DSE Foundation 0.4.0

DSE seals a binary file into an encrypted local capsule. The optional PostgreSQL catalog (Atlas) records which version is current. A local operator can restore any sealed version by ID. Existing 0.1.0 capsules can be committed directly.

Version 0.3.0 adds a FastAPI service with scoped application credentials, authenticated uploads, conditional version commits, metadata reads, and verified downloads.

## Durable commit operations

Version 0.4.0 adds a PostgreSQL commit queue, expiring worker leases, bounded retries, operation status and a transactional event outbox. Existing 0.3.x databases need migration 004 once. Fresh Compose volumes apply migrations 001 through 004.

```powershell
docker compose exec -T postgres psql -X -v ON_ERROR_STOP=1 -U dse_owner -d dse -f /docker-entrypoint-initdb.d/004_operations.sql
```

After sealing an upload through the API, enqueue its commit using a UUIDv7 Idempotency-Key and the original version precondition. These variables use the upload and authentication examples in the API section below.

```powershell
$jobHeaders = $auth.Clone()
$jobHeaders['Idempotency-Key'] = & $python -c "from dse.dcf import uuid7; print(uuid7())"
$jobHeaders['If-None-Match'] = '*'
$operation = Invoke-RestMethod "$versionUrl/commit-operations" -Method Post -Headers $jobHeaders
$status = Invoke-RestMethod "$base/v1/operations/$($operation.operation_id)" -Headers $auth
$status
```

Keep the Idempotency-Key with the sealed object/version IDs and precondition. Repeating an identical enqueue returns the same operation ID. Reusing that key with different inputs returns HTTP 409. For an update, replace If-None-Match with If-Match containing the quoted parent version UUID.

In a separate terminal, configure the same DSE_API_CONFIG, PostgreSQL connection environment and keyrings as the API, then start the worker.

```powershell
& $python -m dse.worker
# Alternatively, process at most one eligible operation and exit.
& $python -m dse.worker --once
```

Poll GET /v1/operations/{operation_id} until state is SUCCEEDED or FAILED. The response includes attempts, a stable error_code and, on success, the object/version/ordinal result. An operation belongs to its submitting principal. Another application identity cannot query it, including another identity in the same tenant.

Workers claim operations with PostgreSQL row locking. The default lease is 300 seconds, configurable with --lease-seconds between 5 and 3600. A stopped worker's operation becomes claimable after that lease expires. The current lease token is checked again inside the publication transaction. A stale worker cannot publish or change another worker's result.

Version publication, operation success and the version.committed outbox event commit together. If the connection drops before COMMIT, they roll back together. If the transaction committed and the response was lost, the persisted operation result is available when the client polls. Independent workers can claim different jobs. Each worker handles one job at a time and cycles through the configured principals.

Transient storage/database failures retry with exponential backoff and a maximum of five claims. Permanent errors include POLICY_DENIED, VERSION_CONFLICT, CAPSULE_MISSING and INTEGRITY_FAILURE. An exhausted operation becomes FAILED with RETRY_EXHAUSTED. Failed operations retain their records. Submitting a new operation key creates a new attempt at the requested action.

The worker reloads configuration between polling passes and checks current write/namespace permission before publication. Keep API and worker permissions synchronized when revoking credentials. Removing an identity entirely leaves its queued work unclaimed until an operator restores or handles that identity.

The outbox records new version commits after migration 004, including synchronous CLI/API commits. Historical versions receive no backfill. External event delivery and consumer checkpoints are a later milestone.

Durability here covers committing an already sealed local capsule. Raw upload reception, orphan cleanup, replica repair and a single-request resumable upload remain further work. Keep workers on the same storage host with the same absolute ciphertext path as the API. Set the lease long enough for full capsule verification on that host.

## Run the authenticated local API

Complete the keyring and PostgreSQL provisioning steps below first. A fresh database applies migrations 001 through 004. For an existing database, apply each missing migration once in numerical order.

```powershell
$python = '.\.venv\Scripts\python.exe'
& $python -m pip install -e ".[api,test]"
docker compose exec -T postgres psql -X -v ON_ERROR_STOP=1 -U dse_owner -d dse -f /docker-entrypoint-initdb.d/003_reads.sql
```

Skip the migration command when a fresh volume already applied 003. Use your existing provisioned keyring and PostgreSQL login. Generate a random application token and save its digest in the server configuration.

```powershell
$credential = & $python -c "import secrets,hashlib,json; t=secrets.token_urlsafe(32); print(json.dumps(dict(token=t,token_sha256=hashlib.sha256(t.encode()).hexdigest())))" | ConvertFrom-Json
$apiConfig = @{
    store = 'api-objects'
    temporary = 'api-temporary'
    max_upload_bytes = 67108864
    max_active_transfers = 2
    principals = @(@{
        id = 'local-app'
        token_sha256 = $credential.token_sha256
        keyring = 'developer.keys'
        database_env = 'DSE_LOCAL_DSN'
        actions = @('read', 'write')
        namespaces = @('default')
    })
}
$apiConfig | ConvertTo-Json -Depth 5 | Set-Content .dse-demo/api.json -Encoding utf8NoBOM
$env:DSE_LOCAL_DSN = 'host=127.0.0.1 port=55432 dbname=dse user=dse_local'
$env:DSE_API_CONFIG = (Resolve-Path .dse-demo/api.json).Path
# Supply this login's password using PGPASSWORD or a protected libpq password file.
& $python -m uvicorn dse.api:create_app --factory --host 127.0.0.1 --port 8000 --workers 1
```

Use PowerShell 7 for the utf8NoBOM encoding above. Paths in api.json resolve relative to the configuration file. Preserve the token in a password manager for the client. The server stores its SHA-256 digest. Each principal has explicit actions and namespaces. Missing permissions deny access. Removing a credential from the configuration and restarting the service revokes it. Give every additional tenant its own keyring and provisioned PostgreSQL login, referenced through its own environment variable. Readiness authenticates and validates the configured database binding.

Run requests from another PowerShell session with the application token available as DSE_API_TOKEN.

```powershell
$base = 'http://127.0.0.1:8000'
$auth = @{ Authorization = "Bearer $env:DSE_API_TOKEN" }
$upload = Invoke-RestMethod "$base/v1/objects?namespace=default" -Method Post -Headers $auth -ContentType 'application/octet-stream' -InFile README.md
$versionUrl = "$base/v1/objects/$($upload.object_id)/versions/$($upload.version_id)"
$commitHeaders = $auth.Clone()
$commitHeaders['If-None-Match'] = '*'
$receipt = Invoke-RestMethod "$versionUrl/commit" -Method Post -Headers $commitHeaders
$meta = Invoke-RestMethod "$base/v1/objects/$($upload.object_id)" -Headers $auth
Invoke-WebRequest "$versionUrl/content" -Headers $auth -OutFile .dse-demo/api-restored.md
(Get-FileHash README.md).Hash -eq (Get-FileHash .dse-demo/api-restored.md).Hash
```

The upload response has state SEALED. Persist its object_id and version_id before committing. The synchronous commit response has state COMMITTED and a strong ETag containing the version UUID. Repeat the identical commit and precondition after a lost response to receive the original ordinal. A new POST upload creates another sealed object. Raw upload retries and orphan reconciliation are future milestones.

For an update, PUT raw bytes to /v1/objects/{object_id}. Then commit the returned candidate using If-Match set to the previous quoted version UUID. Two candidates using the same parent produce one successful commit and one HTTP 412. A missing precondition returns 428. A download can only resolve a committed version through the authenticated tenant's catalog binding. Ciphertext and the signed manifest are verified before serving plaintext. Corruption returns a storage error.

| Method | Path | Result |
|---|---|---|
| POST | /v1/objects?namespace=default | Seal a new object |
| PUT | /v1/objects/{object_id} | Seal an update candidate |
| POST | /v1/objects/{object_id}/versions/{version_id}/commit | Conditionally publish a sealed version |
| POST | /v1/objects/{object_id}/versions/{version_id}/commit-operations | Queue an idempotent durable commit |
| GET | /v1/operations/{operation_id} | Poll an owned operation |
| GET | /v1/objects/{object_id} | Current metadata and ETag |
| GET | /v1/objects/{object_id}/versions/{version_id}/content | Verified content |
| GET | /health/live | Public liveness |
| GET | /health/ready | Authenticated database binding check |
| GET | /docs | OpenAPI documentation |

The service uses a new store with tenant subdirectories. Keep its private temporary directory on encrypted local storage with restrictive OS permissions. Uploads and downloads spool plaintext there and clean up after normal completion or handled failures. Abrupt termination can leave temporary files. Windows directories inherit ACLs. Configure the parent directory's ACLs for the service account before use.

This milestone uses bootstrap application credentials and server-held development keyrings. OIDC, OPA, capability tickets, managed keys, background reconciliation, and the full single-request upload contract remain on the roadmap. Run one API worker so the configured transfer limit applies to the instance. Keep the loopback binding for local use. Remote access requires HTTPS and proxy request-body, timeout, and connection limits. Downloads verify a complete version before serving it, so latency and temporary disk use grow with object size.

## Run the first round trip on Windows

Use Python 3.12 or newer. Run the following in PowerShell from the directory containing this README. Install Node.js 22 or newer to run the independent manifest test. Docker is optional for the capsule workflow.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
$python = '.\.venv\Scripts\python.exe'
New-Item -ItemType Directory -Path .dse-demo -Force | Out-Null
$key = '.dse-demo\developer.keys'
$store = '.dse-demo\objects'
& $python -m dse --keyring $key init
$sealed = & $python -m dse --keyring $key seal README.md --store $store | ConvertFrom-Json
& $python -m dse --keyring $key verify --store $store --object $sealed.object_id --version $sealed.version_id
& $python -m dse --keyring $key restore .dse-demo\restored.md --store $store --object $sealed.object_id --version $sealed.version_id
(Get-FileHash README.md).Hash -eq (Get-FileHash .dse-demo\restored.md).Hash
```

The last line should print `True`. Run `init` once per keyring. To seal a second version, supply the existing ID with `seal <file> --store $store --object $sealed.object_id`. Save both returned IDs. Restore takes an explicit version and a fresh destination filename. The keyring contains the signing key and the key that unwraps version encryption keys. Use a private OS account directory, keep the keys outside the ciphertext store, and make a separate protected backup before relying on recovery. Losing the keyring makes encrypted files unrecoverable. Windows uses inherited directory ACLs.

## Verify development changes

```powershell
& $python -m unittest discover -s tests -v
```

Tests exercise fresh CLI processes, zero-length and multi-chunk inputs, immutable versions, signature checks, wrong keys, corruption, failure before publication, and preserving an existing output. Node independently serializes the unsigned manifest and verifies the Ed25519 signature. With Node missing, unittest reports that check as skipped.

## Start the PostgreSQL development catalog

Use Docker Desktop in Linux-container mode. On a fresh volume Compose applies migrations 001 through 004. It binds PostgreSQL to loopback port 55432. Set DSE_PG_PORT before startup to select another port and use that port in PGPORT below.

```powershell
$env:DSE_PG_PASSWORD = [System.Net.NetworkCredential]::new('', (Read-Host 'Development database password' -AsSecureString)).Password
docker compose up -d --wait postgres
docker compose exec -T postgres psql -X -v ON_ERROR_STOP=1 -U dse_owner -d dse -f /checks/catalog.sql
```

For an existing 0.1.0 volume, use the original DSE_PG_PASSWORD, then apply migration 002 **once** after startup. PostgreSQL only runs its initialization scripts when the volume is new.

```powershell
docker compose exec -T postgres psql -X -v ON_ERROR_STOP=1 -U dse_owner -d dse -f /docker-entrypoint-initdb.d/002_commit.sql
```

The catalog check above rolls back its changes. It exercises read filtering, cross-tenant write rejection, and historical version privileges.

## Commit a sealed version to Atlas

Run the local round trip above first, or use your existing keyring, store and IDs. Install the database driver. Provision a dedicated PostgreSQL login, binding it to the keyring's public tenant and signer IDs. Run the provisioning script once per new login. The password prompt sets its password without placing it in SQL history.

```powershell
& $python -m pip install -e ".[catalog]"
$identity = & $python -m dse --keyring $key identity | ConvertFrom-Json
docker compose exec -T postgres psql -X -U dse_owner -d dse -v login=dse_local -v "tenant=$($identity.tenant)" -v "signer=$($identity.signer_id)" -f /checks/provision_client.psql
docker compose exec postgres psql -X -U dse_owner -d dse -c '\password dse_local'
$env:PGHOST = '127.0.0.1'
$env:PGPORT = '55432'
$env:PGDATABASE = 'dse'
$env:PGUSER = 'dse_local'
$env:PGPASSWORD = [System.Net.NetworkCredential]::new('', (Read-Host 'dse_local password' -AsSecureString)).Password
$target = @('--store', $store, '--object', $sealed.object_id, '--version', $sealed.version_id)
& $python -m dse --keyring $key commit @target --expect none
& $python -m dse --keyring $key head --object $sealed.object_id
```

`commit` verifies the local manifest, wrapped key, and ciphertext before opening the database transaction. The first commit returns ordinal 1. For an update, read the current head, seal the edited file with the same object ID and namespace, then commit the new version with the observed head as `--expect`. A stale writer exits with code 3. Inspect the winning version before deciding whether to resubmit your own change.

Keep the seal result before starting a commit. After interruption, repeat the **same** commit command with the original parent and store. An exact replay returns the original ordinal even after a later update. One transaction writes the version, commit event and local placement, then advances the head. Losing candidates stay on disk and can still be restored by ID. If sealing stopped before the CLI printed the IDs, a fully published version directory contains them in its manifest. A directory starting with `.stage-` is incomplete.

This release assumes one trusted storage host and a stable absolute store path. PostgreSQL authenticates the login, binds it to a tenant, and allows the client role to execute only the catalog functions. The trusted CLI verifies capsule signatures and bytes. A holder of the database credentials can invoke the functions directly and supply its own metadata for that tenant. Restrict those credentials to the operator. Retire its binding before dropping or reusing a login name. Back up both the store and the keyring separately from the catalog.

## Run PostgreSQL acceptance tests

Use a disposable, migrated database and its provisioning administrator. The test creates a temporary login and a uniquely named tenant, then retains the test tenant and its committed records for inspection. These settings use the Compose instance above.

```powershell
$env:DSE_TEST_ADMIN_DSN = "host=127.0.0.1 port=55432 dbname=dse user=dse_owner"
$env:PGPASSWORD = $env:DSE_PG_PASSWORD
try {
    & $python -m unittest discover -s tests -v
} finally {
    Remove-Item Env:DSE_TEST_ADMIN_DSN, Env:PGPASSWORD -ErrorAction SilentlyContinue
}
docker compose stop
```

The tests disconnect a writer before COMMIT, race two CLI writers against the same parent, replay an older request, and check the committed row counts and final head. With the api/test extras installed, they also exercise authenticated API transfers, namespace permissions, cross-tenant denial, upload limits and corruption handling against PostgreSQL. Running the default suite without DSE_TEST_ADMIN_DSN skips the live database tests.

Version 0.2.1 was verified on Windows against an isolated PostgreSQL 18.1 instance. Both migrations and the catalog isolation SQL completed successfully. The full 16-test suite completed with the live acceptance test enabled. This verification used portable PostgreSQL. The Compose configuration uses PostgreSQL 18.7 and its container execution remains unverified here.

Version 0.3.0 passed all 21 tests on Windows with PostgreSQL 18.1, FastAPI 0.165.0, Starlette 1.10.0 and Uvicorn 0.54.0. This included migration 003, the existing CLI concurrency/retry checks, the authenticated API workflow against real PostgreSQL, and a download through a Uvicorn server started from the environment-configured app factory. The API suite also checks cross-tenant denial, read-only permissions, namespace denial, streamed upload limits, corruption, stale commits and plaintext cleanup after a failed response send. Docker Compose configuration validated, and container execution is pending.

Version 0.4.0 passed all 25 tests against PostgreSQL 18.1 on Windows after applying migration 004 to the existing 0.3.0 catalog. The new cases cover durable request replay after recreating the API, execution through the worker CLI, competing lease claims, transient retry scheduling, permission revocation, corruption, retry exhaustion, stale-worker fencing, and rollback of a completion transaction before COMMIT. Recovery tests check that the outbox contains exactly one event for the recovered version. Lease expiry is advanced through the disposable test administrator to keep the suite fast.

The live test removes its temporary login binding before dropping the login. Its uniquely named tenant and committed records remain available for inspection in the disposable test database.

## Storage and format

- `dse/dcf.py` defines UUIDv7 IDs, canonical serialization, SHA-256 Merkle computation and chunk authentication data. The local canonical profile permits ASCII member names, Unicode string values, arrays, objects and safe integers. The machine-readable profile is in `schemas/dcf-1-local.schema.json`.
- `dse/capsule.py` processes 4 MiB plaintext chunks under a fresh per-version AES-256-GCM key. A nonce combines a fresh 4-byte prefix and an 8-byte big-endian index. AAD binds the tenant, logical object, version, index, plaintext size and compression profile. All UUIDs use their 16-byte network representation. This milestone uses the uncompressed profile.
- `dse/local.py` writes ciphertext and rereads it to confirm the SHA-256 digest. Each Merkle leaf hashes byte 0x00, the 8-byte index and the binary ciphertext digest. Each parent hashes byte 0x01 and its two children. An odd last node carries to the next level. The empty root hashes zero bytes.
- Each version directory contains a signed manifest, a wrapped-key envelope, and ciphertext chunks. The manifest embeds no storage paths. The development envelope uses AES key wrap. A keyring is the local root of trust. The default limit is 4,096 chunks (16 GiB); tests cover up to 8 MiB plus 13 bytes.
- Sealing publishes a completed staging directory by same-volume rename. Restore writes plaintext to a temporary file in the destination directory, verifies all chunks, and publishes only upon success. Use a private restore directory. An abrupt process kill can leave a staging directory or a temporary plaintext file. The current release has no startup reconciliation. POSIX restore requires a filesystem supporting hard links. Directory fsync runs on POSIX; Windows power-loss durability has not been qualified.

The full API contract, managed key service, reconciliation of uncommitted capsules, and external storage adapters are future milestones.
