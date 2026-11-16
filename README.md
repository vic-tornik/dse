# DSE Foundation 0.2.0

DSE seals a binary file into an encrypted local capsule. The optional PostgreSQL catalog (Atlas) records which version is current. A local operator can restore any sealed version by ID. Existing 0.1.0 capsules can be committed directly.

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

Use Docker Desktop in Linux-container mode. On a fresh volume Compose applies migrations 001 and 002. It binds PostgreSQL to loopback port 55432. Set DSE_PG_PORT before startup to select another port and use that port in PGPORT below.

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
    & $python -m unittest discover -s tests -p test_postgres.py -v
} finally {
    Remove-Item Env:DSE_TEST_ADMIN_DSN, Env:PGPASSWORD -ErrorAction SilentlyContinue
}
docker compose stop
```

The test disconnects a writer before COMMIT, races two CLI writers against the same parent, replays an older request, and checks the committed row counts and final head. Running the default suite without DSE_TEST_ADMIN_DSN reports this test as skipped.

## Storage and format

- `dse/dcf.py` defines UUIDv7 IDs, canonical serialization, SHA-256 Merkle computation and chunk authentication data. The local canonical profile permits ASCII member names, Unicode string values, arrays, objects and safe integers. The machine-readable profile is in `schemas/dcf-1-local.schema.json`.
- `dse/capsule.py` processes 4 MiB plaintext chunks under a fresh per-version AES-256-GCM key. A nonce combines a fresh 4-byte prefix and an 8-byte big-endian index. AAD binds the tenant, logical object, version, index, plaintext size and compression profile. All UUIDs use their 16-byte network representation. This milestone uses the uncompressed profile.
- `dse/local.py` writes ciphertext and rereads it to confirm the SHA-256 digest. Each Merkle leaf hashes byte 0x00, the 8-byte index and the binary ciphertext digest. Each parent hashes byte 0x01 and its two children. An odd last node carries to the next level. The empty root hashes zero bytes.
- Each version directory contains a signed manifest, a wrapped-key envelope, and ciphertext chunks. The manifest embeds no storage paths. The development envelope uses AES key wrap. A keyring is the local root of trust. The default limit is 4,096 chunks (16 GiB); tests cover up to 8 MiB plus 13 bytes.
- Sealing publishes a completed staging directory by same-volume rename. Restore writes plaintext to a temporary file in the destination directory, verifies all chunks, and publishes only upon success. Use a private restore directory. An abrupt process kill can leave a staging directory or a temporary plaintext file. The current release has no startup reconciliation. POSIX restore requires a filesystem supporting hard links. Directory fsync runs on POSIX; Windows power-loss durability has not been qualified.

The network API, managed key service, reconciliation of uncommitted capsules, and external storage adapters remain future milestones.
