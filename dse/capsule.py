"""Seal and open single-tenant development capsules using trusted local keys."""
import os
from pathlib import Path
import re
import shutil
import tempfile

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap, InvalidUnwrap

from . import dcf
from .local import LocalChunks, sync_directory, write_file


def transform(version):
    return {
        "chunking": {"scheme": "fixed-v1", "plaintext_chunk_bytes": dcf.CHUNK_BYTES},
        "compression": {"algorithm": "none"},
        "encryption": {"suite": "AES-256-GCM", "key_ref": "dek-wrap:" + version,
                       "nonce_scheme": "dse-gcm-v1", "aad_profile": "dcf-aad-v1"},
    }


def seal(source: Path, store: Path, keys, namespace="default", object_id=None):
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", namespace):
        raise ValueError("Invalid namespace")
    obj = dcf.identifier(object_id, 7) if object_id is not None else dcf.uuid7()
    version = dcf.uuid7()
    dek = AESGCM.generate_key(bit_length=256)
    cipher = AESGCM(dek)
    prefix = os.urandom(4)
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".stage-", dir=store))
    try:
        chunks_dir = staging / "chunks"
        chunks_dir.mkdir()
        chunks = LocalChunks(chunks_dir)
        rows, leaves = [], []
        offset = 0
        with source.open("rb") as stream:
            while block := stream.read(dcf.CHUNK_BYTES):
                i = len(rows)
                if i >= dcf.MAX_CHUNKS:
                    raise ValueError("Input exceeds the local profile limit")
                nonce = prefix + i.to_bytes(8, "big")
                body = cipher.encrypt(nonce, block, dcf.aad(keys.tenant, obj, version, i, len(block)))
                sha = chunks.put(i, body)
                item_leaf = dcf.leaf(i, sha)
                leaves.append(item_leaf)
                rows.append({"index": i, "logical_offset": str(offset), "plaintext_bytes": len(block),
                             "stored_bytes": len(body), "nonce": dcf.enc(nonce),
                             "ciphertext_sha256": dcf.enc(sha), "ciphertext_leaf": dcf.enc(item_leaf)})
                offset += len(block)
        wrapped = aes_key_wrap(keys.kek, dek)
        manifest = {
            "dcf": "1.0", "tenant_ref": keys.tenant, "namespace": namespace, "object_id": obj,
            "version_id": version, "created_at": dcf.now(), "media": {
                "content_type": "application/octet-stream", "logical_size": str(offset)},
            "transform": transform(version), "chunks": rows, "integrity": {
                "hash_algorithm": "SHA-256", "ciphertext_merkle_root": dcf.enc(dcf.merkle(leaves))},
            "extensions": {}, "critical": [],
        }
        signature = keys.signer.sign(dcf.signed_bytes(manifest))
        manifest["signatures"] = [{"suite": "Ed25519", "key_id": keys.signer_id,
                                   "signed_at": manifest["created_at"], "signature": dcf.enc(signature)}]
        write_file(staging / "manifest.json", dcf.canonical(manifest))
        write_file(staging / "envelope.json", dcf.canonical({"wrapped_dek": dcf.enc(wrapped)}))
        sync_directory(chunks_dir)
        sync_directory(staging)
        staging.rename(store / version)
        sync_directory(store)
        return {"object_id": obj, "version_id": version, "bytes": offset, "chunks": len(rows)}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def verified_manifest(directory, version, keys, object_id):
    manifest = dcf.read_json(directory / "manifest.json", dcf.MAX_MANIFEST)
    signatures = manifest["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise dcf.InvalidData("The local profile requires one trusted signature")
    sig = signatures[0]
    if sig["suite"] != "Ed25519" or sig["key_id"] != keys.signer_id:
        raise dcf.InvalidData("Unknown signing key or suite")
    try:
        keys.signer.public_key().verify(dcf.dec(sig["signature"], 64), dcf.signed_bytes(manifest))
    except InvalidSignature as exc:
        raise dcf.InvalidData("Manifest signature verification failed") from exc
    if (manifest["dcf"] != "1.0" or manifest["tenant_ref"] != keys.tenant
            or manifest["version_id"] != version or manifest["object_id"] != object_id
            or manifest["critical"] != [] or manifest["transform"] != transform(version)
            or manifest["integrity"]["hash_algorithm"] != "SHA-256"):
        raise dcf.InvalidData("Manifest identity or storage profile mismatch")
    rows = manifest["chunks"]
    if not isinstance(rows, list) or len(rows) > dcf.MAX_CHUNKS:
        raise dcf.InvalidData("Invalid chunk count")
    return manifest


def _open_version(store, keys, object_id, version):
    directory = store / dcf.identifier(version, 7)
    obj = dcf.identifier(object_id, 7)
    manifest = verified_manifest(directory, version, keys, obj)
    envelope = dcf.read_json(directory / "envelope.json", 1024)
    wrapped = dcf.dec(envelope["wrapped_dek"], 40)
    try:
        cipher = AESGCM(aes_key_unwrap(keys.kek, wrapped))
    except InvalidUnwrap as exc:
        raise dcf.InvalidData("Invalid wrapped data key") from exc
    return directory, manifest, wrapped, cipher


def catalog_material(store, keys, object_id, version):
    directory, manifest, wrapped, cipher = _open_version(store, keys, object_id, version)
    _read_chunks(directory, manifest, cipher, None)
    return manifest, wrapped


def recover(store, keys, object_id, version, destination=None):
    directory, manifest, _, cipher = _open_version(store, keys, object_id, version)

    output = None
    try:
        if destination is not None:
            # Same-volume temporary output; publish exclusively after full verification.
            output = tempfile.NamedTemporaryFile(dir=destination.parent, delete=False)
        count = _read_chunks(directory, manifest, cipher, output)
        if output:
            output.flush()
            os.fsync(output.fileno())
            output.close()
            if os.name == "nt":
                os.rename(output.name, destination)  # Windows rejects an existing target.
            else:
                os.link(output.name, destination)
            sync_directory(destination.parent)
        return {"object_id": object_id, "version_id": version, "bytes": count, "chunks": len(manifest["chunks"])}
    finally:
        if output:
            output.close()
            Path(output.name).unlink(missing_ok=True)


def _read_chunks(directory, manifest, cipher, output):
    leaves, offset, prefix = [], 0, None
    chunks = LocalChunks(directory / "chunks")
    rows = manifest["chunks"]
    for i, row in enumerate(rows):
        size = row["plaintext_bytes"]
        nonce = dcf.dec(row["nonce"], 12)
        if (type(size) is not int or not 0 < size <= dcf.CHUNK_BYTES
                or (i + 1 < len(rows) and size != dcf.CHUNK_BYTES)
                or row["index"] != i or row["logical_offset"] != str(offset)
                or row["stored_bytes"] != size + 16 or nonce[4:] != i.to_bytes(8, "big")
                or (prefix is not None and nonce[:4] != prefix)):
            raise dcf.InvalidData(f"Invalid chunk metadata at index {i}")
        prefix = nonce[:4]
        sha = dcf.dec(row["ciphertext_sha256"], 32)
        item_leaf = dcf.leaf(i, sha)
        if item_leaf != dcf.dec(row["ciphertext_leaf"], 32):
            raise dcf.InvalidData("Invalid ciphertext leaf")
        leaves.append(item_leaf)
        body = chunks.get(i, size + 16, sha)
        aad = dcf.aad(manifest["tenant_ref"], manifest["object_id"], manifest["version_id"], i, size)
        try:
            block = cipher.decrypt(nonce, body, aad)
        except InvalidTag as exc:
            raise dcf.InvalidData(f"Chunk authentication failed at index {i}") from exc
        if output:
            output.write(block)
        offset += len(block)
    if (dcf.merkle(leaves) != dcf.dec(manifest["integrity"]["ciphertext_merkle_root"], 32)
            or manifest["media"]["logical_size"] != str(offset)):
        raise dcf.InvalidData("Manifest root or total size mismatch")
    return offset
