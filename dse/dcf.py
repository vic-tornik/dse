"""DCF/1 local profile. The signed vocabulary uses ASCII keys and safe integers."""
import base64
import binascii
import hashlib
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

CHUNK_BYTES = 4 * 1024 * 1024
MAX_CHUNKS = 4096
MAX_MANIFEST = 4 * 1024 * 1024
DOMAIN = b"DSE-DCF/1\x00"


class InvalidData(ValueError):
    pass


def uuid7():
    bits = int.from_bytes(os.urandom(10), "big")
    value = ((time.time_ns() // 1_000_000) << 80 | 7 << 76 |
             ((bits >> 62) & 0xfff) << 64 | 2 << 62 | (bits & ((1 << 62) - 1)))
    return str(uuid.UUID(int=value))


def identifier(value, version=None):
    parsed = uuid.UUID(value)
    if str(parsed) != value or (version and parsed.version != version):
        raise InvalidData("Invalid identifier")
    return value


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical(value):
    # ASCII field names, Unicode scalar strings and safe integers are the JCS
    # subset used by this profile. No float formatting or UTF-16 key sorting needed.
    def check(node):
        if isinstance(node, dict):
            for key, child in node.items():
                if not key.isascii():
                    raise InvalidData("Unsupported non-ASCII field name")
                check(child)
        elif isinstance(node, list):
            for child in node:
                check(child)
        elif type(node) is int and abs(node) <= 2**53 - 1:
            pass
        elif not isinstance(node, str):
            raise InvalidData("Unsupported canonical value")
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def read_json(path: Path, limit):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise InvalidData("Duplicate JSON field")
        return result
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise InvalidData("JSON exceeds size limit")
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
        if not isinstance(result, dict):
            raise InvalidData("Expected JSON object")
        return result
    except (RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        raise InvalidData("Invalid JSON document") from exc


def enc(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def dec(value, length):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", value):
        raise InvalidData("Invalid base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise InvalidData("Invalid base64url") from exc
    if len(raw) != length or enc(raw) != value:
        raise InvalidData("Unexpected binary field encoding")
    return raw


def digest(data):
    return hashlib.sha256(data).digest()


def leaf(index, cipher_digest):
    return digest(b"\x00" + index.to_bytes(8, "big") + cipher_digest)


def merkle(leaves):
    if not leaves:
        return digest(b"")
    while len(leaves) > 1:
        parents = [digest(b"\x01" + leaves[i] + leaves[i+1]) for i in range(0, len(leaves)-1, 2)]
        if len(leaves) % 2:
            parents.append(leaves[-1])
        leaves = parents
    return leaves[0]


def aad(tenant, obj, ver, index, size):
    ids = b"".join(uuid.UUID(v).bytes for v in (tenant, obj, ver))
    return b"DSE-DCF-AAD/1" + ids + index.to_bytes(8, "big") + size.to_bytes(8, "big") + b"none"


def signed_bytes(manifest):
    unsigned = {k: v for k, v in manifest.items() if k != "signatures"}
    return DOMAIN + digest(canonical(unsigned))
