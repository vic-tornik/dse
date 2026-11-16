"""Single-operator development keyring. The containing directory must be private."""
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .dcf import InvalidData, canonical, dec, digest, enc, identifier, read_json, uuid7


@dataclass(frozen=True)
class Keyring:
    tenant: str
    kek: bytes
    signer: Ed25519PrivateKey

    @property
    def signer_id(self):
        return "ed25519:" + enc(digest(self.signer.public_key().public_bytes_raw()))


def initialize(path: Path):
    data = canonical({"format": "dse-dev-keys/1", "tenant": uuid7(),
                      "kek": enc(AESGCM.generate_key(bit_length=256)),
                      "signer": enc(Ed25519PrivateKey.generate().private_bytes_raw())})
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600), "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def load(path: Path):
    data = read_json(path, 4096)
    if data.get("format") != "dse-dev-keys/1":
        raise InvalidData("Unrecognized keyring")
    return Keyring(identifier(data["tenant"], 7), dec(data["kek"], 32),
                   Ed25519PrivateKey.from_private_bytes(dec(data["signer"], 32)))
