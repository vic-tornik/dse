"""Bootstrap application credentials and default-deny local service permissions."""
from dataclasses import dataclass, field
import hashlib
import hmac
import os
from pathlib import Path
import re

from . import dcf, keys


@dataclass(frozen=True)
class Principal:
    id: str
    token_sha256: str
    keyring: keys.Keyring = field(repr=False)
    dsn: str = field(repr=False)
    actions: frozenset[str]
    namespaces: frozenset[str]

    def allows(self, action, namespace):
        return action in self.actions and namespace in self.namespaces


@dataclass(frozen=True)
class Settings:
    store: Path
    temporary: Path
    principals: tuple[Principal, ...]
    max_upload_bytes: int = 64 * 1024 * 1024
    max_active_transfers: int = 2

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        data = dcf.read_json(path, 65536)
        base = path.parent
        principals = []
        for item in data["principals"]:
            digest = item["token_sha256"]
            if not re.fullmatch("[0-9a-f]{64}", digest):
                raise ValueError("Invalid token digest")
            if not isinstance(item.get("actions", []), list) or not isinstance(item.get("namespaces", []), list):
                raise ValueError("Permissions must be arrays")
            actions = frozenset(item.get("actions", []))
            namespaces = frozenset(item.get("namespaces", []))
            if not actions <= {"read", "write"} or any(
                    not re.fullmatch("[a-z0-9][a-z0-9._-]{0,62}", n) for n in namespaces):
                raise ValueError("Invalid principal permissions")
            dsn = os.environ[item["database_env"]]
            if not dsn.strip():
                raise ValueError("Empty database connection setting")
            principals.append(Principal(item["id"], digest, keys.load(base / item["keyring"]),
                                        dsn, actions, namespaces))
        if not principals or len({p.token_sha256 for p in principals}) != len(principals):
            raise ValueError("Credentials must be present and unique")
        if len({p.id for p in principals}) != len(principals):
            raise ValueError("Principal IDs must be unique")
        tenants = {}
        for p in principals:
            identity = (p.keyring.signer_id, p.keyring.kek)
            if tenants.setdefault(p.keyring.tenant, identity) != identity:
                raise ValueError("Conflicting tenant keyrings")
        limit = data.get("max_upload_bytes", 64 * 1024 * 1024)
        active = data.get("max_active_transfers", 2)
        if type(limit) is not int or not 0 < limit <= dcf.CHUNK_BYTES * dcf.MAX_CHUNKS:
            raise ValueError("Invalid upload byte limit")
        if type(active) is not int or not 1 <= active <= 16:
            raise ValueError("Invalid transfer limit")
        store = (base / data["store"]).resolve()
        temporary = (base / data["temporary"]).resolve()
        if store == temporary or store in temporary.parents or temporary in store.parents:
            raise ValueError("Ciphertext and temporary directories must be separate")
        return cls(store, temporary, tuple(principals), limit, active)

    def authenticate(self, token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        match = None
        for principal in self.principals:
            if hmac.compare_digest(digest, principal.token_sha256):
                match = principal
        return match
