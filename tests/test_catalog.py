import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dse import capsule, catalog, dcf, keys


class CatalogInputTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        keys.initialize(self.base / "keys")
        self.key = keys.load(self.base / "keys")
        source = self.base / "input"
        source.write_bytes(b"catalog input")
        self.store = self.base / "store"
        result = capsule.seal(source, self.store, self.key)
        self.obj, self.ver = result["object_id"], result["version_id"]

    def test_verified_material_is_bound_to_request(self):
        with patch.object(catalog, "_query", return_value=1) as query:
            result = catalog.commit(self.store, self.key, self.obj, self.ver, "none")
        _, args = query.call_args.args
        directory = self.store / self.ver
        self.assertEqual(args[:2], (self.key.tenant, self.key.signer_id))
        self.assertEqual(args[2].encode(), (directory / "manifest.json").read_bytes())
        self.assertEqual(args[3], dcf.digest(args[2].encode()))
        self.assertEqual(args[4], dcf.dec(dcf.read_json(directory / "envelope.json", 1024)["wrapped_dek"], 40))
        self.assertEqual(args[5:], (None, str(self.store.resolve())))
        self.assertEqual(result, {"object_id": self.obj, "version_id": self.ver, "ordinal": 1})

    def test_corrupt_ciphertext_never_reaches_catalog(self):
        (self.store / self.ver / "chunks/00000000.bin").write_bytes(os.urandom(29))
        with patch.object(catalog, "_query") as query, self.assertRaises(dcf.InvalidData):
            catalog.commit(self.store, self.key, self.obj, self.ver, "none")
        query.assert_not_called()
