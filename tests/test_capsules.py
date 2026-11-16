import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from dse import capsule, dcf, keys
from dse.cli import main


class CapsuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.secret = self.base / "keys"
        keys.initialize(self.secret)
        self.key = keys.load(self.secret)
        self.store = self.base / "store"
        self.src = self.base / "input"
        self.out = self.base / "restored"

    def seal(self, data, obj=None):
        self.src.write_bytes(data)
        return capsule.seal(self.src, self.store, self.key, object_id=obj)

    def recover(self, record, output=None):
        return capsule.recover(self.store, self.key, record["object_id"], record["version_id"], output)

    def test_stream_sizes(self):
        for size in (0, 1, dcf.CHUNK_BYTES, 2 * dcf.CHUNK_BYTES + 13):
            with self.subTest(size=size):
                data = os.urandom(size)
                record = self.seal(data)
                self.assertEqual(self.recover(record, self.out), record)
                self.assertEqual(self.out.read_bytes(), data)
                self.out.unlink()

    def test_immutable_versions_and_unique_nonces(self):
        first = self.seal(b"first")
        second = self.seal(b"B" * (dcf.CHUNK_BYTES + 2), first["object_id"])
        self.assertNotEqual(first["version_id"], second["version_id"])
        self.recover(first, self.out)
        self.assertEqual(self.out.read_bytes(), b"first")
        folder = self.store / second["version_id"]
        rows = json.loads((folder / "manifest.json").read_bytes())["chunks"]
        self.assertEqual(len({r["nonce"] for r in rows}), 2)
        self.assertNotIn(b"B" * 80, (folder / "chunks/00000000.bin").read_bytes())
        self.assertNotEqual((folder / "envelope.json").read_bytes(),
                            (self.store / first["version_id"] / "envelope.json").read_bytes())

    def test_tampered_late_chunk_leaves_no_plaintext_output(self):
        obj = self.seal(b"A" * (dcf.CHUNK_BYTES+1))
        path = self.store / obj["version_id"] / "chunks/00000001.bin"
        data = bytearray(path.read_bytes())
        data[0] ^= 1
        path.write_bytes(data)
        before = set(self.base.iterdir())
        with self.assertRaisesRegex(dcf.InvalidData, "integrity failure"):
            self.recover(obj, self.out)
        self.assertEqual(set(self.base.iterdir()), before)

    def test_missing_chunk(self):
        obj = self.seal(b"data")
        (self.store / obj["version_id"] / "chunks/00000000.bin").unlink()
        with self.assertRaises(FileNotFoundError):
            self.recover(obj, self.out)
        self.assertFalse(self.out.exists())

    def test_manifest_tamper(self):
        obj = self.seal(b"hello")
        path = self.store / obj["version_id"] / "manifest.json"
        path.write_bytes(path.read_bytes().replace(b"default", b"changed"))
        with self.assertRaisesRegex(dcf.InvalidData, "signature"):
            self.recover(obj)

    def test_substituted_key_envelope(self):
        first, second = self.seal(b"first"), self.seal(b"second")
        shutil.copyfile(self.store / second["version_id"] / "envelope.json",
                        self.store / first["version_id"] / "envelope.json")
        with self.assertRaisesRegex(dcf.InvalidData, "authentication"):
            self.recover(first, self.out)

    def test_existing_files_survive(self):
        obj = self.seal(b"new")
        self.out.write_bytes(b"prior")
        with self.assertRaises(FileExistsError):
            self.recover(obj, self.out)
        self.assertEqual(self.out.read_bytes(), b"prior")
        with self.assertRaises(FileExistsError):
            keys.initialize(self.secret)
        self.assertEqual(keys.load(self.secret).signer_id, self.key.signer_id)

    def test_wrong_identity(self):
        obj = self.seal(b"hello")
        with self.assertRaisesRegex(dcf.InvalidData, "mismatch"):
            capsule.recover(self.store, self.key, dcf.uuid7(), obj["version_id"])
        other = self.base / "other"
        keys.initialize(other)
        with self.assertRaisesRegex(dcf.InvalidData, "signing key"):
            capsule.recover(self.store, keys.load(other), obj["object_id"], obj["version_id"])

    def test_failure_before_publish(self):
        self.src.write_bytes(b"hello")
        with patch.object(capsule, "write_file", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                capsule.seal(self.src, self.store, self.key)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_forbidden_critical_feature(self):
        obj = self.seal(b"hello")
        path = self.store / obj["version_id"] / "manifest.json"
        manifest = json.loads(path.read_bytes())
        manifest["critical"] = ["other-profile"]
        manifest["signatures"][0]["signature"] = dcf.enc(self.key.signer.sign(dcf.signed_bytes(manifest)))
        path.write_bytes(dcf.canonical(manifest))
        with self.assertRaisesRegex(dcf.InvalidData, "mismatch"):
            self.recover(obj)

    def test_canonical_input_limits(self):
        self.assertEqual(dcf.canonical({"b": 2, "a": "水"}), '{"a":"水","b":2}'.encode())
        for bad in (1.0, 2**53, {"水": "non-ASCII key"}):
            with self.assertRaises(dcf.InvalidData):
                dcf.canonical(bad)
        self.src.write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex(dcf.InvalidData, "Duplicate"):
            dcf.read_json(self.src, 128)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for independent wire-format verification")
    def test_node_verifies_python_signature(self):
        record = self.seal(b"interoperability")
        subprocess.run(["node", str(Path(__file__).with_name("verify_manifest.mjs")),
                        str(self.store / record["version_id"] / "manifest.json"),
                        dcf.enc(self.key.signer.public_key().public_bytes_raw())], check=True)

    def test_fresh_cli_processes(self):
        self.src.write_bytes(b"cli smoke")
        def run(*args):
            result = subprocess.run([sys.executable, "-m", "dse", "--keyring", str(self.secret), *args],
                                    capture_output=True, check=True, text=True)
            return json.loads(result.stdout)
        obj = run("seal", str(self.src), "--store", str(self.store))
        args = ["--object", obj["object_id"], "--version", obj["version_id"], "--store", str(self.store)]
        self.assertEqual(run("verify", *args), obj)
        run("restore", str(self.out), *args)
        self.assertEqual(self.out.read_bytes(), b"cli smoke")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--keyring", str(self.secret), "init"]), 1)
