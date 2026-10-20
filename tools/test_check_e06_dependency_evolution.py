"""Fail-closed proof that E06 cannot rewrite historic dependency evidence."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from check_e06_dependency_evolution import E06_LOCK_STANZA, verified_local_extension

ROOT = Path(__file__).resolve().parents[1]

class ExactAdditiveE06GraphTests(unittest.TestCase):
    def test_frozen_sha_unchanged_and_e06_reconstructs_exact_historic_bytes(self):
        historical = json.loads((ROOT/"dependencies/rust-direct-lock.json").read_text())["cargo_lock"]["sha256"]
        self.assertEqual(verified_local_extension(ROOT/"Cargo.lock", historical),1)

    def test_modified_or_second_e06_stanza_and_extra_registry_package_fail(self):
        raw = (ROOT/"Cargo.lock").read_bytes()
        historical = hashlib.sha256(raw.replace(E06_LOCK_STANZA, b"", 1)).hexdigest()
        mutations = [
            raw.replace(b'"rusqlite",', b'"not-rusqlite",', 1),
            raw + E06_LOCK_STANZA,
            raw.replace(E06_LOCK_STANZA,b''),
            raw.replace(E06_LOCK_STANZA,E06_LOCK_STANZA.replace(b'"serde_json"',b'"serde"')),
            raw + b'\n[[package]]\nname = "unapproved"\nversion = "0.0.1"\n',
        ]
        for changed in mutations:
            with self.subTest(changed_hash=hashlib.sha256(changed).hexdigest()):
                with tempfile.TemporaryDirectory() as folder:
                    target=Path(folder)/"Cargo.lock"
                    target.write_bytes(changed)
                    if changed==raw.replace(E06_LOCK_STANZA,b''):
                        self.assertEqual(verified_local_extension(target,historical),0)
                    else:
                        with self.assertRaises(ValueError):
                            verified_local_extension(target,historical)

    def test_other_historical_digest_cannot_be_substituted(self):
        with self.assertRaises(ValueError):
            verified_local_extension(ROOT/"Cargo.lock","0"*64)
