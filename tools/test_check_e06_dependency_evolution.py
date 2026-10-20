"""Fail-closed proof that E06 cannot rewrite historic dependency evidence."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from check_e06_dependency_evolution import E06_LOCK_STANZA, verified_local_extension, strip_exact_e07_local_service_extension, _E07_NODE_AFTER, _E07_CONTROL_AFTER

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

    def test_e07_local_dependency_changes_are_exact_not_any_lock_waiver(self):
        raw=(ROOT/"Cargo.lock").read_bytes()
        base=strip_exact_e07_local_service_extension(raw)
        historic=hashlib.sha256(base.replace(E06_LOCK_STANZA,b"",1)).hexdigest()
        self.assertEqual(verified_local_extension(ROOT/"Cargo.lock",historic),1)
        bad_versions=[
            raw.replace(b' "ring",',b' "untrusted_e07_extra",',1),
            raw.replace(_E07_NODE_AFTER,_E07_NODE_AFTER.replace(b' "serde",',b' "json_override",')),
            raw.replace(_E07_CONTROL_AFTER,_E07_CONTROL_AFTER.replace(b' "rusqlite",',b'')),
            raw+b'\n[[package]]\nname = "evil"\nversion = "0.0.1"\n',
        ]
        for bad in bad_versions:
            with self.subTest(size=len(bad)),tempfile.TemporaryDirectory() as tmp:
                destination=Path(tmp)/"Cargo.lock"
                destination.write_bytes(bad)
                with self.assertRaises(ValueError):
                    verified_local_extension(destination,historic)

    def test_other_historical_digest_cannot_be_substituted(self):
        with self.assertRaises(ValueError):
            verified_local_extension(ROOT/"Cargo.lock","0"*64)
