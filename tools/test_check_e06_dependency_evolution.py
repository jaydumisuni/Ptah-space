"""Fail-closed proof that E06 cannot rewrite historic dependency evidence."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from check_e06_dependency_evolution import (
    E06_LOCK_STANZA, verified_local_extension,
    strip_exact_e07_local_service_extension, strip_exact_p13_local_extension, strip_exact_webpki_security_patch, strip_exact_tokio_security_patch, _TOKIO_PATCHED_STANZA, _TOKIO_FROZEN_STANZA, _TOKIO_MACROS_PATCHED_STANZA, _TOKIO_MACROS_FROZEN_STANZA, _E07_NODE_AFTER, _E07_NODE_BEFORE, _E07_CONTROL_AFTER,
    _E07_SQLITE_BUNDLE_AFTER, _E07_SQLITE_BUNDLE_BEFORE
)

ROOT = Path(__file__).resolve().parents[1]

class ExactAdditiveE06GraphTests(unittest.TestCase):
    def test_frozen_sha_unchanged_and_e06_reconstructs_exact_historic_bytes(self):
        historical = json.loads((ROOT/"dependencies/rust-direct-lock.json").read_text())["cargo_lock"]["sha256"]
        self.assertEqual(verified_local_extension(ROOT/"Cargo.lock", historical),2)

    def test_modified_or_second_e06_stanza_and_extra_registry_package_fail(self):
        raw = strip_exact_p13_local_extension(strip_exact_tokio_security_patch(strip_exact_webpki_security_patch((ROOT/"Cargo.lock").read_bytes())))
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
        raw=strip_exact_p13_local_extension(strip_exact_tokio_security_patch(strip_exact_webpki_security_patch((ROOT/"Cargo.lock").read_bytes())))
        base=strip_exact_e07_local_service_extension(raw)
        historic=hashlib.sha256(base.replace(E06_LOCK_STANZA,b"",1)).hexdigest()
        self.assertEqual(verified_local_extension(ROOT/"Cargo.lock",historic),2)
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

    def test_exact_e07_windows_sqlite_native_bundle_is_evidence_not_lock_drift(self):
        original=strip_exact_p13_local_extension(strip_exact_tokio_security_patch(strip_exact_webpki_security_patch((ROOT/"Cargo.lock").read_bytes())))
        # Validate exact proposed Windows extension even on current main
        # before the bundled SQLite edge is merged.
        raw=(original if _E07_SQLITE_BUNDLE_AFTER in original else
             original.replace(_E07_SQLITE_BUNDLE_BEFORE,_E07_SQLITE_BUNDLE_AFTER,1))
        self.assertEqual(raw.count(_E07_SQLITE_BUNDLE_AFTER),1)
        base=strip_exact_e07_local_service_extension(raw)
        self.assertEqual(base.count(_E07_SQLITE_BUNDLE_BEFORE),1)
        original=hashlib.sha256(base.replace(E06_LOCK_STANZA,b"",1)).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            candidate=Path(temporary)/"Cargo.lock";candidate.write_bytes(raw)
            self.assertEqual(verified_local_extension(candidate,original),1)
        for forged in [
            raw.replace(_E07_SQLITE_BUNDLE_AFTER,
                        _E07_SQLITE_BUNDLE_AFTER.replace(b' "cc",',b' "evil",')),
            raw.replace(_E07_SQLITE_BUNDLE_AFTER,
                        _E07_SQLITE_BUNDLE_AFTER.replace(b"0.35.0",b"0.35.1")),
            raw.replace(_E07_SQLITE_BUNDLE_AFTER,
                        _E07_SQLITE_BUNDLE_AFTER.replace(b"133c182a",b"abcabcab")),
            raw.replace(_E07_NODE_AFTER,_E07_NODE_BEFORE),
        ]:
            with self.subTest(digest=hashlib.sha256(forged).hexdigest()):
                with tempfile.TemporaryDirectory() as folder:
                    f=Path(folder)/"Cargo.lock";f.write_bytes(forged)
                    with self.assertRaises(ValueError):
                        verified_local_extension(f,original)

    def test_exact_p13_adapter_extension_denies_forged_local_graph(self):
        original = (ROOT / "Cargo.lock").read_bytes()
        historic = json.loads((ROOT / "dependencies/rust-direct-lock.json").read_text())["cargo_lock"]["sha256"]
        self.assertEqual(verified_local_extension(ROOT / "Cargo.lock", historic), 2)
        changed = [
            original.replace(b'name = "ptah-formula-work-cells"', b'name = "ptah-forged-workcells"', 1),
            original.replace(b' "thiserror 2.0.17",', b' "unreviewed-dependency",', 1),
            original + b'\n[[package]]\nname = "unreviewed"\nversion = "0.1.0"\n',
        ]
        for candidate in changed:
            with self.subTest(digest=hashlib.sha256(candidate).hexdigest()):
                with tempfile.TemporaryDirectory() as folder:
                    path = Path(folder) / "Cargo.lock"
                    path.write_bytes(candidate)
                    with self.assertRaises(ValueError):
                        verified_local_extension(path, historic)

    def test_webpki_security_patch_keeps_historical_lock_recoverable(self):
        historical = json.loads((ROOT/"dependencies/rust-direct-lock.json").read_text())["cargo_lock"]["sha256"]
        self.assertEqual(verified_local_extension(ROOT/"Cargo.lock", historical), 2)
        current = (ROOT/"Cargo.lock").read_bytes()
        self.assertIn(b'version = "0.103.16"', current)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Cargo.lock"
            path.write_bytes(current.replace(b'version = "0.103.16"', b'version = "0.103.14"', 1))
            with self.assertRaises(ValueError):
                verified_local_extension(path, historical)

    def test_tokio_security_patch_exact_pair_preserves_historical_authority(self):
        historical = json.loads((ROOT/"dependencies/rust-direct-lock.json").read_text())["cargo_lock"]["sha256"]
        raw = (ROOT/"Cargo.lock").read_bytes()
        self.assertEqual(raw.count(_TOKIO_PATCHED_STANZA), 1)
        self.assertEqual(raw.count(_TOKIO_MACROS_PATCHED_STANZA), 1)
        self.assertEqual(verified_local_extension(ROOT/"Cargo.lock", historical), 2)
        normalized = strip_exact_tokio_security_patch(raw)
        self.assertEqual(normalized.count(_TOKIO_FROZEN_STANZA), 1)
        self.assertEqual(normalized.count(_TOKIO_MACROS_FROZEN_STANZA), 1)
        self.assertEqual(strip_exact_tokio_security_patch(normalized), normalized)
        tampered = [
            raw.replace(b'version = "1.53.3"', b'version = "1.53.2"', 1),
            raw.replace(b'ce3335fa71841cda', b'0000000000000000', 1),
            raw.replace(_TOKIO_PATCHED_STANZA, _TOKIO_FROZEN_STANZA, 1),
            raw.replace(_TOKIO_MACROS_PATCHED_STANZA, _TOKIO_MACROS_FROZEN_STANZA, 1),
            raw.replace(b'version = "2.7.2"', b'version = "2.7.1"', 1),
            raw.replace(b'78773a2a397f4515', b'0000000000000000', 1),
            raw.replace(_TOKIO_PATCHED_STANZA,
                        _TOKIO_PATCHED_STANZA.replace(b' "mio",', b' "untrusted",'), 1),
            raw + b'\n[[package]]\nname = "extra"\nversion = "1.0.0"\n',
        ]
        for changed in tampered:
            with self.subTest(digest=hashlib.sha256(changed).hexdigest()):
                with tempfile.TemporaryDirectory() as folder:
                    candidate = Path(folder) / "Cargo.lock"
                    candidate.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        verified_local_extension(candidate, historical)

    def test_other_historical_digest_cannot_be_substituted(self):
        with self.assertRaises(ValueError):
            verified_local_extension(ROOT/"Cargo.lock","0"*64)
