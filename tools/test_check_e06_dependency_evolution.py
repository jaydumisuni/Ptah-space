"""Adversarial exact E06/E07 private dependency evolution conformance."""
import json
import tempfile
import unittest
from pathlib import Path
from check_e06_dependency_evolution import (
    E06_LOCK_STANZA, verified_local_extension,
)

ROOT = Path(__file__).resolve().parents[1]

class ExactAdditiveE06GraphTests(unittest.TestCase):
    def historical(self):
        return json.loads((ROOT / "dependencies/rust-direct-lock.json").read_text())["cargo_lock"]["sha256"]

    def check_bytes(self, raw):
        with tempfile.TemporaryDirectory(prefix="ptah-lock-negative-") as work:
            f = Path(work) / "Cargo.lock"
            f.write_bytes(raw)
            return verified_local_extension(f, self.historical())

    def test_frozen_sha_unmodified_and_exact_e06_e07_reconstructs(self):
        self.assertEqual(verified_local_extension(ROOT / "Cargo.lock", self.historical()), 1)

    def test_native_gateway_private_dependency_additions_are_all_or_nothing(self):
        raw = (ROOT / "Cargo.lock").read_bytes()
        mutations = [
            # Registry dependency substitution and an unreviewed resolved package.
            raw.replace(b' "rusqlite",\n', b' "unreviewed",\n', 1),
            raw + b'\n[[package]]\nname = "evil"\nversion = "1.0.0"\n',
            # Duplicate E06 package and mutated E06 source identity.
            raw + E06_LOCK_STANZA,
            raw.replace(E06_LOCK_STANZA, E06_LOCK_STANZA.replace(b'"serde_json"', b'"serde"')),
            # Missing E06 while native gateway changes remain.
            raw.replace(E06_LOCK_STANZA, b'', 1),
            # Incomplete gateway package dependency changes.
            raw.replace(b' "ptah-control",\n', b'', 1),
            raw.replace(b' "ring",\n', b'', 1),
            # Incomplete Node dependency expansion.
            raw.replace(b' "ptah-placement-runtime",\n', b'', 1),
            # Malicious checksum/signed historic package drift.
            raw.replace(b' "ptah-control",\n', b' "ptah-control",\n', 1) + b' ',
        ]
        for i, mutation in enumerate(mutations):
            self.assertNotEqual(mutation, raw)
            with self.subTest(index=i):
                with self.assertRaises(ValueError):
                    self.check_bytes(mutation)

    def test_unknown_historical_digest_is_not_accepted(self):
        with self.assertRaises(ValueError):
            verified_local_extension(ROOT / "Cargo.lock", "0" * 64)
