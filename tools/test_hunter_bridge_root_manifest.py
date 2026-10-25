"""Adversarial exact-root-manifest admission tests for Hunter/Ptah bridge."""

import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).with_name("check_hunter_bridge_root_manifest.py")
spec = importlib.util.spec_from_file_location("bridge_root_manifest", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

BASE = b'[dependencies]\ntokio = { version = "=1.48.0", features = ["full"] }\n'
PATCHED = BASE.replace(module.OLD, module.NEW, 1)


class BridgeRootManifestTests(unittest.TestCase):
    def test_approved_exact_pin_change(self):
        module.verify_root_manifest(BASE, PATCHED)

    def test_unchanged_accepted_old_base(self):
        module.verify_root_manifest(BASE, BASE)

    def test_unchanged_accepted_patched_base(self):
        module.verify_root_manifest(PATCHED, PATCHED)

    def test_unrelated_change_to_old_base_rejected(self):
        with self.assertRaisesRegex(ValueError, "unreviewed_root_manifest_change"):
            module.verify_root_manifest(BASE, PATCHED + b"extra = true\n")

    def test_unrelated_change_to_patched_base_rejected(self):
        with self.assertRaisesRegex(ValueError, "unrecognized_frozen_root_manifest"):
            module.verify_root_manifest(PATCHED, PATCHED + b"extra = true\n")

    def test_second_tokio_pin_rejected(self):
        with self.assertRaisesRegex(ValueError, "unrecognized_frozen_root_manifest"):
            module.verify_root_manifest(BASE + module.OLD, PATCHED)

    def test_unrecognized_change_to_old_base_rejected(self):
        with self.assertRaisesRegex(ValueError, "unreviewed_root_manifest_change"):
            module.verify_root_manifest(BASE, BASE.replace(b"full", b"rt"))

    def test_reverting_patched_base_rejected(self):
        with self.assertRaisesRegex(ValueError, "unrecognized_frozen_root_manifest"):
            module.verify_root_manifest(PATCHED, BASE)

    def test_commit_sha_must_be_exact_lowercase_hex(self):
        for sha in ("HEAD", "f" * 39, "F" * 40, "f" * 40 + ":x"):
            with self.subTest(sha=sha):
                with self.assertRaisesRegex(ValueError, "invalid_exact_commit_sha"):
                    module.committed_manifest(sha)


if __name__ == "__main__":
    unittest.main()
