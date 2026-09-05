#!/usr/bin/env python3
"""Regression tests for the E01 secure multi-Node acceptance checker."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from check_e01_secure_multi_node import load_and_validate_corpus, require_report_files


REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "conformance/e01/secure-multi-node-cases.v0.1.0.json"
REQUIRED_CASES = {
    "two_node_concurrency",
    "reconnect",
    "node_restart",
    "control_restart",
    "credential_rotation",
    "plaintext_rejected",
    "wrong_ca_rejected",
    "wrong_enrollment_binding_rejected",
    "revoked_enrollment_rejected",
    "expired_enrollment_rejected",
    "stale_generation_rejected",
    "stale_or_equal_epoch_rejected",
    "superseded_publish_rejected",
    "capability_identity_mismatch_rejected",
    "malformed_frame_rejected",
    "oversized_frame_rejected",
    "unsupported_protocol_rejected",
}


def repository_corpus() -> dict:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def write_corpus(root: Path, document: dict) -> Path:
    path = root / "corpus.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class E01CheckerTests(unittest.TestCase):
    def test_repository_corpus_is_valid_and_complete(self) -> None:
        document = load_and_validate_corpus(CORPUS_PATH)
        self.assertEqual(document["schema_version"], "0.1.0")
        self.assertEqual({case["id"] for case in document["cases"]}, REQUIRED_CASES)

    def test_rejects_missing_required_case(self) -> None:
        document = repository_corpus()
        document["cases"] = document["cases"][:-1]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "coverage"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_duplicate_case_id(self) -> None:
        document = repository_corpus()
        document["cases"][1]["id"] = document["cases"][0]["id"]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "unique"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_authority_widening(self) -> None:
        for field in (
            "scheduler_added",
            "transfer_plane_added",
            "overlay_transport_added",
            "automatic_discovery_added",
            "new_core_entity_required",
            "frozen_contract_change_required",
        ):
            document = repository_corpus()
            document[field] = True
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(ValueError, "must remain false"):
                    load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_wrong_predecessor(self) -> None:
        document = repository_corpus()
        document["accepted_predecessor"] = "0" * 40
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "predecessor"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_missing_evidence_or_expected_result(self) -> None:
        for field, value in (("required_evidence", []), ("expected_result", "")):
            document = repository_corpus()
            document["cases"][0][field] = copy.deepcopy(value)
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_require_report_files_rejects_missing_empty_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "empty.txt").write_bytes(b"")
            (root / "dir").mkdir()
            with self.assertRaisesRegex(ValueError, "missing"):
                require_report_files(root, ["missing.txt"])
            with self.assertRaisesRegex(ValueError, "empty"):
                require_report_files(root, ["empty.txt"])
            with self.assertRaisesRegex(ValueError, "regular file"):
                require_report_files(root, ["dir"])

    def test_require_report_files_rejects_unsafe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "safe relative"):
                require_report_files(Path(tmp), ["../escape.txt"])

    def test_require_report_files_returns_deterministic_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = b"e01-proof\n"
            (root / "proof.txt").write_bytes(payload)
            result = require_report_files(root, ["proof.txt"])
            self.assertEqual(result[0]["size"], len(payload))
            self.assertEqual(result[0]["sha256"], hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    unittest.main()
