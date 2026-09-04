#!/usr/bin/env python3
"""Regression tests for the D09 Full Workspace release corpus checker."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from check_d09_full_workspace_release import load_and_validate_corpus, require_report_files


REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "conformance/d09/full-workspace-release-cases.v0.1.0.json"


def repository_corpus() -> dict:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def write_corpus(root: Path, document: dict) -> Path:
    path = root / "corpus.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class D09CheckerTests(unittest.TestCase):
    def test_repository_corpus_is_valid(self) -> None:
        document = load_and_validate_corpus(CORPUS_PATH)
        self.assertEqual(document["schema_version"], "0.1.0")
        self.assertEqual(len(document["cases"]), 10)

    def test_rejects_wrong_case_count(self) -> None:
        document = repository_corpus()
        document["cases"] = document["cases"][:-1]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "exactly 10"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_duplicate_case_id(self) -> None:
        document = repository_corpus()
        document["cases"][1]["id"] = document["cases"][0]["id"]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "unique"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_missing_required_category(self) -> None:
        document = repository_corpus()
        document["cases"][0]["category"] = "invented_category"
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "categories"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_missing_human_hunter_or_sergeant_participant(self) -> None:
        for participant in ("human", "hunter", "sergeant"):
            document = repository_corpus()
            for case in document["cases"]:
                case["participants"] = [
                    value for value in case["participants"] if value != participant
                ]
            with self.subTest(participant=participant), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(ValueError, "participants"):
                    load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_ptah_semantic_authority(self) -> None:
        document = repository_corpus()
        document["cases"][0]["ptah_semantic_authority"] = True
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "semantic authority"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_new_core_entity_requirement(self) -> None:
        document = repository_corpus()
        document["new_core_entity_required"] = True
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "new Core"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_frozen_contract_change(self) -> None:
        document = repository_corpus()
        document["frozen_contract_change_required"] = True
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "frozen contract"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_runtime_feature_addition(self) -> None:
        document = repository_corpus()
        document["runtime_feature_added"] = True
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "runtime feature"):
                load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_wrong_predecessor_and_roadmap_authority(self) -> None:
        for field in ("accepted_predecessor", "roadmap_authority"):
            document = repository_corpus()
            document[field] = "0" * 40
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(ValueError, field.replace("_", " ")):
                    load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_rejects_missing_or_empty_case_evidence(self) -> None:
        for value in ([], [""], "not-a-list"):
            document = repository_corpus()
            document["cases"][0]["required_evidence"] = copy.deepcopy(value)
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(ValueError, "required evidence"):
                    load_and_validate_corpus(write_corpus(Path(tmp), document))

    def test_require_report_files_rejects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "missing"):
                require_report_files(Path(tmp), ["missing.txt"])

    def test_require_report_files_rejects_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "empty.txt").write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "empty"):
                require_report_files(root, ["empty.txt"])

    def test_require_report_files_rejects_non_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "folder").mkdir()
            with self.assertRaisesRegex(ValueError, "regular file"):
                require_report_files(root, ["folder"])

    def test_require_report_files_returns_deterministic_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = b"d09-proof\n"
            (root / "b.txt").write_bytes(payload)
            (root / "a.txt").write_bytes(b"alpha\n")
            result = require_report_files(root, ["b.txt", "a.txt"])
            self.assertEqual([item["path"] for item in result], ["a.txt", "b.txt"])
            b_record = next(item for item in result if item["path"] == "b.txt")
            self.assertEqual(b_record["size"], len(payload))
            self.assertEqual(b_record["sha256"], hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    unittest.main()
