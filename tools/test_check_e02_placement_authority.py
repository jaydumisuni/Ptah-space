#!/usr/bin/env python3
"""Regression tests for the exact E02 placement-authority corpus checker."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import check_e02_placement_authority as checker

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL = REPO_ROOT / checker.CORPUS_RELATIVE_PATH


class E02CorpusCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(CANONICAL.read_text(encoding="utf-8"))

    def validate(self, document: dict) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return checker.load_and_validate_corpus(path)

    def assert_rejected(self, document: dict) -> None:
        with self.assertRaises(ValueError):
            self.validate(document)

    def test_canonical_28_case_corpus_passes(self) -> None:
        validated = self.validate(self.document)
        self.assertEqual(len(validated["cases"]), 28)

    def test_missing_case_fails_closed(self) -> None:
        document = copy.deepcopy(self.document)
        document["cases"].pop()
        self.assert_rejected(document)

    def test_duplicate_case_fails_closed(self) -> None:
        document = copy.deepcopy(self.document)
        document["cases"][-1] = copy.deepcopy(document["cases"][0])
        self.assert_rejected(document)

    def test_unexpected_case_fails_closed(self) -> None:
        document = copy.deepcopy(self.document)
        document["cases"][0]["id"] = "invented_unapproved_case"
        self.assert_rejected(document)

    def test_false_pass_bit_fails_closed(self) -> None:
        document = copy.deepcopy(self.document)
        document["cases"][0]["passed"] = False
        self.assert_rejected(document)

    def test_observed_result_mismatch_fails_closed(self) -> None:
        document = copy.deepcopy(self.document)
        document["cases"][0]["observed_result"] = "not actually proven"
        self.assert_rejected(document)

    def test_scope_expansion_fails_closed(self) -> None:
        for field in checker.SCOPE_FALSE_FIELDS:
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document[field] = True
                self.assert_rejected(document)


if __name__ == "__main__":
    unittest.main()
