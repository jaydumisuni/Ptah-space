#!/usr/bin/env python3
"""Regression tests for the frozen E04 compatible-workspace-movement corpus checker."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPO_ROOT / "tools/check-e04-conformance.py"
SPEC = importlib.util.spec_from_file_location("check_e04_conformance", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load E04 checker")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
CANONICAL = REPO_ROOT / checker.CORPUS_RELATIVE_PATH


class E04CorpusCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(CANONICAL.read_text(encoding="utf-8"))

    def validate(self, document: dict) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "e04.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return checker.load_and_validate_corpus(path)

    def test_canonical_32_case_corpus_passes(self) -> None:
        validated = self.validate(copy.deepcopy(self.document))
        self.assertEqual(len(validated["cases"]), 32)
        self.assertEqual(
            {case["id"] for case in validated["cases"]},
            checker.EXPECTED_CASES,
        )

    def test_wrong_case_count_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["cases"].pop()
        with self.assertRaisesRegex(ValueError, "exactly 32 cases"):
            self.validate(mutated)

    def test_duplicate_case_id_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["cases"][1]["id"] = mutated["cases"][0]["id"]
        with self.assertRaisesRegex(ValueError, "case ids must be unique"):
            self.validate(mutated)

    def test_unproven_case_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["cases"][0]["passed"] = False
        with self.assertRaisesRegex(ValueError, "is not proven passing"):
            self.validate(mutated)

    def test_false_observation_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["cases"][0]["observed_result"] = "transport ACK alone means success"
        with self.assertRaisesRegex(ValueError, "falsely claims a passing observation"):
            self.validate(mutated)

    def test_forbidden_scope_claim_fails_closed(self) -> None:
        for field in checker.SCOPE_FALSE_FIELDS:
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.document)
                mutated[field] = True
                with self.assertRaisesRegex(ValueError, f"{field} must remain false"):
                    self.validate(mutated)


if __name__ == "__main__":
    unittest.main()
