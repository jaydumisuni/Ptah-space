#!/usr/bin/env python3
"""Adversarial regression tests for the deep Workspace operations donor study."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from check_workspace_operations_donor_v2 import StudyError, validate


class WorkspaceOperationsStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source_root = Path(__file__).resolve().parents[1]

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "repo"
        shutil.copytree(self.source_root, self.root)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def load(self, relative: str) -> dict:
        return json.loads((self.root / relative).read_text(encoding="utf-8"))

    def save(self, relative: str, value: dict) -> None:
        (self.root / relative).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def assert_invalid(self) -> None:
        with self.assertRaises(StudyError):
            validate(self.root)

    def test_00_valid_candidate_passes(self) -> None:
        report = validate(self.root)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["mechanical_capability_count"], 22)
        self.assertEqual(report["fixture_count"], 20)
        self.assertFalse(report["runtime_implementation_authorized"])

    def test_01_private_source_claim_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["source_boundary"]["openai_private_source_used"] = True
        self.save(path, data)
        self.assert_invalid()

    def test_02_hidden_implementation_claim_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["source_boundary"]["hidden_implementation_inferred"] = True
        self.save(path, data)
        self.assert_invalid()

    def test_03_code_reuse_claim_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["source_boundary"]["code_reuse"] = "selective"
        self.save(path, data)
        self.assert_invalid()

    def test_04_ten_for_two_lane_loss_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["study_method"]["independent_verifier_lanes"] = 9
        self.save(path, data)
        self.assert_invalid()

    def test_05_decision_authority_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["decision_authority"] = True
        self.save(path, data)
        self.assert_invalid()

    def test_06_context_authority_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["context_selection_authority"] = True
        self.save(path, data)
        self.assert_invalid()

    def test_07_review_authority_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["review_authority"] = True
        self.save(path, data)
        self.assert_invalid()

    def test_08_approval_authority_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["approval_authority"] = True
        self.save(path, data)
        self.assert_invalid()

    def test_09_new_core_entity_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["new_core_entity_required"] = True
        self.save(path, data)
        self.assert_invalid()

    def test_10_frozen_contract_reopen_fails(self) -> None:
        path = "design/candidates/workspace-operations-gap-map-v2.json"
        data = self.load(path)
        data["frozen_contract_change_required"] = True
        self.save(path, data)
        self.assert_invalid()

    def test_11_runtime_authorization_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["runtime_implementation_authorized"] = True
        self.save(path, data)
        self.assert_invalid()

    def test_12_missing_effect_class_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["operation_effect_classes"].remove("destructive")
        self.save(path, data)
        self.assert_invalid()

    def test_13_missing_materialization_state_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["object_availability_states"].remove("external_reference")
        self.save(path, data)
        self.assert_invalid()

    def test_14_result_state_collapse_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["activity_result_states"].remove("declined")
        self.save(path, data)
        self.assert_invalid()

    def test_15_caller_semantic_merge_ownership_loss_fails(self) -> None:
        path = "design/candidates/workspace-operations-profile-v2.json"
        data = self.load(path)
        data["caller_owned_functions"].remove("semantic merge and reconciliation")
        self.save(path, data)
        self.assert_invalid()

    def test_16_gap_extension_fails(self) -> None:
        path = "design/candidates/workspace-operations-gap-map-v2.json"
        data = self.load(path)
        data["summary"]["candidate_core_extension"] = 1
        data["summary"]["covered_by_neutral_substrate"] = 15
        data["mappings"][0]["classification"] = "candidate_core_extension"
        self.save(path, data)
        self.assert_invalid()

    def test_17_context_mapping_to_core_fails(self) -> None:
        path = "design/candidates/workspace-operations-gap-map-v2.json"
        data = self.load(path)
        item = next(x for x in data["mappings"] if x["capability"] == "context selection and relevance")
        item["classification"] = "covered_by_neutral_substrate"
        data["summary"]["caller_application_composition"] = 5
        data["summary"]["covered_by_neutral_substrate"] = 17
        self.save(path, data)
        self.assert_invalid()

    def test_18_approval_mapping_to_core_fails(self) -> None:
        path = "design/candidates/workspace-operations-gap-map-v2.json"
        data = self.load(path)
        item = next(x for x in data["mappings"] if x["capability"] == "approval decision")
        item["classification"] = "covered_by_neutral_substrate"
        data["summary"]["caller_application_composition"] = 5
        data["summary"]["covered_by_neutral_substrate"] = 17
        self.save(path, data)
        self.assert_invalid()

    def test_19_missing_materialization_fixture_fails(self) -> None:
        path = "design/candidates/fixtures/workspace-operations-fixtures-v2.json"
        data = self.load(path)
        item = next(x for x in data["fixtures"] if x["id"] == "reference-is-not-materialized-by-name")
        item["expected"] = "invent_local_path"
        self.save(path, data)
        self.assert_invalid()

    def test_20_invocation_as_success_fails(self) -> None:
        path = "design/candidates/fixtures/workspace-operations-fixtures-v2.json"
        data = self.load(path)
        item = next(x for x in data["fixtures"] if x["id"] == "invocation-is-not-success")
        item["expected"] = "succeeded"
        self.save(path, data)
        self.assert_invalid()

    def test_21_ptah_semantic_verdict_fails(self) -> None:
        path = "design/candidates/fixtures/workspace-operations-fixtures-v2.json"
        data = self.load(path)
        item = next(x for x in data["fixtures"] if x["id"] == "semantic-merge-remains-caller-owned")
        item["expected"] = "ptah_selects_winner"
        self.save(path, data)
        self.assert_invalid()

    def test_22_missing_official_source_fails(self) -> None:
        path = self.root / "design/donors/openai-chatgpt-workspace-deep-study.md"
        text = path.read_text(encoding="utf-8")
        text = text.replace("https://help.openai.com/en/articles/20001247", "https://example.invalid/missing")
        path.write_text(text, encoding="utf-8")
        self.assert_invalid()

    def test_23_study_contract_reopen_text_loss_fails(self) -> None:
        path = self.root / "design/donors/openai-chatgpt-workspace-deep-study.md"
        text = path.read_text(encoding="utf-8")
        text = text.replace("no reason to reopen WP01–WP14", "contracts may be reopened")
        path.write_text(text, encoding="utf-8")
        self.assert_invalid()

    def test_24_existing_neutral_profile_drift_fails(self) -> None:
        path = "design/candidates/ai-project-workspace-profile.json"
        data = self.load(path)
        data["ptah_role"] = "intelligent_workspace_coordinator"
        self.save(path, data)
        self.assert_invalid()

    def test_25_catalog_count_change_fails(self) -> None:
        path = "contracts/generated/catalog-index.json"
        data = self.load(path)
        data["schema_count"] = 347
        self.save(path, data)
        self.assert_invalid()


if __name__ == "__main__":
    unittest.main()
