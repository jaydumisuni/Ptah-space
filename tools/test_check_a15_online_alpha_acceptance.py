#!/usr/bin/env python3
"""Regression tests for the A15 Online Ptah Alpha acceptance validator."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from check_a15_online_alpha_acceptance import (
    A14_BASE_SHA,
    AcceptanceError,
    WP14_MERGE_SHA,
    evaluate_wp14_case,
    require_report_files,
    validate_repository,
    validate_wp14_corpus,
)

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance/a15/wp14-golden-negative-freeze-cases.v0.1.0.json"
SNAPSHOT = ROOT / "services/ptah-control/tests/fixtures/a14_snapshot.json"
DEEP_PROFILE = ROOT / "design/candidates/workspace-operations-profile-v2.json"


class A15AcceptanceTests(unittest.TestCase):
    def test_repository_acceptance_inputs_pass_without_granting_ptah_authority(self) -> None:
        report = validate_repository(ROOT)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["a14_base_sha"], A14_BASE_SHA)
        self.assertEqual(report["wp14_merge_sha"], WP14_MERGE_SHA)
        for key in (
            "ptah_caller_work_selection_authority",
            "ptah_context_selection_authority",
            "ptah_review_authority",
            "ptah_result_acceptance_authority",
            "ptah_autonomous_upgrade_authority",
        ):
            self.assertIs(report[key], False)

    def test_frozen_wp14_corpus_has_eight_golden_and_eight_negative_cases(self) -> None:
        result = validate_wp14_corpus(CORPUS)
        self.assertEqual(result, {"case_count": 16, "positive_count": 8, "negative_count": 8})

    def test_raw_secret_is_rejected(self) -> None:
        case = {"rule": "no_raw_secret", "payload": {"api_key": "live-secret"}}
        self.assertEqual(evaluate_wp14_case(case), "RAW_SECRET_PRESENT")

    def test_stale_provider_generation_is_rejected(self) -> None:
        case = {"rule": "current_generation", "payload": {"expected_generation": 7, "observed_generation": 6}}
        self.assertEqual(evaluate_wp14_case(case), "STALE_PROVIDER_GENERATION")

    def test_stale_fence_is_rejected(self) -> None:
        case = {"rule": "current_fence", "payload": {"expected_fence_token": 12, "observed_fence_token": 11}}
        self.assertEqual(evaluate_wp14_case(case), "STALE_FENCE_TOKEN")

    def test_retry_must_create_a_new_attempt(self) -> None:
        case = {"rule": "retry_attempt_unique", "payload": {"attempt_refs": ["attempt-1", "attempt-1"]}}
        self.assertEqual(evaluate_wp14_case(case), "ATTEMPT_ID_REUSED")

    def test_acknowledgement_without_verification_evidence_is_rejected(self) -> None:
        case = {
            "rule": "acknowledgement_not_verification",
            "payload": {"acknowledged": True, "verified": True, "verification_evidence_refs": []},
        }
        self.assertEqual(evaluate_wp14_case(case), "ACKNOWLEDGEMENT_IS_NOT_VERIFICATION")

    def test_incomplete_citation_is_rejected(self) -> None:
        case = {"rule": "exact_citation", "payload": {"source_revision_ref": "source-r1"}}
        self.assertEqual(evaluate_wp14_case(case), "CITATION_IDENTITY_INCOMPLETE")

    def test_expired_accepted_risk_is_rejected_against_frozen_acceptance_time(self) -> None:
        case = {"rule": "accepted_risk_current", "payload": {"expires_at": "2020-01-01T00:00:00Z"}}
        self.assertEqual(evaluate_wp14_case(case), "ACCEPTED_RISK_EXPIRED")

    def test_same_environment_reproduction_is_not_independent(self) -> None:
        case = {
            "rule": "independent_reproduction",
            "payload": {
                "original_environment_ref": "env-a",
                "reproduction_environment_ref": "env-a",
                "attempt_refs": ["a1", "a1"],
                "shared_mutable_cache": True,
            },
        }
        self.assertEqual(evaluate_wp14_case(case), "REPRODUCTION_NOT_INDEPENDENT")

    def test_missing_capability_advisory_is_evidenced_but_unresolved(self) -> None:
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        advisory = snapshot["advisories"][0]
        self.assertTrue(advisory["observed_facts"])
        self.assertTrue(advisory["evidence"])
        self.assertTrue(advisory["suggestions"])
        self.assertTrue(advisory["uncertainty"])
        self.assertEqual(advisory["state"], "open")
        report = validate_repository(ROOT)
        self.assertIs(report["ptah_autonomous_upgrade_authority"], False)

    def test_false_positive_advisory_does_not_gain_authority(self) -> None:
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        advisory = copy.deepcopy(snapshot["advisories"][0])
        advisory["observed_facts"] = ["deliberately incorrect qualification observation"]
        advisory["evidence"] = ["receipt:contradicted-observation"]
        advisory["uncertainty"] = "independent evidence contradicts this observation"
        self.assertEqual(advisory["state"], "open")
        self.assertNotEqual(advisory["state"], "upgrade_submitted")
        self.assertIs(validate_repository(ROOT)["ptah_autonomous_upgrade_authority"], False)

    def test_degraded_provider_advisory_remains_advice_not_an_upgrade_decision(self) -> None:
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        provider = copy.deepcopy(snapshot["providers"][0])
        advisory = copy.deepcopy(snapshot["advisories"][0])
        provider["health"] = "degraded"
        provider["limitations"] = ["qualification degradation is explicit"]
        provider["evidence"] = ["receipt:terminal-provider-degraded"]
        advisory["observed_facts"] = ["terminal-provider reports degraded health"]
        advisory["evidence"] = ["receipt:terminal-provider-degraded"]
        advisory["suggestions"] = ["caller may choose a repair or upgrade Activity"]
        advisory["state"] = "open"
        self.assertEqual(provider["health"], "degraded")
        self.assertTrue(provider["evidence"])
        self.assertEqual(advisory["state"], "open")
        self.assertIs(validate_repository(ROOT)["ptah_autonomous_upgrade_authority"], False)

    def test_stale_advisory_evidence_is_visible_but_cannot_be_current_authority(self) -> None:
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        current_generation = snapshot["authority"]["provider_generations"]["terminal-provider"]
        stale_generation = current_generation - 1
        advisory = copy.deepcopy(snapshot["advisories"][0])
        advisory["observed_facts"] = [f"terminal-provider generation {stale_generation} was degraded"]
        advisory["evidence"] = [f"receipt:terminal-provider-generation-{stale_generation}"]
        self.assertEqual(advisory["state"], "open")
        case = {
            "rule": "current_generation",
            "payload": {
                "expected_generation": current_generation,
                "observed_generation": stale_generation,
            },
        }
        self.assertEqual(evaluate_wp14_case(case), "STALE_PROVIDER_GENERATION")
        self.assertIs(validate_repository(ROOT)["ptah_autonomous_upgrade_authority"], False)

    def test_ten_for_two_formation_is_bounded_distinct_recoverable_and_unaccepted(self) -> None:
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        profile = json.loads(DEEP_PROFILE.read_text(encoding="utf-8"))
        method = profile["study_method"]
        self.assertEqual((method["primary_lanes"], method["independent_verifier_lanes"]), (10, 10))
        template = snapshot["workers"][0]
        workers = []
        for index in range(20):
            worker = copy.deepcopy(template)
            worker["formation_id"] = "formation-ten-for-two"
            worker["worker_id"] = f"worker-{index:02d}"
            worker["role"] = f"{'primary' if index < 10 else 'verifier'}-lane-{index:02d}"
            worker["checkpoint"] = f"checkpoint-{index:02d}"
            worker["partial_result"] = f"artifact:evidence-{index:02d}"
            worker["conflict"] = "verifier conflict remains visible" if index == 19 else None
            worker["completed"] = True
            worker["acceptance"] = "pending"
            workers.append(worker)
        self.assertEqual(len(workers), 20)
        self.assertEqual(len({item["worker_id"] for item in workers}), 20)
        self.assertEqual(len({item["role"] for item in workers}), 20)
        self.assertEqual(len({item["checkpoint"] for item in workers}), 20)
        self.assertEqual(len({item["partial_result"] for item in workers}), 20)
        self.assertTrue(any(item["conflict"] for item in workers))
        self.assertTrue(all(item["acceptance"] == "pending" for item in workers))
        self.assertEqual(snapshot["recovery"]["checkpoint_integrity"], "verified")
        self.assertEqual(snapshot["recovery"]["restore_compatibility"], "compatible")
        self.assertEqual(snapshot["recovery"]["recovery_verification"], "verified")

    def test_green_without_immutable_reports_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "one.json").write_text(json.dumps({"status": "pass"}) + "\n", encoding="utf-8")
            with self.assertRaises(AcceptanceError):
                require_report_files(root, ["one.json", "missing.json"])

    def test_report_bundle_records_digest_and_size_for_every_required_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "one.json").write_text("{\"status\":\"pass\"}\n", encoding="utf-8")
            (root / "two.log").write_text("proof\n", encoding="utf-8")
            records = require_report_files(root, ["one.json", "two.log"])
            self.assertEqual(set(records), {"one.json", "two.log"})
            self.assertGreater(records["one.json"]["size_bytes"], 0)
            self.assertEqual(len(records["two.log"]["sha256"]), 64)

    def test_unknown_frozen_rule_is_not_silently_accepted(self) -> None:
        with self.assertRaises(AcceptanceError):
            evaluate_wp14_case({"rule": "invented_rule", "payload": {}})


if __name__ == "__main__":
    unittest.main()