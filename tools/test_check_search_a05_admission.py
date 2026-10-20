"""Adversarial Search PR scope tests: no scope bypass."""
import unittest
from tools.check_search_a05_admission import (
    SEARCH_PATHS,REMEDIATION_PATHS,AGENT_NEUTRAL_MAINTENANCE_PATHS,
    approved_paths,AdmissionError
)
class SearchScopeTests(unittest.TestCase):
    def test_original_search_only(self):
        v=approved_paths(set(SEARCH_PATHS))
        self.assertEqual(v["historical_phase_delta"],"NONE")
        self.assertFalse(v["rust_remediation_complete"])
    def test_complete_security_remediation(self):
        v=approved_paths(set(SEARCH_PATHS|REMEDIATION_PATHS))
        self.assertTrue(v["rust_remediation_complete"])
        self.assertEqual(v["historical_proof_disposition"],"NOT_APPLICABLE_TO_THIS_DELTA_NOT_TESTED")
    def test_agent_neutral_maintenance_is_not_reclassified_as_original_a05_proof(self):
        v=approved_paths(set(AGENT_NEUTRAL_MAINTENANCE_PATHS))
        self.assertEqual(v["scope_mode"], "agent_neutral_postbaseline_maintenance")
        self.assertEqual(v["historical_proof_disposition"], "A05_ORIGINAL_SCOPE_NOT_REPLAYED")
        self.assertFalse(v["rust_remediation_complete"])
    def test_missing_or_extra_agent_maintenance_paths_are_rejected(self):
        with self.assertRaises(AdmissionError):
            approved_paths(set(AGENT_NEUTRAL_MAINTENANCE_PATHS)-{"adapters/internet-search/bridge.py"})
        with self.assertRaises(AdmissionError):
            approved_paths(set(AGENT_NEUTRAL_MAINTENANCE_PATHS)|{"tools/unrelated_authority.py"})
    def test_historical_scope_still_requires_original_exact_delta(self):
        with self.assertRaises(AdmissionError):
            approved_paths(set(SEARCH_PATHS)-{"README.md"})
    def test_reject_partial_rust_remediation(self):
        with self.assertRaises(AdmissionError):
            approved_paths(set(SEARCH_PATHS)|{"Cargo.lock"})
    def test_reject_changed_phase_proof_file(self):
        with self.assertRaises(AdmissionError):
            approved_paths(set(SEARCH_PATHS)|{".github/workflows/e01-secure-multi-node-identity-connection.yml"})
    def test_reject_frozen_contract_change(self):
        with self.assertRaises(AdmissionError):
            approved_paths(set(SEARCH_PATHS)|{"contracts/upstream-lock.json"})
    def test_reject_missing_bridge(self):
        with self.assertRaises(AdmissionError):
            approved_paths(set(SEARCH_PATHS)-{"adapters/internet-search/bridge.py"})
    def test_reject_arbitrary_new_provider(self):
        with self.assertRaises(AdmissionError):
            approved_paths(set(SEARCH_PATHS)|{"adapters/browser-provider/new.py"})
    def test_reject_empty(self):
        with self.assertRaises(AdmissionError):
            approved_paths(set())
if __name__=="__main__":unittest.main()
