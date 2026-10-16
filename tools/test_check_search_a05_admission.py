"""Adversarial Search PR scope tests: no scope bypass."""
import unittest
from tools.check_search_a05_admission import (
    SEARCH_PATHS,REMEDIATION_PATHS,GOVERNANCE_PATHS,A05_SCOPE_GATE_PATHS,approved_paths,AdmissionError
)
class SearchScopeTests(unittest.TestCase):
    def test_original_search_only(self):
        v=approved_paths(set(SEARCH_PATHS))
        self.assertEqual(v["e01_to_e05_source_or_workflow_delta"],"NONE")
        self.assertFalse(v["rust_remediation_complete"])
    def test_complete_security_remediation(self):
        v=approved_paths(set(SEARCH_PATHS|REMEDIATION_PATHS))
        self.assertTrue(v["rust_remediation_complete"])
        self.assertEqual(v["historical_proof_disposition"],"HISTORICAL_PHASE_PROOFS_UNCHANGED_NOT_SUPERSEDED")
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
    def test_exact_approved_search_remediation_and_governance(self):
        approved=SEARCH_PATHS|REMEDIATION_PATHS|GOVERNANCE_PATHS|A05_SCOPE_GATE_PATHS
        verdict=approved_paths(set(approved))
        self.assertTrue(verdict["governance_complete"])
        self.assertTrue(verdict["rust_remediation_complete"])
        self.assertEqual(verdict["e01_to_e05_source_or_workflow_delta"],"NONE")
    def test_reject_partial_signed_evidence_governance(self):
        changed=set(SEARCH_PATHS|REMEDIATION_PATHS|GOVERNANCE_PATHS|A05_SCOPE_GATE_PATHS)
        changed.remove("conformance/immutable-source-manifests/kernel-org-autosigner-public.gpg")
        with self.assertRaises(AdmissionError):approved_paths(changed)
    def test_reject_historical_phase_workflow_even_if_other_changes_approved(self):
        changed=set(SEARCH_PATHS|REMEDIATION_PATHS|GOVERNANCE_PATHS|A05_SCOPE_GATE_PATHS)
        changed.add(".github/workflows/e01-secure-multi-node-identity-connection.yml")
        with self.assertRaises(AdmissionError):approved_paths(changed)
    def test_reject_unreviewed_governance_test(self):
        changed=set(SEARCH_PATHS|REMEDIATION_PATHS|GOVERNANCE_PATHS|A05_SCOPE_GATE_PATHS)
        changed.add("tools/silent_bypass.py")
        with self.assertRaises(AdmissionError):approved_paths(changed)
if __name__=="__main__":unittest.main()
