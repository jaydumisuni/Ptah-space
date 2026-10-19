"""Adversarial current-head applicability checks: preserve historical proof bodies."""
import contextlib
import importlib.util
import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
# Immutable pre-governance reference. Never compare the current branch to
# floating origin/main after the workflow applicability migration merges.
HISTORIC_PRE_GOVERNANCE_BASE="e7d2381680d95de6128cb4d62cadb518344c1416"
spec=importlib.util.spec_from_file_location("current_pr_admission",ROOT/"tools/check_current_pr_admission.py")
assert spec and spec.loader
policy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ApplicabilityProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.history={}
        for name in policy.HISTORIC:
            before=subprocess.check_output(
                ["git","show",HISTORIC_PRE_GOVERNANCE_BASE+":.github/workflows/"+name],
                cwd=ROOT,text=True,timeout=20)
            after=(ROOT/".github/workflows"/name).read_text()
            cls.history[name]=(before,after)

    def test_historical_base_is_fixed_pre_governance_ancestor(self):
        self.assertEqual(HISTORIC_PRE_GOVERNANCE_BASE,
                         "e7d2381680d95de6128cb4d62cadb518344c1416")
        proc=subprocess.run(["git","merge-base","--is-ancestor",
                             HISTORIC_PRE_GOVERNANCE_BASE,"HEAD"],
                            cwd=ROOT,timeout=20,check=False)
        self.assertEqual(proc.returncode,0)

    def test_all_22_only_exact_reviewed_pr_events_changed(self):
        self.assertEqual(len(policy.HISTORIC),22)
        self.assertEqual(len(policy.E_OWNED),5)
        for name,(before,after) in self.history.items():
            with self.subTest(name=name):
                current=policy.approved_phase_scope(name,before,after)
                self.assertIn(".github/workflows/"+name,current)
                self.assertNotIn("Cargo.toml",current)
                self.assertNotIn("Cargo.lock",current)
                self.assertNotIn("dependencies/**",current)

    def test_modified_proof_step_rejected(self):
        name="e01-secure-multi-node-identity-connection.yml"
        before,after=self.history[name]
        corrupted=after.replace("timeout-minutes: 120","timeout-minutes: 1")
        with self.assertRaisesRegex(policy.AdmissionError,"historical_proof_body"):
            policy.approved_phase_scope(name,before,corrupted)

    def test_attempt_to_drop_phase_owner_trigger_rejected(self):
        name="e04-proof.yml"
        before,after=self.history[name]
        corrupted=after.replace('      - "crates/ptah-workspace-movement/src/**"\n',"")
        with self.assertRaisesRegex(policy.AdmissionError,"ownership_trigger_drift"):
            policy.approved_phase_scope(name,before,corrupted)

    def test_broad_trigger_reintroduced_rejected(self):
        name="a07-object-store-proof.yml"
        before,after=self.history[name]
        corrupted=after.replace('      - ".github/workflows/a07-object-store-proof.yml"',
                                '      - "Cargo.lock"\n      - ".github/workflows/a07-object-store-proof.yml"')
        with self.assertRaisesRegex(policy.AdmissionError,"ownership_trigger_drift"):
            policy.approved_phase_scope(name,before,corrupted)

    def test_phase_owner_change_is_not_admitted_with_global_cargo(self):
        name="a09-git-provider-proof.yml"
        _,after=self.history[name]
        self.assertTrue(policy.scope_affected(name,policy.pull_paths(after),
                                             {"adapters/git-cli/handler.py"}))
        self.assertFalse(policy.scope_affected(name,policy.pull_paths(after),
                                              {"Cargo.lock","Cargo.toml"}))

    def test_e05_dependency_manifest_only_not_legacy_exact_phase(self):
        name="e05-proof.yml"
        _,after=self.history[name]
        self.assertFalse(policy.scope_affected(name,policy.pull_paths(after),
                    {"crates/ptah-platform-admission/Cargo.toml"}))
        self.assertTrue(policy.scope_affected(name,policy.pull_paths(after),
                    {"crates/ptah-platform-admission/src/lib.rs"}))

    def test_nonexistent_phase_name_fails_closed(self):
        with self.assertRaisesRegex(policy.AdmissionError,"unreviewed_phase_workflow"):
            policy.approved_phase_scope("evil.yml","on:\n","on:\n")

    def test_exact_head_short_or_nonhex_rejected(self):
        for base,head in (("abc","f"*40),("a"*40,"z"*40)):
            with self.assertRaisesRegex(policy.AdmissionError,"invalid_exact_commit"):
                policy.qualify(base,head)

    def test_search_adapter_phase_is_separately_qualified(self):
        txt=(ROOT/".github/workflows/current-head-universal-admission.yml").read_text()
        self.assertIn("tools/check_search_a05_admission.py",txt)
        self.assertIn("tools/check_rust_dependency_lock.py",txt)
        self.assertIn("tools/check_a01_scaffold.py",txt)
        self.assertIn("tools/check_phase0c_scaffold.py",txt)
        self.assertIn("pull_request:\n    branches: [main]",txt)
        self.assertNotIn("paths:\n",txt.split("permissions:",1)[0])

    def test_knights_runtime_path_scope_is_exact_and_independent(self):
        paths=policy.KNIGHTS_RUNTIME_MAINTENANCE_PATHS
        self.assertEqual(len(paths),15)
        self.assertIn("adapters/ptah-hunter-workspace/src/main.rs",paths)
        self.assertIn("crates/ptah-package-plugin/src/activation.rs",paths)
        self.assertIn("browser-provider/test/workspace-default-route.test.mjs",paths)
        self.assertNotIn(".github/workflows/d02-ai-project-workspace-proof.yml",paths)
        self.assertNotIn("crates/ptah-workspace/src/lib.rs",paths)

    def test_knights_lane_is_not_historical_proof_rewrite(self):
        src=(ROOT/"tools/check_current_pr_admission.py").read_text()
        self.assertIn("KNIGHTS_POST_BASELINE_RUNTIME_TESTS_REQUIRED_HISTORIC_NOT_REPLAYED",src)
        self.assertIn("knights_maintenance and not historic_changes",src)
        self.assertIn("independent_phase_owned_change_requires_own_proof",src)
        self.assertEqual(len(policy.HISTORIC),22)

    def test_phase_owned_on_governance_must_remain_separately_proved(self):
        script=(ROOT/"tools/check_current_pr_admission.py").read_text()
        self.assertIn('if name == "a11-browser-provider-proof.yml" and not historic_changes:',script)
        self.assertIn("A11_POST_BASELINE_PHYSICAL_PROOF_REQUIRED",script)
        self.assertIn("independent_phase_owned_change_requires_own_proof",script)


if __name__ == "__main__":
    unittest.main()
