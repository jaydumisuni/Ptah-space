"""Adversarial A11 post-baseline maintenance acceptance scope tests."""
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("a11maint",ROOT/"tools/check_a11_maintenance_admission.py")
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class A11MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.good={"browser-provider/src/owned_chromium.mjs",
                   "browser-provider/src/playwright_backend.mjs",
                   "browser-provider/test/owned-chromium.test.mjs",
                   "tools/ptah_workspace_browser.mjs",
                   ".github/workflows/ptah-owned-browser-current.yml"}
    def test_good_strictly_owned_delta(self):
        module.validate_paths(self.good)
    def test_historic_proof_cannot_be_modified(self):
        with self.assertRaisesRegex(module.AdmissionError,"locked_phase"):
            module.validate_paths(self.good|{".github/workflows/a11-browser-provider-proof.yml"})
    def test_governance_self_mutation_not_admitted(self):
        with self.assertRaisesRegex(module.AdmissionError,"locked_phase"):
            module.validate_paths(self.good|{"tools/check_a11_maintenance_admission.py"})
    def test_unrelated_phase_cannot_be_laundered(self):
        for path in ("crates/ptah-browser-runtime/src/lib.rs",
                     "services/ptah-control/src/server.rs","adapters/internet-search/bridge.py",
                     "tools/check_a01_scaffold.py",".github/workflows/current-head-universal-admission.yml"):
            with self.subTest(path=path),self.assertRaises(module.AdmissionError):
                module.validate_paths(self.good|{path})
    def test_binary_modules_and_runtime_rejected(self):
        for path in ("browser-provider/.workspace/browser-runtime/chrome",
                     "browser-provider/node_modules/playwright/index.js",
                     "browser-provider/bin/payload.dat"):
            with self.subTest(path=path),self.assertRaises(module.AdmissionError):
                module.validate_paths(self.good|{path})
    def test_missing_product_change_rejected(self):
        with self.assertRaisesRegex(module.AdmissionError,"no_a11_runtime"):
            module.validate_paths({"browser-provider/README.md",
                                   "tools/ptah_workspace_browser.mjs"})
    def test_exact_head_scope_records_historic_non_applicability(self):
        b="a"*40;h="b"*40
        def fake_git(*args):
            if args[:2]==("rev-parse","HEAD"):return h
            if args[0]=="merge-base":return b
            if args[0]=="diff" and "--name-only" in args:return "\n".join(sorted(self.good))
            if args[0]=="diff" and "--check" in args:return ""
            raise AssertionError(args)
        with patch.object(module,"git",side_effect=fake_git):
            output=module.qualify(b,h)
        self.assertTrue(output["separate_a11_physical_proof_required"])
        self.assertFalse(output["personal_or_oracle_browser_use_authorized"])
        self.assertEqual(output["historic_a11_proof"],
                         "UNCHANGED_AND_NOT_APPLICABLE_TO_POST_BASELINE")
    def test_head_drift_rejected(self):
        with patch.object(module,"git",return_value="f"*40):
            with self.assertRaisesRegex(module.AdmissionError,"head_drift"):
                module.qualify("a"*40,"b"*40)
    def test_independently_trusted_base_branch_integrity_gate(self):
        workflow=(ROOT/".github/workflows/a11-governance-integrity.yml").read_text()
        self.assertIn("pull_request_target:",workflow)
        self.assertIn("ref: ${{ env.PTAH_BASE }}",workflow)
        self.assertNotIn("ref: ${{ env.PTAH_HEAD }}",workflow)
        for protected in (".github/workflows/a11-post-baseline-maintenance.yml",
                          ".github/workflows/a11-governance-integrity.yml",
                          ".github/workflows/current-head-universal-admission.yml",
                          "tools/check_a11_maintenance_admission.py",
                          "tools/check_current_pr_admission.py"):
            self.assertIn(protected,workflow)
        self.assertIn("BASE_AUTHORITY_REJECTED_SELF_MODIFICATION",workflow)
    def test_invalid_sha(self):
        with self.assertRaisesRegex(module.AdmissionError,"invalid_exact_sha"):
            module.qualify("a"*8,"b"*40)
if __name__=="__main__":unittest.main()
