#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "run_development_host_probe.py"
SPEC = importlib.util.spec_from_file_location("run_development_host_probe", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class DevelopmentHostProbeTests(unittest.TestCase):
    def test_contract_is_os_neutral_and_non_authorizing(self) -> None:
        contract = json.loads((ROOT / "host" / "development-host-contract.json").read_text(encoding="utf-8"))
        self.assertEqual(contract["record_type"], "ptah.phase0c.development_host_contract")
        self.assertFalse(contract["host_model"]["specific_os_distribution_required"])
        self.assertFalse(contract["host_model"]["specific_kernel_required"])
        self.assertFalse(contract["host_model"]["dedicated_guest_os_required"])
        self.assertFalse(contract["claim_boundary"]["runtime_implementation_authorized"])

    def test_required_portable_checks_pass_on_supported_ci_host(self) -> None:
        contract = json.loads((ROOT / "host" / "development-host-contract.json").read_text(encoding="utf-8"))
        for name in contract["required_capabilities"]:
            with self.subTest(capability=name):
                result = probe.CHECKS[name]()
                self.assertEqual(result["status"], "pass", result)

    def test_physical_style_report_binds_clean_exact_checkout(self) -> None:
        head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory(prefix="ptah-dev-host-test-") as directory:
            output = Path(directory) / "report.json"
            report = probe.build_report(
                repo_root=ROOT,
                contract_path=Path("host/development-host-contract.json"),
                output=output,
                expected_commit=head,
                machine_label="ci-test-host",
                control_transport="ci-diagnostic",
                transport_receipt_id=None,
            )
        self.assertTrue(report["development_host_eligible"], report["eligibility_failures"])
        self.assertFalse(report["runtime_implementation_authorized"])
        self.assertFalse(report["deployment_host_qualified"])
        self.assertEqual(report["repository_binding"]["before"]["head"], head)
        self.assertEqual(report["repository_binding"]["after"]["head"], head)
        self.assertTrue(report["repository_binding"]["before"]["clean"])
        self.assertTrue(report["repository_binding"]["after"]["clean"])

    def test_physical_proof_rejects_output_inside_checkout(self) -> None:
        head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        report = probe.build_report(
            repo_root=ROOT,
            contract_path=Path("host/development-host-contract.json"),
            output=ROOT / "evidence" / "development-host-probe.json",
            expected_commit=head,
            machine_label="ci-test-host",
            control_transport=None,
            transport_receipt_id=None,
        )
        self.assertFalse(report["development_host_eligible"])
        self.assertIn(
            "repository:physical_proof_output_must_be_outside_repository",
            report["eligibility_failures"],
        )

    def test_control_plane_metadata_never_authorizes(self) -> None:
        head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory(prefix="ptah-dev-host-test-") as directory:
            report = probe.build_report(
                repo_root=ROOT,
                contract_path=Path("host/development-host-contract.json"),
                output=Path(directory) / "report.json",
                expected_commit=head,
                machine_label="ci-test-host",
                control_transport="mcp-rpc",
                transport_receipt_id="example-receipt",
            )
        self.assertEqual(report["control_plane_observation"]["transport"], "mcp-rpc")
        self.assertTrue(report["control_plane_observation"]["caller_supplied_metadata_only"])
        self.assertFalse(report["runtime_implementation_authorized"])
        self.assertFalse(report["release_accepted"])


if __name__ == "__main__":
    unittest.main()
