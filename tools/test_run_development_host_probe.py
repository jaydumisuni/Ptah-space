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
SPEC = importlib.util.spec_from_file_location(
    "run_development_host_probe", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class DevelopmentHostProbeTests(unittest.TestCase):
    def test_contract_is_os_neutral_and_non_authorizing(self) -> None:
        contract = json.loads(
            (ROOT / "host" / "development-host-contract.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            contract["record_type"],
            "ptah.phase0c.development_host_contract",
        )
        self.assertFalse(
            contract["host_model"]["specific_os_distribution_required"]
        )
        self.assertFalse(contract["host_model"]["specific_kernel_required"])
        self.assertFalse(
            contract["host_model"]["dedicated_guest_os_required"]
        )
        self.assertFalse(
            contract["host_model"]["probe_can_prove_physical_machine_identity"]
        )
        self.assertFalse(
            contract["claim_boundary"]["runtime_implementation_authorized"]
        )

    def test_required_portable_checks_pass_on_supported_ci_host(self) -> None:
        contract = json.loads(
            (ROOT / "host" / "development-host-contract.json").read_text(
                encoding="utf-8"
            )
        )
        for name in contract["required_capabilities"]:
            with self.subTest(capability=name):
                result = probe.CHECKS[name]()
                self.assertEqual(result["status"], "pass", result)

    def test_exact_checkout_can_pass_portable_probe_only(self) -> None:
        head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory(
            prefix="ptah-dev-host-test-"
        ) as directory:
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
        self.assertTrue(
            report["portable_capabilities_passed"], report["probe_failures"]
        )
        self.assertFalse(report["physical_host_identity_verified"])
        self.assertFalse(report["development_host_accepted"])
        self.assertFalse(report["runtime_implementation_authorized"])
        self.assertFalse(report["deployment_host_qualified"])
        self.assertEqual(
            report["repository_binding"]["before"]["head"], head
        )
        self.assertEqual(
            report["repository_binding"]["after"]["head"], head
        )
        self.assertTrue(report["repository_binding"]["before"]["clean"])
        self.assertTrue(report["repository_binding"]["after"]["clean"])

    def test_acceptance_style_probe_rejects_output_inside_checkout(self) -> None:
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
        self.assertFalse(report["portable_capabilities_passed"])
        self.assertIn(
            "repository:acceptance_evidence_output_must_be_outside_repository",
            report["probe_failures"],
        )

    def test_external_receipt_metadata_never_accepts_host(self) -> None:
        head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory(
            prefix="ptah-dev-host-test-"
        ) as directory:
            report = probe.build_report(
                repo_root=ROOT,
                contract_path=Path("host/development-host-contract.json"),
                output=Path(directory) / "report.json",
                expected_commit=head,
                machine_label="ci-test-host",
                control_transport="example-rpc",
                transport_receipt_id="example-receipt",
            )
        external = report["external_execution_observation"]
        self.assertEqual(external["transport"], "example-rpc")
        self.assertEqual(external["external_receipt_id"], "example-receipt")
        self.assertTrue(external["caller_supplied_metadata_only"])
        self.assertTrue(external["receipt_not_validated_by_public_probe"])
        self.assertFalse(report["physical_host_identity_verified"])
        self.assertFalse(report["development_host_accepted"])
        self.assertFalse(report["runtime_implementation_authorized"])
        self.assertFalse(report["release_accepted"])


if __name__ == "__main__":
    unittest.main()
