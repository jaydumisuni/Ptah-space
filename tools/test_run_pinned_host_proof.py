from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("run_pinned_host_proof.py")
SPEC = importlib.util.spec_from_file_location("run_pinned_host_proof", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def passing_capability_payload() -> dict[str, object]:
    return {
        "record_type": "ptah.phase0c.host_capability_report",
        "runtime_implementation_authorized": False,
        "required_capabilities_passed": True,
        "proof_eligible": True,
        "pinned_host_match": {"all_match": True},
        "required_failures": [],
    }


def passing_package_artifact_payload(count: int = 1) -> dict[str, object]:
    return {
        "record_type": "ptah.phase0c.installed_package_artifact_manifest",
        "runtime_implementation_authorized": False,
        "network_used": False,
        "package_count": count,
        "artifact_count": count,
        "missing_count": 0,
        "complete": True,
        "missing": [],
        "apt_index_inventory": {"present": True},
    }


class PinnedHostProofTests(unittest.TestCase):
    def test_exact_frozen_host_identity_passes(self) -> None:
        os_release = {
            "ID": "ubuntu",
            "VERSION_ID": "24.04",
            "VERSION": "24.04.4 LTS (Noble Numbat)",
            "PRETTY_NAME": "Ubuntu 24.04.4 LTS",
        }
        self.assertEqual(
            MODULE.validate_host(os_release, "6.8.0-136-generic", "x86_64"), []
        )

    def test_generic_host_is_not_proof_eligible(self) -> None:
        os_release = {
            "ID": "ubuntu",
            "VERSION_ID": "24.04",
            "VERSION": "24.04.3 LTS",
            "PRETTY_NAME": "Ubuntu 24.04.3 LTS",
        }
        failures = MODULE.validate_host(os_release, "6.17.0-azure", "x86_64")
        self.assertTrue(any(item.startswith("point_release_not_found") for item in failures))
        self.assertTrue(any(item.startswith("kernel=") for item in failures))

    def test_package_digest_is_order_sensitive_until_records_are_sorted(self) -> None:
        first = [{"package": "a"}, {"package": "b"}]
        second = list(reversed(first))
        self.assertNotEqual(MODULE.canonical_sha256(first), MODULE.canonical_sha256(second))
        self.assertEqual(
            MODULE.canonical_sha256(sorted(first, key=lambda item: item["package"])),
            MODULE.canonical_sha256(sorted(second, key=lambda item: item["package"])),
        )

    def test_json_writer_uses_stable_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "record.json"
            MODULE.write_json(
                target, {"runtime_implementation_authorized": False, "value": "Ptah"}
            )
            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertIs(payload["runtime_implementation_authorized"], False)
            self.assertTrue(target.read_bytes().endswith(b"\n"))

    def test_real_collector_path_is_selected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "host" / "scripts" / "collect_capabilities.py"
            legacy = root / "tools" / "collect_host_capabilities.py"
            real.parent.mkdir(parents=True)
            legacy.parent.mkdir(parents=True)
            real.write_text("# real\n", encoding="utf-8")
            legacy.write_text("# legacy\n", encoding="utf-8")
            self.assertEqual(MODULE.locate_capability_collector(root), real)

    def test_missing_real_collector_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                MODULE.ProofError, "host/scripts/collect_capabilities.py"
            ):
                MODULE.locate_capability_collector(Path(directory))

    def test_legacy_only_collector_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "tools" / "collect_host_capabilities.py"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("# stale legacy collector\n", encoding="utf-8")
            with self.assertRaisesRegex(
                MODULE.ProofError, "host/scripts/collect_capabilities.py"
            ):
                MODULE.locate_capability_collector(root)

    def test_package_artifact_collector_path_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector = root / "tools" / "collect_apt_package_artifacts.py"
            collector.parent.mkdir(parents=True)
            collector.write_text("# accepted\n", encoding="utf-8")
            self.assertEqual(MODULE.locate_package_artifact_collector(root), collector)

    def test_missing_package_artifact_collector_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                MODULE.ProofError, "tools/collect_apt_package_artifacts.py"
            ):
                MODULE.locate_package_artifact_collector(Path(directory))

    def test_capability_payload_must_be_proof_eligible(self) -> None:
        self.assertEqual(MODULE.validate_capability_payload(passing_capability_payload()), [])
        payload = passing_capability_payload()
        payload["required_capabilities_passed"] = False
        payload["proof_eligible"] = False
        payload["pinned_host_match"] = {"all_match": False}
        payload["required_failures"] = ["systemd"]
        failures = MODULE.validate_capability_payload(payload)
        self.assertIn("required_capabilities_not_passed", failures)
        self.assertIn("capability_report_not_proof_eligible", failures)
        self.assertIn("capability_pinned_host_identity_not_matched", failures)
        self.assertIn("capability_required_failures_present_or_invalid", failures)

    def test_package_artifact_payload_must_be_complete(self) -> None:
        self.assertEqual(
            MODULE.validate_package_artifact_payload(
                passing_package_artifact_payload(2), 2
            ),
            [],
        )
        payload = passing_package_artifact_payload(2)
        payload["artifact_count"] = 1
        payload["missing_count"] = 1
        payload["complete"] = False
        payload["missing"] = [{"package": "beta"}]
        payload["apt_index_inventory"] = {"present": False}
        failures = MODULE.validate_package_artifact_payload(payload, 2)
        self.assertIn("package_artifact_count_incomplete", failures)
        self.assertIn("package_artifact_missing_count_nonzero", failures)
        self.assertIn("package_artifact_manifest_incomplete", failures)
        self.assertIn("package_artifact_missing_records_present_or_invalid", failures)
        self.assertIn("apt_index_inventory_missing", failures)

    def test_capability_failure_blocks_bundle_eligibility(self) -> None:
        failures = MODULE.proof_failures(
            [], False, ["required_capabilities_not_passed"], []
        )
        self.assertEqual(
            failures, ["capability:required_capabilities_not_passed"]
        )

    def test_package_artifact_failure_blocks_bundle_eligibility(self) -> None:
        failures = MODULE.proof_failures(
            [], False, [], ["package_artifact_manifest_incomplete"]
        )
        self.assertEqual(
            failures,
            ["package_artifact:package_artifact_manifest_incomplete"],
        )

    def test_dirty_repository_blocks_bundle_eligibility(self) -> None:
        self.assertEqual(
            MODULE.proof_failures([], True, [], []), ["repository_dirty"]
        )

    def test_invoke_uses_real_collector_cli_and_validates_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector = root / "host" / "scripts" / "collect_capabilities.py"
            collector.parent.mkdir(parents=True)
            collector.write_text(
                """#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
payload = {
    'record_type': 'ptah.phase0c.host_capability_report',
    'runtime_implementation_authorized': False,
    'required_capabilities_passed': True,
    'proof_eligible': True,
    'pinned_host_match': {'all_match': True},
    'required_failures': [],
}
args.output.write_text(json.dumps(payload) + '\\n', encoding='utf-8')
""",
                encoding="utf-8",
            )
            output = root / "evidence"
            output.mkdir()
            result = MODULE.invoke_capability_collector(root, output)
            self.assertEqual(
                result["collector_path"], "host/scripts/collect_capabilities.py"
            )
            self.assertEqual(result["collector_returncode"], 0)
            self.assertEqual(result["validation_failures"], [])

    def test_invoke_package_artifact_collector_validates_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector = root / "tools" / "collect_apt_package_artifacts.py"
            collector.parent.mkdir(parents=True)
            collector.write_text(
                """#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--installed-packages', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
payload = {
    'record_type': 'ptah.phase0c.installed_package_artifact_manifest',
    'runtime_implementation_authorized': False,
    'network_used': False,
    'package_count': 1,
    'artifact_count': 1,
    'missing_count': 0,
    'complete': True,
    'missing': [],
    'apt_index_inventory': {'present': True},
}
args.output.write_text(json.dumps(payload) + '\\n', encoding='utf-8')
""",
                encoding="utf-8",
            )
            output = root / "evidence"
            output.mkdir()
            installed = output / "installed-packages.json"
            installed.write_text("{}\n", encoding="utf-8")
            result = MODULE.invoke_package_artifact_collector(
                root, installed, output, 1
            )
            self.assertEqual(
                result["collector_path"], "tools/collect_apt_package_artifacts.py"
            )
            self.assertEqual(result["collector_returncode"], 0)
            self.assertEqual(result["validation_failures"], [])

    def test_capability_hostname_is_hashed_before_bundle_retention(self) -> None:
        payload = passing_capability_payload()
        payload["host"] = {"hostname": "ptah-proof-host", "python": "3.12"}
        sanitized = MODULE.sanitize_capability_payload(payload)
        self.assertNotIn("hostname", sanitized["host"])
        self.assertEqual(len(sanitized["host"]["hostname_sha256"]), 64)
        self.assertEqual(payload["host"]["hostname"], "ptah-proof-host")

    def test_bundle_output_does_not_make_clean_repository_dirty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Ptah Test"],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "config",
                    "user.email",
                    "ptah@example.invalid",
                ],
                check=True,
            )
            tracked = root / "tracked.txt"
            tracked.write_text("frozen\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "freeze"], check=True
            )
            output = root / "evidence" / "phase0c" / "pinned-host-candidate"
            output.mkdir(parents=True)
            (output / "bundle-manifest.json").write_text("{}\n", encoding="utf-8")
            self.assertIs(MODULE.repository_state(root, output)["dirty"], False)
            (root / "unexpected.txt").write_text("unsafe\n", encoding="utf-8")
            state = MODULE.repository_state(root, output)
            self.assertIs(state["dirty"], True)
            self.assertEqual(state["unexpected_untracked"], ["unexpected.txt"])


if __name__ == "__main__":
    unittest.main()
