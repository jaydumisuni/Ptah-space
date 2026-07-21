from __future__ import annotations

import importlib.util
import json
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


def test_exact_frozen_host_identity_passes() -> None:
    os_release = {
        "ID": "ubuntu",
        "VERSION_ID": "24.04",
        "VERSION": "24.04.4 LTS (Noble Numbat)",
        "PRETTY_NAME": "Ubuntu 24.04.4 LTS",
    }
    assert MODULE.validate_host(os_release, "6.8.0-136-generic", "x86_64") == []


def test_generic_host_is_not_proof_eligible() -> None:
    os_release = {
        "ID": "ubuntu",
        "VERSION_ID": "24.04",
        "VERSION": "24.04.3 LTS",
        "PRETTY_NAME": "Ubuntu 24.04.3 LTS",
    }
    failures = MODULE.validate_host(os_release, "6.17.0-azure", "x86_64")
    assert any(item.startswith("point_release_not_found") for item in failures)
    assert any(item.startswith("kernel=") for item in failures)


def test_package_digest_is_order_sensitive_until_records_are_sorted() -> None:
    first = [{"package": "a"}, {"package": "b"}]
    second = list(reversed(first))
    assert MODULE.canonical_sha256(first) != MODULE.canonical_sha256(second)
    assert MODULE.canonical_sha256(sorted(first, key=lambda item: item["package"])) == MODULE.canonical_sha256(
        sorted(second, key=lambda item: item["package"])
    )


def test_json_writer_uses_stable_utf8(tmp_path: Path) -> None:
    target = tmp_path / "record.json"
    MODULE.write_json(target, {"runtime_implementation_authorized": False, "value": "Ptah"})
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["runtime_implementation_authorized"] is False
    assert target.read_bytes().endswith(b"\n")


def test_real_collector_path_is_selected(tmp_path: Path) -> None:
    real = tmp_path / "host" / "scripts" / "collect_capabilities.py"
    legacy = tmp_path / "tools" / "collect_host_capabilities.py"
    real.parent.mkdir(parents=True)
    legacy.parent.mkdir(parents=True)
    real.write_text("# real\n", encoding="utf-8")
    legacy.write_text("# legacy\n", encoding="utf-8")
    assert MODULE.locate_capability_collector(tmp_path) == real


def test_missing_real_collector_fails_closed(tmp_path: Path) -> None:
    try:
        MODULE.locate_capability_collector(tmp_path)
    except MODULE.ProofError as exc:
        assert "host/scripts/collect_capabilities.py" in str(exc)
    else:
        raise AssertionError("missing collector did not fail closed")


def test_capability_payload_must_be_proof_eligible() -> None:
    assert MODULE.validate_capability_payload(passing_capability_payload()) == []
    payload = passing_capability_payload()
    payload["required_capabilities_passed"] = False
    payload["proof_eligible"] = False
    payload["pinned_host_match"] = {"all_match": False}
    payload["required_failures"] = ["systemd"]
    failures = MODULE.validate_capability_payload(payload)
    assert "required_capabilities_not_passed" in failures
    assert "capability_report_not_proof_eligible" in failures
    assert "capability_pinned_host_identity_not_matched" in failures
    assert "capability_required_failures_present_or_invalid" in failures


def test_capability_failure_blocks_bundle_eligibility() -> None:
    failures = MODULE.proof_failures([], False, ["required_capabilities_not_passed"])
    assert failures == ["capability:required_capabilities_not_passed"]


def test_dirty_repository_blocks_bundle_eligibility() -> None:
    assert MODULE.proof_failures([], True, []) == ["repository_dirty"]


def test_invoke_uses_real_collector_cli_and_validates_payload(tmp_path: Path) -> None:
    collector = tmp_path / "host" / "scripts" / "collect_capabilities.py"
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
    output = tmp_path / "evidence"
    output.mkdir()
    result = MODULE.invoke_capability_collector(tmp_path, output)
    assert result["collector_path"] == "host/scripts/collect_capabilities.py"
    assert result["collector_returncode"] == 0
    assert result["validation_failures"] == []
