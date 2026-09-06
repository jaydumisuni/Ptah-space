#!/usr/bin/env python3
"""Validate the frozen E02 placement-authority corpus and retained proof bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_SCHEMA_VERSION = "0.1.0"
EXPECTED_RECORD_TYPE = "ptah.e02.placement_authority_acceptance_corpus"
EXPECTED_PREDECESSOR = "18c1bb26bf074fd8146c2dd8e47838d658af8561"
EXPECTED_ROADMAP_AUTHORITY = "dc2db457f1705d0cba80f17ab76e5e93f808aee0"
EXPECTED_PROTOCOL_ID = "ptah.node.link.v1"
EXPECTED_CONTROL_AUTHORITY = "ptah-control"
CORPUS_RELATIVE_PATH = Path("conformance/e02/placement-authority-cases.v0.1.0.json")
EXPECTED_CASES = {
    "two_concurrently_connected_capable_nodes",
    "deterministic_repeated_winner",
    "deterministic_stable_tie_break",
    "capability_mismatch_rejected",
    "provider_revision_mismatch_rejected",
    "resource_insufficiency_rejected",
    "critical_resource_pressure_rejected",
    "reservation_double_allocation_rejected",
    "reservation_expiry",
    "capability_only_cannot_dispatch",
    "reservation_only_cannot_dispatch",
    "valid_lease_fence_dispatches",
    "lease_expiry_blocks_dispatch",
    "stale_fence_rejected",
    "wrong_attempt_rejected",
    "stale_node_generation_rejected",
    "stale_connection_epoch_rejected",
    "superseded_e01_session_rejected",
    "disconnect_before_dispatch_rejected",
    "control_loss_during_valid_lease_bounded",
    "node_restart_invalidates_stale_authority",
    "control_restart_recovers_or_fails_closed",
    "replacement_issues_newer_authority",
    "delayed_old_dispatch_rejected",
    "no_capable_node_typed_unavailable",
    "exactly_one_current_owner",
    "provider_invocation_after_node_validation_only",
    "real_e01_provider_release_boundary",
}
EXPECTED_CLASSES = {
    "positive",
    "determinism",
    "negative",
    "adversarial",
    "recovery",
    "resilience",
    "integration",
}
SCOPE_FALSE_FIELDS = (
    "new_transport_added",
    "node_to_node_transfer_added",
    "workspace_transport_added",
    "platform_specific_admission_added",
    "discovery_relay_added",
    "synthetic_remote_node_added",
    "frozen_contract_change_required",
)
REQUIRED_PROOF_REPORTS = (
    "action-pin-audit.txt",
    "cargo-clippy.txt",
    "cargo-deny.txt",
    "cargo-fmt.txt",
    "cargo-test.txt",
    "changed-paths.txt",
    "d08-remote-placement-tests.txt",
    "dependency-lock.json",
    "e02-corpus-regressions.txt",
    "e02-targeted-tests.txt",
    "exact-head.txt",
    "provider-dispatch-tests.txt",
    "secret-scan.txt",
)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"E02 corpus is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("E02 corpus root must be a JSON object")
    return value


def load_and_validate_corpus(path: Path) -> dict[str, Any]:
    """Load and fail closed on any drift from the approved 28-case E02 boundary."""

    document = _load_json(path)
    fixed = {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "record_type": EXPECTED_RECORD_TYPE,
        "accepted_predecessor": EXPECTED_PREDECESSOR,
        "roadmap_authority": EXPECTED_ROADMAP_AUTHORITY,
        "protocol_id": EXPECTED_PROTOCOL_ID,
        "control_authority": EXPECTED_CONTROL_AUTHORITY,
    }
    for field, expected in fixed.items():
        if document.get(field) != expected:
            raise ValueError(f"E02 {field} changed")
    for field in SCOPE_FALSE_FIELDS:
        if document.get(field) is not False:
            raise ValueError(f"E02 {field} must remain false")

    cases = document.get("cases")
    if not isinstance(cases, list):
        raise ValueError("E02 cases must be a JSON array")
    if len(cases) != 28:
        raise ValueError(f"E02 corpus must contain exactly 28 cases, found {len(cases)}")

    case_ids: list[str] = []
    classes: set[str] = set()
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            raise ValueError(f"E02 case {index} must be a JSON object")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"E02 case {index} id is missing")
        case_ids.append(case_id)
        case_class = case.get("class")
        if case_class not in EXPECTED_CLASSES:
            raise ValueError(f"E02 case {case_id} class is invalid")
        classes.add(case_class)
        expected = case.get("expected_result")
        observed = case.get("observed_result")
        if not isinstance(expected, str) or not expected.strip():
            raise ValueError(f"E02 case {case_id} expected result is missing")
        if not isinstance(observed, str) or not observed.strip():
            raise ValueError(f"E02 case {case_id} observed result is missing")
        if observed != expected:
            raise ValueError(f"E02 case {case_id} falsely claims a passing observation")
        if case.get("passed") is not True:
            raise ValueError(f"E02 case {case_id} is not proven passing")
        evidence = case.get("required_evidence")
        if (
            not isinstance(evidence, list)
            or not evidence
            or any(not isinstance(item, str) or not item.strip() for item in evidence)
        ):
            raise ValueError(f"E02 case {case_id} required evidence is invalid")
        if len(evidence) != len(set(evidence)):
            raise ValueError(f"E02 case {case_id} required evidence must be unique")

    if len(case_ids) != len(set(case_ids)):
        raise ValueError("E02 case ids must be unique")
    actual = set(case_ids)
    if actual != EXPECTED_CASES:
        raise ValueError(
            "E02 case coverage drifted: "
            f"missing={sorted(EXPECTED_CASES-actual)} "
            f"unexpected={sorted(actual-EXPECTED_CASES)}"
        )
    if classes != EXPECTED_CLASSES:
        raise ValueError(f"E02 case classes drifted: {sorted(classes)}")
    return document


def require_report_files(root: Path, names: tuple[str, ...]) -> list[dict[str, Any]]:
    """Require non-empty regular proof files and return deterministic digests."""

    records: list[dict[str, Any]] = []
    for name in sorted(names):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"E02 report path is not a safe relative path: {name}")
        path = root / relative
        if not path.exists() or not path.is_file():
            raise ValueError(f"E02 required report is missing: {name}")
        size = path.stat().st_size
        if size <= 0:
            raise ValueError(f"E02 required report is empty: {name}")
        records.append(
            {
                "path": name,
                "size": size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return records


def validation_report(
    document: dict[str, Any], reports: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build the exact non-expanding E02 validation report."""

    return {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "record_type": "ptah.e02.placement_authority_acceptance_validation",
        "status": "pass",
        "accepted_predecessor": EXPECTED_PREDECESSOR,
        "roadmap_authority": EXPECTED_ROADMAP_AUTHORITY,
        "protocol_id": EXPECTED_PROTOCOL_ID,
        "control_authority": EXPECTED_CONTROL_AUTHORITY,
        "case_count": len(document["cases"]),
        "case_ids": sorted(case["id"] for case in document["cases"]),
        "report_count": len(reports),
        "reports": reports,
        **{field: False for field in SCOPE_FALSE_FIELDS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--proof-root", type=Path)
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    document = load_and_validate_corpus(repo_root / CORPUS_RELATIVE_PATH)
    reports: list[dict[str, Any]] = []
    if args.proof_root is not None:
        reports = require_report_files(args.proof_root.resolve(), REQUIRED_PROOF_REPORTS)
    report = validation_report(document, reports)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
