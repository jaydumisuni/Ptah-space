#!/usr/bin/env python3
"""Validate the frozen E01 secure multi-Node acceptance corpus and proof bundle.

This checker is intentionally mechanical. It proves required case coverage,
predecessor/design authority, E01 scope fences, and retained report bytes. It
does not authorize E02-E06 placement, transfer, discovery, or reconciliation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_SCHEMA_VERSION = "0.1.0"
EXPECTED_RECORD_TYPE = "ptah.e01.secure_multi_node_acceptance_corpus"
EXPECTED_PREDECESSOR = "f22d23c9bbf3c9c43884535e3483486c4bc0826f"
EXPECTED_ROADMAP_AUTHORITY = "98dc8c4e8639cda80510bee0625db34b4fdf9384"
EXPECTED_PROTOCOL_ID = "ptah.node.link.v1"
CORPUS_RELATIVE_PATH = Path("conformance/e01/secure-multi-node-cases.v0.1.0.json")
EXPECTED_CASES = {
    "two_node_concurrency",
    "reconnect",
    "node_restart",
    "control_restart",
    "credential_rotation",
    "plaintext_rejected",
    "wrong_ca_rejected",
    "wrong_enrollment_binding_rejected",
    "revoked_enrollment_rejected",
    "expired_enrollment_rejected",
    "stale_generation_rejected",
    "stale_or_equal_epoch_rejected",
    "superseded_publish_rejected",
    "capability_identity_mismatch_rejected",
    "malformed_frame_rejected",
    "oversized_frame_rejected",
    "unsupported_protocol_rejected",
}
EXPECTED_CLASSES = {"positive", "recovery", "negative"}
SCOPE_FALSE_FIELDS = (
    "scheduler_added",
    "transfer_plane_added",
    "overlay_transport_added",
    "automatic_discovery_added",
    "local_first_reconciliation_added",
    "new_core_entity_required",
    "frozen_contract_change_required",
)
REQUIRED_PROOF_REPORTS = (
    "action-pin-audit.txt",
    "cargo-clippy.txt",
    "cargo-deny.txt",
    "cargo-fmt.txt",
    "cargo-test.txt",
    "changed-paths.txt",
    "d09-regressions.txt",
    "deep-workspace-regressions.txt",
    "dependency-lock.json",
    "exact-head.txt",
    "node-agent-tests.txt",
    "node-link-tests.txt",
    "secret-scan.txt",
    "service-tests.txt",
)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"E01 corpus is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("E01 corpus root must be a JSON object")
    return value


def load_and_validate_corpus(path: Path) -> dict[str, Any]:
    """Load and fail closed on any drift from the frozen E01 corpus."""

    document = _load_json(path)
    if document.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        raise ValueError("E01 corpus schema version changed")
    if document.get("record_type") != EXPECTED_RECORD_TYPE:
        raise ValueError("E01 corpus record type changed")
    if document.get("accepted_predecessor") != EXPECTED_PREDECESSOR:
        raise ValueError("E01 accepted predecessor changed")
    if document.get("roadmap_authority") != EXPECTED_ROADMAP_AUTHORITY:
        raise ValueError("E01 roadmap authority changed")
    if document.get("protocol_id") != EXPECTED_PROTOCOL_ID:
        raise ValueError("E01 protocol identity changed")
    if document.get("first_transport") != "tls13_mutual_authentication_over_tcp":
        raise ValueError("E01 first transport changed")

    for field in SCOPE_FALSE_FIELDS:
        if document.get(field) is not False:
            raise ValueError(f"E01 {field} must remain false")

    cases = document.get("cases")
    if not isinstance(cases, list):
        raise ValueError("E01 cases must be a JSON array")

    case_ids: list[str] = []
    classes: set[str] = set()
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            raise ValueError(f"E01 case {index} must be a JSON object")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"E01 case {index} id is missing")
        case_ids.append(case_id)
        case_class = case.get("class")
        if case_class not in EXPECTED_CLASSES:
            raise ValueError(f"E01 case {case_id} class is invalid")
        classes.add(case_class)
        expected = case.get("expected_result")
        if not isinstance(expected, str) or not expected.strip():
            raise ValueError(f"E01 case {case_id} expected result is missing")
        evidence = case.get("required_evidence")
        if (
            not isinstance(evidence, list)
            or not evidence
            or any(not isinstance(item, str) or not item.strip() for item in evidence)
        ):
            raise ValueError(f"E01 case {case_id} required evidence is invalid")
        if len(evidence) != len(set(evidence)):
            raise ValueError(f"E01 case {case_id} required evidence must be unique")

    if len(case_ids) != len(set(case_ids)):
        raise ValueError("E01 case ids must be unique")
    actual = set(case_ids)
    if actual != EXPECTED_CASES:
        raise ValueError(
            "E01 case coverage drifted: "
            f"missing={sorted(EXPECTED_CASES-actual)} unexpected={sorted(actual-EXPECTED_CASES)}"
        )
    if classes != EXPECTED_CLASSES:
        raise ValueError(f"E01 case classes drifted: {sorted(classes)}")
    return document


def require_report_files(root: Path, names: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    """Require non-empty regular proof files and return deterministic digests."""

    records: list[dict[str, Any]] = []
    for name in sorted(names):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"E01 report path is not a safe relative path: {name}")
        path = root / relative
        if not path.exists():
            raise ValueError(f"E01 required report is missing: {name}")
        if not path.is_file():
            raise ValueError(f"E01 required report is not a regular file: {name}")
        size = path.stat().st_size
        if size <= 0:
            raise ValueError(f"E01 required report is empty: {name}")
        records.append(
            {
                "path": name,
                "size": size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return records


def validation_report(document: dict[str, Any], reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the non-expanding E01 acceptance report."""

    return {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "record_type": "ptah.e01.secure_multi_node_acceptance_validation",
        "status": "pass",
        "accepted_predecessor": EXPECTED_PREDECESSOR,
        "roadmap_authority": EXPECTED_ROADMAP_AUTHORITY,
        "protocol_id": EXPECTED_PROTOCOL_ID,
        "case_count": len(document["cases"]),
        "case_ids": sorted(case["id"] for case in document["cases"]),
        "report_count": len(reports),
        "reports": reports,
        "scheduler_added": False,
        "transfer_plane_added": False,
        "overlay_transport_added": False,
        "automatic_discovery_added": False,
        "local_first_reconciliation_added": False,
        "new_core_entity_required": False,
        "frozen_contract_change_required": False,
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
