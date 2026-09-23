#!/usr/bin/env python3
"""Validate the frozen E04 compatible-workspace-movement conformance corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

EXPECTED_SCHEMA_VERSION = "0.1.0"
EXPECTED_RECORD_TYPE = "ptah.e04.compatible_workspace_movement_acceptance_corpus"
EXPECTED_PREDECESSOR = "d25679c7f039d7328fe1a785af91e82bd403b44e"
EXPECTED_DESIGN_SPEC = (
    "docs/superpowers/specs/2026-09-13-e04-compatible-workspace-movement-design.md"
)
CORPUS_RELATIVE_PATH = Path("conformance/e04-cases.json")
EXPECTED_CASE_IDS = (
    "verified_source_vault_prepared",
    "unverified_source_checkpoint_rejected",
    "exact_vault_digest_preserved",
    "vault_bulk_not_e01_control",
    "direct_transfer_supported",
    "explicit_relay_supported",
    "resume_verified_missing_ranges_only",
    "corrupt_destination_blocks_import_restore",
    "target_import_drops_restore_authorization",
    "target_checkpoint_reverification_required",
    "exact_compatible_target_restores",
    "missing_b06_capability_blocks_restore",
    "missing_a13_component_capability_blocks_restore",
    "stale_target_node_generation_blocks_progress",
    "stale_connection_epoch_blocks_progress",
    "expired_revoked_e02_lease_blocks_restore",
    "stale_fence_blocks_restore",
    "provider_generation_mismatch_blocks_restore",
    "expired_compatibility_blocks_restore",
    "foreign_workspace_revision_generation_blocks_restore",
    "retained_conflicts_visible",
    "failed_restore_attempt_not_reused",
    "retry_fresh_attempt_retains_failure",
    "recovery_partial_not_success",
    "recovery_inconclusive_not_success",
    "recovery_failed_not_success",
    "recovery_recovered_with_current_evidence_success",
    "coordinator_restart_from_owner_evidence",
    "concurrent_attempts_do_not_alias",
    "source_not_auto_deleted",
    "no_e05_e06_scope",
    "inherited_regressions_green",
)
EXPECTED_CASES = set(EXPECTED_CASE_IDS)
EXPECTED_CLASSES = {
    "positive",
    "negative",
    "adversarial",
    "recovery",
    "resilience",
    "integration",
    "scope",
}
SCOPE_FALSE_FIELDS = (
    "platform_admission_added",
    "automatic_discovery_added",
    "automatic_relay_selection_added",
    "offline_reconciliation_added",
    "new_checkpoint_format_added",
    "new_transfer_model_added",
    "new_placement_authority_added",
    "source_auto_deleted",
    "multi_writer_sync_added",
    "frozen_contract_change_required",
)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"E04 corpus is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("E04 corpus root must be a JSON object")
    return value


def load_and_validate_corpus(path: Path) -> dict[str, Any]:
    """Load and fail closed on any drift from the approved 32-case E04 boundary."""

    document = _load_json(path)
    fixed = {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "record_type": EXPECTED_RECORD_TYPE,
        "accepted_predecessor": EXPECTED_PREDECESSOR,
        "design_spec": EXPECTED_DESIGN_SPEC,
    }
    for field, expected in fixed.items():
        if document.get(field) != expected:
            raise ValueError(f"E04 {field} changed")

    for field in SCOPE_FALSE_FIELDS:
        if document.get(field) is not False:
            raise ValueError(f"E04 {field} must remain false")

    cases = document.get("cases")
    if not isinstance(cases, list):
        raise ValueError("E04 cases must be a JSON array")
    if len(cases) != 32:
        raise ValueError(f"E04 corpus must contain exactly 32 cases, found {len(cases)}")

    case_ids: list[str] = []
    classes: set[str] = set()
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            raise ValueError(f"E04 case {index} must be a JSON object")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"E04 case {index} id is missing")
        case_ids.append(case_id)

        case_class = case.get("class")
        if case_class not in EXPECTED_CLASSES:
            raise ValueError(f"E04 case {case_id} class is invalid")
        classes.add(case_class)

        expected = case.get("expected_result")
        observed = case.get("observed_result")
        if not isinstance(expected, str) or not expected.strip():
            raise ValueError(f"E04 case {case_id} expected result is missing")
        if not isinstance(observed, str) or not observed.strip():
            raise ValueError(f"E04 case {case_id} observed result is missing")
        if observed != expected:
            raise ValueError(f"E04 case {case_id} falsely claims a passing observation")
        if case.get("passed") is not True:
            raise ValueError(f"E04 case {case_id} is not proven passing")

        evidence = case.get("required_evidence")
        if (
            not isinstance(evidence, list)
            or not evidence
            or any(not isinstance(item, str) or not item.strip() for item in evidence)
        ):
            raise ValueError(f"E04 case {case_id} required evidence is invalid")
        if len(evidence) != len(set(evidence)):
            raise ValueError(f"E04 case {case_id} required evidence must be unique")

    if len(case_ids) != len(set(case_ids)):
        raise ValueError("E04 case ids must be unique")
    if set(case_ids) != EXPECTED_CASES:
        actual = set(case_ids)
        raise ValueError(
            "E04 case coverage drifted: "
            f"missing={sorted(EXPECTED_CASES - actual)} "
            f"unexpected={sorted(actual - EXPECTED_CASES)}"
        )
    if tuple(case_ids) != EXPECTED_CASE_IDS:
        raise ValueError("E04 case order drifted from design obligations 1-32")
    if classes != EXPECTED_CLASSES:
        raise ValueError(f"E04 case classes drifted: {sorted(classes)}")

    return document


def validation_report(document: dict[str, Any]) -> dict[str, Any]:
    """Build the deterministic non-expanding E04 validation report."""

    return {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "record_type": "ptah.e04.compatible_workspace_movement_acceptance_validation",
        "status": "pass",
        "accepted_predecessor": EXPECTED_PREDECESSOR,
        "design_spec": EXPECTED_DESIGN_SPEC,
        "case_count": len(document["cases"]),
        "case_ids": [case["id"] for case in document["cases"]],
        **{field: False for field in SCOPE_FALSE_FIELDS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    document = load_and_validate_corpus(repo_root / CORPUS_RELATIVE_PATH)
    rendered = json.dumps(validation_report(document), indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
