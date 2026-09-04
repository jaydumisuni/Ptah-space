#!/usr/bin/env python3
"""Validate the frozen D09 Full Workspace release corpus and proof reports.

This module is intentionally mechanical. It validates the accepted D09
release-acceptance contract and report bytes; it does not decide semantic
correctness, release desirability, caller intent, review meaning or approval.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_SCHEMA_VERSION = "0.1.0"
EXPECTED_RECORD_TYPE = "ptah.d09.full_workspace_release_corpus"
EXPECTED_PREDECESSOR = "ca6b3526ce9b58ffce11f8582be8fbf860dfa53d"
EXPECTED_ROADMAP_AUTHORITY = "98dc8c4e8639cda80510bee0625db34b4fdf9384"
EXPECTED_CATEGORIES = {
    "human_agent_coexistence",
    "deep_workspace_authority_separation",
    "concurrent_activity_operation",
    "long_running_recovery",
    "provider_replacement",
    "plugin_rollback",
    "provenance_reviewability",
    "security_reproduction_history",
    "application_truth",
    "public_private_release_audit",
}
EXPECTED_PARTICIPANTS = {"human", "hunter", "sergeant"}
CORPUS_RELATIVE_PATH = Path("conformance/d09/full-workspace-release-cases.v0.1.0.json")


def _require_false(document: dict[str, Any], field: str, label: str) -> None:
    if document.get(field) is not False:
        raise ValueError(f"D09 {label} must remain false")


def load_and_validate_corpus(path: Path) -> dict[str, Any]:
    """Load and fail closed on any drift from the frozen D09 corpus."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"D09 corpus is unreadable: {exc}") from exc

    if not isinstance(document, dict):
        raise ValueError("D09 corpus root must be a JSON object")
    if document.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        raise ValueError("D09 corpus schema version changed")
    if document.get("record_type") != EXPECTED_RECORD_TYPE:
        raise ValueError("D09 corpus record type changed")
    if document.get("accepted_predecessor") != EXPECTED_PREDECESSOR:
        raise ValueError("D09 accepted predecessor changed")
    if document.get("roadmap_authority") != EXPECTED_ROADMAP_AUTHORITY:
        raise ValueError("D09 roadmap authority changed")

    _require_false(document, "new_core_entity_required", "new Core entity requirement")
    _require_false(document, "frozen_contract_change_required", "frozen contract change requirement")
    _require_false(document, "runtime_feature_added", "runtime feature addition")

    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != 10:
        raise ValueError("D09 corpus must contain exactly 10 release cases")

    case_ids: list[str] = []
    categories: list[str] = []
    participant_union: set[str] = set()

    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            raise ValueError(f"D09 case {index} must be a JSON object")

        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"D09 case {index} id is missing")
        case_ids.append(case_id)

        category = case.get("category")
        if not isinstance(category, str) or not category.strip():
            raise ValueError(f"D09 case {case_id} category is missing")
        categories.append(category)

        participants = case.get("participants")
        if (
            not isinstance(participants, list)
            or not participants
            or any(not isinstance(value, str) or not value for value in participants)
        ):
            raise ValueError(f"D09 case {case_id} participants are invalid")
        participant_set = set(participants)
        unknown_participants = participant_set - EXPECTED_PARTICIPANTS
        if unknown_participants:
            raise ValueError(
                f"D09 case {case_id} participants contain unknown values: "
                f"{sorted(unknown_participants)}"
            )
        participant_union.update(participant_set)

        if case.get("ptah_semantic_authority") is not False:
            raise ValueError(f"D09 case {case_id} widens Ptah semantic authority")

        evidence = case.get("required_evidence")
        if (
            not isinstance(evidence, list)
            or not evidence
            or any(not isinstance(value, str) or not value.strip() for value in evidence)
        ):
            raise ValueError(f"D09 case {case_id} required evidence is invalid")
        if len(evidence) != len(set(evidence)):
            raise ValueError(f"D09 case {case_id} required evidence must be unique")

    if len(case_ids) != len(set(case_ids)):
        raise ValueError("D09 case ids must be unique")
    if set(categories) != EXPECTED_CATEGORIES or len(categories) != len(set(categories)):
        raise ValueError(
            "D09 release categories drifted: "
            f"expected={sorted(EXPECTED_CATEGORIES)} actual={sorted(categories)}"
        )
    if participant_union != EXPECTED_PARTICIPANTS:
        raise ValueError(
            "D09 corpus participants drifted: "
            f"expected={sorted(EXPECTED_PARTICIPANTS)} actual={sorted(participant_union)}"
        )

    return document


def require_report_files(root: Path, names: list[str]) -> list[dict[str, Any]]:
    """Require non-empty regular proof files and return deterministic digests."""

    records: list[dict[str, Any]] = []
    for name in sorted(names):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"D09 report path is not a safe relative path: {name}")
        path = root / relative
        if not path.exists():
            raise ValueError(f"D09 required report is missing: {name}")
        if not path.is_file():
            raise ValueError(f"D09 required report is not a regular file: {name}")
        size = path.stat().st_size
        if size <= 0:
            raise ValueError(f"D09 required report is empty: {name}")
        records.append(
            {
                "path": name,
                "size": size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return records


def validation_report(document: dict[str, Any]) -> dict[str, Any]:
    """Build the non-authorizing D09 corpus-validation report."""

    participants = sorted(
        {
            participant
            for case in document["cases"]
            for participant in case["participants"]
        }
    )
    return {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "record_type": "ptah.d09.full_workspace_release_validation",
        "status": "pass",
        "case_count": len(document["cases"]),
        "participants": participants,
        "ptah_semantic_authority": False,
        "new_core_entity_required": False,
        "frozen_contract_change_required": False,
        "runtime_feature_added": False,
        "accepted_predecessor": EXPECTED_PREDECESSOR,
        "roadmap_authority": EXPECTED_ROADMAP_AUTHORITY,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    document = load_and_validate_corpus(repo_root / CORPUS_RELATIVE_PATH)
    report = validation_report(document)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
