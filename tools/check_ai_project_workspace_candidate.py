#!/usr/bin/env python3
"""Validate the non-operative AI Project Workspace donor/profile candidate."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

EXPECTED_PROFILE_ID = "ptah.workspace.ai_project.v1"
EXPECTED_OFFICIAL_URLS = {
    "https://help.openai.com/en/articles/10169521-projects-in-chatgpt",
    "https://help.openai.com/en/articles/20001052/library-for-chatgpt",
    "https://help.openai.com/en/articles/20001275/chatgpt-work-and-codex",
    "https://help.openai.com/en/articles/9930697/what-is-the-canvas-feature-in-chatgpt-and-how-do-i-use-it",
    "https://help.openai.com/en/articles/10291617/tasks-in-chatgpt",
}
EXPECTED_AUTHORITY_CLASSES = {
    "canonical",
    "accepted_evidence",
    "recovery_copy",
    "reference",
    "generated_candidate",
    "temporary_context",
    "rejected",
    "superseded",
}
EXPECTED_PRIMITIVES = {
    "Workspace",
    "Session",
    "Activity",
    "Event",
    "Attempt",
    "Object",
    "Revision",
    "View",
    "Artifact",
    "Knowledge",
    "Policy",
    "Facility",
    "Provider",
    "Grant",
    "Recipe",
    "Receipt",
}
EXPECTED_CLASS_COUNTS = {
    "covered_by_existing_primitive": 4,
    "covered_by_profile_composition": 8,
    "candidate_extension": 0,
    "rejected_or_not_adopted": 2,
}


class CandidateError(RuntimeError):
    """Raised when the candidate violates its frozen non-operative boundary."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise CandidateError(f"top-level JSON object required: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_text(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise CandidateError(f"{label}: missing required text: {needle}")


def validate_candidate(repo_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    paths = {
        "readme": repo_root / "README.md",
        "donor": repo_root / "design/donors/openai-chatgpt-projects-work.md",
        "profile": repo_root / "design/candidates/ai-project-workspace-profile.json",
        "gap_map": repo_root / "design/candidates/ai-project-workspace-gap-map.json",
        "profile_doc": repo_root / "design/candidates/PTAH-AI-PROJECT-WORKSPACE-PROFILE.md",
        "bridge_doc": repo_root / "design/candidates/HUNTER-PTAH-WORKSPACE-BRIDGE.md",
        "fixtures": repo_root / "design/candidates/fixtures/ai-project-workspace-fixtures.json",
    }
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        raise CandidateError(f"candidate files missing: {', '.join(sorted(missing))}")

    readme = paths["readme"].read_text(encoding="utf-8")
    require_text(readme, "Runtime implementation is not authorized", "README")
    require_text(readme, "licensed under the Apache License, Version 2.0", "README")
    if "owner acceptance is still pending" in readme:
        raise CandidateError("README retains obsolete Apache-2.0 pending text")

    donor = paths["donor"].read_text(encoding="utf-8")
    require_text(donor, "architecture study only", "donor")
    require_text(donor, "Code reuse: none", "donor")
    require_text(donor, "Integration decision: Study only", "donor")
    require_text(donor, "does not authorize any runtime implementation", "donor")
    found_urls = {url for url in EXPECTED_OFFICIAL_URLS if url in donor}
    if found_urls != EXPECTED_OFFICIAL_URLS:
        raise CandidateError("donor record does not contain the complete official-source set")
    if "OpenAI source code" not in donor or "must be copied" in donor:
        raise CandidateError("donor source-code boundary is missing or inverted")

    profile = load_json(paths["profile"])
    if profile.get("record_type") != "ptah.phase0c.ai_project_workspace_profile_candidate":
        raise CandidateError("profile record type mismatch")
    if profile.get("profile_id") != EXPECTED_PROFILE_ID:
        raise CandidateError("profile identity mismatch")
    if profile.get("status") != "candidate_non_operative":
        raise CandidateError("profile must remain non-operative")
    if profile.get("runtime_implementation_authorized") is not False:
        raise CandidateError("profile cannot authorize runtime implementation")
    if profile.get("new_core_entity_required") is not False:
        raise CandidateError("candidate cannot silently add a new core entity")
    if profile.get("frozen_contract_change_required") is not False:
        raise CandidateError("candidate cannot silently reopen frozen contracts")
    primitives = profile.get("composed_primitives")
    if not isinstance(primitives, list) or set(primitives) != EXPECTED_PRIMITIVES:
        raise CandidateError("profile primitive composition does not match the reviewed set")
    authority = profile.get("source_authority_classes")
    if not isinstance(authority, list) or set(authority) != EXPECTED_AUTHORITY_CLASSES:
        raise CandidateError("profile authority classes are incomplete")
    context_fields = profile.get("context_packet_required_fields")
    if not isinstance(context_fields, list) or len(context_fields) < 10:
        raise CandidateError("context packet field set is incomplete")
    if len(context_fields) != len(set(context_fields)):
        raise CandidateError("context packet fields must be unique")
    privacy_rules = profile.get("privacy_rules")
    if not isinstance(privacy_rules, list) or not any(
        "cannot be retrieved by another Workspace" in item
        for item in privacy_rules
        if isinstance(item, str)
    ):
        raise CandidateError("cross-Workspace privacy rule is missing")
    grant_rules = profile.get("facility_grant_rules")
    if not isinstance(grant_rules, dict) or set(grant_rules) != {
        "read", "write", "protected_action", "private_export", "destructive_action"
    }:
        raise CandidateError("Facility Grant rules are incomplete")

    gap_map = load_json(paths["gap_map"])
    if gap_map.get("profile_id") != EXPECTED_PROFILE_ID:
        raise CandidateError("gap map profile identity mismatch")
    if gap_map.get("status") != "candidate_complete_no_contract_reopen":
        raise CandidateError("gap map status must preserve the no-reopen conclusion")
    if gap_map.get("frozen_contract_change_required") is not False:
        raise CandidateError("gap map cannot claim a frozen contract change")
    if gap_map.get("runtime_implementation_authorized") is not False:
        raise CandidateError("gap map cannot authorize runtime implementation")
    mappings = gap_map.get("mappings")
    if not isinstance(mappings, list) or not mappings:
        raise CandidateError("gap map mappings are missing")
    capabilities = [item.get("capability") for item in mappings if isinstance(item, dict)]
    if len(capabilities) != len(mappings) or len(capabilities) != len(set(capabilities)):
        raise CandidateError("gap map capabilities must be unique non-empty records")
    classifications = Counter(item.get("classification") for item in mappings)
    summary = gap_map.get("summary")
    if not isinstance(summary, dict) or summary != EXPECTED_CLASS_COUNTS:
        raise CandidateError("gap map summary does not match the reviewed counts")
    if dict(classifications) != {k: v for k, v in EXPECTED_CLASS_COUNTS.items() if v}:
        raise CandidateError("gap map classification counts do not match its summary")
    if classifications.get("candidate_extension", 0) != 0:
        raise CandidateError("candidate extension requires a separate contract reopening review")
    hidden = next(
        (item for item in mappings if item.get("capability") == "hidden provider memory"),
        None,
    )
    if not isinstance(hidden, dict) or hidden.get("classification") != "rejected_or_not_adopted":
        raise CandidateError("hidden provider memory must remain rejected")

    fixtures = load_json(paths["fixtures"])
    if fixtures.get("profile_id") != EXPECTED_PROFILE_ID:
        raise CandidateError("fixture profile identity mismatch")
    if fixtures.get("runtime_implementation_authorized") is not False:
        raise CandidateError("fixtures cannot authorize runtime implementation")
    fixture_list = fixtures.get("fixtures")
    if not isinstance(fixture_list, list) or len(fixture_list) != 10:
        raise CandidateError("exactly ten reviewed fixtures are required")
    fixture_ids = [item.get("id") for item in fixture_list if isinstance(item, dict)]
    if len(fixture_ids) != len(fixture_list) or len(fixture_ids) != len(set(fixture_ids)):
        raise CandidateError("fixture identities must be unique")
    kinds = {item.get("kind") for item in fixture_list}
    if kinds != {"positive", "negative"}:
        raise CandidateError("positive and negative fixture classes are both required")
    for item in fixture_list:
        if not isinstance(item.get("proof"), list) or not item["proof"]:
            raise CandidateError(f"fixture proof is missing: {item.get('id')}")
    isolation = next((item for item in fixture_list if item.get("id") == "workspace-isolation"), None)
    if not isinstance(isolation, dict) or isolation.get("expected") != "deny":
        raise CandidateError("cross-Workspace isolation fixture must fail closed")
    scheduled = next(
        (item for item in fixture_list if item.get("id") == "scheduled-artifact-least-privilege"),
        None,
    )
    if not isinstance(scheduled, dict) or scheduled.get("expected") != "deny":
        raise CandidateError("scheduled Artifact access must remain least privilege")

    profile_doc = paths["profile_doc"].read_text(encoding="utf-8")
    bridge_doc = paths["bridge_doc"].read_text(encoding="utf-8")
    for label, text in (("profile document", profile_doc), ("Hunter bridge", bridge_doc)):
        require_text(text, "non-operative", label)
        require_text(text, "does not authorize", label)
    require_text(profile_doc, EXPECTED_PROFILE_ID, "profile document")
    require_text(profile_doc, "No WP01–WP14 reopening is proposed", "profile document")
    require_text(bridge_doc, "Candidate-to-truth rule", "Hunter bridge")
    require_text(bridge_doc, "No model response directly changes canonical truth", "Hunter bridge")

    report_files = {}
    for name, path in paths.items():
        report_files[name] = {
            "repository_path": path.relative_to(repo_root).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        }

    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.ai_project_workspace_candidate_validation",
        "status": "candidate_valid_non_operative",
        "profile_id": EXPECTED_PROFILE_ID,
        "official_source_count": len(EXPECTED_OFFICIAL_URLS),
        "composed_primitive_count": len(EXPECTED_PRIMITIVES),
        "mapping_count": len(mappings),
        "fixture_count": len(fixture_list),
        "frozen_contract_change_required": False,
        "runtime_implementation_authorized": False,
        "files": report_files,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = validate_candidate(args.repo_root)
    except CandidateError as exc:
        raise SystemExit(str(exc)) from exc
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
