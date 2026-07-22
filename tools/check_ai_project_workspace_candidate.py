#!/usr/bin/env python3
"""Validate the corrected non-operative AI Project Workspace donor/profile."""
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
EXPECTED_PRIMITIVES = {
    "Workspace", "Session", "Activity", "Event", "Attempt", "Object",
    "Revision", "View", "Artifact", "Knowledge", "Policy", "Facility",
    "Provider", "Grant", "Recipe", "Receipt",
}
EXPECTED_CLASS_COUNTS = {
    "covered_by_neutral_substrate": 8,
    "caller_application_composition": 4,
    "candidate_extension": 0,
    "rejected_or_not_adopted": 2,
}
EXPECTED_FIXTURES = {
    "workspace-isolation",
    "caller-label-roundtrip",
    "conflicting-labels-no-ranking",
    "model-independent-resume",
    "grant-survives-agent-change",
    "scheduled-exact-inputs",
    "private-hunter-public-workspace",
    "archived-session-discoverability",
    "failed-activity-visible",
    "sergeant-review-no-ptah-verdict",
}


class CandidateError(RuntimeError):
    """Raised when the candidate violates the neutral non-operative boundary."""


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


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise CandidateError(f"{label}: missing required text: {needle}")


def forbid(text: str, needle: str, label: str) -> None:
    if needle in text:
        raise CandidateError(f"{label}: forbidden decision-authority text remains: {needle}")


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
    require(readme, "Runtime implementation is not authorized", "README")
    require(readme, "licensed under the Apache License, Version 2.0", "README")
    if "owner acceptance is still pending" in readme:
        raise CandidateError("README retains obsolete Apache-2.0 pending text")

    donor = paths["donor"].read_text(encoding="utf-8")
    for token in (
        "application-experience study only",
        "Integration decision: Study only",
        "Code reuse: none",
        "Ptah provides neutral storage, execution, isolation, access enforcement",
        "does not assign context, authority, review or approval decisions to Ptah",
        "does not authorize any runtime implementation",
    ):
        require(donor, token, "donor")
    for url in EXPECTED_OFFICIAL_URLS:
        require(donor, url, "donor official-source set")
    forbid(donor, "Ptah subsystem: Workspace composition, context compilation", "donor")
    forbid(donor, "Ptah must implement the capability", "donor")

    profile = load_json(paths["profile"])
    if profile.get("record_type") != "ptah.phase0c.ai_project_workspace_profile_candidate":
        raise CandidateError("profile record type mismatch")
    if profile.get("profile_id") != EXPECTED_PROFILE_ID:
        raise CandidateError("profile identity mismatch")
    if profile.get("status") != "corrected_candidate_non_operative":
        raise CandidateError("profile must remain corrected and non-operative")
    if profile.get("runtime_implementation_authorized") is not False:
        raise CandidateError("profile cannot authorize runtime implementation")
    if profile.get("new_core_entity_required") is not False:
        raise CandidateError("candidate cannot silently add a new Core entity")
    if profile.get("frozen_contract_change_required") is not False:
        raise CandidateError("candidate cannot silently reopen frozen contracts")
    if profile.get("ptah_role") != "neutral_workspace_and_execution_substrate":
        raise CandidateError("Ptah neutral substrate role is missing")
    if profile.get("decision_authority") is not False:
        raise CandidateError("Ptah cannot have decision authority")

    expected_owners = {
        "context_selection_owner": "caller_application",
        "source_authority_owner": "caller_application",
        "review_authority_owner": "reviewer_application",
        "approval_authority_owner": "human_or_calling_application",
        "next_action_owner": "caller_application",
    }
    for key, value in expected_owners.items():
        if profile.get(key) != value:
            raise CandidateError(f"profile responsibility owner mismatch: {key}")

    primitives = profile.get("composed_primitives")
    if not isinstance(primitives, list) or set(primitives) != EXPECTED_PRIMITIVES:
        raise CandidateError("profile primitive composition does not match the reviewed set")

    surfaces = profile.get("mechanical_workspace_surfaces")
    if not isinstance(surfaces, list) or len(surfaces) < 10 or len(surfaces) != len(set(surfaces)):
        raise CandidateError("mechanical Workspace surface set is incomplete or duplicated")

    caller_functions = profile.get("caller_owned_functions")
    required_caller_functions = {
        "intent interpretation", "context search and selection",
        "source authority and trust labels", "review and verdict",
        "approval and rejection", "next-action selection",
    }
    if not isinstance(caller_functions, list) or not required_caller_functions.issubset(caller_functions):
        raise CandidateError("caller-owned decision functions are incomplete")

    grant_rules = profile.get("facility_grant_rules")
    if not isinstance(grant_rules, dict) or set(grant_rules) != {
        "read", "write", "protected_action", "private_export", "destructive_action"
    }:
        raise CandidateError("mechanical Facility Grant rules are incomplete")
    if any("decide" in str(value).lower() and "without deciding" not in str(value).lower() for value in grant_rules.values()):
        raise CandidateError("Grant rule assigns judgment to Ptah")

    non_claims = profile.get("non_claims")
    required_non_claims = {
        "no Ptah context compiler",
        "no Ptah source-authority ranking",
        "no Ptah review or approval authority",
        "no Ptah next-action selection",
    }
    if not isinstance(non_claims, list) or not required_non_claims.issubset(non_claims):
        raise CandidateError("neutral Ptah non-claims are incomplete")

    gap_map = load_json(paths["gap_map"])
    if gap_map.get("profile_id") != EXPECTED_PROFILE_ID:
        raise CandidateError("gap map profile identity mismatch")
    if gap_map.get("status") != "corrected_candidate_complete_no_contract_reopen":
        raise CandidateError("gap map corrected status is missing")
    if gap_map.get("frozen_contract_change_required") is not False:
        raise CandidateError("gap map cannot claim a frozen contract change")
    if gap_map.get("runtime_implementation_authorized") is not False:
        raise CandidateError("gap map cannot authorize runtime implementation")
    require(str(gap_map.get("core_boundary", "")), "Ptah provides neutral storage", "gap map boundary")

    mappings = gap_map.get("mappings")
    if not isinstance(mappings, list) or len(mappings) != 14:
        raise CandidateError("exactly fourteen donor mappings are required")
    capabilities = [item.get("capability") for item in mappings if isinstance(item, dict)]
    if len(capabilities) != len(mappings) or len(capabilities) != len(set(capabilities)):
        raise CandidateError("gap map capabilities must be unique non-empty records")
    classifications = Counter(item.get("classification") for item in mappings)
    if gap_map.get("summary") != EXPECTED_CLASS_COUNTS:
        raise CandidateError("gap map summary does not match the corrected counts")
    if dict(classifications) != {key: value for key, value in EXPECTED_CLASS_COUNTS.items() if value}:
        raise CandidateError("gap map classification counts do not match its summary")
    if classifications.get("candidate_extension", 0) != 0:
        raise CandidateError("candidate extension requires a separate contract reopening review")
    for capability in ("project instructions", "project memory", "long-running agent work", "scheduled continuation"):
        item = next((record for record in mappings if record.get("capability") == capability), None)
        if not isinstance(item, dict) or item.get("classification") != "caller_application_composition":
            raise CandidateError(f"decision-bearing donor behavior must remain caller-owned: {capability}")
        require(str(item.get("boundary", "")), "Ptah", f"{capability} boundary")

    fixtures = load_json(paths["fixtures"])
    if fixtures.get("profile_id") != EXPECTED_PROFILE_ID:
        raise CandidateError("fixture profile identity mismatch")
    if fixtures.get("runtime_implementation_authorized") is not False:
        raise CandidateError("fixtures cannot authorize runtime implementation")
    fixture_list = fixtures.get("fixtures")
    if not isinstance(fixture_list, list) or len(fixture_list) != 10:
        raise CandidateError("exactly ten corrected fixtures are required")
    fixture_ids = {item.get("id") for item in fixture_list if isinstance(item, dict)}
    if fixture_ids != EXPECTED_FIXTURES:
        raise CandidateError("corrected fixture identities do not match the reviewed set")
    if {item.get("kind") for item in fixture_list} != {"positive", "negative"}:
        raise CandidateError("positive and negative fixture classes are both required")
    for item in fixture_list:
        if not isinstance(item.get("proof"), list) or not item["proof"]:
            raise CandidateError(f"fixture proof is missing: {item.get('id')}")

    conflict = next(item for item in fixture_list if item.get("id") == "conflicting-labels-no-ranking")
    if conflict.get("expected") != "retain_both_no_winner":
        raise CandidateError("Ptah must not rank conflicting caller labels")
    sergeant = next(item for item in fixture_list if item.get("id") == "sergeant-review-no-ptah-verdict")
    if sergeant.get("expected") != "store_review_without_promotion":
        raise CandidateError("Sergeant review must not become a Ptah verdict")
    archived = next(item for item in fixture_list if item.get("id") == "archived-session-discoverability")
    if archived.get("expected") != "return_if_authorized":
        raise CandidateError("Ptah must not make archived-Session relevance decisions")

    profile_doc = paths["profile_doc"].read_text(encoding="utf-8")
    bridge_doc = paths["bridge_doc"].read_text(encoding="utf-8")
    for label, text in (("profile document", profile_doc), ("Hunter bridge", bridge_doc)):
        require(text, "non-operative", label)
        require(text, "does not authorize", label)
    require(profile_doc, "Ptah is the world and machinery, not the thinker", "profile document")
    require(profile_doc, "Ptah Core does not compile context", "profile document")
    require(profile_doc, "Ptah does not perform the review", "profile document")
    require(bridge_doc, "Ptah does not interpret intent, select context, rank sources", "Hunter bridge")
    require(bridge_doc, "Ptah does not perform the review", "Hunter bridge")
    require(bridge_doc, "Ptah does not promote a candidate", "Hunter bridge")

    forbidden_phrases = {
        "profile document": (
            "Ptah should compile a bounded context packet",
            "A lower-authority record cannot silently override",
            "sharing the same accepted Workspace truth",
        ),
        "Hunter bridge": (
            "authoritative source index",
            "pending approval or denial",
            "candidate authority promotion request",
            "Promotion requires the Workspace's applicable acceptance policy",
        ),
    }
    for label, phrases in forbidden_phrases.items():
        text = profile_doc if label == "profile document" else bridge_doc
        for phrase in phrases:
            forbid(text, phrase, label)

    report_files = {
        name: {
            "repository_path": path.relative_to(repo_root).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for name, path in paths.items()
    }

    return {
        "schema_version": "0.2.0",
        "record_type": "ptah.phase0c.ai_project_workspace_candidate_validation",
        "status": "candidate_valid_non_operative",
        "profile_id": EXPECTED_PROFILE_ID,
        "official_source_count": len(EXPECTED_OFFICIAL_URLS),
        "composed_primitive_count": len(EXPECTED_PRIMITIVES),
        "mapping_count": len(mappings),
        "fixture_count": len(fixture_list),
        "neutral_substrate_boundary_restored": True,
        "ptah_decision_authority": False,
        "ptah_context_selection_authority": False,
        "ptah_review_authority": False,
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
