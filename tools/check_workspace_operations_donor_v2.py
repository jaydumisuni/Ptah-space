#!/usr/bin/env python3
"""Validate the non-operative deep Workspace operations donor study."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

PROFILE_ID = "ptah.workspace.operations.v2"
EXPECTED_SUMMARY = {
    "covered_by_neutral_substrate": 16,
    "caller_application_composition": 6,
    "candidate_core_extension": 0,
    "rejected_or_not_adopted": 6,
}
EXPECTED_EFFECTS = {
    "observe", "draft", "simulate", "mutate", "publish",
    "destructive", "external_side_effect",
}
EXPECTED_AVAILABILITY = {
    "external_reference", "indexed_reference", "mounted_read_only",
    "materialized_copy", "generated_artifact",
}
EXPECTED_RESULTS = {
    "succeeded", "failed", "declined", "cancelled", "not_run",
    "partially_completed",
}
EXPECTED_FIXTURES = {
    "lazy-operation-discovery",
    "effect-class-grant-denial",
    "external-permission-preservation",
    "confirmation-does-not-expand-access",
    "reference-is-not-materialized-by-name",
    "materialization-retains-provenance",
    "partial-output-survives-failure",
    "large-result-resource-handle",
    "exact-revision-conflict",
    "draft-before-publish",
    "invocation-is-not-success",
    "declined-failed-cancelled-distinction",
    "render-independent-view",
    "view-cannot-promote-authority",
    "condition-watch-no-notification",
    "scheduled-task-exact-input-boundary",
    "cross-device-resume",
    "semantic-merge-remains-caller-owned",
    "resource-limit-is-visible",
    "retry-preserves-prior-attempt",
}
OFFICIAL_URLS = {
    "https://help.openai.com/en/articles/10169521-projects-in-chatgpt",
    "https://help.openai.com/en/articles/11487775-connectors-in-chatgpt",
    "https://help.openai.com/en/articles/10847137",
    "https://help.openai.com/en/articles/20001052-file-storage-and-library-in-chatgpt",
    "https://help.openai.com/en/articles/10291617-tasks-in-chatgpt",
    "https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex",
    "https://help.openai.com/en/articles/9213685-extracting-insights-with-chatgpt-data-analysis",
    "https://help.openai.com/en/articles/11509118-admin-controls-security-and-compliance-for-plugins-and-apps",
    "https://help.openai.com/en/articles/20001256-plugins-in-chatgpt-and-codex",
    "https://help.openai.com/en/articles/20001247",
}


class StudyError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StudyError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise StudyError(f"top-level JSON object required: {path}")
    return value


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise StudyError(f"{label}: missing required text: {needle}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(repo_root: Path) -> dict[str, Any]:
    root = repo_root.resolve()
    paths = {
        "readme": root / "README.md",
        "existing_donor": root / "design/donors/openai-chatgpt-projects-work.md",
        "existing_profile": root / "design/candidates/ai-project-workspace-profile.json",
        "study": root / "design/donors/openai-chatgpt-workspace-deep-study.md",
        "profile": root / "design/candidates/workspace-operations-profile-v2.json",
        "gap": root / "design/candidates/workspace-operations-gap-map-v2.json",
        "fixtures": root / "design/candidates/fixtures/workspace-operations-fixtures-v2.json",
        "catalog": root / "contracts/generated/catalog-index.json",
    }
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        raise StudyError(f"required files missing: {', '.join(sorted(missing))}")

    readme = paths["readme"].read_text(encoding="utf-8")
    require(readme, "Runtime implementation is not authorized", "README")

    existing_donor = paths["existing_donor"].read_text(encoding="utf-8")
    require(existing_donor, "does not assign context, authority, review or approval decisions to Ptah", "existing donor")
    existing_profile = load_json(paths["existing_profile"])
    if existing_profile.get("ptah_role") != "neutral_workspace_and_execution_substrate":
        raise StudyError("existing neutral Workspace correction is not preserved")
    if existing_profile.get("runtime_implementation_authorized") is not False:
        raise StudyError("existing profile unexpectedly authorizes runtime implementation")

    study = paths["study"].read_text(encoding="utf-8")
    for url in OFFICIAL_URLS:
        require(study, url, "official source set")
    for token in (
        "ten primary specialist lanes and ten independent verification lanes",
        "Ptah remains the already-decided product",
        "no justified new Core entity",
        "no reason to reopen WP01–WP14",
        "does not authorize runtime implementation",
        "connector file reference is not automatically a file inside the active execution environment",
        "Invocation alone is not success",
        "Views as replaceable renderings",
    ):
        require(study, token, "deep study")

    profile = load_json(paths["profile"])
    if profile.get("record_type") != "ptah.phase0c.workspace_operations_profile_candidate":
        raise StudyError("profile record type mismatch")
    if profile.get("profile_id") != PROFILE_ID:
        raise StudyError("profile identity mismatch")
    if profile.get("status") != "candidate_non_operative":
        raise StudyError("profile must remain candidate and non-operative")
    for key in (
        "decision_authority", "context_selection_authority", "review_authority",
        "approval_authority", "new_core_entity_required",
        "frozen_contract_change_required", "runtime_implementation_authorized",
    ):
        if profile.get(key) is not False:
            raise StudyError(f"profile boundary must remain false: {key}")
    if profile.get("ptah_role") != "neutral_workspace_and_execution_substrate":
        raise StudyError("neutral Ptah role missing")
    method = profile.get("study_method")
    if not isinstance(method, dict) or method.get("name") != "ten_for_two":
        raise StudyError("ten-for-two method record missing")
    if method.get("primary_lanes") != 10 or method.get("independent_verifier_lanes") != 10:
        raise StudyError("ten-for-two lane count mismatch")
    source = profile.get("source_boundary")
    if not isinstance(source, dict):
        raise StudyError("source boundary missing")
    if source.get("openai_private_source_used") is not False or source.get("hidden_implementation_inferred") is not False:
        raise StudyError("study cannot claim private source or hidden implementation")
    if source.get("code_reuse") != "none":
        raise StudyError("workspace donor cannot claim code reuse")

    capabilities = profile.get("mechanical_capabilities_to_borrow")
    if not isinstance(capabilities, list) or len(capabilities) != 22 or len(set(capabilities)) != 22:
        raise StudyError("exactly twenty-two unique mechanical capabilities are required")
    if set(profile.get("operation_effect_classes", [])) != EXPECTED_EFFECTS:
        raise StudyError("operation effect classes mismatch")
    if set(profile.get("object_availability_states", [])) != EXPECTED_AVAILABILITY:
        raise StudyError("object availability states mismatch")
    if set(profile.get("activity_result_states", [])) != EXPECTED_RESULTS:
        raise StudyError("Activity result states mismatch")
    caller = profile.get("caller_owned_functions")
    if not isinstance(caller, list) or len(caller) < 10:
        raise StudyError("caller-owned semantic and authority functions are incomplete")
    for phrase in ("approval and rejection", "semantic merge and reconciliation", "next-action selection"):
        if phrase not in caller:
            raise StudyError(f"caller ownership missing: {phrase}")
    rejected = profile.get("rejected_patterns")
    if not isinstance(rejected, list) or len(rejected) != 8:
        raise StudyError("rejected pattern set mismatch")

    gap = load_json(paths["gap"])
    if gap.get("profile_id") != PROFILE_ID:
        raise StudyError("gap map profile mismatch")
    if gap.get("summary") != EXPECTED_SUMMARY:
        raise StudyError("gap map summary mismatch")
    if gap.get("frozen_contract_change_required") is not False or gap.get("runtime_implementation_authorized") is not False:
        raise StudyError("gap map changes frozen authority")
    mappings = gap.get("mappings")
    if not isinstance(mappings, list) or len(mappings) != 28:
        raise StudyError("exactly twenty-eight gap mappings are required")
    names = [item.get("capability") for item in mappings if isinstance(item, dict)]
    if len(names) != 28 or len(set(names)) != 28:
        raise StudyError("gap capabilities must be unique")
    counts = Counter(item.get("classification") for item in mappings)
    if dict(counts) != {key: value for key, value in EXPECTED_SUMMARY.items() if value}:
        raise StudyError("gap mapping counts do not match summary")
    if counts.get("candidate_core_extension", 0) != 0:
        raise StudyError("deep study cannot add a Core extension")
    for capability in (
        "context selection and relevance",
        "tool and Provider selection",
        "semantic merge of worker outputs",
        "approval decision",
        "result acceptance and canonical promotion",
        "next-action and schedule-purpose selection",
    ):
        item = next((entry for entry in mappings if entry.get("capability") == capability), None)
        if not isinstance(item, dict) or item.get("classification") != "caller_application_composition":
            raise StudyError(f"semantic function is not caller-owned: {capability}")

    fixtures = load_json(paths["fixtures"])
    if fixtures.get("profile_id") != PROFILE_ID:
        raise StudyError("fixture profile mismatch")
    if fixtures.get("new_core_entity_required") is not False or fixtures.get("frozen_contract_change_required") is not False:
        raise StudyError("fixtures reopen frozen contracts")
    if fixtures.get("runtime_implementation_authorized") is not False:
        raise StudyError("fixtures authorize runtime implementation")
    fixture_list = fixtures.get("fixtures")
    if not isinstance(fixture_list, list) or len(fixture_list) != 20:
        raise StudyError("exactly twenty fixtures are required")
    fixture_ids = {item.get("id") for item in fixture_list if isinstance(item, dict)}
    if fixture_ids != EXPECTED_FIXTURES:
        raise StudyError("fixture identities mismatch")
    kinds = Counter(item.get("kind") for item in fixture_list)
    if kinds != Counter({"positive": 11, "negative": 9}):
        raise StudyError("fixture positive/negative balance mismatch")
    for item in fixture_list:
        if not isinstance(item.get("proof"), list) or not item["proof"]:
            raise StudyError(f"fixture proof missing: {item.get('id')}")
    semantic = next(item for item in fixture_list if item.get("id") == "semantic-merge-remains-caller-owned")
    if semantic.get("expected") != "retain_both_without_ptah_verdict":
        raise StudyError("Ptah must not issue a semantic verdict")
    materialization = next(item for item in fixture_list if item.get("id") == "reference-is-not-materialized-by-name")
    if materialization.get("expected") != "no_local_path_claim":
        raise StudyError("external reference/materialization boundary weakened")
    invocation = next(item for item in fixture_list if item.get("id") == "invocation-is-not-success")
    if invocation.get("expected") != "not_run_or_unknown_effect_not_success":
        raise StudyError("invocation is incorrectly treated as success")

    catalog = load_json(paths["catalog"])
    if catalog.get("catalog_count") != 14 or catalog.get("schema_count") != 346 or catalog.get("state_machine_count") != 99:
        raise StudyError("frozen contract catalog changed during donor study")

    report_files = {
        name: {"path": str(path.relative_to(root)), "sha256": sha256(path)}
        for name, path in paths.items()
    }
    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.workspace_operations_deep_study_validation",
        "status": "pass",
        "profile_id": PROFILE_ID,
        "study_method": "10 primary + 10 independent verifier lanes",
        "mechanical_capability_count": 22,
        "gap_mapping_count": 28,
        "fixture_count": 20,
        "new_core_entity_required": False,
        "frozen_contract_change_required": False,
        "runtime_implementation_authorized": False,
        "files": report_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--output")
    args = parser.parse_args()
    report = validate(Path(args.repo_root))
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
