#!/usr/bin/env python3
"""Validate the A15 Online Ptah Alpha acceptance envelope without adding runtime authority."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

A14_BASE_SHA = "db74eccbd988fc1e30349412aa08b4464ca8d3c1"
WP14_MERGE_SHA = "fef387c4f074af7fcf86f2d99f7f9b7637e91f88"
PHASE0B_FREEZE_SHA = "dc2db457f1705d0cba80f17ab76e5e93f808aee0"
WP14_CORPUS_SHA256 = "809dc89e848737d1b2fa7cc3e6aecf92cf7ffe008dee8c2fb3b7cf3cd9e3baaa"
WP14_SUITE_ID = "ptah.conformance.wp14.freeze.0.1.0"
FIXED_ACCEPTANCE_TIME = datetime(2026, 8, 23, tzinfo=timezone.utc)
EXPECTED_WP14_CASE_IDS = {
    "G01_NO_RAW_SECRET",
    "N01_RAW_SECRET_REJECTED",
    "G02_CURRENT_PROVIDER_GENERATION",
    "N02_STALE_PROVIDER_GENERATION",
    "G03_CURRENT_FENCE",
    "N03_STALE_FENCE",
    "G04_UNIQUE_RETRY_ATTEMPTS",
    "N04_REUSED_ATTEMPT_ID",
    "G05_VERIFICATION_HAS_EVIDENCE",
    "N05_ACK_AS_VERIFICATION",
    "G06_EXACT_CITATION",
    "N06_RANK_WITHOUT_CITATION",
    "G07_CURRENT_ACCEPTED_RISK",
    "N07_EXPIRED_ACCEPTED_RISK",
    "G08_INDEPENDENT_REPRODUCTION",
    "N08_SAME_ENV_REPRODUCTION",
}
SENSITIVE_KEYS = {
    "api_key",
    "password",
    "secret",
    "private_key",
    "bearer_token",
    "access_token",
}


class AcceptanceError(RuntimeError):
    """Raised when the A15 acceptance envelope is incomplete or contradictory."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceptanceError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise AcceptanceError(f"top-level JSON object required: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def _is_redacted(value: Any) -> bool:
    return isinstance(value, str) and value.strip().upper() in {
        "REDACTED",
        "MASKED",
        "REMOVED",
    }


def _contains_raw_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in SENSITIVE_KEYS and child not in (None, "") and not _is_redacted(child):
                return True
            if _contains_raw_secret(child):
                return True
    elif isinstance(value, list):
        return any(_contains_raw_secret(child) for child in value)
    return False


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AcceptanceError(f"invalid UTC timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise AcceptanceError(f"timezone required: {value}")
    return parsed.astimezone(timezone.utc)


def evaluate_wp14_case(case: dict[str, Any]) -> str | None:
    """Return the frozen failure code, or ``None`` when the case is valid."""
    rule = case.get("rule")
    payload = case.get("payload")
    if not isinstance(payload, dict):
        raise AcceptanceError(f"WP14 case {case.get('id')} payload must be an object")

    if rule == "no_raw_secret":
        return "RAW_SECRET_PRESENT" if _contains_raw_secret(payload) else None
    if rule == "current_generation":
        return (
            None
            if payload.get("expected_generation") == payload.get("observed_generation")
            else "STALE_PROVIDER_GENERATION"
        )
    if rule == "current_fence":
        return (
            None
            if payload.get("expected_fence_token") == payload.get("observed_fence_token")
            else "STALE_FENCE_TOKEN"
        )
    if rule == "retry_attempt_unique":
        attempts = payload.get("attempt_refs")
        valid = (
            isinstance(attempts, list)
            and len(attempts) >= 2
            and len(attempts) == len(set(attempts))
        )
        return None if valid else "ATTEMPT_ID_REUSED"
    if rule == "acknowledgement_not_verification":
        evidence = payload.get("verification_evidence_refs")
        valid = payload.get("verified") is not True or (
            isinstance(evidence, list) and bool(evidence)
        )
        return None if valid else "ACKNOWLEDGEMENT_IS_NOT_VERIFICATION"
    if rule == "exact_citation":
        range_value = payload.get("range")
        valid = (
            isinstance(payload.get("source_revision_ref"), str)
            and bool(payload.get("source_revision_ref"))
            and isinstance(range_value, dict)
            and isinstance(range_value.get("start"), int)
            and isinstance(range_value.get("end"), int)
            and range_value["start"] <= range_value["end"]
            and isinstance(payload.get("digest"), str)
            and bool(payload.get("digest"))
        )
        return None if valid else "CITATION_IDENTITY_INCOMPLETE"
    if rule == "accepted_risk_current":
        expires = payload.get("expires_at")
        valid = isinstance(expires, str) and _parse_utc(expires) > FIXED_ACCEPTANCE_TIME
        return None if valid else "ACCEPTED_RISK_EXPIRED"
    if rule == "independent_reproduction":
        attempts = payload.get("attempt_refs")
        valid = (
            payload.get("original_environment_ref") != payload.get("reproduction_environment_ref")
            and isinstance(attempts, list)
            and len(attempts) >= 2
            and len(attempts) == len(set(attempts))
            and payload.get("shared_mutable_cache") is False
        )
        return None if valid else "REPRODUCTION_NOT_INDEPENDENT"
    raise AcceptanceError(f"unsupported frozen WP14 rule: {rule}")


def validate_wp14_corpus(path: Path) -> dict[str, Any]:
    require(sha256(path) == WP14_CORPUS_SHA256, "frozen WP14 corpus digest mismatch")
    corpus = load_json(path)
    require(corpus.get("suite_id") == WP14_SUITE_ID, "WP14 suite identity mismatch")
    require(corpus.get("fixture_version") == "0.1.0", "WP14 fixture version mismatch")
    cases = corpus.get("cases")
    require(isinstance(cases, list) and len(cases) == 16, "WP14 must contain exactly 16 frozen cases")
    ids = {case.get("id") for case in cases if isinstance(case, dict)}
    require(ids == EXPECTED_WP14_CASE_IDS, "WP14 frozen case identities changed")

    positive = negative = 0
    for case in cases:
        require(isinstance(case, dict), "WP14 case must be an object")
        observed = evaluate_wp14_case(case)
        expected = case.get("expected")
        if expected == "valid":
            positive += 1
            require(observed is None, f"golden WP14 case failed: {case.get('id')} -> {observed}")
        elif expected == "invalid":
            negative += 1
            require(
                observed == case.get("expected_code"),
                f"negative WP14 case mismatch: {case.get('id')} -> {observed}",
            )
        else:
            raise AcceptanceError(f"unknown WP14 expected class: {case.get('id')}")
    require((positive, negative) == (8, 8), "WP14 positive/negative balance changed")
    return {"case_count": len(cases), "positive_count": positive, "negative_count": negative}


def require_report_files(root: Path, required_names: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Fail closed when a green status is not accompanied by every required report."""
    records: dict[str, dict[str, Any]] = {}
    for name in required_names:
        path = root / name
        require(path.is_file() and path.stat().st_size > 0, f"required A15 report missing or empty: {name}")
        records[name] = {"size_bytes": path.stat().st_size, "sha256": sha256(path)}
    return records


def _validate_contract_bindings(repo_root: Path) -> dict[str, Any]:
    manifest_path = repo_root / "contracts/generated/manifest.json"
    manifest = load_json(manifest_path)
    authority = manifest.get("authority")
    require(isinstance(authority, dict), "generated contract authority missing")
    require(authority.get("wp14_merge") == WP14_MERGE_SHA, "generated bindings are not bound to frozen WP14")
    require(authority.get("phase_0b_freeze_merge") == PHASE0B_FREEZE_SHA, "Phase 0B freeze binding changed")
    require(manifest.get("catalog_count") == 14, "frozen catalog count changed")
    require(manifest.get("schema_count") == 346, "frozen schema count changed")
    require(manifest.get("state_machine_count") == 99, "frozen lifecycle count changed")
    require(manifest.get("runtime_implementation_authorized") is False, "contract metadata cannot authorize runtime work")
    files = manifest.get("files")
    require(isinstance(files, list) and files, "generated contract file manifest missing")
    checked: dict[str, str] = {}
    for entry in files:
        require(isinstance(entry, dict), "generated file manifest entry must be an object")
        relative = entry.get("repository_path")
        expected = entry.get("sha256")
        require(isinstance(relative, str) and isinstance(expected, str), "generated file identity incomplete")
        path = repo_root / relative
        require(path.is_file(), f"generated contract file missing: {relative}")
        actual = sha256(path)
        require(actual == expected, f"generated contract digest mismatch: {relative}")
        checked[relative] = actual
    return {
        "catalog_count": 14,
        "schema_count": 346,
        "state_machine_count": 99,
        "catalog_set_sha256": manifest.get("catalog_set_sha256"),
        "checked_files": checked,
    }


def _validate_workspace_profiles(repo_root: Path) -> dict[str, Any]:
    ai_profile = load_json(repo_root / "design/candidates/ai-project-workspace-profile.json")
    expected_owners = {
        "context_selection_owner": "caller_application",
        "source_authority_owner": "caller_application",
        "review_authority_owner": "reviewer_application",
        "approval_authority_owner": "human_or_calling_application",
        "next_action_owner": "caller_application",
    }
    require(ai_profile.get("decision_authority") is False, "Ptah decision authority must remain false")
    require(ai_profile.get("runtime_implementation_authorized") is False, "AI profile cannot authorize runtime work")
    for key, value in expected_owners.items():
        require(ai_profile.get(key) == value, f"authority owner drift: {key}")

    bridge = (repo_root / "design/candidates/HUNTER-PTAH-WORKSPACE-BRIDGE.md").read_text(encoding="utf-8")
    for phrase in (
        "Ptah does not interpret intent, select context, rank sources",
        "Ptah does not perform the review",
        "Ptah does not promote a candidate",
        "Ptah does not decide whether approval should be granted",
    ):
        require(phrase in bridge, f"Hunter handoff boundary missing: {phrase}")

    deep = load_json(repo_root / "design/candidates/workspace-operations-profile-v2.json")
    capabilities = deep.get("mechanical_capabilities_to_borrow")
    require(isinstance(capabilities, list) and len(capabilities) == 22, "deep profile must retain 22 mechanical capabilities")
    for key in (
        "decision_authority",
        "context_selection_authority",
        "review_authority",
        "approval_authority",
        "new_core_entity_required",
        "frozen_contract_change_required",
        "runtime_implementation_authorized",
    ):
        require(deep.get(key) is False, f"deep profile forbidden authority state: {key}")
    method = deep.get("study_method")
    require(isinstance(method, dict), "deep study method missing")
    require(method.get("primary_lanes") == 10 and method.get("independent_verifier_lanes") == 10, "deep study ten-for-two formation changed")

    fixtures = load_json(repo_root / "design/candidates/fixtures/workspace-operations-fixtures-v2.json")
    fixture_list = fixtures.get("fixtures")
    require(isinstance(fixture_list, list) and len(fixture_list) == 20, "deep workspace fixture count must remain 20")
    require(fixtures.get("runtime_implementation_authorized") is False, "deep fixtures cannot authorize runtime work")
    return {
        "mechanical_capability_count": 22,
        "fixture_count": 20,
        "primary_lanes": 10,
        "independent_verifier_lanes": 10,
    }


def _validate_human_control_snapshot(repo_root: Path) -> dict[str, Any]:
    snapshot = load_json(repo_root / "services/ptah-control/tests/fixtures/a14_snapshot.json")
    activities = snapshot.get("activities")
    require(isinstance(activities, list) and activities, "A14 activity projection missing")
    for activity in activities:
        require(isinstance(activity, dict), "activity projection must be an object")
        if activity.get("worker_completion") and activity.get("acceptance") == "accepted":
            require(bool(activity.get("evidence")), "green accepted activity lacks retained evidence")

    advisories = snapshot.get("advisories")
    require(isinstance(advisories, list) and advisories, "diagnostic advisory projection missing")
    for advisory in advisories:
        require(isinstance(advisory, dict), "advisory projection must be an object")
        require(bool(advisory.get("observed_facts")), "advisory observed facts missing")
        require(bool(advisory.get("evidence")), "advisory evidence missing")
        require(bool(advisory.get("suggestions")), "advisory suggestion missing")

    workers = snapshot.get("workers")
    require(isinstance(workers, list) and workers, "worker formation projection missing")
    for worker in workers:
        require(isinstance(worker, dict), "worker projection must be an object")
        require(bool(worker.get("checkpoint")), "worker checkpoint missing")
        require(bool(worker.get("partial_result")), "worker partial result missing")
        require(bool(worker.get("conflict")), "worker conflict must remain visible")
        require(worker.get("completed") is True, "qualification worker must be complete")
        require(worker.get("acceptance") == "pending", "worker completion must not auto-accept")

    recovery = snapshot.get("recovery")
    require(isinstance(recovery, dict), "recovery projection missing")
    require(recovery.get("checkpoint_integrity") == "verified", "checkpoint integrity is not verified")
    require(recovery.get("restore_compatibility") == "compatible", "restore compatibility is not proven")
    require(recovery.get("recovery_verification") == "verified", "recovery verification is not proven")
    require(bool(snapshot.get("evidence_links")), "human control surface lacks evidence links")
    return {
        "activity_count": len(activities),
        "advisory_count": len(advisories),
        "worker_projection_count": len(workers),
        "recovery_verified": True,
    }


def validate_repository(repo_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    required_paths = [
        "Cargo.lock",
        "dependencies/backend-artifact-lock.json",
        "browser-provider/package-lock.json",
        "contracts/generated/manifest.json",
        "crates/ptah-contracts/src/generated.rs",
        "design/candidates/ai-project-workspace-profile.json",
        "design/candidates/HUNTER-PTAH-WORKSPACE-BRIDGE.md",
        "design/candidates/workspace-operations-profile-v2.json",
        "design/candidates/fixtures/workspace-operations-fixtures-v2.json",
        "services/ptah-control/tests/fixtures/a14_snapshot.json",
        "conformance/a15/wp14-golden-negative-freeze-cases.v0.1.0.json",
    ]
    for relative in required_paths:
        require((repo_root / relative).is_file(), f"required A15 input missing: {relative}")

    wp14 = validate_wp14_corpus(repo_root / required_paths[-1])
    contracts = _validate_contract_bindings(repo_root)
    profiles = _validate_workspace_profiles(repo_root)
    human = _validate_human_control_snapshot(repo_root)
    dependency_files = {
        relative: sha256(repo_root / relative)
        for relative in (
            "Cargo.lock",
            "dependencies/backend-artifact-lock.json",
            "browser-provider/package-lock.json",
            "contracts/generated/manifest.json",
        )
    }
    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.a15.online_alpha_acceptance",
        "status": "pass",
        "a14_base_sha": A14_BASE_SHA,
        "wp14_merge_sha": WP14_MERGE_SHA,
        "wp14_corpus_sha256": WP14_CORPUS_SHA256,
        "wp14": wp14,
        "contracts": contracts,
        "workspace_profiles": profiles,
        "human_control": human,
        "dependencies": dependency_files,
        "offline_schema_resolution_required": True,
        "ptah_caller_work_selection_authority": False,
        "ptah_context_selection_authority": False,
        "ptah_review_authority": False,
        "ptah_result_acceptance_authority": False,
        "ptah_autonomous_upgrade_authority": False,
        "limitations": [
            "This validator proves committed acceptance inputs and authority boundaries; execution proof is emitted by the A15 exact-head workflow.",
            "Authorized-for-dispatch is not operation success and worker completion is not caller/reviewer acceptance.",
            "External Provider effects remain subject to their own retained Receipts and verification evidence.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate_repository(args.repo_root)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())