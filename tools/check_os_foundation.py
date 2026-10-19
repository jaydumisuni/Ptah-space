#!/usr/bin/env python3
"""Programme F: read-only, fail-closed OS foundation profile and evidence preflight.

This is a preparation gate, NOT an installer, service manager, transport,
production enrollment authority, native Ptah dispatcher or release approver.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

PROFILE_SCHEMA = "ptah.os-foundation.profile/1"
EVIDENCE_SCHEMA = "ptah.os-foundation.evidence-index/1"
PHASES = ("F01", "F02", "F03", "F04", "F05", "F06", "F07")
REQUIRED_PROOFS = {
    "F01": ("signed_package_manifest", "service_dependency_closure", "service_fail_closed"),
    "F02": ("physical_hardware_inventory", "capability_evidence", "device_rule_isolation"),
    "F03": ("vm_isolation", "virtual_disk_recovery", "host_resource_bound"),
    "F04": ("reproducible_image_digest", "offline_install_recovery", "verified_boot_route"),
    "F05": ("atomic_update", "rollback_compatibility", "encrypted_recovery"),
    "F06": ("human_shell_accessibility", "offline_local_shell", "shell_restart"),
    "F07": ("two_host_owner_acceptance", "independent_review", "full_os_recovery"),
}
HOST_OS = frozenset(("linux", "windows", "macos", "android"))
IDENT = re.compile(r"^[a-z][a-z0-9-]{1,59}$")
SENSITIVE = frozenset((
    "secret", "private_key", "password", "credential", "token",
    "key_material", "certificate_private_key", "shell_command", "execute",
    "install_command", "transport_endpoint", "private_cert",
))
MAX_FILE = 128 * 1024


class ProfileError(ValueError):
    """Invalid/untrusted foundation candidate."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ProfileError(code)


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in obj, "DUPLICATE_KEY:" + key)
        obj[key] = value
    return obj


def read_json(file: Path) -> dict[str, Any]:
    require(file.is_file() and not file.is_symlink(), "INVALID_PROFILE_FILE")
    require(file.stat().st_size <= MAX_FILE, "PROFILE_TOO_LARGE")
    try:
        result = json.loads(file.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError("INVALID_JSON") from exc
    require(type(result) is dict, "ROOT_NOT_OBJECT")
    return result


def keys(record: Any, expected: set[str], code: str) -> None:
    require(type(record) is dict and set(record) == expected, code + "_KEYS")


def scrub(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            require(isinstance(key, str), "NONSTRING_KEY")
            require(key.lower() not in SENSITIVE, "UNAPPROVED_SECRET_OR_EXEC_FIELD:" + key)
            scrub(item)
    elif isinstance(value, list):
        for item in value:
            scrub(item)


def valid_id(value: Any) -> bool:
    return type(value) is str and IDENT.fullmatch(value) is not None


def require_ids(records: list[dict[str, Any]], field: str) -> None:
    vals = [x.get(field) for x in records]
    require(all(valid_id(x) for x in vals) and len(vals) == len(set(vals)),
            "DUPLICATE_OR_INVALID_" + field.upper())


def validate_profile(p: dict[str, Any]) -> dict[str, Any]:
    keys(p, {"schema", "scope", "architecture", "targets", "services", "phase_gates"}, "PROFILE")
    scrub(p)
    require(p["schema"] == PROFILE_SCHEMA and p["scope"] == "design_only", "NOT_NONACTIVATING_PROFILE")
    arch = p["architecture"]
    keys(arch, {"machine_transport", "ptah_role", "agent_authority", "native_execution"}, "ARCH")
    require(arch == {
        "machine_transport": "oracle",
        "ptah_role": "shared_workspace_only",
        "agent_authority": "external_to_ptah",
        "native_execution": "disabled_without_production_admission",
    }, "WRONG_TRANSPORT_OR_AUTHORITY_BOUNDARY")

    targets = p["targets"]
    require(type(targets) is list and 1 <= len(targets) <= 16, "INVALID_TARGETS")
    for host in targets:
        keys(host, {"id", "os", "admission", "physical_proof"}, "TARGET")
        require(type(host["os"]) is str and host["os"] in HOST_OS and host["admission"] == "unverified"
                and host["physical_proof"] is None, "FORGED_HOST_ADMISSION")
    require_ids(targets, "id")

    services = p["services"]
    require(type(services) is list and 1 <= len(services) <= 50, "INVALID_SERVICES")
    for service in services:
        keys(service, {"id", "provider", "default_enabled", "artifact_digest", "admission",
                       "required_authorities"}, "SERVICE")
        require(valid_id(service["provider"]) and service["default_enabled"] is False
                and service["artifact_digest"] is None
                and service["admission"] == "not_admitted", "UNAPPROVED_SERVICE_ACTIVATION")
        req = service["required_authorities"]
        require(type(req) is list and all(type(x) is str for x in req) and req == sorted(set(req))
                and set(req) == {"e01", "e02", "e05", "owner"}, "MISSING_NATIVE_AUTHORITY")
    require_ids(services, "id")
    gates = p["phase_gates"]
    keys(gates, set(PHASES), "PHASE_GATE")
    for phase in PHASES:
        rec = gates[phase]
        keys(rec, {"status", "required_proofs"}, "PHASE_" + phase)
        require(rec["status"] == "not_admitted", "FORGED_PHASE_RELEASE:" + phase)
        require(rec["required_proofs"] == list(REQUIRED_PROOFS[phase]),
                "MISSING_OR_ALTERED_PHASE_PROOFS:" + phase)
    return {"profile_valid": True, "status": "CANDIDATE_ONLY_NOT_ADMITTED",
            "targets": len(targets), "services": len(services), "phases": len(PHASES)}


def validate_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    keys(evidence, {"schema", "candidate_commit", "status", "external_reviews",
                    "phase_proofs", "native_e07"}, "EVIDENCE")
    scrub(evidence)
    require(evidence["schema"] == EVIDENCE_SCHEMA and evidence["status"] == "not_admitted",
            "SELF_CERTIFIED_EVIDENCE")
    require(type(evidence["candidate_commit"]) is str
            and re.fullmatch(r"[a-f0-9]{40}", evidence["candidate_commit"]),
            "INVALID_COMMIT_ID")
    require(type(evidence["external_reviews"]) is list and evidence["external_reviews"] == [], "UNVERIFIED_EXTERNAL_REVIEW_CLAIM")
    keys(evidence["phase_proofs"], set(PHASES), "EVIDENCE_PHASES")
    for phase in PHASES:
        require(evidence["phase_proofs"][phase] == [], "UNVERIFIED_PHASE_PROOF:" + phase)
    e07 = evidence["native_e07"]
    keys(e07, {"production_enrollment", "two_host_mtls", "owner_signoff"}, "NATIVE_E07")
    require(all(v is False for v in e07.values()), "UNVERIFIED_NATIVE_E07_CLAIM")
    return {"evidence_valid": True, "native_e07": "NO_GO", "os_foundation": "NO_GO",
            "outstanding": [phase + ":" + proof for phase, proofs in REQUIRED_PROOFS.items()
                            for proof in proofs]}


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--profile", type=Path, required=True)
    cli.add_argument("--evidence", type=Path, required=True)
    cli.add_argument("--output", type=Path)
    args = cli.parse_args()
    try:
        result = {
            "schema": "ptah.os-foundation.preflight/1",
            "profile": validate_profile(read_json(args.profile)),
            "evidence": validate_evidence(read_json(args.evidence)),
            "execution_authorized": False,
            "release_authorized": False,
        }
    except ProfileError as exc:
        print("F_PRECHECK_REJECTED:" + str(exc), file=sys.stderr)
        return 2
    report = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        if args.output in (args.profile, args.evidence):
            print("F_PRECHECK_REJECTED:OUTPUT_MUST_NOT_OVERWRITE_SOURCE", file=sys.stderr)
            return 2
        args.output.write_text(report, encoding="utf-8")
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
