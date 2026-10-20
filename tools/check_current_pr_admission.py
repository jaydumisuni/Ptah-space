#!/usr/bin/env python3
"""Fail-closed Ptah PR admission applicability on the actual checked-out head.

Historical phase proof workflows remain owned by their original predecessor
and path sets; a general PR is not falsely marked as passing them. This is a
universal scope/baseline gate, not a production admission or phase waiver.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HISTORIC = (
    "a02-exact-head-runtime-proof.yml",
    "a07-object-store-proof.yml",
    "a08-transfer-proof.yml",
    "a09-git-provider-proof.yml",
    "a11-browser-provider-proof.yml",
    "a14-human-alpha-control-proof.yml",
    "c08-device-identity-transport.yml",
    "c09-ttg-device-xray-admission.yml",
    "c10-android-application-device-session.yml",
    "c11-device-manager-mibu-workload-admissions.yml",
    "d02-ai-project-workspace-proof.yml",
    "d03-knowledge-data-search-v2-proof.yml",
    "d04-recipes-service-registry-proof.yml",
    "d05-package-plugin-lifecycle-proof.yml",
    "d06-provenance-sbom-signing-proof.yml",
    "d07-security-evidence-reproduction-proof.yml",
    "d08-application-platform-expansion-proof.yml",
    "e01-secure-multi-node-identity-connection.yml",
    "e02-placement-reservation-lease-fence.yml",
    "e03-node-to-node-object-artifact-transfer.yml",
    "e04-proof.yml",
    "e05-proof.yml",
)
# E07 optional native gateway engineering spans pre-existing E01/A14/D08
# crates, and is NOT a replay of those earlier predecessor-bound milestones.
# This exact, reviewed maintenance delta still needs the real current-head
# Rust/Python/scaffold CI workflows. No user/agent admission gate is created.
E07_NATIVE_INTEGRATION_PATHS = frozenset({
    '.github/workflows/e05-supervisor-shadow-gateway-proof.yml',
    '.github/workflows/shared-workspace-python-client.yml',
    'Cargo.lock',
    'clients/python/README.md',
    'clients/python/ptah_control_client.py',
    'clients/python/ptah_shared_workspace.py',
    'clients/python/qualify_live_ptah_control.py',
    'clients/python/test_ptah_control_client.py',
    'clients/python/test_ptah_shared_workspace.py',
    'clients/python/test_ptah_verified_readback.py',
    'crates/ptah-node-link/src/session.rs',
    'docs/HUNTER_SHARED_MISSION_PROVENANCE_20261018.md',
    'docs/SUPERVISOR_E05_GATEWAY_TEST_PROOF_20261013.md',
    'docs/plans/2026-10-16-e07-control-readback-proof.md',
    'services/ptah-control/Cargo.toml',
    'services/ptah-control/src/bin/ptah-enrollment-gateway.rs',
    'services/ptah-control/src/e01_lib.rs',
    'services/ptah-control/src/gateway_control_journal.rs',
    'services/ptah-control/src/gateway_e02_dispatch.rs',
    'services/ptah-control/src/gateway_enrollment.rs',
    'services/ptah-control/src/gateway_session.rs',
    'services/ptah-control/src/gateway_witness.rs',
    'services/ptah-control/src/main.rs',
    'services/ptah-control/src/node_link.rs',
    'services/ptah-control/src/placement.rs',
    'services/ptah-control/src/server.rs',
    'services/ptah-control/src/verified_readback.rs',
    'services/ptah-control/tests/e01_node_link.rs',
    'services/ptah-control/tests/gateway_journal_permissions.rs',
    'services/ptah-control/tests/gateway_mtls_enrollment.rs',
    'services/ptah-control/tests/gateway_retained_session.rs',
    'services/ptah-control/tests/gateway_witness.rs',
    'services/ptah-node/Cargo.toml',
    'services/ptah-node/src/gateway_e02_wire.rs',
    'services/ptah-node/src/gateway_journal.rs',
    'services/ptah-node/src/lib.rs',
    'services/ptah-node/tests/supervisor_gateway_boundary.rs',
    'tools/check_current_pr_admission.py',
    'tools/check_e06_dependency_evolution.py',
    'tools/test_check_current_pr_admission.py',
    'tools/test_check_e06_dependency_evolution.py',
})
E_OWNED = {
    "e01-secure-multi-node-identity-connection.yml": (
        "E01_SECURE_MULTI_NODE_IDENTITY_CONNECTION.md",
        "crates/ptah-node-link/**",
        "services/ptah-node/**",
        "services/ptah-control/tests/e01_node_link.rs",
        "tools/check_e01_secure_multi_node.py",
    ),
    "e02-placement-reservation-lease-fence.yml": (
        "E02_PLACEMENT_RESERVATION_LEASE_FENCE.md",
        "services/ptah-control/tests/e02_placement_authority.rs",
        "tools/check_e02_placement_authority.py",
    ),
    "e03-node-to-node-object-artifact-transfer.yml": (
        "E03_NODE_TO_NODE_OBJECT_ARTIFACT_TRANSFER.md",
        "services/ptah-control/tests/e03_node_transfer.rs",
        "tools/check_e03_node_transfer.py",
    ),
    "e04-proof.yml": (
        "E04_COMPATIBLE_WORKSPACE_MOVEMENT.md",
        "tools/check-e04-conformance.py",
        "crates/ptah-workspace-movement/src/**",
        "crates/ptah-workspace-movement/tests/**",
    ),
    "e05-proof.yml": (
        "E05_PLATFORM_NODES.md",
        "tools/check_e05_conformance.py",
        "tools/check_e05_physical_stage.py",
        "crates/ptah-platform-admission/src/**",
        "crates/ptah-platform-admission/tests/**",
    ),
}
COMMON = frozenset({"Cargo.toml", "Cargo.lock", "dependencies/**"})
HEX = re.compile(r"^[a-f0-9]{40}$")


class AdmissionError(ValueError):
    pass


def git(*args: str) -> str:
    r = subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True, timeout=40)
    if r.returncode:
        raise AdmissionError("git_failed: " + r.stderr[-260:])
    return r.stdout.strip()


def pull_paths(text: str) -> tuple[str, ...]:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line == "  pull_request:"), -1)
    if start < 0:
        raise AdmissionError("pull_request_event_missing")
    subset = []
    for line in lines[start + 1:]:
        if line.startswith("  ") and not line.startswith("    "):
            break
        match = re.fullmatch(r'      - [\x27\x22]?([^\x27\x22\s]+)[\x27\x22]?', line)
        if match:
            subset.append(match.group(1))
    return tuple(subset)


def approved_phase_scope(name: str, baseline: str, candidate: str) -> tuple[str, ...]:
    if name not in HISTORIC:
        raise AdmissionError("unreviewed_phase_workflow")
    original = pull_paths(baseline)
    current = pull_paths(candidate)
    self_path = ".github/workflows/" + name
    if name in E_OWNED:
        expected = (*E_OWNED[name], self_path)
    else:
        expected = tuple(x for x in original if x not in COMMON)
    if tuple(current) != tuple(expected):
        raise AdmissionError("historic_phase_ownership_trigger_drift: " + name)
    # Exact expected textual patch: only PR event path filtering may change;
    # preserve all historical proof steps and branch/dispatch authorities.
    if name in E_OWNED:
        base_event = "  pull_request:\n    branches: [main]\n"
        new_event = base_event + "    paths:\n" + "".join(
            '      - "' + item + '"\n' for item in expected
        )
        computed = baseline.replace(base_event, new_event, 1)
    else:
        lines = baseline.splitlines(keepends=True)
        inside = False
        kept = []
        for line in lines:
            if line == "  pull_request:\n":
                inside = True
            elif inside and line.startswith("  ") and not line.startswith("    "):
                inside = False
            if inside and line.strip().strip("- ").strip('"\x27') in COMMON:
                continue
            kept.append(line)
        computed = "".join(kept)
    if candidate != computed:
        raise AdmissionError("historical_proof_body_or_event_changed: " + name)
    return expected


def scope_affected(name: str, scope: tuple[str, ...], changed: set[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, glob) for path in changed
               for glob in scope if path != ".github/workflows/" + name)


def qualify(base: str, head: str) -> dict:
    if not HEX.fullmatch(head) or not HEX.fullmatch(base):
        raise AdmissionError("invalid_exact_commit")
    if git("rev-parse", "HEAD") != head:
        raise AdmissionError("head_drift")
    if git("merge-base", base, head) != base:
        raise AdmissionError("base_not_ancestor")
    changed = set(git("diff", "--name-only", "--diff-filter=ACDMRT",
                      base + "..." + head).splitlines()) - {""}
    if not changed:
        raise AdmissionError("empty_pr_delta")
    if git("diff", "--check", base + "..." + head):
        raise AdmissionError("diff_whitespace_violation")
    e07_native_integration = changed == E07_NATIVE_INTEGRATION_PATHS
    historic_changes = {
        name for name in HISTORIC if ".github/workflows/" + name in changed
    }
    if historic_changes and historic_changes != set(HISTORIC):
        raise AdmissionError("partial_historical_governance_change")
    phase = {}
    a11_maintenance=False
    for name in HISTORIC:
        path = ".github/workflows/" + name
        before = git("show", base + ":" + path)
        now = (ROOT / path).read_text(encoding="utf-8").strip()
        # git() strips terminal whitespace; compare the same normalized text.
        if historic_changes:
            scope = approved_phase_scope(name, before + "\n", now + "\n")
        else:
            scope = pull_paths(now)
            # For pre-governance Search candidate, historical broad shared
            # dependency triggers are classified, never called successful.
            scope = tuple(p for p in scope if p not in COMMON)
        relevant = scope_affected(name, scope, changed)
        phase[name] = "REQUIRES_PHASE_OWNED_PROOF" if relevant else "NOT_APPLICABLE_NOT_TESTED"
        if relevant:
            if e07_native_integration and not historic_changes:
                # The original milestone was not retested. E07 is covered
                # by current-head native Control/Node/client/scaffold CI.
                phase[name] = "E07_NATIVE_INTEGRATION_HISTORIC_NOT_REPLAYED"
                continue
            # Original historical A11 proof remains immutable and NOT passing
            # for post-baseline maintenance. An independently physically
            # qualified exact-head A11 maintenance gate may handle only its
            # tightly scoped Browser Provider surface. All other phases fail.
            if name == "a11-browser-provider-proof.yml" and not historic_changes:
                from check_a11_maintenance_admission import qualify as qualify_a11
                try:
                    qualify_a11(base,head)
                except ValueError as error:
                    raise AdmissionError("a11_maintenance_scope_rejected: "+str(error)) from error
                phase[name] = "A11_POST_BASELINE_PHYSICAL_PROOF_REQUIRED"
                a11_maintenance=True
            else:
                raise AdmissionError("independent_phase_owned_change_requires_own_proof: " + name)
    search_paths = {
        "README.md", "adapters/internet-search/README.md",
        "adapters/internet-search/bridge.py",
        "adapters/internet-search/test/test_bridge.py",
        "adapters/internet-search/test/test_operator.py",
        "adapters/native-process/tests/a05_ttgs_search_integration.rs",
        "docs/TTG_INTERNET_SEARCH_PROVIDER_2026-10-15.md",
        "tools/ptah_internet_search.py",
    }
    touches_search = bool(changed & (search_paths - {"README.md"}))
    return {
        "schema": "ptah.current-pr.admission-scope.v1",
        "base_sha": base, "exact_head_sha": head,
        "changed_paths_count": len(changed),
        "historical_governance_event_only_change": len(historic_changes) == len(HISTORIC),
        "historical_phase_proofs": phase,
        "search_scope_requires_independent_checker": touches_search,
        "a11_maintenance_scope_requires_independent_checker": a11_maintenance,
        "e07_native_integration_needs_native_ci": e07_native_integration,
        "universal_baseline_required": True,
        "paid_search_authorized": False,
        "production_activation_authorized": False,
        "result": "CURRENT_HEAD_SCOPE_CLASSIFIED_GLOBAL_BASELINE_STILL_REQUIRED",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    try:
        record = qualify(args.base, args.head)
    except AdmissionError as e:
        p.exit(1, "CURRENT_HEAD_ADMISSION_SCOPE_FAILURE: " + str(e) + "\n")
    out = json.dumps(record, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(out)
    print(out, end="")


if __name__ == "__main__":
    main()
