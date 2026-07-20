#!/usr/bin/env python3
"""Validate that Phase 0C preparation cannot be mistaken for an authorized runtime."""
from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCKED_BINDING_STATE = "frozen_catalogs_and_bindings_locked_runtime_dependencies_open"


def sha256(path: Path) -> str:
    """Return one file's lower-case SHA-256 digest."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def string_entries_contain(value: Any, needle: str, *, ignore_case: bool = False) -> bool:
    """Return whether a list contains a string entry with ``needle``."""
    if not isinstance(value, list):
        return False
    if ignore_case:
        needle = needle.lower()
    return any(
        isinstance(item, str)
        and needle in (item.lower() if ignore_case else item)
        for item in value
    )


readme = (ROOT / "README.md").read_text(encoding="utf-8")
if "Runtime implementation is not authorized" not in readme:
    raise SystemExit("README no-build boundary missing")

lock = json.loads((ROOT / "contracts/upstream-lock.json").read_text(encoding="utf-8"))
allowed_lock_states = {
    "incomplete_phase0c_candidate",
    "frozen_catalogs_locked_binding_generation_open",
    LOCKED_BINDING_STATE,
}
if lock.get("status") not in allowed_lock_states:
    raise SystemExit("Contract lock state is not an accepted Phase 0C preparation state")
if lock.get("network_resolution_allowed") is not False:
    raise SystemExit("Network schema resolution must remain disabled")

if lock.get("status") in {
    "frozen_catalogs_locked_binding_generation_open",
    LOCKED_BINDING_STATE,
}:
    catalogs = lock.get("catalogs")
    if lock.get("catalog_count") != 14 or not isinstance(catalogs, list) or len(catalogs) != 14:
        raise SystemExit("Frozen catalog lock must contain exactly fourteen active catalogs")

if lock.get("status") == "frozen_catalogs_locked_binding_generation_open":
    if lock.get("generated_bindings") is not None:
        raise SystemExit("Generated bindings cannot be claimed before the binding gate passes")
    blockers = lock.get("blockers")
    if not string_entries_contain(blockers, "Generate Rust bindings"):
        raise SystemExit("Catalog-locked state must retain the generated-binding blocker")

if lock.get("status") == LOCKED_BINDING_STATE:
    generated = lock.get("generated_bindings")
    if not isinstance(generated, dict):
        raise SystemExit("Binding-locked state must contain generated binding evidence")
    if generated.get("runtime_implementation_authorized") is not False:
        raise SystemExit("Generated binding evidence cannot authorize runtime implementation")
    if (
        generated.get("catalog_count"),
        generated.get("schema_count"),
        generated.get("state_machine_count"),
    ) != (14, 346, 99):
        raise SystemExit("Generated binding counts do not match the frozen set")

    manifest_path = ROOT / "contracts/generated/manifest.json"
    index_path = ROOT / "contracts/generated/catalog-index.json"
    rust_path = ROOT / "crates/ptah-contracts/src/generated.rs"
    for path in (manifest_path, index_path, rust_path):
        if not path.is_file():
            raise SystemExit(f"Locked generated output is missing: {path.relative_to(ROOT)}")

    expected_files = {
        "manifest": (manifest_path, "contracts/generated/manifest.json"),
        "catalog_index": (index_path, "contracts/generated/catalog-index.json"),
        "rust_module": (rust_path, "crates/ptah-contracts/src/generated.rs"),
    }
    for key, (path, repository_path) in expected_files.items():
        record = generated.get(key)
        if not isinstance(record, dict):
            raise SystemExit(f"Generated binding record is missing: {key}")
        if record.get("repository_path") != repository_path:
            raise SystemExit(f"Generated binding path mismatch: {key}")
        if record.get("sha256") != sha256(path):
            raise SystemExit(f"Generated binding digest mismatch: {key}")
        if record.get("size_bytes") != path.stat().st_size:
            raise SystemExit(f"Generated binding size mismatch: {key}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if generated.get("generator") != manifest.get("generator"):
        raise SystemExit("Locked binding generator record does not match the manifest")
    if generated.get("output_tree_sha256") != manifest.get("output_tree_sha256"):
        raise SystemExit("Locked binding output-tree digest does not match the manifest")
    if manifest.get("runtime_implementation_authorized") is not False:
        raise SystemExit("Generated manifest cannot authorize runtime implementation")

    blockers = lock.get("blockers")
    if not isinstance(blockers, list) or string_entries_contain(
        blockers, "Generate Rust bindings"
    ):
        raise SystemExit("Binding-locked state cannot retain an obsolete generation blocker")
    if not string_entries_contain(blockers, "runtime dependency", ignore_case=True):
        raise SystemExit("Binding-locked state must retain the runtime-dependency blocker")

selection_path = ROOT / "dependencies/rust-direct-lock.json"
if selection_path.is_file():
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    if selection.get("runtime_implementation_authorized") is not False:
        raise SystemExit("Rust dependency evidence cannot authorize runtime implementation")
    if selection.get("status") not in {
        "candidate_exact_versions_lock_generation_open",
        "exact_versions_locked_policy_evidence_open",
        "exact_versions_and_policy_locked_host_proof_open",
        "exact_versions_and_policy_selected_host_proof_open",
    }:
        raise SystemExit("Rust dependency selection has an unknown Phase 0C state")

    cargo_record = selection.get("cargo_lock")
    cargo_lock_path = ROOT / "Cargo.lock"
    if not isinstance(cargo_record, dict) or cargo_record.get("repository_path") != "Cargo.lock":
        raise SystemExit("Rust dependency selection lacks the Cargo lock record")
    if cargo_record.get("sha256") != sha256(cargo_lock_path):
        raise SystemExit("Cargo.lock does not match the Rust dependency selection")
    if cargo_record.get("git_dependency_count") != 0:
        raise SystemExit("Git dependencies are not allowed in the selected Rust graph")

    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    members = workspace.get("workspace", {}).get("members", [])
    evidence_member = "evidence/rust-dependency-lock"
    if evidence_member not in members:
        raise SystemExit("Dependency lock evidence package is not a workspace member")
    evidence_manifest = ROOT / evidence_member / "Cargo.toml"
    if not evidence_manifest.is_file():
        raise SystemExit("Dependency lock evidence package is missing")

    for manifest_path in ROOT.rglob("Cargo.toml"):
        relative = manifest_path.relative_to(ROOT).as_posix()
        if relative in {"Cargo.toml", f"{evidence_member}/Cargo.toml"}:
            continue
        if "ptah-rust-dependency-lock" in manifest_path.read_text(encoding="utf-8"):
            raise SystemExit(f"Production package links the evidence-only dependency crate: {relative}")

backend_path = ROOT / "dependencies/backend-artifact-lock.json"
if backend_path.is_file():
    backend = json.loads(backend_path.read_text(encoding="utf-8"))
    if backend.get("runtime_implementation_authorized") is not False:
        raise SystemExit("Backend artifact lock cannot authorize runtime implementation")
    if backend.get("status") != "static_and_browser_artifacts_locked_pinned_host_packages_open":
        raise SystemExit("Backend artifact lock is not in the accepted pre-host-proof state")
    verification = backend.get("verification")
    if not isinstance(verification, dict):
        raise SystemExit("Backend verification record is missing")
    if verification.get("tool_path") != "tools/verify_backend_artifacts.py":
        raise SystemExit("Backend verifier path is not canonical")
    if verification.get("workflow_path") != ".github/workflows/phase0c-backend-artifacts.yml":
        raise SystemExit("Backend evidence workflow path is not canonical")
    if verification.get("runtime_implementation_authorized") is not False:
        raise SystemExit("Backend verification cannot authorize runtime implementation")

    artifacts = backend.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 9:
        raise SystemExit("Backend artifact lock must contain exactly nine selected artifacts")
    components: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise SystemExit("Backend artifact entry is invalid")
        component = artifact.get("component")
        digest_record = artifact.get("digest")
        if not isinstance(component, str) or component in components:
            raise SystemExit("Backend artifact identities must be unique")
        components.add(component)
        if not isinstance(digest_record, dict):
            raise SystemExit(f"Backend artifact digest is missing: {component}")
        value = digest_record.get("value")
        if not isinstance(value, str) or not value:
            raise SystemExit(f"Backend artifact digest value is missing: {component}")

    browser = backend.get("browser_binary")
    if not isinstance(browser, dict):
        raise SystemExit("Playwright Browser binary lock is missing")
    if browser.get("runtime_implementation_authorized") is not False:
        raise SystemExit("Browser binary lock cannot authorize runtime implementation")
    if browser.get("status") != "installed_tree_locked":
        raise SystemExit("Browser binary tree is not locked")
    for key in ("revision", "descriptor_sha256", "installed_tree_sha256"):
        if not isinstance(browser.get(key), str) or not browser.get(key):
            raise SystemExit(f"Browser binary lock field is missing: {key}")

    host_packages = backend.get("host_packages")
    if not isinstance(host_packages, dict):
        raise SystemExit("Pinned host package record is missing")
    if host_packages.get("status") != "pinned_host_run_open":
        raise SystemExit("Pinned host package evidence cannot be claimed before the host run")
    if host_packages.get("installed_package_manifest") is not None:
        raise SystemExit("Installed package manifest cannot be claimed before pinned host proof")
    blockers = backend.get("blockers")
    if not string_entries_contain(blockers, "pinned Ubuntu host"):
        raise SystemExit("Backend lock must retain the pinned-host package blocker")

host = json.loads((ROOT / "host/image-lock.json").read_text(encoding="utf-8"))
if host.get("runtime_authorized") is not False:
    raise SystemExit("Host candidate cannot claim runtime authorization")

host_profile = json.loads((ROOT / "host/capability-profile.json").read_text(encoding="utf-8"))
collector = host_profile.get("collector")
if collector is not None:
    if not isinstance(collector, dict):
        raise SystemExit("Host collector record must be an object")
    if collector.get("repository_path") != "host/scripts/collect_capabilities.py":
        raise SystemExit("Host collector path is not canonical")
    if collector.get("identity_finalizer_path") != "host/scripts/finalize_capability_report.py":
        raise SystemExit("Host identity finalizer path is not canonical")
    if collector.get("runtime_implementation_authorized") is not False:
        raise SystemExit("Host collector cannot authorize runtime implementation")
if host_profile.get("pinned_host_proof") is not None:
    raise SystemExit("Pinned host proof cannot be claimed before the reviewed host run")

forbidden_gateway = "applied" + "-caas-gateway"
skip_roots = {".git", "target", "node_modules"}
for path in ROOT.rglob("*"):
    relative = path.relative_to(ROOT)
    if not path.is_file() or any(part in skip_roots for part in relative.parts):
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    if forbidden_gateway in text:
        raise SystemExit(f"Internal package gateway leaked into {relative}")

print("Phase 0C non-claiming scaffold checks passed")
