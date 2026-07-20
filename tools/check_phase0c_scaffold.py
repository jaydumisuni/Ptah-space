#!/usr/bin/env python3
"""Validate that Phase 0C preparation cannot be mistaken for an authorized runtime."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCKED_BINDING_STATE = "frozen_catalogs_and_bindings_locked_runtime_dependencies_open"


def sha256(path: Path) -> str:
    """Return one file's lower-case SHA-256 digest."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    if not isinstance(blockers, list) or not any("Generate Rust bindings" in item for item in blockers):
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
    if not isinstance(blockers, list) or any("Generate Rust bindings" in item for item in blockers):
        raise SystemExit("Binding-locked state cannot retain an obsolete generation blocker")
    if not any("runtime dependency" in item.lower() for item in blockers):
        raise SystemExit("Binding-locked state must retain the runtime-dependency blocker")

host = json.loads((ROOT / "host/image-lock.json").read_text(encoding="utf-8"))
if host.get("runtime_authorized") is not False:
    raise SystemExit("Host candidate cannot claim runtime authorization")

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
