#!/usr/bin/env python3
"""Generate and verify the Phase 0B frozen public contract lock.

The lock is derived only from the exact frozen roadmap catalogs and the
committed deterministic binding manifest. It does not authorize runtime
implementation or change any frozen Ptah contract.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

GENERATOR_VERSION = "0.2.0"
FREEZE_COMMIT = "dc2db457f1705d0cba80f17ab76e5e93f808aee0"
WP14_MERGE = "fef387c4f074af7fcf86f2d99f7f9b7637e91f88"
EXPECTED_COUNTS = (14, 346, 99)

EXPECTED_CATALOGS: tuple[tuple[str, str], ...] = (
    ("schemas/phase-0b/activity/schema-catalog.v0.1.1.json", "urn:ptah:schema-catalog:activity:0.1.1"),
    ("schemas/phase-0b/application/schema-catalog.v0.1.0.json", "urn:ptah:schema-catalog:application:0.1.0"),
    ("schemas/phase-0b/build/schema-catalog.v0.1.1.json", "urn:ptah:schema-catalog:build:0.1.1"),
    ("schemas/phase-0b/common/schema-catalog.v0.1.0.json", "urn:ptah:schema-catalog:common:0.1.0"),
    ("schemas/phase-0b/conformance/schema-catalog.v0.1.0.json", "urn:ptah:schema-catalog:conformance:0.1.0"),
    ("schemas/phase-0b/corpus/schema-catalog.v0.1.0.json", "urn:ptah:schema-catalog:corpus:0.1.0"),
    ("schemas/phase-0b/domain/schema-catalog.v0.1.2.json", "urn:ptah:schema-catalog:domain:0.1.2"),
    ("schemas/phase-0b/isolation/schema-catalog.v0.1.0.json", "urn:ptah:schema-catalog:isolation:0.1.0"),
    ("schemas/phase-0b/knowledge/schema-catalog.v0.1.0.json", "urn:ptah:schema-catalog:knowledge:0.1.0"),
    ("schemas/phase-0b/object/schema-catalog.v0.1.0.json", "urn:ptah:schema-catalog:object:0.1.0"),
    ("schemas/phase-0b/runtime/schema-catalog.v0.1.2.json", "urn:ptah:schema-catalog:runtime:0.1.2"),
    ("schemas/phase-0b/security/schema-catalog.v0.1.0.json", "urn:ptah:schema-catalog:security:0.1.0"),
    ("schemas/phase-0b/transfer/schema-catalog.v0.1.0.json", "urn:ptah:schema-catalog:transfer:0.1.0"),
    ("schemas/phase-0b/workspace/schema-catalog.v0.1.1.json", "urn:ptah:schema-catalog:workspace:0.1.1"),
)


class LockError(RuntimeError):
    """Raised when the frozen contract set cannot be locked safely."""


def sha256_bytes(data: bytes) -> str:
    """Return a lower-case SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    """Serialize a JSON value deterministically for aggregate digests."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def optional_text(value: Any) -> str | None:
    """Preserve a non-empty textual field without inventing metadata."""
    return value if isinstance(value, str) and value else None


def load_json_object(path: Path) -> tuple[dict[str, Any], bytes]:
    """Load one required JSON object and preserve its exact bytes."""
    if not path.is_file():
        raise LockError(f"required file is missing: {path}")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LockError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise LockError(f"JSON root must be an object: {path}")
    return payload, raw


def load_catalog(root: Path, repository_path: str, expected_id: str) -> dict[str, Any]:
    """Load, validate and describe one exact frozen catalog."""
    payload, raw = load_json_object(root / repository_path)
    actual_id = payload.get("catalog_id")
    if actual_id != expected_id:
        raise LockError(
            f"catalog ID mismatch for {repository_path}: expected {expected_id!r}, "
            f"observed {actual_id!r}"
        )

    resolution = payload.get("resolution_policy", {})
    if isinstance(resolution, dict) and resolution.get("network_resolution_required") is True:
        raise LockError(f"frozen catalog requires network resolution: {repository_path}")

    schemas = payload.get("schemas", [])
    state_machines = payload.get("state_machines", [])
    if not isinstance(schemas, list):
        raise LockError(f"catalog schemas must be an array: {repository_path}")
    if not isinstance(state_machines, list):
        raise LockError(f"catalog state_machines must be an array: {repository_path}")

    schema_ids = [item.get("schema_id") for item in schemas if isinstance(item, dict)]
    if len(schema_ids) != len(set(schema_ids)):
        raise LockError(f"duplicate schema IDs in catalog: {repository_path}")

    machine_keys = [
        (
            item.get("state_machine_name") or item.get("machine") or item.get("name"),
            item.get("state_machine_version") or item.get("version"),
        )
        for item in state_machines
        if isinstance(item, dict)
    ]
    if len(machine_keys) != len(set(machine_keys)):
        raise LockError(f"duplicate lifecycle identity in catalog: {repository_path}")

    version = (
        optional_text(payload.get("catalog_version"))
        or optional_text(payload.get("version"))
        or expected_id.rsplit(":", 1)[-1]
    )
    return {
        "repository_path": repository_path,
        "catalog_id": expected_id,
        "catalog_version": version,
        "maturity": optional_text(payload.get("maturity")),
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
        "schema_count": len(schemas),
        "state_machine_count": len(state_machines),
    }


def validate_binding_manifest(
    manifest_path: Path,
    expected_catalog_digest: str,
) -> dict[str, Any]:
    """Validate the committed deterministic binding manifest and its outputs."""
    manifest, manifest_raw = load_json_object(manifest_path)
    authority = manifest.get("authority")
    if authority != {
        "repository": "jaydumisuni/ptah-roadmap-",
        "phase_0b_freeze_merge": FREEZE_COMMIT,
        "wp14_merge": WP14_MERGE,
    }:
        raise LockError("binding manifest authority does not match the frozen checkpoint")
    if manifest.get("catalog_set_sha256") != expected_catalog_digest:
        raise LockError("binding manifest catalog-set digest does not match the frozen lock")
    if (
        manifest.get("catalog_count"),
        manifest.get("schema_count"),
        manifest.get("state_machine_count"),
    ) != EXPECTED_COUNTS:
        raise LockError("binding manifest counts do not match the frozen set")
    if manifest.get("runtime_implementation_authorized") is not False:
        raise LockError("binding manifest cannot authorize runtime implementation")

    generator = manifest.get("generator")
    if not isinstance(generator, dict):
        raise LockError("binding manifest generator record is missing")
    required_generator_fields = ("name", "version", "repository_path", "sha256", "sources")
    if not all(generator.get(field) for field in required_generator_fields):
        raise LockError("binding manifest generator record is incomplete")

    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != 2:
        raise LockError("binding manifest must record exactly the index and Rust module")
    by_path = {
        item.get("repository_path"): item
        for item in files
        if isinstance(item, dict) and isinstance(item.get("repository_path"), str)
    }
    expected_paths = {
        "contracts/generated/catalog-index.json",
        "crates/ptah-contracts/src/generated.rs",
    }
    if set(by_path) != expected_paths:
        raise LockError("binding manifest output paths are incomplete or unexpected")

    repository_root = manifest_path.parents[2]
    verified_files: dict[str, dict[str, Any]] = {}
    for repository_path in sorted(expected_paths):
        record = by_path[repository_path]
        output_path = repository_root / repository_path
        if not output_path.is_file():
            raise LockError(f"generated binding output is missing: {repository_path}")
        raw = output_path.read_bytes()
        if record.get("sha256") != sha256_bytes(raw) or record.get("size_bytes") != len(raw):
            raise LockError(f"generated binding output digest/size mismatch: {repository_path}")
        verified_files[repository_path] = {
            "repository_path": repository_path,
            "sha256": record["sha256"],
            "size_bytes": record["size_bytes"],
        }

    file_records = [verified_files[path] for path in sorted(verified_files)]
    output_tree_sha256 = sha256_bytes(canonical_bytes(file_records))
    if manifest.get("output_tree_sha256") != output_tree_sha256:
        raise LockError("binding manifest output-tree digest is invalid")

    return {
        "generator": generator,
        "manifest": {
            "repository_path": "contracts/generated/manifest.json",
            "sha256": sha256_bytes(manifest_raw),
            "size_bytes": len(manifest_raw),
        },
        "catalog_index": verified_files["contracts/generated/catalog-index.json"],
        "rust_module": verified_files["crates/ptah-contracts/src/generated.rs"],
        "output_tree_sha256": output_tree_sha256,
        "catalog_count": manifest["catalog_count"],
        "schema_count": manifest["schema_count"],
        "state_machine_count": manifest["state_machine_count"],
        "runtime_implementation_authorized": False,
    }


def build_lock(
    roadmap_root: Path,
    generator_path: Path,
    binding_manifest_path: Path,
) -> dict[str, Any]:
    """Build the complete deterministic catalog-and-binding lock document."""
    catalogs = [
        load_catalog(roadmap_root, repository_path, catalog_id)
        for repository_path, catalog_id in EXPECTED_CATALOGS
    ]
    catalogs.sort(key=lambda item: item["catalog_id"])
    if len(catalogs) != EXPECTED_COUNTS[0]:
        raise LockError(f"expected 14 active catalogs, generated {len(catalogs)}")

    catalog_set_sha256 = sha256_bytes(canonical_bytes(catalogs))
    generated_bindings = validate_binding_manifest(binding_manifest_path, catalog_set_sha256)
    return {
        "schema_version": "0.3.0",
        "status": "frozen_catalogs_and_bindings_locked_runtime_dependencies_open",
        "authority": {
            "repository": "jaydumisuni/ptah-roadmap-",
            "phase_0b_freeze_merge": FREEZE_COMMIT,
            "wp14_merge": WP14_MERGE,
        },
        "network_resolution_allowed": False,
        "catalog_count": len(catalogs),
        "catalog_set_sha256": catalog_set_sha256,
        "catalogs": catalogs,
        "generator": {
            "name": "ptah-phase0c-frozen-contract-lock",
            "version": GENERATOR_VERSION,
            "repository_path": "tools/lock_frozen_contracts.py",
            "sha256": sha256_bytes(generator_path.read_bytes()),
        },
        "generated_bindings": generated_bindings,
        "blockers": [
            "Select and lock the minimal external Rust runtime dependency graph.",
            "Produce exact dependency licence and advisory evidence.",
            "Implement and run the host capability collector on the pinned host image.",
            "Retain final Phase 0C evidence in a durable proof Location.",
            "Accept the public licence boundary and ADR-0033 before runtime authorization.",
        ],
    }


def render(lock: dict[str, Any]) -> bytes:
    """Render the lock with stable formatting and one trailing newline."""
    return (json.dumps(lock, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roadmap-root", type=Path, required=True)
    parser.add_argument(
        "--generator-path", type=Path, default=Path("tools/lock_frozen_contracts.py")
    )
    parser.add_argument(
        "--binding-manifest",
        type=Path,
        default=Path("contracts/generated/manifest.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    expected = render(
        build_lock(args.roadmap_root, args.generator_path, args.binding_manifest)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(expected)

    if args.check is not None:
        if not args.check.is_file():
            raise LockError(f"committed lock is missing: {args.check}")
        if args.check.read_bytes() != expected:
            raise LockError(
                f"committed lock does not match generated lock; candidate written to {args.output}"
            )

    lock = json.loads(expected)
    print(
        json.dumps(
            {
                "catalog_count": lock["catalog_count"],
                "catalog_set_sha256": lock["catalog_set_sha256"],
                "binding_output_tree_sha256": lock["generated_bindings"][
                    "output_tree_sha256"
                ],
                "output": str(args.output),
                "check": str(args.check) if args.check else None,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
