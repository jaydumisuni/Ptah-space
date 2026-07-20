#!/usr/bin/env python3
"""Generate and verify the Phase 0B frozen public catalog lock.

This is Phase 0C preparation tooling. It does not generate runtime behavior or
change any frozen Ptah contract.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

GENERATOR_VERSION = "0.1.0"
FREEZE_COMMIT = "dc2db457f1705d0cba80f17ab76e5e93f808aee0"
WP14_MERGE = "fef387c4f074af7fcf86f2d99f7f9b7637e91f88"

EXPECTED_CATALOGS: tuple[tuple[str, str], ...] = (
    (
        "schemas/phase-0b/activity/schema-catalog.v0.1.1.json",
        "urn:ptah:schema-catalog:activity:0.1.1",
    ),
    (
        "schemas/phase-0b/application/schema-catalog.v0.1.0.json",
        "urn:ptah:schema-catalog:application:0.1.0",
    ),
    (
        "schemas/phase-0b/build/schema-catalog.v0.1.1.json",
        "urn:ptah:schema-catalog:build:0.1.1",
    ),
    (
        "schemas/phase-0b/common/schema-catalog.v0.1.0.json",
        "urn:ptah:schema-catalog:common:0.1.0",
    ),
    (
        "schemas/phase-0b/conformance/schema-catalog.v0.1.0.json",
        "urn:ptah:schema-catalog:conformance:0.1.0",
    ),
    (
        "schemas/phase-0b/corpus/schema-catalog.v0.1.0.json",
        "urn:ptah:schema-catalog:corpus:0.1.0",
    ),
    (
        "schemas/phase-0b/domain/schema-catalog.v0.1.2.json",
        "urn:ptah:schema-catalog:domain:0.1.2",
    ),
    (
        "schemas/phase-0b/isolation/schema-catalog.v0.1.0.json",
        "urn:ptah:schema-catalog:isolation:0.1.0",
    ),
    (
        "schemas/phase-0b/knowledge/schema-catalog.v0.1.0.json",
        "urn:ptah:schema-catalog:knowledge:0.1.0",
    ),
    (
        "schemas/phase-0b/object/schema-catalog.v0.1.0.json",
        "urn:ptah:schema-catalog:object:0.1.0",
    ),
    (
        "schemas/phase-0b/runtime/schema-catalog.v0.1.2.json",
        "urn:ptah:schema-catalog:runtime:0.1.2",
    ),
    (
        "schemas/phase-0b/security/schema-catalog.v0.1.0.json",
        "urn:ptah:schema-catalog:security:0.1.0",
    ),
    (
        "schemas/phase-0b/transfer/schema-catalog.v0.1.0.json",
        "urn:ptah:schema-catalog:transfer:0.1.0",
    ),
    (
        "schemas/phase-0b/workspace/schema-catalog.v0.1.1.json",
        "urn:ptah:schema-catalog:workspace:0.1.1",
    ),
)


class LockError(RuntimeError):
    """Raised when the frozen catalog set cannot be locked safely."""


def sha256_bytes(data: bytes) -> str:
    """Return a lower-case SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    """Serialize a JSON value deterministically for aggregate digests."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def load_catalog(root: Path, repository_path: str, expected_id: str) -> dict[str, Any]:
    """Load, validate and describe one exact frozen catalog."""
    path = root / repository_path
    if not path.is_file():
        raise LockError(f"required frozen catalog is missing: {repository_path}")

    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LockError(f"invalid JSON in {repository_path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise LockError(f"catalog root must be an object: {repository_path}")

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
    if not isinstance(schemas, list):
        raise LockError(f"catalog schemas must be an array: {repository_path}")

    state_machines = payload.get("state_machines", [])
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

    return {
        "repository_path": repository_path,
        "catalog_id": expected_id,
        "catalog_version": str(payload.get("catalog_version", "")),
        "maturity": str(payload.get("maturity", "")),
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
        "schema_count": len(schemas),
        "state_machine_count": len(state_machines),
    }


def build_lock(roadmap_root: Path, generator_path: Path) -> dict[str, Any]:
    """Build the complete deterministic lock document."""
    catalogs = [
        load_catalog(roadmap_root, repository_path, catalog_id)
        for repository_path, catalog_id in EXPECTED_CATALOGS
    ]
    catalogs.sort(key=lambda item: item["catalog_id"])

    if len(catalogs) != 14:
        raise LockError(f"expected 14 active catalogs, generated {len(catalogs)}")

    catalog_set_digest = sha256_bytes(canonical_bytes(catalogs))
    generator_raw = generator_path.read_bytes()

    return {
        "schema_version": "0.2.0",
        "status": "frozen_catalogs_locked_binding_generation_open",
        "authority": {
            "repository": "jaydumisuni/ptah-roadmap-",
            "phase_0b_freeze_merge": FREEZE_COMMIT,
            "wp14_merge": WP14_MERGE,
        },
        "network_resolution_allowed": False,
        "catalog_count": len(catalogs),
        "catalog_set_sha256": catalog_set_digest,
        "catalogs": catalogs,
        "generator": {
            "name": "ptah-phase0c-frozen-contract-lock",
            "version": GENERATOR_VERSION,
            "repository_path": "tools/lock_frozen_contracts.py",
            "sha256": sha256_bytes(generator_raw),
        },
        "generated_bindings": None,
        "blockers": [
            "Generate Rust bindings offline from this exact locked catalog set.",
            "Record generated input and output-tree SHA-256 digests.",
            "Run generated-binding reproducibility and frozen WP13 conformance at one exact head.",
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
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    lock = build_lock(args.roadmap_root, args.generator_path)
    expected = render(lock)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(expected)

    if args.check is not None:
        if not args.check.is_file():
            raise LockError(f"committed lock is missing: {args.check}")
        observed = args.check.read_bytes()
        if observed != expected:
            raise LockError(
                f"committed lock does not match generated lock; candidate written to {args.output}"
            )

    print(
        json.dumps(
            {
                "catalog_count": lock["catalog_count"],
                "catalog_set_sha256": lock["catalog_set_sha256"],
                "output": str(args.output),
                "check": str(args.check) if args.check else None,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
