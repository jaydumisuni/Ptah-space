#!/usr/bin/env python3
"""Generate deterministic Phase 0C Rust bindings from the frozen catalog lock.

The output is metadata binding only: catalog, schema and lifecycle identities,
versions, repository paths and digests. It does not implement Ptah runtime
behavior or replace JSON Schema validation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

GENERATOR_VERSION = "0.1.0"
GENERATED_PATHS = (
    "contracts/generated/catalog-index.json",
    "contracts/generated/manifest.json",
    "crates/ptah-contracts/src/generated.rs",
)


class BindingError(RuntimeError):
    """Raised when locked contracts cannot be bound deterministically."""


def sha256_bytes(data: bytes) -> str:
    """Return a lower-case SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    """Serialize a JSON value deterministically."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def render_json(value: Any) -> bytes:
    """Render stable human-readable JSON with one trailing newline."""
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def rust_string(value: str) -> str:
    """Render an ASCII/Unicode string as a Rust string literal."""
    return json.dumps(value, ensure_ascii=False)


def optional_text(value: Any) -> str | None:
    """Return a non-empty string or None."""
    return value if isinstance(value, str) and value else None


def version_from_id(identifier: str) -> str:
    """Return the final colon-delimited version token."""
    return identifier.rsplit(":", 1)[-1]


def version_from_path(repository_path: str) -> str:
    """Extract a `.vX.Y.Z` token from a repository path."""
    match = re.search(r"\.v(\d+\.\d+\.\d+)\.", repository_path)
    return match.group(1) if match else ""


def load_json(path: Path) -> dict[str, Any]:
    """Load one required JSON object."""
    if not path.is_file():
        raise BindingError(f"required file is missing: {path}")
    try:
        payload = json.loads(path.read_bytes())
    except json.JSONDecodeError as exc:
        raise BindingError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise BindingError(f"JSON root must be an object: {path}")
    return payload


def validate_lock(lock: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate the frozen catalog lock and return its catalog entries."""
    if lock.get("status") != "frozen_catalogs_locked_binding_generation_open":
        raise BindingError("catalog lock is not in the binding-generation-open state")
    if lock.get("network_resolution_allowed") is not False:
        raise BindingError("network schema resolution must remain disabled")
    catalogs = lock.get("catalogs")
    if not isinstance(catalogs, list) or lock.get("catalog_count") != 14 or len(catalogs) != 14:
        raise BindingError("frozen lock must contain exactly fourteen active catalogs")
    if lock.get("generated_bindings") is not None:
        raise BindingError("generator input lock must not pre-claim generated bindings")
    return [item for item in catalogs if isinstance(item, dict)]


def normalize_catalogs(
    roadmap_root: Path, lock: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Verify locked bytes and normalize catalog, schema and lifecycle records."""
    catalog_bindings: list[dict[str, Any]] = []
    schema_bindings: list[dict[str, Any]] = []
    machine_bindings: list[dict[str, Any]] = []

    for locked in validate_lock(lock):
        repository_path = locked.get("repository_path")
        expected_id = locked.get("catalog_id")
        expected_digest = locked.get("sha256")
        if not all(isinstance(item, str) and item for item in (repository_path, expected_id, expected_digest)):
            raise BindingError("catalog lock entry has missing path, ID or digest")

        catalog_path = roadmap_root / repository_path
        raw = catalog_path.read_bytes() if catalog_path.is_file() else b""
        if not raw:
            raise BindingError(f"locked catalog is missing or empty: {repository_path}")
        observed_digest = sha256_bytes(raw)
        if observed_digest != expected_digest:
            raise BindingError(
                f"catalog digest mismatch for {repository_path}: "
                f"expected {expected_digest}, observed {observed_digest}"
            )

        catalog = load_json(catalog_path)
        if catalog.get("catalog_id") != expected_id:
            raise BindingError(f"catalog ID mismatch for {repository_path}")

        schemas = catalog.get("schemas", [])
        machines = catalog.get("state_machines", [])
        if not isinstance(schemas, list) or not isinstance(machines, list):
            raise BindingError(f"catalog arrays are invalid: {repository_path}")
        if len(schemas) != locked.get("schema_count"):
            raise BindingError(f"schema count drift in {repository_path}")
        if len(machines) != locked.get("state_machine_count"):
            raise BindingError(f"state-machine count drift in {repository_path}")

        catalog_version = (
            optional_text(catalog.get("catalog_version"))
            or optional_text(catalog.get("version"))
            or version_from_id(expected_id)
        )
        catalog_bindings.append(
            {
                "catalog_id": expected_id,
                "catalog_version": catalog_version,
                "repository_path": repository_path,
                "sha256": expected_digest,
                "schema_count": len(schemas),
                "state_machine_count": len(machines),
            }
        )

        for item in schemas:
            if not isinstance(item, dict):
                raise BindingError(f"non-object schema entry in {repository_path}")
            schema_id = item.get("schema_id")
            schema_path = item.get("repository_path")
            if not isinstance(schema_id, str) or not schema_id:
                raise BindingError(f"schema entry without ID in {repository_path}")
            if not isinstance(schema_path, str) or not schema_path:
                raise BindingError(f"schema entry without repository path: {schema_id}")
            schema_bindings.append(
                {
                    "catalog_id": expected_id,
                    "schema_id": schema_id,
                    "schema_version": optional_text(item.get("schema_version"))
                    or version_from_id(schema_id),
                    "maturity": optional_text(item.get("maturity")),
                    "repository_path": schema_path,
                }
            )

        for item in machines:
            if not isinstance(item, dict):
                raise BindingError(f"non-object state-machine entry in {repository_path}")
            name = item.get("state_machine_name") or item.get("machine") or item.get("name")
            machine_path = item.get("repository_path")
            if not isinstance(name, str) or not name:
                raise BindingError(f"state-machine entry without name in {repository_path}")
            if not isinstance(machine_path, str) or not machine_path:
                raise BindingError(f"state-machine entry without repository path: {name}")
            version = (
                optional_text(item.get("state_machine_version"))
                or optional_text(item.get("version"))
                or version_from_path(machine_path)
            )
            if not version:
                raise BindingError(f"state-machine version cannot be derived: {name}")
            machine_bindings.append(
                {
                    "catalog_id": expected_id,
                    "state_machine_name": name,
                    "state_machine_version": version,
                    "repository_path": machine_path,
                }
            )

    catalog_bindings.sort(key=lambda item: item["catalog_id"])
    schema_bindings.sort(key=lambda item: item["schema_id"])
    machine_bindings.sort(
        key=lambda item: (item["state_machine_name"], item["state_machine_version"])
    )

    schema_keys = [item["schema_id"] for item in schema_bindings]
    machine_keys = [
        (item["state_machine_name"], item["state_machine_version"])
        for item in machine_bindings
    ]
    if len(schema_keys) != len(set(schema_keys)):
        raise BindingError("duplicate schema IDs across the locked catalog set")
    if len(machine_keys) != len(set(machine_keys)):
        raise BindingError("duplicate state-machine name/version across the locked catalog set")

    return catalog_bindings, schema_bindings, machine_bindings


def render_rust(
    lock: dict[str, Any],
    catalogs: list[dict[str, Any]],
    schemas: list[dict[str, Any]],
    machines: list[dict[str, Any]],
) -> bytes:
    """Render zero-dependency Rust metadata bindings."""
    authority = lock["authority"]
    lines = [
        "// @generated by tools/generate_contract_bindings.py; do not edit manually.",
        "// This binds frozen public contract metadata and implements no runtime capability.",
        "",
        "/// One frozen schema-catalog binding.",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]",
        "pub struct CatalogBinding {",
        "    pub catalog_id: &'static str,",
        "    pub catalog_version: &'static str,",
        "    pub repository_path: &'static str,",
        "    pub sha256: &'static str,",
        "    pub schema_count: usize,",
        "    pub state_machine_count: usize,",
        "}",
        "",
        "/// One frozen JSON Schema identity binding.",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]",
        "pub struct SchemaBinding {",
        "    pub catalog_id: &'static str,",
        "    pub schema_id: &'static str,",
        "    pub schema_version: &'static str,",
        "    pub maturity: Option<&'static str>,",
        "    pub repository_path: &'static str,",
        "}",
        "",
        "/// One frozen lifecycle-machine identity binding.",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]",
        "pub struct StateMachineBinding {",
        "    pub catalog_id: &'static str,",
        "    pub state_machine_name: &'static str,",
        "    pub state_machine_version: &'static str,",
        "    pub repository_path: &'static str,",
        "}",
        "",
        f"pub const PHASE_0B_FREEZE_COMMIT: &str = {rust_string(authority['phase_0b_freeze_merge'])};",
        f"pub const WP14_MERGE_COMMIT: &str = {rust_string(authority['wp14_merge'])};",
        f"pub const CATALOG_SET_SHA256: &str = {rust_string(lock['catalog_set_sha256'])};",
        f"pub const CATALOG_COUNT: usize = {len(catalogs)};",
        f"pub const SCHEMA_COUNT: usize = {len(schemas)};",
        f"pub const STATE_MACHINE_COUNT: usize = {len(machines)};",
        "",
        "pub static CATALOGS: &[CatalogBinding] = &[",
    ]
    for item in catalogs:
        lines.extend(
            [
                "    CatalogBinding {",
                f"        catalog_id: {rust_string(item['catalog_id'])},",
                f"        catalog_version: {rust_string(item['catalog_version'])},",
                f"        repository_path: {rust_string(item['repository_path'])},",
                f"        sha256: {rust_string(item['sha256'])},",
                f"        schema_count: {item['schema_count']},",
                f"        state_machine_count: {item['state_machine_count']},",
                "    },",
            ]
        )
    lines.extend(["]", "", "pub static SCHEMAS: &[SchemaBinding] = &["])
    for item in schemas:
        maturity = (
            f"Some({rust_string(item['maturity'])})" if item["maturity"] is not None else "None"
        )
        lines.extend(
            [
                "    SchemaBinding {",
                f"        catalog_id: {rust_string(item['catalog_id'])},",
                f"        schema_id: {rust_string(item['schema_id'])},",
                f"        schema_version: {rust_string(item['schema_version'])},",
                f"        maturity: {maturity},",
                f"        repository_path: {rust_string(item['repository_path'])},",
                "    },",
            ]
        )
    lines.extend(["]", "", "pub static STATE_MACHINES: &[StateMachineBinding] = &["])
    for item in machines:
        lines.extend(
            [
                "    StateMachineBinding {",
                f"        catalog_id: {rust_string(item['catalog_id'])},",
                f"        state_machine_name: {rust_string(item['state_machine_name'])},",
                f"        state_machine_version: {rust_string(item['state_machine_version'])},",
                f"        repository_path: {rust_string(item['repository_path'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "]", "",
            "/// Find one frozen catalog by canonical catalog URN.",
            "#[must_use]",
            "pub fn catalog_by_id(catalog_id: &str) -> Option<&'static CatalogBinding> {",
            "    CATALOGS.iter().find(|binding| binding.catalog_id == catalog_id)",
            "}", "",
            "/// Find one frozen schema by canonical schema URN.",
            "#[must_use]",
            "pub fn schema_by_id(schema_id: &str) -> Option<&'static SchemaBinding> {",
            "    SCHEMAS.iter().find(|binding| binding.schema_id == schema_id)",
            "}", "",
            "/// Find one frozen lifecycle machine by name and version.",
            "#[must_use]",
            "pub fn state_machine(",
            "    name: &str,",
            "    version: &str,",
            ") -> Option<&'static StateMachineBinding> {",
            "    STATE_MACHINES.iter().find(|binding| {",
            "        binding.state_machine_name == name && binding.state_machine_version == version",
            "    })",
            "}", "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def build_outputs(roadmap_root: Path, lock_path: Path, generator_path: Path) -> dict[str, bytes]:
    """Build every generated payload and its deterministic manifest."""
    lock_raw = lock_path.read_bytes()
    lock = load_json(lock_path)
    catalogs, schemas, machines = normalize_catalogs(roadmap_root, lock)

    index = {
        "schema_version": "0.1.0",
        "authority": lock["authority"],
        "catalog_set_sha256": lock["catalog_set_sha256"],
        "catalog_count": len(catalogs),
        "schema_count": len(schemas),
        "state_machine_count": len(machines),
        "catalogs": catalogs,
        "schemas": schemas,
        "state_machines": machines,
        "runtime_implementation_authorized": False,
    }
    index_bytes = render_json(index)
    rust_bytes = render_rust(lock, catalogs, schemas, machines)

    payloads = {
        "contracts/generated/catalog-index.json": index_bytes,
        "crates/ptah-contracts/src/generated.rs": rust_bytes,
    }
    file_records = [
        {"repository_path": path, "sha256": sha256_bytes(data), "size_bytes": len(data)}
        for path, data in sorted(payloads.items())
    ]
    manifest = {
        "schema_version": "0.1.0",
        "generator": {
            "name": "ptah-phase0c-contract-bindings",
            "version": GENERATOR_VERSION,
            "repository_path": "tools/generate_contract_bindings.py",
            "sha256": sha256_bytes(generator_path.read_bytes()),
        },
        "authority": lock["authority"],
        "catalog_set_sha256": lock["catalog_set_sha256"],
        "input_lock_sha256": sha256_bytes(lock_raw),
        "output_tree_sha256": sha256_bytes(canonical_bytes(file_records)),
        "files": file_records,
        "catalog_count": len(catalogs),
        "schema_count": len(schemas),
        "state_machine_count": len(machines),
        "runtime_implementation_authorized": False,
    }
    payloads["contracts/generated/manifest.json"] = render_json(manifest)
    return payloads


def write_tree(root: Path, payloads: dict[str, bytes]) -> None:
    """Write a generated candidate tree."""
    for relative, data in payloads.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def check_tree(root: Path, payloads: dict[str, bytes]) -> None:
    """Require every committed generated file to match exactly."""
    mismatches: list[str] = []
    for relative, expected in payloads.items():
        path = root / relative
        if not path.is_file():
            mismatches.append(f"missing:{relative}")
        elif path.read_bytes() != expected:
            mismatches.append(f"changed:{relative}")
    if mismatches:
        raise BindingError("generated binding tree mismatch: " + ", ".join(mismatches))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roadmap-root", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=Path("contracts/upstream-lock.json"))
    parser.add_argument(
        "--generator-path", type=Path, default=Path("tools/generate_contract_bindings.py")
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--check-root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payloads = build_outputs(args.roadmap_root, args.lock, args.generator_path)
    write_tree(args.output_root, payloads)
    if args.check_root is not None:
        check_tree(args.check_root, payloads)

    manifest = json.loads(payloads["contracts/generated/manifest.json"])
    print(
        json.dumps(
            {
                "catalog_count": manifest["catalog_count"],
                "schema_count": manifest["schema_count"],
                "state_machine_count": manifest["state_machine_count"],
                "output_tree_sha256": manifest["output_tree_sha256"],
                "output_root": str(args.output_root),
                "check_root": str(args.check_root) if args.check_root else None,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
