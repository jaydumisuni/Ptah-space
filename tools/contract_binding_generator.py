#!/usr/bin/env python3
"""Generate deterministic zero-dependency Rust metadata bindings.

The frozen JSON Schema and lifecycle files remain authoritative. Generated Rust
binds their identities, paths and SHA-256 digests; it implements no runtime
behavior and performs no network resolution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

VERSION = "0.2.0"


class BindingError(RuntimeError):
    """Raised when the frozen input cannot be bound safely."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def pretty(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def load_object(path: Path) -> tuple[dict[str, Any], bytes]:
    if not path.is_file():
        raise BindingError(f"required file missing: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BindingError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BindingError(f"JSON root must be an object: {path}")
    return value, raw


def text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def safe_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise BindingError(f"unsafe repository path: {value!r}")
    return path.as_posix()


def id_version(identifier: str) -> str:
    return identifier.rsplit(":", 1)[-1]


def path_version(path: str) -> str:
    match = re.search(r"\.v(\d+\.\d+\.\d+)\.", path)
    return match.group(1) if match else ""


def rust(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def validate_lock(lock: dict[str, Any]) -> list[dict[str, Any]]:
    if lock.get("status") != "frozen_catalogs_locked_binding_generation_open":
        raise BindingError("lock is not in the binding-generation-open state")
    if lock.get("network_resolution_allowed") is not False:
        raise BindingError("network schema resolution must remain disabled")
    catalogs = lock.get("catalogs")
    if not isinstance(catalogs, list) or len(catalogs) != 14 or lock.get("catalog_count") != 14:
        raise BindingError("lock must contain exactly fourteen active catalogs")
    if lock.get("generated_bindings") is not None:
        raise BindingError("input lock must not pre-claim generated bindings")
    return [item for item in catalogs if isinstance(item, dict)]


def schema_entry(
    root: Path,
    catalog: dict[str, Any],
    catalog_id: str,
    entry: Any,
) -> dict[str, Any]:
    if isinstance(entry, str):
        template = text(catalog.get("schema_path_template"))
        if template is None:
            raise BindingError(f"path-only schema entry without template in {catalog_id}")
        repository_path = safe_path(template.format(name=entry))
        explicit_id = None
        explicit_version = None
        explicit_maturity = None
    elif isinstance(entry, dict):
        repository_path = text(entry.get("repository_path")) or text(entry.get("path"))
        if repository_path is None:
            raise BindingError(f"schema entry without path in {catalog_id}")
        repository_path = safe_path(repository_path)
        explicit_id = text(entry.get("schema_id"))
        explicit_version = text(entry.get("schema_version")) or text(entry.get("version"))
        explicit_maturity = text(entry.get("maturity"))
    else:
        raise BindingError(f"unsupported schema entry in {catalog_id}: {entry!r}")

    document, raw = load_object(root / repository_path)
    observed_id = text(document.get("$id")) or text(document.get("schema_id"))
    schema_id = explicit_id or observed_id
    if schema_id is None:
        raise BindingError(f"schema has no canonical ID: {repository_path}")
    if explicit_id is not None and observed_id is not None and explicit_id != observed_id:
        raise BindingError(f"catalog/schema ID mismatch: {repository_path}")

    return {
        "catalog_id": catalog_id,
        "schema_id": schema_id,
        "schema_version": explicit_version
        or text(document.get("schema_version"))
        or id_version(schema_id),
        "maturity": explicit_maturity or text(document.get("maturity")),
        "repository_path": repository_path,
        "sha256": digest(raw),
        "size_bytes": len(raw),
    }


def machine_entry(root: Path, catalog_id: str, entry: Any) -> dict[str, Any]:
    if isinstance(entry, str):
        repository_path = safe_path(entry)
        explicit_name = None
        explicit_version = None
    elif isinstance(entry, dict):
        repository_path = text(entry.get("repository_path")) or text(entry.get("path"))
        if repository_path is None:
            raise BindingError(f"state-machine entry without path in {catalog_id}")
        repository_path = safe_path(repository_path)
        explicit_name = (
            text(entry.get("state_machine_name"))
            or text(entry.get("machine"))
            or text(entry.get("name"))
        )
        explicit_version = text(entry.get("state_machine_version")) or text(entry.get("version"))
    else:
        raise BindingError(f"unsupported state-machine entry in {catalog_id}: {entry!r}")

    document, raw = load_object(root / repository_path)
    observed_name = (
        text(document.get("state_machine_name"))
        or text(document.get("machine"))
        or text(document.get("name"))
    )
    name = explicit_name or observed_name
    if name is None:
        raise BindingError(f"state machine has no name: {repository_path}")
    if explicit_name is not None and observed_name is not None and explicit_name != observed_name:
        raise BindingError(f"catalog/state-machine name mismatch: {repository_path}")
    version = (
        explicit_version
        or text(document.get("state_machine_version"))
        or text(document.get("version"))
        or path_version(repository_path)
    )
    if not version:
        raise BindingError(f"state-machine version cannot be derived: {repository_path}")

    return {
        "catalog_id": catalog_id,
        "state_machine_name": name,
        "state_machine_version": version,
        "repository_path": repository_path,
        "sha256": digest(raw),
        "size_bytes": len(raw),
    }


def normalize(
    roadmap_root: Path, lock: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    catalogs: list[dict[str, Any]] = []
    schemas: list[dict[str, Any]] = []
    machines: list[dict[str, Any]] = []

    for locked in validate_lock(lock):
        repository_path = text(locked.get("repository_path"))
        catalog_id = text(locked.get("catalog_id"))
        expected_hash = text(locked.get("sha256"))
        if repository_path is None or catalog_id is None or expected_hash is None:
            raise BindingError("lock entry lacks catalog path, ID or digest")
        repository_path = safe_path(repository_path)
        catalog, raw = load_object(roadmap_root / repository_path)
        if digest(raw) != expected_hash:
            raise BindingError(f"catalog digest mismatch: {repository_path}")
        if catalog.get("catalog_id") != catalog_id:
            raise BindingError(f"catalog ID mismatch: {repository_path}")

        schema_items = catalog.get("schemas", [])
        machine_items = catalog.get("state_machines", [])
        if not isinstance(schema_items, list) or not isinstance(machine_items, list):
            raise BindingError(f"catalog arrays invalid: {repository_path}")
        if len(schema_items) != locked.get("schema_count"):
            raise BindingError(f"schema count drift: {repository_path}")
        if len(machine_items) != locked.get("state_machine_count"):
            raise BindingError(f"state-machine count drift: {repository_path}")

        version = (
            text(catalog.get("catalog_version"))
            or text(catalog.get("version"))
            or id_version(catalog_id)
        )
        catalogs.append(
            {
                "catalog_id": catalog_id,
                "catalog_version": version,
                "repository_path": repository_path,
                "sha256": expected_hash,
                "schema_count": len(schema_items),
                "state_machine_count": len(machine_items),
            }
        )
        schemas.extend(schema_entry(roadmap_root, catalog, catalog_id, item) for item in schema_items)
        machines.extend(machine_entry(roadmap_root, catalog_id, item) for item in machine_items)

    catalogs.sort(key=lambda item: item["catalog_id"])
    schemas.sort(key=lambda item: item["schema_id"])
    machines.sort(key=lambda item: (item["state_machine_name"], item["state_machine_version"]))

    schema_keys = [item["schema_id"] for item in schemas]
    machine_keys = [(item["state_machine_name"], item["state_machine_version"]) for item in machines]
    if len(schema_keys) != len(set(schema_keys)):
        raise BindingError("duplicate schema IDs in frozen set")
    if len(machine_keys) != len(set(machine_keys)):
        raise BindingError("duplicate lifecycle identities in frozen set")
    if (len(catalogs), len(schemas), len(machines)) != (14, 346, 99):
        raise BindingError(
            f"unexpected frozen binding counts: {len(catalogs)}, {len(schemas)}, {len(machines)}"
        )
    return catalogs, schemas, machines


def rust_source(
    lock: dict[str, Any],
    catalogs: list[dict[str, Any]],
    schemas: list[dict[str, Any]],
    machines: list[dict[str, Any]],
) -> bytes:
    lines = [
        "//! Generated frozen-contract metadata bindings.",
        "//!",
        "//! JSON Schema and lifecycle files remain authoritative. This module",
        "//! implements no runtime capability and performs no validation by itself.",
        "",
        "// @generated by tools/contract_binding_generator.py; do not edit.",
        "",
        "/// One frozen schema-catalog binding.",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]",
        "pub struct CatalogBinding {",
        "    /// Canonical catalog URN.",
        "    pub catalog_id: &'static str,",
        "    /// Catalog version.",
        "    pub catalog_version: &'static str,",
        "    /// Frozen roadmap-relative path.",
        "    pub repository_path: &'static str,",
        "    /// SHA-256 of the original catalog bytes.",
        "    pub sha256: &'static str,",
        "    /// Number of schema entries.",
        "    pub schema_count: usize,",
        "    /// Number of lifecycle entries.",
        "    pub state_machine_count: usize,",
        "}",
        "",
        "/// One frozen JSON Schema binding.",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]",
        "pub struct SchemaBinding {",
        "    /// Owning catalog URN.",
        "    pub catalog_id: &'static str,",
        "    /// Canonical schema URN.",
        "    pub schema_id: &'static str,",
        "    /// Schema version.",
        "    pub schema_version: &'static str,",
        "    /// Optional maturity declared by the frozen source.",
        "    pub maturity: Option<&'static str>,",
        "    /// Frozen roadmap-relative path.",
        "    pub repository_path: &'static str,",
        "    /// SHA-256 of the original schema bytes.",
        "    pub sha256: &'static str,",
        "    /// Original file size.",
        "    pub size_bytes: usize,",
        "}",
        "",
        "/// One frozen lifecycle-machine binding.",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]",
        "pub struct StateMachineBinding {",
        "    /// Owning catalog URN.",
        "    pub catalog_id: &'static str,",
        "    /// Namespaced lifecycle-machine name.",
        "    pub state_machine_name: &'static str,",
        "    /// Lifecycle-machine version.",
        "    pub state_machine_version: &'static str,",
        "    /// Frozen roadmap-relative path.",
        "    pub repository_path: &'static str,",
        "    /// SHA-256 of the original lifecycle bytes.",
        "    pub sha256: &'static str,",
        "    /// Original file size.",
        "    pub size_bytes: usize,",
        "}",
        "",
        "/// Phase 0B frozen governance checkpoint.",
        f"pub const PHASE_0B_FREEZE_COMMIT: &str = {rust(lock['authority']['phase_0b_freeze_merge'])};",
        "/// WP14 merge containing the frozen proof burden.",
        f"pub const WP14_MERGE_COMMIT: &str = {rust(lock['authority']['wp14_merge'])};",
        "/// Aggregate digest of the fourteen locked catalog entries.",
        f"pub const CATALOG_SET_SHA256: &str = {rust(lock['catalog_set_sha256'])};",
        "/// Number of active frozen catalogs.",
        "pub const CATALOG_COUNT: usize = 14;",
        "/// Number of frozen schema bindings.",
        "pub const SCHEMA_COUNT: usize = 346;",
        "/// Number of frozen lifecycle-machine bindings.",
        "pub const STATE_MACHINE_COUNT: usize = 99;",
        "",
        "/// Every active frozen catalog binding.",
        "pub static CATALOGS: &[CatalogBinding] = &[",
    ]
    for item in catalogs:
        lines += [
            "    CatalogBinding {",
            f"        catalog_id: {rust(item['catalog_id'])},",
            f"        catalog_version: {rust(item['catalog_version'])},",
            f"        repository_path: {rust(item['repository_path'])},",
            f"        sha256: {rust(item['sha256'])},",
            f"        schema_count: {item['schema_count']},",
            f"        state_machine_count: {item['state_machine_count']},",
            "    },",
        ]
    lines += ["]", "", "/// Every frozen schema binding.", "pub static SCHEMAS: &[SchemaBinding] = &["]
    for item in schemas:
        maturity = f"Some({rust(item['maturity'])})" if item["maturity"] else "None"
        lines += [
            "    SchemaBinding {",
            f"        catalog_id: {rust(item['catalog_id'])},",
            f"        schema_id: {rust(item['schema_id'])},",
            f"        schema_version: {rust(item['schema_version'])},",
            f"        maturity: {maturity},",
            f"        repository_path: {rust(item['repository_path'])},",
            f"        sha256: {rust(item['sha256'])},",
            f"        size_bytes: {item['size_bytes']},",
            "    },",
        ]
    lines += [
        "]",
        "",
        "/// Every frozen lifecycle-machine binding.",
        "pub static STATE_MACHINES: &[StateMachineBinding] = &[",
    ]
    for item in machines:
        lines += [
            "    StateMachineBinding {",
            f"        catalog_id: {rust(item['catalog_id'])},",
            f"        state_machine_name: {rust(item['state_machine_name'])},",
            f"        state_machine_version: {rust(item['state_machine_version'])},",
            f"        repository_path: {rust(item['repository_path'])},",
            f"        sha256: {rust(item['sha256'])},",
            f"        size_bytes: {item['size_bytes']},",
            "    },",
        ]
    lines += [
        "]",
        "",
        "/// Find a frozen catalog by canonical URN.",
        "#[must_use]",
        "pub fn catalog_by_id(catalog_id: &str) -> Option<&'static CatalogBinding> {",
        "    CATALOGS.iter().find(|binding| binding.catalog_id == catalog_id)",
        "}",
        "",
        "/// Find a frozen schema by canonical URN.",
        "#[must_use]",
        "pub fn schema_by_id(schema_id: &str) -> Option<&'static SchemaBinding> {",
        "    SCHEMAS.iter().find(|binding| binding.schema_id == schema_id)",
        "}",
        "",
        "/// Find a frozen lifecycle machine by name and version.",
        "#[must_use]",
        "pub fn state_machine(",
        "    name: &str,",
        "    version: &str,",
        ") -> Option<&'static StateMachineBinding> {",
        "    STATE_MACHINES.iter().find(|binding| {",
        "        binding.state_machine_name == name && binding.state_machine_version == version",
        "    })",
        "}",
        "",
    ]
    return "\n".join(lines).encode()


def build(root: Path, lock_path: Path, generator: Path) -> dict[str, bytes]:
    lock, _ = load_object(lock_path)
    catalogs, schemas, machines = normalize(root, lock)
    index = {
        "schema_version": "0.1.0",
        "authority": lock["authority"],
        "catalog_set_sha256": lock["catalog_set_sha256"],
        "catalog_count": 14,
        "schema_count": 346,
        "state_machine_count": 99,
        "catalogs": catalogs,
        "schemas": schemas,
        "state_machines": machines,
        "runtime_implementation_authorized": False,
    }
    outputs = {
        "contracts/generated/catalog-index.json": pretty(index),
        "crates/ptah-contracts/src/generated.rs": rust_source(lock, catalogs, schemas, machines),
    }
    files = [
        {"repository_path": path, "sha256": digest(data), "size_bytes": len(data)}
        for path, data in sorted(outputs.items())
    ]
    manifest = {
        "schema_version": "0.1.0",
        "generator": {
            "name": "ptah-phase0c-contract-bindings",
            "version": VERSION,
            "repository_path": "tools/contract_binding_generator.py",
            "sha256": digest(generator.read_bytes()),
        },
        "authority": lock["authority"],
        "catalog_set_sha256": lock["catalog_set_sha256"],
        "output_tree_sha256": digest(canonical(files)),
        "files": files,
        "catalog_count": 14,
        "schema_count": 346,
        "state_machine_count": 99,
        "runtime_implementation_authorized": False,
    }
    outputs["contracts/generated/manifest.json"] = pretty(manifest)
    return outputs


def write_tree(root: Path, outputs: dict[str, bytes]) -> None:
    for relative, data in outputs.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def check_tree(root: Path, outputs: dict[str, bytes]) -> None:
    mismatches = []
    for relative, expected in outputs.items():
        path = root / relative
        if not path.is_file():
            mismatches.append(f"missing:{relative}")
        elif path.read_bytes() != expected:
            mismatches.append(f"changed:{relative}")
    if mismatches:
        raise BindingError("generated binding mismatch: " + ", ".join(mismatches))


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roadmap-root", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=Path("contracts/upstream-lock.json"))
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--check-root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    outputs = build(args.roadmap_root, args.lock, Path(__file__))
    write_tree(args.output_root, outputs)
    if args.check_root is not None:
        check_tree(args.check_root, outputs)
    manifest = json.loads(outputs["contracts/generated/manifest.json"])
    print(
        json.dumps(
            {
                "catalog_count": 14,
                "schema_count": 346,
                "state_machine_count": 99,
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
