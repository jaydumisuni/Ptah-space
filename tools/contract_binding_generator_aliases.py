#!/usr/bin/env python3
"""Alias-aware wrapper for deterministic frozen contract bindings.

Frozen schema/lifecycle files own canonical identity. Older catalog identifiers
that differ from the file are retained as aliases and never promoted to
canonical Ptah identity.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import contract_binding_generator as base

VERSION = "0.2.1"
WRAPPER_PATH = Path(__file__)
BASE_PATH = WRAPPER_PATH.with_name("contract_binding_generator.py")
WRAPPER_REPOSITORY_PATH = "tools/contract_binding_generator_aliases.py"
BASE_REPOSITORY_PATH = "tools/contract_binding_generator.py"


def schema_entry(
    root: Path,
    catalog: dict[str, Any],
    catalog_id: str,
    entry: Any,
) -> dict[str, Any]:
    """Bind a schema file canonically while retaining any catalog alias."""
    if isinstance(entry, str):
        template = base.text(catalog.get("schema_path_template"))
        if template is None:
            raise base.BindingError(f"path-only schema entry without template in {catalog_id}")
        repository_path = base.safe_path(template.format(name=entry))
        declared_id = None
        declared_version = None
        declared_maturity = None
    elif isinstance(entry, dict):
        repository_path = base.text(entry.get("repository_path")) or base.text(entry.get("path"))
        if repository_path is None:
            raise base.BindingError(f"schema entry without path in {catalog_id}")
        repository_path = base.safe_path(repository_path)
        declared_id = base.text(entry.get("schema_id"))
        declared_version = base.text(entry.get("schema_version")) or base.text(
            entry.get("version")
        )
        declared_maturity = base.text(entry.get("maturity"))
    else:
        raise base.BindingError(f"unsupported schema entry in {catalog_id}: {entry!r}")

    document, raw = base.load_object(root / repository_path)
    observed_id = base.text(document.get("$id")) or base.text(document.get("schema_id"))
    canonical_id = observed_id or declared_id
    if canonical_id is None:
        raise base.BindingError(f"schema has no canonical ID: {repository_path}")

    catalog_alias = declared_id if declared_id and declared_id != canonical_id else None
    return {
        "catalog_id": catalog_id,
        "schema_id": canonical_id,
        "catalog_alias": catalog_alias,
        "schema_version": base.text(document.get("schema_version"))
        or declared_version
        or base.id_version(canonical_id),
        "maturity": base.text(document.get("maturity")) or declared_maturity,
        "repository_path": repository_path,
        "sha256": base.digest(raw),
        "size_bytes": len(raw),
    }


def machine_entry(root: Path, catalog_id: str, entry: Any) -> dict[str, Any]:
    """Bind a lifecycle file canonically while retaining catalog aliases."""
    if isinstance(entry, str):
        repository_path = base.safe_path(entry)
        declared_name = None
        declared_version = None
    elif isinstance(entry, dict):
        repository_path = base.text(entry.get("repository_path")) or base.text(entry.get("path"))
        if repository_path is None:
            raise base.BindingError(f"state-machine entry without path in {catalog_id}")
        repository_path = base.safe_path(repository_path)
        declared_name = (
            base.text(entry.get("state_machine_name"))
            or base.text(entry.get("machine"))
            or base.text(entry.get("name"))
        )
        declared_version = base.text(entry.get("state_machine_version")) or base.text(
            entry.get("version")
        )
    else:
        raise base.BindingError(f"unsupported state-machine entry in {catalog_id}: {entry!r}")

    document, raw = base.load_object(root / repository_path)
    observed_name = (
        base.text(document.get("state_machine_name"))
        or base.text(document.get("machine"))
        or base.text(document.get("name"))
    )
    canonical_name = observed_name or declared_name
    if canonical_name is None:
        raise base.BindingError(f"state machine has no canonical name: {repository_path}")

    observed_version = (
        base.text(document.get("state_machine_version"))
        or base.text(document.get("version"))
        or base.path_version(repository_path)
    )
    canonical_version = observed_version or declared_version
    if not canonical_version:
        raise base.BindingError(f"state-machine version cannot be derived: {repository_path}")

    return {
        "catalog_id": catalog_id,
        "state_machine_name": canonical_name,
        "catalog_alias_name": declared_name
        if declared_name and declared_name != canonical_name
        else None,
        "state_machine_version": canonical_version,
        "catalog_alias_version": declared_version
        if declared_version and declared_version != canonical_version
        else None,
        "repository_path": repository_path,
        "sha256": base.digest(raw),
        "size_bytes": len(raw),
    }


def build_outputs(
    roadmap_root: Path,
    lock_path: Path,
) -> dict[str, bytes]:
    """Run the base generator with alias-aware identity normalization."""
    base.schema_entry = schema_entry
    base.machine_entry = machine_entry
    outputs = base.build(roadmap_root, lock_path, WRAPPER_PATH)

    rust_path = "crates/ptah-contracts/src/generated.rs"
    outputs[rust_path] = outputs[rust_path].replace(
        b"tools/contract_binding_generator.py",
        WRAPPER_REPOSITORY_PATH.encode("utf-8"),
    )

    file_records = [
        {
            "repository_path": path,
            "sha256": base.digest(data),
            "size_bytes": len(data),
        }
        for path, data in sorted(outputs.items())
        if path != "contracts/generated/manifest.json"
    ]
    manifest = json.loads(outputs["contracts/generated/manifest.json"])
    manifest["generator"] = {
        "name": "ptah-phase0c-contract-bindings-alias-aware",
        "version": VERSION,
        "repository_path": WRAPPER_REPOSITORY_PATH,
        "sha256": base.digest(WRAPPER_PATH.read_bytes()),
        "sources": [
            {
                "repository_path": WRAPPER_REPOSITORY_PATH,
                "sha256": base.digest(WRAPPER_PATH.read_bytes()),
            },
            {
                "repository_path": BASE_REPOSITORY_PATH,
                "sha256": base.digest(BASE_PATH.read_bytes()),
            },
        ],
    }
    manifest["files"] = file_records
    manifest["output_tree_sha256"] = base.digest(base.canonical(file_records))
    outputs["contracts/generated/manifest.json"] = base.pretty(manifest)
    return outputs


def main() -> int:
    """Generate the candidate tree and optionally compare committed outputs."""
    args = base.arguments()
    outputs = build_outputs(args.roadmap_root, args.lock)
    base.write_tree(args.output_root, outputs)
    if args.check_root is not None:
        base.check_tree(args.check_root, outputs)

    manifest = json.loads(outputs["contracts/generated/manifest.json"])
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
