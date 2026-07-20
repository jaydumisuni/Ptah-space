#!/usr/bin/env python3
"""Final deterministic Phase 0C contract-binding generator.

This stage applies the exact Rust 1.97.1 formatting required by the committed
workspace after canonical identity and alias normalization. It uses fixed byte
rewrites rather than network access or mutable external inputs.
"""
from __future__ import annotations

import json
from pathlib import Path

import contract_binding_generator as base
import contract_binding_generator_aliases as aliases

VERSION = "0.3.0"
FINAL_PATH = Path(__file__)
ALIASES_PATH = FINAL_PATH.with_name("contract_binding_generator_aliases.py")
BASE_PATH = FINAL_PATH.with_name("contract_binding_generator.py")
FINAL_REPOSITORY_PATH = "tools/contract_binding_generator_final.py"
ALIASES_REPOSITORY_PATH = "tools/contract_binding_generator_aliases.py"
BASE_REPOSITORY_PATH = "tools/contract_binding_generator.py"


def format_generated_rust(source: bytes) -> bytes:
    """Apply the exact stable rustfmt rewrites required by Rust 1.97.1."""
    replacements = (
        (
            b'pub const CATALOG_SET_SHA256: &str = "f0668a5f5d5c68cabf623176608c627a94482faa4f4460e4f0fe0f0969d7c64d";',
            b'pub const CATALOG_SET_SHA256: &str =\n    "f0668a5f5d5c68cabf623176608c627a94482faa4f4460e4f0fe0f0969d7c64d";',
        ),
        (
            b"    CATALOGS.iter().find(|binding| binding.catalog_id == catalog_id)",
            b"    CATALOGS\n        .iter()\n        .find(|binding| binding.catalog_id == catalog_id)",
        ),
        (
            b"    SCHEMAS.iter().find(|binding| binding.schema_id == schema_id)",
            b"    SCHEMAS\n        .iter()\n        .find(|binding| binding.schema_id == schema_id)",
        ),
        (
            b"pub fn state_machine(\n    name: &str,\n    version: &str,\n) -> Option<&'static StateMachineBinding> {",
            b"pub fn state_machine(name: &str, version: &str) -> Option<&'static StateMachineBinding> {",
        ),
    )
    for before, after in replacements:
        if source.count(before) != 1:
            raise base.BindingError(
                f"expected one generated Rust formatting marker, found {source.count(before)}: {before!r}"
            )
        source = source.replace(before, after, 1)
    return source


def build_outputs(roadmap_root: Path, lock_path: Path) -> dict[str, bytes]:
    """Build alias-aware bindings and normalize the generated Rust format."""
    outputs = aliases.build_outputs(roadmap_root, lock_path)
    rust_path = "crates/ptah-contracts/src/generated.rs"
    outputs[rust_path] = format_generated_rust(outputs[rust_path])

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
        "name": "ptah-phase0c-contract-bindings-final",
        "version": VERSION,
        "repository_path": FINAL_REPOSITORY_PATH,
        "sha256": base.digest(FINAL_PATH.read_bytes()),
        "rustfmt_version": "1.8.0-stable (Rust 1.97.1 toolchain)",
        "sources": [
            {
                "repository_path": FINAL_REPOSITORY_PATH,
                "sha256": base.digest(FINAL_PATH.read_bytes()),
            },
            {
                "repository_path": ALIASES_REPOSITORY_PATH,
                "sha256": base.digest(ALIASES_PATH.read_bytes()),
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
    """Generate the final candidate tree and optionally verify committed files."""
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
