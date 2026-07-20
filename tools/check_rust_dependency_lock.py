#!/usr/bin/env python3
"""Verify the Phase 0C exact Rust dependency selection and Cargo lock."""
from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


class DependencyLockError(RuntimeError):
    """Raised when dependency evidence is incomplete or inconsistent."""


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DependencyLockError(f"JSON root must be an object: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify() -> dict[str, Any]:
    selection_path = ROOT / "dependencies/rust-direct-lock.json"
    cargo_lock_path = ROOT / "Cargo.lock"
    workspace_path = ROOT / "Cargo.toml"
    evidence_path = ROOT / "evidence/rust-dependency-lock/Cargo.toml"

    selection = load_json(selection_path)
    if selection.get("runtime_implementation_authorized") is not False:
        raise DependencyLockError("dependency selection cannot authorize runtime implementation")
    if selection.get("registry") != "https://github.com/rust-lang/crates.io-index":
        raise DependencyLockError("only the canonical crates.io index is allowed")

    direct_entries = selection.get("direct_dependencies")
    if not isinstance(direct_entries, list) or not direct_entries:
        raise DependencyLockError("direct dependency selection is empty")
    selected: dict[str, dict[str, Any]] = {}
    for entry in direct_entries:
        if not isinstance(entry, dict):
            raise DependencyLockError("direct dependency entry is not an object")
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise DependencyLockError("direct dependency lacks name or version")
        if name in selected:
            raise DependencyLockError(f"duplicate direct dependency: {name}")
        selected[name] = entry

    workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8"))
    workspace_dependencies = workspace.get("workspace", {}).get("dependencies", {})
    if not isinstance(workspace_dependencies, dict):
        raise DependencyLockError("workspace dependencies are missing")

    evidence = tomllib.loads(evidence_path.read_text(encoding="utf-8"))
    evidence_dependencies = evidence.get("dependencies", {})
    if not isinstance(evidence_dependencies, dict):
        raise DependencyLockError("dependency evidence package has no dependencies")

    for name, entry in selected.items():
        workspace_entry = workspace_dependencies.get(name)
        if not isinstance(workspace_entry, dict):
            raise DependencyLockError(f"workspace dependency missing: {name}")
        expected_requirement = f"={entry['version']}"
        if workspace_entry.get("version") != expected_requirement:
            raise DependencyLockError(
                f"workspace dependency {name} is not exact: {workspace_entry.get('version')!r}"
            )
        evidence_entry = evidence_dependencies.get(name)
        if not isinstance(evidence_entry, dict) or evidence_entry.get("workspace") is not True:
            raise DependencyLockError(f"evidence package does not resolve workspace dependency: {name}")

    extra_evidence = sorted(set(evidence_dependencies) - set(selected))
    missing_evidence = sorted(set(selected) - set(evidence_dependencies))
    if extra_evidence or missing_evidence:
        raise DependencyLockError(
            f"dependency evidence mismatch: extra={extra_evidence}, missing={missing_evidence}"
        )

    lock = tomllib.loads(cargo_lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise DependencyLockError("Cargo.lock package array is missing")

    registry_prefix = "registry+https://github.com/rust-lang/crates.io-index"
    resolved: dict[tuple[str, str], dict[str, Any]] = {}
    git_packages: list[str] = []
    registry_packages = 0
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            resolved[(name, version)] = package
        source = package.get("source")
        if isinstance(source, str):
            if source.startswith("git+"):
                git_packages.append(f"{name}@{version}")
            elif source == registry_prefix:
                registry_packages += 1
                checksum = package.get("checksum")
                if not isinstance(checksum, str) or len(checksum) != 64:
                    raise DependencyLockError(f"registry package lacks checksum: {name}@{version}")
            else:
                raise DependencyLockError(f"unapproved Cargo source: {source}")
    if git_packages:
        raise DependencyLockError(f"git dependencies are forbidden: {git_packages}")

    direct_resolved = []
    for name, entry in sorted(selected.items()):
        key = (name, str(entry["version"]))
        package = resolved.get(key)
        if package is None:
            raise DependencyLockError(f"selected dependency not present in Cargo.lock: {name}@{key[1]}")
        direct_resolved.append(
            {
                "name": name,
                "version": key[1],
                "source": package.get("source"),
                "checksum": package.get("checksum"),
                "features": entry.get("features", []),
                "purpose": entry.get("purpose"),
                "expected_licence": entry.get("expected_licence"),
            }
        )

    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.rust_dependency_lock_verification",
        "selection_status": selection.get("status"),
        "toolchain": selection.get("toolchain"),
        "cargo_lock_sha256": sha256(cargo_lock_path),
        "selection_sha256": sha256(selection_path),
        "workspace_manifest_sha256": sha256(workspace_path),
        "evidence_manifest_sha256": sha256(evidence_path),
        "resolved_package_count": len(packages),
        "registry_package_count": registry_packages,
        "direct_dependency_count": len(direct_resolved),
        "direct_dependencies": direct_resolved,
        "git_dependency_count": 0,
        "runtime_implementation_authorized": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = verify()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
