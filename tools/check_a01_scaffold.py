#!/usr/bin/env python3
"""Validate the public A01 repository/contracts/reproducible-scaffold boundary."""
from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "a01/scaffold-contract.json"
ACTION_PIN = re.compile(r"^[0-9a-f]{40}$")


class ValidationError(RuntimeError):
    """Raised when an A01 scaffold invariant is not satisfied."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def load_json(path: Path) -> dict[str, Any]:
    require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"JSON root must be an object: {path.relative_to(ROOT)}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_workspace(contract: dict[str, Any]) -> dict[str, Any]:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    config = workspace.get("workspace", {})
    package = config.get("package", {})
    members = config.get("members", [])
    expected = contract["required_workspace_members"]
    require(members == expected, "Rust workspace member order/content drifted from A01 contract")
    require(package.get("rust-version") == contract["required_rust_toolchain"], "Rust toolchain pin mismatch")
    require(package.get("publish") is False, "workspace packages must remain non-publishable by default")
    for member in expected:
        require((ROOT / member / "Cargo.toml").is_file(), f"workspace member manifest missing: {member}")
    return {"member_count": len(members), "rust_toolchain": package.get("rust-version")}


def validate_browser(contract: dict[str, Any]) -> dict[str, Any]:
    package = load_json(ROOT / "browser-provider/package.json")
    lock = load_json(ROOT / "browser-provider/package-lock.json")
    require(package.get("private") is True, "Browser Provider package must remain private")
    require(package.get("engines", {}).get("node") == contract["required_node_toolchain"], "Node toolchain pin mismatch")
    require(package.get("dependencies", {}).get("playwright") == contract["required_playwright_version"], "Playwright pin mismatch")
    require(lock.get("lockfileVersion") == 3, "Browser Provider npm lockfile version mismatch")
    require(lock.get("packages", {}).get("", {}).get("dependencies", {}).get("playwright") == contract["required_playwright_version"], "npm lock does not preserve Playwright pin")
    return {"node": contract["required_node_toolchain"], "playwright": contract["required_playwright_version"]}


def validate_contract_lock(contract: dict[str, Any]) -> dict[str, Any]:
    lock = load_json(ROOT / "contracts/upstream-lock.json")
    frozen = contract["frozen_contracts"]
    require(lock.get("network_resolution_allowed") is False, "network schema resolution must remain disabled")
    require(lock.get("catalog_count") == frozen["catalog_count"], "frozen catalog count mismatch")
    authority = lock.get("authority", {})
    require(authority.get("phase_0b_freeze_merge") == frozen["phase_0b_freeze_commit"], "Phase 0B freeze binding mismatch")
    require(authority.get("wp14_merge") == frozen["wp14_freeze_commit"], "WP14 freeze binding mismatch")
    generated = lock.get("generated_bindings")
    require(isinstance(generated, dict), "generated binding lock missing")
    require(generated.get("catalog_count") == frozen["catalog_count"], "generated catalog count mismatch")
    require(generated.get("schema_count") == frozen["schema_count"], "generated schema count mismatch")
    require(generated.get("state_machine_count") == frozen["state_machine_count"], "generated lifecycle count mismatch")
    expected_files = {
        "manifest": ROOT / "contracts/generated/manifest.json",
        "catalog_index": ROOT / "contracts/generated/catalog-index.json",
        "rust_module": ROOT / "crates/ptah-contracts/src/generated.rs",
    }
    for key, path in expected_files.items():
        record = generated.get(key)
        require(isinstance(record, dict), f"generated binding record missing: {key}")
        require(path.is_file(), f"generated output missing: {path.relative_to(ROOT)}")
        require(record.get("sha256") == sha256(path), f"generated output digest mismatch: {key}")
        require(record.get("size_bytes") == path.stat().st_size, f"generated output size mismatch: {key}")
    manifest = load_json(expected_files["manifest"])
    require(manifest.get("catalog_count") == frozen["catalog_count"], "generated manifest catalog count mismatch")
    require(manifest.get("schema_count") == frozen["schema_count"], "generated manifest schema count mismatch")
    require(manifest.get("state_machine_count") == frozen["state_machine_count"], "generated manifest lifecycle count mismatch")
    require(manifest.get("output_tree_sha256") == generated.get("output_tree_sha256"), "generated output-tree digest mismatch")
    return {
        "catalog_count": generated.get("catalog_count"),
        "schema_count": generated.get("schema_count"),
        "state_machine_count": generated.get("state_machine_count"),
        "output_tree_sha256": generated.get("output_tree_sha256"),
    }


def validate_dependency_lock(contract: dict[str, Any]) -> dict[str, Any]:
    record = load_json(ROOT / "dependencies/rust-direct-lock.json")
    require(record.get("toolchain") == contract["required_rust_toolchain"], "Rust dependency evidence toolchain mismatch")
    policy = record.get("selection_policy", {})
    require(policy.get("exact_manifest_versions") is True, "exact Rust manifest versions are not enforced")
    require(policy.get("git_dependencies_allowed") is False, "Git Rust dependencies must remain forbidden")
    dependencies = record.get("direct_dependencies")
    require(isinstance(dependencies, list) and len(dependencies) == 10, "A01 expects ten locked direct Rust dependencies")
    names: set[str] = set()
    for item in dependencies:
        require(isinstance(item, dict), "invalid Rust dependency record")
        name = item.get("name")
        version = item.get("version")
        checksum = item.get("checksum")
        require(isinstance(name, str) and name not in names, "Rust dependency names must be unique")
        require(isinstance(version, str) and version, f"Rust dependency version missing: {name}")
        require(isinstance(checksum, str) and len(checksum) == 64, f"Rust dependency checksum missing: {name}")
        names.add(name)
    cargo = record.get("cargo_lock", {})
    require(cargo.get("repository_path") == "Cargo.lock", "Cargo.lock evidence path mismatch")
    require(cargo.get("sha256") == sha256(ROOT / "Cargo.lock"), "Cargo.lock digest mismatch")
    require(cargo.get("git_dependency_count") == 0, "Cargo.lock contains Git dependencies")
    return {"direct_dependency_count": len(dependencies), "cargo_lock_sha256": cargo.get("sha256")}


def validate_licence(contract: dict[str, Any]) -> dict[str, Any]:
    for relative in contract["required_operative_licence_files"]:
        require((ROOT / relative).is_file(), f"operative licence/source-boundary file missing: {relative}")
    boundary = load_json(ROOT / "legal/apache-2.0-boundary.json")
    require(boundary.get("apache_2_0_accepted") is True, "Apache-2.0 boundary is not accepted")
    require(boundary.get("operative_root_files_present") is True, "operative licence root files are not accepted")
    require(boundary.get("public_default_scope", {}).get("repository") == "jaydumisuni/Ptah-space", "public source scope repository mismatch")
    require(boundary.get("private_not_permitted_in_public_repository"), "private/public exclusion inventory missing")
    return {"spdx": boundary.get("spdx_license"), "private_exclusion_count": len(boundary["private_not_permitted_in_public_repository"])}


def validate_action_pins() -> dict[str, Any]:
    workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
    require(workflows, "no workflows found")
    references: list[dict[str, str]] = []
    for path in workflows:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line.startswith("uses:") and " uses:" not in raw:
                continue
            value = line.split("uses:", 1)[1].strip()
            value = value.split(" #", 1)[0].strip().strip('"\'')
            if value.startswith("./"):
                continue
            require("@" in value, f"workflow Action reference lacks ref: {path.name}: {value}")
            action, ref = value.rsplit("@", 1)
            require(ACTION_PIN.fullmatch(ref) is not None, f"workflow Action is not pinned to an immutable commit: {path.name}: {value}")
            references.append({"workflow": path.name, "action": action, "ref": ref})
    require(references, "no external workflow Action references found")
    return {"workflow_count": len(workflows), "immutable_action_reference_count": len(references)}


def validate_claim_boundary(contract: dict[str, Any]) -> None:
    boundary = contract.get("claim_boundary")
    require(isinstance(boundary, dict) and boundary, "A01 claim boundary missing")
    require(all(value is True for value in boundary.values()), "every A01 non-claim boundary must remain explicit")
    phase0c = (ROOT / "PHASE0C_SCAFFOLD.md").read_text(encoding="utf-8")
    require("candidate scaffold only" in phase0c, "historical Phase 0C non-claiming record was rewritten")
    require("does not implement or claim" in phase0c, "historical Phase 0C claim boundary was weakened")


def validate(root: Path = ROOT) -> dict[str, Any]:
    del root  # The validator is intentionally repository-root bound.
    contract = load_json(CONTRACT_PATH)
    require(contract.get("record_type") == "ptah.a01.scaffold_contract", "A01 contract record type mismatch")
    require(contract.get("scope") == "repository_contracts_and_reproducible_scaffold", "A01 contract scope mismatch")
    require(contract.get("runtime_semantics_implemented") is False, "A01 contract must not claim runtime semantics")
    validate_claim_boundary(contract)
    return {
        "record_type": "ptah.a01.scaffold_validation",
        "status": "a01_scaffold_static_invariants_passed",
        "workspace": validate_workspace(contract),
        "browser": validate_browser(contract),
        "contracts": validate_contract_lock(contract),
        "dependencies": validate_dependency_lock(contract),
        "licence": validate_licence(contract),
        "actions": validate_action_pins(),
        "runtime_semantics_implemented": False,
        "production_or_release_accepted": False,
    }


def main() -> None:
    print(json.dumps(validate(), indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except ValidationError as exc:
        raise SystemExit(f"A01_SCAFFOLD_VALIDATION_FAILED: {exc}")
