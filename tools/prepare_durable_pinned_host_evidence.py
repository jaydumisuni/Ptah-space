#!/usr/bin/env python3
"""Independently verify and retain a proof-eligible pinned-host bundle.

The tool consumes the exact output of ``run_pinned_host_proof.py``. It rechecks
all file hashes, aggregate digests and cross-record proof conditions before
writing an exact-byte durable candidate bundle and a separate pending review
record. It never accepts the host, package boundary, ADR or runtime.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_FILES = {
    "apt-sources.json",
    "bundle-manifest.json",
    "host-capabilities.json",
    "host-identity.json",
    "installed-packages.json",
    "package-artifacts.json",
}
BUNDLED_FILES = REQUIRED_FILES - {"bundle-manifest.json"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_HOST = {
    "id": "ubuntu",
    "version_id": "24.04",
    "point_release": "24.04.4",
    "architecture": "x86_64",
    "kernel_prefix": "6.8.0-136-generic",
}


class RetentionError(RuntimeError):
    """Raised when source evidence cannot be retained safely."""


def sha256_bytes(value: bytes) -> str:
    """Return a lower-case SHA-256 digest for exact bytes."""
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    """Return a lower-case SHA-256 digest for one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    """Hash one JSON value using stable canonical encoding."""
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return sha256_bytes(raw)


def load_json(path: Path) -> dict[str, Any]:
    """Load one JSON object or fail closed."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetentionError(f"unreadable JSON evidence {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise RetentionError(f"JSON evidence root is not an object: {path.name}")
    return value


def require(condition: bool, message: str) -> None:
    """Raise a retention failure when one proof invariant is false."""
    if not condition:
        raise RetentionError(message)


def require_false_boundary(record: dict[str, Any], name: str) -> None:
    """Require the explicit non-authorization boundary on one record."""
    require(
        record.get("runtime_implementation_authorized") is False,
        f"{name} does not retain runtime_implementation_authorized=false",
    )


def package_identity(record: dict[str, Any]) -> tuple[str, str, str]:
    """Return a strict package/version/architecture identity."""
    values: list[str] = []
    for field in ("package", "architecture", "version"):
        value = record.get(field)
        require(
            isinstance(value, str) and bool(value.strip()),
            f"package identity field {field!r} is invalid",
        )
        values.append(value.strip())
    return values[0], values[1], values[2]


def verify_source_file_set(bundle_dir: Path) -> None:
    """Require an exact, flat source bundle file set."""
    require(bundle_dir.is_dir(), f"bundle directory does not exist: {bundle_dir}")
    present = {path.name for path in bundle_dir.iterdir() if path.is_file()}
    directories = [path.name for path in bundle_dir.iterdir() if path.is_dir()]
    require(not directories, f"bundle directory contains subdirectories: {directories}")
    require(
        present == REQUIRED_FILES,
        f"bundle file set mismatch: expected {sorted(REQUIRED_FILES)}, got {sorted(present)}",
    )


def verify_repository_state(manifest: dict[str, Any]) -> None:
    """Require one clean unchanged repository commit around collection."""
    before = manifest.get("repository_state_before_collection")
    after = manifest.get("repository_state_after_collection")
    require(isinstance(before, dict), "repository pre-collection state is missing")
    require(isinstance(after, dict), "repository post-collection state is missing")
    for label, state in (("before", before), ("after", after)):
        require(state.get("dirty") is False, f"repository was dirty {label} collection")
        require(
            state.get("worktree_dirty") is False,
            f"tracked worktree was dirty {label} collection",
        )
        require(
            state.get("index_dirty") is False,
            f"Git index was dirty {label} collection",
        )
        require(
            state.get("unexpected_untracked") == [],
            f"unexpected untracked files existed {label} collection",
        )
    commit = manifest.get("implementation_commit")
    after_commit = manifest.get("repository_commit_after_collection")
    require(isinstance(commit, str) and COMMIT_RE.fullmatch(commit), "invalid implementation commit")
    require(after_commit == commit, "repository commit changed during collection")
    require(
        manifest.get("repository_commit_changed_during_collection") is False,
        "manifest records a commit change during collection",
    )
    require(manifest.get("repository_dirty") is False, "manifest records a dirty repository")


def verify_manifest_file_records(
    bundle_dir: Path, manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    """Recompute every source file hash, size and aggregate bundle digest."""
    records = manifest.get("files")
    require(isinstance(records, list), "bundle manifest files list is missing")
    require(len(records) == len(BUNDLED_FILES), "bundle manifest file count is invalid")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for item in records:
        require(isinstance(item, dict), "bundle file record is not an object")
        name = item.get("path")
        require(isinstance(name, str), "bundle file path is invalid")
        require(name in BUNDLED_FILES, f"unexpected bundled file record: {name!r}")
        require(name not in seen, f"duplicate bundled file record: {name}")
        seen.add(name)
        path = bundle_dir / name
        expected_size = path.stat().st_size
        expected_sha = sha256_file(path)
        require(item.get("size_bytes") == expected_size, f"size mismatch for {name}")
        require(item.get("sha256") == expected_sha, f"SHA-256 mismatch for {name}")
        normalized.append(
            {"path": name, "sha256": expected_sha, "size_bytes": expected_size}
        )
    require(seen == BUNDLED_FILES, "bundle manifest does not cover the exact source files")
    normalized.sort(key=lambda item: item["path"])
    require(
        manifest.get("bundle_sha256") == canonical_sha256(normalized),
        "bundle aggregate SHA-256 mismatch",
    )
    return normalized


def verify_host_identity(record: dict[str, Any]) -> None:
    """Verify exact frozen host identity and privacy-preserving fields."""
    require_false_boundary(record, "host identity")
    require(
        record.get("record_type") == "ptah.phase0c.pinned_host_identity",
        "host identity record type mismatch",
    )
    require(record.get("proof_eligible") is True, "host identity is not proof-eligible")
    require(record.get("identity_failures") == [], "host identity contains failures")
    require(record.get("expected") == EXPECTED_HOST, "frozen host expectation mismatch")
    os_release = record.get("os_release")
    require(isinstance(os_release, dict), "host os-release record is missing")
    require(os_release.get("ID") == "ubuntu", "host distribution identity mismatch")
    require(os_release.get("VERSION_ID") == "24.04", "host base release mismatch")
    pretty = " ".join(
        [str(os_release.get("VERSION", "")), str(os_release.get("PRETTY_NAME", ""))]
    )
    require("24.04.4" in pretty, "host point release mismatch")
    require(record.get("architecture") == "x86_64", "host architecture mismatch")
    kernel = record.get("kernel")
    require(
        isinstance(kernel, str) and kernel.startswith("6.8.0-136-generic"),
        "host kernel mismatch",
    )
    require(
        isinstance(record.get("hostname_sha256"), str)
        and bool(SHA256_RE.fullmatch(record["hostname_sha256"])),
        "host name is not retained as SHA-256",
    )
    boot = record.get("boot_identity")
    require(isinstance(boot, dict), "boot identity record is missing")
    for field in ("machine_id_sha256", "boot_id_sha256"):
        require(
            isinstance(boot.get(field), str) and bool(SHA256_RE.fullmatch(boot[field])),
            f"{field} is not retained as SHA-256",
        )


def verify_capabilities(record: dict[str, Any]) -> None:
    """Verify the accepted capability report's own proof boundary."""
    require_false_boundary(record, "host capability report")
    require(
        record.get("record_type") == "ptah.phase0c.host_capability_report",
        "host capability record type mismatch",
    )
    require(record.get("proof_eligible") is True, "capability report is not proof-eligible")
    require(
        record.get("required_capabilities_passed") is True,
        "required host capabilities did not pass",
    )
    require(record.get("required_failures") == [], "capability report contains required failures")
    match = record.get("pinned_host_match")
    require(isinstance(match, dict) and match.get("all_match") is True, "capability host identity did not match")
    host = record.get("host")
    require(isinstance(host, dict), "capability host record is missing")
    require("hostname" not in host, "raw hostname remains in capability evidence")
    require(
        isinstance(host.get("hostname_sha256"), str)
        and bool(SHA256_RE.fullmatch(host["hostname_sha256"])),
        "capability hostname is not retained as SHA-256",
    )


def verify_installed_packages(record: dict[str, Any]) -> set[tuple[str, str, str]]:
    """Verify exact installed package identities and aggregate digest."""
    require_false_boundary(record, "installed package manifest")
    require(
        record.get("record_type") == "ptah.phase0c.installed_package_manifest",
        "installed package record type mismatch",
    )
    packages = record.get("packages")
    require(isinstance(packages, list) and bool(packages), "installed package list is empty")
    require(record.get("package_count") == len(packages), "installed package count mismatch")
    require(
        record.get("packages_sha256") == canonical_sha256(packages),
        "installed package aggregate SHA-256 mismatch",
    )
    identities: set[tuple[str, str, str]] = set()
    for package in packages:
        require(isinstance(package, dict), "installed package record is not an object")
        identity = package_identity(package)
        require(identity not in identities, f"duplicate installed package identity: {identity!r}")
        identities.add(identity)
        status = package.get("status")
        require(isinstance(status, str) and status.startswith("ii"), f"package is not installed: {identity!r}")
    return identities


def verify_apt_index_inventory(inventory: dict[str, Any]) -> None:
    """Verify hashed APT release and package-index inventory records."""
    require(inventory.get("present") is True, "APT index inventory is not present")
    files = inventory.get("files")
    require(isinstance(files, list) and bool(files), "APT index file inventory is empty")
    require(inventory.get("file_count") == len(files), "APT index file count mismatch")
    require(
        inventory.get("files_sha256") == canonical_sha256(files),
        "APT index inventory aggregate SHA-256 mismatch",
    )
    release_count = 0
    package_count = 0
    paths: set[str] = set()
    for item in files:
        require(isinstance(item, dict), "APT index file record is not an object")
        path = item.get("path")
        require(isinstance(path, str) and path and path not in paths, "invalid or duplicate APT index path")
        paths.add(path)
        require(
            isinstance(item.get("sha256"), str)
            and bool(SHA256_RE.fullmatch(item["sha256"])),
            f"invalid APT index SHA-256: {path}",
        )
        require(isinstance(item.get("size_bytes"), int) and item["size_bytes"] >= 0, f"invalid APT index size: {path}")
        release_count += int(item.get("release_metadata") is True)
        package_count += int(item.get("package_index") is True)
    require(release_count > 0 and package_count > 0, "APT release/package index classes are incomplete")
    require(inventory.get("release_file_count") == release_count, "APT release file count mismatch")
    require(inventory.get("package_index_file_count") == package_count, "APT package index count mismatch")


def verify_package_artifacts(
    record: dict[str, Any], installed: set[tuple[str, str, str]]
) -> None:
    """Verify one exact artifact SHA-256 record per installed package."""
    require_false_boundary(record, "package artifact manifest")
    require(
        record.get("record_type")
        == "ptah.phase0c.installed_package_artifact_manifest",
        "package artifact record type mismatch",
    )
    require(record.get("network_used") is False, "package artifact collection used network")
    require(record.get("complete") is True, "package artifact manifest is incomplete")
    require(record.get("missing") == [], "package artifact manifest contains missing records")
    require(record.get("missing_count") == 0, "package artifact missing count is non-zero")
    artifacts = record.get("artifacts")
    require(isinstance(artifacts, list), "package artifact list is missing")
    require(record.get("package_count") == len(installed), "package artifact package count mismatch")
    require(record.get("artifact_count") == len(artifacts), "package artifact count mismatch")
    require(len(artifacts) == len(installed), "package artifact coverage is incomplete")
    require(
        record.get("artifacts_sha256") == canonical_sha256(artifacts),
        "package artifact aggregate SHA-256 mismatch",
    )
    artifact_identities: set[tuple[str, str, str]] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict), "package artifact record is not an object")
        identity = package_identity(artifact)
        require(identity in installed, f"artifact is not linked to an installed package: {identity!r}")
        require(identity not in artifact_identities, f"duplicate package artifact identity: {identity!r}")
        artifact_identities.add(identity)
        require(
            isinstance(artifact.get("sha256"), str)
            and bool(SHA256_RE.fullmatch(artifact["sha256"])),
            f"invalid package artifact SHA-256: {identity!r}",
        )
        require(isinstance(artifact.get("size_bytes"), int) and artifact["size_bytes"] > 0, f"invalid package artifact size: {identity!r}")
        require(isinstance(artifact.get("filename"), str) and bool(artifact["filename"]), f"missing package artifact filename: {identity!r}")
        require(artifact.get("digest_source") == "apt_package_index", f"invalid digest source: {identity!r}")
    require(artifact_identities == installed, "package artifact identities do not exactly match installed packages")
    inventory = record.get("apt_index_inventory")
    require(isinstance(inventory, dict), "APT index inventory is missing")
    verify_apt_index_inventory(inventory)


def verify_apt_sources(record: dict[str, Any]) -> None:
    """Verify the exact active APT source list and aggregate digest."""
    require_false_boundary(record, "APT source manifest")
    require(
        record.get("record_type") == "ptah.phase0c.apt_source_manifest",
        "APT source record type mismatch",
    )
    sources = record.get("sources")
    require(isinstance(sources, list), "APT source list is missing")
    require(all(isinstance(item, str) and item for item in sources), "APT source record is invalid")
    require(record.get("sources_sha256") == canonical_sha256(sources), "APT source aggregate SHA-256 mismatch")


def verify_bundle(bundle_dir: Path) -> dict[str, Any]:
    """Independently verify all source bundle and cross-record invariants."""
    verify_source_file_set(bundle_dir)
    records = {name: load_json(bundle_dir / name) for name in REQUIRED_FILES}
    manifest = records["bundle-manifest.json"]
    require_false_boundary(manifest, "bundle manifest")
    require(
        manifest.get("record_type") == "ptah.phase0c.pinned_host_proof_bundle",
        "bundle manifest record type mismatch",
    )
    require(manifest.get("schema_version") == "0.3.0", "unsupported bundle schema version")
    require(manifest.get("proof_eligible") is True, "source bundle is not proof-eligible")
    for field in (
        "eligibility_failures",
        "host_identity_failures",
        "capability_failures",
        "package_artifact_failures",
    ):
        require(manifest.get(field) == [], f"bundle manifest contains {field}")
    verify_repository_state(manifest)
    file_records = verify_manifest_file_records(bundle_dir, manifest)

    host = records["host-identity.json"]
    capabilities = records["host-capabilities.json"]
    installed = records["installed-packages.json"]
    artifacts = records["package-artifacts.json"]
    apt_sources = records["apt-sources.json"]
    verify_host_identity(host)
    verify_capabilities(capabilities)
    identities = verify_installed_packages(installed)
    verify_package_artifacts(artifacts, identities)
    verify_apt_sources(apt_sources)

    require(manifest.get("package_count") == len(identities), "bundle package count mismatch")
    require(manifest.get("package_artifact_count") == len(identities), "bundle package artifact count mismatch")
    capability_report = manifest.get("capability_report")
    artifact_report = manifest.get("package_artifact_report")
    require(isinstance(capability_report, dict), "bundle capability report binding is missing")
    require(isinstance(artifact_report, dict), "bundle package artifact binding is missing")
    require(capability_report.get("collector_path") == "host/scripts/collect_capabilities.py", "capability collector path mismatch")
    require(artifact_report.get("collector_path") == "tools/collect_apt_package_artifacts.py", "package artifact collector path mismatch")
    require(capability_report.get("validation_failures") == [], "bound capability validation contains failures")
    require(artifact_report.get("validation_failures") == [], "bound package artifact validation contains failures")
    require(capability_report.get("report_sha256") == sha256_file(bundle_dir / "host-capabilities.json"), "bound capability report SHA-256 mismatch")
    require(artifact_report.get("report_sha256") == sha256_file(bundle_dir / "package-artifacts.json"), "bound package artifact report SHA-256 mismatch")

    return {
        "implementation_commit": manifest["implementation_commit"],
        "source_bundle_sha256": manifest["bundle_sha256"],
        "source_manifest_sha256": sha256_file(bundle_dir / "bundle-manifest.json"),
        "package_count": len(identities),
        "file_records": file_records,
        "records": records,
    }


def exact_byte_records(bundle_dir: Path) -> list[dict[str, Any]]:
    """Encode the exact source evidence bytes for durable repository retention."""
    retained: list[dict[str, Any]] = []
    for name in sorted(REQUIRED_FILES):
        raw = (bundle_dir / name).read_bytes()
        retained.append(
            {
                "path": name,
                "size_bytes": len(raw),
                "sha256": sha256_bytes(raw),
                "content_base64": base64.b64encode(raw).decode("ascii"),
            }
        )
    return retained


def write_json(path: Path, value: Any) -> None:
    """Write stable UTF-8 JSON with a final newline."""
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def prepare_retention(bundle_dir: Path, output_dir: Path) -> dict[str, Any]:
    """Verify source evidence and create durable candidate plus pending review files."""
    bundle_dir = bundle_dir.resolve()
    output_dir = output_dir.resolve()
    require(bundle_dir != output_dir, "source and output directories must differ")
    require(not output_dir.exists() or not any(output_dir.iterdir()), f"output directory is not empty: {output_dir}")
    verification = verify_bundle(bundle_dir)
    retained = exact_byte_records(bundle_dir)
    descriptors = [
        {"path": item["path"], "size_bytes": item["size_bytes"], "sha256": item["sha256"]}
        for item in retained
    ]
    retained_files_sha256 = canonical_sha256(descriptors)
    output_dir.mkdir(parents=True, exist_ok=True)
    durable = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.durable_pinned_host_evidence_candidate",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "implementation_commit": verification["implementation_commit"],
        "source_bundle_sha256": verification["source_bundle_sha256"],
        "source_manifest_sha256": verification["source_manifest_sha256"],
        "package_count": verification["package_count"],
        "retained_file_count": len(retained),
        "retained_files_sha256": retained_files_sha256,
        "retained_files": retained,
        "retention_status": "durable_candidate_pending_review",
        "proof_eligible_source_verified": True,
        "runtime_implementation_authorized": False,
    }
    durable_path = output_dir / "durable-pinned-host-bundle.json"
    write_json(durable_path, durable)
    durable_file_sha256 = sha256_file(durable_path)
    review = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.pinned_host_review",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "implementation_commit": verification["implementation_commit"],
        "source_bundle_sha256": verification["source_bundle_sha256"],
        "durable_bundle_file_sha256": durable_file_sha256,
        "retained_files_sha256": retained_files_sha256,
        "review_status": "pending",
        "physical_host_identity_accepted": False,
        "installed_package_manifest_accepted": False,
        "package_artifact_manifest_accepted": False,
        "durable_retention_accepted": False,
        "reviewers": [],
        "review_notes": [],
        "adr0033_accepted": False,
        "runtime_implementation_authorized": False,
    }
    review_path = output_dir / "pinned-host-review-record.json"
    write_json(review_path, review)
    readme = f"""# Phase 0C durable pinned-host evidence candidate

Implementation commit: `{verification['implementation_commit']}`

Source bundle SHA-256: `{verification['source_bundle_sha256']}`

Durable bundle file SHA-256: `{durable_file_sha256}`

Retained exact-file descriptor SHA-256: `{retained_files_sha256}`

The source bundle independently passed file, aggregate, host, capability, package,
APT-index and clean-commit verification before exact bytes were encoded into
`durable-pinned-host-bundle.json`.

This directory is a durable **candidate**, not accepted host proof. The adjacent
`pinned-host-review-record.json` deliberately begins with every acceptance field
set to `false` and `review_status: pending`.

ADR-0033 remains proposed and runtime implementation remains unauthorized.
"""
    (output_dir / "README.md").write_text(readme, encoding="utf-8")
    return {
        "implementation_commit": verification["implementation_commit"],
        "source_bundle_sha256": verification["source_bundle_sha256"],
        "durable_bundle_file_sha256": durable_file_sha256,
        "retained_files_sha256": retained_files_sha256,
        "output_dir": str(output_dir),
        "review_status": "pending",
        "runtime_implementation_authorized": False,
    }


def main() -> int:
    """Run independent verification and prepare durable candidate retention."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = prepare_retention(args.bundle_dir, args.output_dir)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RetentionError as exc:
        print(f"PINNED_HOST_RETENTION_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
