#!/usr/bin/env python3
"""Collect exact APT artifact digests for the installed Phase 0C package set.

The collector is local-only: it reads the dpkg-derived installed-package manifest,
queries the existing APT cache for the exact version/architecture records, and
hashes the local APT index files that supplied that metadata. It does not update
APT, download packages, or authorize runtime implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
RECORD_TYPE = "ptah.phase0c.installed_package_artifact_manifest"


class ArtifactError(RuntimeError):
    """Raised when package artifact evidence cannot be collected safely."""


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run one command without a shell and optionally fail on non-zero status."""
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise ArtifactError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{(result.stderr or result.stdout).strip()}"
        )
    return result


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    """Hash one JSON value using stable key and separator ordering."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: Any) -> None:
    """Write stable UTF-8 JSON with a final newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def parse_deb822(text: str) -> list[dict[str, str]]:
    """Parse the Debian control paragraphs emitted by ``apt-cache show``."""
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    current_key: str | None = None
    for raw_line in text.splitlines() + [""]:
        if not raw_line.strip():
            if current:
                paragraphs.append(current)
                current = {}
                current_key = None
            continue
        if raw_line[0].isspace():
            if current_key is None:
                raise ArtifactError("APT metadata continuation appeared before a field")
            current[current_key] += "\n" + raw_line[1:]
            continue
        if ":" not in raw_line:
            raise ArtifactError(f"malformed APT metadata line: {raw_line!r}")
        key, value = raw_line.split(":", 1)
        key = key.strip()
        if not key:
            raise ArtifactError("APT metadata contains an empty field name")
        if key in current:
            raise ArtifactError(f"APT metadata repeats field {key!r} in one paragraph")
        current[key] = value.lstrip()
        current_key = key
    return paragraphs


def load_installed_packages(path: Path) -> list[dict[str, str]]:
    """Load and validate the dpkg-derived installed package manifest."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"installed package manifest is unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise ArtifactError("installed package manifest root must be an object")
    if payload.get("record_type") != "ptah.phase0c.installed_package_manifest":
        raise ArtifactError("installed package manifest record type is invalid")
    if payload.get("runtime_implementation_authorized") is not False:
        raise ArtifactError("installed package manifest authorization boundary is invalid")
    packages = payload.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ArtifactError("installed package manifest contains no packages")
    if payload.get("package_count") != len(packages):
        raise ArtifactError("installed package count does not match package records")
    normalized: list[dict[str, str]] = []
    identities: set[tuple[str, str, str]] = set()
    for item in packages:
        if not isinstance(item, dict):
            raise ArtifactError("installed package record must be an object")
        record = {
            "package": str(item.get("package", "")).strip(),
            "version": str(item.get("version", "")).strip(),
            "architecture": str(item.get("architecture", "")).strip(),
        }
        if not all(record.values()):
            raise ArtifactError(f"installed package record is incomplete: {item!r}")
        identity = (record["package"], record["version"], record["architecture"])
        if identity in identities:
            raise ArtifactError(f"duplicate installed package identity: {identity!r}")
        identities.add(identity)
        normalized.append(record)
    return sorted(
        normalized,
        key=lambda item: (item["package"], item["architecture"], item["version"]),
    )


def package_queries(package: dict[str, str]) -> list[str]:
    """Build deterministic exact-version APT queries for one binary package."""
    name = package["package"]
    version = package["version"]
    architecture = package["architecture"]
    base_name = name.split(":", 1)[0]
    candidates = [f"{name}={version}"]
    if ":" not in name:
        candidates.insert(0, f"{name}:{architecture}={version}")
    candidates.append(f"{base_name}={version}")
    unique: list[str] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique


def exact_artifacts(
    package: dict[str, str], paragraphs: list[dict[str, str]], query: str
) -> list[dict[str, Any]]:
    """Extract complete SHA-256 artifact records matching one installed package."""
    expected_name = package["package"].split(":", 1)[0]
    expected_version = package["version"]
    expected_architecture = package["architecture"]
    matches: list[dict[str, Any]] = []
    for paragraph in paragraphs:
        if paragraph.get("Package") != expected_name:
            continue
        if paragraph.get("Version") != expected_version:
            continue
        if paragraph.get("Architecture") != expected_architecture:
            continue
        digest = paragraph.get("SHA256", "").lower()
        filename = paragraph.get("Filename", "")
        size_text = paragraph.get("Size", "")
        if not SHA256_RE.fullmatch(digest) or not filename or not size_text.isdigit():
            continue
        matches.append(
            {
                "package": package["package"],
                "version": expected_version,
                "architecture": expected_architecture,
                "apt_package": paragraph["Package"],
                "apt_query": query,
                "filename": filename,
                "size_bytes": int(size_text),
                "sha256": digest,
                "source_package": paragraph.get("Source"),
                "section": paragraph.get("Section"),
                "priority": paragraph.get("Priority"),
                "multi_arch": paragraph.get("Multi-Arch"),
                "digest_source": "apt_package_index",
            }
        )
    return matches


def query_package_artifacts(
    package: dict[str, str], apt_cache: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Query local APT metadata for one exact installed package identity."""
    attempts: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []
    for query in package_queries(package):
        result = run([apt_cache, "show", query], check=False)
        attempts.append(
            {
                "query": query,
                "returncode": result.returncode,
                "stderr": result.stderr.strip(),
            }
        )
        if result.returncode != 0 or not result.stdout.strip():
            continue
        paragraphs = parse_deb822(result.stdout)
        matches.extend(exact_artifacts(package, paragraphs, query))
    unique_by_digest: dict[tuple[str, int], dict[str, Any]] = {}
    for match in matches:
        identity = (match["sha256"], match["size_bytes"])
        existing = unique_by_digest.get(identity)
        if existing is None or match["filename"] < existing["filename"]:
            unique_by_digest[identity] = match
    if len(unique_by_digest) > 1:
        raise ArtifactError(
            "conflicting APT SHA-256 metadata for "
            f"{package['package']}={package['version']}:{package['architecture']}"
        )
    return list(unique_by_digest.values()), attempts


def collect_apt_index_inventory(root: Path) -> dict[str, Any]:
    """Hash the local APT list files that make exact artifact metadata reproducible."""
    files: list[dict[str, Any]] = []
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            if any(part in {"partial", "auxfiles"} for part in relative.parts):
                continue
            if path.name == "lock":
                continue
            files.append(
                {
                    "path": relative.as_posix(),
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return {
        "root": str(root),
        "file_count": len(files),
        "files": files,
        "files_sha256": canonical_sha256(files),
        "present": bool(files),
    }


def build_manifest(
    packages: list[dict[str, str]],
    *,
    apt_cache: str,
    apt_lists_root: Path,
    query_fn: Callable[
        [dict[str, str], str], tuple[list[dict[str, Any]], list[dict[str, Any]]]
    ] = query_package_artifacts,
) -> dict[str, Any]:
    """Build the complete fail-closed installed-package artifact manifest."""
    artifacts: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for package in packages:
        matches, attempts = query_fn(package, apt_cache)
        if len(matches) == 1:
            artifact = matches[0]
            artifact["queries_attempted"] = [attempt["query"] for attempt in attempts]
            artifacts.append(artifact)
        else:
            missing.append(
                {
                    **package,
                    "reason": "exact_sha256_artifact_metadata_not_found",
                    "attempts": attempts,
                }
            )
    artifacts.sort(
        key=lambda item: (item["package"], item["architecture"], item["version"])
    )
    missing.sort(
        key=lambda item: (item["package"], item["architecture"], item["version"])
    )
    index_inventory = collect_apt_index_inventory(apt_lists_root)
    complete = len(artifacts) == len(packages) and not missing and index_inventory["present"]
    return {
        "schema_version": "0.1.0",
        "record_type": RECORD_TYPE,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "collection_mode": "local_apt_cache_exact_version_metadata",
        "network_used": False,
        "apt_cache": apt_cache,
        "package_count": len(packages),
        "artifact_count": len(artifacts),
        "missing_count": len(missing),
        "complete": complete,
        "artifacts_sha256": canonical_sha256(artifacts),
        "artifacts": artifacts,
        "missing": missing,
        "apt_index_inventory": index_inventory,
        "claim_boundary": (
            "SHA-256 values are the exact binary-package artifact digests recorded in the "
            "local APT package metadata for the installed version and architecture. This "
            "does not replace host capability proof or authorize runtime implementation."
        ),
        "runtime_implementation_authorized": False,
    }


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-packages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--apt-lists-root", type=Path, default=Path("/var/lib/apt/lists")
    )
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Collect and write one package-artifact manifest."""
    args = parse_args()
    apt_cache = shutil.which("apt-cache")
    if apt_cache is None:
        raise ArtifactError("apt-cache is unavailable on the candidate host")
    packages = load_installed_packages(args.installed_packages)
    manifest = build_manifest(
        packages, apt_cache=apt_cache, apt_lists_root=args.apt_lists_root
    )
    version = run([apt_cache, "--version"], check=False)
    manifest["apt_cache_version"] = (version.stdout or version.stderr).strip()
    write_json(args.output, manifest)
    print(json.dumps(manifest, indent=2))
    if args.require_complete and not manifest["complete"]:
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ArtifactError as exc:
        print(f"APT_PACKAGE_ARTIFACT_EVIDENCE_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
