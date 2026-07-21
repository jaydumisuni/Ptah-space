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
APT_QUERY_BATCH_SIZE = 128
PackageIdentity = tuple[str, str, str]
Resolution = dict[PackageIdentity, tuple[list[dict[str, Any]], list[dict[str, Any]]]]


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
    identities: set[PackageIdentity] = set()
    for item in packages:
        if not isinstance(item, dict):
            raise ArtifactError("installed package record must be an object")
        record: dict[str, str] = {}
        for field in ("package", "version", "architecture"):
            value = item.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ArtifactError(
                    f"installed package record field {field!r} is invalid: {item!r}"
                )
            record[field] = value.strip()
        identity = package_identity(record)
        if identity in identities:
            raise ArtifactError(f"duplicate installed package identity: {identity!r}")
        identities.add(identity)
        normalized.append(record)
    return sorted(normalized, key=package_identity)


def package_identity(package: dict[str, str]) -> PackageIdentity:
    """Return the stable identity tuple for one installed binary package."""
    return (package["package"], package["architecture"], package["version"])


def architecture_query(package: dict[str, str]) -> str:
    """Build the preferred exact-version, exact-architecture APT selector."""
    name = package["package"]
    if ":" not in name:
        name = f"{name}:{package['architecture']}"
    return f"{name}={package['version']}"


def plain_query(package: dict[str, str]) -> str:
    """Build the architecture-neutral exact-version fallback selector."""
    base_name = package["package"].split(":", 1)[0]
    return f"{base_name}={package['version']}"


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


def _chunks(items: list[dict[str, str]], size: int) -> list[list[dict[str, str]]]:
    """Split package records into bounded APT command batches."""
    return [items[index : index + size] for index in range(0, len(items), size)]


def _query_batches(
    packages: list[dict[str, str]],
    apt_cache: str,
    query_builder: Callable[[dict[str, str]], str],
) -> Resolution:
    """Query exact package metadata in bounded local APT batches."""
    resolution: Resolution = {
        package_identity(package): ([], []) for package in packages
    }
    for batch in _chunks(packages, APT_QUERY_BATCH_SIZE):
        queries = [query_builder(package) for package in batch]
        result = run([apt_cache, "show", *queries], check=False)
        paragraphs = parse_deb822(result.stdout) if result.stdout.strip() else []
        stderr = result.stderr.strip()
        for package, query in zip(batch, queries, strict=True):
            identity = package_identity(package)
            matches, attempts = resolution[identity]
            matches.extend(exact_artifacts(package, paragraphs, query))
            attempts.append(
                {
                    "query": query,
                    "batch_returncode": result.returncode,
                    "stderr": stderr,
                }
            )
    return resolution


def query_package_artifacts(
    packages: list[dict[str, str]], apt_cache: str
) -> Resolution:
    """Resolve exact installed artifacts using architecture-first batched queries."""
    primary = _query_batches(packages, apt_cache, architecture_query)
    unresolved = [
        package for package in packages if not primary[package_identity(package)][0]
    ]
    fallback = _query_batches(unresolved, apt_cache, plain_query) if unresolved else {}
    resolution: Resolution = {}
    for package in packages:
        identity = package_identity(package)
        matches, attempts = primary[identity]
        if identity in fallback:
            fallback_matches, fallback_attempts = fallback[identity]
            matches.extend(fallback_matches)
            attempts.extend(fallback_attempts)
        unique_by_digest: dict[tuple[str, int], dict[str, Any]] = {}
        for match in matches:
            digest_identity = (match["sha256"], match["size_bytes"])
            existing = unique_by_digest.get(digest_identity)
            if existing is None or match["filename"] < existing["filename"]:
                unique_by_digest[digest_identity] = match
        if len(unique_by_digest) > 1:
            raise ArtifactError(
                "conflicting APT SHA-256 metadata for "
                f"{package['package']}={package['version']}:{package['architecture']}"
            )
        resolution[identity] = (list(unique_by_digest.values()), attempts)
    return resolution


def collect_apt_index_inventory(root: Path) -> dict[str, Any]:
    """Hash APT list files and require both release and package-index evidence."""
    files: list[dict[str, Any]] = []
    release_count = 0
    package_index_count = 0
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            if any(part in {"partial", "auxfiles"} for part in relative.parts):
                continue
            if path.name == "lock":
                continue
            name = path.name
            is_release = (
                name.endswith("InRelease")
                or name.endswith("Release")
                or name.endswith("Release.gpg")
            )
            is_package_index = "Packages" in name
            if is_release:
                release_count += 1
            if is_package_index:
                package_index_count += 1
            files.append(
                {
                    "path": relative.as_posix(),
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "release_metadata": is_release,
                    "package_index": is_package_index,
                }
            )
    present = bool(files) and release_count > 0 and package_index_count > 0
    return {
        "root": str(root),
        "file_count": len(files),
        "release_file_count": release_count,
        "package_index_file_count": package_index_count,
        "files": files,
        "files_sha256": canonical_sha256(files),
        "present": present,
    }


def build_manifest(
    packages: list[dict[str, str]],
    *,
    apt_cache: str,
    apt_lists_root: Path,
    resolver: Callable[
        [list[dict[str, str]], str], Resolution
    ] = query_package_artifacts,
) -> dict[str, Any]:
    """Build the complete fail-closed installed-package artifact manifest."""
    resolution = resolver(packages, apt_cache)
    artifacts: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for package in packages:
        matches, attempts = resolution.get(package_identity(package), ([], []))
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
    artifacts.sort(key=package_identity)
    missing.sort(key=package_identity)
    index_inventory = collect_apt_index_inventory(apt_lists_root)
    complete = (
        len(artifacts) == len(packages)
        and not missing
        and index_inventory["present"]
    )
    return {
        "schema_version": "0.2.0",
        "record_type": RECORD_TYPE,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "collection_mode": "local_apt_cache_exact_version_metadata",
        "network_used": False,
        "apt_cache": apt_cache,
        "apt_query_batch_size": APT_QUERY_BATCH_SIZE,
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
