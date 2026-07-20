#!/usr/bin/env python3
"""Download and verify selected Phase 0C backend artifacts.

The verifier is evidence-only. It never installs a Ptah runtime and never
changes the repository lock. Unknown or incomplete digests are reported as
candidate evidence for a later reviewed lock update.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


class ArtifactError(RuntimeError):
    """Raised when an authoritative artifact cannot be verified."""


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ArtifactError(f"JSON root must be an object: {path}")
    return value


def download(url: str, path: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "Ptah-Phase0C-Evidence/1"})
    with urllib.request.urlopen(request, timeout=120) as response, path.open("wb") as handle:
        while chunk := response.read(1024 * 1024):
            handle.write(chunk)


def digest(path: Path, algorithm: str) -> str:
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha3-256":
        hasher = hashlib.sha3_256()
    elif algorithm == "sha512-base64":
        hasher = hashlib.sha512()
    else:
        raise ArtifactError(f"unsupported digest algorithm: {algorithm}")
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    if algorithm == "sha512-base64":
        return base64.b64encode(hasher.digest()).decode("ascii")
    return hasher.hexdigest()


def extract_git_sha256(manifest: Path, filename: str) -> str:
    text = manifest.read_text(encoding="utf-8", errors="replace")
    pattern = re.compile(rf"^([0-9a-f]{{64}})\s+{re.escape(filename)}$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        raise ArtifactError(f"signed Git checksum manifest lacks {filename}")
    return match.group(1)


def verify(lock_path: Path, download_root: Path) -> dict[str, Any]:
    lock = load_object(lock_path)
    if lock.get("runtime_implementation_authorized") is not False:
        raise ArtifactError("backend artifact lock cannot authorize runtime implementation")
    artifacts = lock.get("artifacts")
    if not isinstance(artifacts, list):
        raise ArtifactError("backend artifact array is missing")

    download_root.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    git_manifest: Path | None = None

    for entry in artifacts:
        if not isinstance(entry, dict):
            raise ArtifactError("backend artifact entry is not an object")
        component = entry.get("component")
        filename = entry.get("filename")
        url = entry.get("download_url")
        expected = entry.get("digest")

        if component == "ubuntu-server":
            image_lock = load_object(ROOT / "host/image-lock.json")
            image = image_lock.get("image", {})
            if not isinstance(image, dict):
                raise ArtifactError("host image lock is invalid")
            matches = image.get("filename") == filename and image.get("sha256") == expected.get("value")
            if not matches:
                raise ArtifactError("backend Ubuntu record does not match host/image-lock.json")
            results.append(
                {
                    "component": component,
                    "filename": filename,
                    "status": "cross_record_verified_not_downloaded",
                    "digest": expected,
                }
            )
            continue

        if component == "git-source":
            manifest_url = entry.get("signed_checksum_manifest")
            if not isinstance(manifest_url, str):
                raise ArtifactError("Git signed checksum manifest URL is missing")
            git_manifest = download_root / "git-sha256sums.asc"
            download(manifest_url, git_manifest)
            if not isinstance(filename, str) or not isinstance(url, str):
                raise ArtifactError("Git source record is incomplete")
            expected_git = extract_git_sha256(git_manifest, filename)
            target = download_root / filename
            download(url, target)
            observed = digest(target, "sha256")
            if observed != expected_git:
                raise ArtifactError("Git source does not match signed checksum manifest")
            results.append(
                {
                    "component": component,
                    "filename": filename,
                    "status": "verified_candidate_digest",
                    "digest": {"algorithm": "sha256", "value": observed},
                    "signed_checksum_manifest_sha256": digest(git_manifest, "sha256"),
                }
            )
            continue

        if not isinstance(filename, str) or not isinstance(url, str):
            raise ArtifactError(f"download record incomplete: {component}")
        if not isinstance(expected, dict):
            raise ArtifactError(f"digest record missing: {component}")
        algorithm = expected.get("algorithm")
        expected_value = expected.get("value")
        if not isinstance(algorithm, str) or not isinstance(expected_value, str):
            raise ArtifactError(f"digest record invalid: {component}")

        target = download_root / filename
        download(url, target)
        observed = digest(target, algorithm)
        if observed != expected_value:
            raise ArtifactError(
                f"digest mismatch for {component}: expected {expected_value}, observed {observed}"
            )
        results.append(
            {
                "component": component,
                "filename": filename,
                "status": "verified",
                "digest": expected,
                "size_bytes": target.stat().st_size,
            }
        )

    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.backend_artifact_verification",
        "lock_path": str(lock_path.relative_to(ROOT)),
        "verified_artifact_count": len(results),
        "results": results,
        "runtime_implementation_authorized": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lock", type=Path, default=ROOT / "dependencies/backend-artifact-lock.json"
    )
    parser.add_argument("--download-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = verify(args.lock, args.download_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
