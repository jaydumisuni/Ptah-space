#!/usr/bin/env python3
"""Validate the operative Phase 0C Apache-2.0 owner acceptance boundary.

This checker verifies exact licence bytes, the accepted owner identity, operative
root governance files, machine-readable source annotations, the historical
candidate record, third-party NOTICE review, and the continuing runtime block.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXPECTED_LICENSE_SIZE = 11358
EXPECTED_LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)
EXPECTED_OWNER = "John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS"
EXPECTED_NOTICE = f"Copyright 2026 {EXPECTED_OWNER}"
OPERATIVE_ROOT_FILES = ("LICENSE", "NOTICE", "CONTRIBUTING.md", "SECURITY.md")
SPECIAL_LICENSE_PATHS = {
    "LICENSE",
    "LICENSES/Apache-2.0.txt",
    "legal/candidates/LICENSE.apache-2.0.txt",
}


class AcceptanceError(RuntimeError):
    """Raised when the operative licence boundary is unsafe or inconsistent."""


def require(condition: bool, message: str) -> None:
    """Raise a fail-closed acceptance error."""
    if not condition:
        raise AcceptanceError(message)


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    """Load one JSON object."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError(f"unreadable JSON {path}: {exc}") from exc
    require(isinstance(value, dict), f"JSON root must be an object: {path}")
    return value


def load_text(path: Path, required: tuple[str, ...]) -> str:
    """Read one UTF-8 file and require exact boundary fragments."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AcceptanceError(f"unreadable text {path}: {exc}") from exc
    for fragment in required:
        require(fragment in text, f"{path.name} is missing required text: {fragment!r}")
    return text


def tracked_files(repo_root: Path) -> set[str]:
    """Return exact tracked repository paths."""
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=False,
    )
    require(result.returncode == 0, f"git ls-files failed: {result.stderr.strip()}")
    return {item for item in result.stdout.split("\0") if item}


def validate_reuse(repo_root: Path) -> dict[str, Any]:
    """Validate the repository-wide Apache-2.0 source annotation."""
    path = repo_root / "REUSE.toml"
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise AcceptanceError(f"unreadable REUSE.toml: {exc}") from exc
    require(data.get("version") == 1, "REUSE.toml version must be 1")
    annotations = data.get("annotations")
    require(isinstance(annotations, list) and len(annotations) >= 2, "REUSE annotations missing")

    default = None
    special = None
    for annotation in annotations:
        if not isinstance(annotation, dict):
            continue
        value = annotation.get("path")
        paths = {value} if isinstance(value, str) else set(value or [])
        if "**" in paths:
            default = annotation
        if SPECIAL_LICENSE_PATHS.issubset(paths):
            special = annotation

    require(isinstance(default, dict), "repository-wide REUSE annotation is missing")
    require(default.get("precedence") == "override", "default REUSE precedence must be override")
    require(default.get("SPDX-FileCopyrightText") == f"2026 {EXPECTED_OWNER}", "REUSE owner mismatch")
    require(default.get("SPDX-License-Identifier") == "Apache-2.0", "REUSE licence mismatch")

    require(isinstance(special, dict), "special licence-text annotation is missing")
    require(special.get("precedence") == "override", "special REUSE precedence must be override")
    require(special.get("SPDX-FileCopyrightText") == "NONE", "licence texts must not claim Ptah copyright")
    require(special.get("SPDX-License-Identifier") == "Apache-2.0", "licence-text SPDX mismatch")

    tracked = tracked_files(repo_root)
    require("REUSE.toml" in tracked, "REUSE.toml is not tracked")
    require(SPECIAL_LICENSE_PATHS.issubset(tracked), "one or more exact licence texts are not tracked")
    return {"tracked_file_count": len(tracked), "annotation_count": len(annotations)}


def validate_acceptance(repo_root: Path) -> dict[str, Any]:
    """Validate the complete operative owner-acceptance package."""
    repo_root = repo_root.resolve()
    require(repo_root.is_dir(), f"repository root does not exist: {repo_root}")

    for name in OPERATIVE_ROOT_FILES:
        path = repo_root / name
        require(path.is_file() and not path.is_symlink(), f"operative root file missing or unsafe: {name}")

    candidate_license = repo_root / "legal/candidates/LICENSE.apache-2.0.txt"
    license_paths = [repo_root / "LICENSE", repo_root / "LICENSES/Apache-2.0.txt", candidate_license]
    for path in license_paths:
        require(path.is_file() and not path.is_symlink(), f"exact licence file missing or unsafe: {path}")
        require(path.stat().st_size == EXPECTED_LICENSE_SIZE, f"Apache-2.0 size mismatch: {path}")
        require(sha256_file(path) == EXPECTED_LICENSE_SHA256, f"Apache-2.0 SHA-256 mismatch: {path}")
    require((repo_root / "LICENSE").read_bytes() == candidate_license.read_bytes(), "root LICENSE differs from accepted candidate bytes")
    require((repo_root / "LICENSES/Apache-2.0.txt").read_bytes() == candidate_license.read_bytes(), "LICENSES copy differs from accepted candidate bytes")

    boundary = load_json(repo_root / "legal/apache-2.0-boundary.json")
    require(boundary.get("record_type") == "ptah.phase0c.apache_2_0_boundary", "accepted boundary type mismatch")
    require(boundary.get("status") == "owner_accepted_operative", "accepted boundary status mismatch")
    require(boundary.get("spdx_license") == "Apache-2.0", "accepted SPDX licence mismatch")
    require(boundary.get("operative_root_files_present") is True, "accepted boundary does not record operative files")
    require(boundary.get("apache_2_0_accepted") is True, "Apache-2.0 owner acceptance is not recorded")
    require(boundary.get("runtime_implementation_authorized") is False, "licence acceptance cannot authorize runtime")
    owner = boundary.get("owner_identity")
    require(isinstance(owner, dict), "accepted owner identity is missing")
    require(owner.get("accepted_value") == EXPECTED_OWNER, "accepted owner identity mismatch")
    require(owner.get("status") == "owner_confirmed", "owner identity status mismatch")
    exclusions = boundary.get("private_not_permitted_in_public_repository")
    require(isinstance(exclusions, list) and len(exclusions) >= 10, "private exclusion boundary is incomplete")
    require("customer or client personal data" in exclusions, "customer-data exclusion missing")
    require("unlicensed donor source or proprietary third-party material" in exclusions, "donor-source exclusion missing")
    remaining = boundary.get("remaining_phase0c_blockers")
    require(isinstance(remaining, list) and len(remaining) >= 4, "remaining Phase 0C blockers are not retained")
    require(any("physical" in item.lower() for item in remaining), "physical-host blocker is missing")

    candidate = load_json(repo_root / "legal/candidates/apache-2.0-boundary.json")
    require(candidate.get("apache_2_0_accepted") is False, "historical candidate was rewritten as accepted")
    require(candidate.get("runtime_implementation_authorized") is False, "historical candidate authorizes runtime")
    candidate_owner = candidate.get("owner_identity")
    require(isinstance(candidate_owner, dict) and candidate_owner.get("accepted_value") is None, "historical candidate owner placeholder was rewritten")

    notice = load_text(repo_root / "NOTICE", ("Ptah", EXPECTED_NOTICE, "software developed for the Ptah project"))
    contributing = load_text(
        repo_root / "CONTRIBUTING.md",
        (
            "Status: operative",
            "Apache License, Version 2.0",
            "Not a Contribution",
            "Runtime implementation: AUTHORIZED",
            "REUSE.toml",
        ),
    )
    security = load_text(
        repo_root / "SECURITY.md",
        (
            "Status: operative",
            "support@thetechguyds.com",
            "[PTAH SECURITY]",
            "runtime implementation remains unauthorized",
        ),
    )
    owner_record = load_text(
        repo_root / "legal/APACHE-2.0-OWNER-ACCEPTANCE.md",
        (
            EXPECTED_OWNER,
            "Apache-2.0 accepted: YES",
            "Runtime implementation authorized: NO",
        ),
    )
    notice_review = load_text(
        repo_root / "legal/THIRD-PARTY-NOTICE-REVIEW.md",
        (
            "Status: reviewed",
            "No root NOTICE attribution entries are required",
            "Runtime implementation remains unauthorized",
        ),
    )

    combined = "\n".join((notice, contributing, security, owner_record, notice_review))
    require("[COPYRIGHT OWNER TO CONFIRM]" not in combined, "owner placeholder remains operative")
    require("Status: candidate" not in combined, "candidate status remains in operative files")
    require('"runtime_implementation_authorized": true' not in combined, "operative text contains runtime authorization")

    reuse = validate_reuse(repo_root)
    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.apache_2_0_boundary_acceptance_check",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "owner_identity": EXPECTED_OWNER,
        "official_license_size_bytes": EXPECTED_LICENSE_SIZE,
        "official_license_sha256": EXPECTED_LICENSE_SHA256,
        "operative_root_files": list(OPERATIVE_ROOT_FILES),
        "reuse": reuse,
        "apache_2_0_accepted": True,
        "runtime_implementation_authorized": False,
        "status": "owner_accepted_operative_verified",
    }


def write_json(path: Path, value: Any) -> None:
    """Write stable UTF-8 JSON with a final newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    """Validate the accepted boundary and optionally write a CI report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate_acceptance(args.repo_root)
    if args.output is not None:
        write_json(args.output, report)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceError as exc:
        print(f"APACHE2_BOUNDARY_ACCEPTANCE_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
