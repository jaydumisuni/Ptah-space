#!/usr/bin/env python3
"""Validate the non-operative Phase 0C Apache-2.0 boundary candidate.

The checker intentionally fails if operative root licence/governance files appear
before owner acceptance, if the official licence bytes change, or if a candidate
record claims acceptance or runtime authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXPECTED_LICENSE_SIZE = 11358
EXPECTED_LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)
EXPECTED_BOUNDARY_TYPE = "ptah.phase0c.apache_2_0_boundary_candidate"
OPERATIVE_ROOT_FILES = ("LICENSE", "NOTICE", "CONTRIBUTING.md", "SECURITY.md")
REQUIRED_CANDIDATE_FILES = (
    "LICENSE.apache-2.0.txt",
    "PUBLIC-PRIVATE-BOUNDARY.md",
    "NOTICE.candidate.txt",
    "CONTRIBUTING.candidate.md",
    "SECURITY.candidate.md",
    "apache-2.0-boundary.json",
)


class BoundaryError(RuntimeError):
    """Raised when the candidate licence boundary is unsafe or inconsistent."""


def require(condition: bool, message: str) -> None:
    """Raise a fail-closed boundary error."""
    if not condition:
        raise BoundaryError(message)


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
        raise BoundaryError(f"unreadable boundary JSON: {exc}") from exc
    require(isinstance(value, dict), "boundary JSON root must be an object")
    return value


def require_text(path: Path, required_fragments: tuple[str, ...]) -> str:
    """Read one UTF-8 candidate and require all boundary fragments."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BoundaryError(f"unreadable candidate {path.name}: {exc}") from exc
    for fragment in required_fragments:
        require(fragment in text, f"{path.name} is missing required text: {fragment!r}")
    return text


def validate_candidate(repo_root: Path) -> dict[str, Any]:
    """Validate the complete non-operative candidate package."""
    repo_root = repo_root.resolve()
    require(repo_root.is_dir(), f"repository root does not exist: {repo_root}")
    candidate_root = repo_root / "legal" / "candidates"
    require(candidate_root.is_dir(), "legal/candidates directory is missing")

    for name in OPERATIVE_ROOT_FILES:
        require(
            not (repo_root / name).exists(),
            f"operative root file appeared before owner acceptance: {name}",
        )

    for name in REQUIRED_CANDIDATE_FILES:
        path = candidate_root / name
        require(path.is_file(), f"required candidate file is missing: {name}")
        require(not path.is_symlink(), f"candidate file cannot be a symlink: {name}")

    licence_path = candidate_root / "LICENSE.apache-2.0.txt"
    licence_size = licence_path.stat().st_size
    licence_sha256 = sha256_file(licence_path)
    require(
        licence_size == EXPECTED_LICENSE_SIZE,
        f"Apache-2.0 candidate size mismatch: {licence_size}",
    )
    require(
        licence_sha256 == EXPECTED_LICENSE_SHA256,
        f"Apache-2.0 candidate SHA-256 mismatch: {licence_sha256}",
    )

    boundary = load_json(candidate_root / "apache-2.0-boundary.json")
    require(
        boundary.get("record_type") == EXPECTED_BOUNDARY_TYPE,
        "boundary record type mismatch",
    )
    require(
        boundary.get("status") == "candidate_owner_acceptance_required",
        "boundary status is not pending owner acceptance",
    )
    require(
        boundary.get("proposed_spdx_license") == "Apache-2.0",
        "proposed SPDX licence mismatch",
    )
    require(
        boundary.get("official_license_size_bytes") == licence_size,
        "boundary licence size does not match candidate bytes",
    )
    require(
        boundary.get("official_license_sha256") == licence_sha256,
        "boundary licence digest does not match candidate bytes",
    )
    require(
        boundary.get("operative_root_files_present") is False,
        "boundary record claims operative root files are present",
    )
    require(
        boundary.get("apache_2_0_accepted") is False,
        "candidate cannot accept Apache-2.0",
    )
    require(
        boundary.get("runtime_implementation_authorized") is False,
        "licence candidate cannot authorize runtime implementation",
    )

    owner = boundary.get("owner_identity")
    require(isinstance(owner, dict), "owner identity decision record is missing")
    require(
        owner.get("status") == "owner_confirmation_required",
        "owner identity is not pending confirmation",
    )
    require(
        owner.get("accepted_value") is None,
        "candidate silently selects a copyright owner",
    )

    private_items = boundary.get("private_not_permitted_in_public_repository")
    require(
        isinstance(private_items, list) and len(private_items) >= 8,
        "private exclusion boundary is incomplete",
    )
    acceptance = boundary.get("acceptance_requirements")
    require(
        isinstance(acceptance, list) and len(acceptance) >= 8,
        "owner acceptance gate is incomplete",
    )

    boundary_text = require_text(
        candidate_root / "PUBLIC-PRIVATE-BOUNDARY.md",
        (
            "Status: candidate — owner acceptance required",
            "No root `LICENSE`, `NOTICE` or `CONTRIBUTING.md` is created",
            "Copyright 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS",
            "Copyright 2026 THETECHGUY DIGITAL SOLUTIONS",
            "runtime implementation",
        ),
    )
    notice_text = require_text(
        candidate_root / "NOTICE.candidate.txt",
        (
            "[COPYRIGHT OWNER TO CONFIRM]",
            "[THIRD-PARTY ATTRIBUTION NOTICES TO BE INSERTED ONLY WHEN REVIEW CONFIRMS THEY ARE REQUIRED]",
        ),
    )
    contributing_text = require_text(
        candidate_root / "CONTRIBUTING.candidate.md",
        (
            "Status: candidate — not operative until owner acceptance",
            "Not a Contribution",
            "SPDX-License-Identifier: Apache-2.0",
            "Runtime implementation: AUTHORIZED",
        ),
    )
    security_text = require_text(
        candidate_root / "SECURITY.candidate.md",
        (
            "Status: candidate — not operative until owner acceptance",
            "support@thetechguyds.com",
            "[PTAH SECURITY]",
            "runtime implementation remains unauthorized",
        ),
    )

    require(
        "apache_2_0_accepted: true" not in boundary_text.lower(),
        "boundary prose contains an acceptance claim",
    )
    require(
        "runtime_implementation_authorized\": true" not in notice_text,
        "NOTICE candidate contains an authorization claim",
    )
    require(
        "runtime implementation: authorized" not in security_text.lower(),
        "security candidate contains an authorization claim",
    )
    require(
        "customer or client personal data" in private_items,
        "customer-data exclusion is missing",
    )
    require(
        "unlicensed donor source or proprietary third-party material" in private_items,
        "donor-source exclusion is missing",
    )

    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.apache_2_0_boundary_candidate_check",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "candidate_file_count": len(REQUIRED_CANDIDATE_FILES),
        "official_license_size_bytes": licence_size,
        "official_license_sha256": licence_sha256,
        "owner_confirmation_required": True,
        "operative_root_files_present": False,
        "apache_2_0_accepted": False,
        "runtime_implementation_authorized": False,
        "status": "candidate_valid_non_operative",
        "checked_text_bytes": {
            "public_private_boundary": len(boundary_text.encode("utf-8")),
            "notice": len(notice_text.encode("utf-8")),
            "contributing": len(contributing_text.encode("utf-8")),
            "security": len(security_text.encode("utf-8")),
        },
    }


def write_json(path: Path, value: Any) -> None:
    """Write stable UTF-8 JSON with a final newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    """Validate the candidate and optionally write a CI report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate_candidate(args.repo_root)
    if args.output is not None:
        write_json(args.output, report)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BoundaryError as exc:
        print(f"APACHE2_BOUNDARY_CANDIDATE_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
