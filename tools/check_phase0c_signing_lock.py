#!/usr/bin/env python3
"""Validate the immutable Phase 0C backend signing-authority lock."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "dependencies/signing-key-lock.json"
EXPECTED_COMPONENTS = {"nodejs", "runc", "git-source", "libarchive-source"}


class SigningLockError(RuntimeError):
    """Raised when the signer lock is incomplete or claims runtime authority."""


def object_value(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SigningLockError(f"{name} must be an object")
    return value


def text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SigningLockError(f"{name} must be non-empty text")
    return value


def hex_digest(value: Any, name: str, length: int = 64) -> str:
    item = text(value, name)
    if len(item) != length or any(character not in "0123456789abcdefABCDEF" for character in item):
        raise SigningLockError(f"{name} must be a {length}-character hexadecimal value")
    return item.lower()


def fingerprint(value: Any, name: str) -> str:
    item = text(value, name).upper()
    if len(item) != 40 or any(character not in "0123456789ABCDEF" for character in item):
        raise SigningLockError(f"{name} must be a 40-character OpenPGP fingerprint")
    return item


def verify() -> dict[str, Any]:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    if not isinstance(lock, dict):
        raise SigningLockError("signing lock root must be an object")
    if lock.get("status") != "all_selected_signatures_locked_pinned_host_proof_open":
        raise SigningLockError("signing lock is not in the accepted pre-host-proof state")
    if lock.get("runtime_implementation_authorized") is not False:
        raise SigningLockError("signing lock cannot authorize runtime implementation")

    verification = object_value(lock.get("verification"), "verification")
    expected_paths = {
        "base_tool_path": "tools/verify_backend_signatures.py",
        "final_tool_path": "tools/verify_backend_signatures_final.py",
        "workflow_path": ".github/workflows/phase0c-backend-signatures.yml",
    }
    for key, expected in expected_paths.items():
        if verification.get(key) != expected:
            raise SigningLockError(f"noncanonical signing verification path: {key}")
        if not (ROOT / expected).is_file():
            raise SigningLockError(f"signing verification source is missing: {expected}")
    if verification.get("required_signature_count") != 4:
        raise SigningLockError("exactly four backend signatures must be required")
    if verification.get("runtime_implementation_authorized") is not False:
        raise SigningLockError("signing verifier cannot authorize runtime implementation")

    authorities = lock.get("authorities")
    if not isinstance(authorities, list) or len(authorities) != 4:
        raise SigningLockError("signing lock must contain exactly four authorities")
    by_component: dict[str, dict[str, Any]] = {}
    for entry in authorities:
        record = object_value(entry, "authority")
        component = text(record.get("component"), "authority.component")
        if component in by_component:
            raise SigningLockError(f"duplicate signing authority: {component}")
        if record.get("status") != "signature_locked":
            raise SigningLockError(f"signing authority is not locked: {component}")
        by_component[component] = record
    if set(by_component) != EXPECTED_COMPONENTS:
        raise SigningLockError(
            f"signing authority set mismatch: expected={sorted(EXPECTED_COMPONENTS)}, observed={sorted(by_component)}"
        )

    node = by_component["nodejs"]
    text(node.get("key_source_repository"), "node.key_source_repository")
    hex_digest(node.get("key_source_commit"), "node.key_source_commit", 40)
    fingerprint(node.get("verified_primary_fingerprint"), "node.verified_primary_fingerprint")
    hex_digest(node.get("signed_manifest_sha256"), "node.signed_manifest_sha256")

    runc = by_component["runc"]
    hex_digest(runc.get("keyring_sha256"), "runc.keyring_sha256")
    hex_digest(runc.get("normalized_keyring_sha256"), "runc.normalized_keyring_sha256")
    fingerprint(runc.get("verified_primary_fingerprint"), "runc.verified_primary_fingerprint")
    hex_digest(runc.get("signature_sha256"), "runc.signature_sha256")

    git = by_component["git-source"]
    fingerprint(git.get("primary_fingerprint"), "git.primary_fingerprint")
    fingerprint(git.get("signing_subkey_fingerprint"), "git.signing_subkey_fingerprint")
    text(git.get("fingerprint_authority"), "git.fingerprint_authority")
    hex_digest(git.get("signature_sha256"), "git.signature_sha256")

    libarchive = by_component["libarchive-source"]
    fingerprint(libarchive.get("signer_fingerprint"), "libarchive.signer_fingerprint")
    text(libarchive.get("fingerprint_authority"), "libarchive.fingerprint_authority")
    hex_digest(libarchive.get("key_sha256"), "libarchive.key_sha256")
    hex_digest(libarchive.get("signature_sha256"), "libarchive.signature_sha256")

    blockers = lock.get("blockers")
    if not isinstance(blockers, list):
        raise SigningLockError("signing lock blockers must be an array")
    if any("Verify all four selected backend signatures" in str(item) for item in blockers):
        raise SigningLockError("signing lock retains an obsolete verification blocker")
    if not any("pinned Ubuntu host" in str(item) for item in blockers):
        raise SigningLockError("signing lock must retain the pinned-host blocker")

    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.signing_lock_check",
        "status": lock["status"],
        "authority_count": len(authorities),
        "components": sorted(by_component),
        "runtime_implementation_authorized": False,
    }


def main() -> int:
    report = verify()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
