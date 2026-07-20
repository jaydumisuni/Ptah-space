#!/usr/bin/env python3
"""Final Phase 0C backend signature verifier.

This wrapper keeps the base verifier intact while normalizing runc's
human-readable armored keyring and enforcing the independently pinned
libarchive release signer.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

import verify_backend_signatures as base


def imported_fingerprints(home: Path) -> list[str]:
    listing = base.run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(home),
            "--with-colons",
            "--fingerprint",
        ]
    ).stdout.decode("utf-8", errors="replace")
    return sorted(
        {
            line.split(":")[9]
            for line in listing.splitlines()
            if line.startswith("fpr:") and len(line.split(":")) > 9
        }
    )


def verify_runc(
    authority: dict[str, Any], download_root: Path, work_root: Path
) -> dict[str, Any]:
    ref = authority.get("key_source_ref")
    expected_keyring_sha256 = authority.get("keyring_sha256")
    expected_primary = authority.get("verified_primary_fingerprint")
    if not all(
        isinstance(value, str)
        for value in (ref, expected_keyring_sha256, expected_primary)
    ):
        raise base.SignatureError("runc signing authority record is incomplete")
    binary = download_root / "runc.amd64"
    if not binary.is_file():
        raise base.SignatureError("runc binary was not downloaded")

    signature = work_root / "runc.amd64.asc"
    keyring = work_root / "runc.keyring"
    signature_transfer = base.download(
        f"https://github.com/opencontainers/runc/releases/download/{ref}/runc.amd64.asc",
        signature,
    )
    keyring_transfer = base.download(
        f"https://raw.githubusercontent.com/opencontainers/runc/{ref}/runc.keyring",
        keyring,
    )
    if base.sha256(keyring) != expected_keyring_sha256:
        raise base.SignatureError("runc keyring digest does not match the pinned lock")

    keyring_text = keyring.read_text(encoding="utf-8", errors="replace")
    blocks = re.findall(
        r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
        keyring_text,
        flags=re.DOTALL,
    )
    if not blocks:
        raise base.SignatureError("runc.keyring contains no armored public keys")
    normalized = work_root / "runc-public-keys.asc"
    normalized.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")

    home = base.make_home(work_root, "runc-gnupg")
    base.run(["gpg", "--batch", "--homedir", str(home), "--import", str(normalized)])
    fingerprints = imported_fingerprints(home)
    if expected_primary not in fingerprints:
        raise base.SignatureError(
            f"pinned runc signer is absent from the release keyring: {expected_primary}"
        )

    result = base.run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(home),
            "--status-fd",
            "1",
            "--verify",
            str(signature),
            str(binary),
        ]
    )
    valid = base.parse_validsig(result.stdout)
    if valid["primary_fingerprint"] != expected_primary:
        raise base.SignatureError(
            "runc signature fingerprint mismatch: "
            f"expected={expected_primary}, observed={json.dumps(valid, sort_keys=True)}"
        )
    return {
        "component": "runc",
        "status": "signature_verified",
        "key_source_ref": ref,
        "keyring_sha256": base.sha256(keyring),
        "normalized_keyring_sha256": base.sha256(normalized),
        "imported_fingerprints": fingerprints,
        "keyring_transfer": keyring_transfer,
        "signature_sha256": base.sha256(signature),
        "signature_transfer": signature_transfer,
        "signature": valid,
    }


def verify_libarchive(
    authority: dict[str, Any], download_root: Path, work_root: Path
) -> dict[str, Any]:
    expected_primary = authority.get("signer_fingerprint")
    key_transport = authority.get("key_transport")
    if not isinstance(expected_primary, str) or not isinstance(key_transport, str):
        raise base.SignatureError("libarchive signing authority record is incomplete")
    archive = download_root / "libarchive-3.8.7.tar.xz"
    if not archive.is_file():
        raise base.SignatureError("libarchive source archive was not downloaded")

    signature = work_root / "libarchive-3.8.7.tar.xz.asc"
    key = work_root / "libarchive-release-key.asc"
    signature_transfer = base.download(
        "https://libarchive.org/downloads/libarchive-3.8.7.tar.xz.asc", signature
    )
    key_transfer = base.download(key_transport, key)
    home = base.make_home(work_root, "libarchive-gnupg")
    base.run(["gpg", "--batch", "--homedir", str(home), "--import", str(key)])
    fingerprints = imported_fingerprints(home)
    if expected_primary not in fingerprints:
        raise base.SignatureError(
            "libarchive key fingerprint mismatch: "
            f"expected={expected_primary}, imported={fingerprints}"
        )

    result = base.run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(home),
            "--status-fd",
            "1",
            "--verify",
            str(signature),
            str(archive),
        ]
    )
    valid = base.parse_validsig(result.stdout)
    if valid["primary_fingerprint"] != expected_primary:
        raise base.SignatureError(
            "libarchive signature fingerprint mismatch: "
            f"expected={expected_primary}, observed={json.dumps(valid, sort_keys=True)}"
        )
    return {
        "component": "libarchive-source",
        "status": "signature_verified",
        "expected_primary_fingerprint": expected_primary,
        "key_sha256": base.sha256(key),
        "key_transfer": key_transfer,
        "signature_sha256": base.sha256(signature),
        "signature_transfer": signature_transfer,
        "signature": valid,
    }


def verify_all(key_lock: Path, download_root: Path, work_root: Path) -> dict[str, Any]:
    if (
        shutil.which("gpg") is None
        or shutil.which("git") is None
        or shutil.which("xz") is None
    ):
        raise base.SignatureError("gpg, git and xz are required for signature evidence")
    lock = base.load_object(key_lock)
    if lock.get("runtime_implementation_authorized") is not False:
        raise base.SignatureError("signing-key lock cannot authorize runtime implementation")
    authorities = lock.get("authorities")
    if not isinstance(authorities, list):
        raise base.SignatureError("signing authority array is missing")
    by_component = {
        item.get("component"): item for item in authorities if isinstance(item, dict)
    }
    required = {"nodejs", "runc", "git-source", "libarchive-source"}
    if not required.issubset(by_component):
        raise base.SignatureError("one or more signing authority records are missing")

    work_root.mkdir(parents=True, exist_ok=True)
    results = [
        base.verify_node(by_component["nodejs"], download_root, work_root),
        verify_runc(by_component["runc"], download_root, work_root),
        base.verify_git(by_component["git-source"], download_root, work_root),
        verify_libarchive(
            by_component["libarchive-source"], download_root, work_root
        ),
    ]
    return {
        "schema_version": "0.2.0",
        "record_type": "ptah.phase0c.backend_signature_verification",
        "verified_signature_count": 4,
        "discovery_count": 0,
        "results": results,
        "runtime_implementation_authorized": False,
    }


def main() -> int:
    base.verify_runc = verify_runc
    base.verify = verify_all
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
