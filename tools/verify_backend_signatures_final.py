#!/usr/bin/env python3
"""Final Phase 0C backend signature verifier.

This wrapper keeps the base verifier intact while normalizing runc's
human-readable armored ``runc.keyring`` into an isolated GPG home and capturing
libarchive packet metadata from both GPG output streams.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import verify_backend_signatures as base


def verify_runc(
    authority: dict[str, Any], download_root: Path, work_root: Path
) -> dict[str, Any]:
    ref = authority.get("key_source_ref")
    if not isinstance(ref, str):
        raise base.SignatureError("runc signing authority ref is missing")
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
    key_listing = base.run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(home),
            "--with-colons",
            "--fingerprint",
        ]
    ).stdout.decode("utf-8", errors="replace")
    imported_fingerprints = sorted(
        {
            line.split(":")[9]
            for line in key_listing.splitlines()
            if line.startswith("fpr:") and len(line.split(":")) > 9
        }
    )
    if not imported_fingerprints:
        raise base.SignatureError("runc keyring import produced no fingerprints")

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
    if valid["primary_fingerprint"] not in imported_fingerprints:
        raise base.SignatureError(
            "runc signature was valid but its primary fingerprint was not in the pinned keyring: "
            f"signature={json.dumps(valid, sort_keys=True)}, imported={imported_fingerprints}"
        )
    return {
        "component": "runc",
        "status": "signature_verified",
        "key_source_ref": ref,
        "keyring_sha256": base.sha256(keyring),
        "normalized_keyring_sha256": base.sha256(normalized),
        "imported_fingerprints": imported_fingerprints,
        "keyring_transfer": keyring_transfer,
        "signature_sha256": base.sha256(signature),
        "signature_transfer": signature_transfer,
        "signature": valid,
    }


def discover_libarchive(
    authority: dict[str, Any], work_root: Path
) -> dict[str, Any]:
    signature = work_root / "libarchive-3.8.7.tar.xz.asc"
    transfer = base.download(
        "https://libarchive.org/downloads/libarchive-3.8.7.tar.xz.asc", signature
    )
    result = base.run(["gpg", "--batch", "--list-packets", str(signature)])
    packet_output = (
        result.stdout.decode("utf-8", errors="replace")
        + "\n"
        + result.stderr.decode("utf-8", errors="replace")
    )
    fingerprint_matches = re.findall(
        r"issuer fpr v\d+ ([0-9A-Fa-f]+)", packet_output
    )
    key_id_matches = re.findall(r"keyid ([0-9A-Fa-f]+)", packet_output)
    return {
        "component": "libarchive-source",
        "status": "signature_issuer_discovered_not_verified",
        "signature_sha256": base.sha256(signature),
        "signature_transfer": transfer,
        "issuer_fingerprints": sorted(
            {value.upper() for value in fingerprint_matches}
        ),
        "issuer_key_ids": sorted({value.upper() for value in key_id_matches}),
        "locked_fingerprint": authority.get("signer_fingerprint"),
        "packet_metadata_sha256": base.hashlib.sha256(
            packet_output.encode("utf-8")
        ).hexdigest(),
    }


def main() -> int:
    base.verify_runc = verify_runc
    base.discover_libarchive = discover_libarchive
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
