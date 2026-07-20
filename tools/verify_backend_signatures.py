#!/usr/bin/env python3
"""Verify selected backend signatures against pinned signing authorities."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from verify_backend_artifacts import ArtifactError, download

ROOT = Path(__file__).resolve().parents[1]


class SignatureError(RuntimeError):
    """Raised when an upstream signature does not match its pinned authority."""


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SignatureError(f"JSON root must be an object: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        args,
        cwd=cwd,
        input=input_bytes,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise SignatureError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"stdout={result.stdout.decode(errors='replace')}\n"
            f"stderr={result.stderr.decode(errors='replace')}"
        )
    return result


def make_home(root: Path, name: str) -> Path:
    home = root / name
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(stat.S_IRWXU)
    return home


def parse_validsig(output: bytes) -> dict[str, str]:
    lines = output.decode("utf-8", errors="replace").splitlines()
    records = [line for line in lines if line.startswith("[GNUPG:] VALIDSIG ")]
    if len(records) != 1:
        raise SignatureError(f"expected exactly one VALIDSIG record, observed {records}")
    parts = records[0].split()
    if len(parts) < 12:
        raise SignatureError(f"invalid VALIDSIG record: {records[0]}")
    return {
        "signing_fingerprint": parts[2],
        "signature_date": parts[3],
        "signature_timestamp": parts[4],
        "primary_fingerprint": parts[-1],
    }


def verify_node(
    authority: dict[str, Any], download_root: Path, work_root: Path
) -> dict[str, Any]:
    repository = authority.get("key_source_repository")
    commit = authority.get("key_source_commit")
    keyring_path = authority.get("keyring_path")
    if not all(isinstance(value, str) for value in (repository, commit, keyring_path)):
        raise SignatureError("Node signing authority record is incomplete")

    checkout = work_root / "node-release-keys"
    checkout.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "--quiet"], cwd=checkout)
    run(
        [
            "git",
            "remote",
            "add",
            "origin",
            f"https://github.com/{repository}.git",
        ],
        cwd=checkout,
    )
    run(["git", "fetch", "--quiet", "--depth", "1", "origin", commit], cwd=checkout)
    run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=checkout)
    observed_commit = run(["git", "rev-parse", "HEAD"], cwd=checkout).stdout.decode().strip()
    if observed_commit != commit:
        raise SignatureError(
            f"Node release-key checkout mismatch: expected={commit}, observed={observed_commit}"
        )

    home = checkout / keyring_path
    if not home.is_dir():
        raise SignatureError(f"Node active keyring directory is missing: {home}")
    home.chmod(stat.S_IRWXU)
    manifest = download_root / "node-SHASUMS256.txt.asc"
    if not manifest.is_file():
        raise SignatureError("Node signed checksum manifest was not downloaded")
    result = run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(home),
            "--status-fd",
            "1",
            "--verify",
            str(manifest),
        ]
    )
    signature = parse_validsig(result.stdout)
    return {
        "component": "nodejs",
        "status": "signature_verified",
        "key_source_repository": repository,
        "key_source_commit": observed_commit,
        "keyring_tree_sha256": tree_sha256(home),
        "manifest_sha256": sha256(manifest),
        "signature": signature,
    }


def tree_sha256(root: Path) -> str:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def verify_runc(
    authority: dict[str, Any], download_root: Path, work_root: Path
) -> dict[str, Any]:
    ref = authority.get("key_source_ref")
    if not isinstance(ref, str):
        raise SignatureError("runc signing authority ref is missing")
    binary = download_root / "runc.amd64"
    if not binary.is_file():
        raise SignatureError("runc binary was not downloaded")
    signature = work_root / "runc.amd64.asc"
    keyring = work_root / "runc.keyring"
    signature_transfer = download(
        f"https://github.com/opencontainers/runc/releases/download/{ref}/runc.amd64.asc",
        signature,
    )
    keyring_transfer = download(
        f"https://raw.githubusercontent.com/opencontainers/runc/{ref}/runc.keyring",
        keyring,
    )
    home = make_home(work_root, "runc-gnupg")
    result = run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(home),
            "--no-default-keyring",
            "--keyring",
            str(keyring),
            "--status-fd",
            "1",
            "--verify",
            str(signature),
            str(binary),
        ]
    )
    return {
        "component": "runc",
        "status": "signature_verified",
        "key_source_ref": ref,
        "keyring_sha256": sha256(keyring),
        "keyring_transfer": keyring_transfer,
        "signature_sha256": sha256(signature),
        "signature_transfer": signature_transfer,
        "signature": parse_validsig(result.stdout),
    }


def verify_git(
    authority: dict[str, Any], download_root: Path, work_root: Path
) -> dict[str, Any]:
    expected_primary = authority.get("primary_fingerprint")
    key_transport = authority.get("key_transport")
    if not isinstance(expected_primary, str) or not isinstance(key_transport, str):
        raise SignatureError("Git signing authority record is incomplete")
    archive = download_root / "git-2.55.0.tar.xz"
    if not archive.is_file():
        raise SignatureError("Git source archive was not downloaded")
    signature = work_root / "git-2.55.0.tar.sign"
    key = work_root / "git-release-key.asc"
    signature_transfer = download(
        "https://www.kernel.org/pub/software/scm/git/git-2.55.0.tar.sign",
        signature,
    )
    key_transfer = download(key_transport, key)
    home = make_home(work_root, "git-gnupg")
    run(["gpg", "--batch", "--homedir", str(home), "--import", str(key)])
    fingerprints = (
        run(
            [
                "gpg",
                "--batch",
                "--homedir",
                str(home),
                "--with-colons",
                "--fingerprint",
            ]
        )
        .stdout.decode("utf-8", errors="replace")
        .splitlines()
    )
    imported = [line.split(":")[9] for line in fingerprints if line.startswith("fpr:")]
    if expected_primary not in imported:
        raise SignatureError(
            f"Git key fingerprint mismatch: expected={expected_primary}, imported={imported}"
        )

    decompressed = run(["xz", "--decompress", "--stdout", str(archive)], timeout=180).stdout
    result = run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(home),
            "--status-fd",
            "1",
            "--verify",
            str(signature),
            "-",
        ],
        input_bytes=decompressed,
        timeout=180,
    )
    valid = parse_validsig(result.stdout)
    if valid["primary_fingerprint"] != expected_primary:
        raise SignatureError(
            f"Git signature primary fingerprint mismatch: expected={expected_primary}, observed={valid}"
        )
    return {
        "component": "git-source",
        "status": "signature_verified",
        "expected_primary_fingerprint": expected_primary,
        "key_sha256": sha256(key),
        "key_transfer": key_transfer,
        "signature_sha256": sha256(signature),
        "signature_transfer": signature_transfer,
        "signature": valid,
    }


def discover_libarchive(
    authority: dict[str, Any], work_root: Path
) -> dict[str, Any]:
    signature = work_root / "libarchive-3.8.7.tar.xz.asc"
    transfer = download(
        "https://libarchive.org/downloads/libarchive-3.8.7.tar.xz.asc", signature
    )
    packet_output = run(["gpg", "--batch", "--list-packets", str(signature)]).stdout.decode(
        "utf-8", errors="replace"
    )
    fingerprint_matches = re.findall(r"issuer fpr v\d+ ([0-9A-Fa-f]+)", packet_output)
    key_id_matches = re.findall(r"keyid ([0-9A-Fa-f]+)", packet_output)
    return {
        "component": "libarchive-source",
        "status": "signature_issuer_discovered_not_verified",
        "signature_sha256": sha256(signature),
        "signature_transfer": transfer,
        "issuer_fingerprints": sorted(set(value.upper() for value in fingerprint_matches)),
        "issuer_key_ids": sorted(set(value.upper() for value in key_id_matches)),
        "locked_fingerprint": authority.get("signer_fingerprint"),
    }


def verify(key_lock: Path, download_root: Path, work_root: Path) -> dict[str, Any]:
    if shutil.which("gpg") is None or shutil.which("git") is None or shutil.which("xz") is None:
        raise SignatureError("gpg, git and xz are required for signature evidence")
    lock = load_object(key_lock)
    if lock.get("runtime_implementation_authorized") is not False:
        raise SignatureError("signing-key lock cannot authorize runtime implementation")
    authorities = lock.get("authorities")
    if not isinstance(authorities, list):
        raise SignatureError("signing authority array is missing")
    by_component = {
        item.get("component"): item for item in authorities if isinstance(item, dict)
    }
    work_root.mkdir(parents=True, exist_ok=True)
    results = [
        verify_node(by_component["nodejs"], download_root, work_root),
        verify_runc(by_component["runc"], download_root, work_root),
        verify_git(by_component["git-source"], download_root, work_root),
        discover_libarchive(by_component["libarchive-source"], work_root),
    ]
    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.backend_signature_verification",
        "verified_signature_count": 3,
        "discovery_count": 1,
        "results": results,
        "runtime_implementation_authorized": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key-lock", type=Path, default=ROOT / "dependencies/signing-key-lock.json"
    )
    parser.add_argument("--download-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = verify(args.key_lock, args.download_root, args.work_root)
    except ArtifactError as exc:
        raise SignatureError(str(exc)) from exc
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
