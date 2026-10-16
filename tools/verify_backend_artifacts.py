#!/usr/bin/env python3
"""Download and verify selected Phase 0C backend artifacts.

The verifier is evidence-only. It never installs a Ptah runtime and never
changes the repository lock. Every network transfer uses strict HTTPS through
curl and records its final URL, HTTP status, content type, byte count and magic
bytes so a proxy or CDN substitution cannot masquerade as a digest mismatch.
Node and Git source hashes are derived from their downloaded signed checksum
manifests in the same exact-head run.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import tempfile
import shutil
import subprocess
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


def file_magic(path: Path, length: int = 16) -> str:
    with path.open("rb") as handle:
        return handle.read(length).hex()


def download(url: str, path: Path) -> dict[str, Any]:
    curl = shutil.which("curl")
    if curl is None:
        raise ArtifactError("curl is required for strict artifact downloads")
    marker = "PTAH_CURL_META"
    write_out = (
        f"\\n{marker}"
        "%{url_effective}\\n%{http_code}\\n%{content_type}\\n%{size_download}\\n"
    )
    result = subprocess.run(
        [
            curl,
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--retry",
            "3",
            "--retry-all-errors",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--user-agent",
            "Ptah-Phase0C-Evidence/3",
            "--output",
            str(path),
            "--write-out",
            write_out,
            url,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if result.returncode != 0:
        raise ArtifactError(
            f"download failed for {url}: curl={result.returncode}, stderr={result.stderr.strip()}"
        )
    if marker not in result.stdout:
        raise ArtifactError(f"curl metadata marker missing for {url}")
    metadata_text = result.stdout.split(marker, 1)[1].strip().splitlines()
    if len(metadata_text) < 4:
        raise ArtifactError(f"curl metadata incomplete for {url}: {metadata_text}")
    final_url, http_code, content_type, size_download = metadata_text[:4]
    if http_code != "200":
        raise ArtifactError(f"unexpected HTTP status for {url}: {http_code}")
    if not path.is_file() or path.stat().st_size == 0:
        raise ArtifactError(f"downloaded artifact is empty: {url}")
    try:
        reported_size = int(float(size_download))
    except ValueError as exc:
        raise ArtifactError(f"invalid curl size for {url}: {size_download}") from exc
    if reported_size != path.stat().st_size:
        raise ArtifactError(
            f"curl byte count mismatch for {url}: reported={reported_size}, file={path.stat().st_size}"
        )
    return {
        "requested_url": url,
        "final_url": final_url,
        "http_code": int(http_code),
        "content_type": content_type,
        "size_bytes": path.stat().st_size,
        "magic_hex": file_magic(path),
    }


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


def extract_named_sha256(manifest: Path, filename: str, authority: str) -> str:
    text = manifest.read_text(encoding="utf-8", errors="replace")
    if "-----BEGIN PGP SIGN" not in text or "-----BEGIN PGP SIGNATURE-----" not in text:
        raise ArtifactError(f"{authority} checksum manifest is not OpenPGP clear-signed")
    pattern = re.compile(
        rf"^([0-9a-f]{{64}})\s+[*]?{re.escape(filename)}$", re.MULTILINE
    )
    match = pattern.search(text)
    if not match:
        raise ArtifactError(f"{authority} signed checksum manifest lacks {filename}")
    return match.group(1)


KERNEL_ORG_AUTOSIGNER_FPR = "B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1"
KERNEL_ORG_AUTOSIGNER_KEY_SHA256 = "099fb3eca2b31006bc0f37db9dd9226a1bc51a8958d54c278e3f67006a8a114b"


def verify_pinned_kernel_checksum_signature(manifest: Path) -> dict[str, str]:
    """Authenticate archived kernel.org autosigner material with a pinned key.

    The original checksum file's digest also must match the immutable Phase 0C
    backend lock. This operation never signs, alters or authorizes a new lock.
    """
    key = ROOT / "conformance/immutable-source-manifests/kernel-org-autosigner-public.gpg"
    if key.is_symlink() or not key.is_file():
        raise ArtifactError("pinned kernel.org autosigner key missing or symlinked")
    if digest(key, "sha256") != KERNEL_ORG_AUTOSIGNER_KEY_SHA256:
        raise ArtifactError("pinned kernel.org autosigner key digest mismatch")
    executable = shutil.which("gpg")
    if executable is None:
        raise ArtifactError("gpg required to verify archived kernel.org manifest")
    with tempfile.TemporaryDirectory(prefix="ptah-kernel-manifest-") as folder:
        home = Path(folder) / "gnupg"
        home.mkdir(mode=0o700)
        fingerprint = subprocess.run(
            [executable, "--batch", "--homedir", str(home),
             "--with-colons", "--show-keys", str(key)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        fprs = {line.split(":")[9] for line in fingerprint.stdout.splitlines()
                if line.startswith("fpr:") and len(line.split(":")) > 9}
        if fingerprint.returncode or KERNEL_ORG_AUTOSIGNER_FPR not in fprs:
            raise ArtifactError("kernel.org autosigner fingerprint mismatch")
        imported = subprocess.run(
            [executable, "--batch", "--homedir", str(home), "--import", str(key)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if imported.returncode:
            raise ArtifactError("kernel.org autosigner key import failed")
        verified = subprocess.run(
            [executable, "--batch", "--homedir", str(home),
             "--status-fd", "1", "--verify", str(manifest)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        expected = "[GNUPG:] VALIDSIG " + KERNEL_ORG_AUTOSIGNER_FPR + " "
        if verified.returncode or not any(
            line.startswith(expected) for line in verified.stdout.splitlines()
        ):
            raise ArtifactError("archived kernel.org checksum manifest PGP verification failed")
    return {
        "fingerprint": KERNEL_ORG_AUTOSIGNER_FPR,
        "public_key_sha256": KERNEL_ORG_AUTOSIGNER_KEY_SHA256,
        "status": "good_signature_and_pinned_fingerprint",
    }


def verify_signed_manifest_artifact(
    *,
    component: str,
    filename: str,
    url: str,
    manifest_url: str,
    manifest_filename: str,
    download_root: Path,
    pinned_snapshot: Path | None = None,
    immutable_snapshot_sha256: str | None = None,
) -> dict[str, Any]:
    manifest = download_root / manifest_filename
    if pinned_snapshot is not None:
        # kernel.org's sha256sums.asc is a *rolling* signed catalogue.
        # Never compare today's catalogue bytes against an old immutable
        # digest. Recover the exact historically selected signed bytes,
        # without changing the frozen lock or claiming a new signature.
        if pinned_snapshot.is_symlink() or not pinned_snapshot.is_file():
            raise ArtifactError("pinned Git checksum evidence missing or symlinked")
        if not pinned_snapshot.resolve().is_relative_to(ROOT.resolve()):
            raise ArtifactError("pinned checksum evidence must be under repository")
        if not isinstance(immutable_snapshot_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", immutable_snapshot_sha256
        ):
            raise ArtifactError("immutable signed manifest digest missing")
        observed_manifest_digest = digest(pinned_snapshot, "sha256")
        if observed_manifest_digest != immutable_snapshot_sha256:
            raise ArtifactError("pinned historical signed manifest digest mismatch")
        shutil.copyfile(pinned_snapshot, manifest)
        manifest_transfer = {
            "retrieval_mode": "original_signed_manifest_pinned_in_repository",
            "original_url": manifest_url,
            "source_path": pinned_snapshot.relative_to(ROOT).as_posix(),
            "sha256": observed_manifest_digest,
            "same_run_download": False,
        }
    else:
        manifest_transfer = download(manifest_url, manifest)
    signature_evidence = (
        verify_pinned_kernel_checksum_signature(manifest)
        if pinned_snapshot is not None else None
    )
    expected = extract_named_sha256(manifest, filename, component)
    target = download_root / filename
    transfer = download(url, target)
    observed = digest(target, "sha256")
    if observed != expected:
        raise ArtifactError(
            f"{component} artifact does not match signed checksum manifest: "
            f"expected={expected}, observed={observed}, transfer={json.dumps(transfer, sort_keys=True)}"
        )
    return {
        "component": component,
        "filename": filename,
        "status": "verified_candidate_digest",
        "digest": {"algorithm": "sha256", "value": observed},
        "transfer": transfer,
        "signed_checksum_manifest_sha256": digest(manifest, "sha256"),
        "signed_checksum_manifest_transfer": manifest_transfer,
        "signed_checksum_manifest_pgp": signature_evidence,
    }


def verify(lock_path: Path, download_root: Path) -> dict[str, Any]:
    lock = load_object(lock_path)
    if lock.get("runtime_implementation_authorized") is not False:
        raise ArtifactError("backend artifact lock cannot authorize runtime implementation")
    artifacts = lock.get("artifacts")
    if not isinstance(artifacts, list):
        raise ArtifactError("backend artifact array is missing")

    download_root.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []

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
            if not isinstance(image, dict) or not isinstance(expected, dict):
                raise ArtifactError("host image or backend Ubuntu record is invalid")
            matches = (
                image.get("filename") == filename
                and image.get("sha256") == expected.get("value")
            )
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

        if component == "nodejs":
            manifest_url = entry.get("checksum_authority")
            if not all(isinstance(value, str) for value in (filename, url, manifest_url)):
                raise ArtifactError("Node artifact record is incomplete")
            results.append(
                verify_signed_manifest_artifact(
                    component="nodejs",
                    filename=filename,
                    url=url,
                    manifest_url=manifest_url,
                    manifest_filename="node-SHASUMS256.txt.asc",
                    download_root=download_root,
                )
            )
            continue

        if component == "git-source":
            manifest_url = entry.get("signed_checksum_manifest")
            if not all(isinstance(value, str) for value in (filename, url, manifest_url)):
                raise ArtifactError("Git source record is incomplete")
            results.append(
                verify_signed_manifest_artifact(
                    component="git-source",
                    filename=filename,
                    url=url,
                    manifest_url=manifest_url,
                    manifest_filename="git-sha256sums.asc",
                    download_root=download_root,
                    pinned_snapshot=ROOT / "conformance/immutable-source-manifests/git-2.55.0-sha256sums.asc",
                    immutable_snapshot_sha256=entry.get("signed_checksum_manifest_sha256"),
                )
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
        transfer = download(url, target)
        observed = digest(target, algorithm)
        if observed != expected_value:
            raise ArtifactError(
                f"digest mismatch for {component}: expected={expected_value}, observed={observed}, "
                f"transfer={json.dumps(transfer, sort_keys=True)}"
            )
        results.append(
            {
                "component": component,
                "filename": filename,
                "status": "verified",
                "digest": expected,
                "transfer": transfer,
            }
        )

    return {
        "schema_version": "0.3.0",
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
