#!/usr/bin/env python3
"""Create a fail-closed Phase 0C pinned-host proof bundle.

This script collects host identity, installed package inventory, repository state,
and existing Ptah host-capability evidence. It never authorizes runtime behavior.
Run it only on the exact frozen Ubuntu host candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXPECTED_OS_ID = "ubuntu"
EXPECTED_VERSION_ID = "24.04"
EXPECTED_POINT_RELEASE = "24.04.4"
EXPECTED_ARCH = "x86_64"
EXPECTED_KERNEL_PREFIX = "6.8.0-136-generic"
EXPECTED_CAPABILITY_RECORD_TYPE = "ptah.phase0c.host_capability_report"


class ProofError(RuntimeError):
    """Raised when the pinned-host proof cannot be produced safely."""


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise ProofError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr.strip()}"
        )
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def locate_capability_collector(repo_root: Path) -> Path:
    candidates = [
        repo_root / "host" / "scripts" / "collect_capabilities.py",
        repo_root / "tools" / "collect_host_capabilities.py",
        repo_root / "tools" / "collect_host_capability_evidence.py",
        repo_root / "tools" / "host_capability_collector.py",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ProofError(
        "accepted Ptah host-capability collector was not found at "
        "host/scripts/collect_capabilities.py"
    )


def collect_packages() -> list[dict[str, str]]:
    if shutil.which("dpkg-query") is None:
        raise ProofError("dpkg-query is unavailable on the candidate host")
    result = run(
        [
            "dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\\n",
        ]
    )
    packages: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 4 or not fields[3].startswith("ii"):
            continue
        packages.append(
            {
                "package": fields[0],
                "version": fields[1],
                "architecture": fields[2],
                "status": fields[3],
            }
        )
    packages.sort(key=lambda item: (item["package"], item["architecture"], item["version"]))
    if not packages:
        raise ProofError("installed package inventory is empty")
    return packages


def collect_apt_sources() -> list[str]:
    paths = [Path("/etc/apt/sources.list")]
    paths.extend(sorted(Path("/etc/apt/sources.list.d").glob("*")))
    records: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                records.append(f"{path}:{line}")
    return sorted(records)


def collect_boot_identity() -> dict[str, Any]:
    result: dict[str, Any] = {
        "machine_id_sha256": None,
        "boot_id": None,
        "secure_boot": "unknown",
    }
    machine_id = Path("/etc/machine-id")
    if machine_id.is_file():
        result["machine_id_sha256"] = hashlib.sha256(machine_id.read_bytes().strip()).hexdigest()
    boot_id = Path("/proc/sys/kernel/random/boot_id")
    if boot_id.is_file():
        result["boot_id"] = boot_id.read_text(encoding="utf-8").strip()
    if shutil.which("mokutil"):
        secure = run(["mokutil", "--sb-state"], check=False)
        result["secure_boot"] = (secure.stdout or secure.stderr).strip()
    return result


def validate_host(os_release: dict[str, str], kernel: str, arch: str) -> list[str]:
    failures: list[str] = []
    pretty = " ".join(
        [os_release.get("VERSION", ""), os_release.get("PRETTY_NAME", "")]
    )
    if os_release.get("ID") != EXPECTED_OS_ID:
        failures.append(f"ID={os_release.get('ID')!r}")
    if os_release.get("VERSION_ID") != EXPECTED_VERSION_ID:
        failures.append(f"VERSION_ID={os_release.get('VERSION_ID')!r}")
    if EXPECTED_POINT_RELEASE not in pretty:
        failures.append(f"point_release_not_found:{pretty!r}")
    if arch != EXPECTED_ARCH:
        failures.append(f"architecture={arch!r}")
    if not kernel.startswith(EXPECTED_KERNEL_PREFIX):
        failures.append(f"kernel={kernel!r}")
    return failures


def validate_capability_payload(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if payload.get("record_type") != EXPECTED_CAPABILITY_RECORD_TYPE:
        failures.append("capability_record_type_mismatch")
    if payload.get("runtime_implementation_authorized") is not False:
        failures.append("capability_report_authorization_boundary_invalid")
    if payload.get("required_capabilities_passed") is not True:
        failures.append("required_capabilities_not_passed")
    if payload.get("proof_eligible") is not True:
        failures.append("capability_report_not_proof_eligible")
    pinned_match = payload.get("pinned_host_match")
    if not isinstance(pinned_match, dict) or pinned_match.get("all_match") is not True:
        failures.append("capability_pinned_host_identity_not_matched")
    required_failures = payload.get("required_failures")
    if not isinstance(required_failures, list) or required_failures:
        failures.append("capability_required_failures_present_or_invalid")
    return failures


def proof_failures(
    host_failures: list[str], repository_dirty: bool, capability_failures: list[str]
) -> list[str]:
    failures = [f"host:{failure}" for failure in host_failures]
    if repository_dirty:
        failures.append("repository_dirty")
    failures.extend(f"capability:{failure}" for failure in capability_failures)
    return failures


def invoke_capability_collector(repo_root: Path, output_root: Path) -> dict[str, Any]:
    collector = locate_capability_collector(repo_root)
    output = output_root / "host-capabilities.json"
    command = [sys.executable, str(collector), "--output", str(output)]
    result = run(command, check=False)
    if result.returncode != 0:
        raise ProofError(
            "host-capability collector failed "
            f"({result.returncode}): {(result.stderr or result.stdout).strip()}"
        )
    if not output.is_file():
        raise ProofError("host-capability collector did not produce host-capabilities.json")
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProofError(f"capability collector emitted invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ProofError("capability collector JSON root is not an object")
    return {
        "collector_path": collector.relative_to(repo_root).as_posix(),
        "collector_sha256": sha256_file(collector),
        "collector_returncode": result.returncode,
        "report_path": output.name,
        "report_sha256": sha256_file(output),
        "validation_failures": validate_capability_payload(payload),
        "payload": payload,
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_bundle(repo_root: Path, output_root: Path) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    os_release = read_os_release()
    kernel = platform.release()
    arch = platform.machine()
    host_failures = validate_host(os_release, kernel, arch)

    packages = collect_packages()
    package_record = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.installed_package_manifest",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "package_count": len(packages),
        "packages_sha256": canonical_sha256(packages),
        "packages": packages,
        "runtime_implementation_authorized": False,
    }
    package_path = output_root / "installed-packages.json"
    write_json(package_path, package_record)

    apt_sources = collect_apt_sources()
    apt_record = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.apt_source_manifest",
        "sources": apt_sources,
        "sources_sha256": canonical_sha256(apt_sources),
        "runtime_implementation_authorized": False,
    }
    apt_path = output_root / "apt-sources.json"
    write_json(apt_path, apt_record)

    capabilities = invoke_capability_collector(repo_root, output_root)
    capability_failures = list(capabilities["validation_failures"])
    commit = run(["git", "-C", str(repo_root), "rev-parse", "HEAD"]).stdout.strip()
    dirty = bool(run(["git", "-C", str(repo_root), "status", "--porcelain"]).stdout.strip())
    eligibility_failures = proof_failures(host_failures, dirty, capability_failures)

    host_record = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.pinned_host_identity",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "os_release": os_release,
        "kernel": kernel,
        "architecture": arch,
        "hostname_sha256": hashlib.sha256(platform.node().encode()).hexdigest(),
        "boot_identity": collect_boot_identity(),
        "expected": {
            "id": EXPECTED_OS_ID,
            "version_id": EXPECTED_VERSION_ID,
            "point_release": EXPECTED_POINT_RELEASE,
            "architecture": EXPECTED_ARCH,
            "kernel_prefix": EXPECTED_KERNEL_PREFIX,
        },
        "identity_failures": host_failures,
        "proof_eligible": not host_failures,
        "runtime_implementation_authorized": False,
    }
    host_path = output_root / "host-identity.json"
    write_json(host_path, host_record)

    file_records = []
    for path in sorted(output_root.glob("*.json")):
        if path.name == "bundle-manifest.json":
            continue
        file_records.append(
            {
                "path": path.name,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )

    manifest = {
        "schema_version": "0.2.0",
        "record_type": "ptah.phase0c.pinned_host_proof_bundle",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "implementation_commit": commit,
        "repository_dirty": dirty,
        "proof_eligible": not eligibility_failures,
        "eligibility_failures": eligibility_failures,
        "host_identity_failures": host_failures,
        "capability_failures": capability_failures,
        "capability_report": {
            key: value for key, value in capabilities.items() if key != "payload"
        },
        "package_count": len(packages),
        "files": file_records,
        "bundle_sha256": canonical_sha256(file_records),
        "runtime_implementation_authorized": False,
    }
    write_json(output_root / "bundle-manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    output = args.output.resolve()
    manifest = build_bundle(repo_root, output)
    print(json.dumps(manifest, indent=2))
    if not manifest["proof_eligible"]:
        raise ProofError(
            "candidate host evidence was collected but is not proof-eligible: "
            + ", ".join(manifest["eligibility_failures"])
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProofError as exc:
        print(f"PINNED_HOST_PROOF_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
