#!/usr/bin/env python3
"""Finalize one host capability report against the exact pinned image identity.

Ubuntu Server identifies itself as ``ID=ubuntu`` and commonly keeps
``VERSION_ID=24.04`` across point releases. The exact 24.04.4 point release is
therefore verified from ``VERSION`` or ``PRETTY_NAME`` while kernel identity
remains an exact prefix match against the frozen image lock.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


def normalize_architecture(value: str) -> str:
    aliases = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    return aliases.get(value.lower(), value.lower())


def pinned_host_match(
    image_lock: dict[str, Any],
    os_release: dict[str, Any],
    uname: dict[str, Any],
) -> dict[str, Any]:
    expected_distribution = str(image_lock.get("distribution", ""))
    expected_release = str(image_lock.get("release", ""))
    expected_architecture = str(image_lock.get("architecture", ""))
    kernel_record = image_lock.get("kernel", {})
    if not isinstance(kernel_record, dict):
        kernel_record = {}
    expected_kernel = str(kernel_record.get("expected_uname_family", ""))

    observed_id = str(os_release.get("ID", ""))
    observed_name = str(os_release.get("NAME", ""))
    observed_version_id = str(os_release.get("VERSION_ID", ""))
    observed_version = str(os_release.get("VERSION", ""))
    observed_pretty = str(os_release.get("PRETTY_NAME", ""))
    observed_architecture = str(uname.get("machine", ""))
    observed_kernel = str(uname.get("release", ""))

    expected_distribution_lower = expected_distribution.lower()
    distribution_match = (
        ("ubuntu" in expected_distribution_lower and observed_id.lower() == "ubuntu")
        or expected_distribution_lower == observed_name.lower()
    )

    expected_point_release = expected_release.split()[0]
    release_sources = [observed_version, observed_pretty]
    release_match = any(expected_point_release in source for source in release_sources)
    base_release_match = observed_version_id == ".".join(expected_point_release.split(".")[:2])

    architecture_match = normalize_architecture(expected_architecture) == normalize_architecture(
        observed_architecture
    )
    kernel_match = bool(expected_kernel) and observed_kernel.startswith(expected_kernel)

    return {
        "distribution": {
            "expected": expected_distribution,
            "observed_id": observed_id,
            "observed_name": observed_name,
            "match": distribution_match,
        },
        "release": {
            "expected": expected_release,
            "observed_version_id": observed_version_id,
            "observed_version": observed_version,
            "observed_pretty_name": observed_pretty,
            "base_release_match": base_release_match,
            "point_release_match": release_match,
            "match": base_release_match and release_match,
        },
        "architecture": {
            "expected": expected_architecture,
            "observed": observed_architecture,
            "match": architecture_match,
        },
        "kernel": {
            "expected_family": expected_kernel,
            "observed": observed_kernel,
            "match": kernel_match,
        },
        "all_match": (
            distribution_match
            and base_release_match
            and release_match
            and architecture_match
            and kernel_match
        ),
    }


def finalize(report: dict[str, Any], image_lock: dict[str, Any]) -> dict[str, Any]:
    host = report.get("host", {})
    if not isinstance(host, dict):
        raise RuntimeError("host report does not contain a host object")
    release = host.get("os_release", {})
    uname = host.get("uname", {})
    if not isinstance(release, dict) or not isinstance(uname, dict):
        raise RuntimeError("host report identity fields are invalid")

    match = pinned_host_match(image_lock, release, uname)
    required_passed = report.get("required_capabilities_passed") is True
    proof_eligible = required_passed and match["all_match"]

    report["pinned_host_match"] = match
    report["proof_eligible"] = proof_eligible
    report["status"] = "proof_eligible" if proof_eligible else "candidate_host_observed"
    report["runtime_implementation_authorized"] = False
    report["identity_finalizer"] = {
        "repository_path": "host/scripts/finalize_capability_report.py",
        "ubuntu_point_release_source": ["VERSION", "PRETTY_NAME"],
        "runtime_implementation_authorized": False,
    }
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--image-lock", type=Path, default=ROOT / "host/image-lock.json"
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-pinned-host", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = finalize(load_object(args.report), load_object(args.image_lock))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    destination = args.output or args.report
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.require_pinned_host and not report["proof_eligible"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
