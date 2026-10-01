#!/usr/bin/env python3
"""Collect non-claiming E05 evidence from currently connected ADB endpoints.

ADB reachability alone is not Android proof. A physical Android endpoint is
reported only when read-only Android build/product properties are verified.
Raw transport serials are never emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ANDROID_PROPERTIES = {
    "manufacturer": "ro.product.manufacturer",
    "model": "ro.product.model",
    "device": "ro.product.device",
    "release": "ro.build.version.release",
    "sdk": "ro.build.version.sdk",
    "abi": "ro.product.cpu.abi",
}


def command(*args: str) -> dict[str, Any]:
    """Run one bounded read-only ADB probe."""
    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "error": type(exc).__name__}
    return {
        "available": True,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def serial_digest(serial: str) -> str:
    """Return a stable one-way transport identifier for evidence correlation."""
    return hashlib.sha256(serial.encode("utf-8")).hexdigest()


def parse_devices(output: str) -> list[tuple[str, str, dict[str, str]]]:
    """Parse adb devices -l without exposing raw serials to callers."""
    endpoints: list[tuple[str, str, dict[str, str]]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices attached"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        descriptors: dict[str, str] = {}
        for token in parts[2:]:
            if ":" in token:
                key, value = token.split(":", 1)
                descriptors[key] = value
        endpoints.append((serial, state, descriptors))
    return endpoints


def clean_property(value: str) -> str:
    """Reject shell errors and blank values as property evidence."""
    stripped = value.strip()
    lowered = stripped.lower()
    if not stripped or "getprop: not found" in lowered or lowered.startswith("/bin/sh:"):
        return ""
    return stripped


def read_android_properties(serial: str) -> dict[str, str]:
    """Read the bounded Android property set from one ADB endpoint."""
    values: dict[str, str] = {}
    for label, key in ANDROID_PROPERTIES.items():
        result = command("adb", "-s", serial, "shell", "getprop", key)
        if result.get("available") is not True or result.get("returncode") != 0:
            values[label] = ""
            continue
        values[label] = clean_property(str(result.get("stdout", "")))
    return values


def android_properties_verified(properties: dict[str, str]) -> bool:
    """Require Android SDK, model, release and ABI rather than an ADB alias."""
    sdk = properties.get("sdk", "")
    return (
        sdk.isdigit()
        and bool(properties.get("model"))
        and bool(properties.get("release"))
        and bool(properties.get("abi"))
    )


def collect() -> dict[str, Any]:
    """Collect current ADB endpoint evidence without creating Node/Device authority."""
    listing = command("adb", "devices", "-l")
    endpoints: list[dict[str, Any]] = []

    if listing.get("available") is True and listing.get("returncode") == 0:
        for serial, state, descriptors in parse_devices(str(listing.get("stdout", ""))):
            properties = read_android_properties(serial) if state == "device" else {}
            verified = state == "device" and android_properties_verified(properties)
            endpoints.append(
                {
                    "transport_serial_sha256": serial_digest(serial),
                    "adb_state": state,
                    "adb_descriptors": descriptors,
                    "properties": properties,
                    "android_properties_verified": verified,
                    "classification": (
                        "physical_android" if verified else "adb_non_android_or_unverified"
                    ),
                }
            )

    physical_android = any(
        endpoint["classification"] == "physical_android" for endpoint in endpoints
    )
    blockers: list[str] = []
    if not physical_android:
        blockers.append("no_physical_android_device_verified")

    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.e05.android_device_capability_report",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "physical_android_device_observed": physical_android,
        "blockers": blockers,
        "e05_admission_authorized": False,
        "c08_c10_authority_created": False,
        "runtime_authorized": False,
        "automatic_upgrade_authorized": False,
        "self_approved": False,
        "claim_boundary": (
            "ADB reachability is transport evidence only. Physical Android is reported only when "
            "read-only Android SDK/model/release/ABI properties are verified. This report does not "
            "create a Ptah Node identity, C08 Device identity, C08 lease/fence, C10 Device Session, "
            "or E05 admission."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-android", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = collect()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.require_android and not report["physical_android_device_observed"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
