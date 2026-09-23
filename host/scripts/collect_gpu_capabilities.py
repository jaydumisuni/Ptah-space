#!/usr/bin/env python3
"""Collect non-claiming E05 GPU capability evidence.

The collector distinguishes observed GPU hardware/render paths from independently
verified compute APIs. It never authorizes E05 admission or Ptah runtime work.
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DRM_ROOT = Path("/sys/class/drm")
MAX_OUTPUT = 4096


def read_text(path: Path) -> str:
    """Read one host evidence file without turning read failure into a claim."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def command(*args: str) -> dict[str, Any]:
    """Run one bounded evidence probe."""
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
        "stdout": result.stdout.strip()[:MAX_OUTPUT],
        "stderr": result.stderr.strip()[:MAX_OUTPUT],
    }


def parse_uevent(text: str) -> dict[str, str]:
    """Parse Linux sysfs uevent key/value evidence."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def discover_drm_devices(drm_root: Path = DEFAULT_DRM_ROOT) -> list[dict[str, Any]]:
    """Discover PCI display-class DRM cards and their bound render nodes."""
    devices: list[dict[str, Any]] = []
    for card_path in sorted(drm_root.glob("card[0-9]*")):
        device_path = card_path / "device"
        if not device_path.exists():
            continue
        uevent = parse_uevent(read_text(device_path / "uevent"))
        pci_class = uevent.get("PCI_CLASS", "")
        if not pci_class.startswith("3"):
            continue
        render_root = device_path / "drm"
        render_nodes = (
            sorted(path.name for path in render_root.glob("renderD*"))
            if render_root.exists()
            else []
        )
        devices.append(
            {
                "card": card_path.name,
                "vendor_id": read_text(device_path / "vendor"),
                "device_id": read_text(device_path / "device"),
                "driver": uevent.get("DRIVER"),
                "pci_class": pci_class,
                "pci_id": uevent.get("PCI_ID"),
                "pci_slot": uevent.get("PCI_SLOT_NAME"),
                "render_nodes": render_nodes,
            }
        )
    return devices


def probe_tool(name: str, *args: str) -> dict[str, Any]:
    """Probe one optional API tool without treating installation as success."""
    binary = shutil.which(name)
    if binary is None:
        return {
            "binary": None,
            "available": False,
            "verified": False,
        }
    result = command(binary, *args)
    verified = (
        result.get("available") is True
        and result.get("returncode") == 0
        and bool(str(result.get("stdout", "")).strip())
    )
    return {
        "binary": binary,
        "available": True,
        "verified": verified,
        "result": result,
    }


def collect(drm_root: Path = DEFAULT_DRM_ROOT) -> dict[str, Any]:
    """Collect E05 GPU evidence while retaining a fail-closed claim boundary."""
    devices = discover_drm_devices(drm_root)
    render_nodes = sorted(
        {
            render
            for device in devices
            for render in device.get("render_nodes", [])
            if isinstance(render, str) and render
        }
    )

    compute_probes = {
        "opencl": probe_tool("clinfo", "-l"),
        "rocm": probe_tool("rocminfo"),
        "nvidia_compute": probe_tool(
            "nvidia-smi",
            "--query-gpu=compute_cap",
            "--format=csv,noheader",
        ),
    }
    graphics_probes = {
        "vulkan": probe_tool("vulkaninfo", "--summary"),
        "opengl": probe_tool("glxinfo", "-B"),
    }

    verified_compute = sorted(
        name for name, result in compute_probes.items() if result["verified"]
    )
    verified_graphics = sorted(
        name for name, result in graphics_probes.items() if result["verified"]
    )

    gpu_device_present = bool(devices)
    render_node_present = bool(render_nodes)
    compute_api_evidenced = bool(verified_compute)
    hardware_ready = (
        gpu_device_present and render_node_present and compute_api_evidenced
    )

    blockers: list[str] = []
    if not gpu_device_present:
        blockers.append("gpu_device_not_observed")
    if not render_node_present:
        blockers.append("gpu_render_node_not_observed")
    if not compute_api_evidenced:
        blockers.append("gpu_compute_api_not_verified")

    return {
        "schema_version": "0.1.0",
        "record_type": "ptah.e05.gpu_capability_report",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": {
            "hostname": platform.node(),
            "system": platform.system(),
            "machine": platform.machine(),
            "kernel_release": platform.release(),
        },
        "gpu_devices": devices,
        "gpu_device_present": gpu_device_present,
        "render_nodes": render_nodes,
        "render_node_present": render_node_present,
        "compute_probes": compute_probes,
        "graphics_probes": graphics_probes,
        "verified_compute_backends": verified_compute,
        "verified_graphics_backends": verified_graphics,
        "compute_api_evidenced": compute_api_evidenced,
        "workstation_gpu_hardware_ready": hardware_ready,
        "blockers": blockers,
        "runtime_authorized": False,
        "e05_admission_authorized": False,
        "automatic_upgrade_authorized": False,
        "self_approved": False,
        "claim_boundary": (
            "GPU vendor/model, a loaded kernel driver, or a DRM render node does not by itself "
            "prove GPU compute readiness. workstation_gpu_hardware_ready requires observed GPU "
            "hardware, a render node, and at least one independently successful compute API probe. "
            "Even then this report is evidence only; E05 admission remains a separate policy decision."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-compute", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = collect()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.require_compute and not report["workstation_gpu_hardware_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
