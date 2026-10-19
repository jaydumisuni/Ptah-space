#!/usr/bin/env python3
"""F02/F03 machine-local observation only (no install, probe != admission).

Invoke after Oracle or an authorized agent has already reached the host.
Does NOT establish Ptah enrollment, host profile acceptance or OS readiness.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import time

TOOLS = ("qemu-system-x86_64", "qemu-img", "virsh", "virt-install",
         "systemd-run", "cryptsetup", "podman", "grub-mkrescue", "xorriso")


def snapshot() -> dict:
    """Passive facts only; no unique identifiers, paths, PID, or secrets."""
    system = platform.system()
    report = {
        "schema": "ptah.os-foundation.host-observation/1",
        "evidence_class": "local_unattested_observation",
        "machine_transport_used": "out_of_band_oracle_when_remote",
        "ptah_native_enrollment": "not_inferred",
        "host_accepted": False,
        "phase_f02_accepted": False,
        "phase_f03_accepted": False,
        "os": system.lower(),
        "arch": platform.machine(),
        "kernel": platform.release(),
        "tools": {name: shutil.which(name) is not None for name in TOOLS},
        "kvm": {"present": False, "accessible": False, "cpu_supported": False},
    }
    if system == "Linux":
        kvm = pathlib.Path("/dev/kvm")
        report["kvm"]["present"] = kvm.exists()
        report["kvm"]["accessible"] = os.access(kvm, os.R_OK | os.W_OK)
        try:
            contents=pathlib.Path("/proc/cpuinfo").read_text(encoding="utf-8")
            report["kvm"]["cpu_supported"] = any(
                token in line.split() for line in contents.splitlines()
                if line.startswith("flags") for token in ("vmx","svm")
            )
        except OSError:
            pass
    return report


def bounded_no_boot_smoke(duration_seconds: float = 0.5) -> dict:
    """Opt-in, network-free, small KVM process plus disposable QCOW2 integrity.

    A live process here is NOT successful OS boot, guest isolation certification
    or data recovery. Host services and persistent disk are never touched.
    """
    r = {"requested": True, "no_guest_boot": True, "network": "disabled",
         "host_admission": False, "vm_process_started": False,
         "qcow2_integrity_passed": False, "all_temp_removed": False}
    snap = snapshot()
    if snap["os"] != "linux" or not all(snap["tools"].get(x, False)
                                            for x in ("qemu-system-x86_64", "qemu-img")):
        r["reason"] = "KVM_TOOL_UNAVAILABLE"
        return r
    if not snap["kvm"]["accessible"]:
        r["reason"] = "KVM_NOT_ACCESSIBLE"
        return r
    with tempfile.TemporaryDirectory(prefix="ptah-f03-ephemeral-") as work:
        image = str(pathlib.Path(work) / "probe.qcow2")
        cmd = subprocess.run(["qemu-img", "create", "-f", "qcow2", image, "4M"],
                             capture_output=True, timeout=10, check=False)
        if cmd.returncode != 0:
            r["reason"] = "QCOW2_CREATE_FAILED"
            return r
        check = subprocess.run(["qemu-img", "check", "-f", "qcow2", image],
                               capture_output=True, timeout=10, check=False)
        r["qcow2_integrity_passed"] = check.returncode == 0
        # -S means do not start vCPU; -nodefaults prevents default network.
        child=subprocess.Popen(["qemu-system-x86_64", "-machine", "accel=kvm",
                                 "-S", "-m", "96M", "-nodefaults", "-no-user-config",
                                 "-display", "none", "-monitor", "none", "-serial", "none",
                                 "-no-reboot"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(duration_seconds)
            r["vm_process_started"] = child.poll() is None
        finally:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
    r["all_temp_removed"] = not pathlib.Path(image).exists()
    r["reason"] = ("BOUNDED_SMOKE_ONLY_NOT_ADMISSION" if
                   r["vm_process_started"] and r["qcow2_integrity_passed"]
                   and r["all_temp_removed"] else "SMOKE_FAILED_OR_UNSUPPORTED")
    return r


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bounded-kvm-smoke", action="store_true",
                   help="Create a temporary disk and run a 96 MiB non-booting KVM process")
    args=p.parse_args()
    result=snapshot()
    if args.bounded_kvm_smoke:
        result["optional_smoke"]=bounded_no_boot_smoke()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
