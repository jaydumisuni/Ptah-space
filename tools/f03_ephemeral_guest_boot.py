#!/usr/bin/env python3
"""Optional bounded F03 x86/KVM guest boot proof, not a Linux OS or VM release.

Creates a tiny 16-bit x86 guest BIOS boot sector in a disposable directory,
runs guest instructions in QEMU/KVM without network, checks a guest debugport
marker, verifies the guest disk is unchanged, and cleans every file. This does
NOT install services, use Oracle as a Ptah-native channel, or certify recovery.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

MARKER = "PTAH_F03_BIOS_GUEST_BOOT_OK\n"
PROOF_SCHEMA = "ptah.f03.ephemeral-guest-boot/1"


class F03Error(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise F03Error(reason)


def assembly() -> str:
    """Hardcoded 16-bit guest payload, never user-derived shell code."""
    lines = [
        ".code16", ".global _start", "_start:", "cli",
        "xorw %ax,%ax", "movw %ax,%ds", "movw %ax,%ss",
        "movw $0x7c00,%sp",
    ]
    for char in MARKER:
        lines += ["movb $" + str(ord(char)) + ", %al", "outb %al, $0xe9"]
    lines += ["movb $0, %al", "outb %al, $0xf4",
              "halt:", "hlt", "jmp halt", ".org 510", ".word 0xaa55"]
    return "\n".join(lines) + "\n"


def boot_command(disk: Path, guest_output: Path) -> list[str]:
    """Fixed maximum CPU, RAM, disk and network profile."""
    return [
        "qemu-system-x86_64", "-machine", "pc,accel=kvm",
        "-cpu", "host", "-smp", "1", "-m", "128M",
        "-display", "none", "-serial", "none", "-monitor", "none",
        "-net", "none", "-drive", f"file={disk},format=raw,if=ide",
        "-boot", "order=c",
        "-device", "isa-debugcon,iobase=0xe9,chardev=proof",
        "-chardev", f"file,id=proof,path={guest_output}",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
        "-no-reboot",
    ]


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True, timeout=timeout, check=False)


def inspect_host() -> dict:
    tools = ("as", "ld", "qemu-system-x86_64")
    return {
        "schema": PROOF_SCHEMA,
        "required_tools": {item: shutil.which(item) is not None for item in tools},
        "kvm_accessible": Path("/dev/kvm").exists()
        and os.access("/dev/kvm", os.R_OK | os.W_OK),
        "guest_os_booted": False,
        "guest_data_recovered": False,
        "native_ptah_admitted": False,
        "prime_os_integrated": False,
        "execution_requested": False,
    }


def proof(max_seconds: int = 12) -> dict:
    require(3 <= max_seconds <= 20, "INVALID_TIME_BUDGET")
    report = inspect_host()
    report["execution_requested"] = True
    require(all(report["required_tools"].values()), "REQUIRED_EXECUTABLE_MISSING")
    require(report["kvm_accessible"], "KVM_NOT_ACCESSIBLE")
    try:
        with tempfile.TemporaryDirectory(prefix="ptah-f03-ephemeral-") as directory:
            work = Path(directory)
            source = work / "boot.s"
            object_file = work / "boot.o"
            disk = work / "boot.bin"
            marker_file = work / "guest-marker.txt"
            source.write_text(assembly(), encoding="ascii")
            assemble = _run(["as", "--32", "-o", str(object_file), str(source)], 10)
            require(assemble.returncode == 0, "ASSEMBLY_FAILED")
            link = _run([
                "ld", "-m", "elf_i386", "-Ttext", "0x7c00",
                "--oformat", "binary", "-e", "_start",
                "-o", str(disk), str(object_file),
            ], 10)
            require(link.returncode == 0, "BOOTSECTOR_LINK_FAILED")
            first = disk.read_bytes()
            require(len(first) == 512 and first[-2:] == b"\x55\xaa",
                    "INVALID_BOOT_SECTOR")
            digest_before = hashlib.sha256(first).hexdigest()
            try:
                guest = _run(boot_command(disk, marker_file), max_seconds)
            except subprocess.TimeoutExpired as exc:
                raise F03Error("GUEST_EXECUTION_TIMEOUT") from exc
            require(guest.returncode == 1, "GUEST_DID_NOT_SIGNAL_DEBUG_EXIT")
            require(marker_file.is_file() and marker_file.read_text() == MARKER,
                    "GUEST_MARKER_MISSING_OR_ALTERED")
            require(hashlib.sha256(disk.read_bytes()).hexdigest() == digest_before,
                    "GUEST_DISK_MUTATED")
            report["guest_boot_sector_executed"] = True
            report["guest_marker_sha256"] = hashlib.sha256(
                MARKER.encode("ascii")).hexdigest()
            report["guest_disk_unchanged"] = True
            report["guest_bootsector_bytes"] = len(first)
            report["network"] = "none"
            report["guest_ram_mib"] = 128
            report["guest_vcpu"] = 1
        report["temporary_files_removed"] = True
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise F03Error("HOST_OR_TOOL_FAILURE") from exc
    report["f03_phase_accepted"] = False
    report["status"] = "BOUNDED_GUEST_BOOT_ONLY_NOT_ADMITTED"
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", action="store_true",
                   help="Explicitly start one temporary KVM guest (128 MiB, no network)")
    p.add_argument("--max-seconds", type=int, default=12)
    args = p.parse_args()
    try:
        require(3 <= args.max_seconds <= 20, "INVALID_TIME_BUDGET")
        result = proof(args.max_seconds) if args.run else inspect_host()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except F03Error as exc:
        print("F03_REJECTED:" + str(exc), file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
