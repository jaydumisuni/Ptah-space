#!/usr/bin/env python3
"""F03 disposable COW guest interruption and clean rollback proof.

Requires explicit --run. One vCPU, 128 MiB, no network, no host partitions.
A process SIGKILL is *not* a physical power interruption. An acknowledged
guest write may be absent after crash; it is *never* trusted or replayed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

SCHEMA = "ptah.f03.cow-interruption/1"
ACK = "PTAH_F03_GUEST_DISK_WRITE_OK\n"
NAK = "PTAH_F03_GUEST_DISK_WRITE_FAILED\n"
PAYLOAD = b"PTAHF03WRITE"
SIZE = 1048576
SECTOR = 512
TOOLS = ("as", "ld", "qemu-img", "qemu-system-x86_64")


class F03RecoveryError(ValueError):
    pass


def require(value: bool, code: str) -> None:
    if not value:
        raise F03RecoveryError(code)


def host() -> dict:
    return {
        "schema": SCHEMA,
        "tooling": {name: shutil.which(name) is not None for name in TOOLS},
        "kvm_accessible": Path("/dev/kvm").exists()
        and os.access("/dev/kvm", os.R_OK | os.W_OK),
        "execution_requested": False,
        "guest_os_qualified": False,
        "physical_power_loss_tested": False,
        "e01_e05_enrolled": False,
        "prime_os_integrated": False,
        "phase_accepted": False,
    }


def asm() -> str:
    lines = [
        ".code16", ".global _start", "_start:", "cli",
        "xorw %ax,%ax", "movw %ax,%ds", "movw %ax,%es",
        "movw %ax,%ss", "movw $0x7c00,%sp", "movw $0x7e00,%bx",
    ]
    for index, byte in enumerate(PAYLOAD):
        lines.append("movb $" + str(byte) + ", %es:" + str(index) + "(%bx)")
    lines += [
        "movb $0x03,%ah", "movb $0x01,%al", "movb $0,%ch",
        "movb $2,%cl", "movb $0,%dh", "movb $0x80,%dl",
        "int $0x13", "jc failed",
    ]
    for byte in ACK.encode("ascii"):
        lines += ["movb $" + str(byte) + ",%al", "outb %al,$0xe9"]
    lines += ["jmp halted", "failed:"]
    for byte in NAK.encode("ascii"):
        lines += ["movb $" + str(byte) + ",%al", "outb %al,$0xe9"]
    lines += ["halted:", "hlt", "jmp halted", ".org 510", ".word 0xaa55"]
    return "\n".join(lines) + "\n"


def invoke(args: list[str], timeout: int = 12) -> None:
    try:
        child = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise F03RecoveryError("TOOL_LAUNCH_OR_TIMEOUT") from exc
    require(child.returncode == 0, "TOOL_COMMAND_FAILED")


def overlay_from(base: Path, dest: Path) -> None:
    require(not dest.exists(), "OVERLAY_ALREADY_EXISTS")
    invoke(["qemu-img", "create", "-f", "qcow2", "-F", "raw",
            "-b", str(base), str(dest)])


def qemu_command(disk: Path, trace: Path) -> list[str]:
    return [
        "qemu-system-x86_64", "-machine", "pc,accel=kvm",
        "-cpu", "host", "-smp", "1", "-m", "128M",
        "-display", "none", "-serial", "none", "-monitor", "none",
        "-net", "none", "-drive", "file=" + str(disk) +
        ",format=qcow2,if=ide,cache=none",
        "-boot", "order=c",
        "-device", "isa-debugcon,iobase=0xe9,chardev=trace",
        "-chardev", "file,id=trace,path=" + str(trace),
        "-no-reboot",
    ]


def kill_after_ack(disk: Path, trace: Path, seconds: int) -> dict:
    require(3 <= seconds <= 15, "INVALID_TIMEOUT")
    child = None
    found = False
    try:
        child = subprocess.Popen(
            qemu_command(disk, trace),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if trace.exists():
                value = trace.read_text(errors="replace")
                require(NAK not in value, "GUEST_BIOS_WRITE_FAILED")
                if ACK in value:
                    found = True
                    break
            require(child.poll() is None, "QEMU_EXITED_BEFORE_ACK")
            time.sleep(0.05)
        require(found, "ACK_TIMEOUT")
        require(child.poll() is None, "QEMU_EXITED_BEFORE_KILL")
        child.kill()
        child.wait(timeout=5)
        return {"guest_acknowledged": True, "qemu_sigkill_injected": True}
    except OSError as exc:
        raise F03RecoveryError("QEMU_SPAWN_OR_IO_FAILED") from exc
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Never release control with the created child still live.
                raise F03RecoveryError("QEMU_DID_NOT_EXIT") from None


def converted(overlay: Path, dest: Path) -> bytes:
    invoke(["qemu-img", "convert", "-f", "qcow2", "-O", "raw",
            str(overlay), str(dest)])
    data = dest.read_bytes()
    require(len(data) == SIZE, "WRONG_DISK_SIZE")
    return data


def run(seconds: int = 8) -> dict:
    require(3 <= seconds <= 15, "INVALID_TIMEOUT")
    result = host()
    require(all(result["tooling"].values()), "TOOLS_UNAVAILABLE")
    require(result["kvm_accessible"], "KVM_UNAVAILABLE")
    result["execution_requested"] = True
    with tempfile.TemporaryDirectory(prefix="ptah-f03-cow-recovery-") as directory:
        work = Path(directory)
        source = work / "guest.s"
        obj = work / "guest.o"
        sector = work / "boot.bin"
        source.write_text(asm(), encoding="ascii")
        invoke(["as", "--32", "-o", str(obj), str(source)])
        invoke(["ld", "-m", "elf_i386", "-Ttext", "0x7c00",
                "--oformat", "binary", "-e", "_start",
                "-o", str(sector), str(obj)])
        raw_sector = sector.read_bytes()
        require(len(raw_sector) == SECTOR and raw_sector[-2:] == b"\x55\xaa",
                "INVALID_BOOT_SECTOR")
        base = work / "base.raw"
        original = raw_sector + b"\x00" * (SIZE - SECTOR)
        base.write_bytes(original)
        checksum = hashlib.sha256(original).hexdigest()
        crash = work / "crashed.qcow2"
        overlay_from(base, crash)
        first = kill_after_ack(crash, work / "first.marker", seconds)
        # A successful BIOS write call is NOT a durable commit receipt.
        # A process crash may leave the overlay unmodified or unreadable.
        try:
            observed = converted(crash, work / "after-crash.raw")
            before_recovery = (
                "effect_observed_not_authorized"
                if observed[SECTOR:SECTOR + len(PAYLOAD)] == PAYLOAD
                else "effect_missing_or_incomplete"
            )
        except F03RecoveryError:
            before_recovery = "overlay_unreadable"
        require(hashlib.sha256(base.read_bytes()).hexdigest() == checksum,
                "BASE_CHANGED_AFTER_INTERRUPTION")
        # Never replay or trust the uncertain operation. Discard the
        # crashed overlay; rebuild the exact clean state from verified base.
        crash.unlink()
        clean = work / "restored.qcow2"
        overlay_from(base, clean)
        exact = converted(clean, work / "restored.raw")
        require(exact == original, "ROLLBACK_BASE_MISMATCH")
        # Fresh guest must still execute from the clean base after recovery.
        second = kill_after_ack(clean, work / "second.marker", seconds)
        require(hashlib.sha256(base.read_bytes()).hexdigest() == checksum,
                "BASE_CHANGED_AFTER_RESTART")
        result.update({
            "first_boot": first,
            "second_boot_after_rollback": second,
            "post_crash_write_evidence": before_recovery,
            "post_crash_write_authoritative": False,
            "uncertain_prior_write_replayed": False,
            "base_sha256": "sha256:" + checksum,
            "base_byte_identical_after_crash_and_restart": True,
            "clean_overlay_restored_exact_base": True,
            "network": "disabled", "guest_vcpus": 1, "guest_ram_mib": 128,
            "guest_disk_bytes": SIZE,
            "status": "PROCESS_CRASH_COW_RECOVERY_PROVEN_NOT_ADMITTED",
        })
    result["temp_files_removed"] = True
    return result


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", action="store_true")
    p.add_argument("--timeout-seconds", type=int, default=8)
    args = p.parse_args()
    try:
        require(3 <= args.timeout_seconds <= 15, "INVALID_TIMEOUT")
        print(json.dumps(run(args.timeout_seconds) if args.run else host(),
                         sort_keys=True, indent=2))
        return 0
    except (F03RecoveryError, OSError, subprocess.TimeoutExpired) as exc:
        print("F03_COW_RECOVERY_REJECTED:" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
