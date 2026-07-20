#!/usr/bin/env python3
"""Collect non-claiming Phase 0C host capability evidence.

The collector records observable host facts and evaluates the requirements in
``host/capability-profile.json``. It never authorizes the Ptah runtime. A report
is proof-eligible only when the observed distribution, release, architecture and
kernel match ``host/image-lock.json`` and every required capability passes.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import tempfile
import termios
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def command(*args: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            list(args), capture_output=True, text=True, timeout=10, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "error": type(exc).__name__}
    return {
        "available": True,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_text(Path("/etc/os-release")).splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def observation(status: str, evidence: Any, message: str = "") -> dict[str, Any]:
    return {"status": status, "evidence": evidence, "message": message}


def check_systemd() -> dict[str, Any]:
    binary = shutil.which("systemctl")
    version = command("systemctl", "--version") if binary else {"available": False}
    pid1 = read_text(Path("/proc/1/comm"))
    ok = bool(binary) and version.get("returncode") == 0 and pid1 == "systemd"
    return observation(
        "pass" if ok else "fail",
        {"binary": binary, "version": version, "pid1_comm": pid1},
        "PID 1 must be systemd on the accepted host image.",
    )


def check_cgroups_v2() -> dict[str, Any]:
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    mountinfo = read_text(Path("/proc/self/mountinfo"))
    ok = controllers.is_file() and " - cgroup2 " in mountinfo
    return observation(
        "pass" if ok else "fail",
        {
            "controllers_path": str(controllers),
            "controllers": read_text(controllers).split(),
            "cgroup2_mount_seen": " - cgroup2 " in mountinfo,
        },
    )


def check_namespace(name: str) -> dict[str, Any]:
    path = Path("/proc/self/ns") / name
    try:
        target = os.readlink(path)
    except OSError as exc:
        return observation("fail", {"path": str(path), "error": str(exc)})
    return observation("pass", {"path": str(path), "target": target})


def check_user_namespace() -> dict[str, Any]:
    base = check_namespace("user")
    maximum = read_text(Path("/proc/sys/user/max_user_namespaces"))
    try:
        enabled = int(maximum) > 0
    except ValueError:
        enabled = False
    ok = base["status"] == "pass" and enabled
    return observation(
        "pass" if ok else "fail",
        {"namespace": base["evidence"], "max_user_namespaces": maximum},
    )


def check_seccomp() -> dict[str, Any]:
    fields: dict[str, str] = {}
    for line in read_text(Path("/proc/self/status")).splitlines():
        if line.startswith(("Seccomp:", "Seccomp_filters:")):
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    return observation("pass" if "Seccomp" in fields else "fail", fields)


def check_overlayfs() -> dict[str, Any]:
    filesystems = read_text(Path("/proc/filesystems")).splitlines()
    present = any(line.split()[-1:] == ["overlay"] for line in filesystems)
    return observation("pass" if present else "fail", {"listed": present})


def check_unix_domain_sockets() -> dict[str, Any]:
    left: socket.socket | None = None
    right: socket.socket | None = None
    try:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        left.sendall(b"ptah")
        received = right.recv(4)
        ok = received == b"ptah"
        return observation("pass" if ok else "fail", {"round_trip": received.decode("ascii")})
    except OSError as exc:
        return observation("fail", {"error": str(exc)})
    finally:
        if left is not None:
            left.close()
        if right is not None:
            right.close()


def check_pty_resize() -> dict[str, Any]:
    master = slave = -1
    try:
        master, slave = os.openpty()
        wanted = (31, 101, 0, 0)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", *wanted))
        observed = struct.unpack("HHHH", fcntl.ioctl(slave, termios.TIOCGWINSZ, b"\0" * 8))
        ok = observed[:2] == wanted[:2]
        return observation(
            "pass" if ok else "fail",
            {"requested_rows_cols": list(wanted[:2]), "observed_rows_cols": list(observed[:2])},
        )
    except OSError as exc:
        return observation("fail", {"error": str(exc)})
    finally:
        for descriptor in (master, slave):
            if descriptor >= 0:
                os.close(descriptor)


def check_fsync() -> dict[str, Any]:
    try:
        with tempfile.TemporaryDirectory(prefix="ptah-host-") as directory:
            path = Path(directory) / "fsync.bin"
            with path.open("wb") as handle:
                handle.write(b"ptah")
                handle.flush()
                os.fsync(handle.fileno())
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return observation("pass", {"file_and_directory_fsync": True})
    except OSError as exc:
        return observation("fail", {"error": str(exc)})


def check_atomic_rename() -> dict[str, Any]:
    try:
        with tempfile.TemporaryDirectory(prefix="ptah-host-") as directory:
            source = Path(directory) / "source"
            target = Path(directory) / "target"
            source.write_bytes(b"before")
            os.replace(source, target)
            ok = not source.exists() and target.read_bytes() == b"before"
        return observation("pass" if ok else "fail", {"os_replace": ok})
    except OSError as exc:
        return observation("fail", {"error": str(exc)})


def check_advisory_locking() -> dict[str, Any]:
    try:
        with tempfile.NamedTemporaryFile(prefix="ptah-host-") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return observation("pass", {"flock_exclusive_nonblocking": True})
    except OSError as exc:
        return observation("fail", {"error": str(exc)})


def check_inotify() -> dict[str, Any]:
    maximum = read_text(Path("/proc/sys/fs/inotify/max_user_watches"))
    try:
        ok = int(maximum) > 0
    except ValueError:
        ok = False
    return observation("pass" if ok else "fail", {"max_user_watches": maximum})


def check_monotonic_clock() -> dict[str, Any]:
    first = time.monotonic_ns()
    time.sleep(0.001)
    second = time.monotonic_ns()
    info = time.get_clock_info("monotonic")
    ok = info.monotonic and second > first
    return observation(
        "pass" if ok else "fail",
        {
            "monotonic": info.monotonic,
            "adjustable": info.adjustable,
            "resolution": info.resolution,
            "advanced": second > first,
        },
    )


def check_offline_schema_resolution() -> dict[str, Any]:
    try:
        lock = read_json(ROOT / "contracts/upstream-lock.json")
    except (OSError, RuntimeError, ValueError) as exc:
        return observation("fail", {"error": str(exc)})
    ok = lock.get("network_resolution_allowed") is False
    return observation(
        "pass" if ok else "fail",
        {
  "lock_status": lock.get("status"),
  "network_resolution_allowed": lock.get("network_resolution_allowed"),
        },
    )


def check_apparmor() -> dict[str, Any]:
    enabled = read_text(Path("/sys/module/apparmor/parameters/enabled"))
    profiles = Path("/sys/kernel/security/apparmor/profiles")
    present = enabled.lower().startswith("y")
    return observation(
        "pass" if present else "limited",
        {"kernel_enabled": enabled, "profiles_path_present": profiles.exists()},
        "A missing AppArmor result must be carried as an explicit reduced-isolation limitation.",
    )


CHECKS: dict[str, Callable[[], dict[str, Any]]] = {
    "systemd": check_systemd,
    "cgroups_v2_unified": check_cgroups_v2,
    "pid_namespace": lambda: check_namespace("pid"),
    "mount_namespace": lambda: check_namespace("mnt"),
    "uts_namespace": lambda: check_namespace("uts"),
    "ipc_namespace": lambda: check_namespace("ipc"),
    "network_namespace": lambda: check_namespace("net"),
    "user_namespace": check_user_namespace,
    "seccomp": check_seccomp,
    "overlayfs": check_overlayfs,
    "unix_domain_sockets": check_unix_domain_sockets,
    "pty_resize": check_pty_resize,
    "fsync": check_fsync,
    "atomic_rename": check_atomic_rename,
    "advisory_locking": check_advisory_locking,
    "inotify": check_inotify,
    "monotonic_clock": check_monotonic_clock,
    "offline_schema_resolution": check_offline_schema_resolution,
    "apparmor": check_apparmor,
}


def pinned_host_match(image_lock: dict[str, Any], release: dict[str, str]) -> dict[str, Any]:
    expected_distribution = str(image_lock.get("distribution", ""))
    expected_release = str(image_lock.get("release", ""))
    expected_architecture = str(image_lock.get("architecture", ""))
    kernel_record = image_lock.get("kernel", {})
    if not isinstance(kernel_record, dict):
        kernel_record = {}
    expected_kernel = str(kernel_record.get("expected_uname_family", ""))

    observed_id = release.get("ID", "")
    observed_name = release.get("NAME", "")
    observed_version_id = release.get("VERSION_ID", "")
    observed_version = release.get("VERSION", "")
    observed_pretty = release.get("PRETTY_NAME", "")
    observed_architecture = platform.machine()
    observed_kernel = platform.release()

    expected_distribution_lower = expected_distribution.lower()
    distribution_match = (
        ("ubuntu" in expected_distribution_lower and observed_id.lower() == "ubuntu")
        or expected_distribution_lower == observed_name.lower()
    )
    expected_point_release = expected_release.split()[0]
    release_match = any(
        expected_point_release in source
        for source in (observed_version, observed_pretty)
    )
    base_release_match = observed_version_id == ".".join(
        expected_point_release.split(".")[:2]
    )
    architecture_aliases = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    architecture_match = architecture_aliases.get(
        expected_architecture.lower(), expected_architecture.lower()
    ) == architecture_aliases.get(
        observed_architecture.lower(), observed_architecture.lower()
    )
    kernel_match = bool(expected_kernel) and observed_kernel.startswith(
        expected_kernel
    )
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


def collect() -> dict[str, Any]:
    profile = read_json(ROOT / "host/capability-profile.json")
    image_lock = read_json(ROOT / "host/image-lock.json")
    release = os_release()
    required = profile.get("required", [])
    conditional_entries = profile.get("conditional", [])
    if not isinstance(required, list) or not isinstance(conditional_entries, list):
        raise RuntimeError("capability profile arrays are invalid")
    conditional = [
        entry.get("capability")
        for entry in conditional_entries
        if isinstance(entry, dict) and isinstance(entry.get("capability"), str)
    ]
    names = [str(name) for name in required] + conditional
    unknown = sorted(set(names) - set(CHECKS))
    if unknown:
        raise RuntimeError(f"collector has no implementation for capabilities: {unknown}")
    observations = {name: CHECKS[name]() for name in names}
    required_failures = [name for name in required if observations[name]["status"] != "pass"]
    conditional_limits = [name for name in conditional if observations[name]["status"] != "pass"]
    host_match = pinned_host_match(image_lock, release)
    proof_eligible = not required_failures and host_match["all_match"]
    return {
        "schema_version": "0.2.0",
        "record_type": "ptah.phase0c.host_capability_report",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "proof_eligible" if proof_eligible else "candidate_host_observed",
        "runtime_implementation_authorized": False,
        "proof_eligible": proof_eligible,
        "host": {
            "hostname": platform.node(),
            "os_release": release,
            "uname": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
            },
            "python": platform.python_version(),
        },
        "pinned_image": image_lock,
        "pinned_host_match": host_match,
        "required_capabilities_passed": not required_failures,
        "required_failures": required_failures,
        "conditional_limitations": conditional_limits,
        "observations": observations,
        "claim_boundary": (
            "This report proves only observed host facts. It does not prove installation from the "
            "pinned ISO unless pinned_host_match.all_match is true, and it never authorizes runtime implementation."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-capabilities", action="store_true")
    parser.add_argument("--require-pinned-host", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = collect()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.require_capabilities and not report["required_capabilities_passed"]:
        return 2
    if args.require_pinned_host and not report["proof_eligible"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
