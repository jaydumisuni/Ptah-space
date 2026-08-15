#!/usr/bin/env python3
"""Create a provider-neutral physical development-host qualification report.

The probe is intentionally cross-platform. It verifies only the portable
mechanical baseline required to begin Ptah runtime development. Deployment-host
isolation, resource enforcement and OS-integration proof are separate later
obligations.

This tool never authorizes runtime implementation or release acceptance.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

RECORD_TYPE = "ptah.phase0c.development_host_probe"
CONTRACT_RECORD_TYPE = "ptah.phase0c.development_host_contract"
DEFAULT_CONTRACT = Path("host/development-host-contract.json")


class ProbeError(RuntimeError):
    """Raised when the development-host probe cannot be produced safely."""


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def command(args: list[str], *, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def observation(status: str, evidence: Any = None, error: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status, "evidence": evidence}
    if error:
        result["error"] = error
    return result


def check_process_spawn() -> dict[str, Any]:
    try:
        result = command([sys.executable, "-c", "print('ptah-development-host')"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return observation("fail", error=f"{type(exc).__name__}: {exc}")
    ok = result.returncode == 0 and result.stdout.strip() == "ptah-development-host"
    return observation(
        "pass" if ok else "fail",
        {
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        },
    )


def check_temporary_workspace() -> dict[str, Any]:
    path: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="ptah-dev-host-") as directory:
            path = Path(directory)
            marker = path / "marker.bin"
            marker.write_bytes(b"ptah")
            ok_inside = marker.read_bytes() == b"ptah"
        ok_cleanup = path is not None and not path.exists()
        return observation(
            "pass" if ok_inside and ok_cleanup else "fail",
            {"write_read": ok_inside, "cleanup": ok_cleanup},
        )
    except OSError as exc:
        return observation("fail", error=f"{type(exc).__name__}: {exc}")


def check_file_fsync() -> dict[str, Any]:
    try:
        with tempfile.TemporaryDirectory(prefix="ptah-dev-host-") as directory:
            path = Path(directory) / "fsync.bin"
            with path.open("wb") as handle:
                handle.write(b"ptah")
                handle.flush()
                os.fsync(handle.fileno())
            ok = path.read_bytes() == b"ptah"
        return observation("pass" if ok else "fail", {"file_fsync": ok})
    except OSError as exc:
        return observation("fail", error=f"{type(exc).__name__}: {exc}")


def check_atomic_replace() -> dict[str, Any]:
    try:
        with tempfile.TemporaryDirectory(prefix="ptah-dev-host-") as directory:
            root = Path(directory)
            source = root / "source.bin"
            target = root / "target.bin"
            source.write_bytes(b"after")
            target.write_bytes(b"before")
            os.replace(source, target)
            ok = not source.exists() and target.read_bytes() == b"after"
        return observation("pass" if ok else "fail", {"atomic_replace": ok})
    except OSError as exc:
        return observation("fail", error=f"{type(exc).__name__}: {exc}")


def check_advisory_file_lock() -> dict[str, Any]:
    try:
        with tempfile.NamedTemporaryFile(prefix="ptah-dev-host-", delete=True) as handle:
            if os.name == "nt":
                import msvcrt

                handle.write(b"x")
                handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                try:
                    locked = True
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                mechanism = "msvcrt.locking"
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    locked = True
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                mechanism = "fcntl.flock"
        return observation("pass" if locked else "fail", {"mechanism": mechanism})
    except (OSError, ImportError) as exc:
        return observation("fail", error=f"{type(exc).__name__}: {exc}")


def check_monotonic_clock() -> dict[str, Any]:
    first = time.monotonic_ns()
    time.sleep(0.002)
    second = time.monotonic_ns()
    info = time.get_clock_info("monotonic")
    ok = bool(info.monotonic) and second > first
    return observation(
        "pass" if ok else "fail",
        {
            "monotonic": info.monotonic,
            "adjustable": info.adjustable,
            "resolution": info.resolution,
            "advanced": second > first,
        },
    )


def check_local_stream_socket() -> dict[str, Any]:
    server: socket.socket | None = None
    client: socket.socket | None = None
    accepted: socket.socket | None = None
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.settimeout(3)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        address = server.getsockname()
        client = socket.create_connection(address, timeout=3)
        accepted, _ = server.accept()
        accepted.settimeout(3)
        client.sendall(b"ptah")
        received = accepted.recv(4)
        accepted.sendall(received)
        echoed = client.recv(4)
        ok = received == b"ptah" and echoed == b"ptah"
        return observation(
            "pass" if ok else "fail",
            {"loopback": "127.0.0.1", "round_trip": ok},
        )
    except OSError as exc:
        return observation("fail", error=f"{type(exc).__name__}: {exc}")
    finally:
        for sock in (accepted, client, server):
            if sock is not None:
                sock.close()


def check_thread_execution() -> dict[str, Any]:
    completed = threading.Event()

    def worker() -> None:
        completed.set()

    thread = threading.Thread(target=worker, name="ptah-development-host-probe")
    thread.start()
    thread.join(timeout=3)
    ok = completed.is_set() and not thread.is_alive()
    return observation("pass" if ok else "fail", {"thread_joined": not thread.is_alive()})


def memory_bytes() -> int | None:
    if os.name == "nt":
        class MemoryStatusEx(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(MemoryStatusEx)
        try:
            ok = bool(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)))
        except (AttributeError, OSError):
            return None
        return int(status.ullTotalPhys) if ok else None

    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        page_count = int(os.sysconf("SC_PHYS_PAGES"))
        total = page_size * page_count
        return total if total > 0 else None
    except (AttributeError, OSError, ValueError):
        return None


def collect_host_observations() -> dict[str, Any]:
    temp_root = Path(tempfile.gettempdir())
    try:
        free_disk = int(shutil.disk_usage(temp_root).free)
    except OSError:
        free_disk = 0
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "kernel": platform.version(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "memory_bytes": memory_bytes(),
        "free_disk_bytes": free_disk,
        "temporary_root": str(temp_root),
    }


def validate_observations(values: dict[str, Any], required: list[str]) -> list[str]:
    failures: list[str] = []
    mapping = {
        "os": values.get("os"),
        "kernel": values.get("kernel"),
        "architecture": values.get("architecture"),
        "cpu_count": values.get("cpu_count"),
        "memory_bytes": values.get("memory_bytes"),
        "free_disk_bytes": values.get("free_disk_bytes"),
    }
    for name in required:
        value = mapping.get(name)
        if isinstance(value, str):
            ok = bool(value.strip())
        elif isinstance(value, int):
            ok = value > 0
        else:
            ok = False
        if not ok:
            failures.append(name)
    return failures


def repository_state(repo_root: Path) -> dict[str, Any]:
    git = shutil.which("git")
    if git is None:
        return {"available": False, "clean": False, "head": None, "status": None}
    try:
        head = command([git, "-C", str(repo_root), "rev-parse", "HEAD"])
        status = command([git, "-C", str(repo_root), "status", "--porcelain=v1", "--untracked-files=all"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "available": False,
            "clean": False,
            "head": None,
            "status": None,
            "error": f"{type(exc).__name__}: {exc}",
        }
    available = head.returncode == 0 and status.returncode == 0
    status_text = status.stdout
    return {
        "available": available,
        "clean": available and not status_text.strip(),
        "head": head.stdout.strip() if head.returncode == 0 else None,
        "status": status_text.splitlines(),
    }


def output_outside_repository(output: Path, repo_root: Path) -> bool:
    try:
        output.resolve().relative_to(repo_root.resolve())
        return False
    except ValueError:
        return True


def load_contract(repo_root: Path, contract_path: Path) -> dict[str, Any]:
    path = contract_path if contract_path.is_absolute() else repo_root / contract_path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProbeError(f"development-host contract is unreadable: {exc}") from exc
    if not isinstance(value, dict) or value.get("record_type") != CONTRACT_RECORD_TYPE:
        raise ProbeError("development-host contract record type is invalid")
    return value


CHECKS: dict[str, Callable[[], dict[str, Any]]] = {
    "process_spawn": check_process_spawn,
    "temporary_workspace": check_temporary_workspace,
    "file_fsync": check_file_fsync,
    "atomic_replace": check_atomic_replace,
    "advisory_file_lock": check_advisory_file_lock,
    "monotonic_clock": check_monotonic_clock,
    "local_stream_socket": check_local_stream_socket,
    "thread_execution": check_thread_execution,
}


def build_report(
    *,
    repo_root: Path,
    contract_path: Path,
    output: Path,
    expected_commit: str | None,
    machine_label: str | None,
    control_transport: str | None,
    transport_receipt_id: str | None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    output = output.resolve()
    contract = load_contract(repo_root, contract_path)

    required = contract.get("required_capabilities")
    required_observations = contract.get("required_observations")
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        raise ProbeError("required_capabilities is invalid")
    if not isinstance(required_observations, list) or not all(
        isinstance(item, str) for item in required_observations
    ):
        raise ProbeError("required_observations is invalid")

    unknown = sorted(set(required) - set(CHECKS))
    if unknown:
        raise ProbeError(f"no probe implementation exists for required capabilities: {unknown}")

    repository_before = repository_state(repo_root)
    observations = collect_host_observations()
    capabilities = {name: CHECKS[name]() for name in required}
    repository_after = repository_state(repo_root)

    capability_failures = [name for name in required if capabilities[name].get("status") != "pass"]
    observation_failures = validate_observations(observations, required_observations)

    binding_failures: list[str] = []
    if not repository_before.get("available") or not repository_after.get("available"):
        binding_failures.append("repository_unavailable")
    if not repository_before.get("clean"):
        binding_failures.append("repository_not_clean_before")
    if not repository_after.get("clean"):
        binding_failures.append("repository_not_clean_after")
    if repository_before.get("head") != repository_after.get("head"):
        binding_failures.append("repository_head_changed_during_probe")
    if expected_commit:
        if repository_before.get("head") != expected_commit:
            binding_failures.append("expected_commit_mismatch_before")
        if repository_after.get("head") != expected_commit:
            binding_failures.append("expected_commit_mismatch_after")
        if not output_outside_repository(output, repo_root):
            binding_failures.append("physical_proof_output_must_be_outside_repository")

    eligibility_failures = [f"capability:{name}" for name in capability_failures]
    eligibility_failures.extend(f"observation:{name}" for name in observation_failures)
    eligibility_failures.extend(f"repository:{name}" for name in binding_failures)

    eligible = not eligibility_failures
    return {
        "schema_version": "0.1.0",
        "record_type": RECORD_TYPE,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "development_host_eligible" if eligible else "development_host_not_eligible",
        "development_host_eligible": eligible,
        "runtime_implementation_authorized": False,
        "deployment_host_qualified": False,
        "release_accepted": False,
        "machine_label": machine_label,
        "host_observations": observations,
        "required_capabilities": required,
        "capabilities": capabilities,
        "capability_failures": capability_failures,
        "required_observations": required_observations,
        "observation_failures": observation_failures,
        "repository_binding": {
            "repo_root": str(repo_root),
            "expected_commit": expected_commit,
            "before": repository_before,
            "after": repository_after,
            "failures": binding_failures,
        },
        "control_plane_observation": {
            "transport": control_transport,
            "external_receipt_id": transport_receipt_id,
            "caller_supplied_metadata_only": True,
            "private_acceptance_must_review_external_receipt": True,
        },
        "eligibility_failures": eligibility_failures,
        "deferred_deployment_capabilities": contract.get("deferred_deployment_capabilities", []),
        "claim_boundary": {
            "development_host_eligible_is_only_a_mechanical_probe_result": True,
            "external_control_plane_receipt_is_reviewed_separately": True,
            "runtime_implementation_authorized": False,
            "deployment_host_qualified": False,
            "release_accepted": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument("--machine-label")
    parser.add_argument("--control-transport")
    parser.add_argument("--transport-receipt-id")
    parser.add_argument("--require-eligible", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        repo_root=args.repo_root,
        contract_path=args.contract,
        output=args.output,
        expected_commit=args.expected_commit,
        machine_label=args.machine_label,
        control_transport=args.control_transport,
        transport_receipt_id=args.transport_receipt_id,
    )
    write_json(args.output.resolve(), report)
    print(json.dumps({
        "status": report["status"],
        "development_host_eligible": report["development_host_eligible"],
        "eligibility_failures": report["eligibility_failures"],
        "output": str(args.output.resolve()),
    }, indent=2))
    if args.require_eligible and not report["development_host_eligible"]:
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as exc:
        print(f"DEVELOPMENT_HOST_PROBE_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
