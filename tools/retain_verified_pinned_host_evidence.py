#!/usr/bin/env python3
"""Bind, verify and durably retain a physical pinned-host proof candidate.

This is the operator entry point for durable retention. It combines the
independent cross-record verifier with a clean exact-repository binding and
collector-byte checks before and after retention. The produced review record
remains pending and non-authorizing.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

HELPER_PATH = Path(__file__).with_name("prepare_durable_pinned_host_evidence.py")
SPEC = importlib.util.spec_from_file_location(
    "prepare_durable_pinned_host_evidence", HELPER_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load durable pinned-host retention helper")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class BindingError(RuntimeError):
    """Raised when durable evidence is not bound to the reviewed repository."""


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run one command without a shell and optionally fail closed."""
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise BindingError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{(result.stderr or result.stdout).strip()}"
        )
    return result


def require(condition: bool, message: str) -> None:
    """Raise one repository-binding failure."""
    if not condition:
        raise BindingError(message)


def relative_lane(repo_root: Path, path: Path, label: str) -> str:
    """Return one non-root path relative to the repository."""
    try:
        relative = path.relative_to(repo_root)
    except ValueError as exc:
        raise BindingError(f"{label} must be inside the repository") from exc
    require(relative.parts, f"{label} cannot be the repository root")
    return relative.as_posix().rstrip("/")


def validate_paths(
    repo_root: Path, bundle_dir: Path, output_dir: Path
) -> tuple[str, str]:
    """Reject symlink, nesting and overwrite ambiguities."""
    require(repo_root.is_dir() and not repo_root.is_symlink(), "repository root is invalid")
    require(bundle_dir.is_dir() and not bundle_dir.is_symlink(), "source bundle directory is invalid")
    bundle_relative = relative_lane(repo_root, bundle_dir, "source bundle directory")
    output_relative = relative_lane(repo_root, output_dir, "durable output directory")
    require(
        bundle_dir not in output_dir.parents and output_dir not in bundle_dir.parents,
        "source and durable output directories cannot contain one another",
    )
    for entry in bundle_dir.iterdir():
        require(not entry.is_symlink(), f"source bundle contains a symlink: {entry.name}")
    if output_dir.exists():
        require(output_dir.is_dir() and not output_dir.is_symlink(), "durable output path is invalid")
        require(not any(output_dir.iterdir()), f"durable output directory is not empty: {output_dir}")
    return bundle_relative, output_relative


def repository_state(
    repo_root: Path, allowed_untracked_lanes: tuple[str, ...]
) -> dict[str, Any]:
    """Capture tracked, staged and unexpected untracked repository state."""
    worktree_dirty = run(
        ["git", "-C", str(repo_root), "diff", "--quiet"], check=False
    ).returncode != 0
    index_dirty = run(
        ["git", "-C", str(repo_root), "diff", "--cached", "--quiet"],
        check=False,
    ).returncode != 0
    untracked_result = run(
        [
            "git",
            "-C",
            str(repo_root),
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ]
    )
    untracked = [item for item in untracked_result.stdout.split("\0") if item]
    unexpected = [
        item
        for item in untracked
        if not any(
            item == lane or item.startswith(lane + "/")
            for lane in allowed_untracked_lanes
        )
    ]
    return {
        "worktree_dirty": worktree_dirty,
        "index_dirty": index_dirty,
        "unexpected_untracked": sorted(unexpected),
        "dirty": worktree_dirty or index_dirty or bool(unexpected),
    }


def validate_repository_binding(
    repo_root: Path,
    bundle_dir: Path,
    output_dir: Path,
    verification: dict[str, Any],
) -> dict[str, Any]:
    """Bind one internally valid bundle to exact reviewed repository bytes."""
    bundle_relative, output_relative = validate_paths(repo_root, bundle_dir, output_dir)
    commit = run(["git", "-C", str(repo_root), "rev-parse", "HEAD"]).stdout.strip()
    require(
        commit == verification["implementation_commit"],
        "current repository HEAD does not match the source bundle implementation commit",
    )
    state = repository_state(repo_root, (bundle_relative, output_relative))
    require(not state["dirty"], f"repository binding is dirty: {state}")

    records = verification.get("records")
    require(isinstance(records, dict), "verified source records are unavailable")
    manifest = records.get("bundle-manifest.json")
    apt_sources = records.get("apt-sources.json")
    require(isinstance(manifest, dict), "verified bundle manifest is unavailable")
    require(isinstance(apt_sources, dict), "verified APT source manifest is unavailable")
    sources = apt_sources.get("sources")
    require(isinstance(sources, list) and bool(sources), "APT source manifest is empty")

    capability_collector = repo_root / "host" / "scripts" / "collect_capabilities.py"
    package_collector = repo_root / "tools" / "collect_apt_package_artifacts.py"
    proof_runner = repo_root / "tools" / "run_pinned_host_proof.py"
    for path in (capability_collector, package_collector, proof_runner):
        require(path.is_file() and not path.is_symlink(), f"reviewed proof tool is missing or a symlink: {path}")

    capability_binding = manifest.get("capability_report")
    package_binding = manifest.get("package_artifact_report")
    require(isinstance(capability_binding, dict), "capability collector binding is missing")
    require(isinstance(package_binding, dict), "package artifact collector binding is missing")
    require(
        capability_binding.get("collector_sha256")
        == HELPER.sha256_file(capability_collector),
        "capability collector bytes do not match the source bundle binding",
    )
    require(
        package_binding.get("collector_sha256")
        == HELPER.sha256_file(package_collector),
        "package artifact collector bytes do not match the source bundle binding",
    )
    return {
        "implementation_commit": commit,
        "repository_state": state,
        "bundle_relative": bundle_relative,
        "output_relative": output_relative,
        "capability_collector_sha256": HELPER.sha256_file(capability_collector),
        "package_artifact_collector_sha256": HELPER.sha256_file(package_collector),
        "proof_runner_sha256": HELPER.sha256_file(proof_runner),
    }


def retain_verified(
    repo_root: Path, bundle_dir: Path, output_dir: Path
) -> dict[str, Any]:
    """Perform internal verification, repository binding and durable retention."""
    repo_root = repo_root.resolve()
    bundle_dir = bundle_dir.resolve()
    output_dir = output_dir.resolve()
    verification = HELPER.verify_bundle(bundle_dir)
    before = validate_repository_binding(
        repo_root, bundle_dir, output_dir, verification
    )
    retained = HELPER.prepare_retention(bundle_dir, output_dir)
    after = validate_repository_binding(repo_root, bundle_dir, output_dir, verification)
    require(
        before["implementation_commit"] == after["implementation_commit"],
        "repository HEAD changed during durable retention",
    )
    binding = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.durable_pinned_host_repository_binding",
        "implementation_commit": before["implementation_commit"],
        "source_bundle_sha256": retained["source_bundle_sha256"],
        "durable_bundle_file_sha256": retained["durable_bundle_file_sha256"],
        "retained_files_sha256": retained["retained_files_sha256"],
        "repository_state_before": before["repository_state"],
        "repository_state_after": after["repository_state"],
        "capability_collector_sha256": before["capability_collector_sha256"],
        "package_artifact_collector_sha256": before[
            "package_artifact_collector_sha256"
        ],
        "proof_runner_sha256": before["proof_runner_sha256"],
        "review_status": "pending",
        "runtime_implementation_authorized": False,
    }
    binding_path = output_dir / "repository-binding.json"
    HELPER.write_json(binding_path, binding)
    return {
        **retained,
        "repository_binding_file_sha256": HELPER.sha256_file(binding_path),
        "repository_binding_verified": True,
        "review_status": "pending",
        "runtime_implementation_authorized": False,
    }


def main() -> int:
    """Run exact repository-bound durable retention."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = retain_verified(args.repo_root, args.bundle_dir, args.output_dir)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BindingError, HELPER.RetentionError) as exc:
        print(f"VERIFIED_PINNED_HOST_RETENTION_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
