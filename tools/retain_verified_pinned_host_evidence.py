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

EXPECTED_OUTPUT_FILES = {
    "README.md",
    "durable-pinned-host-bundle.json",
    "pinned-host-review-record.json",
    "repository-binding.json",
}


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
    repo_root: Path,
    bundle_dir: Path,
    output_dir: Path,
    *,
    allow_populated_output: bool,
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
        if not allow_populated_output:
            require(not any(output_dir.iterdir()), f"durable output directory is not empty: {output_dir}")
    elif allow_populated_output:
        raise BindingError("durable output directory disappeared during retention")
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
    *,
    allow_populated_output: bool,
) -> dict[str, Any]:
    """Bind one internally valid bundle to exact reviewed repository bytes."""
    bundle_relative, output_relative = validate_paths(
        repo_root,
        bundle_dir,
        output_dir,
        allow_populated_output=allow_populated_output,
    )
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


def validate_final_output(output_dir: Path) -> dict[str, str]:
    """Require the exact final durable output set and pending boundaries."""
    require(output_dir.is_dir() and not output_dir.is_symlink(), "final durable output directory is invalid")
    entries = list(output_dir.iterdir())
    require(not any(entry.is_symlink() for entry in entries), "final durable output contains a symlink")
    require(not any(entry.is_dir() for entry in entries), "final durable output contains a subdirectory")
    present = {entry.name for entry in entries if entry.is_file()}
    require(
        present == EXPECTED_OUTPUT_FILES,
        f"final durable output set mismatch: expected {sorted(EXPECTED_OUTPUT_FILES)}, got {sorted(present)}",
    )
    durable = HELPER.load_json(output_dir / "durable-pinned-host-bundle.json")
    review = HELPER.load_json(output_dir / "pinned-host-review-record.json")
    binding = HELPER.load_json(output_dir / "repository-binding.json")
    require(
        durable.get("retention_status") == "durable_candidate_pending_review",
        "durable bundle is not pending review",
    )
    require(durable.get("proof_eligible_source_verified") is True, "durable bundle did not retain a verified source")
    require(review.get("review_status") == "pending", "review record is not pending")
    for field in (
        "physical_host_identity_accepted",
        "installed_package_manifest_accepted",
        "package_artifact_manifest_accepted",
        "durable_retention_accepted",
        "adr0033_accepted",
        "runtime_implementation_authorized",
    ):
        require(review.get(field) is False, f"review field must remain false: {field}")
    require(binding.get("review_status") == "pending", "repository binding is not pending review")
    require(
        binding.get("runtime_implementation_authorized") is False,
        "repository binding authorizes runtime implementation",
    )
    return {
        "durable_bundle_file_sha256": HELPER.sha256_file(
            output_dir / "durable-pinned-host-bundle.json"
        ),
        "review_record_file_sha256": HELPER.sha256_file(
            output_dir / "pinned-host-review-record.json"
        ),
        "repository_binding_file_sha256": HELPER.sha256_file(
            output_dir / "repository-binding.json"
        ),
        "readme_file_sha256": HELPER.sha256_file(output_dir / "README.md"),
    }


def retain_verified(
    repo_root: Path, bundle_dir: Path, output_dir: Path
) -> dict[str, Any]:
    """Perform internal verification, repository binding and durable retention."""
    raw_repo_root = Path(repo_root)
    raw_bundle_dir = Path(bundle_dir)
    raw_output_dir = Path(output_dir)
    require(not raw_repo_root.is_symlink(), "repository root cannot be a symlink")
    require(not raw_bundle_dir.is_symlink(), "source bundle directory cannot be a symlink")
    if raw_output_dir.exists():
        require(not raw_output_dir.is_symlink(), "durable output directory cannot be a symlink")

    repo_root = raw_repo_root.resolve()
    bundle_dir = raw_bundle_dir.resolve()
    output_dir = raw_output_dir.resolve()
    verification = HELPER.verify_bundle(bundle_dir)
    before = validate_repository_binding(
        repo_root,
        bundle_dir,
        output_dir,
        verification,
        allow_populated_output=False,
    )
    retained = HELPER.prepare_retention(bundle_dir, output_dir)
    after = validate_repository_binding(
        repo_root,
        bundle_dir,
        output_dir,
        verification,
        allow_populated_output=True,
    )
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
    final_hashes = validate_final_output(output_dir)
    final_state = repository_state(
        repo_root, (before["bundle_relative"], before["output_relative"])
    )
    require(not final_state["dirty"], f"repository changed after durable retention: {final_state}")
    final_commit = run(["git", "-C", str(repo_root), "rev-parse", "HEAD"]).stdout.strip()
    require(final_commit == before["implementation_commit"], "repository HEAD changed after durable retention")
    return {
        **retained,
        **final_hashes,
        "repository_binding_verified": True,
        "final_repository_state": final_state,
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
