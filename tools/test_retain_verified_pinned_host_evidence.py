from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).parent


def load(name: str, filename: str):
    path = TOOLS / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WRAPPER = load(
    "retain_verified_pinned_host_evidence",
    "retain_verified_pinned_host_evidence.py",
)
BASE_TEST = load(
    "test_prepare_durable_pinned_host_evidence_support",
    "test_prepare_durable_pinned_host_evidence.py",
)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def patch_manifest_file_record(source: Path, name: str) -> None:
    manifest_path = source / "bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    path = source / name
    for item in manifest["files"]:
        if item["path"] == name:
            item["sha256"] = WRAPPER.HELPER.sha256_file(path)
            item["size_bytes"] = path.stat().st_size
            break
    manifest["bundle_sha256"] = WRAPPER.HELPER.canonical_sha256(manifest["files"])
    write_json(manifest_path, manifest)


def make_repository(root: Path):
    repo = root / "repo"
    repo.mkdir()
    capability = repo / "host" / "scripts" / "collect_capabilities.py"
    package = repo / "tools" / "collect_apt_package_artifacts.py"
    runner = repo / "tools" / "run_pinned_host_proof.py"
    capability.parent.mkdir(parents=True)
    package.parent.mkdir(parents=True)
    capability.write_text("# canonical capability collector\n", encoding="utf-8")
    package.write_text("# canonical package collector\n", encoding="utf-8")
    runner.write_text("# canonical proof runner\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    git(repo, "config", "user.name", "Ptah Test")
    git(repo, "config", "user.email", "ptah@example.invalid")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "reviewed proof tools")
    commit = git(repo, "rev-parse", "HEAD")

    source = repo / "evidence" / "phase0c" / "pinned-host-candidate"
    output = repo / "evidence" / "phase0c" / "pinned-host-durable-candidate"
    source.mkdir(parents=True)
    BASE_TEST.make_bundle(source)
    manifest_path = source / "bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["implementation_commit"] = commit
    manifest["repository_commit_after_collection"] = commit
    manifest["capability_report"]["collector_sha256"] = WRAPPER.HELPER.sha256_file(
        capability
    )
    manifest["package_artifact_report"][
        "collector_sha256"
    ] = WRAPPER.HELPER.sha256_file(package)
    write_json(manifest_path, manifest)
    return repo, source, output, commit


class VerifiedPinnedHostRetentionTests(unittest.TestCase):
    def test_valid_repository_bound_candidate_is_retained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, source, output, commit = make_repository(Path(directory))
            result = WRAPPER.retain_verified(repo, source, output)
            self.assertEqual(result["implementation_commit"], commit)
            self.assertTrue(result["repository_binding_verified"])
            self.assertEqual(result["review_status"], "pending")
            binding = json.loads(
                (output / "repository-binding.json").read_text(encoding="utf-8")
            )
            self.assertEqual(binding["implementation_commit"], commit)
            self.assertEqual(binding["review_status"], "pending")
            self.assertFalse(binding["runtime_implementation_authorized"])

    def test_bundle_commit_must_match_current_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, source, output, _ = make_repository(Path(directory))
            manifest_path = source / "bundle-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["implementation_commit"] = "9" * 40
            manifest["repository_commit_after_collection"] = "9" * 40
            write_json(manifest_path, manifest)
            with self.assertRaisesRegex(WRAPPER.BindingError, "HEAD does not match"):
                WRAPPER.retain_verified(repo, source, output)

    def test_collector_bytes_must_match_bundle_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, source, output, _ = make_repository(Path(directory))
            manifest_path = source / "bundle-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["capability_report"]["collector_sha256"] = "0" * 64
            write_json(manifest_path, manifest)
            with self.assertRaisesRegex(
                WRAPPER.BindingError, "capability collector bytes"
            ):
                WRAPPER.retain_verified(repo, source, output)

    def test_unexpected_untracked_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, source, output, _ = make_repository(Path(directory))
            (repo / "unexpected.txt").write_text("not evidence\n", encoding="utf-8")
            with self.assertRaisesRegex(WRAPPER.BindingError, "binding is dirty"):
                WRAPPER.retain_verified(repo, source, output)

    def test_source_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, source, output, _ = make_repository(Path(directory))
            source_path = source / "apt-sources.json"
            external = repo / "evidence" / "apt-sources-copy.json"
            external.write_bytes(source_path.read_bytes())
            source_path.unlink()
            os.symlink(external, source_path)
            with self.assertRaisesRegex(WRAPPER.BindingError, "contains a symlink"):
                WRAPPER.retain_verified(repo, source, output)

    def test_nested_output_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, source, _, _ = make_repository(Path(directory))
            output = source / "durable"
            with self.assertRaisesRegex(WRAPPER.BindingError, "cannot contain"):
                WRAPPER.retain_verified(repo, source, output)

    def test_empty_apt_source_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, source, output, _ = make_repository(Path(directory))
            path = source / "apt-sources.json"
            record = json.loads(path.read_text())
            record["sources"] = []
            record["sources_sha256"] = WRAPPER.HELPER.canonical_sha256([])
            write_json(path, record)
            patch_manifest_file_record(source, "apt-sources.json")
            with self.assertRaisesRegex(WRAPPER.BindingError, "APT source manifest is empty"):
                WRAPPER.retain_verified(repo, source, output)


if __name__ == "__main__":
    unittest.main()
