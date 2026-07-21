from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("prepare_durable_pinned_host_evidence.py")
SPEC = importlib.util.spec_from_file_location(
    "prepare_durable_pinned_host_evidence", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

COMMIT = "a" * 40
SHA = "b" * 64


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def make_bundle(root: Path) -> dict[str, object]:
    package = {
        "package": "alpha:amd64",
        "version": "1.0-1",
        "architecture": "amd64",
        "status": "ii ",
    }
    packages = [package]
    installed = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.installed_package_manifest",
        "package_count": 1,
        "packages_sha256": MODULE.canonical_sha256(packages),
        "packages": packages,
        "runtime_implementation_authorized": False,
    }
    artifact = {
        "package": "alpha:amd64",
        "version": "1.0-1",
        "architecture": "amd64",
        "apt_package": "alpha",
        "apt_query": "alpha:amd64=1.0-1",
        "filename": "pool/a/alpha_1.0-1_amd64.deb",
        "size_bytes": 42,
        "sha256": SHA,
        "source_package": None,
        "section": "utils",
        "priority": "optional",
        "multi_arch": "same",
        "digest_source": "apt_package_index",
        "queries_attempted": ["alpha:amd64=1.0-1"],
    }
    artifacts = [artifact]
    apt_index_files = [
        {
            "path": "archive_InRelease",
            "size_bytes": 10,
            "sha256": "c" * 64,
            "release_metadata": True,
            "package_index": False,
        },
        {
            "path": "archive_binary-amd64_Packages.lz4",
            "size_bytes": 20,
            "sha256": "d" * 64,
            "release_metadata": False,
            "package_index": True,
        },
    ]
    package_artifacts = {
        "schema_version": "0.2.0",
        "record_type": "ptah.phase0c.installed_package_artifact_manifest",
        "collection_mode": "local_apt_cache_exact_version_metadata",
        "network_used": False,
        "package_count": 1,
        "artifact_count": 1,
        "missing_count": 0,
        "complete": True,
        "artifacts_sha256": MODULE.canonical_sha256(artifacts),
        "artifacts": artifacts,
        "missing": [],
        "apt_index_inventory": {
            "root": "/var/lib/apt/lists",
            "file_count": 2,
            "release_file_count": 1,
            "package_index_file_count": 1,
            "files": apt_index_files,
            "files_sha256": MODULE.canonical_sha256(apt_index_files),
            "present": True,
        },
        "runtime_implementation_authorized": False,
    }
    host = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.pinned_host_identity",
        "os_release": {
            "ID": "ubuntu",
            "VERSION_ID": "24.04",
            "VERSION": "24.04.4 LTS (Noble Numbat)",
            "PRETTY_NAME": "Ubuntu 24.04.4 LTS",
        },
        "kernel": "6.8.0-136-generic",
        "architecture": "x86_64",
        "hostname_sha256": "e" * 64,
        "boot_identity": {
            "machine_id_sha256": "f" * 64,
            "boot_id_sha256": "1" * 64,
            "secure_boot": "SecureBoot disabled",
        },
        "expected": MODULE.EXPECTED_HOST,
        "identity_failures": [],
        "proof_eligible": True,
        "runtime_implementation_authorized": False,
    }
    capabilities = {
        "record_type": "ptah.phase0c.host_capability_report",
        "host": {
            "hostname_sha256": "e" * 64,
            "architecture": "x86_64",
            "kernel": "6.8.0-136-generic",
        },
        "required_capabilities_passed": True,
        "required_failures": [],
        "pinned_host_match": {"all_match": True},
        "proof_eligible": True,
        "runtime_implementation_authorized": False,
    }
    apt_sources_list = [
        "/etc/apt/sources.list.d/ubuntu.sources:Types: deb",
        "/etc/apt/sources.list.d/ubuntu.sources:URIs: http://archive.ubuntu.com/ubuntu/",
    ]
    apt_sources = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.apt_source_manifest",
        "sources": apt_sources_list,
        "sources_sha256": MODULE.canonical_sha256(apt_sources_list),
        "runtime_implementation_authorized": False,
    }
    source_records = {
        "apt-sources.json": apt_sources,
        "host-capabilities.json": capabilities,
        "host-identity.json": host,
        "installed-packages.json": installed,
        "package-artifacts.json": package_artifacts,
    }
    for name, value in source_records.items():
        write_json(root / name, value)
    file_records = []
    for name in sorted(source_records):
        path = root / name
        file_records.append(
            {
                "path": name,
                "sha256": MODULE.sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    clean_state = {
        "worktree_dirty": False,
        "index_dirty": False,
        "unexpected_untracked": [],
        "dirty": False,
    }
    manifest = {
        "schema_version": "0.3.0",
        "record_type": "ptah.phase0c.pinned_host_proof_bundle",
        "implementation_commit": COMMIT,
        "repository_commit_after_collection": COMMIT,
        "repository_commit_changed_during_collection": False,
        "repository_state_before_collection": clean_state,
        "repository_state_after_collection": clean_state,
        "repository_dirty": False,
        "proof_eligible": True,
        "eligibility_failures": [],
        "host_identity_failures": [],
        "capability_failures": [],
        "package_artifact_failures": [],
        "capability_report": {
            "collector_path": "host/scripts/collect_capabilities.py",
            "collector_sha256": "2" * 64,
            "collector_returncode": 0,
            "report_path": "host-capabilities.json",
            "report_sha256": MODULE.sha256_file(root / "host-capabilities.json"),
            "validation_failures": [],
        },
        "package_artifact_report": {
            "collector_path": "tools/collect_apt_package_artifacts.py",
            "collector_sha256": "3" * 64,
            "collector_returncode": 0,
            "report_path": "package-artifacts.json",
            "report_sha256": MODULE.sha256_file(root / "package-artifacts.json"),
            "validation_failures": [],
        },
        "package_count": 1,
        "package_artifact_count": 1,
        "files": file_records,
        "bundle_sha256": MODULE.canonical_sha256(file_records),
        "runtime_implementation_authorized": False,
    }
    write_json(root / "bundle-manifest.json", manifest)
    return manifest


class DurablePinnedHostEvidenceTests(unittest.TestCase):
    def test_valid_bundle_is_retained_as_pending_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "durable"
            source.mkdir()
            make_bundle(source)
            result = MODULE.prepare_retention(source, output)
            self.assertEqual(result["implementation_commit"], COMMIT)
            self.assertEqual(result["review_status"], "pending")
            durable = json.loads(
                (output / "durable-pinned-host-bundle.json").read_text()
            )
            review = json.loads(
                (output / "pinned-host-review-record.json").read_text()
            )
            self.assertEqual(durable["retained_file_count"], 6)
            self.assertTrue(durable["proof_eligible_source_verified"])
            self.assertEqual(durable["retention_status"], "durable_candidate_pending_review")
            self.assertFalse(review["physical_host_identity_accepted"])
            self.assertFalse(review["installed_package_manifest_accepted"])
            self.assertFalse(review["package_artifact_manifest_accepted"])
            self.assertFalse(review["runtime_implementation_authorized"])

    def test_tampered_source_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            make_bundle(source)
            path = source / "apt-sources.json"
            path.write_text(path.read_text() + " ", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.RetentionError, "mismatch"):
                MODULE.verify_bundle(source)

    def test_non_proof_eligible_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            make_bundle(source)
            path = source / "bundle-manifest.json"
            manifest = json.loads(path.read_text())
            manifest["proof_eligible"] = False
            write_json(path, manifest)
            with self.assertRaisesRegex(MODULE.RetentionError, "not proof-eligible"):
                MODULE.verify_bundle(source)

    def test_runtime_authorizing_record_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            make_bundle(source)
            path = source / "host-identity.json"
            record = json.loads(path.read_text())
            record["runtime_implementation_authorized"] = True
            write_json(path, record)
            manifest_path = source / "bundle-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            for item in manifest["files"]:
                if item["path"] == "host-identity.json":
                    item["sha256"] = MODULE.sha256_file(path)
                    item["size_bytes"] = path.stat().st_size
            manifest["bundle_sha256"] = MODULE.canonical_sha256(manifest["files"])
            write_json(manifest_path, manifest)
            with self.assertRaisesRegex(
                MODULE.RetentionError, "runtime_implementation_authorized=false"
            ):
                MODULE.verify_bundle(source)

    def test_missing_package_artifact_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            make_bundle(source)
            path = source / "package-artifacts.json"
            record = json.loads(path.read_text())
            record["artifacts"][0]["version"] = "2.0"
            record["artifacts_sha256"] = MODULE.canonical_sha256(record["artifacts"])
            write_json(path, record)
            manifest_path = source / "bundle-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            for item in manifest["files"]:
                if item["path"] == "package-artifacts.json":
                    item["sha256"] = MODULE.sha256_file(path)
                    item["size_bytes"] = path.stat().st_size
            manifest["package_artifact_report"]["report_sha256"] = MODULE.sha256_file(path)
            manifest["bundle_sha256"] = MODULE.canonical_sha256(manifest["files"])
            write_json(manifest_path, manifest)
            with self.assertRaisesRegex(MODULE.RetentionError, "not linked"):
                MODULE.verify_bundle(source)

    def test_raw_capability_hostname_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            make_bundle(source)
            path = source / "host-capabilities.json"
            record = json.loads(path.read_text())
            record["host"]["hostname"] = "proof-host"
            write_json(path, record)
            manifest_path = source / "bundle-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            for item in manifest["files"]:
                if item["path"] == "host-capabilities.json":
                    item["sha256"] = MODULE.sha256_file(path)
                    item["size_bytes"] = path.stat().st_size
            manifest["capability_report"]["report_sha256"] = MODULE.sha256_file(path)
            manifest["bundle_sha256"] = MODULE.canonical_sha256(manifest["files"])
            write_json(manifest_path, manifest)
            with self.assertRaisesRegex(MODULE.RetentionError, "raw hostname"):
                MODULE.verify_bundle(source)

    def test_non_empty_output_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "durable"
            source.mkdir()
            output.mkdir()
            (output / "existing.txt").write_text("do not overwrite", encoding="utf-8")
            make_bundle(source)
            with self.assertRaisesRegex(MODULE.RetentionError, "not empty"):
                MODULE.prepare_retention(source, output)


if __name__ == "__main__":
    unittest.main()
