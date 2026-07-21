from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("collect_apt_package_artifacts.py")
SPEC = importlib.util.spec_from_file_location("collect_apt_package_artifacts", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def identity(package: dict[str, str]):
    return MODULE.package_identity(package)


class AptPackageArtifactTests(unittest.TestCase):
    def test_parse_deb822_handles_paragraphs_and_continuations(self) -> None:
        parsed = MODULE.parse_deb822(
            "Package: alpha\nVersion: 1\nDescription: first\n continued\n\n"
            "Package: beta\nVersion: 2\n"
        )
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["Description"], "first\ncontinued")
        self.assertEqual(parsed[1]["Package"], "beta")

    def test_exact_queries_preserve_version_and_architecture(self) -> None:
        package = {
            "package": "libc6:amd64",
            "version": "2.39-0ubuntu8",
            "architecture": "amd64",
        }
        self.assertEqual(
            MODULE.architecture_query(package), "libc6:amd64=2.39-0ubuntu8"
        )
        self.assertEqual(MODULE.plain_query(package), "libc6=2.39-0ubuntu8")

    def test_exact_artifact_requires_version_architecture_and_sha256(self) -> None:
        package = {
            "package": "alpha:amd64",
            "version": "1.2",
            "architecture": "amd64",
        }
        paragraphs = [
            {
                "Package": "alpha",
                "Version": "1.2",
                "Architecture": "amd64",
                "Filename": "pool/a/alpha_1.2_amd64.deb",
                "Size": "42",
                "SHA256": "a" * 64,
            },
            {
                "Package": "alpha",
                "Version": "1.3",
                "Architecture": "amd64",
                "Filename": "pool/a/alpha_1.3_amd64.deb",
                "Size": "43",
                "SHA256": "b" * 64,
            },
        ]
        matches = MODULE.exact_artifacts(package, paragraphs, "alpha:amd64=1.2")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["sha256"], "a" * 64)
        self.assertEqual(matches[0]["digest_source"], "apt_package_index")

    def test_load_installed_packages_rejects_authorizing_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "installed.json"
            path.write_text(
                json.dumps(
                    {
                        "record_type": "ptah.phase0c.installed_package_manifest",
                        "runtime_implementation_authorized": True,
                        "package_count": 1,
                        "packages": [
                            {
                                "package": "alpha",
                                "version": "1",
                                "architecture": "amd64",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.ArtifactError):
                MODULE.load_installed_packages(path)

    def test_load_installed_packages_rejects_non_string_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "installed.json"
            path.write_text(
                json.dumps(
                    {
                        "record_type": "ptah.phase0c.installed_package_manifest",
                        "runtime_implementation_authorized": False,
                        "package_count": 1,
                        "packages": [
                            {
                                "package": None,
                                "version": "1",
                                "architecture": "amd64",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.ArtifactError):
                MODULE.load_installed_packages(path)

    def test_build_manifest_is_complete_only_with_all_digests_and_indexes(self) -> None:
        packages = [
            {"package": "alpha", "version": "1", "architecture": "amd64"},
            {"package": "beta", "version": "2", "architecture": "all"},
        ]

        def resolver(records: list[dict[str, str]], apt_cache: str):
            resolution = {}
            for package in records:
                digest = "a" * 64 if package["package"] == "alpha" else "b" * 64
                resolution[identity(package)] = (
                    [
                        {
                            **package,
                            "apt_package": package["package"],
                            "apt_query": MODULE.architecture_query(package),
                            "filename": "pool/" + package["package"] + ".deb",
                            "size_bytes": 10,
                            "sha256": digest,
                            "source_package": None,
                            "section": None,
                            "priority": None,
                            "multi_arch": None,
                            "digest_source": "apt_package_index",
                        }
                    ],
                    [
                        {
                            "query": MODULE.architecture_query(package),
                            "batch_returncode": 0,
                            "stderr": "",
                        }
                    ],
                )
            return resolution

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "archive_InRelease").write_text(
                "signed index\n", encoding="utf-8"
            )
            (root / "archive_binary-amd64_Packages.lz4").write_text(
                "package metadata\n", encoding="utf-8"
            )
            manifest = MODULE.build_manifest(
                packages,
                apt_cache="/usr/bin/apt-cache",
                apt_lists_root=root,
                resolver=resolver,
            )
        self.assertIs(manifest["complete"], True)
        self.assertEqual(manifest["artifact_count"], 2)
        self.assertEqual(manifest["missing"], [])
        self.assertEqual(manifest["apt_index_inventory"]["release_file_count"], 1)
        self.assertEqual(
            manifest["apt_index_inventory"]["package_index_file_count"], 1
        )
        self.assertIs(manifest["runtime_implementation_authorized"], False)

    def test_missing_digest_keeps_manifest_fail_closed(self) -> None:
        packages = [
            {"package": "alpha", "version": "1", "architecture": "amd64"}
        ]

        def resolver(records: list[dict[str, str]], apt_cache: str):
            package = records[0]
            return {
                identity(package): (
                    [],
                    [
                        {
                            "query": MODULE.architecture_query(package),
                            "batch_returncode": 0,
                            "stderr": "",
                        }
                    ],
                )
            }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "archive_InRelease").write_text(
                "signed index\n", encoding="utf-8"
            )
            (root / "archive_Packages").write_text(
                "package metadata\n", encoding="utf-8"
            )
            manifest = MODULE.build_manifest(
                packages,
                apt_cache="/usr/bin/apt-cache",
                apt_lists_root=root,
                resolver=resolver,
            )
        self.assertIs(manifest["complete"], False)
        self.assertEqual(manifest["artifact_count"], 0)
        self.assertEqual(manifest["missing_count"], 1)

    def test_unrelated_apt_files_do_not_satisfy_index_gate(self) -> None:
        packages = [
            {"package": "alpha", "version": "1", "architecture": "amd64"}
        ]

        def resolver(records: list[dict[str, str]], apt_cache: str):
            package = records[0]
            return {
                identity(package): (
                    [
                        {
                            **package,
                            "apt_package": "alpha",
                            "apt_query": MODULE.architecture_query(package),
                            "filename": "pool/a/alpha.deb",
                            "size_bytes": 10,
                            "sha256": "a" * 64,
                            "source_package": None,
                            "section": None,
                            "priority": None,
                            "multi_arch": None,
                            "digest_source": "apt_package_index",
                        }
                    ],
                    [
                        {
                            "query": MODULE.architecture_query(package),
                            "batch_returncode": 0,
                            "stderr": "",
                        }
                    ],
                )
            }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unrelated.txt").write_text(
                "not apt metadata\n", encoding="utf-8"
            )
            manifest = MODULE.build_manifest(
                packages,
                apt_cache="/usr/bin/apt-cache",
                apt_lists_root=root,
                resolver=resolver,
            )
        self.assertIs(manifest["complete"], False)
        self.assertIs(manifest["apt_index_inventory"]["present"], False)

    def test_batched_queries_resolve_multiple_packages_in_one_command(self) -> None:
        packages = [
            {"package": "alpha", "version": "1", "architecture": "amd64"},
            {"package": "beta", "version": "2", "architecture": "all"},
        ]
        output = (
            "Package: alpha\nVersion: 1\nArchitecture: amd64\n"
            "Filename: pool/a.deb\nSize: 10\nSHA256: "
            + "a" * 64
            + "\n\n"
            "Package: beta\nVersion: 2\nArchitecture: all\n"
            "Filename: pool/b.deb\nSize: 20\nSHA256: "
            + "b" * 64
            + "\n"
        )
        calls: list[list[str]] = []
        original_run = MODULE.run

        def fake_run(command: list[str], *, check: bool = True):
            calls.append(command)
            return type(
                "Result",
                (),
                {"returncode": 0, "stdout": output, "stderr": ""},
            )()

        MODULE.run = fake_run
        try:
            resolution = MODULE.query_package_artifacts(
                packages, "/usr/bin/apt-cache"
            )
        finally:
            MODULE.run = original_run
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(resolution[identity(packages[0])][0]), 1)
        self.assertEqual(len(resolution[identity(packages[1])][0]), 1)


if __name__ == "__main__":
    unittest.main()
