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


class AptPackageArtifactTests(unittest.TestCase):
    def test_parse_deb822_handles_paragraphs_and_continuations(self) -> None:
        parsed = MODULE.parse_deb822(
            "Package: alpha\nVersion: 1\nDescription: first\n continued\n\n"
            "Package: beta\nVersion: 2\n"
        )
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["Description"], "first\ncontinued")
        self.assertEqual(parsed[1]["Package"], "beta")

    def test_package_queries_prefer_architecture_and_exact_version(self) -> None:
        queries = MODULE.package_queries(
            {
                "package": "libc6:amd64",
                "version": "2.39-0ubuntu8",
                "architecture": "amd64",
            }
        )
        self.assertEqual(
            queries,
            ["libc6:amd64=2.39-0ubuntu8", "libc6=2.39-0ubuntu8"],
        )

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

    def test_build_manifest_is_complete_only_with_all_digests_and_indexes(self) -> None:
        packages = [
            {"package": "alpha", "version": "1", "architecture": "amd64"},
            {"package": "beta", "version": "2", "architecture": "all"},
        ]

        def query(package: dict[str, str], apt_cache: str):
            digest = "a" * 64 if package["package"] == "alpha" else "b" * 64
            return (
                [
                    {
                        **package,
                        "apt_package": package["package"],
                        "apt_query": package["package"] + "=" + package["version"],
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
                        "query": package["package"] + "=" + package["version"],
                        "returncode": 0,
                        "stderr": "",
                    }
                ],
            )

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
                query_fn=query,
            )
        self.assertIs(manifest["complete"], True)
        self.assertEqual(manifest["artifact_count"], 2)
        self.assertEqual(manifest["missing"], [])
        self.assertEqual(manifest["apt_index_inventory"]["file_count"], 2)
        self.assertIs(manifest["runtime_implementation_authorized"], False)

    def test_missing_digest_keeps_manifest_fail_closed(self) -> None:
        packages = [
            {"package": "alpha", "version": "1", "architecture": "amd64"}
        ]

        def query(package: dict[str, str], apt_cache: str):
            return [], [
                {"query": "alpha:amd64=1", "returncode": 0, "stderr": ""}
            ]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "archive_InRelease").write_text(
                "signed index\n", encoding="utf-8"
            )
            manifest = MODULE.build_manifest(
                packages,
                apt_cache="/usr/bin/apt-cache",
                apt_lists_root=root,
                query_fn=query,
            )
        self.assertIs(manifest["complete"], False)
        self.assertEqual(manifest["artifact_count"], 0)
        self.assertEqual(manifest["missing_count"], 1)

    def test_missing_apt_index_inventory_keeps_manifest_fail_closed(self) -> None:
        packages = [
            {"package": "alpha", "version": "1", "architecture": "amd64"}
        ]

        def query(package: dict[str, str], apt_cache: str):
            return (
                [
                    {
                        **package,
                        "apt_package": "alpha",
                        "apt_query": "alpha:amd64=1",
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
                        "query": "alpha:amd64=1",
                        "returncode": 0,
                        "stderr": "",
                    }
                ],
            )

        with tempfile.TemporaryDirectory() as directory:
            manifest = MODULE.build_manifest(
                packages,
                apt_cache="/usr/bin/apt-cache",
                apt_lists_root=Path(directory),
                query_fn=query,
            )
        self.assertIs(manifest["complete"], False)
        self.assertIs(manifest["apt_index_inventory"]["present"], False)


if __name__ == "__main__":
    unittest.main()
