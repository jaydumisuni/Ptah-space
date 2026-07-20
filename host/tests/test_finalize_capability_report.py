#!/usr/bin/env python3
"""Tests for final pinned-host identity evaluation."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "finalize_capability_report.py"
SPEC = importlib.util.spec_from_file_location("finalize_capability_report", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
finalizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(finalizer)


class FinalizeHostReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.image_lock = {
            "distribution": "Ubuntu Server",
            "release": "24.04.4 LTS",
            "architecture": "amd64",
            "kernel": {"expected_uname_family": "6.8.0-136-generic"},
            "runtime_authorized": False,
        }
        self.os_release = {
            "ID": "ubuntu",
            "NAME": "Ubuntu",
            "VERSION_ID": "24.04",
            "VERSION": "24.04.4 LTS (Noble Numbat)",
            "PRETTY_NAME": "Ubuntu 24.04.4 LTS",
        }

    def test_real_ubuntu_server_identity_matches_pinned_point_release(self) -> None:
        result = finalizer.pinned_host_match(
            self.image_lock,
            self.os_release,
            {"machine": "x86_64", "release": "6.8.0-136-generic"},
        )
        self.assertTrue(result["distribution"]["match"])
        self.assertTrue(result["release"]["base_release_match"])
        self.assertTrue(result["release"]["point_release_match"])
        self.assertTrue(result["all_match"])

    def test_same_ubuntu_release_with_cloud_kernel_is_not_pinned_proof(self) -> None:
        result = finalizer.pinned_host_match(
            self.image_lock,
            self.os_release,
            {"machine": "x86_64", "release": "6.17.0-1020-azure"},
        )
        self.assertTrue(result["distribution"]["match"])
        self.assertTrue(result["release"]["match"])
        self.assertFalse(result["kernel"]["match"])
        self.assertFalse(result["all_match"])

    def test_base_release_without_point_release_evidence_is_insufficient(self) -> None:
        release = dict(self.os_release)
        release["VERSION"] = "24.04 LTS (Noble Numbat)"
        release["PRETTY_NAME"] = "Ubuntu 24.04 LTS"
        result = finalizer.pinned_host_match(
            self.image_lock,
            release,
            {"machine": "x86_64", "release": "6.8.0-136-generic"},
        )
        self.assertTrue(result["release"]["base_release_match"])
        self.assertFalse(result["release"]["point_release_match"])
        self.assertFalse(result["all_match"])

    def test_finalizer_never_authorizes_runtime(self) -> None:
        report = {
            "host": {
                "os_release": self.os_release,
                "uname": {"machine": "x86_64", "release": "6.8.0-136-generic"},
            },
            "required_capabilities_passed": True,
            "runtime_implementation_authorized": True,
        }
        finalized = finalizer.finalize(report, self.image_lock)
        self.assertTrue(finalized["proof_eligible"])
        self.assertFalse(finalized["runtime_implementation_authorized"])


if __name__ == "__main__":
    unittest.main()
