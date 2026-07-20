#!/usr/bin/env python3
"""Tests for the non-claiming Phase 0C host capability collector."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "collect_capabilities.py"
SPEC = importlib.util.spec_from_file_location("collect_capabilities", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class HostCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.image_lock = {
            "distribution": "Ubuntu Server",
            "release": "24.04.4 LTS",
            "architecture": "amd64",
            "kernel": {"expected_uname_family": "6.8.0-136-generic"},
            "runtime_authorized": False,
        }

    @mock.patch.object(collector.platform, "release", return_value="6.8.0-136-generic")
    @mock.patch.object(collector.platform, "machine", return_value="x86_64")
    def test_exact_pinned_host_match(self, _machine: mock.Mock, _release: mock.Mock) -> None:
        result = collector.pinned_host_match(
            self.image_lock,
            {"NAME": "Ubuntu Server", "VERSION_ID": "24.04.4"},
        )
        self.assertTrue(result["all_match"])

    @mock.patch.object(collector.platform, "release", return_value="6.11.0-azure")
    @mock.patch.object(collector.platform, "machine", return_value="x86_64")
    def test_different_kernel_is_not_pinned_proof(
        self, _machine: mock.Mock, _release: mock.Mock
    ) -> None:
        result = collector.pinned_host_match(
            self.image_lock,
            {"NAME": "Ubuntu", "VERSION_ID": "24.04.4"},
        )
        self.assertFalse(result["kernel"]["match"])
        self.assertFalse(result["all_match"])

    @mock.patch.object(collector.platform, "release", return_value="6.11.0-azure")
    @mock.patch.object(collector.platform, "machine", return_value="x86_64")
    @mock.patch.object(collector.platform, "node", return_value="ci-runner")
    @mock.patch.object(collector.platform, "system", return_value="Linux")
    @mock.patch.object(collector.platform, "version", return_value="#1 test")
    @mock.patch.object(collector.platform, "python_version", return_value="3.13.0")
    @mock.patch.object(
        collector,
        "os_release",
        return_value={"NAME": "Ubuntu", "VERSION_ID": "24.04.4"},
    )
    def test_candidate_report_never_authorizes_runtime(self, _os_release: mock.Mock, *_: mock.Mock) -> None:
        profile = {
            "required": ["fsync"],
            "conditional": [{"capability": "apparmor"}],
        }
        with mock.patch.object(
            collector,
            "read_json",
            side_effect=[profile, self.image_lock],
        ), mock.patch.dict(
            collector.CHECKS,
            {
                "fsync": lambda: collector.observation("pass", {"test": True}),
                "apparmor": lambda: collector.observation("limited", {"test": True}),
            },
            clear=True,
        ):
            report = collector.collect()

        self.assertTrue(report["required_capabilities_passed"])
        self.assertFalse(report["proof_eligible"])
        self.assertFalse(report["runtime_implementation_authorized"])
        self.assertEqual(report["status"], "candidate_host_observed")
        self.assertEqual(report["conditional_limitations"], ["apparmor"])


if __name__ == "__main__":
    unittest.main()
