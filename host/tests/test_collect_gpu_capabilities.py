#!/usr/bin/env python3
"""Tests for the non-claiming E05 GPU capability collector."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "collect_gpu_capabilities.py"
SPEC = importlib.util.spec_from_file_location("collect_gpu_capabilities", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class GpuCollectorTests(unittest.TestCase):
    def fake_drm(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory(prefix="ptah-e05-gpu-")
        root = Path(temp.name)
        card = root / "card0" / "device"
        (card / "drm" / "renderD128").mkdir(parents=True)
        (card / "vendor").write_text("0x8086\n", encoding="utf-8")
        (card / "device").write_text("0x9bc5\n", encoding="utf-8")
        (card / "uevent").write_text(
            "DRIVER=i915\nPCI_CLASS=30000\nPCI_ID=8086:9BC5\n",
            encoding="utf-8",
        )
        return temp, root

    def test_gpu_hardware_and_render_node_do_not_imply_compute(self) -> None:
        temp, root = self.fake_drm()
        self.addCleanup(temp.cleanup)
        with mock.patch.object(collector.shutil, "which", return_value=None):
            report = collector.collect(drm_root=root)

        self.assertTrue(report["gpu_device_present"])
        self.assertTrue(report["render_node_present"])
        self.assertFalse(report["compute_api_evidenced"])
        self.assertFalse(report["workstation_gpu_hardware_ready"])
        self.assertFalse(report["runtime_authorized"])
        self.assertFalse(report["e05_admission_authorized"])
        self.assertIn("gpu_compute_api_not_verified", report["blockers"])

    def test_verified_opencl_probe_can_satisfy_hardware_compute_prerequisite(self) -> None:
        temp, root = self.fake_drm()
        self.addCleanup(temp.cleanup)

        def which(name: str) -> str | None:
            return "/usr/bin/clinfo" if name == "clinfo" else None

        with mock.patch.object(collector.shutil, "which", side_effect=which), mock.patch.object(
            collector,
            "command",
            return_value={
                "available": True,
                "returncode": 0,
                "stdout": "Platform #0: Intel",
                "stderr": "",
            },
        ):
            report = collector.collect(drm_root=root)

        self.assertTrue(report["compute_api_evidenced"])
        self.assertEqual(report["verified_compute_backends"], ["opencl"])
        self.assertTrue(report["workstation_gpu_hardware_ready"])
        self.assertFalse(report["e05_admission_authorized"])

    def test_no_drm_gpu_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ptah-e05-gpu-empty-") as directory, mock.patch.object(
            collector.shutil, "which", return_value=None
        ):
            report = collector.collect(drm_root=Path(directory))

        self.assertFalse(report["gpu_device_present"])
        self.assertFalse(report["render_node_present"])
        self.assertFalse(report["compute_api_evidenced"])
        self.assertIn("gpu_device_not_observed", report["blockers"])
        self.assertIn("gpu_render_node_not_observed", report["blockers"])


if __name__ == "__main__":
    unittest.main()
