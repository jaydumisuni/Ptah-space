#!/usr/bin/env python3
"""Tests for the non-claiming E05 Android/ADB endpoint collector."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "collect_android_device_capabilities.py"
SPEC = importlib.util.spec_from_file_location("collect_android_device_capabilities", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class AndroidCollectorTests(unittest.TestCase):
    def test_adb_endpoint_is_not_android_without_verified_properties(self) -> None:
        responses = {
            ("adb", "devices", "-l"): {
                "available": True,
                "returncode": 0,
                "stdout": "List of devices attached\nSERIAL1 device usb:1-2 transport_id:6",
                "stderr": "",
            },
        }

        def fake_command(*args: str):
            if args in responses:
                return responses[args]
            return {
                "available": True,
                "returncode": 0,
                "stdout": "/bin/sh: getprop: not found",
                "stderr": "",
            }

        with mock.patch.object(collector, "command", side_effect=fake_command):
            report = collector.collect()

        self.assertFalse(report["physical_android_device_observed"])
        self.assertEqual(report["endpoint_count"], 1)
        endpoint = report["endpoints"][0]
        self.assertFalse(endpoint["android_properties_verified"])
        self.assertEqual(endpoint["classification"], "adb_non_android_or_unverified")
        self.assertNotIn("SERIAL1", str(report))

    def test_verified_android_properties_are_required_for_physical_android(self) -> None:
        props = {
            "ro.product.manufacturer": "Xiaomi",
            "ro.product.model": "23076RA4BC",
            "ro.product.device": "sky",
            "ro.build.version.release": "15",
            "ro.build.version.sdk": "35",
            "ro.product.cpu.abi": "arm64-v8a",
        }

        def fake_command(*args: str):
            if args == ("adb", "devices", "-l"):
                return {
                    "available": True,
                    "returncode": 0,
                    "stdout": (
                        "List of devices attached\n"
                        "SERIAL2 device usb:1-8 product:sky model:23076RA4BC device:sky transport_id:2"
                    ),
                    "stderr": "",
                }
            key = args[-1]
            return {
                "available": True,
                "returncode": 0,
                "stdout": props.get(key, ""),
                "stderr": "",
            }

        with mock.patch.object(collector, "command", side_effect=fake_command):
            report = collector.collect()

        self.assertTrue(report["physical_android_device_observed"])
        endpoint = report["endpoints"][0]
        self.assertTrue(endpoint["android_properties_verified"])
        self.assertEqual(endpoint["classification"], "physical_android")
        self.assertEqual(endpoint["properties"]["model"], "23076RA4BC")
        self.assertEqual(endpoint["properties"]["sdk"], "35")
        self.assertFalse(report["e05_admission_authorized"])
        self.assertFalse(report["c08_c10_authority_created"])


if __name__ == "__main__":
    unittest.main()
