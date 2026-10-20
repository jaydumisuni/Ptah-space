"""F02/F03 read-only observation, fake-host-resistant preflight behavior."""
import importlib.util
import os
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT=pathlib.Path(__file__).resolve().parents[1]/"tools/probe_os_foundation_host.py"
SPEC=importlib.util.spec_from_file_location("os_foundation_host_probe",SCRIPT)
assert SPEC and SPEC.loader
PROBE=importlib.util.module_from_spec(SPEC)
sys.modules["os_foundation_host_probe"]=PROBE
SPEC.loader.exec_module(PROBE)


class ReadOnlyHostProbeTests(unittest.TestCase):
    def test_snapshot_is_nonauthorizing(self):
        r=PROBE.snapshot()
        self.assertFalse(r["host_accepted"])
        self.assertFalse(r["phase_f02_accepted"])
        self.assertFalse(r["phase_f03_accepted"])
        self.assertEqual(r["ptah_native_enrollment"],"not_inferred")
        self.assertNotIn("hostname",r)
        self.assertNotIn("serial",r)

    def test_passive_probe_does_not_create_process(self):
        with patch.object(PROBE.subprocess,"Popen",side_effect=AssertionError("spawn prohibited")):
            self.assertIn("schema",PROBE.snapshot())

    def test_missing_qemu_returns_no_go(self):
        state=PROBE.snapshot()
        state["os"]="linux"
        state["tools"]["qemu-system-x86_64"]=False
        state["kvm"]["accessible"]=True
        with patch.object(PROBE,"snapshot",return_value=state):
            with patch.object(PROBE.subprocess,"Popen",side_effect=AssertionError("must not start")):
                result=PROBE.bounded_no_boot_smoke()
                self.assertEqual(result["reason"],"KVM_TOOL_UNAVAILABLE")
                self.assertFalse(result["host_admission"])

    def test_inaccessible_kvm_returns_no_go(self):
        state=PROBE.snapshot()
        state["os"]="linux"
        state["tools"]["qemu-system-x86_64"]=True
        state["tools"]["qemu-img"]=True
        state["kvm"]["accessible"]=False
        with patch.object(PROBE,"snapshot",return_value=state):
            with patch.object(PROBE.subprocess,"Popen",side_effect=AssertionError("must not start")):
                result=PROBE.bounded_no_boot_smoke()
                self.assertEqual(result["reason"],"KVM_NOT_ACCESSIBLE")

    def test_nonlinux_returns_no_go(self):
        state=PROBE.snapshot()
        state["os"]="windows"
        with patch.object(PROBE,"snapshot",return_value=state):
            self.assertEqual(PROBE.bounded_no_boot_smoke()["reason"],"KVM_TOOL_UNAVAILABLE")

    def test_default_cli_is_nonauthorizing_and_passive(self):
        r=subprocess.run([sys.executable,str(SCRIPT)],capture_output=True,text=True,timeout=15,check=True)
        import json
        body=json.loads(r.stdout)
        self.assertFalse(body["host_accepted"])
        self.assertFalse(body["phase_f02_accepted"])
        self.assertFalse(body["phase_f03_accepted"])
        self.assertNotIn("optional_smoke",body)
