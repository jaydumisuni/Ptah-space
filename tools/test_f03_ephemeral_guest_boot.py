"""F03 host-safe no-boot Linux-independent conformance; real smoke is opt-in."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("ptah_f03",ROOT/"tools/f03_ephemeral_guest_boot.py")
assert SPEC and SPEC.loader
F=importlib.util.module_from_spec(SPEC)
sys.modules["ptah_f03"]=F
SPEC.loader.exec_module(F)

class BoundedF03Tests(unittest.TestCase):
    def test_guest_source_is_deterministic_and_has_bios_signature(self):
        text=F.assembly()
        self.assertEqual(text,F.assembly())
        self.assertIn(".org 510",text)
        self.assertIn(".word 0xaa55",text)
        self.assertEqual(text.count("outb %al, $0xe9"),len(F.MARKER))
        self.assertIn("outb %al, $0xf4",text)

    def test_boot_command_has_no_network_and_fixed_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            cmd=F.boot_command(Path(d)/"guest.img",Path(d)/"marker")
        self.assertIn("-net",cmd)
        self.assertEqual(cmd[cmd.index("-net")+1],"none")
        self.assertEqual(cmd[cmd.index("-m")+1],"128M")
        self.assertEqual(cmd[cmd.index("-smp")+1],"1")
        self.assertEqual(cmd[cmd.index("-display")+1],"none")
        self.assertEqual(cmd[cmd.index("-monitor")+1],"none")
        self.assertEqual(cmd[cmd.index("-no-reboot")],"-no-reboot")
        self.assertNotIn("-enable-kvm",cmd)  # Accel is fixed in machine definition
        self.assertIn("pc,accel=kvm",cmd)

    def test_default_cli_does_not_execute_guest(self):
        result=subprocess.run([sys.executable,str(ROOT/"tools/f03_ephemeral_guest_boot.py")],
                              capture_output=True,text=True,timeout=15,check=True)
        output=json.loads(result.stdout)
        self.assertFalse(output["execution_requested"])
        self.assertFalse(output["native_ptah_admitted"])
        self.assertFalse(output["prime_os_integrated"])
        self.assertFalse(output["guest_os_booted"])

    def test_no_implicit_qemu_in_passive_observation(self):
        with patch.object(F.subprocess,"run",side_effect=AssertionError("must stay passive")):
            observed=F.inspect_host()
            self.assertEqual(observed["schema"],F.PROOF_SCHEMA)

    def test_invalid_time_budget_refused_before_process(self):
        for bad in (-1,0,1,2,21,100):
            with self.subTest(time=bad):
                with patch.object(F.subprocess,"run",side_effect=AssertionError("no launch")):
                    with self.assertRaises(F.F03Error):
                        F.proof(bad)

    def test_no_kvm_refuses_without_compilation(self):
        info=F.inspect_host()
        info["kvm_accessible"]=False
        with patch.object(F,"inspect_host",return_value=info):
            with patch.object(F.subprocess,"run",side_effect=AssertionError("no launch")):
                with self.assertRaisesRegex(F.F03Error,"KVM_NOT_ACCESSIBLE"):
                    F.proof()

    def test_missing_tool_refuses_without_compilation(self):
        info=F.inspect_host()
        info["required_tools"]["as"]=False
        with patch.object(F,"inspect_host",return_value=info):
            with patch.object(F.subprocess,"run",side_effect=AssertionError("no launch")):
                with self.assertRaisesRegex(F.F03Error,"REQUIRED_EXECUTABLE_MISSING"):
                    F.proof()

    def test_assembler_failure_does_not_continue_to_vm(self):
        info=F.inspect_host()
        info["kvm_accessible"]=True
        info["required_tools"]={name:True for name in ("as","ld","qemu-system-x86_64")}
        with patch.object(F,"inspect_host",return_value=info):
            with patch.object(F,"_run",return_value=subprocess.CompletedProcess([],1,b"",b"error")) as runner:
                with self.assertRaisesRegex(F.F03Error,"ASSEMBLY_FAILED"):
                    F.proof()
                self.assertEqual(runner.call_count,1)

    def test_requires_explicit_run_flag(self):
        result=subprocess.run([sys.executable,str(ROOT/"tools/f03_ephemeral_guest_boot.py"),
                               "--max-seconds","2"],
                              capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,2)
        self.assertIn("INVALID_TIME_BUDGET",result.stderr)

    def test_marker_is_not_a_release_or_guest_os_claim(self):
        report=F.inspect_host()
        for key in ("guest_os_booted","guest_data_recovered","native_ptah_admitted","prime_os_integrated"):
            self.assertFalse(report[key])
