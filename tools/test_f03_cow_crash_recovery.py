"""F03 disposable recovery: fail-closed, no implicit VM and no replay."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("ptah_f03_cow",ROOT/"tools/f03_cow_crash_recovery.py")
assert SPEC and SPEC.loader
MOD=importlib.util.module_from_spec(SPEC)
sys.modules["ptah_f03_cow"]=MOD
SPEC.loader.exec_module(MOD)


class COWRecoveryTests(unittest.TestCase):
    def test_default_no_implicit_execution(self):
        with patch.object(MOD.subprocess,"Popen",side_effect=AssertionError("unexpected VM")):
            with patch.object(MOD.subprocess,"run",side_effect=AssertionError("unexpected command")):
                result=MOD.host()
                self.assertFalse(result["execution_requested"])
                self.assertFalse(result["guest_os_qualified"])
                self.assertFalse(result["phase_accepted"])
                self.assertFalse(result["physical_power_loss_tested"])
                self.assertFalse(result["prime_os_integrated"])

    def test_cli_passive_and_non_admission(self):
        p=subprocess.run([sys.executable,str(ROOT/"tools/f03_cow_crash_recovery.py")],
                         capture_output=True,text=True,check=True,timeout=20)
        data=json.loads(p.stdout)
        self.assertFalse(data["execution_requested"])
        self.assertFalse(data["e01_e05_enrolled"])

    def test_assembly_deterministic_and_explicit_disk_write(self):
        source=MOD.asm()
        self.assertEqual(source,MOD.asm())
        self.assertIn("int $0x13",source)
        self.assertIn("movb $0x03,%ah",source)
        self.assertEqual(source.count("outb %al,$0xe9"),len(MOD.ACK)+len(MOD.NAK))
        self.assertIn(".word 0xaa55",source)

    def test_qemu_configuration_limited_and_offline(self):
        cmd=MOD.qemu_command(Path("/tmp/candidate.qcow2"),Path("/tmp/m"))
        self.assertEqual(cmd[cmd.index("-net")+1],"none")
        self.assertEqual(cmd[cmd.index("-smp")+1],"1")
        self.assertEqual(cmd[cmd.index("-m")+1],"128M")
        self.assertEqual(cmd[cmd.index("-monitor")+1],"none")
        self.assertIn("pc,accel=kvm",cmd)
        self.assertTrue(any("format=qcow2,if=ide" in x for x in cmd))
        self.assertTrue(any("cache=none" in x for x in cmd))
        self.assertNotIn("-daemonize",cmd)

    def test_bounds_precede_vm_spawn(self):
        for val in [-100,-1,0,1,2,16,30]:
            with self.subTest(seconds=val), patch.object(MOD.subprocess,"Popen",
                                             side_effect=AssertionError("VM spawned")):
                with self.assertRaisesRegex(MOD.F03RecoveryError,"INVALID_TIMEOUT"):
                    MOD.run(val)

    def test_missing_tools_is_no_go(self):
        info=MOD.host()
        info["tooling"]={name:True for name in MOD.TOOLS}
        info["tooling"]["ld"]=False
        info["kvm_accessible"]=True
        with patch.object(MOD,"host",return_value=info),patch.object(
            MOD.subprocess,"Popen",side_effect=AssertionError("VM spawned")):
            with self.assertRaisesRegex(MOD.F03RecoveryError,"TOOLS_UNAVAILABLE"):
                MOD.run()

    def test_missing_kvm_is_no_go_independent_of_runner_tooling(self):
        info=MOD.host()
        info["tooling"]={name:True for name in MOD.TOOLS}
        info["kvm_accessible"]=False
        with patch.object(MOD,"host",return_value=info), patch.object(
            MOD.subprocess,"Popen",side_effect=AssertionError("VM spawned")):
            with self.assertRaisesRegex(MOD.F03RecoveryError,"KVM_UNAVAILABLE"):
                MOD.run()

    def test_existing_overlay_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            base=p/"base";base.write_bytes(b"x"*MOD.SIZE)
            out=p/"overlay";out.write_bytes(b"existing")
            with patch.object(MOD.subprocess,"run",side_effect=AssertionError("qemu-img ran")):
                with self.assertRaisesRegex(MOD.F03RecoveryError,"OVERLAY_ALREADY_EXISTS"):
                    MOD.overlay_from(base,out)
            self.assertEqual(out.read_bytes(),b"existing")

    def test_failed_command_is_not_interpreted_as_success(self):
        with patch.object(MOD.subprocess,"run",return_value=subprocess.CompletedProcess([],2)):
            with self.assertRaisesRegex(MOD.F03RecoveryError,"TOOL_COMMAND_FAILED"):
                MOD.invoke(["qemu-img","info"])

    def test_guest_ack_is_required_before_injecting_kill(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            trace=p/"trace";trace.write_text(MOD.NAK)
            proc=FakeProcess()
            with patch.object(MOD.subprocess,"Popen",return_value=proc):
                with self.assertRaisesRegex(MOD.F03RecoveryError,"GUEST_BIOS_WRITE_FAILED"):
                    MOD.kill_after_ack(p/"disk",trace,3)
            self.assertEqual(proc.kills,1)
            self.assertTrue(proc.waited)

    def test_guest_early_exit_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            proc=FakeProcess(early_exit=True)
            with patch.object(MOD.subprocess,"Popen",return_value=proc):
                with self.assertRaisesRegex(MOD.F03RecoveryError,"QEMU_EXITED_BEFORE_ACK"):
                    MOD.kill_after_ack(p/"disk",p/"trace",3)

    def test_guest_ack_is_not_durability_authority(self):
        self.assertNotEqual(MOD.ACK,MOD.NAK)
        self.assertLess(len(MOD.PAYLOAD),MOD.SECTOR)
        self.assertTrue(MOD.SCHEMA.endswith("/1"))


class FakeProcess:
    def __init__(self,early_exit=False):
        self.early_exit=early_exit
        self.kills=0
        self.waited=False
    def poll(self):
        return 1 if self.early_exit or self.kills else None
    def kill(self):
        self.kills+=1
    def wait(self,timeout=5):
        self.waited=True
        return 1


if __name__=="__main__":
    unittest.main()
