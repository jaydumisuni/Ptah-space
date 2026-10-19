"""Fail-closed OS foundation candidate conformance, no machine mutation."""
from __future__ import annotations
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parents[1]
SCRIPT=HERE/"tools/check_os_foundation.py"
SPEC=importlib.util.spec_from_file_location("ptah_f_preflight",SCRIPT)
assert SPEC and SPEC.loader
GATE=importlib.util.module_from_spec(SPEC)
sys.modules["ptah_f_preflight"]=GATE
SPEC.loader.exec_module(GATE)
DATA=HERE/"conformance/os-foundation"

class FoundationConformance(unittest.TestCase):
    def setUp(self):
        self.profile=GATE.read_json(DATA/"foundation-candidate.json")
        self.evidence=GATE.read_json(DATA/"evidence-index.json")

    def reject_profile(self,change):
        profile=copy.deepcopy(self.profile)
        change(profile)
        with self.assertRaises(GATE.ProfileError):
            GATE.validate_profile(profile)

    def reject_evidence(self,change):
        evidence=copy.deepcopy(self.evidence)
        change(evidence)
        with self.assertRaises(GATE.ProfileError):
            GATE.validate_evidence(evidence)

    def test_candidate_reports_no_go_no_execution(self):
        self.assertEqual(GATE.validate_profile(self.profile)["status"],"CANDIDATE_ONLY_NOT_ADMITTED")
        report=GATE.validate_evidence(self.evidence)
        self.assertEqual(report["native_e07"],"NO_GO")
        self.assertEqual(report["os_foundation"],"NO_GO")
        self.assertEqual(len(report["outstanding"]),21)

    def test_all_seven_phases_have_unforged_requirements(self):
        for phase in GATE.PHASES:
            self.assertEqual(self.profile["phase_gates"][phase]["status"],"not_admitted")
            self.assertEqual(self.evidence["phase_proofs"][phase],[])
            self.assertEqual(self.profile["phase_gates"][phase]["required_proofs"],
                             list(GATE.REQUIRED_PROOFS[phase]))
            with self.subTest(phase=phase):
                self.reject_profile(lambda p:p["phase_gates"][phase].update(status="complete"))

    def test_oracle_is_transport_not_ptah(self):
        self.reject_profile(lambda p:p["architecture"].update(machine_transport="ptah"))
        self.reject_profile(lambda p:p["architecture"].update(ptah_role="transport"))
        self.reject_profile(lambda p:p["architecture"].update(agent_authority="ptah-decides"))

    def test_service_activation_and_implicit_e01_are_rejected(self):
        self.reject_profile(lambda p:p["services"][0].update(default_enabled=True))
        self.reject_profile(lambda p:p["services"][0].update(admission="production"))
        self.reject_profile(lambda p:p["services"][0].update(artifact_digest="sha256:"+("a"*64)))
        self.reject_profile(lambda p:p["services"][0].update(required_authorities=["owner"]))

    def test_hosts_never_self_admit(self):
        self.reject_profile(lambda p:p["targets"][0].update(admission="verified"))
        self.reject_profile(lambda p:p["targets"][0].update(physical_proof="self-reported"))
        self.reject_profile(lambda p:p["targets"][0].update(os="unknown"))
        self.reject_profile(lambda p:p["targets"].append(copy.deepcopy(p["targets"][0])))

    def test_unknown_paths_and_private_fields_rejected(self):
        self.reject_profile(lambda p:p.update(shell_command="systemctl start ptah"))
        self.reject_profile(lambda p:p["services"][0].update(private_key="-----BEGIN..."))
        self.reject_profile(lambda p:p["services"][0].update(rollback_authorized=True))

    def test_missing_gate_or_proof_is_rejected(self):
        self.reject_profile(lambda p:p["phase_gates"].pop("F05"))
        self.reject_profile(lambda p:p["phase_gates"]["F07"].update(required_proofs=[]))

    def test_no_fabricated_reviews_effects_or_native_host_sessions(self):
        self.reject_evidence(lambda e:e.update(status="complete"))
        self.reject_evidence(lambda e:e["external_reviews"].append({"approver":"self"}))
        self.reject_evidence(lambda e:e["phase_proofs"]["F01"].append("fake-proof"))
        self.reject_evidence(lambda e:e["native_e07"].update(two_host_mtls=True))
        self.reject_evidence(lambda e:e["native_e07"].update(owner_signoff=True))

    def test_invalid_commit_and_structural_scope_rejected(self):
        self.reject_evidence(lambda e:e.update(candidate_commit="main"))
        self.reject_evidence(lambda e:e.update(extra="success"))
        self.reject_evidence(lambda e:e["native_e07"].pop("production_enrollment"))

    def test_bounded_parser_blocks_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            f=Path(folder)/"candidate.json"
            f.write_text('{"schema":"x","schema":"y"}')
            with self.assertRaises(GATE.ProfileError):
                GATE.read_json(f)

    def test_bounded_parser_blocks_symlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as folder:
            f=Path(folder)/"profile.json"
            f.write_text("{}")
            alias=Path(folder)/"alias.json"
            alias.symlink_to(f)
            with self.assertRaises(GATE.ProfileError):
                GATE.read_json(alias)
            f.write_bytes(b"x"*(GATE.MAX_FILE+1))
            with self.assertRaises(GATE.ProfileError):
                GATE.read_json(f)

    def test_bounded_cli_returns_explicit_nonauthority(self):
        result=subprocess.run([sys.executable,str(SCRIPT),
             "--profile",str(DATA/"foundation-candidate.json"),
             "--evidence",str(DATA/"evidence-index.json")],
             capture_output=True,text=True,timeout=15,check=True)
        report=json.loads(result.stdout)
        self.assertFalse(report["execution_authorized"])
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["evidence"]["native_e07"],"NO_GO")
        self.assertEqual(report["evidence"]["os_foundation"],"NO_GO")

    def test_cli_refuses_fabricated_activation(self):
        with tempfile.TemporaryDirectory() as folder:
            bad=Path(folder)/"unapproved.json"
            data=copy.deepcopy(self.profile)
            data["architecture"]["machine_transport"]="ptah"
            bad.write_text(json.dumps(data))
            result=subprocess.run([sys.executable,str(SCRIPT),
                "--profile",str(bad), "--evidence",str(DATA/"evidence-index.json")],
                capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,2)
            self.assertIn("WRONG_TRANSPORT_OR_AUTHORITY_BOUNDARY",result.stderr)
