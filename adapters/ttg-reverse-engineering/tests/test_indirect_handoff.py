"""Adversarial tests for optional SHA-bound Qt indirect candidate intake."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


bridge = load_module("donor_handoff_indirect_contract",
                     HERE.parent / "donor_handoff_contract.py")
legacy = load_module("donor_handoff_legacy_fixture",
                     HERE / "test_donor_handoff.py")


class IndirectEvidenceAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.fix = legacy.DonorEvidenceIntakeTests("test_metadata_only_validates_but_does_not_admit_provider")
        self.fix.setUp()
        self.addCleanup(self.fix.doCleanups)
        self.root = self.fix.root
        self.path = self.root / bridge.INDIRECT_PATH
        qt = self.root / "evidence/athena-harvest/20261015/androidutility-qt-metacall-dispatch-v3.json"
        direct = self.root / "evidence/athena-harvest/20261015/androidutility-native-handler-callgraph-v1.json"
        imports = sorted(bridge.EXPECTED_IAT_IMPORTS)
        sites = []
        for i in range(39):
            shape = "pe_import_iat" if i < 8 else (
                "base_index_memory_indirect" if i < 25 else "register_indirect")
            site = {
                "instruction_va": hex(0x941000 + i * 8),
                "instruction_bytes": "ffd0",
                "dispatch_shape": shape,
                "proven_target": i < 8,
            }
            if i < 8:
                site.update(imported_library="KERNEL32.dll", imported_symbol=imports[i],
                            target_kind="declared_import_symbol_not_runtime_library_address")
            sites.append(site)
        self.payload = {
            "schema": bridge.INDIRECT_SCHEMA,
            "source_sha256": bridge.NATIVE_SHA,
            "source_bytes": 353236480,
            "qt_evidence_sha256": bridge.digest(qt),
            "direct_callgraph_evidence_sha256": bridge.digest(direct),
            "qt_named_slots_reviewed": 13,
            "unique_indirect_callsites": 39,
            "verified_iat_callsite_count": 8,
            "indirect_dispatch_shape_counts": {
                "pe_import_iat": 8, "base_index_memory_indirect": 17,
                "register_indirect": 14,
            },
            "indirect_callsites": sites,
            "static_setup_associations": [
                {
                    "slot_name": m["name"],
                    "native_handler_entry_va": m["native_handler_entry_va"],
                    "runtime_sender_receiver_pair_proven": False,
                    "device_operation_enabled": False,
                    "static_setup_evidence": [{
                        "same_setup_function_proven": True,
                        "widget_storage_candidate": {
                            "exact_widget_instance_proven": False,
                        },
                    }],
                }
                for m in self.fix.methods[:13]
            ],
            "per_slot_scan": [
                {"slot": m["name"], "unique_indirect_callsites": 1,
                 "indirect_site_vas": [sites[i]["instruction_va"]]}
                for i, m in enumerate(self.fix.methods[:13])
            ],
            "ui_runtime_receiver_proven": False,
            "handler_to_backend_protocol_proven": False,
            "device_operations_executed": 0,
            "binary_modifications": 0,
        }
        self.original_digest = bridge.INDIRECT_SHA
        self.addCleanup(setattr, bridge, "INDIRECT_SHA", self.original_digest)
        self.write(accept_new_sha=True)

    def write(self, accept_new_sha=False):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps(self.payload, sort_keys=True) + "\n").encode()
        self.path.write_bytes(raw)
        if accept_new_sha:
            bridge.INDIRECT_SHA = hashlib.sha256(raw).hexdigest()

    def test_accepts_candidate_without_promoting_execution(self):
        baseline, _ = bridge.verify(self.root)
        extra, sites = bridge.verify_indirect(self.root)
        self.assertEqual(baseline["verified_control_to_backend_edges"], 0)
        self.assertEqual(extra["static_indirect_instruction_sites"], 39)
        self.assertEqual(len(sites), 39)
        self.assertFalse(extra["execution_authorized"])
        self.assertFalse(extra["production_ptah_provider_admitted"])

    def test_rejects_modified_bytes_even_if_json_valid(self):
        self.payload["untrusted_extra"] = True
        self.write()
        with self.assertRaises(bridge.HandoffRejected):
            bridge.verify_indirect(self.root)

    def test_rejects_forged_virtual_callee_even_with_new_hash(self):
        self.payload["indirect_callsites"][8]["proven_target"] = True
        self.write(accept_new_sha=True)
        with self.assertRaisesRegex(bridge.HandoffRejected, "promoted"):
            bridge.verify_indirect(self.root)

    def test_rejects_slot_rebinding_even_with_new_hash(self):
        self.payload["static_setup_associations"][0]["native_handler_entry_va"] = "0xdeadbeef"
        self.write(accept_new_sha=True)
        with self.assertRaisesRegex(bridge.HandoffRejected, "rebinding"):
            bridge.verify_indirect(self.root)

    def test_rejects_fake_device_authority_even_with_new_hash(self):
        self.payload["handler_to_backend_protocol_proven"] = True
        self.write(accept_new_sha=True)
        with self.assertRaisesRegex(bridge.HandoffRejected, "device access"):
            bridge.verify_indirect(self.root)

    def test_rejects_fake_system_import_even_with_new_hash(self):
        self.payload["indirect_callsites"][0]["imported_symbol"] = "EraseDisk"
        self.write(accept_new_sha=True)
        with self.assertRaisesRegex(bridge.HandoffRejected, "census or import"):
            bridge.verify_indirect(self.root)

    def test_rejects_duplicate_site_even_with_new_hash(self):
        self.payload["indirect_callsites"][1]["instruction_va"] = self.payload["indirect_callsites"][0]["instruction_va"]
        self.write(accept_new_sha=True)
        with self.assertRaisesRegex(bridge.HandoffRejected, "duplicate"):
            bridge.verify_indirect(self.root)


if __name__ == "__main__":
    unittest.main()
