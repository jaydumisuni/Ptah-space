from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

FILE = Path(__file__).resolve().parents[1] / "donor_handoff_contract.py"
spec = importlib.util.spec_from_file_location("donor_handoff_contract", FILE)
assert spec is not None and spec.loader is not None
bridge = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bridge
spec.loader.exec_module(bridge)


class DonorEvidenceIntakeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = "evidence/athena-harvest/20261015/androidutility-ptah-rea-readonly-evidence-handoff-v2.json"
        self.native_sha = bridge.NATIVE_SHA
        self.methods = [{
            "method_index": i,
            "name": f"on_btn{i}_clicked",
            "native_handler_entry_va": hex(0x941000 + 0x10 * i),
            "dispatch_direct_calls": [{"callsite_va": hex(0x951000 + 0x10 * i)}],
            "device_backend_proven": False
        } for i in range(24)]
        self.edges = [{
            "method_index": m["method_index"], "method": m["name"],
            "native_entrypoint_va": m["native_handler_entry_va"],
            "verified_dispatch_callsite_va": m["dispatch_direct_calls"][0]["callsite_va"],
            "exact_ui_sender_verified": False
        } for m in self.methods]
        qt = {
            "source_native_sha256": self.native_sha,
            "method_count": 24,
            "methods": self.methods,
            "named_ui_associations": [
                {"slot_name": m["name"], "exact_receiver_instance_join_proven": False}
                for m in self.methods[:13]
            ]
        }
        graph = {
            "source_sha256": self.native_sha,
            "reports": [
                {"possible_static_resolver_path_count": 0, "search_cap_hit": False}
                for _ in range(13)
            ],
        }
        refs = [
            "evidence/athena-harvest/20261014/native-qt-recovery-review.json",
            "evidence/athena-harvest/20261014/qt-handler-backend-trace.json",
            "evidence/athena-harvest/20261014/qt-native-legacy-connections.json",
            "evidence/athena-harvest/20261015/androidutility-runtime-resolver-catalog.json",
            "evidence/athena-harvest/20261015/androidutility-native-callsite-trace-v2.json",
            "remakes/AndroidUtility.v200/backend-map.json",
            "evidence/androidutility-ui-object-offsets.json",
            "evidence/athena-harvest/20261015/androidutility-qt-metacall-dispatch-v3.json",
            "evidence/athena-harvest/20261015/androidutility-native-handler-callgraph-v1.json",
        ]
        records = []
        for path in refs:
            obj = qt if path.endswith("metacall-dispatch-v3.json") else (
                graph if path.endswith("handler-callgraph-v1.json") else {})
            raw = (json.dumps(obj, sort_keys=True) + "\n").encode()
            f = self.root / path
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(raw)
            records.append({
                "relative_path": path,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw)
            })
        old = self.root / "evidence/athena-harvest/20261015/androidutility-ptah-rea-readonly-evidence-handoff.json"
        old.write_text('{"schema":"v1"}\n')
        self.handoff = {
            "schema": bridge.INPUT_SCHEMA,
            "donor_pe_sha256": self.native_sha,
            "donor_bytes": 353236480,
            "previous_handoff": {
                "relative_path": old.relative_to(self.root).as_posix(),
                "sha256": bridge.digest(old)
            },
            "source_evidence": records,
            "coverage": {
                "proven_qt_meta_method_to_native_entrypoint": 24,
                "qt_named_ui_slot_candidates_with_object_strings": 13,
                "control_to_backend_edges_proven": 0,
                "bounded_direct_callgraph_backend_resolver_paths": 0,
                "qt_exact_receiver_instance_control_join_proven": 0,
                "device_operations_executed": 0,
            },
            "graph": {
                "qt_method_to_native_handler": self.edges,
                "handler_to_backend_resolution": {"verified_paths": []}
            },
            "write_authority": {"device_operations": False, "license_or_auth_bypass": False},
        }
        self.save()

    def save(self):
        file = self.root / self.path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(json.dumps(self.handoff, sort_keys=True) + "\n")

    def test_metadata_only_validates_but_does_not_admit_provider(self):
        receipt, edges = bridge.verify(self.root)
        self.assertEqual(receipt["status"], "metadata_only_verified")
        self.assertFalse(receipt["original_source_rehashed"])
        self.assertFalse(receipt["production_ptah_provider_admitted"])
        self.assertFalse(receipt["workspace_grant_or_lease_created"])
        self.assertEqual(receipt["native_meta_method_edges_verified"], 24)
        self.assertEqual(len(edges), 24)

    def test_exact_git_crlf_roundtrip_is_audited(self):
        # Git may checkout a Windows-created JSON with LF. The exact frozen
        # CRLF bytes must be reconstructed and match the SHA, never guessed.
        old = self.root / self.handoff["previous_handoff"]["relative_path"]
        lf = old.read_bytes()
        self.handoff["previous_handoff"]["sha256"] = hashlib.sha256(lf.replace(b"\n", b"\r\n")).hexdigest()
        self.save()
        receipt, _ = bridge.verify(self.root)
        self.assertEqual(receipt["git_crlf_transport_reconstructions"], 1)
        old.write_bytes(lf + b"extra")
        with self.assertRaises(bridge.HandoffRejected):
            bridge.verify(self.root)

    def test_refuses_backend_claim_promotion(self):
        self.handoff["coverage"]["control_to_backend_edges_proven"] = 1
        self.save()
        with self.assertRaises(bridge.HandoffRejected):
            bridge.verify(self.root)

    def test_refuses_sender_claim_promotion(self):
        self.handoff["graph"]["qt_method_to_native_handler"][0]["exact_ui_sender_verified"] = True
        self.save()
        with self.assertRaises(bridge.HandoffRejected):
            bridge.verify(self.root)

    def test_refuses_evidence_digest_mutation(self):
        p = self.root / "evidence/athena-harvest/20261015/androidutility-qt-metacall-dispatch-v3.json"
        p.write_text('{"changed":true}')
        with self.assertRaises(bridge.HandoffRejected):
            bridge.verify(self.root)

    def test_refuses_traversal(self):
        self.handoff["source_evidence"][0]["relative_path"] = "../../private.txt"
        self.save()
        with self.assertRaises(bridge.HandoffRejected):
            bridge.verify(self.root)

    def test_refuses_without_correct_original_when_requested(self):
        bad = self.root / "source.exe"
        bad.write_bytes(b"MZfake")
        with self.assertRaises(bridge.HandoffRejected):
            bridge.verify(self.root, bad)

    def test_refuses_missing_native_graph_sha_reference(self):
        self.handoff["source_evidence"][-1] = self.handoff["source_evidence"][0].copy()
        self.handoff["source_evidence"][-1]["relative_path"] = "evidence/androidutility-ui-object-offsets.json"
        self.save()
        with self.assertRaises(bridge.HandoffRejected):
            bridge.verify(self.root)

    def test_never_overwrites_output_dir(self):
        out = self.root / "out"
        out.mkdir()
        receipt, edges = bridge.verify(self.root)
        with self.assertRaises(FileExistsError):
            out.mkdir(parents=True, exist_ok=False)
        self.assertEqual(len(edges), 24)


if __name__ == "__main__":
    unittest.main()
