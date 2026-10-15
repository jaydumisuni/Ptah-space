from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / "ttg_re_engine.py"
spec = importlib.util.spec_from_file_location("ttg_re_engine", SOURCE)
assert spec is not None and spec.loader is not None
engine = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = engine
spec.loader.exec_module(engine)


class ReverseEngineeringBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def apk(self, name="sample.apk", entries=None):
        dest = self.root / name
        with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for k, v in (entries or {"AndroidManifest.xml": b"<manifest />", "classes.dex": b"dex\n035\x00", "assets/data.txt": b"hello"}).items():
                z.writestr(k, v)
        return dest

    def test_actual_zip_and_hash_classification(self):
        source = self.apk()
        obj = engine.inspect_input(source)
        self.assertEqual(obj["kind"], "android_apk")
        self.assertEqual(obj["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertIn("android_manifest_entry", obj["claims"])

    def test_apk_raw_derivative_and_provenance(self):
        source = self.apk()
        before = source.read_bytes()
        out = self.root / "evidence"
        receipt = engine.analyze(source, out, providers={"apk_extractor"},
                                 rea_cli="rea-nonexistent", app_recover_root=None)
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual((out / "raw_apk/assets/data.txt").read_bytes(), b"hello")
        children = receipt["provider_results"][0]["views"][0]["children"]
        self.assertEqual(next(x["sha256"] for x in children if x["path"] == "assets/data.txt"),
                         hashlib.sha256(b"hello").hexdigest())
        self.assertIn("Derived/decompiled views are not original source code.", receipt["limitations"])
        self.assertEqual(json.loads((out / "receipt.json").read_text())["schema"], engine.SCHEMA)
        self.assertEqual(receipt["analysis_state"], "partial")  # No installed Apktool/JADX on test host.

    def test_destination_is_non_overwriting(self):
        source = self.apk()
        out = self.root / "evidence"
        out.mkdir()
        with self.assertRaises(FileExistsError):
            engine.analyze(source, out, providers=set(), rea_cli="rea", app_recover_root=None)

    def test_refuses_zip_traversal_and_windows_separators(self):
        for i, name in enumerate(["../escape", "/absolute", r"C:\temp\escape", r"..\escape"]):
            source = self.apk(f"bad{i}.apk", {"AndroidManifest.xml": b"a", "classes.dex": b"b", name: b"blocked"})
            out = self.root / f"bad-out{i}"
            result = engine.analyze(source, out, providers={"apk_extractor"}, rea_cli="rea", app_recover_root=None)
            self.assertEqual(result["provider_failures"], 1)
            self.assertEqual(result["provider_results"][0]["views"][0]["status"], "rejected")
            self.assertFalse((self.root / "escape").exists())

    def test_refuses_symlinks_and_oversized_and_compression_bombs(self):
        self.assertRaises(engine.AdmissionError, engine._safe_zip_name, "../../x")
        source = self.apk("compressed.apk", {
            "AndroidManifest.xml": b"x", "classes.dex": b"y",
            "assets/zeros": b"0" * (1024 * 1024),
        })
        receipt = engine.analyze(source, self.root / "compression-evidence",
                                 providers={"apk_extractor"}, rea_cli="rea", app_recover_root=None)
        self.assertEqual(receipt["provider_failures"], 1)
        self.assertFalse((self.root / "compression-evidence/raw_apk/assets/zeros").exists())
        link = self.root / "source-link.apk"
        try:
            link.symlink_to(source)
        except OSError:
            pass
        else:
            with self.assertRaises(engine.AdmissionError):
                engine.inspect_input(link)

    def test_ignores_target_extension_without_signature(self):
        x = self.root / "imposter.apk"
        x.write_bytes(b"not an APK")
        self.assertEqual(engine.inspect_input(x)["kind"], "unknown")
        z = self.root / "app.zip"
        with zipfile.ZipFile(z, "w") as f:
            f.writestr("anything", "x")
        self.assertEqual(engine.inspect_input(z)["kind"], "zip_container")

    def test_unavailable_rea_reported_without_guessing(self):
        p = self.root / "binfile"
        p.write_bytes(b"\x7fELFfake")
        receipt = engine.analyze(p, self.root / "rea-out", providers={"rea"},
                                 rea_cli="not-installed-at-all", app_recover_root=None)
        self.assertEqual(receipt["provider_results"][0]["status"], "unavailable")
        self.assertEqual(receipt["analysis_state"], "partial")

    def test_cli_capabilities_returns_parseable_schema(self):
        done = subprocess.run([sys.executable, str(SOURCE), "capabilities", "--rea-cli", "missing-reverse-tool"],
                              capture_output=True, text=True, check=True)
        report = json.loads(done.stdout)
        self.assertEqual(report["schema"], engine.SCHEMA)
        self.assertFalse(report["providers"]["rea"]["available"])
        self.assertTrue(report["providers"]["apk_extractor_raw"]["available"])

    def test_directory_javascript_classification(self):
        source = self.root / "electron"
        source.mkdir()
        (source / "package.json").write_text('{"name":"test","main":"index.js"}')
        self.assertEqual(engine.inspect_input(source)["kind"], "javascript_application")

    def test_provider_operation_routing_is_fixed(self):
        expected = {
            "javascript_application": "analyze-javascript-application",
            "android_apk": "inspect-android-package",
            "pe_image": "analyze",
            "firmware_candidate": "inspect-firmware-regions",
            "unknown": None,
        }
        for kind, command in expected.items():
            self.assertEqual(engine._rea_operation(kind), command)

    def test_rea_invocation_with_controlled_mock_and_no_shell(self):
        # Only test the fixed command contract; this is not a claim a native REA backend is installed.
        shim = self.root / "mock-rea.py"
        shim.write_text("#!/usr/bin/env python3\nimport sys,json\nprint(json.dumps({'rea_progress':{'phase':'started'}}))\nprint(json.dumps({'evidence_id':'ev_mock','subject':{'digest':{'sha256':'abc'}},'args':sys.argv[1:]}))\n")
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
        source = self.root / "sample.mjs"
        source.write_text("export const x=1")
        receipt = engine.analyze(source, self.root / "rea-mock", providers={"rea"},
                                 rea_cli=str(shim), app_recover_root=None)
        self.assertEqual(receipt["provider_results"][0]["status"], "success")
        evidence = json.loads((self.root / "rea-mock" / "rea_evidence.json").read_text())
        self.assertEqual(evidence["args"], ["analyze-javascript-application", str(source.resolve()), "--json"])
        self.assertEqual(receipt["provider_results"][0]["evidence"]["evidence_id"], "ev_mock")
        self.assertEqual(receipt["provider_results"][0]["evidence"]["progress_records"], 1)

    def test_provider_candidate_manifest_does_not_admit_runtime(self):
        manifest = json.loads((SOURCE.parent / "provider-candidate.json").read_text())
        self.assertEqual(manifest["status"], "not_admitted")
        self.assertFalse(manifest["ptah_boundary"]["automatic_registration"])
        self.assertTrue(all(not row["launches_target"] for row in manifest["operations"]))
        self.assertEqual(len(manifest["source_authority"]), 3)

    def test_app_recover_driver_receipt_binds_source_digest(self):
        backend = self.root / "private-app-recover"
        backend.mkdir()
        (backend / "native_export_recovery.py").write_text(
            "import hashlib\n"
            "def recover_native_exports(source, out):\n"
            " out.mkdir(exist_ok=True)\n"
            " return {'input_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),"
            "'is_pe':True,'export_count':0,'action_candidate_count':0}\n"
        )
        source = self.root / "sample.exe"
        source.write_bytes(b"MZsynthetic")
        out = self.root / "pe-evidence"
        report = engine.analyze(source, out, providers={"app_recover"}, rea_cli="rea",
                                app_recover_root=str(backend))
        self.assertEqual(report["analysis_state"], "evidence_recorded")
        backend_receipt = report["provider_results"][0]["evidence"]
        receipt_path = out / backend_receipt["file"]
        self.assertEqual(backend_receipt["sha256"], hashlib.sha256(receipt_path.read_bytes()).hexdigest())

    def test_rea_script_launch_policy_is_cross_platform_and_blocks_batch(self):
        stub = self.root / "rea.py"
        stub.write_text("print('ok')\\n")
        self.assertEqual(engine._rea_launch_prefix(str(stub)),
                         [sys.executable, str(stub.resolve())])
        batch = self.root / "rea.cmd"
        batch.write_text("@echo off\\n")
        self.assertIsNone(engine._rea_launch_prefix(str(batch)))
        node_script = self.root / "rea.mjs"
        node_script.write_text("process.stdout.write('ok')\\n")
        launch = engine._rea_launch_prefix(str(node_script))
        if engine.resolve_command("node"):
            self.assertEqual(launch[1], str(node_script.resolve()))

    def test_driver_missing_root_remains_unavailable(self):
        source = self.root / "sample.exe"
        source.write_bytes(b"MZnotreallyPE")
        result = engine.analyze(source, self.root / "recover-out",
                                providers={"app_recover"}, rea_cli="rea", app_recover_root=None)
        self.assertEqual(result["provider_results"][0]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
