#!/usr/bin/env python3
"""Non-destructive contract checks for TTG guarded workspace storage lifecycle."""
import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

FILE=Path(__file__).with_name("storage_guard.py")
if not FILE.exists():
    FILE=Path(__file__).with_name("workspace_storage_guard.py")
spec=importlib.util.spec_from_file_location("workspace_storage_guard",FILE)
guard=importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

class StorageGuardContract(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.project=self.root/"repo"
        self.project.mkdir()
        (self.project/".git").mkdir()
        (self.project/"Cargo.toml").write_text("[package]\nname='fixture'\nversion='0.1.0'\nedition='2021'\n")
        self.cache=self.project/"target"
        self.cache.mkdir()
        (self.cache/"fixture.bin").write_bytes(b"fake regenerable build")
        self.receipt=self.root/"evidence.json"
        self.receipt.write_text(json.dumps({
            "status":"PASS","head":"a"*40,
            "tests":["synthetic-fixture"],"evidence_ref":"fixture://local-receipt",
            "allow_disposable_cleanup":True,
            "machine":"KRATOS",
            "utc":"2026-10-17T09:00:00+00:00",
            "commands":["cargo test --locked --offline"],
            "output_hashes":{"test_output":"a"*64},
            "cleanup_classification":"regenerable_cargo_target"
        }))
        self.saved_state=guard.STATE
        guard.STATE=self.root/"state"
        self.addCleanup(setattr,guard,"STATE",self.saved_state)

    def qualify(self):
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            return guard.mark(self.project,self.receipt)

    def test_scan_is_read_only_and_bounded(self):
        result=guard.audit(self.root)
        self.assertEqual(result["cargo_target_count"],1)
        self.assertTrue((self.cache/"fixture.bin").exists())
        self.assertTrue((guard.STATE/"latest-audit.json").exists())

    def test_without_qualification_even_apply_never_cleans(self):
        with patch.object(guard,"active_builds",return_value=False):
            result=guard.prune(self.root,1,True)
        self.assertEqual(result["actions"],[])
        self.assertTrue((self.cache/"fixture.bin").exists())

    def test_wrong_head_receipt_fails_closed(self):
        self.receipt.write_text(json.dumps({
            "status":"PASS","head":"bad","tests":["sample"],"evidence_ref":"fixture://x",
            "allow_disposable_cleanup":True
        }))
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            with self.assertRaises(ValueError):
                guard.mark(self.project,self.receipt)

    def test_missing_pass_or_explicit_cleanup_fails_closed(self):
        self.receipt.write_text(json.dumps({"status":"FAIL","head":"a"*40,"tests":["sample"],"evidence_ref":"fixture://x"}))
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            with self.assertRaises(ValueError):
                guard.mark(self.project,self.receipt)

    def test_symlink_cache_rejected(self):
        (self.cache/"fixture.bin").unlink()
        self.cache.rmdir()
        self.cache.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):
            guard.valid_cache(self.project,self.cache)

    def test_qualified_changed_evidence_blocks_cleanup(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        m=json.loads(marker.read_text())
        m["qualified_at_epoch"]=time.time()-72*3600
        guard.atomic_json(marker,m)
        self.receipt.write_text('{"tampered":true}')
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            result=guard.prune(self.root,48,True)
        self.assertEqual(result["actions"][0]["status"],"protected")
        self.assertTrue((self.cache/"fixture.bin").exists())
        self.assertTrue(marker.exists())

    def test_marked_cache_stays_protected_during_compilation(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        m=json.loads(marker.read_text())
        m["qualified_at_epoch"]=time.time()-72*3600
        guard.atomic_json(marker,m)
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=True):
            result=guard.prune(self.root,48,True)
        self.assertEqual(result["actions"][0]["status"],"protected")
        self.assertTrue((self.cache/"fixture.bin").exists())

    def test_disposable_cache_only_after_age_and_exact_receipt(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            result=guard.prune(self.root,48,False)
        self.assertEqual(result["actions"][0]["status"],"protected")
        self.assertTrue(marker.exists())

    def test_mark_refuses_evidence_inside_target(self):
        inside=self.cache/"evidence.json"
        inside.write_bytes(self.receipt.read_bytes())
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            with self.assertRaisesRegex(ValueError,"disposable target cache"):
                guard.mark(self.project,inside)

    def test_mark_refuses_incomplete_metadata(self):
        data=json.loads(self.receipt.read_text())
        del data["output_hashes"]
        self.receipt.write_text(json.dumps(data))
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            with self.assertRaisesRegex(ValueError,"SHA-256"):
                guard.mark(self.project,self.receipt)

    def test_mark_denied_during_active_build(self):
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=True):
            with self.assertRaisesRegex(ValueError,"build running"):
                guard.mark(self.project,self.receipt)
        self.assertFalse(guard.marker_path(self.cache).exists())

    def test_prune_rechecks_build_immediately_before_cargo_clean(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        m=json.loads(marker.read_text())
        m["qualified_at_epoch"]=time.time()-72*3600
        guard.atomic_json(marker,m)
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True),patch.object(guard,"size_of",return_value=100),patch.object(guard,"active_builds",side_effect=[False,True]),patch.object(guard.subprocess,"run",side_effect=AssertionError("cargo clean must not execute")):
            result=guard.prune(self.root,48,True)
        self.assertEqual(result["actions"][0]["status"],"protected")
        self.assertTrue((self.cache/"fixture.bin").exists())
        self.assertTrue(marker.exists())

    def test_checkout_status_includes_untracked_sources(self):
        from subprocess import CompletedProcess
        commands=[]
        def fake_run(command,**kwargs):
            commands.append(command)
            if "status" in command:
                return CompletedProcess(command,0,"","")
            return CompletedProcess(command,0,b"target/\0",b"")
        with patch.object(guard.subprocess,"run",side_effect=fake_run):
            self.assertTrue(guard.git_clean(self.project))
        self.assertIn("--untracked-files=all",commands[0])
        self.assertIn("--ignored",commands[1])

    def test_ignored_build_input_blocks_exact_head_qualification(self):
        from subprocess import CompletedProcess
        for ignored in (b".cargo/config.toml\0",b"build.rs\0",b"crates/\0"):
            with self.subTest(ignored=ignored):
                def fake_run(command,**kwargs):
                    if "status" in command:
                        return CompletedProcess(command,0,"","")
                    return CompletedProcess(command,0,ignored,b"")
                with patch.object(guard.subprocess,"run",side_effect=fake_run):
                    self.assertFalse(guard.git_clean(self.project))

    def test_cross_project_target_receipt_rejected_during_mark(self):
        other=self.root/"other"/"target"
        other.mkdir(parents=True)
        copy=other/"important-proof.json"
        copy.write_bytes(self.receipt.read_bytes())
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            with self.assertRaisesRegex(ValueError,"disposable target cache"):
                guard.mark(self.project,copy)
        self.assertFalse(guard.marker_path(self.cache).exists())

    def test_older_cross_project_receipt_refuses_prune(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        item=json.loads(marker.read_text())
        other=self.root/"other"/"target"
        other.mkdir(parents=True)
        copy=other/"proof.json"
        copy.write_bytes(self.receipt.read_bytes())
        item["receipt"]=str(copy)
        item["receipt_sha256"]=guard.sha(copy)
        item["qualified_at_epoch"]=time.time()-72*3600
        guard.atomic_json(marker,item)
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            result=guard.prune(self.root,48,True)
        self.assertEqual(result["actions"][0]["status"],"protected")
        self.assertIn("disposable target cache",result["actions"][0]["reason"])
        self.assertTrue((self.cache/"fixture.bin").exists())

    def test_build_race_before_marker_write_fails_closed(self):
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(
            guard,"active_builds",side_effect=[False,True]):
            with self.assertRaisesRegex(ValueError,"build started"):
                guard.mark(self.project,self.receipt)
        self.assertFalse(guard.marker_path(self.cache).exists())

    def test_source_race_before_marker_write_fails_closed(self):
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",side_effect=[True,False]),patch.object(
            guard,"active_builds",return_value=False):
            with self.assertRaisesRegex(ValueError,"checkout changed"):
                guard.mark(self.project,self.receipt)
        self.assertFalse(guard.marker_path(self.cache).exists())

    def test_real_git_ignored_cargo_config_blocks_marking(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            repo=Path(temporary)
            (repo/"Cargo.toml").write_text("[package]\nname='test'\nversion='0.1.0'\nedition='2021'\n")
            (repo/".gitignore").write_text("target/\n.cargo/config.toml\n")
            (repo/"target").mkdir()
            (repo/"target"/"fixture").write_text("synthetic compiled file")
            subprocess.run(["git","init","-q"],cwd=repo,check=True,capture_output=True)
            subprocess.run(["git","add","Cargo.toml",".gitignore"],cwd=repo,check=True,capture_output=True)
            subprocess.run(["git","-c","user.name=Test","-c","user.email=test@example.invalid",
                            "commit","-qm","test fixture"],cwd=repo,check=True,capture_output=True)
            self.assertTrue(guard.git_clean(repo))
            (repo/".cargo").mkdir()
            (repo/".cargo"/"config.toml").write_text("[build]\nrustflags=['-C', 'target-cpu=native']\n")
            self.assertFalse(guard.git_clean(repo))
            (repo/".cargo"/"config.toml").unlink()
            self.assertTrue(guard.git_clean(repo))

    def test_receipt_mutated_after_parse_cannot_publish_marker(self):
        calls=[0]
        def change_during_final_check():
            calls[0]+=1
            if calls[0]==2:
                self.receipt.write_text('{"status":"PASS","tampered_after_parse":true}')
            return False
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(
            guard,"active_builds",side_effect=change_during_final_check):
            with self.assertRaisesRegex(ValueError,"receipt missing or altered"):
                guard.mark(self.project,self.receipt)
        self.assertFalse(guard.marker_path(self.cache).exists())

    def test_receipt_changes_during_size_scan_prevents_cleanup(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        metadata=json.loads(marker.read_text())
        metadata["qualified_at_epoch"]=time.time()-72*3600
        guard.atomic_json(marker,metadata)
        def mutate_on_size(_):
            self.receipt.write_text('{"status":"tampered-after-initial-check"}')
            return 112
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(
            guard,"size_of",side_effect=mutate_on_size),patch.object(
            guard,"active_builds",return_value=False),patch.object(
            guard.subprocess,"run",side_effect=AssertionError("cargo clean must never run")):
            result=guard.prune(self.root,48,True)
        self.assertEqual(result["actions"][0]["status"],"protected")
        self.assertIn("receipt missing or altered",result["actions"][0]["reason"])
        self.assertTrue((self.cache/"fixture.bin").exists())
        self.assertTrue(marker.exists())

    def test_exact_head_changes_during_mark_fail_closed(self):
        with patch.object(guard,"git_head",side_effect=["a"*40,"b"*40]),patch.object(
            guard,"git_clean",return_value=True),patch.object(
            guard,"active_builds",return_value=False):
            with self.assertRaisesRegex(ValueError,"source head or checkout changed"):
                guard.mark(self.project,self.receipt)
        self.assertFalse(guard.marker_path(self.cache).exists())

if __name__=="__main__":
    unittest.main()
