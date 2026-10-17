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
            "allow_disposable_cleanup":True
        }))
        self.saved_state=guard.STATE
        guard.STATE=self.root/"state"
        self.addCleanup(setattr,guard,"STATE",self.saved_state)

    def qualify(self):
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True):
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
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True):
            with self.assertRaises(ValueError):
                guard.mark(self.project,self.receipt)

    def test_missing_pass_or_explicit_cleanup_fails_closed(self):
        self.receipt.write_text(json.dumps({"status":"FAIL","head":"a"*40,"tests":["sample"],"evidence_ref":"fixture://x"}))
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(guard,"git_clean",return_value=True):
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
if __name__=="__main__":
    unittest.main()
