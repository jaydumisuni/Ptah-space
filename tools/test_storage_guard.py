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
            result=guard.prune(self.root,48,True)
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
            if "submodule" in command:
                return CompletedProcess(command,0,"","")
            return CompletedProcess(command,0,b"target/\0",b"")
        with patch.object(guard.subprocess,"run",side_effect=fake_run),patch.object(
            guard,"cargo_paths_inside_checkout",return_value=True):
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

    def test_real_git_submodule_ignore_all_cannot_hide_changed_build_inputs(self):
        import subprocess
        def git(cwd,*args):
            return subprocess.run(["git",*args],cwd=cwd,check=True,
                                  capture_output=True,text=True).stdout.strip()
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary)
            child=folder/"upstream-module"
            parent=folder/"parent"
            child.mkdir();parent.mkdir()
            git(child,"init","-q")
            (child/"Cargo.toml").write_text("[package]\nname='sub'\nversion='0.1.0'\nedition='2021'\n")
            (child/"src").mkdir()
            (child/"src"/"lib.rs").write_text("pub fn value() -> u32 { 1 }\n")
            git(child,"add",".")
            git(child,"-c","user.name=Fixture","-c","user.email=fixture@example.invalid",
                "commit","-qm","first version")
            git(parent,"init","-q")
            (parent/"Cargo.toml").write_text("[package]\nname='parent'\nversion='0.1.0'\nedition='2021'\n")
            (parent/".gitignore").write_text("target/\n")
            git(parent,"add",".")
            git(parent,"-c","user.name=Fixture","-c","user.email=fixture@example.invalid",
                "commit","-qm","root")
            git(parent,"-c","protocol.file.allow=always","submodule","add","-q",
                str(child),"vendor/module")
            git(parent,"config","-f",".gitmodules","submodule.vendor/module.ignore","all")
            git(parent,"add",".gitmodules","vendor/module")
            git(parent,"-c","user.name=Fixture","-c","user.email=fixture@example.invalid",
                "commit","-qm","add ignored-status submodule")
            module=parent/"vendor"/"module"
            self.assertTrue(guard.git_clean(parent))
            (module/"src"/"lib.rs").write_text("pub fn value() -> u32 { 999 }\n")
            self.assertFalse(guard.git_clean(parent))
            git(module,"checkout","--","src/lib.rs")
            self.assertTrue(guard.git_clean(parent))
            (module/"build.rs").write_text("fn main() {}\n")
            self.assertFalse(guard.git_clean(parent))
            (module/"build.rs").unlink()
            self.assertTrue(guard.git_clean(parent))
            (module/".cargo").mkdir()
            (module/".cargo"/"config.toml").write_text("[build]\nrustflags=['-C','target-cpu=native']\n")
            self.assertFalse(guard.git_clean(parent))

    def test_retention_clock_starts_only_after_final_validation(self):
        calls=[]
        def fingerprint(_):
            calls.append("fingerprint")
            return "f"*64
        def clock():
            calls.append("clock")
            return 12345678
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(
            guard,"active_builds",return_value=False),patch.object(
            guard,"cache_fingerprint",side_effect=fingerprint),patch.object(
            guard.time,"time",side_effect=clock):
            guard.mark(self.project,self.receipt)
        self.assertEqual(calls,["fingerprint","fingerprint","clock"])
        marker=json.loads(guard.marker_path(self.cache).read_text())
        self.assertEqual(marker["qualified_at_epoch"],12345678)

    def test_real_git_external_cargo_path_dependency_denied(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            repo=root/"repo";repo.mkdir()
            outside=root/"shared";outside.mkdir()
            (outside/"Cargo.toml").write_text("[package]\nname='shared'\nversion='0.1.0'\nedition='2021'\n")
            (repo/"Cargo.toml").write_text(
                "[package]\nname='fixture'\nversion='0.1.0'\nedition='2021'\n"
                "[dependencies]\nshared={ path='../shared' }\n")
            subprocess.run(["git","init","-q"],cwd=repo,check=True)
            subprocess.run(["git","add","Cargo.toml"],cwd=repo,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","external dep"],cwd=repo,check=True)
            self.assertFalse(guard.git_clean(repo))
            internal=repo/"vendor"/"shared"
            internal.mkdir(parents=True)
            (internal/"Cargo.toml").write_text((outside/"Cargo.toml").read_text())
            (repo/"Cargo.toml").write_text(
                "[package]\nname='fixture'\nversion='0.1.0'\nedition='2021'\n"
                "[dependencies]\nshared={ path='vendor/shared' }\n")
            subprocess.run(["git","add","."],cwd=repo,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","vendored dep"],cwd=repo,check=True)
            self.assertTrue(guard.git_clean(repo))

    def test_cache_change_between_two_inventory_passes_rejected(self):
        real_walk=guard.os.walk
        passes=[0]
        def changing_walk(*args,**kwargs):
            passes[0]+=1
            if passes[0]==2:
                (self.cache/"fixture.bin").write_bytes(b"modified during second pass")
            yield from real_walk(*args,**kwargs)
        with patch.object(guard.os,"walk",side_effect=changing_walk):
            with self.assertRaisesRegex(ValueError,"cache changed during inventory"):
                guard.cache_fingerprint(self.cache)
        self.assertEqual(passes[0],2)

    def test_cache_file_inserted_between_inventory_passes_rejected(self):
        real_walk=guard.os.walk
        passes=[0]
        def adding_walk(*args,**kwargs):
            passes[0]+=1
            if passes[0]==2:
                (self.cache/"new-artifact.bin").write_bytes(b"not in first scan")
            yield from real_walk(*args,**kwargs)
        with patch.object(guard.os,"walk",side_effect=adding_walk):
            with self.assertRaisesRegex(ValueError,"cache changed during inventory"):
                guard.cache_fingerprint(self.cache)

    def test_real_git_cargo_config_external_paths_denied(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            project=root/"repo";project.mkdir()
            outside=root/"shared";outside.mkdir()
            (outside/"Cargo.toml").write_text("[package]\nname='shared'\nversion='0.1.0'\n")
            (project/"Cargo.toml").write_text("[package]\nname='repo'\nversion='0.1.0'\nedition='2021'\n")
            (project/".cargo").mkdir()
            config=project/".cargo"/"config.toml"
            config.write_text("paths = ['../../shared']\n")
            subprocess.run(["git","init","-q"],cwd=project,check=True)
            subprocess.run(["git","add","."],cwd=project,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","external config"],cwd=project,check=True)
            self.assertFalse(guard.git_clean(project))
            (project/"vendor").mkdir()
            (project/"vendor"/"local").mkdir()
            config.write_text("paths = ['../vendor/local']\n")
            subprocess.run(["git","add","."],cwd=project,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","internal config"],cwd=project,check=True)
            # Even an internal Cargo config path override is not admitted
            # automatically: its effective base depends on Cargo config rules.
            self.assertFalse(guard.git_clean(project))
            config.unlink()
            subprocess.run(["git","add","-A"],cwd=project,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","remove override"],cwd=project,check=True)
            self.assertTrue(guard.git_clean(project))

    def test_global_cargo_config_paths_must_not_supply_build_inputs(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            repo=root/"repo";repo.mkdir()
            (repo/"Cargo.toml").write_text("[package]\nname='repo'\nversion='0.1.0'\nedition='2021'\n")
            subprocess.run(["git","init","-q"],cwd=repo,check=True)
            subprocess.run(["git","add","."],cwd=repo,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","clean"],cwd=repo,check=True)
            home=root/"cargo";home.mkdir()
            (home/"config.toml").write_text("paths = ['../shared']\n")
            with patch.dict(guard.os.environ,{"CARGO_HOME":str(home)}):
                self.assertFalse(guard.git_clean(repo))

    def test_cargo_config_include_and_descendant_config_fail_closed(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory)/"repo";repo.mkdir()
            (repo/"Cargo.toml").write_text(
                "[workspace]\nmembers = ['member']\nresolver='2'\n")
            member=repo/"member";member.mkdir()
            (member/"Cargo.toml").write_text(
                "[package]\nname='member'\nversion='0.1.0'\nedition='2021'\n")
            subprocess.run(["git","init","-q"],cwd=repo,check=True)
            subprocess.run(["git","add","."],cwd=repo,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","workspace"],cwd=repo,check=True)
            self.assertTrue(guard.git_clean(repo))
            cfg=member/".cargo";cfg.mkdir()
            (cfg/"config.toml").write_text("paths = ['../../../external']\n")
            subprocess.run(["git","add","."],cwd=repo,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","member config"],cwd=repo,check=True)
            self.assertFalse(guard.git_clean(repo))
            (cfg/"config.toml").write_text("include = ['local.toml']\n")
            (cfg/"local.toml").write_text("paths = ['../../outside']\n")
            subprocess.run(["git","add","."],cwd=repo,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","config include"],cwd=repo,check=True)
            self.assertFalse(guard.git_clean(repo))
            (cfg/"config.toml").unlink()
            (cfg/"local.toml").unlink()
            subprocess.run(["git","add","-A"],cwd=repo,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","no config overrides"],cwd=repo,check=True)
            self.assertTrue(guard.git_clean(repo))

    def test_same_device_bind_mount_inside_target_denied_by_mount_namespace(self):
        with patch.object(guard,"_mount_points",return_value=[
            self.root,self.cache/"bind-on-same-device"
        ]):
            with self.assertRaisesRegex(ValueError,"mount point inside"):
                guard.cache_fingerprint(self.cache)

    def test_mount_namespace_unavailable_denies_fingerprint(self):
        with patch.object(guard,"_mount_points",side_effect=ValueError("mount namespace unavailable")):
            with self.assertRaisesRegex(ValueError,"mount namespace unavailable"):
                guard.cache_fingerprint(self.cache)

    def test_tracked_symlink_to_mutable_external_source_is_not_qualified(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            repo=base/"repo";repo.mkdir()
            external=base/"library.rs";external.write_text("pub fn value() -> u8 { 1 }\n")
            (repo/"Cargo.toml").write_text("[package]\nname='lib'\nversion='0.1.0'\nedition='2021'\n")
            (repo/"src").mkdir()
            (repo/"src"/"lib.rs").symlink_to(external)
            subprocess.run(["git","init","-q"],cwd=repo,check=True)
            subprocess.run(["git","add","."],cwd=repo,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","external source symlink"],cwd=repo,check=True)
            self.assertFalse(guard.git_clean(repo))

    def test_cargo_source_replacement_local_registry_rejected(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory)/"repo";repo.mkdir()
            (repo/"Cargo.toml").write_text("[package]\nname='lib'\nversion='0.1.0'\nedition='2021'\n")
            (repo/".cargo").mkdir()
            (repo/".cargo"/"config.toml").write_text(
                "[source.crates-io]\nreplace-with='local'\n"
                "[source.local]\nlocal-registry='/outside/registry'\n")
            subprocess.run(["git","init","-q"],cwd=repo,check=True)
            subprocess.run(["git","add","."],cwd=repo,check=True)
            subprocess.run(["git","-c","user.name=Fixture","-c",
                "user.email=fixture@example.invalid","commit","-qm","override"],cwd=repo,check=True)
            self.assertFalse(guard.git_clean(repo))

    def test_receipt_commands_with_cargo_cli_overrides_rejected(self):
        for command in ("cargo --config /outside/override.toml test",
                        "cargo test --config='paths=[\"/tmp/foreign\"]'",
                        "CARGO_HOME=/outside cargo test --locked",
                        "RUSTFLAGS='-L /outside' cargo build"):
            with self.subTest(command=command):
                receipt=json.loads(self.receipt.read_text())
                receipt["commands"]=[command]
                self.receipt.write_text(json.dumps(receipt))
                with patch.object(guard,"git_clean",return_value=True),patch.object(
                    guard,"git_head",return_value="a"*40),patch.object(
                    guard,"active_builds",return_value=False):
                    with self.assertRaisesRegex(ValueError,"unbound Cargo configuration"):
                        guard.mark(self.project,self.receipt)
        self.assertFalse(guard.marker_path(self.cache).exists())

    def test_uninitialized_submodule_is_never_exact_head(self):
        from subprocess import CompletedProcess
        with patch.object(guard,"_checkout_inputs_clean",return_value=True),patch.object(
            guard,"cargo_paths_inside_checkout",return_value=True),patch.object(
            guard,"_external_cargo_overrides_safe",return_value=True),patch.object(
            guard.subprocess,"run",return_value=CompletedProcess(
                ["git","submodule","status"],0,"-"+
                "0"*40+" missing/module\n","")):
            self.assertFalse(guard.git_clean(self.project))

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

    def test_caller_cannot_shorten_48_hour_minimum(self):
        for requested in (0,1,24,47):
            with self.subTest(requested=requested),self.assertRaisesRegex(ValueError,"minimum 48 hours"):
                guard.prune(self.root,requested,True)
        self.assertTrue((self.cache/"fixture.bin").exists())

    def test_cache_rebuild_restarts_qualification_requirement(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        old=json.loads(marker.read_text())
        old["qualified_at_epoch"]=time.time()-72*3600
        guard.atomic_json(marker,old)
        (self.cache/"new-build-artifact.bin").write_bytes(b"rebuilt after qualification")
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            output=guard.prune(self.root,48,True)
        self.assertEqual(output["actions"][0]["status"],"protected")
        self.assertIn("cache changed since qualification",output["actions"][0]["reason"])
        self.assertTrue((self.cache/"fixture.bin").exists())

    def test_replaced_target_does_not_inherit_previous_qualification(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        old=json.loads(marker.read_text())
        old["qualified_at_epoch"]=time.time()-72*3600
        guard.atomic_json(marker,old)
        (self.cache/"fixture.bin").unlink()
        self.cache.rmdir()
        self.cache.mkdir()
        (self.cache/"replacement.bin").write_bytes(b"new generation")
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            output=guard.prune(self.root,48,True)
        self.assertEqual(output["actions"][0]["status"],"protected")
        self.assertTrue((self.cache/"replacement.bin").exists())

    def test_legacy_marker_without_tree_identity_is_never_cleaned(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        old=json.loads(marker.read_text())
        old.pop("cache_fingerprint")
        old["qualified_at_epoch"]=time.time()-72*3600
        guard.atomic_json(marker,old)
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False):
            output=guard.prune(self.root,48,True)
        self.assertEqual(output["actions"][0]["status"],"protected")
        self.assertIn("requalification required",output["actions"][0]["reason"])

    def test_cache_modification_during_size_scan_blocks_destructive_call(self):
        self.qualify()
        marker=guard.marker_path(self.cache)
        old=json.loads(marker.read_text())
        old["qualified_at_epoch"]=time.time()-72*3600
        guard.atomic_json(marker,old)
        def change_cache(_):
            (self.cache/"new.bin").write_bytes(b"new build")
            return 200
        with patch.object(guard,"git_head",return_value="a"*40),patch.object(
            guard,"git_clean",return_value=True),patch.object(guard,"active_builds",return_value=False),patch.object(
            guard,"size_of",side_effect=change_cache),patch.object(
            guard.subprocess,"run",side_effect=AssertionError("no destructive invocation")):
            output=guard.prune(self.root,48,True)
        self.assertEqual(output["actions"][0]["status"],"protected")
        self.assertIn("cache changed immediately before cleanup",output["actions"][0]["reason"])
        self.assertTrue((self.cache/"new.bin").exists())

if __name__=="__main__":
    unittest.main()
