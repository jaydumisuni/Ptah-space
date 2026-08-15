#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

import check_a01_scaffold as checker


class A01ScaffoldValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = Path(__file__).resolve().parents[1]

    def copy_repository(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="ptah-a01-scaffold-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        shutil.copytree(
            self.source,
            root,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(".git", "target", "node_modules", "conformance"),
        )
        return root

    @contextmanager
    def rooted(self, root: Path):
        old_root = checker.ROOT
        old_contract = checker.CONTRACT_PATH
        checker.ROOT = root
        checker.CONTRACT_PATH = root / "a01/scaffold-contract.json"
        try:
            yield
        finally:
            checker.ROOT = old_root
            checker.CONTRACT_PATH = old_contract

    def validate(self, root: Path) -> dict:
        with self.rooted(root):
            return checker.validate(root)

    def invalid(self, root: Path) -> None:
        with self.rooted(root):
            with self.assertRaises(checker.ValidationError):
                checker.validate(root)

    def mutate_json(self, root: Path, relative: str, path: tuple[str, ...], value: object) -> None:
        target = root / relative
        data = json.loads(target.read_text(encoding="utf-8"))
        cursor = data
        for key in path[:-1]:
            cursor = cursor[key]
        cursor[path[-1]] = value
        target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def test_01_current_scaffold_static_invariants_pass(self) -> None:
        report = self.validate(self.copy_repository())
        self.assertEqual(report["status"], "a01_scaffold_static_invariants_passed")
        self.assertEqual(report["workspace"]["member_count"], 18)
        self.assertEqual(report["contracts"]["catalog_count"], 14)
        self.assertEqual(report["contracts"]["schema_count"], 346)
        self.assertEqual(report["contracts"]["state_machine_count"], 99)
        self.assertFalse(report["runtime_semantics_implemented"])

    def test_02_workspace_member_drift_fails(self) -> None:
        root = self.copy_repository()
        cargo = root / "Cargo.toml"
        cargo.write_text(cargo.read_text(encoding="utf-8").replace('  "crates/ptah-ledger",\n', "", 1), encoding="utf-8")
        self.invalid(root)

    def test_03_network_schema_resolution_fails(self) -> None:
        root = self.copy_repository()
        self.mutate_json(root, "contracts/upstream-lock.json", ("network_resolution_allowed",), True)
        self.invalid(root)

    def test_04_generated_digest_drift_fails(self) -> None:
        root = self.copy_repository()
        path = root / "contracts/generated/manifest.json"
        path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.invalid(root)

    def test_05_git_dependency_policy_drift_fails(self) -> None:
        root = self.copy_repository()
        self.mutate_json(root, "dependencies/rust-direct-lock.json", ("selection_policy", "git_dependencies_allowed"), True)
        self.invalid(root)

    def test_06_cargo_lock_digest_drift_fails(self) -> None:
        root = self.copy_repository()
        path = root / "Cargo.lock"
        path.write_text(path.read_text(encoding="utf-8") + "# drift\n", encoding="utf-8")
        self.invalid(root)

    def test_07_browser_pin_drift_fails(self) -> None:
        root = self.copy_repository()
        self.mutate_json(root, "browser-provider/package.json", ("dependencies", "playwright"), "1.59.0")
        self.invalid(root)

    def test_08_unpinned_action_fails(self) -> None:
        root = self.copy_repository()
        workflow = root / ".github/workflows/phase0c-contract-lock.yml"
        text = workflow.read_text(encoding="utf-8")
        text = text.replace("actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405", "actions/setup-python@v6", 1)
        workflow.write_text(text, encoding="utf-8")
        self.invalid(root)

    def test_09_missing_licence_boundary_fails(self) -> None:
        root = self.copy_repository()
        (root / "REUSE.toml").unlink()
        self.invalid(root)

    def test_10_historical_phase0c_claim_rewrite_fails(self) -> None:
        root = self.copy_repository()
        path = root / "PHASE0C_SCAFFOLD.md"
        path.write_text(path.read_text(encoding="utf-8").replace("candidate scaffold only", "runtime accepted", 1), encoding="utf-8")
        self.invalid(root)

    def test_11_a01_runtime_semantics_claim_fails(self) -> None:
        root = self.copy_repository()
        self.mutate_json(root, "a01/scaffold-contract.json", ("runtime_semantics_implemented",), True)
        self.invalid(root)

    def test_12_prime_or_release_claim_boundary_fails(self) -> None:
        root = self.copy_repository()
        self.mutate_json(root, "a01/scaffold-contract.json", ("claim_boundary", "a01_does_not_prove_prime_integration"), False)
        self.invalid(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
