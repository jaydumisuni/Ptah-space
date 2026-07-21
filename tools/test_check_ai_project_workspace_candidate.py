from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("check_ai_project_workspace_candidate.py")
SPEC = importlib.util.spec_from_file_location("workspace_candidate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REPO_ROOT = Path(__file__).resolve().parents[1]

CANDIDATE_PATHS = [
    "README.md",
    "design/donors/openai-chatgpt-projects-work.md",
    "design/candidates/ai-project-workspace-profile.json",
    "design/candidates/ai-project-workspace-gap-map.json",
    "design/candidates/PTAH-AI-PROJECT-WORKSPACE-PROFILE.md",
    "design/candidates/HUNTER-PTAH-WORKSPACE-BRIDGE.md",
    "design/candidates/fixtures/ai-project-workspace-fixtures.json",
]


def candidate_copy(root: Path) -> Path:
    repo = root / "repo"
    for relative in CANDIDATE_PATHS:
        source = REPO_ROOT / relative
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return repo


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def store(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class AIProjectWorkspaceCandidateTests(unittest.TestCase):
    def test_repository_candidate_is_valid_and_non_operative(self) -> None:
        report = MODULE.validate_candidate(REPO_ROOT)
        self.assertEqual(report["status"], "candidate_valid_non_operative")
        self.assertEqual(report["profile_id"], "ptah.workspace.ai_project.v1")
        self.assertEqual(report["official_source_count"], 5)
        self.assertEqual(report["composed_primitive_count"], 16)
        self.assertEqual(report["mapping_count"], 14)
        self.assertEqual(report["fixture_count"], 10)
        self.assertFalse(report["frozen_contract_change_required"])
        self.assertFalse(report["runtime_implementation_authorized"])

    def test_runtime_authorization_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["runtime_implementation_authorized"] = True
            store(path, value)
            with self.assertRaisesRegex(MODULE.CandidateError, "cannot authorize"):
                MODULE.validate_candidate(repo)

    def test_new_core_entity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["new_core_entity_required"] = True
            store(path, value)
            with self.assertRaisesRegex(MODULE.CandidateError, "new core entity"):
                MODULE.validate_candidate(repo)

    def test_contract_reopen_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-gap-map.json"
            value = load(path)
            value["frozen_contract_change_required"] = True
            store(path, value)
            with self.assertRaisesRegex(MODULE.CandidateError, "frozen contract change"):
                MODULE.validate_candidate(repo)

    def test_missing_official_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/donors/openai-chatgpt-projects-work.md"
            text = path.read_text(encoding="utf-8").replace(
                "https://help.openai.com/en/articles/20001275/chatgpt-work-and-codex",
                "missing-source",
            )
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(MODULE.CandidateError, "official-source set"):
                MODULE.validate_candidate(repo)

    def test_hidden_provider_memory_cannot_be_adopted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-gap-map.json"
            value = load(path)
            for item in value["mappings"]:
                if item["capability"] == "hidden provider memory":
                    item["classification"] = "covered_by_profile_composition"
            value["summary"]["covered_by_profile_composition"] += 1
            value["summary"]["rejected_or_not_adopted"] -= 1
            store(path, value)
            with self.assertRaisesRegex(MODULE.CandidateError, "reviewed counts|hidden provider"):
                MODULE.validate_candidate(repo)

    def test_cross_workspace_fixture_must_deny(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/fixtures/ai-project-workspace-fixtures.json"
            value = load(path)
            for item in value["fixtures"]:
                if item["id"] == "workspace-isolation":
                    item["expected"] = "pass"
            store(path, value)
            with self.assertRaisesRegex(MODULE.CandidateError, "isolation fixture"):
                MODULE.validate_candidate(repo)

    def test_obsolete_readme_licence_state_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "README.md"
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\nApache-2.0 owner acceptance is still pending.\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.CandidateError, "obsolete Apache"):
                MODULE.validate_candidate(repo)

    def test_duplicate_fixture_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/fixtures/ai-project-workspace-fixtures.json"
            value = load(path)
            value["fixtures"][1]["id"] = value["fixtures"][0]["id"]
            store(path, value)
            with self.assertRaisesRegex(MODULE.CandidateError, "fixture identities"):
                MODULE.validate_candidate(repo)

    def test_authority_class_removal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["source_authority_classes"].remove("superseded")
            store(path, value)
            with self.assertRaisesRegex(MODULE.CandidateError, "authority classes"):
                MODULE.validate_candidate(repo)


if __name__ == "__main__":
    unittest.main()
