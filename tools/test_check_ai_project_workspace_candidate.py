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
    def assert_invalid(self, repo: Path, pattern: str) -> None:
        with self.assertRaisesRegex(MODULE.CandidateError, pattern):
            MODULE.validate_candidate(repo)

    def test_repository_candidate_is_valid_neutral_and_non_operative(self) -> None:
        report = MODULE.validate_candidate(REPO_ROOT)
        self.assertEqual(report["status"], "candidate_valid_non_operative")
        self.assertEqual(report["profile_id"], "ptah.workspace.ai_project.v1")
        self.assertEqual(report["official_source_count"], 5)
        self.assertEqual(report["composed_primitive_count"], 16)
        self.assertEqual(report["mapping_count"], 14)
        self.assertEqual(report["fixture_count"], 10)
        self.assertTrue(report["neutral_substrate_boundary_restored"])
        self.assertFalse(report["ptah_decision_authority"])
        self.assertFalse(report["ptah_context_selection_authority"])
        self.assertFalse(report["ptah_review_authority"])
        self.assertFalse(report["frozen_contract_change_required"])
        self.assertFalse(report["runtime_implementation_authorized"])

    def test_runtime_authorization_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["runtime_implementation_authorized"] = True
            store(path, value)
            self.assert_invalid(repo, "cannot authorize")

    def test_ptah_decision_authority_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["decision_authority"] = True
            store(path, value)
            self.assert_invalid(repo, "decision authority")

    def test_context_selection_cannot_move_to_ptah(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["context_selection_owner"] = "ptah_core"
            store(path, value)
            self.assert_invalid(repo, "responsibility owner")

    def test_source_authority_cannot_move_to_ptah(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["source_authority_owner"] = "ptah_core"
            store(path, value)
            self.assert_invalid(repo, "responsibility owner")

    def test_review_authority_cannot_move_to_ptah(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["review_authority_owner"] = "ptah_core"
            store(path, value)
            self.assert_invalid(repo, "responsibility owner")

    def test_next_action_cannot_move_to_ptah(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["next_action_owner"] = "ptah_core"
            store(path, value)
            self.assert_invalid(repo, "responsibility owner")

    def test_contract_reopen_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-gap-map.json"
            value = load(path)
            value["frozen_contract_change_required"] = True
            store(path, value)
            self.assert_invalid(repo, "frozen contract change")

    def test_project_memory_must_remain_caller_owned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-gap-map.json"
            value = load(path)
            for item in value["mappings"]:
                if item["capability"] == "project memory":
                    item["classification"] = "covered_by_neutral_substrate"
            value["summary"]["caller_application_composition"] -= 1
            value["summary"]["covered_by_neutral_substrate"] += 1
            store(path, value)
            self.assert_invalid(repo, "caller-owned")

    def test_conflicting_labels_cannot_gain_a_ptah_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/fixtures/ai-project-workspace-fixtures.json"
            value = load(path)
            for item in value["fixtures"]:
                if item["id"] == "conflicting-labels-no-ranking":
                    item["expected"] = "ptah_selects_canonical"
            store(path, value)
            self.assert_invalid(repo, "must not rank")

    def test_sergeant_review_cannot_become_ptah_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/fixtures/ai-project-workspace-fixtures.json"
            value = load(path)
            for item in value["fixtures"]:
                if item["id"] == "sergeant-review-no-ptah-verdict":
                    item["expected"] = "ptah_approves_candidate"
            store(path, value)
            self.assert_invalid(repo, "must not become a Ptah verdict")

    def test_archived_session_relevance_cannot_be_decided_by_ptah(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/fixtures/ai-project-workspace-fixtures.json"
            value = load(path)
            for item in value["fixtures"]:
                if item["id"] == "archived-session-discoverability":
                    item["expected"] = "exclude_as_irrelevant"
            store(path, value)
            self.assert_invalid(repo, "relevance decisions")

    def test_old_ptah_context_compiler_wording_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/PTAH-AI-PROJECT-WORKSPACE-PROFILE.md"
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\nBefore an agent begins or resumes an Activity, Ptah should compile a bounded context packet.\n",
                encoding="utf-8",
            )
            self.assert_invalid(repo, "forbidden decision-authority text")

    def test_old_bridge_promotion_wording_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/HUNTER-PTAH-WORKSPACE-BRIDGE.md"
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\nPromotion requires the Workspace's applicable acceptance policy.\n",
                encoding="utf-8",
            )
            self.assert_invalid(repo, "forbidden decision-authority text")

    def test_missing_official_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/donors/openai-chatgpt-projects-work.md"
            text = path.read_text(encoding="utf-8").replace(
                "https://help.openai.com/en/articles/20001275/chatgpt-work-and-codex",
                "missing-source",
            )
            path.write_text(text, encoding="utf-8")
            self.assert_invalid(repo, "official-source set")

    def test_new_core_entity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "design/candidates/ai-project-workspace-profile.json"
            value = load(path)
            value["new_core_entity_required"] = True
            store(path, value)
            self.assert_invalid(repo, "new Core entity")

    def test_obsolete_readme_licence_state_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "README.md"
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\nApache-2.0 owner acceptance is still pending.\n",
                encoding="utf-8",
            )
            self.assert_invalid(repo, "obsolete Apache")


if __name__ == "__main__":
    unittest.main()
