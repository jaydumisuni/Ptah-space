"""Read-only local Ptah discovery, independent of optional Node enrollment."""
import tempfile
import unittest
from pathlib import Path

from ptah_local_workspace import LocalPtahWorkspace, WorkspaceUnavailable


class LocalWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / "Ptah-space"
        self.base.mkdir()
        (self.base / ".git").mkdir()
        for name in ("workspaces", "worktrees", "evidence", "recovery", "proof-history"):
            (self.base / ".workspace" / name).mkdir(parents=True)
        (self.base / ".workspace" / "workspaces" / "project-a").mkdir()
        (self.base / ".workspace" / "worktrees" / "feature-a").mkdir()

    def test_hunter_and_chatgpt_have_the_same_canonical_root(self):
        locator = LocalPtahWorkspace(self.base)
        hunter = locator.caller_view("hunter")
        chatgpt = locator.caller_view("chatgpt")
        self.assertEqual(hunter["repository"], chatgpt["repository"])
        self.assertEqual(hunter["areas"], chatgpt["areas"])
        self.assertFalse(hunter["control_listener_required"])
        self.assertFalse(hunter["execution_authorized_by_discovery"])
        self.assertEqual(hunter["directory_names"]["workspaces"], ["project-a"])

    def test_no_git_checkout_or_workspace_is_not_ptah(self):
        with self.assertRaises(WorkspaceUnavailable):
            LocalPtahWorkspace(Path(self.temp.name))
        (self.base / ".workspace").rename(self.base / "missing-state")
        with self.assertRaises(WorkspaceUnavailable):
            LocalPtahWorkspace(self.base)

    def test_partial_workspace_without_git_remains_discoverable(self):
        (self.base / ".git").rmdir()
        (self.base / ".workspace" / "proof-history").rmdir()
        view = LocalPtahWorkspace(self.base).caller_view("hunter")
        self.assertFalse(view["git_checkout_present"])
        self.assertIsNone(view["repository"])
        self.assertEqual(view["ptah_root"], str(self.base.resolve()))
        self.assertIn("proof-history", view["missing_optional_areas"])
        self.assertNotIn("proof-history", view["areas"])
        self.assertIn("workspaces", view["areas"])

    def test_symlinked_root_or_area_is_rejected(self):
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(WorkspaceUnavailable):
            LocalPtahWorkspace(alias)
        area = self.base / ".workspace" / "evidence"
        area.rmdir()
        area.symlink_to(Path(self.temp.name), target_is_directory=True)
        with self.assertRaises(WorkspaceUnavailable):
            LocalPtahWorkspace(self.base).caller_view("hunter")

    def test_rejects_invalid_caller_names(self):
        locator = LocalPtahWorkspace(self.base)
        for name in ("../../outside", "", "HUNTER", "tool name", "a" * 90):
            with self.subTest(name=name), self.assertRaises(WorkspaceUnavailable):
                locator.caller_view(name)


if __name__ == "__main__":
    unittest.main()
