# SPDX-FileCopyrightText: 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS
# SPDX-License-Identifier: Apache-2.0
"""Windows-friendly Ptah access, independent of native Node enrollment."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ptah_local_workspace import LocalPtahWorkspace


class PartialWorkspaceWindowsTests(unittest.TestCase):
    def test_athena_style_workspace_without_git_or_node_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "Ptah-space"
            (root / ".workspace" / "worktrees").mkdir(parents=True)
            (root / ".workspace" / "evidence").mkdir()
            hunter = LocalPtahWorkspace(root).caller_view("hunter")
            chatgpt = LocalPtahWorkspace(root).caller_view("chatgpt")
            self.assertFalse(hunter["git_checkout_present"])
            self.assertIsNone(hunter["repository"])
            self.assertEqual(hunter["workspace_root"], chatgpt["workspace_root"])
            self.assertFalse(hunter["control_listener_required"])
            self.assertFalse(hunter["execution_authorized_by_discovery"])
            self.assertEqual(hunter["transport"], "provided_by_caller_outside_ptah")
            self.assertIn("proof-history", hunter["missing_optional_areas"])

    def test_real_cli_readback_does_not_create_missing_areas(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "Ptah-space"
            (root / ".workspace" / "worktrees").mkdir(parents=True)
            before = sorted(p.name for p in (root / ".workspace").iterdir())
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("ptah_local_workspace.py")),
                 "--root", str(root), "--caller", "hunter"],
                capture_output=True, text=True, check=True, timeout=15,
            )
            payload = json.loads(result.stdout)
            after = sorted(p.name for p in (root / ".workspace").iterdir())
            self.assertEqual(before, after)
            self.assertEqual(payload["caller_label"], "hunter")
            self.assertFalse(payload["git_checkout_present"])
            self.assertFalse(payload["execution_authorized_by_discovery"])


if __name__ == "__main__":
    unittest.main()
