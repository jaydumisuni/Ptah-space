# SPDX-FileCopyrightText: 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS
# SPDX-License-Identifier: Apache-2.0
"""Discover the existing Ptah workspace using the caller's machine access.

Oracle (or another independently selected machine transport) opens the host
session. Ptah does not authenticate, approve, schedule or replace that access.
This locator is read-only and does not depend on a Control/Node listener.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

_NAME = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
_AREAS = ("workspaces", "worktrees", "evidence", "recovery", "proof-history")


class WorkspaceUnavailable(ValueError):
    """An expected local Ptah workspace cannot be identified safely."""


def _directory(parent: Path, name: str) -> Path:
    path = parent / name
    if path.is_symlink() or not path.is_dir():
        raise WorkspaceUnavailable(f"Ptah area unavailable or symlinked: {name}")
    if path.resolve() != path:
        raise WorkspaceUnavailable(f"Ptah area moved outside canonical root: {name}")
    return path


class LocalPtahWorkspace:
    """Read-only view of an existing Ptah root for independent agent callers."""

    def __init__(self, root: str | Path):
        provided = Path(root).expanduser()
        if provided.is_symlink():
            raise WorkspaceUnavailable("Ptah root must not be a symlink")
        try:
            resolved = provided.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise WorkspaceUnavailable("Ptah root missing or unreadable") from exc
        if not resolved.is_dir():
            raise WorkspaceUnavailable("expected an existing Ptah directory")
        self.root = resolved
        self.state = _directory(resolved, ".workspace")

    def caller_view(self, caller: str) -> dict[str, Any]:
        if not isinstance(caller, str) or not _NAME.fullmatch(caller):
            raise WorkspaceUnavailable("caller label must be bounded")
        areas: dict[str, str] = {}
        entries: dict[str, list[str]] = {}
        missing: list[str] = []
        for name in _AREAS:
            path = self.state / name
            if not path.exists() and not path.is_symlink():
                missing.append(name)
                continue
            path = _directory(self.state, name)
            areas[name] = str(path)
            entries[name] = sorted(
                p.name for p in path.iterdir()
                if p.is_dir() and not p.is_symlink()
            )
        return {
            "schema": "ptah.local-workspace-discovery.v1",
            "caller_label": caller,
            "ptah_root": str(self.root),
            "repository": str(self.root) if (self.root / ".git").exists() else None,
            "workspace_root": str(self.state),
            "git_checkout_present": (self.root / ".git").exists(),
            "missing_optional_areas": missing,
            "areas": areas,
            "directory_names": entries,
            "transport": "provided_by_caller_outside_ptah",
            "control_listener_required": False,
            "execution_authorized_by_discovery": False,
            "approval_authority": "unchanged",
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect an existing local Ptah workspace")
    parser.add_argument("--root", required=True, help="Existing Ptah checkout path on this host")
    parser.add_argument("--caller", required=True, help="Informational agent label")
    args = parser.parse_args()
    print(json.dumps(LocalPtahWorkspace(args.root).caller_view(args.caller),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
