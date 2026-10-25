#!/usr/bin/env python3
"""Admit only unchanged protected root manifests or the reviewed Tokio pin update."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

OLD = b'tokio = { version = "=1.48.0",'
NEW = b'tokio = { version = "=1.53.3",'


def verify_root_manifest(base: bytes, proposed: bytes) -> None:
    if proposed == base:
        # The protected base already owns its exact dependency state.
        return
    if base.count(OLD) != 1:
        raise ValueError("unrecognized_frozen_root_manifest")
    if proposed != base.replace(OLD, NEW, 1):
        raise ValueError("unreviewed_root_manifest_change")


def committed_manifest(sha: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid_exact_commit_sha")
    return subprocess.check_output(
        ["git", "show", f"{sha}:Cargo.toml"], timeout=30
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_hunter_bridge_root_manifest.py BASE_SHA HEAD_SHA", file=sys.stderr)
        return 2
    try:
        base = committed_manifest(argv[0])
        head = committed_manifest(argv[1])
        if pathlib.Path("Cargo.toml").read_bytes() != head:
            raise ValueError("unreviewed_worktree_root_manifest")
        verify_root_manifest(base, head)
    except (ValueError, subprocess.SubprocessError, OSError) as exc:
        print(f"root manifest admission denied: {exc}", file=sys.stderr)
        return 1
    print("PTAH_HUNTER_ROOT_MANIFEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
