#!/usr/bin/env python3
"""App Recover read-only, static native-export entry point.

No donor executable is started. Imports App Recover from an explicitly
configured checkout rather than copying private source into Ptah.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 3
    root, source, destination = map(Path, argv)
    if not (root / "native_export_recovery.py").is_file():
        print("App Recover backend file unavailable", file=sys.stderr)
        return 3
    sys.path.insert(0, str(root))
    from native_export_recovery import recover_native_exports
    result = recover_native_exports(source, destination)
    (destination / "driver_receipt.json").write_text(
        json.dumps({
            "backend": "app_recover",
            "source_sha256": result.get("input_sha256"),
            "is_pe": result.get("is_pe"),
            "export_count": result.get("export_count"),
            "action_candidate_count": result.get("action_candidate_count"),
            "donor_executed": False,
            "error": result.get("error"),
        }, indent=2) + "\n",
        encoding="utf-8",
    )
    if result.get("error"):
        print(str(result["error"])[:500], file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
