#!/usr/bin/env python3
"""Check same-run backend evidence against the immutable Phase 0C lock."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


class LockError(RuntimeError):
    """Raised when downloaded evidence does not match the committed lock."""


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LockError(f"JSON root must be an object: {path}")
    return value


def check_static(lock: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    if lock.get("runtime_implementation_authorized") is not False:
        raise LockError("backend lock cannot authorize runtime implementation")
    if report.get("runtime_implementation_authorized") is not False:
        raise LockError("backend report cannot authorize runtime implementation")

    entries = lock.get("artifacts")
    results = report.get("results")
    if not isinstance(entries, list) or not isinstance(results, list):
        raise LockError("artifact lock or report arrays are missing")
    result_by_component = {
        item.get("component"): item for item in results if isinstance(item, dict)
    }

    checked: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise LockError("artifact entry is not an object")
        component = entry.get("component")
        result = result_by_component.get(component)
        if not isinstance(component, str) or not isinstance(result, dict):
            raise LockError(f"same-run evidence missing for {component!r}")
        if result.get("filename") != entry.get("filename"):
            raise LockError(f"filename mismatch for {component}")
        if result.get("digest") != entry.get("digest"):
            raise LockError(f"digest mismatch between lock and evidence for {component}")

        if component == "nodejs":
            expected_manifest = entry.get("checksum_manifest_sha256")
            if result.get("signed_checksum_manifest_sha256") != expected_manifest:
                raise LockError("Node signed checksum manifest digest mismatch")
        if component == "git-source":
            expected_manifest = entry.get("signed_checksum_manifest_sha256")
            if result.get("signed_checksum_manifest_sha256") != expected_manifest:
                raise LockError("Git signed checksum manifest digest mismatch")
        checked.append(component)

    if len(checked) != report.get("verified_artifact_count"):
        raise LockError("verified artifact count does not match the immutable lock")
    return {
        "locked_artifact_count": len(checked),
        "components": sorted(checked),
    }


def check_browser(
    lock: dict[str, Any], descriptors: dict[str, Any], tree: dict[str, Any]
) -> dict[str, Any]:
    browser = lock.get("browser_binary")
    if not isinstance(browser, dict):
        raise LockError("browser binary lock is missing")
    if browser.get("runtime_implementation_authorized") is not False:
        raise LockError("browser lock cannot authorize runtime implementation")
    if tree.get("runtime_implementation_authorized") is not False:
        raise LockError("browser evidence cannot authorize runtime implementation")

    browsers = descriptors.get("browsers")
    if not isinstance(browsers, list):
        raise LockError("Playwright browser descriptors are missing")
    chromium = next(
        (
            item
            for item in browsers
            if isinstance(item, dict) and item.get("name") == "chromium"
        ),
        None,
    )
    if not isinstance(chromium, dict):
        raise LockError("Playwright Chromium descriptor is missing")
    if str(chromium.get("revision")) != str(browser.get("revision")):
        raise LockError("Playwright Chromium revision mismatch")
    if chromium.get("browserVersion") != browser.get("browser_version"):
        raise LockError("Playwright Chromium version mismatch")
    if tree.get("tree_sha256") != browser.get("installed_tree_sha256"):
        raise LockError("Playwright installed tree digest mismatch")
    if tree.get("file_count") != browser.get("installed_file_count"):
        raise LockError("Playwright installed file count mismatch")
    if tree.get("size_bytes") != browser.get("installed_size_bytes"):
        raise LockError("Playwright installed size mismatch")

    executables = tree.get("executables")
    expected_executable = browser.get("executable")
    if not isinstance(executables, list) or not isinstance(expected_executable, dict):
        raise LockError("Playwright executable evidence is missing")
    if expected_executable not in executables:
        raise LockError("Playwright Chromium executable does not match the lock")

    return {
        "revision": str(chromium.get("revision")),
        "browser_version": chromium.get("browserVersion"),
        "tree_sha256": tree.get("tree_sha256"),
        "file_count": tree.get("file_count"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lock", type=Path, default=ROOT / "dependencies/backend-artifact-lock.json"
    )
    parser.add_argument("--static-report", type=Path)
    parser.add_argument("--browser-descriptors", type=Path)
    parser.add_argument("--browser-tree", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    lock = load_object(args.lock)
    result: dict[str, Any] = {
        "schema_version": "0.1.0",
        "record_type": "ptah.phase0c.backend_artifact_lock_check",
        "runtime_implementation_authorized": False,
    }
    if args.static_report:
        result["static"] = check_static(lock, load_object(args.static_report))
    if args.browser_descriptors or args.browser_tree:
        if not args.browser_descriptors or not args.browser_tree:
            raise LockError("both Browser evidence paths are required")
        result["browser"] = check_browser(
            lock,
            load_object(args.browser_descriptors),
            load_object(args.browser_tree),
        )
    if "static" not in result and "browser" not in result:
        raise LockError("no evidence was supplied")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
