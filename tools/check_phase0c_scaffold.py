#!/usr/bin/env python3
"""Validate that Phase 0C scaffolding cannot be mistaken for an authorized runtime."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

readme = (ROOT / "README.md").read_text(encoding="utf-8")
if "Runtime implementation is not authorized" not in readme:
    raise SystemExit("README no-build boundary missing")

lock = json.loads((ROOT / "contracts/upstream-lock.json").read_text(encoding="utf-8"))
allowed_lock_states = {
    "incomplete_phase0c_candidate",
    "frozen_catalogs_locked_binding_generation_open",
}
if lock.get("status") not in allowed_lock_states:
    raise SystemExit("Contract lock state is not an accepted Phase 0C preparation state")
if lock.get("network_resolution_allowed") is not False:
    raise SystemExit("Network schema resolution must remain disabled")

if lock.get("status") == "frozen_catalogs_locked_binding_generation_open":
    catalogs = lock.get("catalogs")
    if lock.get("catalog_count") != 14 or not isinstance(catalogs, list) or len(catalogs) != 14:
        raise SystemExit("Frozen catalog lock must contain exactly fourteen active catalogs")
    if lock.get("generated_bindings") is not None:
        raise SystemExit("Generated bindings cannot be claimed before the binding gate passes")
    blockers = lock.get("blockers")
    if not isinstance(blockers, list) or not any("Generate Rust bindings" in item for item in blockers):
        raise SystemExit("Catalog-locked state must retain the generated-binding blocker")

host = json.loads((ROOT / "host/image-lock.json").read_text(encoding="utf-8"))
if host.get("runtime_authorized") is not False:
    raise SystemExit("Host candidate cannot claim runtime authorization")

forbidden_gateway = "applied" + "-caas-gateway"
skip_roots = {".git", "target", "node_modules"}
for path in ROOT.rglob("*"):
    relative = path.relative_to(ROOT)
    if not path.is_file() or any(part in skip_roots for part in relative.parts):
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    if forbidden_gateway in text:
        raise SystemExit(f"Internal package gateway leaked into {relative}")

print("Phase 0C non-claiming scaffold checks passed")
