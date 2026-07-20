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
if lock.get("status") != "incomplete_phase0c_candidate":
    raise SystemExit("Contract lock must remain explicitly incomplete before authorization")
if lock.get("network_resolution_allowed") is not False:
    raise SystemExit("Network schema resolution must remain disabled")

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
