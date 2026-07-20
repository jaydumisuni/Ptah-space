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

for path in ROOT.rglob("*"):
    if path.is_file() and path.name not in {"package-lock.json"}:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "applied-caas-gateway" in text:
            raise SystemExit(f"Internal package gateway leaked into {path.relative_to(ROOT)}")

print("Phase 0C non-claiming scaffold checks passed")
