#!/usr/bin/env python3
"""Phase 0C placeholder: refuses to claim a host report until implemented and reviewed."""
from __future__ import annotations

import json
import sys

print(json.dumps({
    "status": "not_implemented",
    "runtime_authorized": False,
    "message": "Host capability collection is a Phase 0C blocker."
}, indent=2))
raise SystemExit(2)
