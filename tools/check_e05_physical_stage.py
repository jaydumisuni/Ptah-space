#!/usr/bin/env python3
import json, sys
from pathlib import Path

REQUIRED_STAGES = {"always_on_linux", "android_device", "macos", "windows", "workstation_gpu"}

def validate(path: Path) -> list[str]:
    data = json.loads(path.read_text())
    errors = []
    if data.get("record_type") != "ptah.e05.physical_platform_stage_status":
        errors.append("wrong record_type")
    stages = data.get("stages")
    if not isinstance(stages, dict):
        return errors + ["stages must be an object"]
    missing = REQUIRED_STAGES - stages.keys()
    if missing:
        errors.append("missing stages: " + ",".join(sorted(missing)))
    for name, stage in stages.items():
        if not isinstance(stage, dict):
            errors.append(f"{name}: stage must be an object")
            continue
        admitted = stage.get("admission_proven")
        blockers = stage.get("blockers")
        if not isinstance(admitted, bool):
            errors.append(f"{name}: admission_proven must be boolean")
        if not isinstance(blockers, list):
            errors.append(f"{name}: blockers must be a list")
        elif admitted and blockers:
            errors.append(f"{name}: admitted stage cannot retain blockers")
        elif not admitted and not blockers:
            errors.append(f"{name}: blocked stage must name at least one blocker")
    if data.get("complete_physical_e05_proof") is True and any(not s.get("admission_proven", False) for s in stages.values() if isinstance(s, dict)):
        errors.append("complete proof cannot be true while a stage is unproven")
    if data.get("merge_readiness_from_physical_proof") is True and data.get("complete_physical_e05_proof") is not True:
        errors.append("merge readiness requires complete physical proof")
    return errors

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_e05_physical_stage.py <status.json>", file=sys.stderr)
        return 2
    errors = validate(Path(sys.argv[1]))
    if errors:
        print("E05_PHYSICAL_STAGE_FAIL")
        for error in errors:
            print(error)
        return 1
    print("E05_PHYSICAL_STAGE_PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
