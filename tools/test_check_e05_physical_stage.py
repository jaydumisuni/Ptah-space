import json
from pathlib import Path

from check_e05_physical_stage import REQUIRED_STAGES, validate


def write_status(tmp_path: Path, **updates) -> Path:
    stages = {name: {"admission_proven": False, "blockers": ["proof pending"]} for name in REQUIRED_STAGES}
    data = {
        "record_type": "ptah.e05.physical_platform_stage_status",
        "stages": stages,
        "complete_physical_e05_proof": False,
        "merge_readiness_from_physical_proof": False,
    }
    data.update(updates)
    path = tmp_path / "status.json"
    path.write_text(json.dumps(data))
    return path


def test_current_blocked_shape_is_valid(tmp_path):
    assert validate(write_status(tmp_path)) == []


def test_missing_required_stage_fails_closed(tmp_path):
    path = write_status(tmp_path)
    data = json.loads(path.read_text())
    data["stages"].pop("macos")
    path.write_text(json.dumps(data))
    assert "missing stages: macos" in validate(path)


def test_unproven_stage_requires_explicit_blocker(tmp_path):
    path = write_status(tmp_path)
    data = json.loads(path.read_text())
    data["stages"]["windows"]["blockers"] = []
    path.write_text(json.dumps(data))
    assert "windows: blocked stage must name at least one blocker" in validate(path)


def test_admitted_stage_cannot_retain_blocker(tmp_path):
    path = write_status(tmp_path)
    data = json.loads(path.read_text())
    data["stages"]["windows"]["admission_proven"] = True
    path.write_text(json.dumps(data))
    assert "windows: admitted stage cannot retain blockers" in validate(path)


def test_complete_proof_rejects_any_unproven_stage(tmp_path):
    path = write_status(tmp_path, complete_physical_e05_proof=True)
    assert "complete proof cannot be true while a stage is unproven" in validate(path)


def test_merge_readiness_requires_complete_physical_proof(tmp_path):
    path = write_status(tmp_path, merge_readiness_from_physical_proof=True)
    assert "merge readiness requires complete physical proof" in validate(path)
