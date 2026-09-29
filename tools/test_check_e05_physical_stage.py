import json
import tempfile
from pathlib import Path

from check_e05_physical_stage import REQUIRED_STAGES, validate


def write_status(root: Path, **updates) -> Path:
    stages = {
        name: {"admission_proven": False, "blockers": ["proof pending"]}
        for name in REQUIRED_STAGES
    }
    data = {
        "record_type": "ptah.e05.physical_platform_stage_status",
        "stages": stages,
        "complete_physical_e05_proof": False,
        "merge_readiness_from_physical_proof": False,
    }
    data.update(updates)
    path = root / "status.json"
    path.write_text(json.dumps(data))
    return path


def with_temp_status(checker) -> None:
    with tempfile.TemporaryDirectory() as td:
        checker(Path(td))


def test_current_blocked_shape_is_valid() -> None:
    with_temp_status(lambda root: _assert_current_shape(root))


def _assert_current_shape(root: Path) -> None:
    assert validate(write_status(root)) == []


def test_missing_required_stage_fails_closed() -> None:
    def check(root: Path) -> None:
        path = write_status(root)
        data = json.loads(path.read_text())
        data["stages"].pop("macos")
        path.write_text(json.dumps(data))
        assert "missing stages: macos" in validate(path)
    with_temp_status(check)


def test_unproven_stage_requires_explicit_blocker() -> None:
    def check(root: Path) -> None:
        path = write_status(root)
        data = json.loads(path.read_text())
        data["stages"]["windows"]["blockers"] = []
        path.write_text(json.dumps(data))
        assert "windows: blocked stage must name at least one blocker" in validate(path)
    with_temp_status(check)


def test_admitted_stage_cannot_retain_blocker() -> None:
    def check(root: Path) -> None:
        path = write_status(root)
        data = json.loads(path.read_text())
        data["stages"]["windows"]["admission_proven"] = True
        path.write_text(json.dumps(data))
        assert "windows: admitted stage cannot retain blockers" in validate(path)
    with_temp_status(check)


def test_complete_proof_rejects_any_unproven_stage() -> None:
    def check(root: Path) -> None:
        path = write_status(root, complete_physical_e05_proof=True)
        assert "complete proof cannot be true while a stage is unproven" in validate(path)
    with_temp_status(check)


def test_merge_readiness_requires_complete_physical_proof() -> None:
    def check(root: Path) -> None:
        path = write_status(root, merge_readiness_from_physical_proof=True)
        assert "merge readiness requires complete physical proof" in validate(path)
    with_temp_status(check)


def main() -> None:
    test_current_blocked_shape_is_valid()
    test_missing_required_stage_fails_closed()
    test_unproven_stage_requires_explicit_blocker()
    test_admitted_stage_cannot_retain_blocker()
    test_complete_proof_rejects_any_unproven_stage()
    test_merge_readiness_requires_complete_physical_proof()
    print("E05_PHYSICAL_STAGE_REGRESSIONS_PASS")


if __name__ == "__main__":
    main()
