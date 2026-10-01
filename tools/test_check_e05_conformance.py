import copy
import json
import tempfile
from pathlib import Path

from check_e05_conformance import check

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "conformance/e05/e05-conformance-cases.v0.1.0.json"
BASE = json.loads(CANONICAL.read_text())


def mutated(change):
    data = copy.deepcopy(BASE)
    change(data)
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        json.dump(data, handle)
        return Path(handle.name)
    finally:
        handle.close()


def assert_raises_assertion(path: Path) -> None:
    try:
        check(path)
    except AssertionError:
        return
    raise AssertionError(f"mutation unexpectedly passed: {path}")


def test_canonical_corpus_passes() -> None:
    assert check(CANONICAL)


def test_mutations_fail_closed() -> None:
    changes = [
        lambda d: d["cases"].pop(),
        lambda d: d["cases"].__setitem__(1, copy.deepcopy(d["cases"][0])),
        lambda d: d.__setitem__("accepted_predecessor", "0" * 40),
        lambda d: d.__setitem__("merge_claimed", True),
        lambda d: d["cases"][0].__setitem__("evidence", ["missing-proof"]),
    ]
    paths = []
    try:
        for change in changes:
            path = mutated(change)
            paths.append(path)
            assert_raises_assertion(path)
    finally:
        for path in paths:
            path.unlink(missing_ok=True)


def main() -> None:
    test_canonical_corpus_passes()
    test_mutations_fail_closed()
    print("E05_CONFORMANCE_REGRESSIONS_PASS")


if __name__ == "__main__":
    main()
