from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("run_pinned_host_proof.py")
SPEC = importlib.util.spec_from_file_location("run_pinned_host_proof", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_exact_frozen_host_identity_passes() -> None:
    os_release = {
        "ID": "ubuntu",
        "VERSION_ID": "24.04",
        "VERSION": "24.04.4 LTS (Noble Numbat)",
        "PRETTY_NAME": "Ubuntu 24.04.4 LTS",
    }
    assert MODULE.validate_host(os_release, "6.8.0-136-generic", "x86_64") == []


def test_generic_host_is_not_proof_eligible() -> None:
    os_release = {
        "ID": "ubuntu",
        "VERSION_ID": "24.04",
        "VERSION": "24.04.3 LTS",
        "PRETTY_NAME": "Ubuntu 24.04.3 LTS",
    }
    failures = MODULE.validate_host(os_release, "6.17.0-azure", "x86_64")
    assert any(item.startswith("point_release_not_found") for item in failures)
    assert any(item.startswith("kernel=") for item in failures)


def test_package_digest_is_order_sensitive_until_records_are_sorted() -> None:
    first = [{"package": "a"}, {"package": "b"}]
    second = list(reversed(first))
    assert MODULE.canonical_sha256(first) != MODULE.canonical_sha256(second)
    assert MODULE.canonical_sha256(sorted(first, key=lambda item: item["package"])) == MODULE.canonical_sha256(
        sorted(second, key=lambda item: item["package"])
    )


def test_json_writer_uses_stable_utf8(tmp_path: Path) -> None:
    target = tmp_path / "record.json"
    MODULE.write_json(target, {"runtime_implementation_authorized": False, "value": "Ptah"})
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["runtime_implementation_authorized"] is False
    assert target.read_bytes().endswith(b"\n")
