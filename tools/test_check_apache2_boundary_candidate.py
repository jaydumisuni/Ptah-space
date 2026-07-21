from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("check_apache2_boundary_candidate.py")
SPEC = importlib.util.spec_from_file_location(
    "check_apache2_boundary_candidate", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REPO_ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def candidate_copy(root: Path) -> Path:
    repo = root / "repo"
    (repo / "legal").mkdir(parents=True)
    shutil.copytree(REPO_ROOT / "legal" / "candidates", repo / "legal" / "candidates")
    return repo


class Apache2BoundaryCandidateTests(unittest.TestCase):
    def test_repository_candidate_is_valid_and_non_operative(self) -> None:
        report = MODULE.validate_candidate(REPO_ROOT)
        self.assertEqual(report["status"], "candidate_valid_non_operative")
        self.assertEqual(report["official_license_size_bytes"], 11358)
        self.assertEqual(
            report["official_license_sha256"],
            "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
        )
        self.assertFalse(report["apache_2_0_accepted"])
        self.assertFalse(report["runtime_implementation_authorized"])

    def test_operative_root_license_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            (repo / "LICENSE").write_text("premature\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.BoundaryError, "operative root file"):
                MODULE.validate_candidate(repo)

    def test_modified_official_license_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "legal" / "candidates" / "LICENSE.apache-2.0.txt"
            path.write_text(path.read_text() + "modified\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.BoundaryError, "size mismatch"):
                MODULE.validate_candidate(repo)

    def test_candidate_cannot_claim_apache_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "legal" / "candidates" / "apache-2.0-boundary.json"
            record = json.loads(path.read_text())
            record["apache_2_0_accepted"] = True
            write_json(path, record)
            with self.assertRaisesRegex(MODULE.BoundaryError, "cannot accept"):
                MODULE.validate_candidate(repo)

    def test_candidate_cannot_select_owner_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "legal" / "candidates" / "apache-2.0-boundary.json"
            record = json.loads(path.read_text())
            record["owner_identity"]["accepted_value"] = (
                "John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS"
            )
            write_json(path, record)
            with self.assertRaisesRegex(MODULE.BoundaryError, "silently selects"):
                MODULE.validate_candidate(repo)

    def test_candidate_cannot_authorize_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "legal" / "candidates" / "apache-2.0-boundary.json"
            record = json.loads(path.read_text())
            record["runtime_implementation_authorized"] = True
            write_json(path, record)
            with self.assertRaisesRegex(MODULE.BoundaryError, "cannot authorize"):
                MODULE.validate_candidate(repo)

    def test_notice_owner_placeholder_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "legal" / "candidates" / "NOTICE.candidate.txt"
            path.write_text(
                path.read_text().replace(
                    "[COPYRIGHT OWNER TO CONFIRM]", "Premature Owner"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.BoundaryError, "missing required text"):
                MODULE.validate_candidate(repo)

    def test_private_customer_and_donor_exclusions_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = candidate_copy(Path(directory))
            path = repo / "legal" / "candidates" / "apache-2.0-boundary.json"
            record = json.loads(path.read_text())
            record["private_not_permitted_in_public_repository"].remove(
                "customer or client personal data"
            )
            write_json(path, record)
            with self.assertRaisesRegex(MODULE.BoundaryError, "customer-data exclusion"):
                MODULE.validate_candidate(repo)


if __name__ == "__main__":
    unittest.main()
