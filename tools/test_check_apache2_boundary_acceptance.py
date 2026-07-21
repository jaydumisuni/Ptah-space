from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("check_apache2_boundary_acceptance.py")
SPEC = importlib.util.spec_from_file_location(
    "check_apache2_boundary_acceptance", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

OWNER = MODULE.EXPECTED_OWNER


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def init_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Ptah Test"], check=True
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "config",
            "user.email",
            "ptah@example.invalid",
        ],
        check=True,
    )


def synthetic_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    init_repo(repo)
    license_bytes = b"x" * MODULE.EXPECTED_LICENSE_SIZE
    for relative in (
        "LICENSE",
        "LICENSES/Apache-2.0.txt",
        "legal/candidates/LICENSE.apache-2.0.txt",
    ):
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(license_bytes)
    write_json(
        repo / "legal/candidates/apache-2.0-boundary.json",
        {
            "apache_2_0_accepted": False,
            "runtime_implementation_authorized": False,
            "owner_identity": {"accepted_value": None},
        },
    )
    write_json(
        repo / "legal/apache-2.0-boundary.json",
        {
            "record_type": "ptah.phase0c.apache_2_0_boundary",
            "status": "owner_accepted_operative",
            "spdx_license": "Apache-2.0",
            "operative_root_files_present": True,
            "apache_2_0_accepted": True,
            "runtime_implementation_authorized": False,
            "owner_identity": {
                "status": "owner_confirmed",
                "accepted_value": OWNER,
            },
            "private_not_permitted_in_public_repository": [
                "customer or client personal data",
                "device identifiers or customer device evidence",
                "credentials, secrets, tokens, private keys or production configuration",
                "Hunter private memory, prompts, knowledge stores or model data",
                "THETECHGUY private Domain Packs",
                "restricted device-recovery, bypass or unlock adapters",
                "payment-provider secrets, transaction records or internal finance data",
                "private technician procedures, customer cases or forensic records",
                "production deployment state, infrastructure inventory or incident evidence",
                "unlicensed donor source or proprietary third-party material",
            ],
            "remaining_phase0c_blockers": [
                "physical pinned-host proof",
                "package review",
                "durable retention",
                "closure review",
            ],
        },
    )
    (repo / "NOTICE").write_text(
        f"Ptah\nCopyright 2026 {OWNER}\n\n"
        "This product includes software developed for the Ptah project.\n",
        encoding="utf-8",
    )
    (repo / "CONTRIBUTING.md").write_text(
        "Status: operative\nApache License, Version 2.0\nNot a Contribution\n"
        "Until CURRENT_STATE.md says Runtime implementation: AUTHORIZED, no runtime.\n"
        "REUSE.toml\n",
        encoding="utf-8",
    )
    (repo / "SECURITY.md").write_text(
        "Status: operative\nsupport@thetechguyds.com\n[PTAH SECURITY]\n"
        "runtime implementation remains unauthorized\n",
        encoding="utf-8",
    )
    (repo / "legal/APACHE-2.0-OWNER-ACCEPTANCE.md").write_text(
        f"{OWNER}\nApache-2.0 accepted: YES\n"
        "Runtime implementation authorized: NO\n",
        encoding="utf-8",
    )
    (repo / "legal/THIRD-PARTY-NOTICE-REVIEW.md").write_text(
        "Status: reviewed\nNo root NOTICE attribution entries are required\n"
        "Runtime implementation remains unauthorized\n",
        encoding="utf-8",
    )
    (repo / "REUSE.toml").write_text(
        f'''version = 1

[[annotations]]
path = "**"
precedence = "override"
SPDX-FileCopyrightText = "2026 {OWNER}"
SPDX-License-Identifier = "Apache-2.0"

[[annotations]]
path = [
  "LICENSE",
  "LICENSES/Apache-2.0.txt",
  "legal/candidates/LICENSE.apache-2.0.txt",
]
precedence = "override"
SPDX-FileCopyrightText = "NONE"
SPDX-License-Identifier = "Apache-2.0"
''',
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    return repo


class Apache2BoundaryAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_digest = MODULE.EXPECTED_LICENSE_SHA256
        MODULE.EXPECTED_LICENSE_SHA256 = MODULE.hashlib.sha256(
            b"x" * MODULE.EXPECTED_LICENSE_SIZE
        ).hexdigest()

    def tearDown(self) -> None:
        MODULE.EXPECTED_LICENSE_SHA256 = self.original_digest

    def test_valid_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = MODULE.validate_acceptance(synthetic_repo(Path(directory)))
            self.assertEqual(
                report["status"], "owner_accepted_operative_verified"
            )
            self.assertTrue(report["apache_2_0_accepted"])
            self.assertFalse(report["runtime_implementation_authorized"])

    def test_modified_license_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = synthetic_repo(Path(directory))
            (repo / "LICENSE").write_bytes(b"y" * MODULE.EXPECTED_LICENSE_SIZE)
            with self.assertRaisesRegex(MODULE.AcceptanceError, "SHA-256 mismatch"):
                MODULE.validate_acceptance(repo)

    def test_wrong_owner_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = synthetic_repo(Path(directory))
            path = repo / "legal/apache-2.0-boundary.json"
            record = json.loads(path.read_text())
            record["owner_identity"]["accepted_value"] = "Wrong Owner"
            write_json(path, record)
            with self.assertRaisesRegex(
                MODULE.AcceptanceError, "owner identity mismatch"
            ):
                MODULE.validate_acceptance(repo)

    def test_runtime_authorization_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = synthetic_repo(Path(directory))
            path = repo / "legal/apache-2.0-boundary.json"
            record = json.loads(path.read_text())
            record["runtime_implementation_authorized"] = True
            write_json(path, record)
            with self.assertRaisesRegex(
                MODULE.AcceptanceError, "cannot authorize runtime"
            ):
                MODULE.validate_acceptance(repo)

    def test_notice_placeholder_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = synthetic_repo(Path(directory))
            (repo / "NOTICE").write_text(
                "Ptah\n[COPYRIGHT OWNER TO CONFIRM]\n"
                "software developed for the Ptah project\n"
            )
            with self.assertRaisesRegex(
                MODULE.AcceptanceError, "missing required text"
            ):
                MODULE.validate_acceptance(repo)

    def test_private_exclusion_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = synthetic_repo(Path(directory))
            path = repo / "legal/apache-2.0-boundary.json"
            record = json.loads(path.read_text())
            record["private_not_permitted_in_public_repository"][0] = (
                "different private item"
            )
            write_json(path, record)
            with self.assertRaisesRegex(
                MODULE.AcceptanceError, "customer-data exclusion"
            ):
                MODULE.validate_acceptance(repo)

    def test_reuse_owner_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = synthetic_repo(Path(directory))
            path = repo / "REUSE.toml"
            path.write_text(
                path.read_text().replace(
                    f"2026 {OWNER}", "2026 Wrong Owner", 1
                )
            )
            with self.assertRaisesRegex(MODULE.AcceptanceError, "REUSE owner mismatch"):
                MODULE.validate_acceptance(repo)


if __name__ == "__main__":
    unittest.main()
