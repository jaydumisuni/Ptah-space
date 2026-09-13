from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

BASE_EXPECTED_SHA = "65d754df5f9d5bbca74f3385945d01486845fa255cc44f9c2cf32ca29c521dc3"
PRIME_EXPECTED_HEAD = "375ca5475d97d9378e5ecfd86ff2c24b5137c103"
ID_RE = re.compile(r"^#{2,4}\s+(PM-[A-Z0-9-]+)(?:\s+—.*)?\s*$", re.MULTILINE)

REQUIRED_LATEST_IDS = {
    "PM-RAB-GENESIS-001", "PM-ACR-GENESIS-001", "PM-EFFECT-001", "PM-RULE-010",
    "PM-CTRLPLANE-001", "PM-CTRLPLANE-002", "PM-CLOSE-005", "PM-CLOSE-006",
    "PM-CLOSE-007", "PM-CLOSE-008", "PM-WORLD-004", "PM-WORLD-005", "PM-WORLD-006",
    "PM-COMMIT-GUARD-001", "PM-COMMIT-001", "PM-DISCOP-001", "PM-DISCOP-002",
    "PM-DISCOP-003", "PM-DISCOP-004", "PM-DISCRELEASE-001", "PM-AUTHZ-004",
    "PM-AUTHZ-005", "PM-CONSENT-001", "PM-CONSENT-RENDER-001", "PM-OBLIG-001",
    "PM-OBLIG-002", "PM-OBLIG-003", "PM-CAB-005", "PM-QUIESCE-ADMIT-001",
    "PM-QUIESCE-ADMIT-002", "PM-RESERVE-001", "PM-AUDIT-RESERVE-001",
    "PM-CTRLSESS-006", "PM-POLICY-003", "PM-ADMISSION-RECEIPT-001",
    "PM-EVID-QUAL-001", "PM-DESC-RESOLVE-001", "PM-REQUEST-002",
    "PM-PROOF-CLOSURE-AUTH-001", "PM-PROOF-WORLD-FENCE-001", "PM-PROOF-DISCOP-001",
    "PM-PROOF-AUTH-CUTOVER-001", "PM-PROOF-CONSENT-STALE-001",
    "PM-PROOF-CONSENT-RENDER-001", "PM-PROOF-OBLIGATION-CYCLE-001",
    "PM-PROOF-CAB-CUTOVER-001", "PM-PROOF-WORK-ADMISSION-CLOSURE-001",
    "PM-PROOF-COMMIT-PLAN-001", "PM-PROOF-RESERVE-HOARD-001",
    "PM-PROOF-CONTROLSESSION-FENCE-001", "PM-PROOF-POLICY-COMPOSE-001",
    "PM-PROOF-OBLIGATION-UNIVERSE-001", "PM-PROOF-AUDIT-RESERVE-001",
    "PM-PROOF-DISCLOSURE-CUTOVER-001", "PM-PROOF-COMMIT-GUARD-001",
    "PM-PROOF-ADMISSION-RECEIPT-001", "PM-PROOF-EVIDENCE-QUAL-001",
    "PM-PROOF-DESCRIPTOR-RESOLUTION-001", "PM-PROOF-ATOMICITY-001",
    "PM-PROOF-MULTIPHASE-SAFETY-001",
}

PROOF_SUBJECTS = {
    "PM-PROOF-CLOSURE-AUTH-001": ["PM-CLOSE-005", "PM-CLOSE-006", "PM-CLOSE-007", "PM-CLOSE-008"],
    "PM-PROOF-WORLD-FENCE-001": ["PM-WORLD-004", "PM-WORLD-005", "PM-WORLD-006", "PM-COMMIT-GUARD-001"],
    "PM-PROOF-DISCOP-001": ["PM-DISCOP-001", "PM-DISCOP-002", "PM-DISCOP-003", "PM-DISCOP-004", "PM-DISCRELEASE-001"],
    "PM-PROOF-AUTH-CUTOVER-001": ["PM-AUTHZ-004", "PM-AUTHZ-005"],
    "PM-PROOF-CONSENT-STALE-001": ["PM-CONSENT-001"],
    "PM-PROOF-CONSENT-RENDER-001": ["PM-CONSENT-RENDER-001"],
    "PM-PROOF-OBLIGATION-CYCLE-001": ["PM-OBLIG-003"],
    "PM-PROOF-CAB-CUTOVER-001": ["PM-CAB-005"],
    "PM-PROOF-WORK-ADMISSION-CLOSURE-001": ["PM-QUIESCE-ADMIT-001", "PM-QUIESCE-ADMIT-002"],
    "PM-PROOF-COMMIT-PLAN-001": ["PM-COMMIT-001", "PM-COMMIT-GUARD-001"],
    "PM-PROOF-RESERVE-HOARD-001": ["PM-RESERVE-001", "PM-AUDIT-RESERVE-001"],
    "PM-PROOF-CONTROLSESSION-FENCE-001": ["PM-CTRLSESS-006"],
    "PM-PROOF-POLICY-COMPOSE-001": ["PM-POLICY-003"],
    "PM-PROOF-OBLIGATION-UNIVERSE-001": ["PM-OBLIG-001", "PM-OBLIG-002"],
    "PM-PROOF-AUDIT-RESERVE-001": ["PM-AUDIT-RESERVE-001"],
    "PM-PROOF-DISCLOSURE-CUTOVER-001": ["PM-DISCRELEASE-001"],
    "PM-PROOF-COMMIT-GUARD-001": ["PM-COMMIT-GUARD-001"],
    "PM-PROOF-ADMISSION-RECEIPT-001": ["PM-ADMISSION-RECEIPT-001"],
    "PM-PROOF-EVIDENCE-QUAL-001": ["PM-EVID-QUAL-001"],
    "PM-PROOF-DESCRIPTOR-RESOLUTION-001": ["PM-DESC-RESOLVE-001", "PM-DISCOP-004"],
    "PM-PROOF-ATOMICITY-001": ["PM-COMMIT-001"],
    "PM-PROOF-MULTIPHASE-SAFETY-001": ["PM-WORLD-004", "PM-COMMIT-GUARD-001"],
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assemble_base(root: Path, out: Path, expected_sha: str) -> str:
    parts = sorted(p for p in root.glob("base_[0-9][0-9]") if p.is_file())
    data = b"".join(p.read_bytes() for p in parts)
    digest = sha256_bytes(data)
    if digest != expected_sha:
        raise ValueError(f"base authority hash mismatch: {digest} != {expected_sha}")
    out.write_bytes(data)
    return digest


def extract_ids(text: str) -> list[str]:
    return ID_RE.findall(text)


def validate_contracts(base_text: str, overlay_text: str) -> dict:
    base_ids = extract_ids(base_text)
    overlay_ids = extract_ids(overlay_text)
    all_ids = base_ids + overlay_ids
    counts: dict[str, int] = {}
    for item in all_ids:
        counts[item] = counts.get(item, 0) + 1
    duplicates = sorted(k for k, v in counts.items() if v > 1)
    known = set(counts)
    missing_required = sorted(REQUIRED_LATEST_IDS - known)
    missing_subjects = {
        proof: sorted(subject for subject in subjects if subject not in known)
        for proof, subjects in PROOF_SUBJECTS.items()
        if proof in known and any(subject not in known for subject in subjects)
    }
    missing_proofs = sorted(proof for proof in PROOF_SUBJECTS if proof not in known)
    ok = not duplicates and not missing_required and not missing_subjects and not missing_proofs
    return {
        "ok": ok,
        "base_id_count": len(base_ids),
        "overlay_id_count": len(overlay_ids),
        "unique_id_count": len(known),
        "duplicate_ids": duplicates,
        "missing_required_ids": missing_required,
        "missing_proof_ids": missing_proofs,
        "missing_proof_subjects": missing_subjects,
    }


def composite_world_hash(base_sha: str, overlay_sha: str, prime_head: str, cookpit_head: str) -> str:
    payload = "\n".join([base_sha, overlay_sha, prime_head, cookpit_head]).encode()
    return sha256_bytes(payload)


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).strip()


def cli(mode: str) -> int:
    root = Path.cwd()
    base_path = root / "ROADMAP_BASE.md"
    overlay_path = root / "CHAT_AUTHORITY_AMENDMENTS.md"
    if not base_path.exists() or not overlay_path.exists():
        raise SystemExit("required review authority files are missing")
    base_bytes = base_path.read_bytes()
    base_sha = sha256_bytes(base_bytes)
    if base_sha != BASE_EXPECTED_SHA:
        raise SystemExit(f"base authority hash mismatch: {base_sha}")
    overlay_bytes = overlay_path.read_bytes()
    overlay_sha = sha256_bytes(overlay_bytes)
    report = validate_contracts(base_bytes.decode("utf-8"), overlay_bytes.decode("utf-8"))
    prime_head = run(["git", "-C", "/home/kratos/Prime-Manager", "rev-parse", "HEAD"])
    prime_status = run(["git", "-C", "/home/kratos/Prime-Manager", "status", "--porcelain"])
    cookpit_head = run(["git", "-C", "/home/kratos/cookpit", "rev-parse", "HEAD"])
    report.update({
        "mode": mode,
        "base_sha256": base_sha,
        "overlay_sha256": overlay_sha,
        "prime_manager_head": prime_head,
        "prime_manager_expected_head": PRIME_EXPECTED_HEAD,
        "prime_manager_clean": prime_status == "",
        "cookpit_head": cookpit_head,
        "review_world_sha256": composite_world_hash(base_sha, overlay_sha, prime_head, cookpit_head),
    })
    if prime_head != PRIME_EXPECTED_HEAD or prime_status:
        report["ok"] = False
    if mode == "heavy":
        report["heavy_checks"] = {
            "all_overlay_proofs_mapped": all(p in PROOF_SUBJECTS for p in extract_ids(overlay_bytes.decode("utf-8")) if p.startswith("PM-PROOF-")),
            "base_exact_bytes": len(base_bytes) == 103455,
            "latest_amendment_ids_present": not report["missing_required_ids"],
        }
        if not all(report["heavy_checks"].values()):
            report["ok"] = False
    out = root / f"gate-report-{mode}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("micro", "heavy"), required=True)
    args = parser.parse_args()
    return cli(args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
