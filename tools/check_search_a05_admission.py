#!/usr/bin/env python3
"""Additive exact-head scope proof for optional A05 Search admission.

This never overrides the historical E01-E05/A01/Phase0C proofs, deploys
anything, or pretends to validate signed backend custody. It is only an
additional fail-closed PR-scope gate; separate existing required checks remain.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SEARCH_PATHS=frozenset({
    "README.md",
    "adapters/internet-search/README.md",
    "adapters/internet-search/bridge.py",
    "adapters/internet-search/test/test_bridge.py",
    "adapters/internet-search/test/test_operator.py",
    "adapters/native-process/tests/a05_ttgs_search_integration.rs",
    "docs/TTG_INTERNET_SEARCH_PROVIDER_2026-10-15.md",
    "tools/ptah_internet_search.py",
})
REMEDIATION_PATHS=frozenset({
    "Cargo.toml","Cargo.lock",
    "crates/ptah-platform-admission/Cargo.toml",
    "crates/ptah-workspace-movement/Cargo.toml",
    "dependencies/rust-direct-lock.json",
})
HEX40=re.compile(r"^[0-9a-f]{40}$")
PINNED_WHEEL_SHA256="eaecd49153225e1b9c2972fa89d24edde69975e6dd15a7b05230c302fd7d65c4"

class AdmissionError(RuntimeError):
    pass

def approved_paths(changed: set[str]) -> dict:
    if not changed:
        raise AdmissionError("empty_search_delta")
    if not SEARCH_PATHS.issubset(changed):
        raise AdmissionError("missing_exact_search_delta: "+str(sorted(SEARCH_PATHS-changed)))
    extra=changed-SEARCH_PATHS
    if extra and extra!=REMEDIATION_PATHS:
        raise AdmissionError("unapproved_or_partial_remediation_delta: "+str(sorted(extra^REMEDIATION_PATHS)))
    if any(x.startswith((".github/workflows/","contracts/","migrations/","schemas/"))
           for x in changed):
        raise AdmissionError("frozen_authority_or_workflow_change")
    return {
        "search_paths":sorted(SEARCH_PATHS),
        "rust_remediation_paths":sorted(extra),
        "rust_remediation_complete":extra==REMEDIATION_PATHS,
        "historical_phase_delta":"NONE",
        "historical_proof_disposition":"NOT_APPLICABLE_TO_THIS_DELTA_NOT_TESTED",
    }

def git(*args: str)->str:
    proc=subprocess.run(["git",*args],cwd=ROOT,text=True,capture_output=True,check=False,timeout=40)
    if proc.returncode:
        raise AdmissionError("git_command_failed: "+proc.stderr[-260:])
    return proc.stdout.strip()

def qualify(base: str,head: str)->dict:
    if not HEX40.fullmatch(head):
        raise AdmissionError("invalid_exact_head_sha")
    actual=git("rev-parse","HEAD")
    if actual!=head:
        raise AdmissionError("head_drift")
    baseline=git("rev-parse",base)
    if not HEX40.fullmatch(baseline):
        raise AdmissionError("invalid_base_sha")
    if git("merge-base",baseline,head)!=baseline:
        raise AdmissionError("unrelated_or_diverged_history")
    changed={p for p in git("diff","--name-only","--diff-filter=ACDMRT",
                            baseline+"..."+head).splitlines() if p}
    path_proof=approved_paths(changed)
    if git("diff","--check",baseline+"..."+head):
        raise AdmissionError("unexpected_diff_check_output")
    bridge=ROOT/"adapters/internet-search/bridge.py"
    docs=ROOT/"docs/TTG_INTERNET_SEARCH_PROVIDER_2026-10-15.md"
    if not bridge.is_file() or not docs.is_file():
        raise AdmissionError("missing_search_admission_files")
    document=docs.read_text(encoding="utf-8")
    if PINNED_WHEEL_SHA256 not in document:
        raise AdmissionError("approved_wheel_digest_missing_from_docs")
    try:
        module=ast.parse(bridge.read_text(encoding="utf-8"))
        pinned=[
            ast.literal_eval(stmt.value)
            for stmt in module.body
            if isinstance(stmt,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=="EXPECTED_WHEEL_SHA256"
                    for t in stmt.targets)
        ]
    except (ValueError,SyntaxError,TypeError,AttributeError) as exc:
        raise AdmissionError("cannot_validate_wheel_digest_pin") from exc
    if pinned!=[PINNED_WHEEL_SHA256]:
        raise AdmissionError("bridge_wheel_digest_not_exactly_approved")
    if "ZMW 0" not in document:
        raise AdmissionError("missing_zero_cash_commitment")
    if path_proof["rust_remediation_complete"]:
        proc=subprocess.run(["python3","tools/check_rust_dependency_lock.py"],cwd=ROOT,
                            capture_output=True,text=True,check=False,timeout=40)
        if proc.returncode:
            raise AdmissionError("current_rust_dependency_lock_failed: "+proc.stderr[-280:])
    return {
        "schema":"ptah.search-a05.pr-scope-admission.v1",
        "exact_head_sha":head,"base_sha":baseline,
        "changed_paths_count":len(changed),"changed_paths":sorted(changed),
        "scope":path_proof,
        "search_document_sha256":hashlib.sha256(docs.read_bytes()).hexdigest(),
        "external_wheel_sha256_cited":PINNED_WHEEL_SHA256,
        "zero_cash":True,
        "production_enrollment_authorized":False,
        "phase0c_signed_evidence_authorized":False,
        "repo_merge_authorized":False,
        "status":"SEARCH_SCOPE_VERIFIED_ONLY_OTHER_INDEPENDENT_GATES_REMAIN",
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--base",required=True)
    parser.add_argument("--head",required=True)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    try:
        record=qualify(args.base,args.head)
    except AdmissionError as error:
        parser.exit(1,"SEARCH_ADMISSION_SCOPE_FAILED: "+str(error)+"\n")
    rendered=json.dumps(record,indent=2,sort_keys=True)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(rendered,encoding="utf-8")
    print(rendered,end="")
if __name__=="__main__":
    main()
