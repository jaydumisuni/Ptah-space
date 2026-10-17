#!/usr/bin/env python3
"""Fail-closed, exact-head A11 *post-baseline maintenance* admission scope.

This does NOT reproduce or replace historical A11 one-commit-after-A08 proof.
Historical A11 remains immutable. The separate always-on A11 maintenance CI
must physically prove a candidate, and branch protection must require its
specific successful status before merge.
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEX = re.compile(r"^[0-9a-f]{40}$")
APPROVED = frozenset({
    "tools/ptah_workspace_browser.mjs",
    "tools/ptah_workspace.mjs",
    ".github/workflows/ptah-owned-browser-current.yml",
})
PRODUCT_PREFIXES = ("browser-provider/src/","browser-provider/test/")
REQUIRED_PRODUCT = frozenset({"browser-provider/src/owned_chromium.mjs",
                              "browser-provider/src/playwright_backend.mjs"})
LOCKED_FILES = frozenset({
    "Cargo.toml","Cargo.lock","browser-provider/package-lock.json",
    "crates/ptah-provider-api/src/lib.rs",
    "crates/ptah-browser-runtime/src/lib.rs",
    ".github/workflows/a11-browser-provider-proof.yml",
    "tools/check_current_pr_admission.py",
    "tools/check_a11_maintenance_admission.py",
})
class AdmissionError(ValueError):
    pass

def git(*args: str) -> str:
    p = subprocess.run(["git",*args],cwd=ROOT,text=True,capture_output=True,timeout=40)
    if p.returncode:
        raise AdmissionError("git_failure: "+p.stderr[-300:])
    return p.stdout.strip()

def validate_paths(changed: set[str]) -> None:
    if not changed:
        raise AdmissionError("empty_a11_maintenance_delta")
    if changed & LOCKED_FILES:
        raise AdmissionError("locked_phase_or_governance_file_modified")
    if not any(path in REQUIRED_PRODUCT for path in changed):
        raise AdmissionError("no_a11_runtime_product_change")
    for path in changed:
        if path in APPROVED:
            continue
        if path.startswith(PRODUCT_PREFIXES) and path.endswith((".mjs",".js")):
            continue
        if path in ("browser-provider/README.md","browser-provider/package.json",".gitignore"):
            continue
        raise AdmissionError("unreviewed_a11_maintenance_path: "+path)
    if any(x.startswith("browser-provider/.workspace/") or "node_modules/" in x
           for x in changed):
        raise AdmissionError("runtime_binary_or_modules_not_reviewable")

def qualify(base: str,head: str) -> dict:
    if not HEX.fullmatch(base) or not HEX.fullmatch(head):
        raise AdmissionError("invalid_exact_sha")
    if git("rev-parse","HEAD")!=head:
        raise AdmissionError("head_drift")
    if git("merge-base",base,head)!=base:
        raise AdmissionError("base_not_ancestor")
    changed=set(filter(None,git("diff","--name-only","--diff-filter=ACDMRT",
                               base+"..."+head).splitlines()))
    validate_paths(changed)
    if git("diff","--check",base+"..."+head):
        raise AdmissionError("diff_whitespace_violation")
    return {
        "schema":"ptah.a11.post_baseline_maintenance_scope.v1",
        "base_sha":base,"exact_head_sha":head,
        "modified_paths":sorted(changed),
        "historic_a11_proof":"UNCHANGED_AND_NOT_APPLICABLE_TO_POST_BASELINE",
        "separate_a11_physical_proof_required":True,
        "node_lock":"24.18.0","playwright_lock":"1.60.0",
        "owned_chromium_isolation_required":True,
        "personal_or_oracle_browser_use_authorized":False,
        "result":"A11_MAINTENANCE_SCOPE_QUALIFIED_PHYSICAL_ADMISSION_STILL_REQUIRED"
    }

def main() -> None:
    p=argparse.ArgumentParser()
    p.add_argument("--base",required=True)
    p.add_argument("--head",required=True)
    p.add_argument("--output",type=Path)
    args=p.parse_args()
    try:record=qualify(args.base,args.head)
    except AdmissionError as error:
        p.exit(1,"A11_MAINTENANCE_SCOPE_BLOCKED: "+str(error)+"\n")
    output=json.dumps(record,indent=2,sort_keys=True)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(output)
    print(output,end="")
if __name__=="__main__":
    main()
