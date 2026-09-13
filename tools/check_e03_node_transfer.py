#!/usr/bin/env python3
"""Validate the frozen E03 node-to-node transfer acceptance corpus."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import Any
EXPECTED_SCHEMA_VERSION="0.1.0"
EXPECTED_RECORD_TYPE="ptah.e03.node_transfer_acceptance_corpus"
EXPECTED_PREDECESSOR="4b745e7ee0712df0458c1adf55feafdbcc42d9d4"
EXPECTED_CONTROL_PROTOCOL="ptah.node.link.v1"
EXPECTED_DATA_PROTOCOL="ptah.node.transfer.v1"
CORPUS_RELATIVE_PATH=Path("conformance/e03/node-transfer-cases.v0.1.0.json")
EXPECTED_CASES={"two_authenticated_nodes_large_object","bulk_bytes_not_e01_control_frame","direct_exact_integrity","interrupt_resume_missing_ranges_only","direct_failure_relay_continuation","route_change_preserves_verified_ranges","stale_source_generation_rejected","stale_target_epoch_rejected","wrong_peer_fingerprint_rejected","expired_ticket_rejected","wrong_a08_binding_rejected","wrong_content_artifact_binding_rejected","source_size_digest_mismatch_rejected","out_of_bounds_range_rejected","payload_length_mismatch_rejected","corrupt_range_rejected","corrupt_retained_partial_rejected","whole_digest_mismatch_rejected","verified_cache_hit_zero_network","unverified_cache_rejected","relay_no_a07_truth","a08_ack_not_final_verification","a07_acceptance_after_a08_verification_only","reconnect_fresh_ticket_resume","control_restart_ephemeral_ticket_loss","concurrent_transfer_state_isolation","no_e04_e05_e06_scope","inherited_regressions_exact_head"}
EXPECTED_CLASSES={"positive","negative","adversarial","recovery","resilience","integration","scope"}
SCOPE_FALSE_FIELDS=("workspace_movement_added","platform_node_admission_added","automatic_discovery_added","automatic_relay_selection_added","offline_queue_added","new_core_entity_required")
def _load_json(path:Path)->dict[str,Any]:
    try:value=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc: raise ValueError(f"E03 corpus is unreadable: {exc}") from exc
    if not isinstance(value,dict): raise ValueError("E03 corpus root must be a JSON object")
    return value
def load_and_validate_corpus(path:Path)->dict[str,Any]:
    d=_load_json(path)
    fixed={"schema_version":EXPECTED_SCHEMA_VERSION,"record_type":EXPECTED_RECORD_TYPE,"accepted_predecessor":EXPECTED_PREDECESSOR,"control_protocol":EXPECTED_CONTROL_PROTOCOL,"data_protocol":EXPECTED_DATA_PROTOCOL}
    for field,expected in fixed.items():
        if d.get(field)!=expected: raise ValueError(f"E03 {field} changed")
    for field in SCOPE_FALSE_FIELDS:
        if d.get(field) is not False: raise ValueError(f"E03 {field} must remain false")
    cases=d.get("cases")
    if not isinstance(cases,list): raise ValueError("E03 cases must be a JSON array")
    if len(cases)!=28: raise ValueError(f"E03 corpus must contain exactly 28 cases, found {len(cases)}")
    ids=[]; classes=set()
    for index,case in enumerate(cases,1):
        if not isinstance(case,dict): raise ValueError(f"E03 case {index} must be a JSON object")
        cid=case.get("id")
        if not isinstance(cid,str) or not cid.strip(): raise ValueError(f"E03 case {index} id is missing")
        ids.append(cid)
        cls=case.get("class")
        if cls not in EXPECTED_CLASSES: raise ValueError(f"E03 case {cid} class is invalid")
        classes.add(cls)
        expected=case.get("expected_result"); observed=case.get("observed_result")
        if not isinstance(expected,str) or not expected.strip(): raise ValueError(f"E03 case {cid} expected result is missing")
        if observed!=expected: raise ValueError(f"E03 case {cid} falsely claims a passing observation")
        if case.get("passed") is not True: raise ValueError(f"E03 case {cid} is not proven passing")
        evidence=case.get("required_evidence")
        if not isinstance(evidence,list) or not evidence or any(not isinstance(x,str) or not x.strip() for x in evidence): raise ValueError(f"E03 case {cid} required evidence is invalid")
        if len(evidence)!=len(set(evidence)): raise ValueError(f"E03 case {cid} required evidence must be unique")
    if len(ids)!=len(set(ids)): raise ValueError("E03 case ids must be unique")
    actual=set(ids)
    if actual!=EXPECTED_CASES: raise ValueError(f"E03 case coverage drifted: missing={sorted(EXPECTED_CASES-actual)} unexpected={sorted(actual-EXPECTED_CASES)}")
    if classes!=EXPECTED_CLASSES: raise ValueError(f"E03 case classes drifted: {sorted(classes)}")
    return d
def validation_report(d:dict[str,Any])->dict[str,Any]:
    return {"schema_version":EXPECTED_SCHEMA_VERSION,"record_type":"ptah.e03.node_transfer_acceptance_validation","status":"pass","accepted_predecessor":EXPECTED_PREDECESSOR,"control_protocol":EXPECTED_CONTROL_PROTOCOL,"data_protocol":EXPECTED_DATA_PROTOCOL,"case_count":len(d["cases"]),"case_ids":sorted(c["id"] for c in d["cases"]),**{f:False for f in SCOPE_FALSE_FIELDS}}
def main()->int:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--repo-root",type=Path,default=Path(".")); p.add_argument("--output",type=Path,required=True); a=p.parse_args()
    d=load_and_validate_corpus(a.repo_root.resolve()/CORPUS_RELATIVE_PATH); rendered=json.dumps(validation_report(d),indent=2,sort_keys=True)+"\n"; a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(rendered,encoding="utf-8"); print(rendered,end=""); return 0
if __name__=="__main__": raise SystemExit(main())
