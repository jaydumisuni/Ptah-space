#!/usr/bin/env python3
"""Fail-closed, non-authorizing Ptah E07 physical-host gate.

Oracle reachability and development fixtures NEVER imply Ptah E01/E02/E05.
This reporter cannot issue Node identity, Reservation, Lease or Fence.
"""
from __future__ import annotations
import argparse, json
from datetime import datetime, timezone, timedelta
from pathlib import Path

GATES = ("E01", "E05", "E02", "real_dispatch", "durable_crash_recovery", "recipe_service_admission", "E07")
REASONS = {
    "E01": "No production-enrolled authenticated Ptah Control/Node TLS session and current Node A02 evidence",
    "E05": "KRATOS pinned image differs; ATHENA current platform/role admission not proven",
    "E02": "No current Control-issued Reservation/Lease/Fence for exact Attempt",
    "real_dispatch": "No installed resident authenticated Control-to-Node-to-Creative-Studio dispatch",
    "durable_crash_recovery": "Hard-crash, hard-reboot, independently witnessed completion not proven",
    "recipe_service_admission": "No production Ptah D04 Recipe/Service admission of Creative Studio",
    "E07": "Two-node soak, independent final review and owner go/no-go not proven",
}

def parse_utc(s: str):
    t=datetime.fromisoformat(s.replace("Z","+00:00"))
    if t.tzinfo is None:
        raise ValueError("evidence timestamp must carry a timezone")
    return t.astimezone(timezone.utc)

def report(linux: dict, windows: dict, now: datetime) -> dict:
    if linux.get("record_type") != "ptah.phase0c.host_capability_report":
        raise ValueError("invalid canonical Linux collector")
    if windows.get("schema") != "ptah.e07.physical.host_presence.v1" or windows.get("platform") != "windows":
        raise ValueError("invalid Windows observation format")
    if now.tzinfo is None:
        raise ValueError("naive clock")
    for who,when in (("kratos",linux["created_at"]),("athena",windows["observed_utc"])):
        age=now.astimezone(timezone.utc)-parse_utc(when)
        if age>timedelta(hours=2) or age<timedelta(minutes=-5):
            raise ValueError(who+" observation not current")
    host=linux.get("host",{})
    image=linux.get("pinned_image",{})
    pinned=linux.get("pinned_host_match",{})
    if not isinstance(pinned,dict):
        raise ValueError("malformed pinned-host proof")
    return {
        "schema":"ptah.e07.physical_acceptance_preflight.v1",
        "status":"NO_GO",
        "observed_utc":now.astimezone(timezone.utc).isoformat(),
        "kratos":{
            "collector_required_capabilities_passed":linux.get("required_capabilities_passed") is True,
            "pinned_host_proof_eligible":linux.get("proof_eligible") is True and pinned.get("all_match") is True,
            "current_os":host.get("os_release",{}).get("PRETTY_NAME"),
            "current_kernel":host.get("uname",{}).get("release"),
            "pinned_os":image.get("release"),
            "pinned_kernel":image.get("kernel",{}).get("expected_uname_family"),
        },
        "athena":{
            "oracle_terminal_responding":windows.get("machine_reachable") is True,
            "ptah_control_or_node_service_observed":bool(windows.get("services") or windows.get("processes")),
            "production_node_enrollment_verified":False,
        },
        "gates":{name:{"status":"NOT_PROVEN","reason":REASONS[name]} for name in GATES},
        "owner_go_no_go_required":True,
        "may_run_production_dispatch":False,
        "may_close_e07":False,
        "nonclaim":"Physical host observations and development test credentials cannot mint Ptah authority.",
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--linux",type=Path,required=True)
    p.add_argument("--windows",type=Path,required=True)
    p.add_argument("--output",type=Path)
    p.add_argument("--strict",action="store_true")
    a=p.parse_args()
    proof=report(json.loads(a.linux.read_text()),json.loads(a.windows.read_text()),
                 datetime.now(timezone.utc))
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    print(json.dumps(proof,sort_keys=True))
    return 2 if a.strict else 0
if __name__=="__main__":
    raise SystemExit(main())
