#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


class QualificationError(RuntimeError):
    pass


def _load(path: Path) -> dict[str, Any]:
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict):
        raise QualificationError(f"{path}: root must be an object")
    return value


def _sha256(path: Path) -> str:
    return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def qualify(
    result: dict[str,Any],
    projection: dict[str,Any],
    second_use: dict[str,Any],
    reuse_evidence: dict[str,Any],
) -> dict[str,Any]:
    _require(result.get("schema")=="ttg.simulation-result.v2","unexpected simulation-result schema")
    _require(result.get("authority_granted") is False,"simulation must not grant authority")
    boundary=result.get("authority_boundary",{})
    for key in ("simulation_may_promote","simulation_may_mutate_other_projects","self_certification","donor_authority_transferred"):
        _require(boundary.get(key) is False,f"simulation authority boundary violated: {key}")

    winner=result.get("candidate_inference",{}).get("winner") or {}
    _require(winner.get("candidate_id")=="sleeper-channel-separated-mtk","unexpected winner")
    _require(winner.get("eligible") is True,"winner is not eligible")
    _require(winner.get("authority_violations")==0,"winner has authority violations")
    _require(winner.get("hostile_passed")==winner.get("hostile_total"),"hostile corpus not fully passed")
    _require(int(winner.get("hostile_total",0))>=19,"hostile corpus unexpectedly reduced")

    candidate_generation=result.get("evidence",{}).get("candidate_digest")
    _require(isinstance(candidate_generation,str) and candidate_generation.startswith("sha256:"),"candidate generation missing")

    uncertainties=result.get("uncertainty",[])
    for phrase in (
        "Physical BP/modem IMEI channel",
        "Physical serial extraction",
        "Physical MT6768 storage/DA partition backend",
        "Physical security-state operations",
    ):
        _require(any(phrase in str(x) for x in uncertainties),f"required uncertainty disappeared: {phrase}")

    _require(projection.get("schema")=="ttg.simulation.ptah-device-projection.v1","unexpected Ptah projection schema")
    _require(projection.get("aliases_are_evidence_only") is True,"backend aliases were promoted to identity")
    incarnations=projection.get("incarnations",[])
    _require(isinstance(incarnations,list) and len(incarnations)>=3,"insufficient connection incarnations")
    epochs=[int(x["epoch"]) for x in incarnations]
    _require(epochs==sorted(epochs) and len(set(epochs))==len(epochs),"connection epochs are not monotonic")
    meta=[x for x in incarnations if x.get("mode")=="meta"]
    _require(len(meta)==1,"META incarnation must be singular in projection")
    _require((meta[0].get("usb_vid"),meta[0].get("usb_pid"))==("0E8D","2007"),"META transport identity mismatch")
    pab=projection.get("authority_boundary",{})
    _require(pab.get("simulation_grants_physical_authority") is False,"Ptah projection grants physical authority")
    _require("Sleeper" in str(pab.get("production_mutation_owner","")),"production owner is not Sleeper")

    _require(second_use.get("schema")=="ttg.second-use-status.v1","unexpected second-use schema")
    _require(second_use.get("candidate_generation")==candidate_generation,"second-use generation mismatch")
    _require(second_use.get("second_use_passed") is True,"second-use did not pass")
    _require(int(second_use.get("successful_uses",0))>=2,"fewer than two successful uses")
    _require(int(second_use.get("distinct_contexts",0))>=2,"second-use contexts are not distinct")
    _require(int(second_use.get("distinct_evidence_generations",0))>=2,"evidence generations are not distinct")
    _require(second_use.get("authority_granted") is False,"second-use grants authority")

    _require(reuse_evidence.get("schema")=="ttg.simulation.external-physical-evidence.v1","unexpected reuse-evidence schema")
    _require(reuse_evidence.get("authority_granted") is False,"reuse evidence grants authority")
    scope=reuse_evidence.get("physical_scope",{})
    _require(scope.get("platform")=="MT6789","distinct reuse platform is not MT6789")
    for key in ("init_return","connect_return","targetver_return","chipid_return","disconnect_return","deinit_return"):
        _require(scope.get(key)==0,f"MT6789 read-only proof failed: {key}")
    _require(scope.get("targetver_callback") is True,"MT6789 TargetVer callback missing")
    guard=reuse_evidence.get("guard",{})
    _require(guard.get("read_only") is True,"MT6789 evidence is not read-only")
    for key in ("nvram_write","reset","frp_mutation","format","unlock","shell","reboot"):
        _require(guard.get(key) is False,f"MT6789 evidence contains forbidden mutation: {key}")

    return {
        "schema":"ptah.independent-mtk-simulation-qualification.v1",
        "status":"pass",
        "scope":"C05/C08 independent evidence qualification",
        "candidate_id":"sleeper-channel-separated-mtk",
        "candidate_generation":candidate_generation,
        "hostile_worlds":{
            "passed":winner["hostile_passed"],
            "total":winner["hostile_total"],
        },
        "second_use":{
            "passed":True,
            "successful_uses":second_use["successful_uses"],
            "distinct_contexts":second_use["distinct_contexts"],
            "distinct_evidence_generations":second_use["distinct_evidence_generations"],
        },
        "ptah_contracts_checked":[
            "C05 MediaTek read-only evidence boundary",
            "C08 canonical Device identity and connection-epoch boundary",
            "C08 mutation boundary",
        ],
        "physical_evidence_admitted":[
            "MT6768 AP-META read-only reference",
            "MT6789 AP-META read-only D4 reference",
        ],
        "simulation_mutation_claims_admitted_as_physical":False,
        "production_authority_granted":False,
        "physical_mutation_authority_granted":False,
        "qualification_meaning":"candidate structure/evidence passes independent Ptah boundary checks; physical mutation remains unqualified",
    }


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--result",type=Path,required=True)
    ap.add_argument("--projection",type=Path,required=True)
    ap.add_argument("--second-use",type=Path,required=True)
    ap.add_argument("--reuse-evidence",type=Path,required=True)
    ap.add_argument("--output",type=Path)
    ns=ap.parse_args()
    try:
        receipt=qualify(_load(ns.result),_load(ns.projection),_load(ns.second_use),_load(ns.reuse_evidence))
        receipt["inputs"]={
            "result":{"path":str(ns.result),"sha256":_sha256(ns.result)},
            "projection":{"path":str(ns.projection),"sha256":_sha256(ns.projection)},
            "second_use":{"path":str(ns.second_use),"sha256":_sha256(ns.second_use)},
            "reuse_evidence":{"path":str(ns.reuse_evidence),"sha256":_sha256(ns.reuse_evidence)},
        }
    except (QualificationError,KeyError,TypeError,ValueError,json.JSONDecodeError) as exc:
        print(json.dumps({"status":"fail","error":str(exc)},indent=2))
        return 1
    text=json.dumps(receipt,indent=2,sort_keys=False)+"\n"
    if ns.output:
        ns.output.parent.mkdir(parents=True,exist_ok=True)
        ns.output.write_text(text,encoding="utf-8")
    print(text,end="")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
