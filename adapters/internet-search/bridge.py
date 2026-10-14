# SPDX-FileCopyrightText: 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS
# SPDX-License-Identifier: Apache-2.0
"""Ptah A05-compatible read-only subprocess adapter for pinned TTG Internet Search.

One JSON request on stdin, one JSON reply on stdout. No Browser Provider mutation,
no authority to create Ptah source/citation identities, no account payments.
Ptah's existing admission/caller authority is a REQUIRED upstream responsibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

EXPECTED_WHEEL_SHA256 = "eaecd49153225e1b9c2972fa89d24edde69975e6dd15a7b05230c302fd7d65c4"
EXPECTED_VERSION = "0.7.0a2"
PROTOCOL = "ptah.ttg-internet-search.readonly.v1"
MAX_REQUEST_BYTES = 8192
MAX_RESULTS = 10
MAX_OUTPUT_BYTES = 160000
SEARCH_TIMEOUT_SECONDS = 30

# The isolated child has no script/plugin hooks and does not import the Ptah
# repository. Its one package is the independently qualified, hash-pinned wheel.
_CHILD = (
    "import sys;"
    "sys.path.insert(0,sys.argv[1]);"
    "from ttg_search.__main__ import cli;"
    "sys.argv=['ttg-search',*sys.argv[2:]];"
    "raise SystemExit(cli())"
)

class BridgeError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

def require_wheel(path: str) -> Path:
    wheel = Path(path).expanduser()
    if not wheel.is_absolute() or wheel.is_symlink() or not wheel.is_file():
        raise BridgeError("wheel_absent_or_untrusted")
    if not wheel.name.endswith(".whl") or wheel.stat().st_size > 5_000_000:
        raise BridgeError("invalid_wheel")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if digest != EXPECTED_WHEEL_SHA256:
        raise BridgeError("wheel_digest_mismatch")
    return wheel

def read_request(stream) -> dict:
    # Framed one-line JSON supports Ptah A05 authorized PTY input without
    # requiring an EOF/terminal shutdown. Query stays out of process argv.
    data=stream.buffer.readline(MAX_REQUEST_BYTES+1) if hasattr(stream,"buffer") else stream.readline(MAX_REQUEST_BYTES+1)
    if isinstance(data,str):
        data=data.encode("utf-8")
    if len(data)>MAX_REQUEST_BYTES:
        raise BridgeError("request_too_large")
    try:body=json.loads(data)
    except (ValueError,UnicodeError):
        raise BridgeError("invalid_request_json") from None
    if type(body) is not dict:
        raise BridgeError("invalid_request_shape")
    allowed={"operation","query","limit","require_fresh","offline","url",
             "request_id","expected_provider_generation"}
    if set(body)-allowed:
        raise BridgeError("unexpected_request_fields")
    if not isinstance(body.get("request_id"),str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,96}",body["request_id"]):
        raise BridgeError("invalid_request_id")
    return body

def checked_request(body:dict, generation:int, index_path: str|None) -> tuple[str,list[str]]:
    if type(body.get("expected_provider_generation")) is not int or body["expected_provider_generation"]!=generation:
        raise BridgeError("stale_provider_generation")
    operation=body.get("operation")
    if operation == "search":
        if set(body)-{"operation","query","limit","require_fresh","offline","request_id","expected_provider_generation"}:
            raise BridgeError("unexpected_search_fields")
        query=body.get("query")
        if not isinstance(query,str) or not 1<=len(query.strip())<=250 or any(ord(c)<32 for c in query):
            raise BridgeError("invalid_search_query")
        limit=body.get("limit",5)
        if type(limit) is not int or not 1<=limit<=MAX_RESULTS:
            raise BridgeError("invalid_result_limit")
        fresh=body.get("require_fresh",False)
        offline=body.get("offline",False)
        if type(fresh) is not bool or type(offline) is not bool:
            raise BridgeError("invalid_search_policy")
        if offline and not index_path:
            raise BridgeError("offline_index_not_configured")
        args=["search",query,"--limit",str(limit),"--no-preview-fallback"]
        if index_path:
            args.extend(["--index-db",index_path])
        if fresh:
            args.append("--require-fresh")
        if offline:
            args.append("--offline")
        return operation,args
    if operation == "read":
        if set(body)-{"operation","url","request_id","expected_provider_generation"}:
            raise BridgeError("unexpected_read_fields")
        url=body.get("url")
        if not isinstance(url,str) or not 1<=len(url)<=2000:
            raise BridgeError("invalid_page_url")
        try:parts=urlsplit(url)
        except ValueError:raise BridgeError("invalid_page_url") from None
        if parts.scheme!="https" or parts.username is not None or parts.password is not None:
            raise BridgeError("https_only")
        # The Search transport makes the definitive DNS/public-address decision.
        return operation,["read",url]
    if operation == "doctor":
        if set(body)-{"operation","request_id","expected_provider_generation"}:
            raise BridgeError("unexpected_doctor_fields")
        return operation,["doctor"]
    raise BridgeError("unsupported_operation")

def child_env() -> dict[str,str]:
    # Preserve provider's real shared XDG state so a second client cannot use
    # a private quota ledger to bypass current shared courtesy budgets.
    env={"PATH":"/usr/bin:/bin","PYTHONNOUSERSITE":"1",
         "PYTHONIOENCODING":"utf-8"}
    for name in ("HOME","XDG_STATE_HOME","XDG_DATA_HOME","SSL_CERT_FILE","SSL_CERT_DIR"):
        if name in os.environ:
            env[name]=os.environ[name]
    return env

def execute(wheel:Path,command:list[str]) -> tuple[dict,int]:
    try:
        process=subprocess.run(
            [sys.executable,"-I","-B","-c",_CHILD,str(wheel),*command],
            cwd="/",env=child_env(),capture_output=True,timeout=SEARCH_TIMEOUT_SECONDS,
            check=False)
    except subprocess.TimeoutExpired:
        raise BridgeError("search_timeout") from None
    except OSError:
        raise BridgeError("search_spawn_failed") from None
    if len(process.stdout)>MAX_OUTPUT_BYTES or len(process.stderr)>8192:
        raise BridgeError("search_output_exceeds_bounds")
    if process.returncode not in (0,2):
        raise BridgeError("search_provider_rejected_request")
    try:content=json.loads(process.stdout)
    except (UnicodeError,ValueError):
        raise BridgeError("invalid_search_provider_response") from None
    if not isinstance(content,dict):
        raise BridgeError("invalid_search_provider_response")
    return content,process.returncode

def present(operation:str,payload:dict,returncode:int,body:dict,generation:int) -> dict:
    # Never reclassify discovery snippets as verified page content, nor treat
    # an acknowledged process response as canonical Ptah source authority.
    if operation == "search":
        hits=payload.get("results")
        if not isinstance(hits,list) or len(hits)>MAX_RESULTS:
            raise BridgeError("invalid_search_results")
        sanitized=[]
        for item in hits:
            if not isinstance(item,dict):
                raise BridgeError("invalid_search_hit")
            url=item.get("url")
            if not isinstance(url,str) or urlsplit(url).scheme!="https":
                raise BridgeError("invalid_search_source_url")
            entry={k:item.get(k) for k in (
                "url","title","snippet","provider","status","score",
                "license","license_evidence_url","partial_source","indexed_at")
                if k in item}
            sanitized.append(entry)
        truth=payload.get("result_truth","DISCOVERED_NOT_PAGE_VERIFIED")
        if not isinstance(truth,str):
            raise BridgeError("invalid_search_truth")
        attempts=payload.get("attempts",[])
        if not isinstance(attempts,list):
            raise BridgeError("invalid_search_attempts")
        outcome={
            "status":payload.get("status","RESULTS" if sanitized else "UNAVAILABLE"),
            "results":sanitized,"attempts":attempts,
            "result_truth":truth,
            "verified_page_content":False,
            "provider_requests_paid":0,
            "freshness_guaranteed":False,
        }
    elif operation == "read":
        outcome={
            "status":payload.get("status","UNAVAILABLE"),
            "url":payload.get("url"),
            "title":payload.get("title"),
            "description":payload.get("description"),
            "text":payload.get("text"),
            "reason":payload.get("reason"),
            "http_status":payload.get("http_status"),
            "result_truth":"READABLE_HTTP_PAGE_NOT_FACT_VERIFIED" if payload.get("status")=="READABLE" else "NO_READABLE_PAGE",
            "verified_page_content":payload.get("status")=="READABLE",
            "provider_requests_paid":0,
        }
    else:
        outcome={
            "status":payload.get("provider_state","UNKNOWN"),
            "search_version":payload.get("version"),
            "payment_budget_zmw":payload.get("payment_budget_zmw"),
            "paid_search_provider_enabled":payload.get("paid_search_provider_enabled"),
            "paid_overflow_enabled":payload.get("paid_overflow_enabled"),
            "provider_requests_paid":0,
        }
    return {
        "protocol":PROTOCOL,
        "request_id":body["request_id"],
        "expected_provider_generation":generation,
        "provider":"ttg-internet-search",
        "provider_version":EXPECTED_VERSION,
        "role":"non_authoritative_derived_web_discovery",
        "canonical_ptah_source_authority":False,
        "browser_provider_unchanged":True,
        "completed":True,
        "has_results":bool(outcome.get("results")) if operation=="search" else returncode==0,
        "outcome":outcome
    }

def run(argv=None,stream=None) -> int:
    parser=argparse.ArgumentParser(description="Ptah read-only TTG Internet Search adapter")
    parser.add_argument("--wheel",required=True,help="Exact externally supplied and independently pinned 0.7.0a2 wheel")
    parser.add_argument("--provider-generation",type=int,required=True)
    parser.add_argument("--index-db",default=None,
                        help="Optional operator-authorized Search-owned local index file")
    args=parser.parse_args(argv)
    request_id=None
    try:
        if args.provider_generation<=0:
            raise BridgeError("invalid_provider_generation")
        body=read_request(stream or sys.stdin)
        request_id=body["request_id"]
        operation,command=checked_request(body,args.provider_generation,args.index_db)
        wheel=require_wheel(args.wheel)
        payload,exit_code=execute(wheel,command)
        response=present(operation,payload,exit_code,body,args.provider_generation)
    except BridgeError as exc:
        response={
            "protocol":PROTOCOL,"request_id":request_id,
            "provider":"ttg-internet-search",
            "provider_version":EXPECTED_VERSION,
            "completed":False,"has_results":False,
            "canonical_ptah_source_authority":False,
            "browser_provider_unchanged":True,
            "error":{"code":exc.code}
        }
        print(json.dumps(response,separators=(",",":")),flush=True)
        return 2
    print(json.dumps(response,ensure_ascii=False,separators=(",",":")),flush=True)
    return 0

if __name__=="__main__":
    raise SystemExit(run())
