# SPDX-FileCopyrightText: 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS
# SPDX-License-Identifier: Apache-2.0
"""Ptah's optional human/agent terminal entry to the read-only Search Provider.

The A05 native Provider path is a process/lease execution transport.
This CLI is an ordinary terminal convenience. Knights is the external
security boundary; Ptah adds no login, Grant or per-caller admission.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

MAX_QUERY_LEN=250

def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description="Ptah / TTG zero-cash Internet Search")
    parser.add_argument("--wheel",default=os.environ.get("PTAH_TTG_SEARCH_WHEEL"),
                        help="External immutable 0.7.0a2 wheel path")
    parser.add_argument("--provider-generation",type=int,default=1)
    parser.add_argument("--index-db",help="Search-owned local index path (optional)")
    sub=parser.add_subparsers(dest="operation",required=True)
    search=sub.add_parser("search")
    search.add_argument("query")
    search.add_argument("--limit",type=int,default=5)
    search.add_argument("--offline",action="store_true")
    search.add_argument("--fresh",action="store_true")
    reader=sub.add_parser("read")
    reader.add_argument("url")
    sub.add_parser("doctor")
    sub.add_parser("describe",help="Print agent-neutral capability metadata; no provider launch")
    args=parser.parse_args(argv)
    if args.operation=="describe":
        path=Path(__file__).resolve().parents[1]/"adapters/internet-search/agent-capability.json"
        try:
            descriptor=json.loads(path.read_text(encoding="utf-8"))
            if descriptor.get("schema")!="ptah.agent-capability.v1":
                raise ValueError("unrecognized capability manifest")
        except (OSError,ValueError,UnicodeError):
            print(json.dumps({"status":"PTAH_SEARCH_UNAVAILABLE",
                              "error":"capability_descriptor_unavailable"}))
            return 2
        print(json.dumps(descriptor,ensure_ascii=False,indent=2))
        return 0
    if not args.wheel:
        parser.error("configure --wheel or PTAH_TTG_SEARCH_WHEEL (pinned release)")
    if args.provider_generation<=0:
        parser.error("provider generation must be positive")
    request={"operation":args.operation,"request_id":"ptah-terminal-search",
             "expected_provider_generation":args.provider_generation}
    if args.operation=="search":
        if len(args.query)>MAX_QUERY_LEN:
            parser.error("query too long")
        request.update({"query":args.query,"limit":args.limit,
                        "offline":args.offline,"require_fresh":args.fresh})
    elif args.operation=="read":
        request["url"]=args.url
    bridge=Path(__file__).resolve().parents[1]/"adapters/internet-search/bridge.py"
    command=[sys.executable,"-I","-B",str(bridge),"--wheel",args.wheel,
             "--provider-generation",str(args.provider_generation)]
    if args.index_db:command.extend(["--index-db",args.index_db])
    try:
        completed=subprocess.run(command,input=(json.dumps(request)+"\n").encode(),
                                capture_output=True,timeout=35,check=False)
    except (OSError,subprocess.TimeoutExpired):
        print(json.dumps({"status":"PTAH_SEARCH_UNAVAILABLE",
                          "error":"provider_launch_failed"}))
        return 2
    try:
        payload=json.loads(completed.stdout)
    except (UnicodeError,ValueError):
        print(json.dumps({"status":"PTAH_SEARCH_UNAVAILABLE",
                          "error":"invalid_provider_reply"}))
        return 2
    print(json.dumps(payload,ensure_ascii=False,indent=2))
    return 0 if completed.returncode==0 else 2

if __name__=="__main__":
    raise SystemExit(main())
