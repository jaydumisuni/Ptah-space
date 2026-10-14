#!/usr/bin/env python3
"""Offline-only installer of an owner-provided exact TTG Search wheel.

Does not download packages, mutate shared Python, write to Ptah's source
truth, run as root, or activate a Ptah production service.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
EXPECTED_VERSION="0.7.0a2"
EXPECTED_SHA256="eaecd49153225e1b9c2972fa89d24edde69975e6dd15a7b05230c302fd7d65c4"

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--wheel",type=Path,required=True)
    parser.add_argument("--destination",type=Path,required=True)
    args=parser.parse_args()
    wheel=args.wheel.resolve(strict=True)
    actual=hashlib.sha256(wheel.read_bytes()).hexdigest()
    if actual!=EXPECTED_SHA256:
        raise SystemExit("wheel_digest_mismatch: refused install")
    dest=args.destination.expanduser().resolve()
    if dest.exists():
        raise SystemExit("destination_already_exists: no overwrite")
    dest.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    try:
        subprocess.run([sys.executable,"-m","venv",str(dest)],check=True,timeout=60)
        py=dest/"bin/python"
        subprocess.run([str(py),"-m","pip","install","--no-index","--no-deps",
                        "--disable-pip-version-check",str(wheel)],check=True,timeout=65)
        test=subprocess.run([str(py),"-I","-B","-m","ttg_search","version"],
                            check=True,capture_output=True,text=True,timeout=20)
        if "ttg-internet-search "+EXPECTED_VERSION not in test.stdout:
            raise RuntimeError("unexpected_engine_version")
    except (subprocess.SubprocessError,RuntimeError):
        # Never silently use a partially installed runtime.
        raise SystemExit("isolated_install_not_qualified")
    print(json.dumps({"status":"INSTALLED_OFFLINE","wheel_sha256":actual,
          "engine":EXPECTED_VERSION,"python":str(py),"paid_services":False},indent=2))

if __name__=="__main__":
    main()
