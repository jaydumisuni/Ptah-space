#!/usr/bin/env python3
"""TTG shared-workspace storage lifecycle. Safe by default; only qualified Cargo caches are prunable."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

STATE=Path.home()/".local/state/ttg-storage-guard"
MAX_SCAN_DEPTH=9
GIB=1024**3

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def atomic_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile("w",dir=path.parent,delete=False,encoding="utf-8") as out:
        json.dump(value,out,indent=2,sort_keys=True)
        out.write("\n")
        name=out.name
    os.chmod(name,0o600)
    os.replace(name,path)

def size_of(path):
    p=subprocess.run(["du","-sk","--",str(path)],capture_output=True,text=True,timeout=100,check=True)
    return int(p.stdout.split()[0])*1024

def candidates(root):
    root=Path(root).expanduser().resolve(strict=True)
    for folder,dirs,_ in os.walk(root,followlinks=False):
        base=Path(folder)
        depth=len(base.relative_to(root).parts)
        safe=[]
        for name in dirs:
            child=base/name
            if child.is_symlink() or name in {".git","node_modules",".venv","venv","__pycache__"}:
                continue
            if name=="target":
                if child.is_dir():
                    yield child
                continue
            if depth < MAX_SCAN_DEPTH: safe.append(name)
        dirs[:]=safe

def git_head(project):
    r=subprocess.run(["git","-C",str(project),"rev-parse","HEAD"],capture_output=True,text=True)
    if r.returncode: raise ValueError("not a Git source checkout")
    return r.stdout.strip()

def git_clean(project):
    r=subprocess.run(["git","-C",str(project),"status","--porcelain","--untracked-files=no"],capture_output=True,text=True)
    return r.returncode==0 and not r.stdout.strip()

def valid_cache(project,cache):
    if project.is_symlink() or cache.is_symlink() or cache.name!="target":
        raise ValueError("only an ordinary direct Cargo target/ is supported")
    if cache.resolve(strict=True)!=project.resolve(strict=True)/"target":
        raise ValueError("cache path is not project/target")
    if not (project/"Cargo.toml").is_file():
        raise ValueError("project lacks Cargo.toml")
    if not (project/".git").exists():
        raise ValueError("project is not a standalone/worktree Git checkout")

def marker_path(cache):
    return STATE/"qualifications"/(hashlib.sha256(str(cache).encode()).hexdigest()+".json")

def audit(root):
    st=os.statvfs(root)
    caches=[]
    for cache in candidates(root):
        try: caches.append({"path":str(cache),"bytes":size_of(cache)})
        except (OSError,ValueError,subprocess.SubprocessError): pass
    caches.sort(key=lambda x:x["bytes"],reverse=True)
    free_gib=st.f_bavail*st.f_frsize/GIB
    available_pct=100*st.f_bavail/max(1,st.f_blocks)
    total_gib=sum(x["bytes"] for x in caches)/GIB
    alerts=[]
    if free_gib<40 or available_pct<15:
        alerts.append("LOW_FREE_SPACE")
    if total_gib>10:
        alerts.append("MULTIPLE_CARGO_BUILDS_EXCEED_10_GIB")
    result={"schema":"ttg.storage.audit.v1","alerts":alerts,"utc":now(),"host":socket.gethostname(),
      "root":str(root),"filesystem_free_gib":round(st.f_bavail*st.f_frsize/GIB,2),
      "filesystem_used_pct":round(100*(st.f_blocks-st.f_bfree)/max(1,st.f_blocks),2),
      "cargo_target_count":len(caches),"cargo_targets_gib":round(sum(x["bytes"] for x in caches)/GIB,2),
      "top_targets":[{"path":x["path"],"gib":round(x["bytes"]/GIB,2),
       "qualified":marker_path(Path(x["path"])).is_file()} for x in caches[:25]],
      "protect":"Source, credentials, running worktrees and recovery receipts are never pruned by this tool"}
    atomic_json(STATE/"latest-audit.json",result)
    return result

def mark(project,receipt):
    project=Path(project).expanduser().resolve(strict=True)
    cache=project/"target"
    valid_cache(project,cache)
    if not git_clean(project): raise ValueError("source checkout has uncommitted tracked modifications")
    evidence=Path(receipt).expanduser().resolve(strict=True)
    if evidence.is_symlink() or not evidence.is_file(): raise ValueError("not a regular evidence receipt")
    # Safety is based on an *operator-reviewed* proof file, not substring matching.
    proof=json.loads(evidence.read_text())
    if not isinstance(proof,dict) or proof.get("status")!="PASS" or proof.get("head")!=git_head(project):
        raise ValueError("receipt must be structured PASS at exact Git head")
    if not proof.get("evidence_ref") or not proof.get("tests") or proof.get("allow_disposable_cleanup") is not True:
        raise ValueError("receipt missing proof reference, tests or cleanup decision")
    item={"schema":"ttg.storage.cache-qualification.v1","project":str(project),"cache":str(cache),
       "head":git_head(project),"receipt":str(evidence),"receipt_sha256":sha(evidence),
       "qualified_at_epoch":time.time(),"qualified_at_utc":now(),
       "allow_cleanup":True,"cleanup_type":"cargo-clean-target-dir"}
    atomic_json(marker_path(cache),item)
    return {"marked_disposable":str(cache),"head":item["head"],"receipt_sha256":item["receipt_sha256"]}

def active_builds():
    # Refuse GC while Rust/Cargo build processes exist on the host (not just in this repo).
    p=subprocess.run(["ps","-eo","comm="],capture_output=True,text=True,timeout=10,check=True)
    return any(x.strip() in {"cargo","rustc","rustdoc","sccache","clippy-driver","ld.lld","lld"} for x in p.stdout.splitlines())

def prune(root,min_age_hours=48,apply=False):
    root=Path(root).expanduser().resolve(strict=True)
    actions=[]
    blocked_build=active_builds()
    folder=STATE/"qualifications"
    for marker in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            x=json.loads(marker.read_text())
            project=Path(x["project"])
            cache=Path(x["cache"])
            if not project.resolve(strict=True).is_relative_to(root):
                continue
            valid_cache(project,cache)
            if not x.get("allow_cleanup") or x.get("cleanup_type")!="cargo-clean-target-dir":
                raise ValueError("no approved cache cleanup type")
            if (time.time()-float(x["qualified_at_epoch"]))<min_age_hours*3600:
                raise ValueError("retention window not elapsed")
            if git_head(project)!=x["head"] or not git_clean(project):
                raise ValueError("checkout changed since qualification")
            evidence=Path(x["receipt"])
            if not evidence.is_file() or evidence.is_symlink() or sha(evidence)!=x["receipt_sha256"]:
                raise ValueError("receipt missing or altered")
            if blocked_build: raise ValueError("a Rust build is active on the host")
            saved=size_of(cache)
            action={"cache":str(cache),"estimated_gib":round(saved/GIB,2),"status":"eligible"}
            if apply:
                r=subprocess.run(["cargo","clean","--manifest-path",str(project/"Cargo.toml"),
                    "--target-dir",str(cache)],capture_output=True,text=True,timeout=1200)
                if r.returncode: raise RuntimeError("cargo clean failed: "+r.stderr[-300:])
                marker.unlink()
                action["status"]="cleaned"
            actions.append(action)
        except (ValueError,OSError,KeyError,RuntimeError,subprocess.SubprocessError) as e:
            actions.append({"marker":str(marker),"status":"protected","reason":str(e)})
    result={"schema":"ttg.storage.prune.v1","utc":now(),"apply":apply,
        "cleared_gib_estimate":round(sum(x.get("estimated_gib",0) for x in actions if x["status"]=="cleaned"),2),
        "actions":actions}
    atomic_json(STATE/"latest-prune.json",result)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="mode",required=True)
    a=sub.add_parser("audit");a.add_argument("--root",required=True)
    a=sub.add_parser("mark");a.add_argument("--project",required=True);a.add_argument("--receipt",required=True)
    a=sub.add_parser("prune");a.add_argument("--root",required=True);a.add_argument("--min-age-hours",type=int,default=48)
    a.add_argument("--apply",action="store_true")
    args=p.parse_args()
    try:
        if args.mode=="audit": result=audit(Path(args.root).expanduser().resolve(strict=True))
        elif args.mode=="mark":result=mark(args.project,args.receipt)
        else:
            if not 1<=args.min_age_hours<=24*365: raise ValueError("unsafe retention interval")
            result=prune(args.root,args.min_age_hours,args.apply)
        print(json.dumps(result,sort_keys=True,indent=2))
    except (ValueError,OSError,subprocess.SubprocessError) as err:
        print(json.dumps({"status":"BLOCKED","reason":str(err)}),file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
