#!/usr/bin/env python3
"""TTG shared-workspace storage lifecycle. Safe by default; only qualified Cargo caches are prunable."""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import tomllib
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

def _checkout_inputs_clean(project):
    """Fail closed on tracked, untracked and ignored build inputs in a checkout.

    Explicit --ignore-submodules=none overrides submodule.ignore=all.
    The only exempt ignored path is a direct regenerable target/ cache.
    """
    r=subprocess.run(["git","-C",str(project),"status","--porcelain",
                      "--untracked-files=all","--ignore-submodules=none"],
                     capture_output=True,text=True,timeout=15)
    if r.returncode or r.stdout.strip(): return False
    ignored=subprocess.run(["git","-C",str(project),"ls-files","--others",
                            "--ignored","--exclude-standard","--directory","-z"],
                           capture_output=True,timeout=20)
    if ignored.returncode:return False
    return all(item.decode("utf-8","surrogateescape").rstrip("/")=="target"
               for item in ignored.stdout.split(b"\0") if item)


def cargo_paths_inside_checkout(project):
    """Reject Cargo path/build dependencies outside the exact qualified checkout.

    Walk *tracked* manifests only, including manifests used by workspace
    members, patches and target-specific dependencies. No Cargo network calls.
    """
    root=Path(project).resolve(strict=True)
    listed=subprocess.run(["git","-C",str(root),"ls-files","--cached","-z"],
                          capture_output=True,timeout=20)
    if listed.returncode:return False
    manifests=[
        Path(raw.decode("utf-8","surrogateescape"))
        for raw in listed.stdout.split(b"\0") if raw
        and (raw==b"Cargo.toml" or raw.endswith(b"/Cargo.toml"))
    ]
    if not manifests or len(manifests)>2000:return False
    for relative in manifests:
        path=root/relative
        try:
            actual=path.resolve(strict=True)
            if path.is_symlink() or not actual.is_relative_to(root):
                return False
            with actual.open("rb") as handle:
                cargo=tomllib.load(handle)
        except (OSError,ValueError,tomllib.TOMLDecodeError):
            return False

        def is_internal(node,section=""):
            if isinstance(node,dict):
                for key,value in node.items():
                    # Cargo dependencies/patches, package.workspace,
                    # build/dependency manifest overrides: conservative reject.
                    if key=="path" and isinstance(value,str):
                        try:
                            resolved=(path.parent/value).resolve(strict=True)
                            if not resolved.is_relative_to(root):return False
                        except (OSError,ValueError):
                            return False
                    elif section=="package" and key=="workspace" and isinstance(value,str):
                        try:
                            resolved=(path.parent/value).resolve(strict=True)
                            if not resolved.is_relative_to(root):return False
                        except (OSError,ValueError):
                            return False
                    if not is_internal(value,key):return False
            elif isinstance(node,list):
                for child in node:
                    if not is_internal(child,section):return False
            return True

        if not is_internal(cargo):return False
    return True


def git_clean(project):
    if not _checkout_inputs_clean(project) or not cargo_paths_inside_checkout(project):
        return False
    # Git status may hide dirty submodules when .gitmodules sets
    # submodule.<name>.ignore=all. Explicitly enumerate initialized
    # recursive gitlinks, verify expected HEAD, and inspect their checkouts.
    tree=subprocess.run(["git","-C",str(project),"submodule","status","--recursive"],
                        capture_output=True,text=True,timeout=25)
    if tree.returncode:return False
    for entry in tree.stdout.splitlines():
        # Leading space means initialized at the expected gitlink SHA.
        # - (uninitialized), + (wrong commit), U (conflict) are forbidden.
        match=re.fullmatch(r" ([0-9a-f]{40}) (.+?)(?: \([^\n]*\))?",entry)
        if not match:return False
        child=Path(project)/match.group(2)
        try:
            base=Path(project).resolve(strict=True)
            real=child.resolve(strict=True)
            if child.is_symlink() or not real.is_relative_to(base) or not real.is_dir():
                return False
            if not _checkout_inputs_clean(child) or not cargo_paths_inside_checkout(child):
                return False
            revision=subprocess.run(["git","-C",str(child),"rev-parse","HEAD"],
                       capture_output=True,text=True,timeout=15)
            if revision.returncode or revision.stdout.strip()!=match.group(1):
                return False
        except (OSError,ValueError,subprocess.SubprocessError):
            return False
    return True


def retained_receipt(path):
    # Reject *any* disposable target ancestry, not just the cache being
    # qualified: another project's independently prunable target can erase it.
    evidence=Path(path).resolve(strict=True)
    if "target" in evidence.parts:
        raise ValueError("receipt inside a disposable target cache")
    return evidence


def cache_fingerprint(cache):
    """Two stable bounded tree inventories including the root and directories.

    This denies qualification/cleanup if entries mutate while traversing:
    per-directory pre/post checks catch in-directory races and a full second
    walk catches edits made after a directory was visited. No file contents or
    user data are read; only filesystem identity and metadata.
    """
    cache=Path(cache)
    if cache.is_symlink() or not cache.is_dir():
        raise ValueError("cache identity unavailable")
    root=cache.resolve(strict=True)
    first=root.lstat()
    identity=(first.st_dev,first.st_ino)
    started=time.monotonic()
    total_count=0

    def metadata(entry):
        return (entry.st_mode,entry.st_dev,entry.st_ino,entry.st_size,
                entry.st_mtime_ns,entry.st_ctime_ns)

    def inventory():
        nonlocal total_count
        digest=hashlib.sha256()
        for current,dirs,files in os.walk(
            root,followlinks=False,
            onerror=lambda error: (_ for _ in ()).throw(error)
        ):
            folder=Path(current)
            before=folder.lstat()
            if folder.is_symlink() or not folder.resolve(strict=True).is_relative_to(root):
                raise ValueError("unsafe cache directory")
            digest.update(json.dumps(["directory",str(folder.relative_to(root)),
                                      *metadata(before)],separators=(",",":")).encode())
            digest.update(b"\n")
            dirs.sort()
            for name in sorted(dirs+files):
                child=folder/name
                entry=child.lstat()
                if child.is_symlink():
                    raise ValueError("symlink inside regenerable cache")
                digest.update(json.dumps(["entry",str(child.relative_to(root)),
                                         *metadata(entry)],separators=(",",":"),
                                         ensure_ascii=False).encode())
                digest.update(b"\n")
                total_count+=1
                if total_count>300000 or time.monotonic()-started>30:
                    raise ValueError("cache inventory exceeds safe bound")
            after=folder.lstat()
            if metadata(before)!=metadata(after):
                raise ValueError("cache directory changed during inventory")
        latest=root.lstat()
        if cache.is_symlink() or (latest.st_dev,latest.st_ino)!=identity:
            raise ValueError("cache identity changed during inventory")
        return digest.hexdigest()

    before=inventory()
    after=inventory()
    if before!=after:
        raise ValueError("cache changed during inventory")
    return before


def validate_retained_bytes(path, expected_hash):
    source=Path(path)
    if source.is_symlink():
        raise ValueError("receipt symlink is not allowed")
    evidence=retained_receipt(source)
    if not evidence.is_file() or hashlib.sha256(evidence.read_bytes()).hexdigest()!=expected_hash:
        raise ValueError("receipt missing or altered during qualification/cleanup")
    return evidence

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
    if not git_clean(project): raise ValueError("source checkout has untracked or modified files")
    if active_builds(): raise ValueError("build running: cannot qualify cache")
    proposed=Path(receipt).expanduser()
    if proposed.is_symlink(): raise ValueError("receipt symlink is not allowed")
    evidence=retained_receipt(proposed)
    if not evidence.is_file(): raise ValueError("not a regular evidence receipt")
    # Bind all validation fields and the marker digest to the SAME bytes.
    validated_bytes=evidence.read_bytes()
    validated_digest=hashlib.sha256(validated_bytes).hexdigest()
    proof=json.loads(validated_bytes)
    qualified_head=git_head(project)
    if not isinstance(proof,dict) or proof.get("status")!="PASS" or proof.get("head")!=qualified_head:
        raise ValueError("receipt must be structured PASS at exact Git head")
    if not isinstance(proof.get("machine"),str) or not proof["machine"].strip():
        raise ValueError("receipt missing machine identity")
    timestamp=proof.get("utc")
    try:
        instant=dt.datetime.fromisoformat(timestamp.replace("Z","+00:00"))
        if instant.tzinfo is None or instant.utcoffset() is None: raise ValueError()
    except (ValueError,TypeError,AttributeError):
        raise ValueError("receipt requires timezone-aware UTC timestamp") from None
    commands=proof.get("commands")
    if not isinstance(commands,list) or not commands or not all(isinstance(c,str) and c.strip() for c in commands):
        raise ValueError("receipt requires actual test commands")
    hashes=proof.get("output_hashes")
    if not isinstance(hashes,dict) or not hashes or not all(
        isinstance(k,str) and k.strip() and isinstance(v,str)
        and re.fullmatch(r"[a-f0-9]{64}",v) for k,v in hashes.items()
    ):
        raise ValueError("receipt requires output SHA-256 values")
    if proof.get("cleanup_classification")!="regenerable_cargo_target":
        raise ValueError("receipt must explicitly classify disposable Cargo output")
    if not isinstance(proof.get("tests"),list) or not proof["tests"] or not all(
        isinstance(t,str) and t.strip() for t in proof["tests"]
    ):
        raise ValueError("receipt must list tests")
    if not isinstance(proof.get("evidence_ref"),str) or not proof["evidence_ref"].strip():
        raise ValueError("receipt missing evidence reference")
    if proof.get("allow_disposable_cleanup") is not True:
        raise ValueError("receipt lacks explicit disposable cleanup approval")
    fingerprint=cache_fingerprint(cache)
    item={"schema":"ttg.storage.cache-qualification.v1","project":str(project),"cache":str(cache),
       "head":qualified_head,"receipt":str(evidence),"receipt_sha256":validated_digest,
       "cache_fingerprint":fingerprint,
       "allow_cleanup":True,"cleanup_type":"cargo-clean-target-dir"}
    # Fresh qualification state must be stable at the moment the marker
    # becomes visible, not just before receipt parsing and hashing.
    if active_builds(): raise ValueError("build started while qualifying cache")
    if git_head(project)!=qualified_head or not git_clean(project):
        raise ValueError("source head or checkout changed while qualifying cache")
    validate_retained_bytes(evidence,validated_digest)
    if cache_fingerprint(cache)!=fingerprint:
        raise ValueError("cache rebuilt or changed during qualification")
    # Retention starts at publication, not before potentially slow final
    # checkout/recursive submodule/cache inventory checks.
    item["qualified_at_epoch"]=time.time()
    item["qualified_at_utc"]=now()
    atomic_json(marker_path(cache),item)
    return {"marked_disposable":str(cache),"head":item["head"],"receipt_sha256":item["receipt_sha256"]}

def active_builds():
    # Refuse GC while Rust/Cargo build processes exist on the host (not just in this repo).
    p=subprocess.run(["ps","-eo","comm="],capture_output=True,text=True,timeout=10,check=True)
    return any(x.strip() in {"cargo","rustc","rustdoc","sccache","clippy-driver","ld.lld","lld"} for x in p.stdout.splitlines())

def prune(root,min_age_hours=48,apply=False):
    if not isinstance(min_age_hours,int) or not 48<=min_age_hours<=24*365:
        raise ValueError("minimum 48 hours of qualified-cache retention required")
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
            if not isinstance(x.get("cache_fingerprint"),str) or not re.fullmatch(
                r"[0-9a-f]{64}",x["cache_fingerprint"]):
                raise ValueError("cache identity not qualified; requalification required")
            if cache_fingerprint(cache)!=x["cache_fingerprint"]:
                raise ValueError("cache changed since qualification; 48h clock must restart")
            evidence=validate_retained_bytes(x["receipt"],x["receipt_sha256"])
            if blocked_build: raise ValueError("a Rust build is active on the host")
            saved=size_of(cache)
            action={"cache":str(cache),"estimated_gib":round(saved/GIB,2),"status":"eligible"}
            if apply:
                if active_builds(): raise ValueError("a Rust build started before cleanup")
                # Size scans can take minutes; recheck immediately before Cargo.
                validate_retained_bytes(evidence,x["receipt_sha256"])
                if git_head(project)!=x["head"] or not git_clean(project):
                    raise ValueError("checkout changed immediately before cleanup")
                valid_cache(project,cache)
                if cache_fingerprint(cache)!=x["cache_fingerprint"]:
                    raise ValueError("cache changed immediately before cleanup; requalify")
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
            if not 48<=args.min_age_hours<=24*365: raise ValueError("minimum 48 hours of qualified-cache retention required")
            result=prune(args.root,args.min_age_hours,args.apply)
        print(json.dumps(result,sort_keys=True,indent=2))
    except (ValueError,OSError,subprocess.SubprocessError) as err:
        print(json.dumps({"status":"BLOCKED","reason":str(err)}),file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
