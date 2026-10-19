#!/usr/bin/env python3
"""Deterministic, unsigned F01 source/artifact bundle. NOT a deployment tool.

Accept only two already-built, regular, non-symlinked local binaries. Create
a reproducible tar with immutable SHA-256 inventory. Never run service files,
install packages, create credentials, sign, enroll Nodes, or grant Ptah E01–E05
authority. Oracle remains host transport; Ptah is only workspace.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

SCHEMA = "ptah.f01.unsigned-service-bundle/1"
SERVICES = ("ptah-control", "ptah-node")
MAX_BYTES = 128 * 1024 * 1024


class BundleError(ValueError):
    pass


def require(value: bool, error: str) -> None:
    if not value:
        raise BundleError(error)


def digest(source) -> tuple[str, int]:
    h=hashlib.sha256()
    size=0
    while True:
        chunk=source.read(1024 * 1024)
        if not chunk:
            break
        size+=len(chunk)
        require(size <= MAX_BYTES, "INPUT_TOO_LARGE")
        h.update(chunk)
    return h.hexdigest(),size


def canonical_manifest(inputs: dict[str, Path], source_commit: str) -> dict:
    require(re.fullmatch(r"[a-f0-9]{40}",source_commit) is not None, "INVALID_SOURCE_SHA")
    require(set(inputs) == set(SERVICES), "INCOMPLETE_SERVICE_SET")
    registry=[]
    for name in SERVICES:
        path=inputs[name]
        require(not path.is_symlink(), "SYMLINK_INPUT:" + name)
        st=path.stat()
        require(stat.S_ISREG(st.st_mode), "NONREGULAR_INPUT:" + name)
        require(st.st_size > 0 and st.st_size <= MAX_BYTES, "INVALID_INPUT_SIZE:" + name)
        with path.open("rb") as f:
            hexdigest,size=digest(f)
        require(size==st.st_size,"CHANGED_INPUT_SIZE:" + name)
        registry.append({"name":name,"file":"bin/"+name,"size":size,
                         "sha256":"sha256:"+hexdigest,"admission":"not_admitted"})
    return {"schema":SCHEMA,"source_commit":source_commit,
        "publisher":"THETECHGUY DIGITAL SOLUTIONS",
        "oracle_machine_transport":"independent_of_bundle",
        "ptah_role":"shared_workspace",
        "services":registry,
        "signed":False,"native_execution_admitted":False,"release_authorized":False}


def manifest_bytes(value: dict) -> bytes:
    return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode("utf-8")


def header(name: str, length: int, mode: int) -> tarfile.TarInfo:
    info=tarfile.TarInfo(name)
    info.size=length
    info.mode=mode
    info.uid=info.gid=0
    info.uname=info.gname=""
    info.mtime=0
    return info


def create_bundle(inputs: dict[str, Path], source_commit: str, output: Path) -> dict:
    require(not output.exists() and not output.is_symlink(),"OUTPUT_ALREADY_EXISTS")
    require(output.parent.is_dir(),"OUTPUT_PARENT_MISSING")
    for path in inputs.values():
        require(path.resolve()!=output.resolve(),"OUTPUT_OVERLAPS_INPUT")
    manifest=canonical_manifest(inputs,source_commit)
    encoded=manifest_bytes(manifest)
    try:
        with output.open("xb") as handle:
            with tarfile.open(fileobj=handle,mode="w",format=tarfile.PAX_FORMAT) as archive:
                archive.addfile(header("manifest.json",len(encoded),0o644),io.BytesIO(encoded))
                for item in manifest["services"]:
                    name=item["name"]
                    path=inputs[name]
                    require(not path.is_symlink(),"INPUT_REPLACED_BY_SYMLINK")
                    with path.open("rb") as source:
                        before=os.fstat(source.fileno())
                        require(stat.S_ISREG(before.st_mode) and before.st_size==item["size"],
                                "INPUT_CHANGED_BEFORE_BUNDLE")
                        archive.addfile(header(item["file"],item["size"],0o755),source)
                        require(os.fstat(source.fileno()).st_size==before.st_size,
                                "INPUT_CHANGED_DURING_BUNDLE")
        result=verify_bundle(output)
        require(result["source_commit"]==source_commit,"WRONG_SOURCE_COMMIT")
        return result
    except (OSError, BundleError, tarfile.TarError):
        output.unlink(missing_ok=True)
        raise


def verify_bundle(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(),"INVALID_ARCHIVE")
    with tarfile.open(path,mode="r:") as t:
        files=t.getmembers()
        require([m.name for m in files]==["manifest.json","bin/ptah-control","bin/ptah-node"],
                "UNEXPECTED_ARCHIVE_MEMBERS")
        require(all(m.isfile() and m.uid==0 and m.gid==0 and m.mtime==0 for m in files),
                "NONDETERMINISTIC_OR_UNSAFE_MEMBER")
        assert t.extractfile(files[0]) is not None
        raw=t.extractfile(files[0]).read(MAX_BYTES+1)
        require(len(raw) <= MAX_BYTES, "MANIFEST_TOO_LARGE")
        try:
            manifest=json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise BundleError("INVALID_MANIFEST") from exc
        require(type(manifest) is dict and manifest_bytes(manifest)==raw, "NONCANONICAL_MANIFEST")
        require(manifest.get("schema")==SCHEMA and manifest.get("signed") is False
                and manifest.get("native_execution_admitted") is False
                and manifest.get("release_authorized") is False
                and manifest.get("ptah_role")=="shared_workspace"
                and manifest.get("oracle_machine_transport")=="independent_of_bundle",
                "FORGED_RELEASE_OR_TRANSPORT")
        require(re.fullmatch(r"[a-f0-9]{40}",str(manifest.get("source_commit"))),
                "INVALID_SOURCE_COMMIT")
        records=manifest.get("services")
        require(type(records) is list and len(records)==2, "INVALID_SERVICE_REGISTRY")
        for entry,item,name in zip(records,files[1:],SERVICES,strict=True):
            require(type(entry) is dict and
                    set(entry)=={"name","file","size","sha256","admission"} and
                    entry["name"]==name and entry["file"]==item.name
                    and entry["admission"]=="not_admitted"
                    and type(entry["size"]) is int
                    and entry["size"]==item.size
                    and item.size <= MAX_BYTES and item.size>0
                    and item.mode==0o755,
                    "SERVICE_MANIFEST_MISMATCH")
            stream=t.extractfile(item)
            require(stream is not None,"MISSING_CONTENT")
            hexdigest,length=digest(stream)
            require(length==entry["size"] and entry["sha256"]=="sha256:"+hexdigest,
                    "UNVERIFIED_SERVICE_HASH")
    return {"status":"UNSIGNED_SOURCE_BUNDLE_VERIFIED_NO_GO",
            "source_commit":manifest["source_commit"],"services":len(records),
            "signed":False,"native_execution_admitted":False,"release_authorized":False}


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify",type=Path)
    group.add_argument("--output",type=Path)
    p.add_argument("--control",type=Path)
    p.add_argument("--node",type=Path)
    p.add_argument("--source-commit",type=str)
    args=p.parse_args()
    try:
        if args.verify:
            require(args.control is None and args.node is None and args.source_commit is None,
                    "VERIFY_MUST_NOT_ACCEPT_BUILD_INPUTS")
            result=verify_bundle(args.verify)
        else:
            require(args.control is not None and args.node is not None
                    and args.source_commit is not None,"MISSING_BUILD_INPUTS")
            result=create_bundle({"ptah-control":args.control,
                                  "ptah-node":args.node},args.source_commit,args.output)
        print(json.dumps(result,sort_keys=True))
        return 0
    except (OSError,tarfile.TarError,BundleError) as exc:
        print("F01_BUNDLE_REJECTED:"+str(exc),file=__import__("sys").stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
