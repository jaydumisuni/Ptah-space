#!/usr/bin/env python3
"""F01 detached Ed25519 artifact signature candidate; no production admission.

Uses locally available OpenSSL, does not generate or store production keys.
The public key AND its SHA-256 fingerprint must come from an independently
trusted channel. A correct signature alone never authorizes deployment.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import shutil
from contextlib import contextmanager

import build_f01_service_bundle as archive

SCHEMA="ptah.f01.detached-artifact-evidence/1"
FINGERPRINT=re.compile(r"sha256:[a-f0-9]{64}\Z")
SIGNATURE=re.compile(r"[a-f0-9]{128}\Z")
SOURCE_SHA=re.compile(r"[a-f0-9]{40}\Z")
MAX_SIDECAR_BYTES=8192


class F01SignatureError(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise F01SignatureError(code)


def regular_file(path: Path, *, limit: int | None = None) -> None:
    require(not path.is_symlink() and path.is_file(), "NOT_REGULAR_FILE")
    st=path.stat()
    require(stat.S_ISREG(st.st_mode), "INVALID_FILE_KIND")
    require(limit is None or st.st_size<=limit, "FILE_TOO_LARGE")


def hash_file(path: Path) -> str:
    regular_file(path)
    d=hashlib.sha256()
    with path.open("rb") as f:
        while block:=f.read(1024*1024):
            d.update(block)
    return "sha256:"+d.hexdigest()


def openssl(*args: str) -> bytes:
    try:
        p=subprocess.run(["openssl",*args],capture_output=True,timeout=15,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise F01SignatureError("OPENSSL_UNAVAILABLE_OR_TIMEOUT") from exc
    require(p.returncode==0,"OPENSSL_OPERATION_FAILED")
    return p.stdout


def public_key_fingerprint(path: Path) -> str:
    regular_file(path,limit=16384)
    with tempfile.TemporaryDirectory(prefix="ptah-f01-key-snapshot-") as folder:
        snapshot=Path(folder)/"public-key.pem"
        # Snapshot the *opened* key bytes once. OpenSSL never reads an
        # untrusted mutable original after fingerprinting.
        with path.open("rb") as source, snapshot.open("xb") as output:
            raw=source.read(16385)
            require(len(raw)<=16384,"FILE_TOO_LARGE")
            output.write(raw)
        return _public_key_fingerprint_snapshot(snapshot)


def _public_key_fingerprint_snapshot(snapshot: Path) -> str:
    der=openssl("pkey","-pubin","-in",str(snapshot),"-pubout","-outform","DER")
    require(0<len(der)<16384,"INVALID_PUBLIC_KEY")
    return "sha256:"+hashlib.sha256(der).hexdigest()


@contextmanager
def source_snapshots(bundle:Path,public_key:Path):
    """One immutable private snapshot per operation for metadata, digest, key."""
    regular_file(bundle,limit=2*archive.MAX_BYTES+65536)
    regular_file(public_key,limit=16384)
    with tempfile.TemporaryDirectory(prefix="ptah-f01-immutable-inputs-") as folder:
        snapshot_bundle=Path(folder)/"service.tar"
        snapshot_key=Path(folder)/"key.pem"
        # file descriptors remain bound to the same file even on rename
        with bundle.open("rb") as source, snapshot_bundle.open("xb") as output:
            shutil.copyfileobj(source,output,1024*1024)
        with public_key.open("rb") as source, snapshot_key.open("xb") as output:
            data=source.read(16385)
            require(len(data)<=16384,"FILE_TOO_LARGE")
            output.write(data)
        yield snapshot_bundle,snapshot_key


def message_bytes(statement: dict) -> bytes:
    return (json.dumps(statement,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")


def validate_statement(statement: dict) -> None:
    require(type(statement) is dict
            and set(statement)=={"schema","artifact_sha256","source_commit",
                                "service_count","signer_fingerprint","execution_authorized",
                                "release_authorized","evidence_class"},
            "INVALID_SIGNED_STATEMENT_FIELDS")
    require(statement["schema"]==SCHEMA
            and statement["service_count"]==2
            and type(statement["service_count"]) is int
            and statement["execution_authorized"] is False
            and statement["release_authorized"] is False
            and statement["evidence_class"]=="candidate_artifact_integrity_only",
            "FORGED_RELEASE_OR_AUTHORITY")
    require(type(statement["source_commit"]) is str
            and SOURCE_SHA.fullmatch(statement["source_commit"]) is not None,"INVALID_COMMIT")
    for key in ("artifact_sha256","signer_fingerprint"):
        require(type(statement[key]) is str
                and FINGERPRINT.fullmatch(statement[key]) is not None,
                "INVALID_"+key.upper())


def unique_pairs(pairs):
    result={}
    for key,value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key]=value
    return result


def verified_statement(bundle: Path, trusted_key: Path,
                       expected_fingerprint: str) -> dict:
    require(type(expected_fingerprint) is str
            and FINGERPRINT.fullmatch(expected_fingerprint) is not None,
            "EXTERNAL_TRUST_FINGERPRINT_REQUIRED")
    with source_snapshots(bundle,trusted_key) as (saved_bundle,saved_key):
        return _statement_from_snapshots(saved_bundle,saved_key,expected_fingerprint)


def _statement_from_snapshots(bundle: Path, trusted_key: Path,
                              expected_fingerprint: str) -> dict:
    require(type(expected_fingerprint) is str
            and FINGERPRINT.fullmatch(expected_fingerprint) is not None,
            "EXTERNAL_TRUST_FINGERPRINT_REQUIRED")
    archive_result=archive.verify_bundle(bundle)
    fingerprint=_public_key_fingerprint_snapshot(trusted_key)
    require(fingerprint==expected_fingerprint,"EXTERNAL_TRUST_ANCHOR_MISMATCH")
    statement={
        "schema":SCHEMA,
        "artifact_sha256":hash_file(bundle),
        "source_commit":archive_result["source_commit"],
        "service_count":archive_result["services"],
        "signer_fingerprint":fingerprint,
        "execution_authorized":False,
        "release_authorized":False,
        "evidence_class":"candidate_artifact_integrity_only",
    }
    validate_statement(statement)
    return statement


def sign(bundle: Path, private_key: Path, public_key: Path,
         expected_fingerprint: str, output: Path) -> dict:
    require(not output.exists() and not output.is_symlink(),"OUTPUT_ALREADY_EXISTS")
    regular_file(private_key,limit=16384)
    require((private_key.stat().st_mode & 0o077)==0,
            "PRIVATE_KEY_PERMISSIONS_UNSAFE")
    for inp in (bundle,private_key,public_key):
        require(inp.resolve()!=output.resolve(),"OUTPUT_OVERLAPS_INPUT")
    # Keep the same opened archive/key snapshots throughout hashing,
    # signature creation and immediate public-key verification.
    with source_snapshots(bundle,public_key) as (snap_bundle,snap_pub):
        statement=_statement_from_snapshots(snap_bundle,snap_pub,expected_fingerprint)
        with tempfile.TemporaryDirectory(prefix="ptah-f01-sig-proof-") as folder:
            message=Path(folder)/"message"
            signature=Path(folder)/"signature"
            message.write_bytes(message_bytes(statement))
            openssl("pkeyutl","-sign","-inkey",str(private_key),"-rawin",
                    "-in",str(message),"-out",str(signature))
            signature_bytes=signature.read_bytes()
            require(len(signature_bytes)==64,"UNEXPECTED_SIGNATURE_SIZE")
            openssl("pkeyutl","-verify","-pubin","-inkey",str(snap_pub),
                    "-rawin","-in",str(message),"-sigfile",str(signature))
    record={"statement":statement,"signature_ed25519_hex":signature_bytes.hex()}
    data=message_bytes(record)
    require(len(data)<=MAX_SIDECAR_BYTES,"SIDECAR_TOO_LARGE")
    created=False
    try:
        with output.open("xb") as fd:
            created=True
            fd.write(data)
        result=verify(bundle,output,public_key,expected_fingerprint)
        return result
    except BaseException:
        # Do not remove another writer's file if exclusive creation failed.
        if created:
            output.unlink(missing_ok=True)
        raise


def verify(bundle: Path, sidecar: Path, public_key: Path,
           expected_fingerprint: str) -> dict:
    regular_file(sidecar,limit=MAX_SIDECAR_BYTES)
    try:
        raw=sidecar.read_bytes()
        doc=json.loads(raw,object_pairs_hook=unique_pairs)
    except (OSError,UnicodeError,json.JSONDecodeError) as exc:
        raise F01SignatureError("INVALID_SIDECAR_JSON") from exc
    require(type(doc) is dict
            and set(doc)=={"statement","signature_ed25519_hex"},
            "SIDECAR_FIELDS")
    require(message_bytes(doc)==raw,"NONCANONICAL_SIDECAR")
    statement=doc["statement"]
    validate_statement(statement)
    sig=doc["signature_ed25519_hex"]
    require(type(sig) is str and SIGNATURE.fullmatch(sig) is not None,"INVALID_SIGNATURE")
    with source_snapshots(bundle,public_key) as (snap_bundle,snap_pub):
        expected=_statement_from_snapshots(snap_bundle,snap_pub,expected_fingerprint)
        require(statement==expected,"ARTIFACT_OR_SOURCE_COMMIT_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="ptah-f01-verify-") as folder:
            message=Path(folder)/"message";signature=Path(folder)/"signature"
            message.write_bytes(message_bytes(statement))
            signature.write_bytes(bytes.fromhex(sig))
            openssl("pkeyutl","-verify","-pubin","-inkey",str(snap_pub),
                    "-rawin","-in",str(message),"-sigfile",str(signature))
    return {"status":"SIGNED_ARTIFACT_INTEGRITY_VERIFIED_NOT_ADMITTED",
            "source_commit":statement["source_commit"],
            "signer_fingerprint":expected_fingerprint,
            "execution_authorized":False,"release_authorized":False}


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--sign",action="store_true")
    g.add_argument("--verify",action="store_true")
    p.add_argument("--bundle",type=Path,required=True)
    p.add_argument("--sidecar",type=Path,required=True)
    p.add_argument("--public-key",type=Path,required=True)
    p.add_argument("--expected-fingerprint",type=str,required=True)
    p.add_argument("--private-key",type=Path)
    args=p.parse_args()
    try:
        if args.sign:
            require(args.private_key is not None,"SIGNING_KEY_REQUIRED")
            report=sign(args.bundle,args.private_key,args.public_key,
                        args.expected_fingerprint,args.sidecar)
        else:
            require(args.private_key is None,"VERIFY_MUST_NOT_TAKE_PRIVATE_KEY")
            report=verify(args.bundle,args.sidecar,args.public_key,
                          args.expected_fingerprint)
        print(json.dumps(report,sort_keys=True))
        return 0
    except (archive.BundleError,F01SignatureError,OSError) as exc:
        print("F01_SIGNATURE_REJECTED:"+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
