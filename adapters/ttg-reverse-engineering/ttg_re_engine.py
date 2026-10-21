#!/usr/bin/env python3
"""Evidence-oriented, opt-in reverse engineering provider bridge for Ptah.

This adapter is deliberately not a Ptah Core provider. Ptah must allocate the
workspace, authorize source/materialization, and launch it through A04/A05.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
from typing import Any
import zipfile

SCHEMA = "ttg.ptah.reverse-engineering.v1"
MAX_INPUT_BYTES = 1024 * 1024 * 1024
MAX_ZIP_CHILDREN = 20000
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_ENTRY_BYTES = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_REA_EVIDENCE_BYTES = 32 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 180


class AdmissionError(ValueError):
    """The supplied artifact or destination violates a local admission rule."""


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inspect_input(source: Path) -> dict[str, Any]:
    if source.is_symlink():
        raise AdmissionError("symlink inputs are not admitted")
    if not source.exists():
        raise AdmissionError("input does not exist")
    if source.is_dir():
        files = []
        total_size = 0
        tree = hashlib.sha256()
        for f in sorted(source.rglob("*"), key=lambda x: x.relative_to(source).as_posix()):
            if f.is_symlink():
                raise AdmissionError("symlink inside application directory")
            if not f.is_file():
                continue
            total_size += f.stat().st_size
            if len(files) >= MAX_ZIP_CHILDREN or total_size > MAX_INPUT_BYTES:
                raise AdmissionError("application directory exceeds file-count or size budget")
            rel = f.relative_to(source).as_posix()
            checksum = digest(f)
            tree.update(json.dumps([rel, checksum], separators=(",", ":")).encode("utf-8"))
            files.append(rel)
        kind = "javascript_application" if "package.json" in files else "directory"
        return {"kind": kind, "sha256": tree.hexdigest(), "size": total_size,
                "file_count": len(files), "claims": ["tree_digest_sha256_v1"] +
                (["package_json_present"] if kind == "javascript_application" else ["unclassified_directory"])}
    if not source.is_file():
        raise AdmissionError("input must be a regular file or JS application directory")
    length = source.stat().st_size
    if length > MAX_INPUT_BYTES:
        raise AdmissionError("input exceeds 1 GiB admission budget")
    with source.open("rb") as handle:
        header = handle.read(256)
    suffix = source.suffix.lower()
    claims = []
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as zf:
            is_apk = "AndroidManifest.xml" in zf.namelist() and (suffix in {".apk", ".apks", ".xapk", ".apkm"} or "classes.dex" in zf.namelist())
        kind = "android_apk" if is_apk and suffix == ".apk" else "zip_container"
        claims.append("zip_central_directory")
        if is_apk:
            claims.append("android_manifest_entry")
    elif header.startswith(b"MZ"):
        kind = "pe_image"
        claims.append("mz_header_only_pe_signature_not_yet_verified")
    elif header.startswith(b"\x7fELF"):
        kind = "elf"
        claims.append("elf_magic")
    elif header[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        kind = "mach_o"
        claims.append("mach_o_magic")
    elif suffix in {".asar", ".js", ".mjs", ".cjs"}:
        kind = "javascript_artifact"
        claims.append("extension_only")
    elif suffix in {".bin", ".img", ".rom", ".fw", ".trx"}:
        kind = "firmware_candidate"
        claims.append("extension_only")
    else:
        kind = "unknown"
        claims.append("no_supported_signature")
    return {"kind": kind, "sha256": digest(source), "size": length, "claims": claims}


def _safe_zip_name(name: str) -> Path:
    if "\x00" in name or "\\" in name or name.startswith("/") or re.match(r"^[a-zA-Z]:", name):
        raise AdmissionError("unsafe ZIP entry name")
    parts = PurePosixPath(name).parts
    if not parts or any(part in {".", "..", ""} for part in parts):
        raise AdmissionError("unsafe ZIP entry traversal")
    if len(name) > 1024:
        raise AdmissionError("ZIP entry path exceeds budget")
    return Path(*parts)


def extract_raw_apk(source: Path, output: Path) -> dict[str, Any]:
    """Read-only source; bounded, non-overwriting ZIP derivative."""
    output.mkdir(parents=True, exist_ok=False)
    children: list[dict[str, Any]] = []
    with zipfile.ZipFile(source) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_CHILDREN:
            raise AdmissionError("ZIP child count exceeds budget")
        if sum(i.file_size for i in infos) > MAX_UNPACKED_BYTES:
            raise AdmissionError("ZIP expanded-size budget exceeded")
        checked: list[tuple[zipfile.ZipInfo, Path]] = []
        seen = set()
        for info in infos:
            rel = _safe_zip_name(info.filename)
            normalized = str(rel).casefold()
            if normalized in seen:
                raise AdmissionError("duplicate/case-colliding ZIP child")
            seen.add(normalized)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode):
                raise AdmissionError("ZIP symbolic link or special entry rejected")
            if info.file_size > MAX_ENTRY_BYTES:
                raise AdmissionError("ZIP entry exceeds per-child size budget")
            if info.file_size and info.file_size / max(1, info.compress_size) > MAX_COMPRESSION_RATIO:
                raise AdmissionError("ZIP compression ratio exceeds budget")
            checked.append((info, rel))
        for info, rel in checked:
            destination = output / rel
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            size = 0
            h = hashlib.sha256()
            with zf.open(info) as src, destination.open("xb") as dst:
                while chunk := src.read(1024 * 1024):
                    size += len(chunk)
                    if size > info.file_size or size > MAX_ENTRY_BYTES:
                        raise AdmissionError("ZIP stream exceeded declared size")
                    h.update(chunk)
                    dst.write(chunk)
            if size != info.file_size:
                raise AdmissionError("ZIP stream did not match declared size")
            children.append({"path": rel.as_posix(), "size": size, "sha256": h.hexdigest(), "view": "raw_package_child"})
    return {"view": "raw_apk", "count": len(children), "children": children, "status": "derivative_created"}


def resolve_command(value: str) -> str | None:
    if not value:
        return None
    path = Path(value)
    if path.is_file():
        return str(path.resolve())
    return shutil.which(value)


def _rea_launch_prefix(rea_cli: str) -> list[str] | None:
    """Never implicitly shell a Windows npm .cmd/.bat launcher."""
    executable = resolve_command(rea_cli)
    if executable is None:
        return None
    suffix = Path(executable).suffix.lower()
    if suffix in {".cmd", ".bat", ".ps1"}:
        return None
    if suffix in {".js", ".mjs", ".cjs"}:
        node = resolve_command("node")
        return [node, executable] if node else None
    if suffix == ".py":
        return [sys.executable, executable]
    return [executable]


def capabilities(rea_cli: str = "rea", app_recover_root: str | None = None) -> dict[str, Any]:
    app_root = Path(app_recover_root) if app_recover_root else None
    return {
        "schema": SCHEMA,
        "providers": {
            "apk_extractor_raw": {"available": True, "scope": "bounded raw APK extraction"},
            "apktool": {"available": bool(resolve_command("apktool")), "scope": "Android resource/Smali derivative"},
            "jadx": {"available": bool(resolve_command("jadx")), "scope": "Android Java-like decompiled view"},
            "app_recover": {
                "available": bool(app_root and (app_root / "native_export_recovery.py").is_file()),
                "scope": "App Recover static native export evidence; dependency-qualified separately",
            },
             "rea": {"available": bool(_rea_launch_prefix(rea_cli)), "scope": "REA CLI supported target inspections; prerequisites depend on task"},
        },
        "runtime_authority": "caller-owned Ptah Workspace, Grant, A04 Attempt and A05 process",
        "native_binary_execution": False,
    }


def _invoke(argv: list[str], log_path: Path, timeout: int) -> dict[str, Any]:
    """A bounded-time argv call. No shell, no target binary execution."""
    try:
        with log_path.open("wb") as log:
            completed = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, shell=False, timeout=timeout, check=False)
        status = "success" if completed.returncode == 0 else "failed"
        exit_code = completed.returncode
    except subprocess.TimeoutExpired:
        status = "timeout"
        exit_code = None
    except OSError as exc:
        log_path.write_text(type(exc).__name__ + ": " + str(exc)[:500], encoding="utf-8")
        status = "unavailable"
        exit_code = None
    # Reports carry fixed executable identity, not raw target-sensitive output.
    return {"tool": Path(argv[0]).name, "status": status, "exit_code": exit_code, "log": log_path.name, "timeout_seconds": timeout}


def _parse_rea_evidence(log_path: Path, destination: Path, source: Path, expected_sha256: str | None) -> dict[str, Any]:
    """Extract the final REA Evidence JSONL record, never confuse progress with proof."""
    if log_path.stat().st_size > MAX_REA_EVIDENCE_BYTES:
        return {"status": "unavailable", "reason": "REA output exceeded evidence parsing budget"}
    final = None
    progress = 0
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        if "rea_progress" in item:
            progress += 1
        if item.get("evidence_id") and isinstance(item.get("subject"), dict):
            final = item
    if final is None:
        return {"status": "unavailable", "reason": "REA did not provide a final typed Evidence record",
                "progress_records": progress}
    subject = final["subject"]
    claimed_path = subject.get("local_path")
    claimed_digest = subject.get("digest", {}).get("sha256") if isinstance(subject.get("digest"), dict) else None
    if not isinstance(claimed_path, str) or not claimed_path:
        return {"status": "unavailable", "reason": "REA Evidence subject has no source path"}
    try:
        bound_path = Path(claimed_path).resolve()
    except (OSError, ValueError):
        return {"status": "unavailable", "reason": "REA Evidence subject path is invalid"}
    if bound_path != source.resolve():
        return {"status": "unavailable", "reason": "REA Evidence subject is not the admitted input"}
    if not isinstance(claimed_digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", claimed_digest):
        return {"status": "unavailable", "reason": "REA Evidence subject digest is invalid"}
    if source.is_file() and (expected_sha256 is None or claimed_digest.lower() != expected_sha256.lower()):
        return {"status": "unavailable", "reason": "REA Evidence subject digest does not match input"}
    if source.is_dir() and subject.get("format") != "directory":
        return {"status": "unavailable", "reason": "REA Evidence subject is not a directory"}
    output_path = destination / "rea_evidence.json"
    payload = (json.dumps(final, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    output_path.write_bytes(payload)
    return {"status": "captured", "evidence_file": output_path.name,
            "evidence_sha256": hashlib.sha256(payload).hexdigest(), "evidence_id": final["evidence_id"],
            "progress_records": progress, "rea_subject_sha256": final.get("subject", {}).get("digest", {}).get("sha256")}


def _rea_operation(kind: str) -> str | None:
    return {
        "javascript_application": "analyze-javascript-application",
        "javascript_artifact": "analyze-javascript-application",
        "android_apk": "inspect-android-package",
        "pe_image": "analyze",
        "elf": "analyze",
        "mach_o": "analyze",
        "firmware_candidate": "inspect-firmware-regions",
        "zip_container": "inspect-artifact",
    }.get(kind)


def analyze(
    source: Path, destination: Path, *, providers: set[str],
    rea_cli: str, app_recover_root: str | None, app_recover_python: str | None = None,
    timeout: int = TOOL_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Dispatch only declared capabilities; fail closed on unsafe/missing admission."""
    if source.is_symlink():
        raise AdmissionError("symlink inputs are not admitted")
    classification = inspect_input(source)
    destination.mkdir(parents=True, exist_ok=False)
    receipt: dict[str, Any] = {
        "schema": SCHEMA, "input": {"path": str(source.resolve()), **classification},
        "provider_results": [], "limitations": [
            "Derived/decompiled views are not original source code.",
            "No analyzed target executable is launched by this bridge.",
            "This evidence is not a Ptah Object/Grant/Attempt receipt until Ptah admits it.",
        ], "completion": "evidence_only", "provider_failures": 0,
    }
    kind = classification["kind"]
    results = receipt["provider_results"]
    if kind == "android_apk" and "apk_extractor" in providers:
        result = {"provider": "apk_extractor", "views": []}
        try:
            result["views"].append(extract_raw_apk(source, destination / "raw_apk"))
        except (AdmissionError, zipfile.BadZipFile, OSError, EOFError) as exc:
            result["views"].append({"view": "raw_apk", "status": "rejected", "reason": str(exc)[:500]})
            receipt["provider_failures"] += 1
        for tool, argv in (
            ("apktool", ["d", str(source.resolve()), "-o", str(destination / "apktool")]),
            ("jadx", ["-d", str(destination / "jadx"), str(source.resolve())]),
        ):
            executable = resolve_command(tool)
            if executable is None:
                result["views"].append({"view": tool, "status": "unavailable", "reason": "tool not installed"})
            elif receipt["provider_failures"] == 0:
                task = _invoke([executable, *argv], destination / (tool + ".log"), timeout)
                result["views"].append({"view": tool, **task, "role": "derived_view"})
                if task["status"] != "success":
                    receipt["provider_failures"] += 1
        results.append(result)
    if kind == "pe_image" and "app_recover" in providers:
        app_root = Path(app_recover_root) if app_recover_root else None
        if app_root is None or not (app_root / "native_export_recovery.py").is_file():
            results.append({"provider": "app_recover", "status": "unavailable", "reason": "explicit App Recover root not qualified"})
        else:
            driver = Path(__file__).with_name("app_recover_driver.py")
            out = destination / "app_recover"
            out.mkdir(exist_ok=False)
            interpreter = app_recover_python or sys.executable
            task = _invoke([interpreter, str(driver), str(app_root.resolve()), str(source.resolve()), str(out)], destination / "app_recover.log", timeout)
            if task["status"] == "success":
                report_path = out / "driver_receipt.json"
                if report_path.is_file():
                    try:
                        report = json.loads(report_path.read_text(encoding="utf-8"))
                        if report.get("source_sha256") == classification["sha256"] and report.get("is_pe") is True:
                            task["evidence"] = {
                                "file": "app_recover/driver_receipt.json",
                                "sha256": digest(report_path),
                                "export_count": report.get("export_count"),
                                "action_candidate_count": report.get("action_candidate_count"),
                            }
                        else:
                            task["status"] = "incomplete_evidence"
                    except (ValueError, OSError):
                        task["status"] = "incomplete_evidence"
                else:
                    task["status"] = "incomplete_evidence"
            results.append({"provider": "app_recover", **task, "view": "native_export_evidence"})
            if task["status"] != "success":
                receipt["provider_failures"] += 1
    if "rea" in providers:
        launch = _rea_launch_prefix(rea_cli)
        operation = _rea_operation(kind)
        if not launch:
            results.append({"provider": "rea", "status": "unavailable", "reason": "REA CLI unavailable, or Windows batch wrapper rejected; supply a Node .mjs entrypoint"})
        elif not operation:
            results.append({"provider": "rea", "status": "unsupported", "reason": f"no safe REA static lane for {kind}"})
        else:
            task = _invoke([*launch, operation, str(source.resolve()), "--json"], destination / "rea.log", timeout)
            if task["status"] == "success":
                proof = _parse_rea_evidence(
                    destination / "rea.log", destination, source, classification["sha256"]
                )
                task["evidence"] = proof
                if proof["status"] != "captured":
                    task["status"] = "incomplete_evidence"
                else:
                    try:
                        updated = inspect_input(source)
                        if updated["sha256"] != classification["sha256"] or updated.get("size") != classification.get("size"):
                            task["status"] = "incomplete_evidence"
                            proof["status"] = "unavailable"
                            proof["reason"] = "REA input changed during analysis"
                    except (AdmissionError, OSError, ValueError):
                        task["status"] = "incomplete_evidence"
                        proof["status"] = "unavailable"
                        proof["reason"] = "REA input could not be revalidated after analysis"
            results.append({"provider": "rea", "operation": operation, **task, "view": "rea_evidence"})
            if task["status"] != "success":
                receipt["provider_failures"] += 1
    # No matching provider is a classification-only outcome, never evidence
    # of completed reverse-engineering analysis.
    if not results:
        receipt["analysis_state"] = "unsupported"
        receipt["limitations"].append(
            "No selected qualified analyzer handled this artifact kind; classification only."
        )
    else:
        receipt["analysis_state"] = "partial" if receipt["provider_failures"] or any(
            r.get("status") in {"unavailable", "unsupported", "failed", "timeout", "incomplete_evidence"} or
            any(v.get("status") in {"unavailable", "rejected", "failed", "timeout"} for v in r.get("views", []))
            for r in results
        ) else "evidence_recorded"
    (destination / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TTG RE engine: non-authoritative Ptah provider candidate")
    sub = parser.add_subparsers(dest="action", required=True)
    caps = sub.add_parser("capabilities")
    caps.add_argument("--rea-cli", default="rea")
    caps.add_argument("--app-recover-root")
    run = sub.add_parser("analyze")
    run.add_argument("source", type=Path)
    run.add_argument("--out", type=Path, required=True, help="New evidence directory (must not exist)")
    run.add_argument("--providers", nargs="+", choices=["apk_extractor", "app_recover", "rea"], default=["apk_extractor", "app_recover", "rea"])
    run.add_argument("--rea-cli", default="rea")
    run.add_argument("--app-recover-root")
    run.add_argument("--app-recover-python", help="Qualified Python interpreter for the private App Recover checkout")
    run.add_argument("--timeout", type=int, default=TOOL_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    if args.action == "capabilities":
        print(json.dumps(capabilities(args.rea_cli, args.app_recover_root), indent=2))
        return 0
    try:
        if not 1 <= args.timeout <= 3600:
            raise AdmissionError("timeout must be between 1 and 3600 seconds")
        receipt = analyze(args.source, args.out, providers=set(args.providers),
                          rea_cli=args.rea_cli, app_recover_root=args.app_recover_root,
                          app_recover_python=args.app_recover_python, timeout=args.timeout)
        print(json.dumps({"schema": SCHEMA, "analysis_state": receipt["analysis_state"],
                          "receipt": str((args.out / "receipt.json").resolve())}))
        return 0 if receipt["analysis_state"] == "evidence_recorded" else 2
    except (AdmissionError, OSError, zipfile.BadZipFile) as exc:
        print(json.dumps({"schema": SCHEMA, "analysis_state": "admission_rejected", "error": str(exc)[:500]}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
