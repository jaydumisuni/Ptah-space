#!/usr/bin/env python3
"""Fail-closed, evidence-only intake for SHA-bound Donor Fetcher Qt dispatch graphs.

This is not a Ptah production provider or an A07 object registration.
No donor binaries are executed and no device transport is touched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SCHEMA = "ttg.ptah.reverse-engineering.donor-handoff-import.v1"
INPUT_SCHEMA = "ttg.donor.ptah.reverse-engineering-evidence-handoff.v2"
NATIVE_SHA = "fa59be07e4f2cb266fc5dd8e4a132bf95452cbc477949d53ea916191a546bc6f"
MAX_JSON_BYTES = 5 * 1024 * 1024


class HandoffRejected(ValueError):
    pass


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as f:
        for buf in iter(lambda: f.read(8 * 1024 * 1024), b""):
            sha.update(buf)
    return sha.hexdigest()


def child(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative:
        raise HandoffRejected("invalid evidence-relative path")
    parts = Path(relative).parts
    if Path(relative).is_absolute() or any(p in {"..", "."} for p in parts):
        raise HandoffRejected("traversing or absolute evidence path")
    dest = root.joinpath(*parts)
    if dest.is_symlink() or not dest.resolve().is_relative_to(root.resolve()):
        raise HandoffRejected("evidence path escapes root or is a symlink")
    if not dest.is_file() or dest.stat().st_size > MAX_JSON_BYTES:
        raise HandoffRejected("evidence file missing or exceeds bound")
    return dest


def load_json(path: Path):
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as e:
        raise HandoffRejected("malformed or unreadable evidence") from e



def verify_evidence_digest(path: Path, expected: str, expected_size: int | None = None) -> str:
    if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise HandoffRejected("invalid source evidence digest")
    raw = path.read_bytes()
    if (expected_size is None or len(raw) == expected_size) and hashlib.sha256(raw).hexdigest() == expected:
        return "raw"
    # Windows evidence JSON was created with CRLF. Git's text checkout may
    # canonicalize it to LF on Linux. Only the *exact* deterministic reverse
    # conversion is accepted, and its SHA-256 must equal the frozen digest.
    if path.suffix == ".json" and b"\r" not in raw and b"\n" in raw:
        restored = raw.replace(b"\n", b"\r\n")
        if (expected_size is None or len(restored) == expected_size) and hashlib.sha256(restored).hexdigest() == expected:
            return "git_lf_to_original_crlf_exact"
    raise HandoffRejected("evidence content does not match source digest")

def verify(root: Path, native_source: Path | None = None) -> tuple[dict, list]:
    root = root.resolve()
    handoff_path = child(root, "evidence/athena-harvest/20261015/androidutility-ptah-rea-readonly-evidence-handoff-v2.json")
    handoff = load_json(handoff_path)
    if handoff.get("schema") != INPUT_SCHEMA or handoff.get("donor_pe_sha256") != NATIVE_SHA:
        raise HandoffRejected("wrong handoff schema or exact donor digest")
    previous = handoff.get("previous_handoff", {})
    prior = child(root, previous.get("relative_path", ""))
    verification_modes = [verify_evidence_digest(prior, previous.get("sha256"))]
    evidence_sources = handoff.get("source_evidence", [])
    if len(evidence_sources) != 9:
        raise HandoffRejected("unexpected evidence source inventory")
    seen = set()
    for src in evidence_sources:
        path = src.get("relative_path", "")
        if path in seen:
            raise HandoffRejected("duplicate evidence source")
        seen.add(path)
        f = child(root, path)
        verification_modes.append(verify_evidence_digest(f, src.get("sha256"), src.get("bytes")))
    required_graphs = {"evidence/athena-harvest/20261015/androidutility-qt-metacall-dispatch-v3.json", "evidence/athena-harvest/20261015/androidutility-native-handler-callgraph-v1.json"}
    if not required_graphs.issubset(seen):
        raise HandoffRejected("required native graph digests not bound to handoff")
    qt = load_json(child(root, "evidence/athena-harvest/20261015/androidutility-qt-metacall-dispatch-v3.json"))
    graph = load_json(child(root, "evidence/athena-harvest/20261015/androidutility-native-handler-callgraph-v1.json"))
    if qt.get("source_native_sha256") != NATIVE_SHA or graph.get("source_sha256") != NATIVE_SHA:
        raise HandoffRejected("source mismatch in supplementary graph")
    methods = qt.get("methods", [])
    if len(methods) != 24 or qt.get("method_count") != 24:
        raise HandoffRejected("expected 24 exact native Qt dispatch methods")
    edges = handoff.get("graph", {}).get("qt_method_to_native_handler", [])
    if len(edges) != 24:
        raise HandoffRejected("incomplete native dispatch handoff")
    for method, edge in zip(methods, edges):
        if (method.get("method_index") != edge.get("method_index")
            or method.get("name") != edge.get("method")
            or method.get("native_handler_entry_va") != edge.get("native_entrypoint_va")
            or method.get("dispatch_direct_calls", [{}])[0].get("callsite_va") != edge.get("verified_dispatch_callsite_va")
            or edge.get("exact_ui_sender_verified") is not False
            or method.get("device_backend_proven") is not False):
            raise HandoffRejected("invalid or promoted Qt method edge")
    named = qt.get("named_ui_associations", [])
    if len(named) != 13 or len(graph.get("reports", [])) != 13:
        raise HandoffRejected("named slot / callgraph count mismatch")
    if any(a.get("exact_receiver_instance_join_proven") is not False for a in named):
        raise HandoffRejected("unproved Qt sender or receiver claimed as verified")
    if any(r.get("possible_static_resolver_path_count") != 0 or r.get("search_cap_hit") for r in graph["reports"]):
        raise HandoffRejected("backend resolver search needs requalification")
    coverage = handoff.get("coverage", {})
    for key, expected in {
        "proven_qt_meta_method_to_native_entrypoint": 24,
        "qt_named_ui_slot_candidates_with_object_strings": 13,
        "control_to_backend_edges_proven": 0,
        "bounded_direct_callgraph_backend_resolver_paths": 0,
        "qt_exact_receiver_instance_control_join_proven": 0,
        "device_operations_executed": 0,
    }.items():
        if coverage.get(key) != expected:
            raise HandoffRejected("unexpected claim: " + key)
    if handoff.get("graph", {}).get("handler_to_backend_resolution", {}).get("verified_paths") != []:
        raise HandoffRejected("unsupported backend path promotion")
    authority = handoff.get("write_authority", {})
    if authority.get("device_operations") is not False or authority.get("license_or_auth_bypass") is not False:
        raise HandoffRejected("unsafe execution claim")
    original_verified = False
    if native_source is not None:
        source = native_source.resolve(strict=True)
        if not source.is_file() or source.stat().st_size != handoff.get("donor_bytes") or digest(source) != NATIVE_SHA:
            raise HandoffRejected("physical native source digest mismatch")
        original_verified = True
    receipt = {
        "schema": SCHEMA,
        "status": "source_and_metadata_verified" if original_verified else "metadata_only_verified",
        "completion": "evidence_only",
        "source_native_sha256_claimed": NATIVE_SHA,
        "original_source_rehashed": original_verified,
        "evidence_handoff_sha256": digest(handoff_path),
        "evidence_sources_sha256_verified": len(seen) + 1,
        "git_crlf_transport_reconstructions": verification_modes.count("git_lf_to_original_crlf_exact"),
        "native_meta_method_edges_verified": 24,
        "named_control_candidates": 13,
        "verified_control_to_backend_edges": 0,
        "device_operations_executed": 0,
        "production_ptah_provider_admitted": False,
        "workspace_grant_or_lease_created": False,
        "status_note": "Static Qt meta-method calls are verified; sender instance, backend DLL ABI, physical device execution and Ptah A04/A05/A07 admission are not.",
    }
    return receipt, edges



INDIRECT_PATH = "evidence/athena-harvest/20261015/androidutility-qt-instance-indirect-dispatch-v1.json"
INDIRECT_SCHEMA = "ttg.donor.androidutility.qt-instance-indirect-dispatch.v1"
INDIRECT_SHA = "053343dea7cd939f275981b30f814ebe667456616a4a5c037b341c166986e282"
EXPECTED_IAT_IMPORTS = {
    "GetCurrentThreadId", "WaitForSingleObject", "CloseHandle", "CreateThread",
    "SetThreadPriority", "ResumeThread", "GetCurrentThread", "GetThreadPriority",
}


def verify_indirect(root: Path) -> tuple[dict, list]:
    """Validate candidate-only static dispatch against the v2 source graph."""
    root = root.resolve()
    path = child(root, INDIRECT_PATH)
    transport = verify_evidence_digest(path, INDIRECT_SHA)
    row = load_json(path)
    qt_path = child(root, "evidence/athena-harvest/20261015/androidutility-qt-metacall-dispatch-v3.json")
    direct_path = child(root, "evidence/athena-harvest/20261015/androidutility-native-handler-callgraph-v1.json")
    qt = load_json(qt_path)
    if row.get("schema") != INDIRECT_SCHEMA or row.get("source_sha256") != NATIVE_SHA or row.get("source_bytes") != 353236480:
        raise HandoffRejected("indirect evidence schema or native source mismatch")
    if (verify_evidence_digest(qt_path, row.get("qt_evidence_sha256")) not in
            {"raw", "git_lf_to_original_crlf_exact"}):
        raise HandoffRejected("Qt evidence digest mismatch")
    verify_evidence_digest(direct_path, row.get("direct_callgraph_evidence_sha256"))
    named = qt.get("named_ui_associations", [])
    expected = {(a["slot_name"], a["native_handler_entry_va"]) for a in named}
    actual = row.get("static_setup_associations", [])
    if len(expected) != 13 or len(actual) != 13:
        raise HandoffRejected("incomplete Qt setup associations")
    seen = set()
    for item in actual:
        key = (item.get("slot_name"), item.get("native_handler_entry_va"))
        if key not in expected or key in seen:
            raise HandoffRejected("Qt setup slot missing, duplicated or rebinding")
        seen.add(key)
        if item.get("runtime_sender_receiver_pair_proven") is not False or item.get("device_operation_enabled") is not False:
            raise HandoffRejected("unsupported runtime or device authority promotion")
        proofs = item.get("static_setup_evidence")
        if not isinstance(proofs, list) or not proofs:
            raise HandoffRejected("missing construction evidence")
        for proof in proofs:
            if proof.get("same_setup_function_proven") is not True:
                raise HandoffRejected("unsupported setup-function claim")
            member = proof.get("widget_storage_candidate")
            if member is not None and member.get("exact_widget_instance_proven") is not False:
                raise HandoffRejected("unproved instance target promoted")
    sites = row.get("indirect_callsites", [])
    if not isinstance(sites, list) or len(sites) != 39 or row.get("unique_indirect_callsites") != 39:
        raise HandoffRejected("indirect instruction inventory changed")
    allowed = {"pe_import_iat", "base_index_memory_indirect", "register_indirect"}
    counts = {"pe_import_iat": 0, "base_index_memory_indirect": 0, "register_indirect": 0}
    addresses = set()
    imports = set()
    for site in sites:
        va = site.get("instruction_va")
        shape = site.get("dispatch_shape")
        raw_bytes = site.get("instruction_bytes")
        if (not isinstance(va, str) or not va.startswith("0x")
                or not isinstance(raw_bytes, str) or len(raw_bytes) not in range(2, 32)
                or any(c not in "0123456789abcdef" for c in raw_bytes)):
            raise HandoffRejected("invalid instruction witness")
        try:
            address = int(va, 16)
        except ValueError as e:
            raise HandoffRejected("invalid instruction address") from e
        if address < 0x401000 or va in addresses or shape not in allowed:
            raise HandoffRejected("duplicate address or unrecognized indirect shape")
        addresses.add(va)
        counts[shape] += 1
        if shape == "pe_import_iat":
            if (site.get("proven_target") is not True
                or site.get("imported_library", "").upper() != "KERNEL32.DLL"
                or site.get("target_kind") != "declared_import_symbol_not_runtime_library_address"):
                raise HandoffRejected("unbound or escalated IAT edge")
            imports.add(site.get("imported_symbol"))
        elif site.get("proven_target") is not False:
            raise HandoffRejected("unresolved dispatch promoted")
    if (counts != row.get("indirect_dispatch_shape_counts") or counts !=
            {"pe_import_iat": 8, "base_index_memory_indirect": 17, "register_indirect": 14}
            or imports != EXPECTED_IAT_IMPORTS):
        raise HandoffRejected("dispatch census or import binding changed")
    scan = row.get("per_slot_scan", [])
    if len(scan) != 13 or {s.get("slot") for s in scan} != {x[0] for x in expected}:
        raise HandoffRejected("per-slot scan incomplete")
    for item in scan:
        items = item.get("indirect_site_vas")
        if not isinstance(items, list) or len(items) != item.get("unique_indirect_callsites") or len(items) != len(set(items)) or not set(items).issubset(addresses):
            raise HandoffRejected("per-slot scan cites unsupported instruction")
    if (row.get("ui_runtime_receiver_proven") is not False
        or row.get("handler_to_backend_protocol_proven") is not False
        or row.get("device_operations_executed") != 0 or row.get("binary_modifications") != 0
        or row.get("verified_iat_callsite_count") != 8):
        raise HandoffRejected("unproven backend or device access claim")
    receipt = {
        "indirect_evidence_schema": INDIRECT_SCHEMA,
        "indirect_evidence_sha256": INDIRECT_SHA,
        "indirect_digest_transport": transport,
        "qt_setup_candidates": 13,
        "static_indirect_instruction_sites": 39,
        "pe_declared_import_edges": 8,
        "unresolved_non_iat_indirect_sites": 31,
        "concrete_device_backend_edges": 0,
        "physical_device_actions": 0,
        "execution_authorized": False,
        "production_ptah_provider_admitted": False,
    }
    return receipt, sites


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--donor-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="New output directory; existing paths are rejected")
    parser.add_argument("--native-source", type=Path, default=None)
    parser.add_argument("--include-indirect-v1", action="store_true",
                        help="Require exact b71220c SHA-bound static indirect candidate evidence")
    args = parser.parse_args()
    try:
        receipt, edges = verify(args.donor_root, args.native_source)
        indirect_sites = None
        if args.include_indirect_v1:
            extra, indirect_sites = verify_indirect(args.donor_root)
            receipt.update(extra)
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (args.out / "qt_method_edges.json").write_text(json.dumps(edges, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        if indirect_sites is not None:
            (args.out / "indirect_dispatch_candidates.json").write_text(
                json.dumps(indirect_sites, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (HandoffRejected, FileExistsError, FileNotFoundError, OSError, ValueError) as e:
        print(json.dumps({"schema": SCHEMA, "status": "rejected", "reason": str(e)[:320]}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
