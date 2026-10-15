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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--donor-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="New output directory; existing paths are rejected")
    parser.add_argument("--native-source", type=Path, default=None)
    args = parser.parse_args()
    try:
        receipt, edges = verify(args.donor_root, args.native_source)
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (args.out / "qt_method_edges.json").write_text(json.dumps(edges, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (HandoffRejected, FileExistsError, FileNotFoundError, OSError, ValueError) as e:
        print(json.dumps({"schema": SCHEMA, "status": "rejected", "reason": str(e)[:320]}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
