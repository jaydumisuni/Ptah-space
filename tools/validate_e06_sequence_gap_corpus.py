#!/usr/bin/env python3
"""Validate non-authorizing E06 design evidence; never infer runtime admission."""
import json
from pathlib import Path

CORPUS = Path(__file__).resolve().parents[1] / "docs/plans/e06-02-sequence-gap-cases.json"
ALLOWED = {"accept", "accept_terminal", "reject_gap", "requires_gap_evidence",
           "idempotent_replay", "reject_reuse", "reject_order"}

def validate(document):
    if document.get("schema") != "ptah.e06.sequence-gap-review-cases.v1":
        raise ValueError("unknown corpus schema")
    if document.get("status") != "non_authorizing_design_evidence":
        raise ValueError("corpus must remain non-authorizing")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("missing cases")
    seen = set()
    for case in cases:
        identifier = case.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in seen:
            raise ValueError("duplicate/invalid case id")
        seen.add(identifier)
        if case.get("contiguous_contract") not in ALLOWED or case.get("explicit_gap_contract") not in ALLOWED:
            raise ValueError("unknown disposition")
        records = case.get("records")
        if not isinstance(records, list) or not records:
            raise ValueError("missing records")
        invalid_sequence = False
        for record in records:
            if not isinstance(record, list) or len(record) != 3:
                raise ValueError("invalid record shape")
            node, sequence, intent = record
            if not isinstance(node, str) or not node or not isinstance(intent, str) or not intent:
                raise ValueError("invalid record identity")
            if type(sequence) is not int or not 1 <= sequence <= 2**64 - 1:
                invalid_sequence = True
        if invalid_sequence and case["contiguous_contract"] != "reject_order":
            raise ValueError("invalid sequence must reject under contiguous contract")
    return len(cases)

if __name__ == "__main__":
    print(f"validated {validate(json.loads(CORPUS.read_text()))} non-authorizing cases")
