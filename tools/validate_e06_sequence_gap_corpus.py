#!/usr/bin/env python3
"""Validate non-authorizing E06 design evidence; never infer runtime admission."""
import json
import unicodedata
from pathlib import Path

CORPUS = Path(__file__).resolve().parents[1] / "docs/plans/e06-02-sequence-gap-cases.json"
ALLOWED = {"accept", "accept_terminal", "reject_gap", "requires_gap_evidence",
           "idempotent_replay", "reject_reuse", "reject_order"}

def invalid_identity(value):
    return (not isinstance(value, str) or not value.strip()
            or any(unicodedata.category(ch) in ("Cc", "Cf") for ch in value))

def validate(document):
    if not isinstance(document, dict):
        raise ValueError("corpus must be an object")
    if document.get("schema") != "ptah.e06.sequence-gap-review-cases.v1":
        raise ValueError("unknown corpus schema")
    if document.get("status") != "non_authorizing_design_evidence":
        raise ValueError("corpus must remain non-authorizing")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("missing cases")
    seen = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("case must be an object")
        identifier = case.get("id")
        if invalid_identity(identifier) or identifier in seen:
            raise ValueError("duplicate/invalid case id")
        seen.add(identifier)
        if any(type(case.get(key)) is not str or case[key] not in ALLOWED
               for key in ("contiguous_contract", "explicit_gap_contract")):
            raise ValueError("unknown disposition")
        records = case.get("records")
        if not isinstance(records, list) or not records:
            raise ValueError("missing records")
        invalid_sequence = False
        for record in records:
            if not isinstance(record, list) or len(record) != 3:
                raise ValueError("invalid record shape")
            node, sequence, intent = record
            if (invalid_identity(node)
                    or invalid_identity(intent)):
                raise ValueError("invalid record identity")
            if type(sequence) is not int or not 1 <= sequence <= 2**64 - 1:
                invalid_sequence = True
        if invalid_sequence and case["contiguous_contract"] != "reject_order":
            raise ValueError("invalid sequence must reject under contiguous contract")
    return len(cases)

if __name__ == "__main__":
    print(f"validated {validate(json.loads(CORPUS.read_text()))} non-authorizing cases")
