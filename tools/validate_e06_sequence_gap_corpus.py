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
            or value != value.strip()
            or any(unicodedata.category(ch) in ("Cc", "Cf") for ch in value))

def load_corpus(raw):
    """Reject ambiguous duplicate JSON keys before design-evidence validation."""
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate corpus JSON key")
            result[key] = value
        return result

    def reject_nonfinite(token):
        raise ValueError("non-finite corpus JSON constant: " + token)

    return json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_nonfinite)


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
        # Canonically equivalent Unicode identifiers must not alias distinct cases.
        normalized_id = (unicodedata.normalize("NFC", identifier)
                         if isinstance(identifier, str) else None)
        if invalid_identity(identifier) or normalized_id in seen:
            raise ValueError("duplicate/invalid case id")
        seen.add(normalized_id)
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
        if invalid_sequence and any(
            case[contract] != "reject_order"
            for contract in ("contiguous_contract", "explicit_gap_contract")
        ):
            raise ValueError("invalid sequence must reject under both contracts")
    return len(cases)

if __name__ == "__main__":
    print(f"validated {validate(load_corpus(CORPUS.read_text()))} non-authorizing cases")
