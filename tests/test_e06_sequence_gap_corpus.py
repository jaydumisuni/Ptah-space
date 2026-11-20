import copy
import importlib.util
import json
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools/validate_e06_sequence_gap_corpus.py"
spec = importlib.util.spec_from_file_location("e06_validator", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CorpusValidationTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(module.CORPUS.read_text())

    def test_duplicate_json_keys_rejected_at_any_depth(self):
        for raw in (
            '{"schema":"first","schema":"second"}',
            '{"cases":[{"id":"first","id":"second"}]}',
            '{"cases":[{"records":[{"node":"a","node":"b"}]}]}',
        ):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "duplicate corpus JSON key"):
                    module.load_corpus(raw)

    def test_nonfinite_json_constants_rejected_at_any_depth(self):
        for raw in ('{"extra":NaN}', '{"cases":[{"extra":Infinity}]}', '{"cases":[{"records":[-Infinity]}]}'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "non-finite corpus JSON constant"):
                    module.load_corpus(raw)

    def test_unrecognized_corpus_or_case_fields_rejected(self):
        # Unknown fields must not smuggle authority claims into review evidence.
        for location in ("corpus", "case"):
            with self.subTest(location=location):
                case = copy.deepcopy(self.document)
                target = case if location == "corpus" else case["cases"][0]
                target["runtime_authorized"] = True
                with self.assertRaisesRegex(ValueError, "unexpected .* fields"):
                    module.validate(case)

    def test_contradictory_policy_dispositions_rejected(self):
        for contiguous, alternate in (("accept", "reject_order"), ("reject_gap", "accept"),
                                      ("requires_gap_evidence", "reject_gap"),
                                      ("reject_reuse", "idempotent_replay")):
            with self.subTest(contiguous=contiguous, alternate=alternate):
                case = copy.deepcopy(self.document)
                case["cases"][0]["contiguous_contract"] = contiguous
                case["cases"][0]["explicit_gap_contract"] = alternate
                with self.assertRaisesRegex(ValueError, "inconsistent policy dispositions"):
                    module.validate(case)

    def test_current_corpus(self):
        self.assertGreaterEqual(module.validate(self.document), 17)

    def test_non_object_corpus_rejected(self):
        with self.assertRaisesRegex(ValueError, "corpus must be an object"):
            module.validate([])

    def test_non_object_case_rejected(self):
        case = copy.deepcopy(self.document)
        case["cases"][0] = None
        with self.assertRaisesRegex(ValueError, "case must be an object"):
            module.validate(case)

    def test_missing_or_non_list_records_rejected(self):
        for records in (None, {}, [], "records"):
            with self.subTest(records=records):
                case = copy.deepcopy(self.document)
                case["cases"][0]["records"] = records
                with self.assertRaisesRegex(ValueError, "missing records"):
                    module.validate(case)

    def test_malformed_record_shape_rejected(self):
        for record in (None, {}, [], ["node", 1], ["node", 1, "intent", "extra"]):
            with self.subTest(record=record):
                case = copy.deepcopy(self.document)
                case["cases"][0]["records"][0] = record
                with self.assertRaisesRegex(ValueError, "invalid record shape"):
                    module.validate(case)

    def test_boolean_sequence_is_not_integer(self):
        case = copy.deepcopy(self.document)
        case["cases"][0]["records"][0][1] = True
        with self.assertRaises(ValueError):
            module.validate(case)

    def test_whitespace_only_case_id_rejected(self):
        case = copy.deepcopy(self.document)
        case["cases"][0]["id"] = " \t "
        with self.assertRaisesRegex(ValueError, "duplicate/invalid case id"):
            module.validate(case)

    def test_whitespace_only_record_identity_rejected(self):
        for field in (0, 2):
            with self.subTest(field=field):
                case = copy.deepcopy(self.document)
                case["cases"][0]["records"][0][field] = " \n "
                with self.assertRaisesRegex(ValueError, "invalid record identity"):
                    module.validate(case)

    def test_padded_case_and_record_identities_rejected(self):
        for field in ("case", "node", "intent"):
            for padding in (" ", "\t", "\u00a0"):
                for leading in (True, False):
                    with self.subTest(field=field, padding=repr(padding), leading=leading):
                        case = copy.deepcopy(self.document)
                        record = case["cases"][0]["records"][0]
                        if field == "case":
                            target, key, error = case["cases"][0], "id", "duplicate/invalid case id"
                        else:
                            target, key, error = record, 0 if field == "node" else 2, "invalid record identity"
                        target[key] = (padding + target[key]) if leading else (target[key] + padding)
                        with self.assertRaisesRegex(ValueError, error):
                            module.validate(case)

    def test_control_characters_in_case_and_record_identities_rejected(self):
        for field in ("case", "node", "intent"):
            for character in ("\x00", "\x1b", "\x7f", "\n"):
                with self.subTest(field=field, character=repr(character)):
                    case = copy.deepcopy(self.document)
                    if field == "case":
                        case["cases"][0]["id"] += character
                        error = "duplicate/invalid case id"
                    else:
                        case["cases"][0]["records"][0][0 if field == "node" else 2] += character
                        error = "invalid record identity"
                    with self.assertRaisesRegex(ValueError, error):
                        module.validate(case)

    def test_unicode_format_and_c1_controls_in_identities_rejected(self):
        for field in ("case", "node", "intent"):
            for character in ("\u202e", "\u2066", "\u200d", "\u0085"):
                with self.subTest(field=field, character=repr(character)):
                    case = copy.deepcopy(self.document)
                    if field == "case":
                        case["cases"][0]["id"] += character
                        error = "duplicate/invalid case id"
                    else:
                        case["cases"][0]["records"][0][0 if field == "node" else 2] += character
                        error = "invalid record identity"
                    with self.assertRaisesRegex(ValueError, error):
                        module.validate(case)

    def test_unicode_line_and_paragraph_separators_rejected_in_identities(self):
        # These separators can spoof record boundaries in human review evidence.
        for field in ("case", "node", "intent"):
            for character in ("\u2028", "\u2029"):
                with self.subTest(field=field, character=repr(character)):
                    case = copy.deepcopy(self.document)
                    if field == "case":
                        case["cases"][0]["id"] += character
                        error = "duplicate/invalid case id"
                    else:
                        case["cases"][0]["records"][0][0 if field == "node" else 2] += character
                        error = "invalid record identity"
                    with self.assertRaisesRegex(ValueError, error):
                        module.validate(case)

    def test_decomposed_unicode_identity_rejected_at_all_boundaries(self):
        # Distinct serialized identities must not alias after NFC normalization.
        for field in ("case", "node", "intent"):
            with self.subTest(field=field):
                case = copy.deepcopy(self.document)
                if field == "case":
                    case["cases"][0]["id"] += "e\u0301"
                    error = "duplicate/invalid case id"
                else:
                    case["cases"][0]["records"][0][0 if field == "node" else 2] += "e\u0301"
                    error = "invalid record identity"
                with self.assertRaisesRegex(ValueError, error):
                    module.validate(case)

    def test_unpaired_unicode_surrogates_rejected_in_identities(self):
        # JSON permits escaped surrogate code points that cannot be UTF-8 encoded.
        for field in ("case", "node", "intent"):
            for character in ("\ud800", "\udfff"):
                with self.subTest(field=field, character=repr(character)):
                    case = copy.deepcopy(self.document)
                    if field == "case":
                        case["cases"][0]["id"] += character
                        error = "duplicate/invalid case id"
                    else:
                        case["cases"][0]["records"][0][0 if field == "node" else 2] += character
                        error = "invalid record identity"
                    with self.assertRaisesRegex(ValueError, error):
                        module.validate(case)

    def test_unicode_noncharacters_rejected_in_evidence_identities(self):
        # Unicode noncharacters are not portable evidence identifiers, even
        # though JSON permits them and Python classifies them as unassigned.
        for field in ("case", "node", "intent"):
            for character in ("\ufdd0", "\ufdef", "\ufffe", "\U0001ffff"):
                with self.subTest(field=field, character=repr(character)):
                    case = copy.deepcopy(self.document)
                    if field == "case":
                        case["cases"][0]["id"] += character
                        error = "duplicate/invalid case id"
                    else:
                        case["cases"][0]["records"][0][0 if field == "node" else 2] += character
                        error = "invalid record identity"
                    with self.assertRaisesRegex(ValueError, error):
                        module.validate(case)

    def test_variation_selectors_cannot_alias_evidence_identities(self):
        # Variation selectors are NFC-stable and can be invisible in review logs.
        for field in ("case", "node", "intent"):
            for selector in ("\ufe0e", "\ufe0f", "\U000e0100", "\U000e01ef"):
                with self.subTest(field=field, selector=repr(selector)):
                    case = copy.deepcopy(self.document)
                    if field == "case":
                        case["cases"][0]["id"] += selector
                        error = "duplicate/invalid case id"
                    else:
                        case["cases"][0]["records"][0][0 if field == "node" else 2] += selector
                        error = "invalid record identity"
                    with self.assertRaisesRegex(ValueError, error):
                        module.validate(case)

    def test_non_string_record_identity_rejected_fail_closed(self):
        for field in (0, 2):
            for value in (None, [], {}, True, 42):
                with self.subTest(field=field, value=value):
                    case = copy.deepcopy(self.document)
                    case["cases"][0]["records"][0][field] = value
                    with self.assertRaisesRegex(ValueError, "invalid record identity"):
                        module.validate(case)

    def test_non_string_dispositions_rejected_fail_closed(self):
        for field in ("contiguous_contract", "explicit_gap_contract"):
            for value in ([], {}, None, True):
                with self.subTest(field=field, value=value):
                    case = copy.deepcopy(self.document)
                    case["cases"][0][field] = value
                    with self.assertRaisesRegex(ValueError, "unknown disposition"):
                        module.validate(case)

    def test_invalid_sequence_requires_explicit_rejection(self):
        for sequence in (0, -1, 2**64, 1.5, "1", None):
            with self.subTest(sequence=sequence):
                case = copy.deepcopy(self.document)
                case["cases"][0]["records"][0][1] = sequence
                case["cases"][0]["contiguous_contract"] = "accept"
                with self.assertRaisesRegex(ValueError, "invalid sequence"):
                    module.validate(case)

    def test_invalid_sequence_must_reject_under_both_contracts(self):
        for contract in ("contiguous_contract", "explicit_gap_contract"):
            for sequence in (0, -1, 2**64, True, "1"):
                with self.subTest(contract=contract, sequence=sequence):
                    case = copy.deepcopy(self.document)
                    case["cases"][0]["records"][0][1] = sequence
                    case["cases"][0][contract] = "accept"
                    with self.assertRaisesRegex(ValueError, "invalid sequence"):
                        module.validate(case)

    def test_canonically_equivalent_case_ids_rejected(self):
        case = copy.deepcopy(self.document)
        case["cases"][0]["id"] = "caf\u00e9"
        case["cases"][1]["id"] = "cafe\u0301"
        with self.assertRaisesRegex(ValueError, "duplicate/invalid case id"):
            module.validate(case)

    def test_duplicate_case_id_rejected(self):
        case = copy.deepcopy(self.document)
        case["cases"][1]["id"] = case["cases"][0]["id"]
        with self.assertRaises(ValueError):
            module.validate(case)

    def test_authority_must_match_frozen_review_document(self):
        for authority in (None, "", "docs/plans/other.md", "runtime_authorized", 1):
            with self.subTest(authority=authority):
                case = copy.deepcopy(self.document)
                case["authority"] = authority
                with self.assertRaisesRegex(ValueError, "unknown corpus authority"):
                    module.validate(case)

    def test_authorizing_status_rejected(self):
        case = copy.deepcopy(self.document)
        case["status"] = "runtime_authorized"
        with self.assertRaises(ValueError):
            module.validate(case)

if __name__ == "__main__":
    unittest.main()
