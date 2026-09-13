import hashlib
import tempfile
import unittest
from pathlib import Path

import review_gate


class ReviewGateTests(unittest.TestCase):
    def test_assemble_base_requires_exact_expected_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'base_00').write_bytes(b'abc')
            (root / 'base_01').write_bytes(b'def')
            out = root / 'ROADMAP_BASE.md'
            expected = hashlib.sha256(b'abcdef').hexdigest()
            got = review_gate.assemble_base(root, out, expected)
            self.assertEqual(got, expected)
            self.assertEqual(out.read_bytes(), b'abcdef')

    def test_duplicate_stable_ids_are_rejected_across_base_and_overlay(self):
        base = '## PM-ONE-001 — One\n'
        overlay = '### PM-ONE-001 — Duplicate\n'
        report = review_gate.validate_contracts(base, overlay)
        self.assertIn('PM-ONE-001', report['duplicate_ids'])
        self.assertFalse(report['ok'])

    def test_required_latest_contracts_and_proof_subjects_close(self):
        required = sorted(review_gate.REQUIRED_LATEST_IDS)
        contracts = '\n'.join(f'## {item} — Contract' for item in required)
        report = review_gate.validate_contracts(contracts, '')
        self.assertEqual(report['missing_required_ids'], [])
        self.assertEqual(report['missing_proof_subjects'], {})
        self.assertTrue(report['ok'])

    def test_composite_review_world_hash_changes_if_overlay_changes(self):
        a = review_gate.composite_world_hash('a' * 64, 'b' * 64, '375ca5', '045ff8')
        b = review_gate.composite_world_hash('a' * 64, 'c' * 64, '375ca5', '045ff8')
        self.assertNotEqual(a, b)


if __name__ == '__main__':
    unittest.main()
