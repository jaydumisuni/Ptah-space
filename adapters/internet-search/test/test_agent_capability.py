# SPDX-FileCopyrightText: 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS
# SPDX-License-Identifier: Apache-2.0
"""Agent-neutral capability description must stay aligned to existing A05 bridge."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("ptah_existing_search_bridge",ROOT/"bridge.py")
bridge=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)
DESCRIPTOR=json.loads((ROOT/"agent-capability.json").read_text(encoding="utf-8"))

class AgentNeutralContractTests(unittest.TestCase):
    def test_advertises_only_existing_pinned_provider(self):
        self.assertEqual(DESCRIPTOR["provider"]["protocol"],bridge.PROTOCOL)
        self.assertEqual(DESCRIPTOR["provider"]["version"],bridge.EXPECTED_VERSION)
        self.assertEqual(DESCRIPTOR["provider"]["immutable_wheel_sha256"],bridge.EXPECTED_WHEEL_SHA256)
        self.assertEqual(DESCRIPTOR["provider"]["adapter"],"adapters/internet-search/bridge.py")
        self.assertEqual(DESCRIPTOR["provider"]["execution"],"existing_ptah_a05_process_provider")

    def test_all_examples_match_existing_operation_validator(self):
        self.assertEqual({x["name"] for x in DESCRIPTOR["operations"]},{"search","read","doctor"})
        self.assertEqual(DESCRIPTOR["calling_contract"]["max_request_bytes"],bridge.MAX_REQUEST_BYTES)
        for item in DESCRIPTOR["operations"]:
            body=item["example"]
            self.assertEqual(body["operation"],item["name"])
            self.assertEqual(body["expected_provider_generation"],7)
            operation,argv=bridge.checked_request(body,7,None)
            self.assertEqual(operation,item["name"])
            self.assertTrue(argv)
        self.assertEqual(DESCRIPTOR["operations"][0]["limits"]["results"],bridge.MAX_RESULTS)

    def test_two_agent_selected_invocations_use_same_bridge_no_agent_identity(self):
        for request_id in ("chatgpt-search-17","hunter-search-17","other-agent-search-17"):
            body={"operation":"search","query":"Godfrey Mountain video",
                  "limit":5,"request_id":request_id,
                  "expected_provider_generation":19}
            self.assertEqual(bridge.checked_request(body,19,None)[0],"search")
            self.assertNotIn("agent",body)
            self.assertNotIn("owner_ref",body)
        with self.assertRaisesRegex(bridge.BridgeError,"unexpected_search_fields"):
            bridge.checked_request({**body,"owner_ref":"self-asserted-owner"},19,None)

    def test_provider_generation_is_always_fenced(self):
        body={"operation":"doctor","request_id":"check","expected_provider_generation":6}
        with self.assertRaisesRegex(bridge.BridgeError,"stale_provider_generation"):
            bridge.checked_request(body,7,None)

    def test_no_automatic_dispatch_elevation_or_paid_path(self):
        c=DESCRIPTOR["constraints"]
        self.assertTrue(DESCRIPTOR["agent_neutral"])
        self.assertFalse(DESCRIPTOR["calling_contract"]["automatic_enrollment_or_dispatch"])
        self.assertTrue(DESCRIPTOR["calling_contract"]["on_demand"])
        self.assertTrue(c["read_only"])
        self.assertEqual(c["payment_budget_zmw"],0)
        self.assertFalse(c["paid_provider_enabled"])
        self.assertFalse(c["paid_overflow_enabled"])
        self.assertTrue(c["no_canonical_source_promotion"])
        self.assertEqual(DESCRIPTOR["search_truth"],"DISCOVERED_NOT_PAGE_VERIFIED")

if __name__=="__main__":
    unittest.main()
