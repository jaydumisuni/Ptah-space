#!/usr/bin/env python3
"""No self-attestation can promote E07 from host presence."""
import unittest
from datetime import datetime, timezone, timedelta
from physical_acceptance_preflight import report, GATES

NOW = datetime(2026, 10, 14, 12, 35, tzinfo=timezone.utc)

def linux():
    return {
        "record_type":"ptah.phase0c.host_capability_report",
        "created_at":"2026-10-14T12:32:00+00:00",
        "proof_eligible":False,"required_capabilities_passed":True,
        "pinned_host_match":{"all_match":False},
        "pinned_image":{"release":"24.04.4 LTS",
                        "kernel":{"expected_uname_family":"6.8.0-136-generic"}},
        "host":{"os_release":{"PRETTY_NAME":"Ubuntu 26.04.1 LTS"},
                "uname":{"release":"7.0.0-34-generic"}},
    }

def windows():
    return {"schema":"ptah.e07.physical.host_presence.v1","platform":"windows",
            "observed_utc":"2026-10-14T12:31:00+00:00",
            "machine_reachable":True, "services":[], "processes":[],
            "authority_evidence_present":False}

class PhysicalAdmissionTest(unittest.TestCase):
    def test_host_reachability_cannot_grant_e07(self):
        result=report(linux(),windows(),NOW)
        self.assertEqual(result["status"],"NO_GO")
        self.assertFalse(result["may_run_production_dispatch"])
        self.assertFalse(result["may_close_e07"])
        self.assertEqual(set(result["gates"]),set(GATES))
        self.assertTrue(all(x["status"]=="NOT_PROVEN" for x in result["gates"].values()))
    def test_fabricated_authority_flags_cannot_self_promote(self):
        a=linux();w=windows()
        a["proof_eligible"]=True
        a["pinned_host_match"]["all_match"]=True
        w.update(authority_evidence_present=True, production_lease_authorized=True,
                 services=["ptah-control"],processes=["ptah-node"])
        result=report(a,w,NOW)
        self.assertEqual(result["status"],"NO_GO")
        self.assertFalse(result["may_run_production_dispatch"])
        self.assertTrue(all(x["status"]=="NOT_PROVEN" for x in result["gates"].values()))
    def test_restored_oracle_execution_is_not_node_enrollment(self):
        w=windows()
        w["oracle_terminal_execution_passed"]=True
        w["production_lease_authorized"]=True
        w["authenticated_ptah_control_node_session_observed"]=True
        result=report(linux(),w,NOW)
        self.assertTrue(result["athena"]["oracle_execution_observed"])
        self.assertFalse(result["athena"]["production_node_enrollment_verified"])
        self.assertEqual(result["status"],"NO_GO")
        self.assertFalse(result["may_close_e07"])
        self.assertTrue(all(g["status"]=="NOT_PROVEN" for g in result["gates"].values()))

    def test_stale_observations_rejected(self):
        w=windows();w["observed_utc"]="2026-10-13T08:00:00+00:00"
        with self.assertRaisesRegex(ValueError,"not current"):
            report(linux(),w,NOW)
    def test_noncanonical_linux_and_future_windows_rejected(self):
        a=linux();a["record_type"]="fake"
        with self.assertRaisesRegex(ValueError,"canonical"):
            report(a,windows(),NOW)
        w=windows();w["observed_utc"]=(NOW+timedelta(hours=4)).isoformat()
        with self.assertRaisesRegex(ValueError,"not current"):
            report(linux(),w,NOW)
if __name__=="__main__":
    unittest.main()
