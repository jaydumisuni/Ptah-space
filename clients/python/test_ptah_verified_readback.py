"""Verified Ptah A05 readback projection never invents execution authority."""
import unittest
from ptah_control_client import PtahBoundaryError, PtahControlClient

DIGEST=lambda value:"sha256:"+value*64
class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.client=PtahControlClient("http://127.0.0.1:7800")
        self.value={"request_id":"request-1","control_state":"authorized_for_dispatch",
                    "execution_status":"not_executed_by_this_control_service",
                    "workspace_id":"workspace-1","caller_context":None,
                    "verified_effect":None}
        self.client._json=lambda path:self.value

    def test_absent_effect_remains_nonexecution(self):
        receipt=self.client.read_submission("request-1")
        self.assertIsNone(receipt.verified_effect)
        self.assertEqual(receipt.execution_status,"not_executed_by_this_control_service")

    def test_independent_effect_is_not_completion_acceptance(self):
        self.value.update(execution_status="independent_a05_effect_verified",
            verified_effect={"witness_id":"independent-observer",
                             "evidence_digest":DIGEST("a"),"exit_code":0,
                             "stdout_digest":DIGEST("b"),
                             "control_state":"independent_witness_evidence_only",
                             "completion_accepted":False})
        receipt=self.client.read_submission("request-1")
        self.assertEqual(receipt.verified_effect.witness_id,"independent-observer")
        self.assertFalse(receipt.verified_effect.completion_accepted)

    def test_unverified_or_false_completion_status_fails(self):
        for evidence in (None,{},{"witness_id":"fake","evidence_digest":DIGEST("a"),
                                "exit_code":0,"stdout_digest":DIGEST("b"),
                                "control_state":"independent_witness_evidence_only",
                                "completion_accepted":True}):
            self.value.update(execution_status="independent_a05_effect_verified",
                              verified_effect=evidence)
            with self.subTest(evidence=evidence),self.assertRaises(PtahBoundaryError):
                self.client.read_submission("request-1")

    def test_wrong_identity_or_digest_is_denied(self):
        self.value["request_id"]="another-request"
        with self.assertRaises(PtahBoundaryError):
            self.client.read_submission("request-1")
        self.value["request_id"]="request-1"
        self.value.update(execution_status="independent_a05_effect_verified",
            verified_effect={"witness_id":"independent-observer",
                             "evidence_digest":"sha256:bad","exit_code":0,
                             "stdout_digest":DIGEST("b"),
                             "control_state":"independent_witness_evidence_only",
                             "completion_accepted":False})
        with self.assertRaises(PtahBoundaryError):
            self.client.read_submission("request-1")

if __name__=="__main__":unittest.main()
