from __future__ import annotations

import copy
import unittest

from check_mtk_sim_candidate import QualificationError, qualify


def fixture():
    generation="sha256:"+"1"*64
    result={
        "schema":"ttg.simulation-result.v2",
        "authority_granted":False,
        "authority_boundary":{
            "simulation_may_promote":False,
            "simulation_may_mutate_other_projects":False,
            "self_certification":False,
            "donor_authority_transferred":False,
        },
        "candidate_inference":{"winner":{
            "candidate_id":"sleeper-channel-separated-mtk",
            "eligible":True,
            "authority_violations":0,
            "hostile_passed":19,
            "hostile_total":19,
        }},
        "evidence":{"candidate_digest":generation},
        "uncertainty":[
            "Physical BP/modem IMEI channel remains unqualified",
            "Physical serial extraction remains unqualified",
            "Physical MT6768 storage/DA partition backend remains unqualified",
            "Physical security-state operations remain unqualified",
        ],
    }
    projection={
        "schema":"ttg.simulation.ptah-device-projection.v1",
        "aliases_are_evidence_only":True,
        "incarnations":[
            {"epoch":1,"mode":"android","usb_vid":"1782","usb_pid":"4003"},
            {"epoch":2,"mode":"preloader","usb_vid":"0E8D","usb_pid":"2000"},
            {"epoch":3,"mode":"meta","usb_vid":"0E8D","usb_pid":"2007"},
        ],
        "authority_boundary":{
            "simulation_grants_physical_authority":False,
            "production_mutation_owner":"Sleeper after independent physical qualification",
        },
    }
    second={
        "schema":"ttg.second-use-status.v1",
        "candidate_generation":generation,
        "successful_uses":2,
        "distinct_contexts":2,
        "distinct_evidence_generations":2,
        "second_use_passed":True,
        "authority_granted":False,
    }
    reuse={
        "schema":"ttg.simulation.external-physical-evidence.v1",
        "authority_granted":False,
        "physical_scope":{
            "platform":"MT6789",
            "init_return":0,
            "connect_return":0,
            "targetver_return":0,
            "targetver_callback":True,
            "chipid_return":0,
            "disconnect_return":0,
            "deinit_return":0,
        },
        "guard":{
            "read_only":True,
            "nvram_write":False,
            "reset":False,
            "frp_mutation":False,
            "format":False,
            "unlock":False,
            "shell":False,
            "reboot":False,
        },
    }
    return result,projection,second,reuse


class TestMtkSimQualification(unittest.TestCase):
    def test_clean_candidate_passes_without_authority(self):
        receipt=qualify(*fixture())
        self.assertEqual(receipt["status"],"pass")
        self.assertFalse(receipt["production_authority_granted"])
        self.assertFalse(receipt["physical_mutation_authority_granted"])

    def test_simulation_authority_claim_fails(self):
        values=list(fixture())
        values[0]=copy.deepcopy(values[0])
        values[0]["authority_granted"]=True
        with self.assertRaises(QualificationError):
            qualify(*values)

    def test_alias_identity_promotion_fails(self):
        values=list(fixture())
        values[1]=copy.deepcopy(values[1])
        values[1]["aliases_are_evidence_only"]=False
        with self.assertRaises(QualificationError):
            qualify(*values)

    def test_second_use_must_be_distinct(self):
        values=list(fixture())
        values[2]=copy.deepcopy(values[2])
        values[2]["distinct_contexts"]=1
        values[2]["second_use_passed"]=False
        with self.assertRaises(QualificationError):
            qualify(*values)

    def test_mutating_physical_reuse_evidence_fails(self):
        values=list(fixture())
        values[3]=copy.deepcopy(values[3])
        values[3]["guard"]["unlock"]=True
        with self.assertRaises(QualificationError):
            qualify(*values)


if __name__=="__main__":
    unittest.main()
