"""Static Phase0C Git source custody: fail-closed signed evidence."""
import json
import sys
import unittest
from pathlib import Path
from copy import deepcopy
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_backend_artifact_lock import LockError,check_static

class BackendGitManifestCustodyTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[1]
        lock=json.loads((root/"dependencies/backend-artifact-lock.json").read_text())
        self.entry=next(x for x in lock["artifacts"] if x["component"]=="git-source")
        self.lock={"runtime_implementation_authorized":False,"artifacts":[self.entry]}
        manifest=self.entry["signed_checksum_manifest_sha256"]
        self.report={"runtime_implementation_authorized":False,
            "verified_artifact_count":1,"results":[{
             "component":"git-source","filename":self.entry["filename"],"digest":self.entry["digest"],
             "signed_checksum_manifest_sha256":manifest,
             "signed_checksum_manifest_transfer":{
                "retrieval_mode":"original_signed_manifest_pinned_in_repository",
                "sha256":manifest,"same_run_download":False,
                "source_path":"conformance/immutable-source-manifests/git-2.55.0-sha256sums.asc"},
             "signed_checksum_manifest_pgp":{
                "status":"good_signature_and_pinned_fingerprint",
                "fingerprint":"B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1",
                "public_key_sha256":"099fb3eca2b31006bc0f37db9dd9226a1bc51a8958d54c278e3f67006a8a114b"}
             }]}
    def test_01_exact_valid_evidence(self):
        out=check_static(self.lock,self.report)
        self.assertEqual(out["components"],["git-source"])
    def test_02_modified_locked_digest_rejected(self):
        test=deepcopy(self.report)
        test["results"][0]["signed_checksum_manifest_sha256"]="0"*64
        with self.assertRaisesRegex(LockError,"digest mismatch"):check_static(self.lock,test)
    def test_03_missing_signature_fails(self):
        test=deepcopy(self.report)
        del test["results"][0]["signed_checksum_manifest_pgp"]
        with self.assertRaisesRegex(LockError,"cryptographic evidence absent"):
            check_static(self.lock,test)
    def test_04_wrong_public_key_fails(self):
        test=deepcopy(self.report)
        test["results"][0]["signed_checksum_manifest_pgp"]["fingerprint"]="0"*40
        with self.assertRaisesRegex(LockError,"cryptographic evidence absent"):
            check_static(self.lock,test)
    def test_05_misrepresented_same_run_source_fails(self):
        test=deepcopy(self.report)
        test["results"][0]["signed_checksum_manifest_transfer"]["same_run_download"]=True
        with self.assertRaisesRegex(LockError,"custody evidence incomplete"):
            check_static(self.lock,test)
    def test_06_forged_snapshot_location_fails(self):
        test=deepcopy(self.report)
        test["results"][0]["signed_checksum_manifest_transfer"]["source_path"]="../../tmp/injected.asc"
        with self.assertRaisesRegex(LockError,"custody evidence incomplete"):
            check_static(self.lock,test)
if __name__=="__main__":unittest.main()
