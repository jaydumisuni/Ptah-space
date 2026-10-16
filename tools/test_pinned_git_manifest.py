"""Pinned original upstream Git source manifest recovery — no signer bypass."""
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import verify_backend_artifacts as verifier

class OriginalGitManifestCustodyTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).resolve().parents[1]
        self.manifest=self.root/"conformance/immutable-source-manifests/git-2.55.0-sha256sums.asc"
        self.lock=json.loads((self.root/"dependencies/backend-artifact-lock.json").read_text())
        self.git=next(x for x in self.lock["artifacts"] if x["component"]=="git-source")
    def test_01_original_signed_bytes_match_immutable_lock(self):
        self.assertEqual(hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
                         self.git["signed_checksum_manifest_sha256"])
        self.assertEqual(verifier.extract_named_sha256(
            self.manifest,self.git["filename"],"git-source"),self.git["digest"]["value"])
    def test_02_pgp_signature_signed_by_pinned_kernel_org_key(self):
        item=verifier.verify_pinned_kernel_checksum_signature(self.manifest)
        self.assertEqual(item["status"],"good_signature_and_pinned_fingerprint")
        self.assertEqual(item["fingerprint"],verifier.KERNEL_ORG_AUTOSIGNER_FPR)
    def test_03_modified_manifest_fails_before_archive_download(self):
        with tempfile.TemporaryDirectory(dir=self.root) as folder:
            forged=Path(folder)/"forged.asc"
            forged.write_bytes(self.manifest.read_bytes()+b"\n")
            with patch.object(verifier,"download",side_effect=AssertionError("must not fetch")):
                with self.assertRaisesRegex(verifier.ArtifactError,"digest mismatch"):
                    verifier.verify_signed_manifest_artifact(
                        component="git-source",filename=self.git["filename"],
                        url=self.git["download_url"],manifest_url=self.git["signed_checksum_manifest"],
                        manifest_filename="git-sha256sums.asc",download_root=Path(folder),
                        pinned_snapshot=forged,
                        immutable_snapshot_sha256=self.git["signed_checksum_manifest_sha256"])
    def test_04_unapproved_external_snapshot_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            forged=Path(folder)/"snapshot.asc"
            shutil.copyfile(self.manifest,forged)
            with self.assertRaisesRegex(verifier.ArtifactError,"must be under repository"):
                verifier.verify_signed_manifest_artifact(
                    component="git-source",filename=self.git["filename"],
                    url=self.git["download_url"],manifest_url=self.git["signed_checksum_manifest"],
                    manifest_filename="git-sha256sums.asc",download_root=Path(folder),
                    pinned_snapshot=forged,
                    immutable_snapshot_sha256=self.git["signed_checksum_manifest_sha256"])
    def test_05_key_identity_still_pinned(self):
        with patch.object(verifier,"KERNEL_ORG_AUTOSIGNER_FPR","0"*40):
            with self.assertRaisesRegex(verifier.ArtifactError,"fingerprint mismatch"):
                verifier.verify_pinned_kernel_checksum_signature(self.manifest)
    def test_06_no_network_when_validating_original_manifest(self):
        with patch.object(verifier,"download",side_effect=AssertionError("not needed")):
            self.assertEqual(verifier.extract_named_sha256(
                self.manifest,self.git["filename"],"git-source"),
                self.git["digest"]["value"])

if __name__=="__main__":unittest.main()
