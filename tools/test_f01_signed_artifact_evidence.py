"""Detached F01 Ed25519 evidence conformance with disposable test-only keys."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
SPEC=importlib.util.spec_from_file_location("f01_signature",ROOT/"tools/f01_signed_artifact_evidence.py")
assert SPEC and SPEC.loader
S=importlib.util.module_from_spec(SPEC)
sys.modules["f01_signature"]=S
SPEC.loader.exec_module(S)


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="ptah-f01-keytest-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.control=self.root/"ptah-control"
        self.node=self.root/"ptah-node"
        self.control.write_bytes(b"PTAH CONTROL TEST "*9)
        self.node.write_bytes(b"PTAH NODE TEST "*9)
        self.bundle=self.root/"service.tar"
        S.archive.create_bundle({"ptah-control":self.control,
                                 "ptah-node":self.node},"a"*40,self.bundle)
        self.private=self.root/"test-only-key.pem"
        self.public=self.root/"test-only-pub.pem"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(self.private)],check=True,capture_output=True,timeout=10)
        self.private.chmod(0o600)
        subprocess.run(["openssl","pkey","-in",str(self.private),
                        "-pubout","-out",str(self.public)],
                       check=True,capture_output=True,timeout=10)
        self.fingerprint=S.public_key_fingerprint(self.public)
        self.sidecar=self.root/"service.sig.json"

    def sign(self):
        return S.sign(self.bundle,self.private,self.public,self.fingerprint,self.sidecar)

    def test_real_ed25519_sign_and_verify(self):
        result=self.sign()
        self.assertEqual(result["status"],"SIGNED_ARTIFACT_INTEGRITY_VERIFIED_NOT_ADMITTED")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result,S.verify(self.bundle,self.sidecar,self.public,self.fingerprint))
        self.assertEqual(len(json.loads(self.sidecar.read_text())["signature_ed25519_hex"]),128)

    def test_signing_rejects_insecure_private_key_permissions(self):
        self.private.chmod(0o644)
        with self.assertRaisesRegex(S.F01SignatureError,"PRIVATE_KEY_PERMISSIONS_UNSAFE"):
            self.sign()
        self.assertFalse(self.sidecar.exists())

    def test_exclusive_create_race_preserves_other_writers_output(self):
        original=Path.open
        target=self.sidecar
        def intercepted(path, mode="r", *a, **kw):
            if path==target and mode=="xb":
                target.write_bytes(b"another writer's preserved bytes")
                raise FileExistsError("parallel writer created destination")
            return original(path,mode,*a,**kw)
        with mock.patch.object(Path,"open",new=intercepted):
            with self.assertRaises(FileExistsError):
                self.sign()
        self.assertEqual(target.read_bytes(),b"another writer's preserved bytes")

    def test_signing_refuses_existing_sidecar_without_removal(self):
        self.sidecar.write_text("preserve owner data")
        with self.assertRaisesRegex(S.F01SignatureError,"OUTPUT_ALREADY_EXISTS"):
            self.sign()
        self.assertEqual(self.sidecar.read_text(),"preserve owner data")

    def test_different_expected_fingerprint_fails_closed(self):
        with self.assertRaisesRegex(S.F01SignatureError,"EXTERNAL_TRUST_ANCHOR_MISMATCH"):
            S.sign(self.bundle,self.private,self.public,"sha256:"+"0"*64,self.sidecar)
        self.assertFalse(self.sidecar.exists())

    def test_missing_external_trust_binding_refused(self):
        with self.assertRaisesRegex(S.F01SignatureError,"EXTERNAL_TRUST_FINGERPRINT_REQUIRED"):
            S.sign(self.bundle,self.private,self.public,"",self.sidecar)

    def test_tampered_signed_archive_refused_even_if_original_tar_looks_valid(self):
        self.sign()
        with self.control.open("ab") as f:f.write(b"MUTATED INPUT DOES NOT MATTER")
        # Tamper the archived bytes instead of an external source.
        data=self.bundle.read_bytes().replace(b"PTAH CONTROL TEST ",b"PTAH CONTROL FAIL ",1)
        self.assertEqual(len(data),self.bundle.stat().st_size)
        self.bundle.write_bytes(data)
        with self.assertRaises(S.archive.BundleError):
            S.verify(self.bundle,self.sidecar,self.public,self.fingerprint)

    def test_modified_signature_fails(self):
        self.sign()
        obj=json.loads(self.sidecar.read_bytes())
        old=obj["signature_ed25519_hex"]
        obj["signature_ed25519_hex"]=("0" if old[0]!="0" else "1")+old[1:]
        self.sidecar.write_bytes(S.message_bytes(obj))
        with self.assertRaisesRegex(S.F01SignatureError,"OPENSSL_OPERATION_FAILED"):
            S.verify(self.bundle,self.sidecar,self.public,self.fingerprint)

    def test_forged_release_claim_refused(self):
        self.sign()
        obj=json.loads(self.sidecar.read_bytes())
        obj["statement"]["release_authorized"]=True
        self.sidecar.write_bytes(S.message_bytes(obj))
        with self.assertRaisesRegex(S.F01SignatureError,"FORGED_RELEASE_OR_AUTHORITY"):
            S.verify(self.bundle,self.sidecar,self.public,self.fingerprint)

    def test_disallowed_extra_approval_field_rejected(self):
        self.sign()
        obj=json.loads(self.sidecar.read_bytes())
        obj["statement"]["owner_approved"]=True
        self.sidecar.write_bytes(S.message_bytes(obj))
        with self.assertRaisesRegex(S.F01SignatureError,"INVALID_SIGNED_STATEMENT_FIELDS"):
            S.verify(self.bundle,self.sidecar,self.public,self.fingerprint)

    def test_wrong_public_key_cannot_verify_signature(self):
        self.sign()
        other_key=self.root/"other.pem";other_pub=self.root/"other.pub.pem"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519","-out",str(other_key)],
                       check=True,capture_output=True,timeout=10)
        subprocess.run(["openssl","pkey","-in",str(other_key),"-pubout","-out",str(other_pub)],
                       check=True,capture_output=True,timeout=10)
        with self.assertRaisesRegex(S.F01SignatureError,"EXTERNAL_TRUST_ANCHOR_MISMATCH"):
            S.verify(self.bundle,self.sidecar,other_pub,self.fingerprint)

    def test_wrong_signing_private_key_fails_immediate_key_pair_check(self):
        other_key=self.root/"other.pem"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519","-out",str(other_key)],
                       check=True,capture_output=True,timeout=10)
        other_key.chmod(0o600)
        with self.assertRaisesRegex(S.F01SignatureError,"OPENSSL_OPERATION_FAILED"):
            S.sign(self.bundle,other_key,self.public,self.fingerprint,self.sidecar)
        self.assertFalse(self.sidecar.exists())

    def test_duplicate_json_keys_rejected(self):
        self.sign()
        raw=self.sidecar.read_text()
        self.sidecar.write_text(raw.replace('"statement":','"statement":null,"statement":',1))
        with self.assertRaisesRegex(S.F01SignatureError,"DUPLICATE_JSON_KEY"):
            S.verify(self.bundle,self.sidecar,self.public,self.fingerprint)

    def test_noncanonical_json_rejected(self):
        self.sign()
        obj=json.loads(self.sidecar.read_text())
        self.sidecar.write_text(json.dumps(obj,indent=4))
        with self.assertRaisesRegex(S.F01SignatureError,"NONCANONICAL_SIDECAR"):
            S.verify(self.bundle,self.sidecar,self.public,self.fingerprint)

    def test_sidecar_symlink_rejected(self):
        self.sign()
        alias=self.root/"alias.json"
        alias.symlink_to(self.sidecar)
        with self.assertRaisesRegex(S.F01SignatureError,"NOT_REGULAR_FILE"):
            S.verify(self.bundle,alias,self.public,self.fingerprint)

    def test_private_key_is_never_in_signed_statement_or_sidecar(self):
        self.sign()
        data=self.sidecar.read_bytes()
        self.assertNotIn(b"BEGIN PRIVATE KEY",data)
        self.assertNotIn(self.private.read_bytes(),data)
        self.assertNotIn(str(self.private).encode(),data)

    def test_cli_requires_independent_trust_fingerprint_and_blocks_release(self):
        self.sign()
        r=subprocess.run([sys.executable,str(ROOT/"tools/f01_signed_artifact_evidence.py"),
            "--verify","--bundle",str(self.bundle),"--sidecar",str(self.sidecar),
            "--public-key",str(self.public),"--expected-fingerprint",self.fingerprint],
            capture_output=True,text=True,timeout=20)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertFalse(json.loads(r.stdout)["release_authorized"])
        r2=subprocess.run([sys.executable,str(ROOT/"tools/f01_signed_artifact_evidence.py"),
            "--verify","--bundle",str(self.bundle),"--sidecar",str(self.sidecar),
            "--public-key",str(self.public),"--expected-fingerprint",self.fingerprint,
            "--private-key",str(self.private)],capture_output=True,text=True,timeout=20)
        self.assertEqual(r2.returncode,2)
