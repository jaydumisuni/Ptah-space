import importlib.util,io,json,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("f01_bundler",ROOT/"tools/build_f01_service_bundle.py")
assert SPEC and SPEC.loader
B=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(B)
class BundleProof(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.addCleanup(self.tmp.cleanup)
  self.p=Path(self.tmp.name)
  self.c=self.p/"ptah-control";self.n=self.p/"ptah-node"
  self.c.write_bytes(b"CONTROL"*17);self.n.write_bytes(b"NODE"*19)
  self.sha="a"*40
 def inputs(self):
  return {"ptah-control":self.c,"ptah-node":self.n}
 def build(self,name="candidate.tar"):
  return B.create_bundle(self.inputs(),self.sha,self.p/name)
 def test_deterministic_and_explicit_no_go(self):
  a=self.build("a.tar");b=self.build("b.tar")
  self.assertEqual((self.p/"a.tar").read_bytes(),(self.p/"b.tar").read_bytes())
  self.assertFalse(a["signed"]);self.assertFalse(a["release_authorized"])
  self.assertFalse(a["native_execution_admitted"]);self.assertEqual(a,b)
 def test_no_overwrite(self):
  p=self.p/"candidate.tar";p.write_bytes(b"owner bytes")
  with self.assertRaises(B.BundleError):self.build()
  self.assertEqual(p.read_bytes(),b"owner bytes")
 def test_invalid_source_or_missing_service(self):
  with self.assertRaises(B.BundleError):
   B.create_bundle(self.inputs(),"main",self.p/"bad.tar")
  with self.assertRaises(B.BundleError):
   B.create_bundle({"ptah-node":self.n},self.sha,self.p/"bad.tar")
 def test_symlink_rejected(self):
  alias=self.p/"alias";alias.symlink_to(self.c)
  with self.assertRaises(B.BundleError):
   B.create_bundle({"ptah-control":alias,"ptah-node":self.n},self.sha,self.p/"bad.tar")
 def test_payload_tampering_rejected(self):
  self.build();p=self.p/"candidate.tar";raw=p.read_bytes()
  p.write_bytes(raw.replace(b"CONTROL",b"BADFILE",1))
  with self.assertRaises(B.BundleError):B.verify_bundle(p)
 def test_forged_release_flag_rejected(self):
  self.build();src=self.p/"candidate.tar";dst=self.p/"forged.tar"
  with tarfile.open(src) as a,tarfile.open(dst,"w") as b:
   for info in a.getmembers():
    data=a.extractfile(info).read()
    if info.name=="manifest.json":
     obj=json.loads(data);obj["release_authorized"]=True
     data=B.manifest_bytes(obj);info.size=len(data)
    b.addfile(info,io.BytesIO(data))
  with self.assertRaises(B.BundleError):B.verify_bundle(dst)
 def test_unexpected_member_rejected(self):
  self.build();src=self.p/"candidate.tar";dst=self.p/"extra.tar"
  with tarfile.open(src) as a,tarfile.open(dst,"w") as b:
   for info in a.getmembers():b.addfile(info,io.BytesIO(a.extractfile(info).read()))
   info=tarfile.TarInfo("evil");info.size=1;b.addfile(info,io.BytesIO(b"x"))
  with self.assertRaises(B.BundleError):B.verify_bundle(dst)
 def test_archive_never_executes(self):
  with patch("subprocess.run",side_effect=AssertionError("execute denied")):
   self.build()
