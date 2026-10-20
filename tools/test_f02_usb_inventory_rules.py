import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("f02",ROOT/"tools/f02_usb_inventory_rules.py")
assert SPEC and SPEC.loader
F=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(F)

class UsbDeviceProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="f02-conformance-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.usb=self.root/"bus";self.usb.mkdir()
        self.physical=self.root/"devices";self.physical.mkdir()
        self.profile={"schema":F.SCHEMA,"scope":"design_only","rules":[
            {"vendor_id":"0e8d","product_id":"2000","mode":"0660",
             "group":"ptah-devices","enabled":False}]}

    def add_device(self,name,vid,pid):
        entry=self.physical/name
        entry.mkdir()
        (entry/"idVendor").write_text(vid)
        (entry/"idProduct").write_text(pid)
        (self.usb/name).symlink_to(entry,target_is_directory=True)

    def test_passive_deduplicated_inventory_without_sensitive_data(self):
        self.add_device("1-2","0E8D","2000")
        self.add_device("1-3","0e8d","2000")
        (self.usb/"1-2:1.0").symlink_to(self.physical/"1-2")
        result=F.observe(self.usb,self.root)
        self.assertEqual(result["count"],2)
        self.assertEqual(result["devices"],[{"vendor_id":"0e8d",
                                             "product_id":"2000","count":2}])
        self.assertFalse(result["serials_collected"])
        self.assertFalse(result["physical_paths_collected"])
        self.assertFalse(result["host_admitted"])
        self.assertFalse(result["rules_installed"])

    def test_sysfs_symlink_escape_denied(self):
        outside=Path(self.tmp.name).parent
        (self.usb/"1-1").symlink_to(outside,target_is_directory=True)
        with self.assertRaises(F.InvalidF02):
            F.observe(self.usb,self.root)

    def test_usb_attribute_symlink_escape_denied(self):
        self.add_device("1-2","0e8d","2000")
        with tempfile.TemporaryDirectory(prefix="f02-untrusted-") as other:
            outside=Path(other)/"vid"
            outside.write_text("0e8d")
            source=self.physical/"1-2"/"idVendor"
            source.unlink()
            source.symlink_to(outside)
            with self.assertRaises(F.InvalidF02):
                F.observe(self.usb,self.root)

    def test_invalid_device_identifier_fails_closed(self):
        self.add_device("1-2","0e8d","NOTSAFE")
        with self.assertRaises(F.InvalidF02):
            F.observe(self.usb,self.root)

    def test_draft_never_emits_active_udev_rule(self):
        rendered=F.render_rules(self.profile)
        self.assertTrue(all(line.startswith("#") for line in rendered.splitlines()))
        self.assertIn('MODE="0660"',rendered)
        self.assertNotIn('MODE="0666"',rendered)
        self.assertNotIn("RUN+=",rendered)

    def test_world_access_or_unapproved_group_rejected(self):
        for field,value in [("mode","0666"),("group","root"),("enabled",True)]:
            p=json.loads(json.dumps(self.profile))
            p["rules"][0][field]=value
            with self.subTest(field=field),self.assertRaises(F.InvalidF02):
                F.render_rules(p)

    def test_no_wildcard_or_injection(self):
        for value in ["*","0e8d\x22, RUN+=\x22bad", "0E8D","0000"]:
            p=json.loads(json.dumps(self.profile))
            p["rules"][0]["vendor_id"]=value
            with self.subTest(value=value),self.assertRaises(F.InvalidF02):
                F.render_rules(p)

    def test_duplicate_rule_is_rejected(self):
        self.profile["rules"].append(self.profile["rules"][0].copy())
        with self.assertRaises(F.InvalidF02):
            F.render_rules(self.profile)

    def test_extra_unreviewed_key_rejected(self):
        self.profile["rules"][0]["allow_commands"]=True
        with self.assertRaises(F.InvalidF02):
            F.render_rules(self.profile)

    def test_bounded_json_and_duplicate_keys(self):
        path=self.root/"profile.json"
        path.write_text('{"schema":1,"schema":2}')
        with self.assertRaises(F.InvalidF02):
            F.load_json(path)
        path.write_bytes(b"x"*33000)
        with self.assertRaises(F.InvalidF02):
            F.load_json(path)

    def test_empty_rules_valid_but_no_permissions(self):
        self.profile["rules"]=[]
        r=F.render_rules(self.profile)
        self.assertNotIn('ATTR{idVendor}',r)
