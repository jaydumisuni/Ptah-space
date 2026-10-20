#!/usr/bin/env python3
"""F02: passive USB evidence and inert, restrictive udev rule drafts.

No reads of serials, device nodes or credentials. No udev installation,
production admission, OS policy changes or Ptah-native execution.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

HEX4 = re.compile(r"[0-9a-f]{4}\Z")
BUS_DEVICE = re.compile(r"[0-9]+-[0-9]+(?:\.[0-9]+)*\Z")
MAX_DEVICES, MAX_RULES = 512, 32
SCHEMA = "ptah.f02.usb-rules/1"

class InvalidF02(ValueError):
    pass

def ensure(ok: bool, msg: str):
    if not ok:
        raise InvalidF02(msg)

def unique_pairs(pairs):
    out={}
    for key,value in pairs:
        ensure(key not in out,"duplicate_json_key")
        out[key]=value
    return out

def ident(path, trusted):
    try:
        resolved=path.resolve(strict=True)
    except OSError:
        raise InvalidF02("broken_usb_attribute_link") from None
    ensure(resolved.is_relative_to(trusted) and resolved.is_file(),
           "unsafe_usb_attribute_link")
    try:
        val=path.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError):
        raise InvalidF02("unreadable_usb_identity") from None
    ensure(bool(HEX4.fullmatch(val)),"invalid_usb_identity")
    return val

def observe(sys_usb: Path, trusted_sys_root: Path) -> dict:
    ensure(sys_usb.is_dir(),"sys_bus_unavailable")
    trusted=trusted_sys_root.resolve(strict=True)
    counts=Counter()
    examined=0
    for node in sorted(sys_usb.iterdir(),key=lambda x:x.name):
        if not BUS_DEVICE.fullmatch(node.name):
            continue
        examined+=1
        ensure(examined<=MAX_DEVICES,"too_many_devices")
        try:
            physical=node.resolve(strict=True)
        except OSError:
            raise InvalidF02("broken_device_link") from None
        ensure(physical.is_dir() and physical.is_relative_to(trusted),
               "unsafe_usb_sysfs_path")
        counts[(ident(node/"idVendor",trusted),ident(node/"idProduct",trusted))]+=1
    return {"schema":"ptah.f02.usb-observation/1",
            "status":"unattested_read_only","count":examined,
            "devices":[{"vendor_id":v,"product_id":p,"count":num}
                       for (v,p),num in sorted(counts.items())],
            "serials_collected":False,"physical_paths_collected":False,
            "rules_installed":False,"host_admitted":False}

def render_rules(profile: dict) -> str:
    ensure(type(profile) is dict and set(profile)=={"schema","scope","rules"},
           "invalid_profile_fields")
    ensure(profile["schema"]==SCHEMA and profile["scope"]=="design_only",
           "cannot_activate_rules")
    items=profile["rules"]
    ensure(type(items) is list and len(items)<=MAX_RULES,"invalid_rule_count")
    seen=set()
    rows=["# PTAH F02 DESIGN ONLY: inactive rules; DO NOT install or enable",
          "# Prime OS will own group creation, device policy and signed admission."]
    for x in items:
        ensure(type(x) is dict and set(x)=={
            "vendor_id","product_id","mode","group","enabled"},
            "unreviewed_rule_option")
        v,p=x["vendor_id"],x["product_id"]
        ensure(type(v) is str and type(p) is str
               and HEX4.fullmatch(v) is not None
               and HEX4.fullmatch(p) is not None
               and v!="0000" and p!="0000" and (v,p) not in seen,
               "unsafe_or_duplicate_selector")
        seen.add((v,p))
        ensure(x["mode"]=="0660" and x["group"]=="ptah-devices"
               and x["enabled"] is False,
               "unauthorized_device_access")
        rows.append('# INACTIVE: SUBSYSTEM=="usb", ATTR{idVendor}=="'+v+
                    '", ATTR{idProduct}=="'+p+
                    '", MODE="0660", GROUP="ptah-devices"')
    return "\n".join(rows)+"\n"

def load_json(path):
    ensure(path.is_file() and not path.is_symlink()
           and path.stat().st_size<=32768,"unsafe_profile_path")
    try:
        return json.loads(path.read_text("utf-8"),object_pairs_hook=unique_pairs)
    except (OSError,UnicodeError,json.JSONDecodeError):
        raise InvalidF02("invalid_json") from None

def main():
    p=argparse.ArgumentParser(description=__doc__)
    x=p.add_mutually_exclusive_group(required=True)
    x.add_argument("--inventory",action="store_true")
    x.add_argument("--rules",type=Path)
    p.add_argument("--sys-usb",type=Path,default=Path("/sys/bus/usb/devices"))
    p.add_argument("--trusted-sys",type=Path,default=Path("/sys"))
    args=p.parse_args()
    try:
        if args.inventory:
            print(json.dumps(observe(args.sys_usb,args.trusted_sys),indent=2,sort_keys=True))
        else:
            print(render_rules(load_json(args.rules)),end="")
    except (OSError,InvalidF02) as e:
        print("F02_REJECTED:"+str(e),file=sys.stderr)
        return 2
    return 0

if __name__=="__main__":
    raise SystemExit(main())
