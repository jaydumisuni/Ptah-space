#!/usr/bin/env python3
import json,sys
from pathlib import Path
EXPECTED=[f"E05-{i:02d}" for i in range(1,36)]
PRED="77bbd876aaefd78fed2c0583b2b124eee428eb5f"
def check(path):
 root=Path(__file__).resolve().parents[1]; d=json.loads(Path(path).read_text())
 assert d.get("schema")=="ptah.e05.conformance.v1", "schema"
 assert d.get("accepted_predecessor")==PRED, "predecessor"
 assert d.get("merge_claimed") is False, "merge claim"
 cases=d.get("cases",[]); ids=[x.get("id") for x in cases]
 assert ids==EXPECTED, "case order/completeness"
 for x in cases:
  assert x.get("obligation") and x.get("evidence"), f"empty {x.get('id')}"
  for rel in x["evidence"]: assert (root/rel).is_file(), f"missing evidence {rel}"
 return True
if __name__=="__main__":
 try: check(sys.argv[1] if len(sys.argv)>1 else Path(__file__).resolve().parents[1]/"conformance/e05/e05-conformance-cases.v0.1.0.json")
 except (AssertionError,KeyError,ValueError,OSError) as e: print(f"E05_CONFORMANCE_FAIL: {e}"); raise SystemExit(1)
 print("E05_CONFORMANCE_PASS: 35/35")
