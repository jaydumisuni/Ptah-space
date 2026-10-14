# SPDX-FileCopyrightText: 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS
# SPDX-License-Identifier: Apache-2.0
"""Search provider must fail closed, preserve provenance and never charge."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PARENT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("ptah_search_bridge",PARENT/"bridge.py")
bridge=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)
WHEEL_PATH=Path(os.environ.get("PTAH_TTG_SEARCH_WHEEL","/nonexistent/ptah-search-physical.whl"))

def msg(**kwargs):
    return {"operation":"search","query":"Python unittest documentation",
            "limit":5,"request_id":"search-001",
            "expected_provider_generation":7,**kwargs}

def invoke(raw, wheel_path="/not/available", generation=7, index_db=None):
    sink=io.StringIO()
    with contextlib.redirect_stdout(sink):
        rc=bridge.run(["--wheel",str(wheel_path),"--provider-generation",str(generation)] +
                  (["--index-db",str(index_db)] if index_db else []),
                  stream=io.StringIO(raw if isinstance(raw,str) else json.dumps(raw)))
    return rc,json.loads(sink.getvalue())

class BridgeContracts(unittest.TestCase):
    def test_fixed_protocol_and_sha256_pin(self):
        self.assertEqual(bridge.PROTOCOL,"ptah.ttg-internet-search.readonly.v1")
        self.assertEqual(bridge.EXPECTED_VERSION,"0.7.0a2")
        self.assertEqual(len(bridge.EXPECTED_WHEEL_SHA256),64)
    def test_exact_pinned_wheel(self):
        if not WHEEL_PATH.exists():
            self.skipTest("Physical exact wheel absent; run controlled fixture tests")
        self.assertEqual(bridge.require_wheel(str(WHEEL_PATH)),WHEEL_PATH)
    def test_reject_tampered_wheel(self):
        with tempfile.TemporaryDirectory() as root:
            wheel=Path(root)/"tampered.whl"
            wheel.write_bytes(b"malicious")
            with self.assertRaisesRegex(bridge.BridgeError,"wheel_digest_mismatch"):
                bridge.require_wheel(str(wheel))
    def test_no_relative_wheel(self):
        with self.assertRaisesRegex(bridge.BridgeError,"wheel_absent_or_untrusted"):
            bridge.require_wheel("relative.whl")
    def test_generation_mismatch_denied_before_execution(self):
        rc,out=invoke(msg(expected_provider_generation=99))
        self.assertEqual(rc,2)
        self.assertEqual(out["error"]["code"],"stale_provider_generation")
        self.assertFalse(out["completed"])
    def test_missing_generation_denied(self):
        body=msg();del body["expected_provider_generation"]
        rc,out=invoke(body)
        self.assertEqual(out["error"]["code"],"stale_provider_generation")
    def test_extra_field_denied_without_secrets(self):
        rc,out=invoke({**msg(),"api_key":"secret-not-allowed"})
        self.assertEqual(out["error"]["code"],"unexpected_request_fields")
        self.assertNotIn("secret-not-allowed",json.dumps(out))
    def test_limit_boolean_is_invalid(self):
        rc,out=invoke({**msg(),"limit":True})
        self.assertEqual(out["error"]["code"],"invalid_result_limit")
    def test_shell_metacharacters_remain_argv_data(self):
        op,args=bridge.checked_request(msg(query='SQLite"; rm -rf /; #'),7,None)
        self.assertEqual(op,"search")
        self.assertIn('SQLite"; rm -rf /; #',args)
        self.assertNotIn("--brave-api",args)
        self.assertNotIn("--preview-fallback",args)
    def test_fresh_flags_do_not_enable_html(self):
        op,args=bridge.checked_request(msg(require_fresh=True),7,None)
        self.assertIn("--require-fresh",args)
        self.assertIn("--no-preview-fallback",args)
    def test_offline_requires_operator_index(self):
        rc,out=invoke(msg(offline=True))
        self.assertEqual(out["error"]["code"],"offline_index_not_configured")
    def test_offline_propagates_only_operator_index(self):
        op,args=bridge.checked_request(msg(offline=True),7,"/tmp/approved.sqlite")
        self.assertEqual(op,"search")
        self.assertEqual(args[-1],"--offline")
        self.assertEqual(args[args.index("--index-db")+1],"/tmp/approved.sqlite")
    def test_page_read_rejects_http(self):
        rc,out=invoke({"operation":"read","url":"http://example.org/",
            "request_id":"read-1","expected_provider_generation":7})
        self.assertEqual(out["error"]["code"],"https_only")
    def test_page_read_rejects_credentials(self):
        rc,out=invoke({"operation":"read","url":"https://username:secret@example.org/",
            "request_id":"read-1","expected_provider_generation":7})
        self.assertEqual(out["error"]["code"],"https_only")
        self.assertNotIn("secret",json.dumps(out))
    def test_no_mutating_operations(self):
        rc,out=invoke({"operation":"curate","request_id":"bad-1",
            "expected_provider_generation":7})
        self.assertEqual(out["error"]["code"],"unsupported_operation")
    def test_invalid_json(self):
        rc,out=invoke("{bad")
        self.assertEqual(out["error"]["code"],"invalid_request_json")
    def test_overlarge_input(self):
        rc,out=invoke("a"*9000)
        self.assertEqual(out["error"]["code"],"request_too_large")
    def test_sanitized_source_and_truth(self):
        reply={"results":[{"url":"https://docs.python.org/3/library/unittest.html",
                          "title":"unittest","snippet":"unit tests",
                          "provider":"youcom_keyless_mcp",
                          "status":"DISCOVERED","malicious_field":"ignored"}],
               "attempts":[{"provider":"youcom_keyless_mcp","status":"OK"}],
               "result_truth":"DISCOVERED_NOT_PAGE_VERIFIED"}
        item=bridge.present("search",reply,0,msg(),7)
        self.assertEqual(item["outcome"]["result_truth"],"DISCOVERED_NOT_PAGE_VERIFIED")
        self.assertFalse(item["outcome"]["verified_page_content"])
        self.assertNotIn("malicious_field",item["outcome"]["results"][0])
        self.assertEqual(item["outcome"]["provider_requests_paid"],0)
        self.assertFalse(item["canonical_ptah_source_authority"])
        self.assertTrue(item["browser_provider_unchanged"])
    def test_reject_http_result_url(self):
        with self.assertRaisesRegex(bridge.BridgeError,"invalid_search_source_url"):
            bridge.present("search",{"results":[{"url":"http://127.0.0.1/"}]},0,msg(),7)
    def test_legacy_backend_quota_is_shared(self):
        with patch.dict(bridge.os.environ,{"HOME":"/home/kratos","XDG_STATE_HOME":"/tmp/shared-truth",
                                                "HTTP_PROXY":"http://attack.invalid"},clear=True):
            env=bridge.child_env()
        self.assertEqual(env["XDG_STATE_HOME"],"/tmp/shared-truth")
        self.assertNotIn("HTTP_PROXY",env)
        self.assertEqual(env["PYTHONNOUSERSITE"],"1")
    def test_child_command_uses_isolated_python_and_no_shell(self):
        wheel=Path("/non-existent/example.whl")
        response=type("Result",(),{"returncode":0,"stdout":json.dumps({"results":[]}).encode(),
                                   "stderr":b""})()
        with patch.object(bridge.subprocess,"run",return_value=response) as command:
            out,rc=bridge.execute(wheel,["search","safe"])
        args=command.call_args.args[0]
        self.assertEqual(args[1:4],["-I","-B","-c"])
        self.assertEqual(args[5],str(wheel))
        self.assertNotIn("--brave-api",args)
        self.assertFalse(command.call_args.kwargs.get("shell",False))
    def test_provider_unavailability_not_fabricated(self):
        item=bridge.present("search",{"results":[],"attempts":[],
             "result_truth":"DISCOVERED_NOT_PAGE_VERIFIED"},2,msg(),7)
        self.assertFalse(item["has_results"])
        self.assertEqual(item["outcome"]["results"],[])
    def test_invalid_response_does_not_claim_completion(self):
        with patch.object(bridge,"require_wheel",return_value=Path("/pinned.whl")):
            with patch.object(bridge,"execute",side_effect=bridge.BridgeError("search_timeout")):
                code,out=invoke(msg())
        self.assertEqual(code,2)
        self.assertFalse(out["completed"])
        self.assertEqual(out["error"]["code"],"search_timeout")

class PhysicalWheelTests(unittest.TestCase):
    def test_live_pinned_wheel_readable_page(self):
        if not WHEEL_PATH.exists():self.skipTest("pinned wheel unavailable")
        request={"operation":"doctor","request_id":"doctor-physical","expected_provider_generation":5}
        rc,reply=invoke(request,wheel_path=WHEEL_PATH,generation=5)
        self.assertEqual(rc,0)
        self.assertEqual(reply["outcome"]["search_version"],"0.7.0a2")
        self.assertEqual(reply["outcome"]["payment_budget_zmw"],0)
        self.assertFalse(reply["outcome"]["paid_overflow_enabled"])
        self.assertEqual(reply["outcome"]["provider_requests_paid"],0)

if __name__=="__main__":
    unittest.main()
