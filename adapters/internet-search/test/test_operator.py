# SPDX-FileCopyrightText: 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS
# SPDX-License-Identifier: Apache-2.0
"""Operator command delegates only to the pinned, read-only bridge."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[3]/"tools/ptah_internet_search.py"
SPEC=importlib.util.spec_from_file_location("ptah_operator_search",SCRIPT)
op=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(op)

class OperatorTests(unittest.TestCase):
    @staticmethod
    def response():
        return type("Reply",(),{"returncode":0,
            "stdout":json.dumps({"protocol":"ptah.ttg-internet-search.readonly.v1",
                                 "completed":True,"outcome":{"results":[]}}).encode(),
            "stderr":b""})()
    def test_structured_query_not_shell(self):
        with patch.object(op.subprocess,"run",return_value=self.response()) as cmd:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(op.main(["--wheel","/outside/pinned.whl","--provider-generation","9",
                               "search","Python unittest documentation"]),0)
        self.assertEqual(cmd.call_args.args[0][1:3],["-I","-B"])
        req=json.loads(cmd.call_args.kwargs["input"])
        self.assertEqual(req["query"],"Python unittest documentation")
        self.assertEqual(req["expected_provider_generation"],9)
        self.assertFalse(cmd.call_args.kwargs.get("shell",False))
        self.assertNotIn("--brave-api",cmd.call_args.args[0])
    def test_manual_cli_does_not_launch_without_wheel(self):
        with patch.dict(op.os.environ,{"PTAH_TTG_SEARCH_WHEEL":""}):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    op.main(["search","query"])
        self.assertEqual(caught.exception.code,2)
    def test_offline_requires_bridge_to_validate_index(self):
        with patch.object(op.subprocess,"run",return_value=self.response()) as cmd:
            with contextlib.redirect_stdout(io.StringIO()):
                op.main(["--wheel","/external/reviewed.whl","search","SQLite","--offline"])
        req=json.loads(cmd.call_args.kwargs["input"])
        self.assertTrue(req["offline"])
        self.assertNotIn("index_db",req)
    def test_no_success_fabrication_on_invalid_bridge_response(self):
        bad=type("BadReply",(),{"returncode":0,"stdout":b"not-json","stderr":b""})()
        with patch.object(op.subprocess,"run",return_value=bad):
            with contextlib.redirect_stdout(io.StringIO()) as sink:
                rc=op.main(["--wheel","/external/reviewed.whl","doctor"])
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(sink.getvalue())["error"],"invalid_provider_reply")
if __name__=="__main__":
    unittest.main()
