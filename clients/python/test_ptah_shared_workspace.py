"""One Ptah Control workspace shared by independent tool clients."""
import threading
import unittest
from http.server import ThreadingHTTPServer
from ptah_control_client import PtahBoundaryError, PtahControlClient
from ptah_shared_workspace import Caller, SharedWorkspace
from test_ptah_control_client import Handler

class SharedWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.ptah=SharedWorkspace(PtahControlClient(
            f"http://127.0.0.1:{cls.server.server_port}"
        ))
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
    def setUp(self):
        Handler.mismatch=False
        Handler.submissions.clear()
        Handler.origins.clear()

    def test_supervisor_formula_and_simulation_share_one_control_workspace(self):
        clients={
            name:self.ptah.for_tool(name,"ptah")
            for name in ("cookpit","supervisor","formula","ttg-simulation","hunter")
        }
        receipts={
            name:handle.checkpoint({"phase":"candidate-proof", "caller":name})
            for name,handle in clients.items()
        }
        self.assertEqual(len({x.workspace_id for x in receipts.values()}),1)
        self.assertEqual({x.workspace_id for x in receipts.values()},{"w1"})
        self.assertEqual(len({x.request_id for x in receipts.values()}),5)
        self.assertEqual(len(Handler.submissions),5)
        for name,handle in clients.items():
            observed=handle.readback(receipts[name])
            self.assertEqual(observed.execution_status,
                             "not_executed_by_this_control_service")
            self.assertEqual(observed.caller_context,
                             Caller(name,"ptah").context())
        with self.assertRaisesRegex(PtahBoundaryError,"different caller"):
            clients["formula"].readback(receipts["cookpit"])

    def test_provenance_is_not_an_execution_permission(self):
        tool=self.ptah.for_tool("supervisor","ptah")
        with self.assertRaisesRegex(PtahBoundaryError,"not yet qualified"):
            tool.run_tool("unapproved shell")
        self.assertEqual(Handler.submissions,[])

    def test_rejects_invalid_project_and_tool_names(self):
        for value in ("", "../other", "foo/bar", "A", "x"*49, "a b"):
            with self.assertRaises(PtahBoundaryError):
                self.ptah.for_tool(value,"ptah")
        with self.assertRaises(PtahBoundaryError):
            self.ptah.for_tool("supervisor","../../other")

    def test_wrong_workspace_or_provenance_denied(self):
        from dataclasses import replace
        handle=self.ptah.for_tool("cookpit","ptah")
        receipt=handle.checkpoint()
        with self.assertRaisesRegex(PtahBoundaryError,"provenance"):
            handle.readback(replace(receipt,workspace_id="other"))
        entry=next(s for s in Handler.submissions if s["request_id"]==receipt.request_id)
        entry["payload"]["caller_context"]["tool"]="other"
        with self.assertRaisesRegex(PtahBoundaryError,"provenance"):
            handle.readback(receipt)

    def test_missing_or_mismatched_authority_fails_closed(self):
        Handler.mismatch=True
        with self.assertRaises(PtahBoundaryError):
            self.ptah.for_tool("cookpit","ptah").checkpoint()
        self.assertEqual(Handler.submissions,[])

if __name__=="__main__":
    unittest.main(verbosity=2)
