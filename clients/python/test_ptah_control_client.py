"""Negative and integration tests for Ptah's current A14/D01 HTTP contract."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ptah_control_client import PtahControlClient, PtahBoundaryError

AUTH={'workspace_id':'w1','workspace_revision':1,'session_id':'s1',
      'session_revision':2,'node_id':'n1','node_generation':3,
      'provider_generations':{'p1':4},'fence':'opaque-fence'}

class Handler(BaseHTTPRequestHandler):
    mismatch = False
    submissions = []
    origins = []
    def log_message(self, *args):
        pass
    def response(self, status, value):
        raw=json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_GET(self):
        if self.path == '/api/state':
            self.response(200,{'authority':AUTH,'workspaces':['w1']})
        elif self.path == '/api/shell-v2':
            self.response(200,{'authority':dict(AUTH, node_generation=5) if self.mismatch else AUTH})
        elif self.path.startswith('/api/submissions/'):
            identity=self.path.removeprefix('/api/submissions/')
            result=next((x for x in self.submissions if x['request_id']==identity),None)
            if result is None:
                return self.response(404,{'error':'not_found'})
            self.response(200,{'request_id':identity,
                               'control_state':'authorized_for_dispatch',
                               'execution_status':'not_executed_by_this_control_service',
                               'workspace_id':result['expected']['workspace_id'],
                               'target_id':result['target_id']})
        else:
            self.response(404,{'error':'not_found'})
    def do_POST(self):
        if self.path != '/api/control':
            return self.response(404,{'error':'not_found'})
        value=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.origins.append(self.headers.get('Origin'))
        if self.headers.get('Origin') != f'http://127.0.0.1:{self.server.server_port}':
            return self.response(403,{'error':'forbidden_origin'})
        self.submissions.append(value)
        if value['expected'] != AUTH:
            return self.response(409,{'error':'stale_authority'})
        self.response(202,{'request_id':value['request_id']})

class PtahClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True)
        cls.thread.start()
        cls.client=PtahControlClient(f'http://127.0.0.1:{cls.http.server_port}')
    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();cls.thread.join(timeout=2)
    def setUp(self):
        Handler.mismatch=False;Handler.submissions.clear();Handler.origins.clear()
    def test_observe_exact_matching_stamps(self):
        self.assertEqual(self.client.observe().authority,AUTH)
    def test_refuses_mismatched_projection(self):
        Handler.mismatch=True
        with self.assertRaisesRegex(PtahBoundaryError,'authority stamp mismatch'):
            self.client.observe()
    def test_refuses_remote_or_unqualified_endpoint(self):
        for endpoint in ('https://example.com','http://10.2.3.4:7800',
                         'http://user:pass@127.0.0.1:7800',
                         'http://127.0.0.1:7800/anything'):
            with self.subTest(endpoint=endpoint), self.assertRaises(PtahBoundaryError):
                PtahControlClient(endpoint)
    def test_protected_action_requires_caller_approval(self):
        with self.assertRaisesRegex(PtahBoundaryError,'approval'):
            self.client.submit_control(kind='accept_worker_result',target_id='worker1',payload={})
        self.assertEqual(Handler.submissions,[])
    def test_unknown_action_not_emitted(self):
        with self.assertRaisesRegex(PtahBoundaryError,'not in Ptah'):
            self.client.submit_control(kind='execute_shell',target_id='n1',payload={'cmd':'date'})
        self.assertEqual(Handler.submissions,[])
    def test_protected_post_has_exact_loopback_origin(self):
        receipt=self.client.submit_control(kind='checkpoint_request',
                                           target_id='w1',payload={})
        self.assertTrue(receipt.request_id)
        self.assertEqual(Handler.origins,[f'http://127.0.0.1:{self.http.server_port}'])

    def test_submission_round_trip_retains_nonexecution_status(self):
        receipt=self.client.submit_control(kind='checkpoint_request',target_id='w1',payload={})
        status=self.client.read_submission(receipt.request_id)
        self.assertEqual(status.request_id,receipt.request_id)
        self.assertEqual(status.control_state,'authorized_for_dispatch')
        self.assertEqual(status.execution_status,'not_executed_by_this_control_service')

    def test_submission_readback_refuses_invalid_or_missing_identity(self):
        with self.assertRaises(PtahBoundaryError):
            self.client.read_submission('../escape')
        with self.assertRaises(PtahBoundaryError):
            self.client.read_submission('missing-id')

    def test_exact_snapshot_bound_submission_not_completion(self):
        receipt=self.client.submit_control(kind='terminal_reconnect',target_id='t1',payload={},
                                           provider_id='p1',expected_provider_generation=4)
        self.assertEqual(receipt.state,'authorized_for_dispatch_not_executed')
        self.assertEqual(Handler.submissions[0]['expected'],AUTH)
        self.assertEqual(Handler.submissions[0]['request_id'],receipt.request_id)
        self.assertEqual(Handler.submissions[0]['provider_id'],'p1')

if __name__=='__main__': unittest.main(verbosity=2)
