import importlib.util
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location("carrier",Path(__file__).with_name("e07_oracle_stream.py"))
C=importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)

class OracleCarrierContract(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="ptah-e07-oracle-contract-")
        self.addCleanup(self.temp.cleanup)
        self.a=str(Path(self.temp.name)/"kratos")
        self.b=str(Path(self.temp.name)/"athena")
        C.prepare(self.a)
        C.prepare(self.b)
    def test_ordered_ciphertext_frames_survive_duplicate_transport_delivery(self):
        msgs=[bytes(range(256))*8,b"\x16\x03\x03\x00"+b"\xf0"*1800,b"TLS ciphertext no authority"]
        for message in msgs:
            C.publish(self.a,"outbound",message)
        rows=C.pull(self.a,"outbound",0,32)
        C.deliver(self.b,json.dumps(rows))
        C.deliver(self.b,json.dumps(rows))
        received=C.pull(self.b,"inbound",0,32)
        self.assertEqual(received,rows)
    def test_gap_and_conflicting_replay_rejected(self):
        C.deliver(self.b,'[{"seq":1,"b64":"YWJj"}]')
        with self.assertRaisesRegex(ValueError,"out-of-order"):
            C.deliver(self.b,'[{"seq":3,"b64":"YWJj"}]')
        with self.assertRaisesRegex(ValueError,"non-idempotent"):
            C.deliver(self.b,'[{"seq":1,"b64":"YWJk"}]')
    def test_endpoint_is_loopback_only_and_never_decides_tasks(self):
        listener=socket.socket()
        listener.bind(("127.0.0.1",0));port=listener.getsockname()[1]
        listener.close()
        server=threading.Thread(target=C.serve,args=(self.b,"accept",port),daemon=True)
        server.start()
        deadline=time.monotonic()+3
        while not (Path(self.b)/"ready.json").exists() and time.monotonic()<deadline:
            time.sleep(.01)
        cli=socket.create_connection(("127.0.0.1",port),timeout=2)
        cli.sendall(b"e07-opaque-frame")
        deadline=time.monotonic()+3
        while not C.pull(self.b,"outbound",0,10) and time.monotonic()<deadline:
            time.sleep(.01)
        packet=C.pull(self.b,"outbound",0,10)
        self.assertEqual(__import__("base64").b64decode(packet[0]["b64"]),b"e07-opaque-frame")
        C.deliver(self.b,'[{"seq":1,"b64":"cmVzcG9uc2U="}]')
        self.assertEqual(cli.recv(50),b"response")
        cli.close()
        server.join(timeout=3)
        self.assertFalse(server.is_alive())

if __name__=="__main__": unittest.main()
