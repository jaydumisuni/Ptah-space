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
    def test_oversized_or_non_string_ciphertext_is_rejected_before_decode(self):
        # Oracle packet batches must reject oversized frames and malformed types.
        import base64
        too_large = base64.b64encode(b"x" * (C.MAX_CHUNK + 1)).decode("ascii")
        with self.assertRaisesRegex(ValueError, "invalid packet size"):
            C.deliver(self.b, json.dumps([{"seq": 1, "b64": too_large}]))
        with self.assertRaisesRegex(ValueError, "invalid packet schema"):
            C.deliver(self.b, '[{"seq":1,"b64":123}]')
        self.assertEqual(C.pull(self.b, "inbound", 0, 10), [])

    def test_duplicate_json_packet_keys_are_rejected_without_committing_bytes(self):
        # Different JSON decoders must not disagree on packet identity or content.
        samples = (
            '[{"seq":1,"seq":2,"b64":"YWJj"}]',
            '[{"seq":1,"b64":"YWJj","b64":"YWJk"}]',
        )
        for sample in samples:
            with self.subTest(sample=sample):
                with self.assertRaisesRegex(ValueError, "duplicate packet key"):
                    C.deliver(self.b, sample)
                self.assertEqual(C.pull(self.b, "inbound", 0, 10), [])

    def test_exchange_rejects_duplicate_packet_keys_before_snapshot(self):
        from unittest.mock import patch
        with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                "--state", self.b, "--packets",
                                '[{"seq":1,"b64":"YWJj","b64":"YWJk"}]']):
            with self.assertRaisesRegex(ValueError, "duplicate packet key"):
                C.main()
        self.assertEqual(C.pull(self.b, "inbound", 0, 10), [])

    def test_exchange_rejects_non_array_or_oversized_batch_before_snapshot(self):
        from unittest.mock import patch
        invalid = ("{}", "null", "false", "0",
                   json.dumps([None] * (C.MAX_BATCH + 1)))
        for packets in invalid:
            with self.subTest(packets=packets):
                with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                        "--state", self.b, "--packets", packets]):
                    with self.assertRaisesRegex(ValueError, "invalid packet batch"):
                        C.main()
                self.assertEqual(C.pull(self.b, "inbound", 0, 10), [])

    def test_gap_and_conflicting_replay_rejected(self):
        C.deliver(self.b,'[{"seq":1,"b64":"YWJj"}]')
        with self.assertRaisesRegex(ValueError,"out-of-order"):
            C.deliver(self.b,'[{"seq":3,"b64":"YWJj"}]')
        with self.assertRaisesRegex(ValueError,"non-idempotent"):
            C.deliver(self.b,'[{"seq":1,"b64":"YWJk"}]')
    def test_reader_sqlite_or_quota_failure_is_propagated_not_marked_finished(self):
        listener=socket.socket()
        listener.bind(("127.0.0.1",0));port=listener.getsockname()[1]
        listener.close()
        caught=[]
        original=C.publish
        def rejected(*args,**kwargs):
            raise RuntimeError("bounded carrier byte quota exhausted")
        def run():
            try:
                C.serve(self.b,"accept",port)
            except Exception as error:
                caught.append(str(error))
        from unittest.mock import patch
        with patch.object(C,"publish",side_effect=rejected):
            thread=threading.Thread(target=run)
            thread.start()
            deadline=time.monotonic()+3
            while not (Path(self.b)/"ready.json").exists() and time.monotonic()<deadline:
                time.sleep(.01)
            with socket.create_connection(("127.0.0.1",port),timeout=2) as sock:
                sock.sendall(b"force-reader-error")
            thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertTrue(caught)
        self.assertIn("E07_CARRIER_PUMP_FAILED:reader",caught[0])
        status=json.loads((Path(self.b)/"ended.json").read_text())
        self.assertFalse(status["finished"])
        self.assertTrue(status["failed"])

    def test_writer_read_failure_is_propagated(self):
        listener=socket.socket()
        listener.bind(("127.0.0.1",0));port=listener.getsockname()[1]
        listener.close()
        caught=[]
        original=C.pull
        def broken(state,table,after,limit):
            if table=="inbound":
                raise OSError("synthetic local storage I/O failure")
            return original(state,table,after,limit)
        def run():
            try:C.serve(self.b,"accept",port)
            except Exception as error:caught.append(str(error))
        from unittest.mock import patch
        with patch.object(C,"pull",side_effect=broken):
            thread=threading.Thread(target=run)
            thread.start()
            deadline=time.monotonic()+3
            while not (Path(self.b)/"ready.json").exists() and time.monotonic()<deadline:
                time.sleep(.01)
            with socket.create_connection(("127.0.0.1",port),timeout=2):
                thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertTrue(caught)
        self.assertIn("E07_CARRIER_PUMP_FAILED:writer",caught[0])
        self.assertFalse(json.loads((Path(self.b)/"ended.json").read_text())["finished"])

    def test_spent_carrier_state_cannot_reopen_a_socket_and_replay_tls_bytes(self):
        # The same SQLite queue must never be attached to a second TLS session.
        C.deliver(self.b, '[{"seq":1,"b64":"dGxzLWZyYW1l"}]')
        (Path(self.b) / "ended.json").write_text('{"finished":true}')
        from unittest.mock import patch
        with patch.object(C.socket, "socket", side_effect=AssertionError("reopened spent carrier")):
            with self.assertRaisesRegex(ValueError, "newly prepared carrier state"):
                C.serve(self.b, "accept", 41321)

    def test_claimed_carrier_cannot_start_a_second_socket(self):
        # The exclusive claim survives a crash before ready.json is published.
        (Path(self.b) / "serve.claim").write_text("")
        from unittest.mock import patch
        with patch.object(C.socket, "socket", side_effect=AssertionError("reopened claimed carrier")):
            with self.assertRaisesRegex(ValueError, "newly prepared carrier state"):
                C.serve(self.b, "accept", 41321)

    def test_database_handles_are_closed_after_carrier_operations(self):
        import sqlite3
        from unittest.mock import patch
        opened = []
        original = C.dbconnect

        def tracked(state):
            connection = original(state)
            opened.append(connection)
            return connection

        with patch.object(C, "dbconnect", side_effect=tracked):
            C.publish(self.a, "outbound", b"opaque")
            C.pull(self.a, "outbound", 0, 1)
            C.deliver(self.b, '[{"seq":1,"b64":"b3BhcXVl"}]')
            C.pull(self.b, "inbound", 0, 1)
        self.assertEqual(len(opened), 4)
        for connection in opened:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

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
