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

    def test_exchange_rejects_non_array_envelopes_without_mutating_inbound(self):
        from unittest.mock import patch
        for sample in ('{}', 'null', 'false', '0', '""', '{"packets":[]}'):
            with self.subTest(sample=sample):
                with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                        "--state", self.b, "--packets", sample]):
                    with self.assertRaisesRegex(ValueError, "invalid packet batch"):
                        C.main()
                self.assertEqual(C.pull(self.b, "inbound", 0, 10), [])

    def test_exchange_empty_array_remains_valid_snapshot_poll(self):
        from unittest.mock import patch
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                "--state", self.b, "--packets", "[]"]):
            with redirect_stdout(output):
                C.main()
        self.assertEqual(json.loads(output.getvalue())["packets"], [])
        self.assertEqual(C.pull(self.b, "inbound", 0, 10), [])

    def test_unprepared_state_cannot_create_database_on_read(self):
        empty = Path(self.temp.name) / "unprepared"
        empty.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "prepared carrier database required"):
            C.pull(str(empty), "outbound", 0, 1)
        self.assertFalse((empty / "carrier.sqlite3").exists())

    def test_database_symlink_and_hardlink_aliases_are_rejected(self):
        import os
        database = Path(self.b) / "carrier.sqlite3"
        external = Path(self.temp.name) / "external.sqlite3"
        database.rename(external)
        try:
            database.symlink_to(external)
            with self.assertRaisesRegex(ValueError, "unaliased carrier database"):
                C.pull(self.b, "inbound", 0, 1)
            database.unlink()
            os.link(external, database)
            with self.assertRaisesRegex(ValueError, "unaliased carrier database"):
                C.deliver(self.b, '[{"seq":1,"b64":"YWJj"}]')
            database.unlink()
        finally:
            if database.is_symlink():
                database.unlink()
            if not database.exists() and external.exists():
                external.rename(database)
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    def test_symlinked_state_ancestor_cannot_read_or_create_carrier_database(self):
        real = Path(self.temp.name) / "real-parent"
        real.mkdir(mode=0o700)
        alias = Path(self.temp.name) / "alias-parent"
        alias.symlink_to(real, target_is_directory=True)
        C.prepare(str(real / "prepared"))
        with self.assertRaisesRegex(ValueError, "symlinked carrier state ancestor"):
            C.pull(str(alias / "prepared"), "inbound", 0, 1)
        with self.assertRaisesRegex(ValueError, "symlinked carrier state ancestor"):
            C.prepare(str(alias / "new-state"))
        self.assertFalse((real / "new-state").exists())

    def test_parent_traversal_state_path_rejected_before_sqlite_open(self):
        state = str(Path(self.b) / ".." / "athena")
        with self.assertRaisesRegex(ValueError, "carrier state parent traversal"):
            C.pull(state, "inbound", 0, 1)

    def test_sqlite_sidecar_symlink_aliases_are_rejected_before_open(self):
        from unittest.mock import patch
        external = Path(self.temp.name) / "external-journal"
        external.write_bytes(b"outside carrier state")
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                alias = Path(self.b) / ("carrier.sqlite3" + suffix)
                self.assertFalse(alias.exists() or alias.is_symlink())
                alias.symlink_to(external)
                try:
                    with patch.object(C.sqlite3, "connect", side_effect=AssertionError("SQLite opened untrusted sidecar")):
                        with self.assertRaisesRegex(ValueError, "unaliased carrier sidecar"):
                            C.pull(self.b, "inbound", 0, 1)
                    self.assertEqual(external.read_bytes(), b"outside carrier state")
                finally:
                    alias.unlink()

    def test_sqlite_sidecar_hardlink_aliases_are_rejected_before_open(self):
        import os
        from unittest.mock import patch
        external = Path(self.temp.name) / "external-hardlinked-journal"
        external.write_bytes(b"outside carrier state")
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                alias = Path(self.b) / ("carrier.sqlite3" + suffix)
                self.assertFalse(alias.exists() or alias.is_symlink())
                os.link(external, alias)
                try:
                    with patch.object(C.sqlite3, "connect", side_effect=AssertionError("SQLite opened untrusted sidecar")):
                        with self.assertRaisesRegex(ValueError, "unaliased carrier sidecar"):
                            C.pull(self.b, "inbound", 0, 1)
                    self.assertEqual(external.read_bytes(), b"outside carrier state")
                finally:
                    alias.unlink()

    def test_shared_writable_carrier_state_is_rejected_before_database_access(self):
        import os
        state = Path(self.b)
        original_mode = state.stat().st_mode & 0o777
        try:
            os.chmod(state, 0o770)
            with self.assertRaisesRegex(ValueError, "private carrier state directory required"):
                C.pull(self.b, "inbound", 0, 1)
        finally:
            os.chmod(state, original_mode)

    def test_shared_writable_carrier_database_is_rejected_before_sqlite_open(self):
        import os
        database = Path(self.b) / "carrier.sqlite3"
        original_mode = database.stat().st_mode & 0o777
        try:
            os.chmod(database, 0o660)
            with self.assertRaisesRegex(ValueError, "private carrier database required"):
                C.pull(self.b, "inbound", 0, 1)
        finally:
            os.chmod(database, original_mode)

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

    def test_serve_requires_prepared_private_state_before_claiming_socket(self):
        from unittest.mock import patch
        import os
        unprepared = Path(self.temp.name) / "unprepared-serve"
        unprepared.mkdir(mode=0o700)
        with patch.object(C.socket, "socket", side_effect=AssertionError("socket opened without database")):
            with self.assertRaisesRegex(ValueError, "prepared carrier database required"):
                C.serve(str(unprepared), "accept", 41321)
        self.assertFalse((unprepared / "serve.claim").exists())

        original = os.stat(self.b).st_mode & 0o777
        try:
            os.chmod(self.b, 0o777)
            with patch.object(C.socket, "socket", side_effect=AssertionError("socket opened on unsafe state")):
                with self.assertRaisesRegex(ValueError, "private carrier state directory required"):
                    C.serve(self.b, "accept", 41321)
            self.assertFalse((Path(self.b) / "serve.claim").exists())
        finally:
            os.chmod(self.b, original)

    def test_serve_rejects_dangling_lifecycle_marker_aliases(self):
        from unittest.mock import patch
        outside = Path(self.temp.name) / "outside-lifecycle"
        for name in ("ready.json", "ended.json"):
            with self.subTest(marker=name):
                marker = Path(self.b) / name
                marker.symlink_to(outside)
                try:
                    with patch.object(C.socket, "socket", side_effect=AssertionError("socket opened with marker alias")):
                        with self.assertRaisesRegex(ValueError, "newly prepared carrier state"):
                            C.serve(self.b, "accept", 41321)
                    self.assertFalse(outside.exists())
                    self.assertFalse((Path(self.b) / "serve.claim").exists())
                finally:
                    marker.unlink()

    def test_lifecycle_marker_write_cannot_replace_existing_alias(self):
        outside = Path(self.temp.name) / "marker-target"
        for name in ("ready.json", "ended.json"):
            with self.subTest(marker=name):
                marker = Path(self.b) / name
                marker.symlink_to(outside)
                try:
                    with self.assertRaises(FileExistsError):
                        C.write_exclusive_marker(marker, {"finished": True})
                    self.assertFalse(outside.exists())
                    self.assertTrue(marker.is_symlink())
                finally:
                    marker.unlink()

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
