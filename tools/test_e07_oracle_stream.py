import importlib.util
import json
import os
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
    @unittest.skipUnless(os.name == "nt", "Windows ACL integration")
    def test_windows_real_acl_custody_allows_fresh_private_carrier(self):
        # Real native owner/DACL admission is exercised, not mocked.
        C.windows_private_acl(Path(self.a))
        C.windows_private_acl(Path(self.a) / "carrier.sqlite3")
        C.publish(self.a, "outbound", b"windows-private-carrier")
        self.assertEqual(len(C.pull(self.a, "outbound", 0, 1)), 1)

    @unittest.skipUnless(os.name == "nt", "Windows ACL integration")
    def test_windows_acl_rejection_precedes_sqlite_access(self):
        from unittest.mock import patch
        with patch.object(C, "windows_private_acl",
                          side_effect=ValueError("private carrier Windows ACL grants other principals")):
            with patch.object(C.sqlite3, "connect",
                              side_effect=AssertionError("SQLite opened untrusted Windows ACL")):
                with self.assertRaisesRegex(ValueError, "Windows ACL grants other principals"):
                    C.pull(self.b, "inbound", 0, 1)

    @unittest.skipUnless(os.name == "nt", "Windows exclusive-create integration")
    def test_windows_exclusive_creation_does_not_replace_existing_marker(self):
        marker = Path(self.b) / "ready.json"
        marker.write_text("existing", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            C.write_exclusive_marker(marker, {"ready": True})
        self.assertEqual(marker.read_text(encoding="utf-8"), "existing")

    def test_relative_carrier_state_rejected_before_filesystem_or_sqlite_use(self):
        from unittest.mock import patch
        for state in ("relative-carrier", "./relative-carrier"):
            with self.subTest(state=state):
                with self.assertRaisesRegex(ValueError, "absolute carrier state path"):
                    C.prepare(state)
                with patch.object(C.sqlite3, "connect", side_effect=AssertionError("opened relative state")):
                    with self.assertRaisesRegex(ValueError, "absolute carrier state path"):
                        C.pull(state, "inbound", 0, 1)

    def test_outbound_publish_requires_bounded_nonempty_bytes(self):
        # The receiving E07 journal rejects zero-length or oversized frames.
        # Never persist an outbound frame that cannot be delivered over Oracle.
        for payload in (b"", b"x" * (C.MAX_CHUNK + 1), "text", None, bytearray(b"x")):
            with self.subTest(kind=type(payload).__name__, size=len(payload) if payload is not None else None):
                with self.assertRaisesRegex(ValueError, "invalid outbound carrier frame"):
                    C.publish(self.a, "outbound", payload)
                self.assertEqual(C.pull(self.a, "outbound", 0, 1), [])
        C.publish(self.a, "outbound", b"x" * C.MAX_CHUNK)
        rows = C.pull(self.a, "outbound", 0, 1)
        self.assertEqual(len(rows), 1)
        import base64
        self.assertEqual(base64.b64decode(rows[0]["b64"]), b"x" * C.MAX_CHUNK)

    def test_outbound_sequence_exhaustion_is_controlled_before_sqlite_bind(self):
        # A valid final signed-64-bit key may be written, but no successor
        # can be bound to SQLite. Failed publication preserves prior bytes.
        maximum = (1 << 63) - 1
        with C.dbtransaction(self.a) as conn:
            conn.execute("INSERT INTO outbound(seq,content) VALUES (?,?)",
                         (maximum - 1, b"penultimate"))
        C.publish(self.a, "outbound", b"last")
        self.assertEqual(C.pull(self.a, "outbound", maximum - 1, 1),
                         [{"seq": maximum, "b64": "bGFzdA=="}])
        with self.assertRaisesRegex(ValueError, "carrier sequence exhausted"):
            C.publish(self.a, "outbound", b"overflow")
        self.assertEqual(C.pull(self.a, "outbound", maximum - 1, 2),
                         [{"seq": maximum, "b64": "bGFzdA=="}])

    def test_pull_rejects_cursor_beyond_durable_journal(self):
        # An impossible local cursor must not silently hide queued TLS bytes.
        for table in ("outbound", "inbound"):
            with self.subTest(table=table):
                with self.assertRaisesRegex(ValueError, "carrier cursor exceeds durable sequence"):
                    C.pull(self.a, table, 1, 1)
                C.publish(self.a, table, b"first")
                self.assertEqual(len(C.pull(self.a, table, 0, 1)), 1)
                self.assertEqual(C.pull(self.a, table, 1, 1), [])
                with self.assertRaisesRegex(ValueError, "carrier cursor exceeds durable sequence"):
                    C.pull(self.a, table, 2, 1)
                self.assertEqual(len(C.pull(self.a, table, 0, 1)), 1)

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

    def test_invalid_packet_payloads_are_rejected_before_database_admission(self):
        # Reject an untrusted packet envelope without opening SQLite or
        # acquiring a carrier admission lock, including the exchange path.
        from unittest.mock import patch
        invalid = (
            '[{"seq":0,"b64":"YWJj"}]',
            '[{"seq":1,"b64":123}]',
            '[{"seq":1,"b64":"not-base64!"}]',
            json.dumps([{"seq":1,"b64":"A" * (C.MAX_ENCODED_CHUNK + 1)}]),
        )
        for sample in invalid:
            with self.subTest(sample=sample[:48]):
                with patch.object(C, "dbtransaction",
                                  side_effect=AssertionError("invalid packet reached SQLite")):
                    with self.assertRaises(ValueError):
                        C.deliver(self.b, sample)
                    with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                            "--state", self.b, "--packets", sample]):
                        with self.assertRaises(ValueError):
                            C.main()
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    def test_packet_sequence_outside_sqlite_integer_range_fails_closed(self):
        """Hostile JSON bignums must not escape as sqlite3 OverflowError."""
        for seq in (-1, 0, -(1 << 100), (1 << 63), (1 << 100)):
            with self.subTest(seq=seq):
                with self.assertRaisesRegex(ValueError, "invalid packet schema"):
                    C.deliver(self.b, json.dumps([{"seq": seq, "b64": "YWJj"}]))
                self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    def test_packet_depth_scan_ignores_quoted_brackets_and_escaped_quotes(self):
        """Only structural JSON delimiters count toward the envelope limit."""
        sample = ["[[{\"[[", {"seq": 1, "b64": "YWJj"}]
        self.assertEqual(C.decode_packet_batch(json.dumps(sample)), sample)
        nested = [{"seq": 1, "b64": "YWJj", "extra": {"x": 1}}]
        with self.assertRaisesRegex(ValueError, "invalid packet batch nesting"):
            C.decode_packet_batch(json.dumps(nested))

    def test_deeply_nested_packet_envelope_fails_closed_before_sqlite(self):
        # The envelope is well below the byte budget but exceeds the JSON
        # decoder's nesting limit; a RecursionError must not escape the CLI.
        from unittest.mock import patch
        nested = "[" * 10000 + "]" * 10000
        self.assertLess(len(nested), C.MAX_BATCH * (C.MAX_ENCODED_CHUNK + 64) + 2)
        with patch.object(C, "dbtransaction",
                          side_effect=AssertionError("nested JSON reached SQLite")):
            with self.assertRaisesRegex(ValueError, "invalid packet batch nesting"):
                C.deliver(self.b, nested)
            with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                    "--state", self.b, "--packets", nested]):
                with self.assertRaisesRegex(ValueError, "invalid packet batch nesting"):
                    C.main()
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

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

    def test_snapshot_rejects_cursor_ahead_of_durable_outbound(self):
        # A caller-side cursor from another session must never be echoed
        # as acknowledged TLS bytes from this local durable journal.
        from contextlib import redirect_stdout
        from io import StringIO
        C.publish(self.a, "outbound", b"first")
        C.publish(self.a, "outbound", b"second")
        for cursor in (-1, 3, 100):
            with self.subTest(cursor=cursor):
                output = StringIO()
                with redirect_stdout(output):
                    with self.assertRaisesRegex(ValueError, "outbound cursor"):
                        C.snapshot(self.a, cursor)
                self.assertEqual(output.getvalue(), "")
        output = StringIO()
        with redirect_stdout(output):
            C.snapshot(self.a, 1)
        result = json.loads(output.getvalue())
        self.assertEqual([p["seq"] for p in result["packets"]], [2])
        self.assertEqual(result["latest"], 2)
        output = StringIO()
        with redirect_stdout(output):
            C.snapshot(self.a, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result, {"packets": [], "count": 0, "latest": 2})

    def test_stream_queries_reject_unbounded_or_unapproved_sql_parameters(self):
        # Internal carrier helpers must not turn a malformed caller parameter
        # into a raw SQL table expression or SQLite's unlimited LIMIT -1.
        C.publish(self.a, "outbound", b"opaque")
        for table in ("sqlite_master", "outbound WHERE 1=1 --", "", 7):
            with self.subTest(table=table):
                with self.assertRaisesRegex(ValueError, "carrier stream table"):
                    C.publish(self.a, table, b"unexpected")
                with self.assertRaisesRegex(ValueError, "carrier stream table"):
                    C.pull(self.a, table, 0, 1)
        for cursor in (-1, True, 1.5, 2**63):
            with self.subTest(cursor=cursor):
                with self.assertRaisesRegex(ValueError, "carrier cursor"):
                    C.pull(self.a, "outbound", cursor, 1)
        for limit in (0, -1, C.MAX_BATCH + 1, True, 1.5):
            with self.subTest(limit=limit):
                with self.assertRaisesRegex(ValueError, "carrier batch limit"):
                    C.pull(self.a, "outbound", 0, limit)
        self.assertEqual(C.pull(self.a, "outbound", 0, 1),
                         [{"seq": 1, "b64": "b3BhcXVl"}])

    def test_exchange_invalid_outbound_cursor_does_not_commit_inbound(self):
        # An Oracle exchange must not acknowledge failure after already
        # committing new inbound ciphertext: a retry cannot infer its effect.
        from unittest.mock import patch
        from contextlib import redirect_stdout
        from io import StringIO
        C.publish(self.b, "outbound", b"published")
        packet = '[{"seq":1,"b64":"YWJj"}]'
        for cursor in ("-1", "2", str(1 << 63)):
            with self.subTest(cursor=cursor):
                output = StringIO()
                with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                        "--state", self.b, "--after", cursor,
                                        "--packets", packet]):
                    with redirect_stdout(output):
                        with self.assertRaisesRegex(ValueError, "outbound cursor"):
                            C.main()
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(C.pull(self.b, "inbound", 0, 10), [])

        # Valid cursor and packet still complete one ordinary exchange.
        output = StringIO()
        with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                "--state", self.b, "--after", "1",
                                "--packets", packet]):
            with redirect_stdout(output):
                C.main()
        self.assertEqual(json.loads(output.getvalue())["latest"], 1)
        self.assertEqual(C.pull(self.b, "inbound", 0, 10),
                         [{"seq": 1, "b64": "YWJj"}])

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

    def test_sqlite_wal_fallback_is_rejected_before_schema_admission(self):
        # A filesystem refusing WAL must not silently switch carrier journal
        # semantics while the admission lock and sidecar contract assume WAL.
        from unittest.mock import patch

        class FallbackConnection:
            def __init__(self):
                self.closed = False
                self.queries = []

            def execute(self, sql):
                self.queries.append(sql)
                if sql == "PRAGMA journal_mode=WAL":
                    class Cursor:
                        def fetchone(self):
                            return ("delete",)
                    return Cursor()
                raise AssertionError("schema initialized after WAL rejection")

            def close(self):
                self.closed = True

        connection = FallbackConnection()
        with patch.object(C.sqlite3, "connect", return_value=connection):
            with self.assertRaisesRegex(ValueError, "carrier WAL journal mode required"):
                C.pull(self.b, "inbound", 0, 1)
        self.assertEqual(connection.queries, ["PRAGMA journal_mode=WAL"])
        self.assertTrue(connection.closed)

    def test_sqlite_initialization_failure_closes_handle(self):
        # A failed PRAGMA/schema/commit must not leak a SQLite handle after
        # the admission lock is released, especially on Windows WAL files.
        import sqlite3
        from unittest.mock import patch

        for failure_at in ("execute", "commit"):
            with self.subTest(failure_at=failure_at):
                class FailingConnection:
                    closed = False

                    def execute(self, _sql):
                        if failure_at == "execute":
                            raise sqlite3.OperationalError("injected setup failure")
                        if _sql == "PRAGMA journal_mode=WAL":
                            class Cursor:
                                def fetchone(self):
                                    return ("wal",)
                            return Cursor()

                    def commit(self):
                        if failure_at == "commit":
                            raise sqlite3.OperationalError("injected setup failure")

                    def close(self):
                        self.closed = True

                connection = FailingConnection()
                with patch.object(C.sqlite3, "connect", return_value=connection):
                    with self.assertRaisesRegex(sqlite3.OperationalError, "injected setup failure"):
                        C.pull(self.b, "inbound", 0, 1)
                self.assertTrue(connection.closed, "failed SQLite setup leaked a handle")

    @unittest.skipIf(os.name == "nt" or not hasattr(os, "O_NONBLOCK"),
                     "POSIX nonblocking FIFO admission")
    def test_admission_lock_fifo_swap_never_blocks_rpc(self):
        # A FIFO substituted between lstat and open must be rejected without
        # waiting for a writer or letting SQLite touch untrusted state.
        from unittest.mock import patch
        lock_path = Path(self.b) / C._ADMISSION_LOCK_NAME
        original_bytes = lock_path.read_bytes()
        real_open = os.open
        swapped = []

        def replace_at_open(path, flags, *args, **kwargs):
            if Path(path) == lock_path:
                self.assertTrue(flags & os.O_NONBLOCK,
                                "admission lock open must reject blocking FIFOs")
                lock_path.unlink()
                os.mkfifo(lock_path, mode=0o600)
                swapped.append(True)
            return real_open(path, flags, *args, **kwargs)

        try:
            with patch.object(C.os, "open", side_effect=replace_at_open):
                with patch.object(C.sqlite3, "connect",
                                  side_effect=AssertionError("SQLite opened swapped FIFO")):
                    with self.assertRaisesRegex(ValueError,
                                                "admission lock identity changed"):
                        C.pull(self.b, "inbound", 0, 1)
            self.assertEqual(swapped, [True])
        finally:
            lock_path.unlink(missing_ok=True)
            lock_path.write_bytes(original_bytes)
            os.chmod(lock_path, 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX lock unlink race fixture")
    def test_admission_lock_removed_between_stat_and_open_fails_closed(self):
        """Do not leak a raw open error or enter SQLite after lock removal."""
        from unittest.mock import patch
        lock_path = Path(self.b) / C._ADMISSION_LOCK_NAME
        original = lock_path.read_bytes()
        real_open = os.open

        def unlink_before_open(path, flags, *args, **kwargs):
            if Path(path) == lock_path:
                lock_path.unlink()
            return real_open(path, flags, *args, **kwargs)

        try:
            with patch.object(C.os, "open", side_effect=unlink_before_open):
                with patch.object(C.sqlite3, "connect",
                                  side_effect=AssertionError("SQLite opened without lock")):
                    with self.assertRaisesRegex(ValueError,
                                                "admission lock identity changed"):
                        C.pull(self.b, "inbound", 0, 1)
        finally:
            lock_path.write_bytes(original)
            os.chmod(lock_path, 0o600)
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    @unittest.skipIf(os.name == "nt", "POSIX flock unlink race fixture")
    def test_admission_lock_removed_after_flock_fails_closed_and_closes_fd(self):
        """A vanished locked pathname cannot authorize a SQLite transaction."""
        import fcntl
        from unittest.mock import patch
        lock_path = Path(self.b) / C._ADMISSION_LOCK_NAME
        original = lock_path.read_bytes()
        real_flock = fcntl.flock
        observed = []

        def unlink_after_lock(fd, operation):
            result = real_flock(fd, operation)
            if operation & fcntl.LOCK_EX:
                observed.append(fd)
                lock_path.unlink()
            return result

        try:
            with patch.object(fcntl, "flock", side_effect=unlink_after_lock):
                with patch.object(C.sqlite3, "connect",
                                  side_effect=AssertionError("SQLite opened without lock")):
                    with self.assertRaisesRegex(ValueError,
                                                "admission lock identity changed"):
                        C.pull(self.b, "inbound", 0, 1)
            self.assertEqual(len(observed), 1)
            with self.assertRaises(OSError):
                os.fstat(observed[0])
        finally:
            lock_path.write_bytes(original)
            os.chmod(lock_path, 0o600)
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    @unittest.skipIf(os.name == "nt", "POSIX post-flock root replacement fixture")
    def test_admission_lock_root_replaced_after_flock_fails_before_sqlite(self):
        """Locking an old directory's inode must not admit a new named state root."""
        import fcntl
        import shutil
        from unittest.mock import patch

        root = Path(self.b)
        detached = Path(self.temp.name) / "athena-detached"
        real_flock = fcntl.flock
        swapped = []

        def replace_root_after_lock(fd, operation):
            result = real_flock(fd, operation)
            if operation & fcntl.LOCK_EX and not swapped:
                root.rename(detached)
                shutil.copytree(detached, root)
                (root / C._ADMISSION_LOCK_NAME).unlink()
                (detached / C._ADMISSION_LOCK_NAME).rename(root / C._ADMISSION_LOCK_NAME)
                swapped.append(True)
            return result

        try:
            with patch.object(fcntl, "flock", side_effect=replace_root_after_lock):
                with patch.object(C.sqlite3, "connect",
                                  side_effect=AssertionError("SQLite opened replacement state root")):
                    with self.assertRaisesRegex(ValueError, "carrier state directory identity changed"):
                        C.pull(self.b, "inbound", 0, 1)
            self.assertEqual(swapped, [True])
        finally:
            if detached.exists():
                if root.exists():
                    (root / C._ADMISSION_LOCK_NAME).rename(detached / C._ADMISSION_LOCK_NAME)
                    shutil.rmtree(root)
                detached.rename(root)
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    @unittest.skipIf(os.name == "nt", "POSIX post-flock hardlink fixture")
    def test_admission_lock_hardlinked_after_flock_fails_closed(self):
        """A newly aliased locked inode cannot authorize SQLite admission."""
        import fcntl
        from unittest.mock import patch

        lock_path = Path(self.b) / C._ADMISSION_LOCK_NAME
        alias = Path(self.temp.name) / "external-admission-lock-alias"
        real_flock = fcntl.flock
        observed = []

        def alias_after_lock(fd, operation):
            result = real_flock(fd, operation)
            if operation & fcntl.LOCK_EX:
                observed.append(fd)
                os.link(lock_path, alias)
            return result

        try:
            with patch.object(fcntl, "flock", side_effect=alias_after_lock):
                with patch.object(C.sqlite3, "connect",
                                  side_effect=AssertionError("SQLite opened aliased lock")):
                    with self.assertRaisesRegex(ValueError,
                                                "admission lock identity changed"):
                        C.pull(self.b, "inbound", 0, 1)
            self.assertEqual(len(observed), 1)
            with self.assertRaises(OSError):
                os.fstat(observed[0])
        finally:
            if alias.exists():
                alias.unlink()
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    @unittest.skipIf(os.name == "nt", "POSIX injected lock open failures")
    def test_admission_lock_unrelated_open_errors_preserve_errno(self):
        """An I/O or resource failure is not evidence of lock substitution."""
        import errno
        from unittest.mock import patch
        lock_path = Path(self.b) / C._ADMISSION_LOCK_NAME
        real_open = os.open

        for code in (errno.EACCES, errno.EMFILE, errno.EIO):
            with self.subTest(errno=code):
                def fail_lock_open(path, flags, *args, **kwargs):
                    if Path(path) == lock_path:
                        raise OSError(code, os.strerror(code))
                    return real_open(path, flags, *args, **kwargs)

                with patch.object(C.os, "open", side_effect=fail_lock_open):
                    with patch.object(C.sqlite3, "connect",
                                      side_effect=AssertionError("SQLite opened after lock failure")):
                        with self.assertRaises(OSError) as caught:
                            C.pull(self.b, "inbound", 0, 1)
                self.assertEqual(caught.exception.errno, code)
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    @unittest.skipIf(os.name == "nt", "POSIX injected flock failures")
    def test_admission_lock_noncontention_flock_errors_are_not_retried(self):
        """A broken lock operation must preserve its real error immediately."""
        import errno
        import fcntl
        from unittest.mock import patch

        for code in (errno.EIO, errno.EBADF, errno.EINVAL):
            with self.subTest(errno=code):
                with patch.object(fcntl, "flock",
                                  side_effect=OSError(code, os.strerror(code))):
                    with patch.object(C.time, "sleep",
                                      side_effect=AssertionError("noncontention lock error retried")):
                        with patch.object(C.sqlite3, "connect",
                                          side_effect=AssertionError("SQLite opened after lock failure")):
                            with self.assertRaises(OSError) as caught:
                                C.pull(self.b, "inbound", 0, 1)
                self.assertEqual(caught.exception.errno, code)
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    @unittest.skipIf(os.name == "nt", "POSIX transient flock contention")
    def test_admission_lock_retries_transient_contention(self):
        import errno
        import fcntl
        from unittest.mock import patch

        real_flock = fcntl.flock
        attempts = []

        def contend_once(fd, operation):
            if operation & fcntl.LOCK_EX:
                attempts.append(operation)
                if len(attempts) == 1:
                    raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
            return real_flock(fd, operation)

        with patch.object(fcntl, "flock", side_effect=contend_once):
            with patch.object(C.time, "sleep", return_value=None):
                self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])
        self.assertEqual(len(attempts), 2)

    @unittest.skipIf(os.name == "nt", "POSIX injected post-lock stat failures")
    def test_admission_lock_unrelated_post_lock_stat_errors_preserve_errno(self):
        """Keep filesystem diagnostics while still releasing the lock handle."""
        import errno
        from unittest.mock import patch
        lock_path = Path(self.b) / C._ADMISSION_LOCK_NAME
        real_lstat = Path.lstat

        for code in (errno.EACCES, errno.EIO):
            with self.subTest(errno=code):
                seen = []

                def fail_post_lock_lstat(path, *args, **kwargs):
                    if path == lock_path:
                        seen.append(path)
                        if len(seen) == 3:
                            raise OSError(code, os.strerror(code))
                    return real_lstat(path, *args, **kwargs)

                with patch.object(C.Path, "lstat", fail_post_lock_lstat):
                    with patch.object(C.sqlite3, "connect",
                                      side_effect=AssertionError("SQLite opened after stat failure")):
                        with self.assertRaises(OSError) as caught:
                            C.pull(self.b, "inbound", 0, 1)
                self.assertEqual(len(seen), 3)
                self.assertEqual(caught.exception.errno, code)
        self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    def test_cross_process_admission_lock_serializes_transaction_lifetime(self):
        import subprocess
        import sys
        child_code = """
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("carrier", Path(sys.argv[1]))
carrier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(carrier)
with carrier.carrier_admission_lock(sys.argv[2]):
    print("LOCKED", flush=True)
    sys.stdin.readline()
"""
        child = subprocess.Popen(
            [sys.executable, "-c", child_code, str(Path(C.__file__)), self.b],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        finished = threading.Event()
        failures = []
        thread = None
        try:
            self.assertEqual(child.stdout.readline().strip(), "LOCKED")
            def read_while_locked():
                try:
                    C.pull(self.b, "inbound", 0, 1)
                except Exception as error:
                    failures.append(error)
                finally:
                    finished.set()
            thread = threading.Thread(target=read_while_locked, daemon=True)
            thread.start()
            self.assertFalse(finished.wait(0.15), "transaction bypassed cross-process lock")
        finally:
            if child.stdin:
                child.stdin.write("\n")
                child.stdin.flush()
                child.stdin.close()
            child.wait(timeout=10)
            if thread:
                thread.join(timeout=10)
        try:
            self.assertEqual(child.returncode, 0, child.stderr.read())
        finally:
            child.stdout.close()
            child.stderr.close()
        self.assertTrue(finished.is_set(), "transaction did not resume after lock release")
        self.assertFalse(failures, failures)

    def test_missing_admission_lock_fails_closed_before_sqlite_open(self):
        from unittest.mock import patch
        lock_path = Path(self.b) / C._ADMISSION_LOCK_NAME
        lock_path.unlink()
        with patch.object(C.sqlite3, "connect", side_effect=AssertionError("opened missing lock")):
            with self.assertRaisesRegex(ValueError, "prepared carrier admission lock required"):
                C.pull(self.b, "inbound", 0, 1)

    @unittest.skipIf(os.name == "nt", "POSIX mode fixture")
    def test_shared_admission_lock_fails_closed_before_sqlite_open(self):
        from unittest.mock import patch
        lock_path = Path(self.b) / C._ADMISSION_LOCK_NAME
        os.chmod(lock_path, 0o644)
        with patch.object(C.sqlite3, "connect", side_effect=AssertionError("opened shared lock")):
            with self.assertRaisesRegex(ValueError, "private carrier admission lock required"):
                C.pull(self.b, "inbound", 0, 1)

    @unittest.skipIf(os.name == "nt", "POSIX symlink/hardlink fixture")
    def test_admission_lock_alias_rejected_before_sqlite_open(self):
        from unittest.mock import patch
        lock_path = Path(self.b) / C._ADMISSION_LOCK_NAME
        original = lock_path.read_bytes()
        lock_path.unlink()
        victim = Path(self.temp.name) / "external-lock"
        victim.write_bytes(original)
        try:
            for alias in ("symlink", "hardlink"):
                with self.subTest(alias=alias):
                    if alias == "symlink":
                        lock_path.symlink_to(victim)
                    else:
                        os.link(victim, lock_path)
                    with patch.object(C.sqlite3, "connect", side_effect=AssertionError("opened unsafe lock")):
                        with self.assertRaisesRegex(ValueError, "unaliased carrier admission lock"):
                            C.pull(self.b, "inbound", 0, 1)
                    lock_path.unlink()
        finally:
            if lock_path.is_symlink() or lock_path.exists():
                lock_path.unlink()
            lock_path.write_bytes(original)
            os.chmod(lock_path, 0o600)

    def test_private_lifecycle_marker_status_and_missing_marker(self):
        marker = Path(self.b) / "ready.json"
        self.assertFalse(C.admitted_lifecycle_marker(marker))
        C.write_exclusive_marker(marker, {"mode": "accept", "pid": 1})
        self.assertTrue(C.admitted_lifecycle_marker(marker))
        self.assertFalse(C.admitted_lifecycle_marker(Path(self.b) / "ended.json"))

    @unittest.skipIf(os.name == "nt", "POSIX inode replacement fixture")
    def test_lifecycle_marker_regular_file_swap_is_rejected(self):
        from unittest.mock import patch
        marker = Path(self.b) / "ready.json"
        replacement = Path(self.b) / "replacement.json"
        C.write_exclusive_marker(marker, {"pid": 1})
        C.write_exclusive_marker(replacement, {"pid": 2})
        real_open = os.open
        swapped = []

        def swap_before_open(path, flags, *args, **kwargs):
            if Path(path) == marker:
                marker.unlink()
                replacement.rename(marker)
                swapped.append(True)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(C.os, "open", side_effect=swap_before_open):
            with self.assertRaisesRegex(ValueError, "lifecycle marker identity changed"):
                C.admitted_lifecycle_marker(marker)
        self.assertEqual(swapped, [True])

    @unittest.skipIf(os.name == "nt" or not hasattr(os, "O_NONBLOCK"),
                     "POSIX nonblocking FIFO replacement fixture")
    def test_lifecycle_marker_fifo_swap_does_not_block_status(self):
        from unittest.mock import patch
        marker = Path(self.b) / "ready.json"
        C.write_exclusive_marker(marker, {"pid": 1})
        real_open = os.open

        def fifo_before_open(path, flags, *args, **kwargs):
            if Path(path) == marker:
                self.assertTrue(flags & os.O_NONBLOCK)
                marker.unlink()
                os.mkfifo(marker, mode=0o600)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(C.os, "open", side_effect=fifo_before_open):
            with self.assertRaisesRegex(ValueError, "lifecycle marker identity changed"):
                C.admitted_lifecycle_marker(marker)

    @unittest.skipIf(os.name == "nt", "POSIX post-open unlink fixture")
    def test_lifecycle_marker_removed_after_open_fails_closed_and_closes_fd(self):
        from unittest.mock import patch
        real_fstat = os.fstat
        for name in ("ready.json", "ended.json"):
            with self.subTest(marker=name):
                marker = Path(self.b) / name
                C.write_exclusive_marker(marker, {"finished": False})
                observed = []

                def unlink_after_open(fd):
                    opened = real_fstat(fd)
                    observed.append(fd)
                    marker.unlink()
                    return opened

                with patch.object(C.os, "fstat", side_effect=unlink_after_open):
                    with self.assertRaisesRegex(
                            ValueError, "carrier lifecycle marker identity changed"):
                        C.admitted_lifecycle_marker(marker)
                self.assertEqual(len(observed), 1)
                self.assertFalse(marker.exists())
                with self.assertRaises(OSError):
                    real_fstat(observed[0])

    def test_unprepared_state_cannot_create_database_on_read(self):
        empty = Path(self.temp.name) / "unprepared"
        empty.mkdir(mode=0o700)
        if os.name == "nt":
            # A Windows admin token can default new-object owner to Administrators.
            # This fixture is intended to test an owned, unprepared directory.
            C.windows_claim_new_owner(empty)
        with self.assertRaisesRegex(ValueError, "prepared carrier database required"):
            C.pull(str(empty), "outbound", 0, 1)
        self.assertFalse((empty / "carrier.sqlite3").exists())

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
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

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
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

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
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

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
    def test_sqlite_sidecar_shared_permissions_are_rejected_before_open(self):
        # SQLite can read or modify pre-existing WAL/SHM/journal files.
        # Sidecars must not admit readers or writers outside the carrier owner.
        import os
        from unittest.mock import patch
        for suffix in ("-wal", "-shm", "-journal"):
            for mode in (0o644, 0o666):
                with self.subTest(suffix=suffix, mode=oct(mode)):
                    sidecar = Path(self.b) / ("carrier.sqlite3" + suffix)
                    sidecar.write_bytes(b"untrusted sidecar")
                    os.chmod(sidecar, mode)
                    try:
                        with patch.object(C.sqlite3, "connect", side_effect=AssertionError("SQLite opened shared sidecar")):
                            with self.assertRaisesRegex(ValueError, "private carrier sidecar required"):
                                C.pull(self.b, "inbound", 0, 1)
                        self.assertEqual(sidecar.read_bytes(), b"untrusted sidecar")
                    finally:
                        sidecar.unlink()

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
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

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
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

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
    def test_foreign_owned_carrier_state_is_rejected_before_sqlite_open(self):
        import os
        from unittest.mock import patch
        with patch.object(C.os, "geteuid", return_value=os.geteuid() + 1):
            with patch.object(C.sqlite3, "connect", side_effect=AssertionError("opened foreign-owned state")):
                with self.assertRaisesRegex(ValueError, "carrier state directory owner required"):
                    C.pull(self.b, "inbound", 0, 1)

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
    def test_foreign_owned_database_is_rejected_before_sqlite_open(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        database = Path(self.b) / "carrier.sqlite3"
        original = Path.lstat

        def foreign_database(path):
            identity = original(path)
            if path == database:
                return SimpleNamespace(st_mode=identity.st_mode, st_nlink=identity.st_nlink,
                                       st_uid=identity.st_uid + 1)
            return identity

        with patch.object(Path, "lstat", foreign_database):
            with patch.object(C.sqlite3, "connect", side_effect=AssertionError("opened foreign-owned database")):
                with self.assertRaisesRegex(ValueError, "carrier database owner"):
                    C.pull(self.b, "inbound", 0, 1)

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
    def test_foreign_owned_sqlite_sidecars_are_rejected_before_open(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        original = Path.lstat
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                sidecar = Path(self.b) / ("carrier.sqlite3" + suffix)
                sidecar.write_bytes(b"untrusted sidecar")
                def foreign_sidecar(path):
                    identity = original(path)
                    if path == sidecar:
                        return SimpleNamespace(st_mode=identity.st_mode, st_nlink=identity.st_nlink,
                                               st_uid=identity.st_uid + 1)
                    return identity
                try:
                    with patch.object(Path, "lstat", foreign_sidecar):
                        with patch.object(C.sqlite3, "connect", side_effect=AssertionError("opened foreign-owned sidecar")):
                            with self.assertRaisesRegex(ValueError, "carrier sidecar owner"):
                                C.pull(self.b, "inbound", 0, 1)
                finally:
                    sidecar.unlink()

    def test_gap_and_conflicting_replay_rejected(self):
        C.deliver(self.b,'[{"seq":1,"b64":"YWJj"}]')
        with self.assertRaisesRegex(ValueError,"out-of-order"):
            C.deliver(self.b,'[{"seq":3,"b64":"YWJj"}]')
        with self.assertRaisesRegex(ValueError,"non-idempotent"):
            C.deliver(self.b,'[{"seq":1,"b64":"YWJk"}]')
    def test_live_carrier_runtime_budget_exhaustion_is_not_success(self):
        # A still-connected TLS socket at the carrier deadline is not a
        # successful completed byte pump, even without a storage exception.
        from unittest.mock import patch
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        errors = []

        def run():
            try:
                C.serve(self.b, "accept", port)
            except Exception as error:
                errors.append(str(error))

        with patch.object(C, "MAX_RUNTIME", 0.8):
            worker = threading.Thread(target=run)
            worker.start()
            deadline = time.monotonic() + 3
            while not (Path(self.b) / "ready.json").exists() and time.monotonic() < deadline:
                time.sleep(.01)
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors, "runtime exhaustion must not silently succeed")
        self.assertIn("E07_CARRIER_PUMP_FAILED:timeout", errors[0])
        status = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertFalse(status["finished"])
        self.assertTrue(status["failed"])

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

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
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

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
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

    @unittest.skipIf(os.name == "nt", "POSIX modes or privileged symlinks")
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

    def test_status_only_reports_admitted_lifecycle_markers(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        def status():
            output = StringIO()
            with patch.object(C.sys, "argv", ["e07_oracle_stream.py", "status",
                                               "--state", self.b]):
                with redirect_stdout(output):
                    C.main()
            return json.loads(output.getvalue())

        self.assertFalse(status()["ready"])
        self.assertFalse(status()["ended"])
        C.write_exclusive_marker(Path(self.b) / "ready.json", {"bound": "127.0.0.1"})
        self.assertTrue(status()["ready"])
        self.assertFalse(status()["ended"])
        C.write_exclusive_marker(Path(self.b) / "ended.json", {"finished": True})
        self.assertTrue(status()["ended"])

    @unittest.skipIf(os.name == "nt", "POSIX symlink/hardlink/mode fixtures")
    def test_status_rejects_aliased_and_shared_lifecycle_markers(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        outside = Path(self.temp.name) / "outside-marker"
        outside.write_text("{}", encoding="utf-8")
        for name in ("ready.json", "ended.json"):
            marker = Path(self.b) / name
            for kind in ("symlink", "hardlink", "shared"):
                with self.subTest(marker=name, kind=kind):
                    if kind == "symlink":
                        marker.symlink_to(outside)
                        expected = "unaliased carrier lifecycle marker"
                    elif kind == "hardlink":
                        os.link(outside, marker)
                        expected = "unaliased carrier lifecycle marker"
                    else:
                        marker.write_text("{}", encoding="utf-8")
                        os.chmod(marker, 0o644)
                        expected = "private carrier lifecycle marker required"
                    try:
                        with patch.object(C.sys, "argv", ["e07_oracle_stream.py",
                                                           "status", "--state", self.b]):
                            with redirect_stdout(StringIO()):
                                with self.assertRaisesRegex(ValueError, expected):
                                    C.main()
                    finally:
                        marker.unlink()
        self.assertEqual(outside.read_text(encoding="utf-8"), "{}")

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
        status = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertTrue(status["finished"])
        self.assertFalse(status["failed"])

if __name__=="__main__": unittest.main()
