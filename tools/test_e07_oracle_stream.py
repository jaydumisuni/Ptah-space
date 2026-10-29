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
    def test_missing_durable_stream_table_is_not_silently_recreated(self):
        # A missing journal is damaged custody, not an empty fresh stream.
        # A read-only observation must not repair it or report healthy.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        for table in ("inbound", "outbound"):
            with self.subTest(table=table):
                with C.dbtransaction(self.a) as conn:
                    conn.execute(f"DROP TABLE {table}")
                output = StringIO()
                with redirect_stdout(output):
                    with self.assertRaisesRegex(ValueError, "carrier journal schema"):
                        C.pull(self.a, "outbound", 0, 1)
                    with patch("sys.argv", [
                        "e07_oracle_stream.py", "status", "--state", self.a
                    ]):
                        with self.assertRaisesRegex(ValueError, "carrier journal schema"):
                            C.main()
                self.assertEqual(output.getvalue(), "")
                # Verify the failed observation did not recreate the table.
                import sqlite3
                conn = sqlite3.connect(str(Path(self.a) / "carrier.sqlite3"))
                try:
                    self.assertIsNone(conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone())
                    conn.execute(
                        f"CREATE TABLE {table}(seq INTEGER PRIMARY KEY, content BLOB NOT NULL)"
                    )
                    conn.commit()
                finally:
                    conn.close()

    def test_durable_stream_view_cannot_impersonate_missing_table(self):
        # SQLite IF NOT EXISTS accepts a preexisting VIEW of the same name.
        # No transport observation may accept it as a durable frame journal.
        import sqlite3
        with C.dbtransaction(self.a) as conn:
            conn.execute("DROP TABLE inbound")
            conn.execute("CREATE VIEW inbound AS SELECT 1 AS seq, X'6162' AS content")
        with self.assertRaisesRegex(ValueError, "carrier journal schema"):
            C.pull(self.a, "outbound", 0, 1)
        conn = sqlite3.connect(str(Path(self.a) / "carrier.sqlite3"))
        try:
            self.assertEqual(conn.execute(
                "SELECT type FROM sqlite_master WHERE name='inbound'"
            ).fetchone(), ("view",))
        finally:
            conn.close()

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

    def test_publish_rejects_invalid_historical_frame_before_append(self):
        # A valid new ciphertext frame cannot rehabilitate an invalid
        # historical durable frame. Keep the original row and sequence intact.
        for table in ("outbound", "inbound"):
            for damaged in (b"", "text-not-ciphertext", b"x" * (C.MAX_CHUNK + 1)):
                with self.subTest(table=table, kind=type(damaged).__name__,
                                  length=len(damaged)):
                    with C.dbtransaction(self.a) as conn:
                        conn.execute(f"DELETE FROM {table}")
                        conn.execute(f"INSERT INTO {table}(seq,content) VALUES (1,?)",
                                     (damaged,))
                    with self.assertRaisesRegex(ValueError, "invalid durable carrier frame"):
                        C.publish(self.a, table, b"new-ciphertext")
                    with C.dbtransaction(self.a) as conn:
                        self.assertEqual(
                            conn.execute(f"SELECT seq,content FROM {table}").fetchall(),
                            [(1, damaged)],
                        )
            with C.dbtransaction(self.a) as conn:
                conn.execute(f"DELETE FROM {table}")
            C.publish(self.a, table, b"valid-ciphertext")
            with C.dbtransaction(self.a) as conn:
                self.assertEqual(
                    conn.execute(f"SELECT seq,content FROM {table}").fetchall(),
                    [(1, b"valid-ciphertext")],
                )

    def test_publish_rejects_sparse_historical_journal_before_append(self):
        # A valid new frame must not extend a journal whose earlier sequence
        # is missing, zero or negative. This applies to both stream directions.
        damaged = (
            ((1, b"one"), (3, b"three")),
            ((2, b"two"),),
            ((0, b"zero"), (1, b"one")),
            ((-1, b"negative"), (1, b"one")),
        )
        for table in ("outbound", "inbound"):
            for history in damaged:
                with self.subTest(table=table, seqs=[x[0] for x in history]):
                    with C.dbtransaction(self.a) as conn:
                        conn.execute(f"DELETE FROM {table}")
                        conn.executemany(
                            f"INSERT INTO {table}(seq,content) VALUES (?,?)",
                            history,
                        )
                    with self.assertRaisesRegex(
                        ValueError, "carrier journal sequence gap"
                    ):
                        C.publish(self.a, table, b"new-ciphertext")
                    with C.dbtransaction(self.a) as conn:
                        self.assertEqual(
                            conn.execute(
                                f"SELECT seq,content FROM {table} ORDER BY seq"
                            ).fetchall(),
                            list(history),
                        )
            with C.dbtransaction(self.a) as conn:
                conn.execute(f"DELETE FROM {table}")
            C.publish(self.a, table, b"valid-ciphertext")
            self.assertEqual(len(C.pull(self.a, table, 0, 1)), 1)

    def test_outbound_sequence_exhaustion_is_controlled_before_sqlite_bind(self):
        # A fabricated near-limit history is sparse, so reject its append
        # rather than issuing an undeliverable successor. A max-int key also
        # produces a controlled overflow error without SQLite binding.
        maximum = (1 << 63) - 1
        with C.dbtransaction(self.a) as conn:
            conn.execute("INSERT INTO outbound(seq,content) VALUES (?,?)",
                         (maximum - 1, b"penultimate"))
        with self.assertRaisesRegex(ValueError, "carrier journal sequence gap"):
            C.publish(self.a, "outbound", b"last")
        with C.dbtransaction(self.a) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM outbound").fetchone()[0], 1)
            conn.execute("DELETE FROM outbound")
            conn.execute("INSERT INTO outbound(seq,content) VALUES (?,?)",
                         (maximum, b"last"))
        with self.assertRaisesRegex(ValueError, "carrier sequence exhausted"):
            C.publish(self.a, "outbound", b"overflow")
        with C.dbtransaction(self.a) as conn:
            self.assertEqual(conn.execute("SELECT seq,content FROM outbound").fetchall(),
                             [(maximum, b"last")])

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

    def test_sparse_durable_ciphertext_journal_fails_closed_at_read(self):
        # A missing committed frame must not be silently skipped by either
        # the ordinary pull or the Oracle exchange snapshot.
        for table in ("outbound", "inbound"):
            with self.subTest(table=table):
                for payload in (b"one", b"two", b"three"):
                    C.publish(self.a, table, payload)
                with C.dbtransaction(self.a) as conn:
                    conn.execute(f"DELETE FROM {table} WHERE seq=2")
                for after in (0, 1, 2):
                    with self.subTest(after=after):
                        with self.assertRaisesRegex(ValueError, "carrier journal sequence gap"):
                            C.pull(self.a, table, after, C.MAX_BATCH)
                if table == "outbound":
                    with self.assertRaisesRegex(ValueError, "carrier journal sequence gap"):
                        C.snapshot(self.a, 0)
                with C.dbtransaction(self.a) as conn:
                    conn.execute(f"DELETE FROM {table}")

    def test_resumed_reads_reject_corrupt_historical_prefix(self):
        # A valid acknowledged cursor and suffix must not conceal an earlier
        # missing sequence or invalid frame in the same durable TLS stream.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        histories = (
            ((1, b"one"), (3, b"three"), (4, b"four")),
            ((1, b""), (2, b"two"), (3, b"three"), (4, b"four")),
        )
        for table in ("outbound", "inbound"):
            for history in histories:
                with self.subTest(table=table, history=history):
                    with C.dbtransaction(self.a) as conn:
                        conn.execute(f"DELETE FROM {table}")
                        conn.executemany(
                            f"INSERT INTO {table}(seq,content) VALUES (?,?)",
                            history,
                        )
                    for after in (3, 4):
                        with self.subTest(after=after):
                            with self.assertRaisesRegex(
                                ValueError,
                                "carrier journal sequence gap|invalid durable carrier frame",
                            ):
                                C.pull(self.a, table, after, 1)
                            if table == "outbound":
                                output = StringIO()
                                with redirect_stdout(output):
                                    with self.assertRaisesRegex(
                                        ValueError,
                                        "carrier journal sequence gap|invalid durable carrier frame",
                                    ):
                                        C.snapshot(self.a, after)
                                self.assertEqual(output.getvalue(), "")
                    if table == "outbound":
                        output = StringIO()
                        with patch("sys.argv", [
                            "e07_oracle_stream.py", "exchange",
                            "--state", self.a, "--after", "3",
                            "--packets", '[{"seq":1,"b64":"YWJj"}]',
                        ]):
                            with redirect_stdout(output):
                                with self.assertRaisesRegex(
                                    ValueError,
                                    "carrier journal sequence gap|invalid durable carrier frame",
                                ):
                                    C.main()
                        self.assertEqual(output.getvalue(), "")
                        self.assertEqual(C.pull(self.a, "inbound", 0, 1), [])

    def test_historical_inbound_gap_rejects_new_delivery_and_exchange(self):
        # A previously damaged durable inbound journal must never advance its
        # acknowledged cursor. Both RPC paths must roll back before printing.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        damaged_journals = (
            ((1, b"one"), (3, b"three")),
            ((2, b"two"),),
            ((0, b"zero"), (1, b"one")),
            ((-1, b"negative"), (1, b"one")),
        )
        for existing in damaged_journals:
            with self.subTest(existing=[seq for seq, _ in existing]):
                with C.dbtransaction(self.b) as conn:
                    conn.execute("DELETE FROM inbound")
                    conn.executemany(
                        "INSERT INTO inbound(seq,content) VALUES (?,?)", existing
                    )
                next_seq = max(seq for seq, _ in existing) + 1
                incoming = json.dumps([{"seq": next_seq, "b64": "YWJj"}])
                for operation in ("deliver", "exchange"):
                    with self.subTest(operation=operation):
                        output = StringIO()
                        with redirect_stdout(output):
                            with self.assertRaisesRegex(
                                ValueError, "carrier journal sequence gap"
                            ):
                                if operation == "deliver":
                                    C.deliver(self.b, incoming)
                                else:
                                    with patch("sys.argv", [
                                        "e07_oracle_stream.py", "exchange",
                                        "--state", self.b, "--packets", incoming
                                    ]):
                                        C.main()
                        self.assertEqual(output.getvalue(), "")
                        with C.dbtransaction(self.b) as conn:
                            observed = conn.execute(
                                "SELECT seq,content FROM inbound ORDER BY seq"
                            ).fetchall()
                        self.assertEqual(observed, sorted(existing))

    def test_historical_inbound_invalid_frames_cannot_be_acknowledged(self):
        # A contiguous journal may still contain invalid durable bytes. Neither
        # delivery nor exchange may acknowledge a newer frame over that damage.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        incoming = '[{"seq":2,"b64":"YWJj"}]'
        for damaged in (b"", "not-a-blob", b"x" * (C.MAX_CHUNK + 1)):
            with self.subTest(kind=type(damaged).__name__,
                              size=len(damaged) if damaged is not None else None):
                with C.dbtransaction(self.b) as conn:
                    conn.execute("DELETE FROM inbound")
                    conn.execute("INSERT INTO inbound(seq,content) VALUES (1,?)",
                                 (damaged,))
                for operation in ("deliver", "exchange"):
                    with self.subTest(operation=operation):
                        output = StringIO()
                        with redirect_stdout(output):
                            with self.assertRaisesRegex(
                                ValueError, "invalid durable inbound carrier frame"
                            ):
                                if operation == "deliver":
                                    C.deliver(self.b, incoming)
                                else:
                                    with patch("sys.argv", [
                                        "e07_oracle_stream.py", "exchange",
                                        "--state", self.b, "--packets", incoming
                                    ]):
                                        C.main()
                        self.assertEqual(output.getvalue(), "")
                        with C.dbtransaction(self.b) as conn:
                            self.assertEqual(
                                conn.execute("SELECT seq,content FROM inbound").fetchall(),
                                [(1, damaged)],
                            )

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

    def test_noncanonical_base64_packet_encoding_rejected_before_sqlite(self):
        # RFC 4648 padding bits must be zero: permissive decoders otherwise
        # accept alternate text for the same opaque TLS bytes.
        from unittest.mock import patch
        for encoded in ("Zh==", "Zi==", "Zm9="):
            with self.subTest(encoded=encoded):
                batch = json.dumps([{"seq": 1, "b64": encoded}])
                with patch.object(C, "dbtransaction",
                                  side_effect=AssertionError("opened SQLite for noncanonical frame")):
                    with self.assertRaisesRegex(ValueError, "noncanonical packet encoding"):
                        C.deliver(self.b, batch)
        # The canonical representations remain interoperable with publish/pull.
        canonical = [{"seq": 1, "b64": "Zg=="}, {"seq": 2, "b64": "Zm8="}]
        C.deliver(self.b, json.dumps(canonical))
        self.assertEqual(C.pull(self.b, "inbound", 0, 2), canonical)

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

    def test_exchange_sparse_outbound_window_never_commits_inbound(self):
        # A durable missing outbound frame must reject the whole exchange,
        # not accept inbound ciphertext before snapshot raises an error.
        from unittest.mock import patch
        from contextlib import redirect_stdout
        from io import StringIO
        for payload in (b"one", b"two", b"three"):
            C.publish(self.b, "outbound", payload)
        with C.dbtransaction(self.b) as conn:
            conn.execute("DELETE FROM outbound WHERE seq=2")
        incoming = '[{"seq":1,"b64":"YWJj"}]'
        for cursor in (0, 1, 2):
            with self.subTest(cursor=cursor):
                output = StringIO()
                with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                        "--state", self.b, "--after", str(cursor),
                                        "--packets", incoming]):
                    with redirect_stdout(output):
                        with self.assertRaisesRegex(ValueError, "carrier journal sequence gap"):
                            C.main()
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(C.pull(self.b, "inbound", 0, 10), [])
        # A healthy outbound window retains normal bidirectional exchange.
        with C.dbtransaction(self.b) as conn:
            conn.execute("INSERT INTO outbound(seq,content) VALUES (2,?)", (b"two",))
        output = StringIO()
        with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                "--state", self.b, "--after", "1",
                                "--packets", incoming]):
            with redirect_stdout(output):
                C.main()
        self.assertEqual(json.loads(output.getvalue())["latest"], 3)
        self.assertEqual(C.pull(self.b, "inbound", 0, 10),
                         [{"seq": 1, "b64": "YWJj"}])

    def test_corrupt_acknowledged_outbound_cursor_never_commits_inbound(self):
        # A cursor is an assertion that the caller already received this
        # ciphertext. A damaged acknowledged row must not be silently skipped
        # merely because the subsequent outbound window is still healthy.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        incoming = '[{"seq":1,"b64":"YWJj"}]'
        for damaged in (b"", "not-a-blob", b"x" * (C.MAX_CHUNK + 1)):
            for cursor in (1, 2):
                with self.subTest(kind=type(damaged).__name__, cursor=cursor):
                    with C.dbtransaction(self.b) as conn:
                        conn.execute("DELETE FROM outbound")
                        conn.execute("DELETE FROM inbound")
                        conn.executemany(
                            "INSERT INTO outbound(seq,content) VALUES (?,?)",
                            [(1, b"first"), (2, b"second")])
                        conn.execute(
                            "UPDATE outbound SET content=? WHERE seq=?",
                            (damaged, cursor))
                    with self.assertRaisesRegex(
                            ValueError, "invalid durable carrier frame"):
                        C.pull(self.b, "outbound", cursor, C.MAX_BATCH)
                    output = StringIO()
                    with redirect_stdout(output):
                        with self.assertRaisesRegex(
                                ValueError, "invalid durable carrier frame"):
                            C.snapshot(self.b, cursor)
                    self.assertEqual(output.getvalue(), "")
                    output = StringIO()
                    with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                            "--state", self.b, "--after",
                                            str(cursor), "--packets", incoming]):
                        with redirect_stdout(output):
                            with self.assertRaisesRegex(
                                    ValueError, "invalid durable carrier frame"):
                                C.main()
                    self.assertEqual(output.getvalue(), "")
                    self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

        with C.dbtransaction(self.b) as conn:
            conn.execute("UPDATE outbound SET content=? WHERE seq=2", (b"second",))
        output = StringIO()
        with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                "--state", self.b, "--after", "2",
                                "--packets", incoming]):
            with redirect_stdout(output):
                C.main()
        self.assertEqual(json.loads(output.getvalue())["packets"], [])
        self.assertEqual(C.pull(self.b, "inbound", 0, 1),
                         [{"seq": 1, "b64": "YWJj"}])

    def test_corrupt_durable_ciphertext_frames_rejected_before_exchange_commit(self):
        # A damaged SQLite BLOB can pass sequence continuity but cannot be
        # delivered as a TLS frame. Reject it before accepting inbound bytes.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        incoming = '[{"seq":1,"b64":"YWJj"}]'
        for damaged in (b"", "not-a-blob", b"x" * (C.MAX_CHUNK + 1)):
            with self.subTest(kind=type(damaged).__name__, size=len(damaged)):
                with C.dbtransaction(self.b) as conn:
                    conn.execute("DELETE FROM outbound")
                    conn.execute("DELETE FROM inbound")
                    conn.execute("INSERT INTO outbound(seq,content) VALUES (1,?)",
                                 (damaged,))
                output = StringIO()
                with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                        "--state", self.b, "--after", "0",
                                        "--packets", incoming]):
                    with redirect_stdout(output):
                        with self.assertRaisesRegex(ValueError, "invalid durable carrier frame"):
                            C.main()
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(C.pull(self.b, "inbound", 0, 1), [])

    def test_corrupt_durable_ciphertext_frames_rejected_on_read(self):
        # The same fail-closed frame invariant applies to both journal reads.
        for table in ("inbound", "outbound"):
            with self.subTest(table=table):
                with C.dbtransaction(self.a) as conn:
                    conn.execute(f"INSERT INTO {table}(seq,content) VALUES (1,?)",
                                 (b"",))
                with self.assertRaisesRegex(ValueError, "invalid durable carrier frame"):
                    C.pull(self.a, table, 0, 1)
                with C.dbtransaction(self.a) as conn:
                    conn.execute(f"DELETE FROM {table}")

    def test_exchange_snapshot_is_bound_to_inbound_commit_transaction(self):
        # A second SQLite read after the inbound commit can observe a changed
        # outbound journal and fail, even though the inbound bytes persisted.
        # The response must use the validated window captured at commit time.
        from contextlib import contextmanager, redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        for payload in (b"one", b"two", b"three"):
            C.publish(self.b, "outbound", payload)
        real_transaction = C.dbtransaction
        changed = []

        @contextmanager
        def post_commit_change(state):
            with real_transaction(state) as conn:
                yield conn
            if not changed:
                changed.append(True)
                with real_transaction(state) as conn:
                    conn.execute("DELETE FROM outbound WHERE seq=2")

        output = StringIO()
        with patch.object(C, "dbtransaction", side_effect=post_commit_change):
            with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                    "--state", self.b, "--after", "0",
                                    "--packets", '[{"seq":1,"b64":"YWJj"}]']):
                with redirect_stdout(output):
                    C.main()
        result = json.loads(output.getvalue())
        self.assertEqual([row["seq"] for row in result["packets"]], [1, 2, 3])
        self.assertEqual(result["latest"], 3)
        self.assertEqual(changed, [True])
        self.assertEqual(C.pull(self.b, "inbound", 0, 1),
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

    def test_empty_exchange_rejects_damaged_inbound_history(self):
        # An empty Oracle poll still represents a usable bidirectional TLS
        # transport. It must not report success over a broken inbound prefix.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        histories = (
            [(1, b"one"), (3, b"missing-two")],
            [(1, "text-instead-of-ciphertext")],
            [(1, b"")],
        )
        for history in histories:
            with self.subTest(history=history):
                with C.dbtransaction(self.b) as conn:
                    conn.execute("DELETE FROM inbound")
                    conn.executemany(
                        "INSERT INTO inbound(seq,content) VALUES (?,?)", history
                    )
                output = StringIO()
                with patch("sys.argv", ["e07_oracle_stream.py", "exchange",
                                        "--state", self.b, "--packets", "[]"]):
                    with redirect_stdout(output):
                        with self.assertRaisesRegex(
                            ValueError,
                            "carrier journal sequence gap|invalid durable inbound carrier frame",
                        ):
                            C.main()
                self.assertEqual(output.getvalue(), "")

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
                        if "FROM sqlite_master" in _sql:
                            class Cursor:
                                def fetchall(self):
                                    return [("outbound", "table"), ("inbound", "table")]
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
        C.write_exclusive_marker(marker, {"mode": "accept", "port": 41321, "pid": 1, "bound": "127.0.0.1"})
        self.assertTrue(C.admitted_lifecycle_marker(marker))
        self.assertFalse(C.admitted_lifecycle_marker(Path(self.b) / "ended.json"))

    def test_lifecycle_marker_requires_actual_transport_event_schema(self):
        # A private, valid JSON file is not proof that a native carrier ever
        # became ready or ended. Reject incomplete and contradictory events.
        valid_ready = {"mode": "accept", "port": 41321, "pid": 1,
                       "bound": "127.0.0.1"}
        valid_ended = {"pid": 1, "finished": True, "failed": False}
        cases = (
            ("ready.json", {"unrelated": True}),
            ("ready.json", {"mode": "dial", "pid": 1}),
            ("ready.json", {**valid_ready, "port": 443}),
            ("ready.json", {**valid_ready, "bound": "0.0.0.0"}),
            ("ready.json", {**valid_ready, "pid": True}),
            ("ended.json", {"unrelated": True}),
            ("ended.json", {**valid_ended, "finished": True, "failed": True}),
            ("ended.json", {**valid_ended, "finished": 1}),
        )
        for name, document in cases:
            with self.subTest(name=name, document=document):
                marker = Path(self.b) / name
                if marker.exists():
                    marker.unlink()
                C.write_exclusive_marker(marker, document)
                try:
                    with self.assertRaisesRegex(ValueError, "invalid carrier lifecycle marker schema"):
                        C.admitted_lifecycle_marker(marker)
                finally:
                    marker.unlink()
        for name, document in (("ready.json", valid_ready),
                               ("ended.json", valid_ended)):
            marker = Path(self.b) / name
            C.write_exclusive_marker(marker, document)
            self.assertTrue(C.admitted_lifecycle_marker(marker))

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

    def test_batch_sequence_must_increase_before_sqlite_admission(self):
        # A single Oracle packet batch is an ordered TLS stream window.
        # An out-of-order replay or duplicate within that window must not
        # become an acknowledged transport delivery, even if SQLite could
        # ultimately sort the durable rows by their primary keys.
        for sequences in ((2, 1), (1, 1), (1, 3, 2)):
            with self.subTest(sequences=sequences):
                document = json.dumps([
                    {"seq": seq, "b64": "YWJj"} for seq in sequences
                ])
                with self.assertRaisesRegex(ValueError, "strictly increasing"):
                    C.admit_packet_batch(document)
        # A repeated *complete* ordered batch remains idempotent.
        ordered = json.dumps([
            {"seq": seq, "b64": "YWJj"} for seq in (1, 2, 3)
        ])
        C.deliver(self.b, ordered)
        C.deliver(self.b, ordered)
        self.assertEqual([row["seq"] for row in C.pull(self.b, "inbound", 0, 32)],
                         [1, 2, 3])

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

    def test_writer_send_failure_cannot_certify_inbound_delivery(self):
        # A failed local socket send is not an E07 transport completion,
        # even when the Oracle inbound journal already durably holds bytes.
        from unittest.mock import MagicMock, patch
        C.deliver(self.b, '[{"seq":1,"b64":"dGxzLWZyYW1l"}]')
        listener = MagicMock()
        client = MagicMock()
        client.recv.side_effect = socket.timeout("poll while writer runs")
        client.sendall.side_effect = BrokenPipeError("injected local send failure")
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        with patch.object(C.socket, "socket", return_value=listener):
            with self.assertRaisesRegex(
                    RuntimeError, "E07_CARRIER_PUMP_FAILED:writer:BrokenPipeError"):
                C.serve(self.b, "accept", 41321)
        client.sendall.assert_called_once_with(b"tls-frame")
        client.close.assert_called_once_with()
        listener.close.assert_called_once_with()
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))
        self.assertEqual(
            [frame["seq"] for frame in C.pull(self.b, "inbound", 0, 32)], [1])

    def test_post_pump_socket_close_errors_still_seal_failed_lifetime(self):
        # A socket close failure after the pumps stop must not bypass the
        # admission-locked finalizer or leave an apparently live carrier.
        from unittest.mock import MagicMock, patch
        for state, failed_endpoint in ((self.a, "client"), (self.b, "listener")):
            with self.subTest(endpoint=failed_endpoint):
                listener = MagicMock()
                client = MagicMock()
                client.recv.return_value = b""
                listener.accept.return_value = (client, ("127.0.0.1", 41322))
                endpoint = client if failed_endpoint == "client" else listener
                endpoint.close.side_effect = OSError("injected final socket close failure")
                with patch.object(C.socket, "socket", return_value=listener):
                    with self.assertRaisesRegex(
                        RuntimeError, "E07_CARRIER_PUMP_FAILED:shutdown:OSError"
                    ):
                        C.serve(state, "accept", 41321)
                client.close.assert_called_once_with()
                listener.close.assert_called_once_with()
                ended = json.loads((Path(state) / "ended.json").read_text())
                self.assertEqual((ended["finished"], ended["failed"]), (False, True))
                with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
                    C.deliver(state, '[{"seq":1,"b64":"eA=="}]')

    def test_socket_eof_with_undelivered_inbound_is_not_finished(self):
        # The native peer can close before the writer drains already admitted
        # Oracle ciphertext. A clean EOF is not proof those bytes reached it.
        from unittest.mock import patch
        C.deliver(self.b, '[{"seq":1,"b64":"dGxzLWZyYW1l"}]')
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

        # Model a writer whose poll has not yet observed the inbound frame.
        # The durable queue still contains the frame when the reader sees EOF.
        with patch.object(C, "pull", return_value=[]):
            worker = threading.Thread(target=run)
            worker.start()
            deadline = time.monotonic() + 3
            while not (Path(self.b) / "ready.json").exists() and time.monotonic() < deadline:
                time.sleep(.01)
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                pass
            worker.join(timeout=4)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors, "undelivered durable inbound bytes must fail closed")
        self.assertIn("E07_CARRIER_PUMP_FAILED:undelivered", errors[0])
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertFalse(ended["finished"])
        self.assertTrue(ended["failed"])
        self.assertEqual([p["seq"] for p in C.pull(self.b, "inbound", 0, 32)], [1])

    def test_socket_eof_after_inbound_forwarding_can_finish(self):
        # A completed local sendall is eligible for a local pump success
        # claim; it is not a remote TLS or application effect witness.
        C.deliver(self.b, '[{"seq":1,"b64":"dGxzLWZyYW1l"}]')
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

        worker = threading.Thread(target=run)
        worker.start()
        deadline = time.monotonic() + 3
        while not (Path(self.b) / "ready.json").exists() and time.monotonic() < deadline:
            time.sleep(.01)
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.settimeout(2)
            self.assertEqual(sock.recv(32), b"tls-frame")
        worker.join(timeout=4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertTrue(ended["finished"])
        self.assertFalse(ended["failed"])

    def test_ended_carrier_rejects_late_native_outbound_publish(self):
        # A pump thread that survives the bounded shutdown join must not
        # append outbound TLS ciphertext after the finalizer seals the
        # claimed socket lifetime. Already durable bytes stay drainable.
        for state, finished in ((self.a, True), (self.b, False)):
            with self.subTest(finished=finished):
                C.publish(state, "outbound", b"durable-before-end")
                C.write_exclusive_marker(
                    Path(state) / "ended.json",
                    {"pid": 1, "finished": finished, "failed": not finished})
                with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
                    C.publish(state, "outbound", b"late-native-tls")
                packets = C.pull(state, "outbound", 0, 2)
                self.assertEqual(len(packets), 1)
                import base64
                self.assertEqual(base64.b64decode(packets[0]["b64"]),
                                 b"durable-before-end")

    def test_ended_carrier_rejects_late_deliver_and_exchange(self):
        # A finished native socket cannot receive another TLS ciphertext
        # frame through a delayed Oracle RPC. Snapshot reads remain allowed.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        import base64

        C.publish(self.b, "outbound", b"outbound-drainable")
        C.write_exclusive_marker(Path(self.b) / "ended.json",
                                 {"pid": 1, "finished": True, "failed": False})
        packet = json.dumps([{"seq": 1, "b64": base64.b64encode(
            b"late-tls-frame").decode("ascii")}])
        with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
            C.deliver(self.b, packet)
        with patch.object(C.sys, "argv", ["e07_oracle_stream.py",
                                          "exchange", "--state", self.b,
                                          "--after", "0", "--packets", packet]):
            with redirect_stdout(StringIO()):
                with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
                    C.main()
        with C.dbtransaction(self.b) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM inbound").fetchone()[0], 0)
        self.assertEqual(C.pull(self.b, "outbound", 0, 1)[0]["seq"], 1)

    def test_end_marker_admission_is_serialized_against_late_rpc(self):
        # The final EOF check and ended marker must share the admission lock.
        # A concurrent RPC attempting delivery while the marker is being
        # written must not slip into the now-closed TLS session.
        from unittest.mock import patch
        import base64

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        marker_started = threading.Event()
        release_marker = threading.Event()
        result = []
        late = []
        original = C.write_exclusive_marker

        def delayed_marker(path, document):
            if Path(path).name == "ended.json":
                marker_started.set()
                if not release_marker.wait(timeout=4):
                    raise TimeoutError("test marker barrier")
            return original(path, document)

        def run_server():
            try:
                C.serve(self.b, "accept", port)
                result.append("finished")
            except Exception as error:
                result.append(str(error))

        def late_delivery():
            packet = json.dumps([{"seq": 1, "b64": base64.b64encode(
                b"late-tls-frame").decode("ascii")}])
            try:
                C.deliver(self.b, packet)
                late.append("accepted")
            except Exception as error:
                late.append(str(error))

        with patch.object(C, "write_exclusive_marker", side_effect=delayed_marker):
            server = threading.Thread(target=run_server)
            server.start()
            try:
                deadline = time.monotonic() + 3
                while not (Path(self.b) / "ready.json").exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    pass
                self.assertTrue(marker_started.wait(timeout=3))
                sender = threading.Thread(target=late_delivery)
                sender.start()
                time.sleep(.05)
                release_marker.set()
                sender.join(timeout=4)
                server.join(timeout=4)
                self.assertFalse(sender.is_alive())
                self.assertFalse(server.is_alive())
                self.assertEqual(result, ["finished"])
                self.assertEqual(len(late), 1)
                self.assertIn("carrier lifetime ended", late[0])
            finally:
                release_marker.set()
                server.join(timeout=4)

    def test_end_marker_admission_serializes_exchange_snapshot_and_commit(self):
        # The combined Oracle exchange must not commit inbound ciphertext or
        # return an outbound window after the native EOF finalizer seals life.
        # This is a separate concurrency path from deliver(), not just a
        # static already-ended marker check.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        import base64

        C.publish(self.a, "outbound", b"drain-after-end")
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        marker_started = threading.Event()
        release_marker = threading.Event()
        server_result = []
        exchange_result = []
        original_marker = C.write_exclusive_marker

        def held_end_marker(path, document):
            if Path(path).name == "ended.json":
                marker_started.set()
                if not release_marker.wait(timeout=4):
                    raise TimeoutError("test exchange marker barrier")
            return original_marker(path, document)

        def run_server():
            try:
                C.serve(self.a, "accept", port)
                server_result.append("finished")
            except Exception as error:
                server_result.append(str(error))

        def run_exchange():
            packet = json.dumps([{"seq": 1, "b64": base64.b64encode(
                b"late-exchange-tls").decode("ascii")}])
            output = StringIO()
            try:
                with patch.object(C.sys, "argv", [
                    "e07_oracle_stream.py", "exchange", "--state", self.a,
                    "--after", "0", "--packets", packet,
                ]), redirect_stdout(output):
                    C.main()
                exchange_result.append(("accepted", output.getvalue()))
            except Exception as error:
                exchange_result.append((str(error), output.getvalue()))

        with patch.object(C, "write_exclusive_marker", side_effect=held_end_marker):
            server = threading.Thread(target=run_server)
            server.start()
            try:
                deadline = time.monotonic() + 3
                while not (Path(self.a) / "ready.json").exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    pass
                self.assertTrue(marker_started.wait(timeout=3))
                exchange = threading.Thread(target=run_exchange)
                exchange.start()
                time.sleep(.08)
                release_marker.set()
                exchange.join(timeout=4)
                server.join(timeout=4)
                self.assertFalse(exchange.is_alive())
                self.assertFalse(server.is_alive())
                self.assertEqual(server_result, ["finished"])
                self.assertEqual(len(exchange_result), 1)
                self.assertIn("carrier lifetime ended", exchange_result[0][0])
                self.assertEqual(exchange_result[0][1], "")
            finally:
                release_marker.set()
                server.join(timeout=4)
        with C.dbtransaction(self.a) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM inbound").fetchone()[0], 0)
        self.assertEqual(C.pull(self.a, "outbound", 0, 1)[0]["seq"], 1)

    def test_spent_carrier_state_cannot_reopen_a_socket_and_replay_tls_bytes(self):
        # The same SQLite queue must never be attached to a second TLS session.
        C.deliver(self.b, '[{"seq":1,"b64":"dGxzLWZyYW1l"}]')
        (Path(self.b) / "ended.json").write_text('{"finished":true}')
        from unittest.mock import patch
        with patch.object(C.socket, "socket", side_effect=AssertionError("reopened spent carrier")):
            with self.assertRaisesRegex(ValueError, "newly prepared carrier state"):
                C.serve(self.b, "accept", 41321)

    def test_post_ready_failure_seals_under_inbound_admission_lock(self):
        # A late Oracle delivery must not race either post-ready failure
        # marker. Both socket setup and byte-pump launch consume the claim.
        from contextlib import contextmanager
        from unittest.mock import MagicMock, patch

        original_lock = C.carrier_admission_lock
        original_marker = C.write_exclusive_marker
        held = [0]

        @contextmanager
        def traced_lock(*args, **kwargs):
            with original_lock(*args, **kwargs):
                held[0] += 1
                try:
                    yield
                finally:
                    held[0] -= 1

        def require_locked_end(path, document):
            if Path(path).name == "ended.json":
                self.assertGreater(held[0], 0, "failed end marker outside admission lock")
            return original_marker(path, document)

        listener = MagicMock()
        client = MagicMock()
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        client.settimeout.side_effect = OSError("injected post-ready setup failure")
        with patch.object(C, "carrier_admission_lock", side_effect=traced_lock):
            with patch.object(C, "write_exclusive_marker", side_effect=require_locked_end):
                with patch.object(C.socket, "socket", return_value=listener):
                    with self.assertRaisesRegex(OSError, "post-ready setup failure"):
                        C.serve(self.a, "accept", 41321)
        ended = json.loads((Path(self.a) / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))

        listener = MagicMock()
        client = MagicMock()
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        thread = MagicMock()
        thread.start.side_effect = RuntimeError("injected post-ready thread failure")
        with patch.object(C, "carrier_admission_lock", side_effect=traced_lock):
            with patch.object(C, "write_exclusive_marker", side_effect=require_locked_end):
                with patch.object(C.socket, "socket", return_value=listener):
                    with patch.object(C.threading, "Thread", return_value=thread):
                        with self.assertRaisesRegex(RuntimeError, "post-ready thread failure"):
                            C.serve(self.b, "accept", 41321)
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))

    def test_carrier_thread_launch_failure_closes_sockets_and_seals_lifetime(self):
        # Ready is already durable; a failed byte-pump launch must not
        # advertise a live carrier or leave a native socket open.
        from unittest.mock import MagicMock, patch
        listener = MagicMock()
        client = MagicMock()
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        thread = MagicMock()
        thread.start.side_effect = RuntimeError("injected thread launch failure")
        with patch.object(C.socket, "socket", return_value=listener):
            with patch.object(C.threading, "Thread", return_value=thread):
                with self.assertRaisesRegex(RuntimeError, "injected thread launch failure"):
                    C.serve(self.b, "accept", 41321)
        client.close.assert_called_once_with()
        listener.close.assert_called_once_with()
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))

    def test_second_carrier_thread_launch_failure_stops_first_and_seals_lifetime(self):
        # The reader may already have started when the writer cannot launch.
        from unittest.mock import MagicMock, patch
        listener = MagicMock()
        client = MagicMock()
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        reader = MagicMock()
        writer = MagicMock()
        writer.start.side_effect = RuntimeError("injected writer launch failure")
        with patch.object(C.socket, "socket", return_value=listener):
            with patch.object(C.threading, "Thread", side_effect=[reader, writer]):
                with self.assertRaisesRegex(RuntimeError, "injected writer launch failure"):
                    C.serve(self.b, "accept", 41321)
        reader.start.assert_called_once_with()
        reader.join.assert_called_once_with(timeout=3)
        client.close.assert_called_once_with()
        listener.close.assert_called_once_with()
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))

    def test_accept_socket_creation_failure_seals_claimed_lifetime(self):
        # A failed socket constructor occurs after serve.claim but before
        # ready.json. It must still end the spent lifetime and reject late
        # Oracle ciphertext instead of leaving an ambiguous claimed state.
        from unittest.mock import patch

        with patch.object(C.socket, "socket",
                          side_effect=OSError("injected listener allocation failure")):
            with self.assertRaisesRegex(OSError, "injected listener allocation failure"):
                C.serve(self.b, "accept", 41321)
        root = Path(self.b)
        self.assertTrue((root / "serve.claim").exists())
        self.assertFalse((root / "ready.json").exists())
        ended = root / "ended.json"
        self.assertTrue(ended.exists(), "spent socket claim lacks failed end marker")
        status = json.loads(ended.read_text())
        self.assertEqual((status["finished"], status["failed"]), (False, True))
        with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
            C.deliver(self.b, '[{"seq":1,"b64":"dGxzLWZyYW1l"}]')

    def test_accept_bind_failure_closes_listener_and_seals_claimed_lifetime(self):
        # Binding can fail after the claim but before a ready marker exists.
        from unittest.mock import MagicMock, patch

        listener = MagicMock()
        listener.bind.side_effect = OSError("injected loopback bind failure")
        with patch.object(C.socket, "socket", return_value=listener):
            with self.assertRaisesRegex(OSError, "injected loopback bind failure"):
                C.serve(self.b, "accept", 41321)
        listener.close.assert_called_once_with()
        root = Path(self.b)
        self.assertTrue((root / "serve.claim").exists())
        self.assertFalse((root / "ready.json").exists())
        ended = json.loads((root / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))
        with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
            C.deliver(self.b, '[{"seq":1,"b64":"dGxzLWZyYW1l"}]')

    def test_unexpected_dial_attempt_failure_seals_claimed_lifetime(self):
        # Unexpected errors during the bounded dial retry loop occur AFTER
        # serve.claim. They must not leave a spent state open to late RPC bytes.
        from unittest.mock import patch

        for state, interrupted_sleep in ((self.a, False), (self.b, True)):
            with self.subTest(interrupted_sleep=interrupted_sleep):
                with patch.object(C.socket, "create_connection",
                                  side_effect=OSError("Control unavailable") if interrupted_sleep
                                  else RuntimeError("injected dial setup failure")):
                    if interrupted_sleep:
                        with patch.object(C.time, "sleep",
                                          side_effect=RuntimeError("injected dial retry failure")):
                            with self.assertRaisesRegex(RuntimeError, "injected dial retry failure"):
                                C.serve(state, "dial", 41321)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "injected dial setup failure"):
                            C.serve(state, "dial", 41321)
                root = Path(state)
                self.assertTrue((root / "serve.claim").exists())
                self.assertFalse((root / "ready.json").exists())
                self.assertTrue(C.admitted_lifecycle_marker(root / "ended.json"))
                self.assertEqual(json.loads((root / "ended.json").read_text()),
                                 {"pid": os.getpid(), "finished": False, "failed": True})
                with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
                    C.deliver(state, '[{"seq":1,"b64":"eA=="}]')

    def test_accept_bind_cleanup_failure_preserves_original_and_seals_lifetime(self):
        # A failed close must not mask the original post-claim bind error or
        # prevent the admission-locked failure marker from rejecting late bytes.
        from unittest.mock import MagicMock, patch
        listener = MagicMock()
        listener.bind.side_effect = OSError("injected bind failure")
        listener.close.side_effect = OSError("injected listener close failure")
        with patch.object(C.socket, "socket", return_value=listener):
            with self.assertRaisesRegex(OSError, "injected bind failure"):
                C.serve(self.b, "accept", 41321)
        listener.close.assert_called_once_with()
        root = Path(self.b)
        self.assertTrue((root / "serve.claim").exists())
        self.assertFalse((root / "ready.json").exists())
        self.assertEqual(json.loads((root / "ended.json").read_text()),
                         {"pid": os.getpid(), "finished": False, "failed": True})
        with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
            C.deliver(self.b, '[{"seq":1,"b64":"eA=="}]')

    def test_dial_ready_marker_cleanup_failure_preserves_original_and_seals_lifetime(self):
        # Closing a connected socket can itself fail; never let that skip
        # sealing the consumed lifetime after ready publication fails.
        from unittest.mock import MagicMock, patch
        client = MagicMock()
        client.close.side_effect = OSError("injected client close failure")
        original = C.write_exclusive_marker

        def fail_ready(path, document):
            if Path(path).name == "ready.json":
                raise OSError("injected ready marker failure")
            return original(path, document)

        with patch.object(C.socket, "create_connection", return_value=client):
            with patch.object(C, "write_exclusive_marker", side_effect=fail_ready):
                with self.assertRaisesRegex(OSError, "injected ready marker failure"):
                    C.serve(self.a, "dial", 41321)
        client.close.assert_called_once_with()
        root = Path(self.a)
        self.assertTrue((root / "serve.claim").exists())
        self.assertFalse((root / "ready.json").exists())
        self.assertEqual(json.loads((root / "ended.json").read_text()),
                         {"pid": os.getpid(), "finished": False, "failed": True})
        with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
            C.deliver(self.a, '[{"seq":1,"b64":"eA=="}]')

    def test_dial_ready_marker_failure_seals_spent_socket_lifetime(self):
        # A successful native dial followed by a failed ready-marker write
        # must not leave a claimed but apparently unended Oracle carrier.
        from unittest.mock import MagicMock, patch

        client = MagicMock()
        original_marker = C.write_exclusive_marker

        def fail_ready_only(path, document):
            if Path(path).name == "ready.json":
                raise OSError("injected dial ready marker failure")
            return original_marker(path, document)

        with patch.object(C.socket, "create_connection", return_value=client):
            with patch.object(C, "write_exclusive_marker",
                              side_effect=fail_ready_only):
                with self.assertRaisesRegex(OSError, "injected dial ready marker failure"):
                    C.serve(self.b, "dial", 41321)
        client.close.assert_called_once_with()
        root = Path(self.b)
        self.assertTrue((root / "serve.claim").exists())
        self.assertFalse((root / "ready.json").exists())
        ended = json.loads((root / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))
        with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
            C.deliver(self.b, '[{"seq":1,"b64":"dGxzLWZyYW1l"}]')

    def test_accept_closes_listener_when_ready_marker_creation_fails(self):
        from unittest.mock import MagicMock, patch
        listener = MagicMock()
        with patch.object(C.socket, "socket", return_value=listener):
            with patch.object(C, "write_exclusive_marker",
                              side_effect=OSError("ready marker refused")):
                with self.assertRaisesRegex(OSError, "ready marker refused"):
                    C.serve(self.b, "accept", 41321)
        listener.close.assert_called_once_with()
        self.assertFalse((Path(self.b) / "ready.json").exists())
        self.assertTrue((Path(self.b) / "serve.claim").exists())

    def test_accept_timeout_closes_listener_and_records_failed_lifetime(self):
        from unittest.mock import MagicMock, patch
        listener = MagicMock()
        listener.accept.side_effect = socket.timeout("control never connected")
        with patch.object(C.socket, "socket", return_value=listener):
            with self.assertRaisesRegex(socket.timeout, "control never connected"):
                C.serve(self.b, "accept", 41321)
        listener.close.assert_called_once_with()
        self.assertTrue((Path(self.b) / "ready.json").exists())
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))

    def test_post_ready_setup_cleanup_errors_do_not_skip_lifetime_seal(self):
        # Both close operations may fail after readiness; preserve the setup
        # error and serialize a failed end marker before accepting late bytes.
        from unittest.mock import MagicMock, patch
        listener = MagicMock()
        client = MagicMock()
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        client.settimeout.side_effect = OSError("original timeout setup failure")
        client.close.side_effect = OSError("client cleanup failed")
        listener.close.side_effect = OSError("listener cleanup failed")
        with patch.object(C.socket, "socket", return_value=listener):
            with self.assertRaisesRegex(OSError, "original timeout setup failure"):
                C.serve(self.a, "accept", 41321)
        client.close.assert_called_once_with()
        listener.close.assert_called_once_with()
        root = Path(self.a)
        self.assertEqual(json.loads((root / "ended.json").read_text()),
                         {"pid": os.getpid(), "finished": False, "failed": True})
        with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
            C.deliver(self.a, '[{"seq":1,"b64":"eA=="}]')

    def test_thread_launch_cleanup_errors_do_not_skip_lifetime_seal(self):
        # A failed byte-pump launch is the primary error, not socket close.
        from unittest.mock import MagicMock, patch
        listener = MagicMock()
        client = MagicMock()
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        client.close.side_effect = OSError("client cleanup failed")
        listener.close.side_effect = OSError("listener cleanup failed")
        thread = MagicMock()
        thread.start.side_effect = RuntimeError("original thread launch failure")
        with patch.object(C.socket, "socket", return_value=listener):
            with patch.object(C.threading, "Thread", return_value=thread):
                with self.assertRaisesRegex(RuntimeError, "original thread launch failure"):
                    C.serve(self.b, "accept", 41321)
        client.close.assert_called_once_with()
        listener.close.assert_called_once_with()
        root = Path(self.b)
        self.assertEqual(json.loads((root / "ended.json").read_text()),
                         {"pid": os.getpid(), "finished": False, "failed": True})
        with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
            C.deliver(self.b, '[{"seq":1,"b64":"eA=="}]')

    def test_accept_socket_timeout_setup_failure_closes_both_sockets_and_seals_failure(self):
        # Readiness was already published; a failed pump setup must not
        # leave a bound listener or advertise an unfinished live carrier.
        from unittest.mock import MagicMock, patch
        listener = MagicMock()
        client = MagicMock()
        client.settimeout.side_effect = OSError("test socket timeout setup failure")
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        with patch.object(C.socket, "socket", return_value=listener):
            with self.assertRaisesRegex(OSError, "test socket timeout setup failure"):
                C.serve(self.b, "accept", 41321)
        client.close.assert_called_once_with()
        listener.close.assert_called_once_with()
        self.assertTrue((Path(self.b) / "ready.json").exists())
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))

    def test_dial_socket_timeout_setup_failure_closes_client_and_seals_failure(self):
        from unittest.mock import MagicMock, patch
        client = MagicMock()
        client.settimeout.side_effect = OSError("test socket timeout setup failure")
        with patch.object(C.socket, "create_connection", return_value=client):
            with self.assertRaisesRegex(OSError, "test socket timeout setup failure"):
                C.serve(self.b, "dial", 41321)
        client.close.assert_called_once_with()
        self.assertTrue((Path(self.b) / "ready.json").exists())
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))

    def test_dial_does_not_advertise_ready_before_control_connects(self):
        # A dialer has no local Control socket until create_connection succeeds.
        # The exclusive claim remains fail-closed even when connection fails.
        from unittest.mock import patch
        marker = Path(self.b) / "ready.json"
        observed = []

        def unavailable_control(address, timeout=None):
            observed.append(marker.exists())
            raise RuntimeError("test dial unavailable")

        with patch.object(C.socket, "create_connection", side_effect=unavailable_control):
            with self.assertRaisesRegex(RuntimeError, "test dial unavailable"):
                C.serve(self.b, "dial", 41321)
        self.assertEqual(observed, [False])
        self.assertFalse(marker.exists())
        self.assertTrue((Path(self.b) / "serve.claim").exists())

    def test_dial_timeout_records_failed_lifetime_without_ready(self):
        # A claimed carrier that exhausted its local Control dial budget
        # must leave an explicit failed lifetime, never a ready event.
        from unittest.mock import patch
        marker = Path(self.b) / "ready.json"
        ended = Path(self.b) / "ended.json"
        attempts = [0]
        def unavailable(*args, **kwargs):
            attempts[0] += 1
            raise ConnectionRefusedError("no Control")
        with patch.object(C.time, "monotonic",
                          side_effect=lambda: 121 if attempts[0] else 0):
            with patch.object(C.time, "sleep", return_value=None):
                with patch.object(C.socket, "create_connection",
                                  side_effect=unavailable) as connect:
                    with self.assertRaisesRegex(RuntimeError, "local Control unavailable"):
                        C.serve(self.b, "dial", 41321)
        connect.assert_called_once_with(("127.0.0.1", 41321), timeout=3)
        self.assertFalse(marker.exists())
        self.assertTrue((Path(self.b) / "serve.claim").exists())
        self.assertEqual(
            (json.loads(ended.read_text())["finished"],
             json.loads(ended.read_text())["failed"]), (False, True))
        self.assertTrue(C.admitted_lifecycle_marker(ended))
        with self.assertRaisesRegex(ValueError, "carrier lifetime ended"):
            C.deliver(self.b, '[{"seq":1,"b64":"dGxzLWZyYW1l"}]')

    def test_dial_marks_ready_after_local_control_connects(self):
        from unittest.mock import patch
        marker = Path(self.b) / "ready.json"
        client, peer = socket.socketpair()
        peer.close()
        observed = []

        def connected_control(address, timeout=None):
            observed.append(marker.exists())
            return client

        with patch.object(C.socket, "create_connection", side_effect=connected_control):
            C.serve(self.b, "dial", 41321)
        self.assertEqual(observed, [False])
        self.assertTrue(marker.exists())
        self.assertTrue(json.loads((Path(self.b) / "ended.json").read_text())["finished"])

    def test_dial_closes_connected_socket_if_ready_marker_fails(self):
        from unittest.mock import patch
        client, peer = socket.socketpair()
        try:
            with patch.object(C.socket, "create_connection", return_value=client):
                with patch.object(C, "write_exclusive_marker",
                                  side_effect=OSError("test marker failure")):
                    with self.assertRaisesRegex(OSError, "test marker failure"):
                        C.serve(self.b, "dial", 41321)
            self.assertEqual(client.fileno(), -1)
            self.assertFalse((Path(self.b) / "ready.json").exists())
        finally:
            peer.close()

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

    def test_status_rejects_corrupt_durable_history_before_reporting_ready(self):
        # A ready marker and plausible row counts must not present a broken
        # TLS journal as usable transport state. Validate both directions.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        C.write_exclusive_marker(Path(self.b) / "ready.json",
                                 {"mode": "accept", "port": 41321,
                                  "pid": 1, "bound": "127.0.0.1"})
        damaged = (
            ("outbound", 1, "not-ciphertext"),
            ("inbound", 1, b""),
            ("outbound", 2, b"skipped-first"),
            ("inbound", 0, b"invalid-sequence"),
        )
        for table, seq, content in damaged:
            with self.subTest(table=table, seq=seq):
                with C.dbtransaction(self.b) as conn:
                    conn.execute("DELETE FROM outbound")
                    conn.execute("DELETE FROM inbound")
                    conn.execute(f"INSERT INTO {table}(seq,content) VALUES (?,?)",
                                 (seq, content))
                output = StringIO()
                with patch.object(C.sys, "argv", ["e07_oracle_stream.py",
                                                  "status", "--state", self.b]):
                    with redirect_stdout(output):
                        with self.assertRaisesRegex(
                                ValueError,
                                "invalid durable carrier frame|carrier journal sequence gap"):
                            C.main()
                self.assertEqual(output.getvalue(), "")
        with C.dbtransaction(self.b) as conn:
            conn.execute("DELETE FROM outbound")
            conn.execute("DELETE FROM inbound")
        C.publish(self.b, "outbound", b"valid")
        output = StringIO()
        with patch.object(C.sys, "argv", ["e07_oracle_stream.py",
                                          "status", "--state", self.b]):
            with redirect_stdout(output):
                C.main()
        self.assertTrue(json.loads(output.getvalue())["ready"])

    def test_lifecycle_markers_reject_malformed_content_before_reporting_ready(self):
        # A private inode alone does not establish a complete lifecycle event.
        # A crash can leave a newly created marker empty or partially written.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        bad = (b"", b'{"bound":', b"true",
               b'{"finished":true,"finished":false}',
               b'{"finished":NaN}', b'{"port":1e999}',
               b'{"nested":[{"duration":-1e999}]}',
               b'{"pad":"' + b"x" * 4096 + b'"}')
        for name in ("ready.json", "ended.json"):
            marker = Path(self.b) / name
            # Use the same private-owner/ACL creation path as the real pump.
            # A new Path.write_bytes file is 0644 on POSIX and may have the
            # wrong TokenUser owner on hosted Windows, failing custody first.
            C.write_exclusive_marker(marker, {"prepared": True})
            for payload in bad:
                with self.subTest(name=name, payload=payload[:40]):
                    marker.write_bytes(payload)
                    with self.assertRaisesRegex(ValueError, "invalid carrier lifecycle marker"):
                        C.admitted_lifecycle_marker(marker)
                    output = StringIO()
                    with patch.object(C.sys, "argv", ["e07_oracle_stream.py",
                                                      "status", "--state", self.b]):
                        with redirect_stdout(output):
                            with self.assertRaisesRegex(ValueError, "invalid carrier lifecycle marker"):
                                C.main()
                    self.assertEqual(output.getvalue(), "")
            marker.unlink()

    def test_status_rejects_conflicting_ready_and_ended_process_identity(self):
        # Both markers may be independently valid but cannot attest one
        # native socket lifetime when their creator PIDs disagree.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        root = Path(self.b)
        C.write_exclusive_marker(
            root / "ready.json",
            {"mode": "accept", "port": 41321, "pid": 111,
             "bound": "127.0.0.1"},
        )
        C.write_exclusive_marker(
            root / "ended.json",
            {"pid": 222, "finished": True, "failed": False},
        )
        output = StringIO()
        with patch.object(C.sys, "argv", [
            "e07_oracle_stream.py", "status", "--state", self.b
        ]):
            with redirect_stdout(output):
                with self.assertRaisesRegex(
                        ValueError, "carrier lifecycle process identity mismatch"):
                    C.main()
        self.assertEqual(output.getvalue(), "")

        # A matching lifetime remains observable, without weakening either
        # marker's existing private-inode and schema admission.
        (root / "ended.json").unlink()
        C.write_exclusive_marker(
            root / "ended.json",
            {"pid": 111, "finished": True, "failed": False},
        )
        with patch.object(C.sys, "argv", [
            "e07_oracle_stream.py", "status", "--state", self.b
        ]):
            with redirect_stdout(output):
                C.main()
        status = json.loads(output.getvalue())
        self.assertTrue(status["ready"])
        self.assertTrue(status["ended"])

    def test_status_rejects_success_without_ready_marker(self):
        # A failed socket attempt can seal before ready, but a successful
        # native TLS lifetime cannot end without having become ready.
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        root = Path(self.b)
        marker = root / "ended.json"
        C.write_exclusive_marker(
            marker, {"pid": 101, "finished": True, "failed": False},
        )
        output = StringIO()
        with patch.object(C.sys, "argv", [
            "e07_oracle_stream.py", "status", "--state", self.b
        ]):
            with redirect_stdout(output):
                with self.assertRaisesRegex(
                        ValueError, "successful carrier missing ready marker"):
                    C.main()
        self.assertEqual(output.getvalue(), "")

        # An attempt that failed before readiness legitimately has only an
        # ended marker; preserve its observable failed-lifetime evidence.
        marker.unlink()
        C.write_exclusive_marker(
            marker, {"pid": 101, "finished": False, "failed": True},
        )
        with patch.object(C.sys, "argv", [
            "e07_oracle_stream.py", "status", "--state", self.b
        ]):
            with redirect_stdout(output):
                C.main()
        status = json.loads(output.getvalue())
        self.assertFalse(status["ready"])
        self.assertTrue(status["ended"])

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
        C.write_exclusive_marker(Path(self.b) / "ready.json", {"mode": "accept", "port": 41321, "pid": 1, "bound": "127.0.0.1"})
        self.assertTrue(status()["ready"])
        self.assertFalse(status()["ended"])
        C.write_exclusive_marker(Path(self.b) / "ended.json", {"pid": 1, "finished": True, "failed": False})
        self.assertTrue(status()["ended"])

    def test_status_lifecycle_markers_share_durable_admission_transaction(self):
        # A status snapshot must not release the admission lock between
        # journal verification and lifecycle-marker readback. The finalizer
        # writes ended.json while holding that same lock.
        from contextlib import contextmanager, redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        original_transaction = C.dbtransaction
        original_marker = C.admitted_lifecycle_marker
        inside_transaction = [False]

        @contextmanager
        def tracked_transaction(state):
            with original_transaction(state) as conn:
                inside_transaction[0] = True
                try:
                    yield conn
                finally:
                    inside_transaction[0] = False

        def checked_marker(path, return_pid=False, return_document=False):
            self.assertTrue(inside_transaction[0],
                            "status marker read escaped durable admission lock")
            return original_marker(path, return_pid=return_pid,
                                   return_document=return_document)

        C.write_exclusive_marker(
            Path(self.b) / "ready.json",
            {"mode": "accept", "port": 41321, "pid": 1,
             "bound": "127.0.0.1"},
        )
        output = StringIO()
        with patch.object(C, "dbtransaction", tracked_transaction):
            with patch.object(C, "admitted_lifecycle_marker", checked_marker):
                with patch.object(C.sys, "argv", [
                        "e07_oracle_stream.py", "status", "--state", self.b]):
                    with redirect_stdout(output):
                        C.main()
        self.assertTrue(json.loads(output.getvalue())["ready"])
        self.assertFalse(json.loads(output.getvalue())["ended"])

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

    def test_finalize_commit_failure_cannot_publish_success_marker(self):
        # A durable transaction failure after the final history check must
        # never leave a successful ended marker for Oracle-side observers.
        from unittest.mock import MagicMock, patch

        listener = MagicMock()
        client = MagicMock()
        client.recv.return_value = b""
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        original_connect = C.dbconnect

        class FailedFinalizeCommit:
            def __init__(self, connection):
                self.connection = connection

            def __enter__(self):
                self.connection.__enter__()
                return self

            def __exit__(self, *args):
                self.connection.__exit__(*args)
                raise OSError("injected final SQLite commit failure")

            def execute(self, *args, **kwargs):
                return self.connection.execute(*args, **kwargs)

            def close(self):
                self.connection.close()

        def connect_with_final_commit_failure(state, create=False):
            connection = original_connect(state, create)
            if (Path(state) / "ready.json").exists() and (
                    threading.current_thread() is threading.main_thread()):
                return FailedFinalizeCommit(connection)
            return connection

        with patch.object(C.socket, "socket", return_value=listener):
            with patch.object(C, "dbconnect", side_effect=connect_with_final_commit_failure):
                with self.assertRaisesRegex(RuntimeError, "E07_CARRIER_PUMP_FAILED:finalize:OSError"):
                    C.serve(self.b, "accept", 41321)
        ended = json.loads((Path(self.b) / "ended.json").read_text())
        self.assertEqual((ended["finished"], ended["failed"]), (False, True))
        client.close.assert_called_once_with()
        listener.close.assert_called_once_with()


    def test_finalizer_lock_timeout_cannot_publish_unlocked_failed_marker(self):
        # Review regression: a held inbound admission lock must not permit
        # finalization to seal ended.json outside the serialization boundary.
        from contextlib import contextmanager
        from unittest.mock import MagicMock, patch

        listener = MagicMock()
        client = MagicMock()
        client.recv.return_value = b""
        listener.accept.return_value = (client, ("127.0.0.1", 41322))
        original_lock = C.carrier_admission_lock

        @contextmanager
        def finalizer_lock_busy(state):
            if (Path(state) / "ready.json").exists() and (
                    threading.current_thread() is threading.main_thread()):
                raise TimeoutError("injected admission lock busy")
            with original_lock(state):
                yield

        with patch.object(C.socket, "socket", return_value=listener):
            with patch.object(C, "carrier_admission_lock",
                              side_effect=finalizer_lock_busy):
                with self.assertRaisesRegex(
                        RuntimeError, "E07_CARRIER_PUMP_FAILED:finalize:TimeoutError"):
                    C.serve(self.b, "accept", 41321)
        self.assertTrue((Path(self.b) / "serve.claim").exists())
        self.assertTrue((Path(self.b) / "ready.json").exists())
        self.assertFalse((Path(self.b) / "ended.json").exists(),
                         "never seal an ended marker without admission lock")
        client.close.assert_called_once_with()
        listener.close.assert_called_once_with()

if __name__=="__main__": unittest.main()
