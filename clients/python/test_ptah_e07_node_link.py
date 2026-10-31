"""E07 Python Node-Link codec tests; no external network or host changes."""
import io
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ptah_e07_node_link as link


class MemorySocket:
    def __init__(self, data=b"", chunk=3):
        self.data=io.BytesIO(data)
        self.sent=bytearray()
        self.chunk=chunk
    def recv(self, n):
        return self.data.read(min(n,self.chunk))
    def sendall(self, buf):
        self.sent.extend(buf)


class NodeLinkProtocolTests(unittest.TestCase):
    def test_serde_tagged_e01_hello_is_length_delimited_json(self):
        wire=MemorySocket()
        msg={"kind":"hello","payload":{"node_id":"test-node","node_generation":1}}
        link._write_frame(wire,msg)
        raw=bytes(wire.sent)
        self.assertEqual(struct.unpack(">I",raw[:4])[0],len(raw)-4)
        self.assertEqual(json.loads(raw[4:].decode("utf-8")),msg)
        self.assertEqual(link._read_frame(MemorySocket(raw)),msg)

    def test_noncanonical_incoming_json_cannot_become_e01_hello_ack(self):
        # Ambiguous duplicate identities and non-finite JSON numbers must not
        # be normalized into a seemingly authenticated E01 acknowledgement.
        cases = (
            b'{"kind":"hello_ack","kind":"close","payload":{}}',
            b'{"kind":"hello_ack","payload":{"node_id":"trusted","node_id":"other"}}',
            b'{"kind":"hello_ack","payload":{"node_generation":NaN}}',
            b'{"kind":"hello_ack","payload":{"connection_epoch":Infinity}}',
            b'{"kind":"hello_ack","payload":{"connection_epoch":1e999}}',
        )
        for payload in cases:
            with self.subTest(payload=payload):
                wire = struct.pack(">I", len(payload)) + payload
                with self.assertRaisesRegex(link.LinkFailure, "invalid_incoming_frame"):
                    link._read_frame(MemorySocket(wire))

    def test_incoming_json_rejects_unpaired_surrogate_escapes(self):
        # Python accepts escaped lone UTF-16 surrogates; the Rust serde_json
        # E01 peer rejects them. The authenticated wire and local Hello must
        # share the same scalar-value custody.
        invalid = (
            b'{"kind":"hello_ack","payload":{"node_id":"\\ud800"}}',
            b'{"kind":"hello_ack","payload":{"\\udfff":"value"}}',
            b'{"kind":"hello_ack","payload":{"node_id":"x\\ud800y"}}',
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                frame = struct.pack(">I", len(payload)) + payload
                with self.assertRaisesRegex(link.LinkFailure, "invalid_incoming_frame"):
                    link._read_frame(MemorySocket(frame))
        # A valid escaped surrogate pair is one Unicode scalar and remains
        # admissible on the same strict wire decoder.
        valid = b'{"kind":"hello_ack","payload":{"node_id":"\\ud83d\\ude80"}}'
        frame = struct.pack(">I", len(valid)) + valid
        self.assertEqual(link._read_frame(MemorySocket(frame))["payload"]["node_id"],
                         "\U0001f680")

        # Local Hello preflight must reject the same invalid scalar before
        # join() can load TLS credentials or open a network connection.
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            hello_path = Path(directory) / "hello.json"
            hello_path.write_bytes(
                b'{"node_id":"\\ud800","node_generation":1,"connection_epoch":2}')
            with self.assertRaisesRegex(link.LinkFailure, "invalid_hello_frame"):
                link._load_hello_json(hello_path)
            hello_path.write_bytes(
                b'{"node_id":"\\ud83d\\ude80","node_generation":1,"connection_epoch":2}')
            self.assertEqual(link._load_hello_json(hello_path)["node_id"],
                             "\U0001f680")

    def test_excessive_incoming_json_nesting_is_a_protocol_failure(self):
        # A size-valid frame can still exceed E01's bounded nesting budget.
        # No native TLS socket or host state is involved in this regression.
        payload = b'{"kind":' + b'[' * 1200 + b'0' + b']' * 1200 + b'}'
        wire = struct.pack(">I", len(payload)) + payload
        with self.assertRaisesRegex(link.LinkFailure, "invalid_incoming_frame"):
            link._read_frame(MemorySocket(wire))

    def test_incoming_json_nesting_boundary(self):
        # The top-level E01 object consumes one of the 32 nesting levels.
        for arrays in (30, 31):
            with self.subTest(arrays=arrays):
                payload = b'{"kind":' + b'[' * arrays + b'0' + b']' * arrays + b'}'
                wire = struct.pack(">I", len(payload)) + payload
                self.assertIsInstance(link._read_frame(MemorySocket(wire)), dict)
        payload = b'{"kind":' + b'[' * 32 + b'0' + b']' * 32 + b'}'
        wire = struct.pack(">I", len(payload)) + payload
        with self.assertRaisesRegex(link.LinkFailure, "excessive JSON nesting"):
            link._read_frame(MemorySocket(wire))

    def test_quoted_brackets_do_not_consume_json_nesting_budget(self):
        msg = {"kind": "hello", "payload": {
            "node_id": 'quoted \" and ' + '[' * 150 + ']' * 150}}
        payload = json.dumps(msg).encode("utf-8")
        wire = struct.pack(">I", len(payload)) + payload
        self.assertEqual(link._read_frame(MemorySocket(wire)), msg)

    def test_zero_and_oversize_incoming_rejected_before_allocation(self):
        for count in (0,1_048_577,0xFFFFFFFF):
            with self.subTest(count=count):
                with self.assertRaisesRegex(link.LinkFailure,"invalid_incoming_frame_size"):
                    link._read_frame(MemorySocket(struct.pack(">I",count)))

    def test_partial_or_closed_frame_rejected(self):
        with self.assertRaisesRegex(link.LinkFailure,"connection_closed"):
            link._read_frame(MemorySocket(struct.pack(">I",8)+b"{}"))

    def test_non_dict_frame_rejected(self):
        payload=b'["hello"]'
        with self.assertRaisesRegex(link.LinkFailure,"invalid_incoming_frame"):
            link._read_frame(MemorySocket(struct.pack(">I",len(payload))+payload))

    def test_excessive_outgoing_json_nesting_is_bounded_before_wire_write(self):
        # The incoming E01 decoder has a 32-level limit. An otherwise
        # valid, size-bounded outgoing object must not escape as a raw
        # RecursionError or emit a partial frame.
        for depth in (33, 1200):
            with self.subTest(depth=depth):
                nested = 0
                for _ in range(depth):
                    nested = [nested]
                wire = MemorySocket()
                with self.assertRaisesRegex(link.LinkFailure, "invalid_outgoing_frame"):
                    link._write_frame(wire, {"kind": "hello", "payload": nested})
                self.assertEqual(wire.sent, bytearray())

    def test_outgoing_nesting_boundary_and_quoted_delimiters(self):
        nested = "quoted " + "[" * 100 + "]" * 100 + ' \" escaped'
        for _ in range(31):
            nested = [nested]
        wire = MemorySocket()
        link._write_frame(wire, {"kind": "hello", "payload": nested})
        raw = bytes(wire.sent)
        self.assertEqual(struct.unpack(">I", raw[:4])[0], len(raw) - 4)
        self.assertEqual(link._read_frame(MemorySocket(raw))["kind"], "hello")
        # One more list exceeds the shared 32-level E01 budget.
        wire = MemorySocket()
        with self.assertRaisesRegex(link.LinkFailure, "excessive JSON nesting"):
            link._write_frame(wire, {"kind": "hello", "payload": [nested]})
        self.assertEqual(wire.sent, bytearray())

    def test_oversized_outgoing_refused(self):
        with self.assertRaisesRegex(link.LinkFailure,"invalid_frame_size"):
            link._write_frame(MemorySocket(),{"payload":"x"*1_048_577})

    def test_outgoing_frame_rejects_nonfinite_json_before_wire_write(self):
        # Python json.dumps emits NaN/Infinity by default, but the E01
        # Rust/JSON peer cannot admit those tokens as canonical JSON.
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=repr(value)):
                wire = MemorySocket()
                with self.assertRaisesRegex(link.LinkFailure, "invalid_outgoing_frame"):
                    link._write_frame(wire, {"kind": "hello", "payload": {
                        "node_id": "test-node", "nested": [value]}})
                self.assertEqual(wire.sent, bytearray())

    def test_outgoing_frame_rejects_unpaired_unicode_surrogates_before_wire_write(self):
        # Python's ensure_ascii JSON encoder accepts lone UTF-16 surrogates,
        # but the E01 Rust serde_json peer rejects them as invalid strings.
        for value in ("\ud800", "\udfff", "prefix\ud800suffix"):
            with self.subTest(value=ascii(value)):
                wire = MemorySocket()
                with self.assertRaisesRegex(link.LinkFailure, "invalid_outgoing_frame"):
                    link._write_frame(wire, {"kind": "hello", "payload": {
                        "node_id": "test-node", "metadata": {"label": value}}})
                self.assertEqual(wire.sent, bytearray())
        # Valid supplementary Unicode must continue to round-trip.
        wire = MemorySocket()
        msg = {"kind": "hello", "payload": {"label": "\U0001f680"}}
        link._write_frame(wire, msg)
        self.assertEqual(link._read_frame(MemorySocket(bytes(wire.sent))), msg)

    def test_outgoing_frame_rejects_non_json_objects_before_wire_write(self):
        wire = MemorySocket()
        with self.assertRaisesRegex(link.LinkFailure, "invalid_outgoing_frame"):
            link._write_frame(wire, {"kind": "hello", "payload": {"bad": object()}})
        self.assertEqual(wire.sent, bytearray())

    def test_outgoing_frame_rejects_nonstring_object_keys_before_wire_write(self):
        # Python JSON silently coerces integer, boolean, null and float
        # object keys to strings; a native E01 peer must not receive an
        # identity that was never represented by a string source key.
        cases = (
            {7: "numeric"},
            {False: "boolean"},
            {None: "null"},
            {3.5: "float"},
            {"nested": [{"inner": {2: "numeric"}}]},
        )
        for payload in cases:
            with self.subTest(payload=repr(payload)):
                wire = MemorySocket()
                with self.assertRaisesRegex(link.LinkFailure, "invalid_outgoing_frame"):
                    link._write_frame(wire, {"kind": "hello", "payload": payload})
                self.assertEqual(wire.sent, bytearray())
        valid = {"kind": "hello", "payload": {"7": "text", "nested": [{"2": "text"}]}}
        wire = MemorySocket()
        link._write_frame(wire, valid)
        self.assertEqual(link._read_frame(MemorySocket(bytes(wire.sent))), valid)

    def test_no_second_workspace_user_approval_in_client(self):
        source=Path(link.__file__).read_text()
        self.assertNotIn("PTAH_OWNER_LOGIN",source)
        self.assertNotIn("PTAH_GRANTS",source)
        self.assertIn("ptah_second_user_login",source)


    def test_join_rejects_noncanonical_call_arguments_before_transport(self):
        from unittest.mock import patch
        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2}
        cases = (
            ("heartbeats", True, "heartbeats must"),
            ("heartbeats", 2.0, "heartbeats must"),
            ("heartbeats", "2", "heartbeats must"),
            ("timeout", True, "timeout must"),
            ("timeout", 0, "timeout must"),
            ("timeout", 301, "timeout must"),
            ("timeout", float("nan"), "timeout must"),
            ("timeout", float("inf"), "timeout must"),
            ("timeout", "7", "timeout must"),
            ("port", True, "port must"),
            ("port", 0, "port must"),
            ("port", 443.0, "port must"),
            ("port", 65536, "port must"),
        )
        for name, value, expected in cases:
            with self.subTest(name=name, value=repr(value)):
                kwargs = {"heartbeats": 2, "timeout": 7.0}
                port = 2345
                if name == "port":
                    port = value
                else:
                    kwargs[name] = value
                # Invalid caller arguments must fail before TLS context
                # setup, credential loading or any network interaction.
                with patch.object(link.ssl, "SSLContext",
                                  side_effect=AssertionError("TLS setup started")):
                    with self.assertRaisesRegex(ValueError, expected):
                        link.join("localhost", port, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node", **kwargs)

    def test_join_rejects_noncanonical_hello_counters_before_transport(self):
        from unittest.mock import patch
        good = {"node_id": "test-node", "node_generation": 1, "connection_epoch": 2}
        for field, bad in (("node_generation", True), ("connection_epoch", -1),
                           ("node_generation", 1 << 64), ("connection_epoch", "2")):
            with self.subTest(field=field, bad=bad):
                hello = dict(good, **{field: bad})
                with patch.object(link.socket, "create_connection",
                                  side_effect=AssertionError("untrusted Hello reached transport")):
                    with self.assertRaisesRegex(link.LinkFailure, "invalid_node_hello"):
                        link.join("localhost", 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello, expected_node_id="test-node")

    def test_join_rejects_missing_identity_fields_before_transport(self):
        from unittest.mock import patch
        for missing in ("node_generation", "connection_epoch"):
            with self.subTest(missing=missing):
                hello = {"node_id": "test-node", "node_generation": 1,
                         "connection_epoch": 2}
                hello.pop(missing)
                with patch.object(link.socket, "create_connection",
                                  side_effect=AssertionError("untrusted Hello reached transport")):
                    with self.assertRaisesRegex(link.LinkFailure, "invalid_node_hello"):
                        link.join("localhost", 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello, expected_node_id="test-node")

    def test_join_rejects_boolean_ack_counter_alias_before_heartbeat(self):
        from unittest.mock import patch
        from contextlib import nullcontext

        class FakeTLS(MemorySocket):
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def settimeout(self, value):
                pass
            def version(self):
                return "TLSv1.3"

        class FakeContext:
            def __init__(self, *args):
                pass
            def load_verify_locations(self, **kwargs):
                pass
            def load_cert_chain(self, **kwargs):
                pass
            def wrap_socket(self, sock, **kwargs):
                return sock

        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2}
        for field, bad in (("node_generation", True), ("connection_epoch", 2.0),
                           ("node_generation", 1.0)):
            with self.subTest(field=field, bad=bad):
                ack = {"kind": "hello_ack", "payload": {
                    "node_id": "test-node", "node_generation": 1,
                    "connection_epoch": 2, "selected_version": {"major": 1, "minor": 0}}}
                ack["payload"][field] = bad
                payload = json.dumps(ack).encode("utf-8")
                tls = FakeTLS(struct.pack(">I", len(payload)) + payload)
                with patch.object(link.ssl, "SSLContext", FakeContext), patch.object(
                    link.socket, "create_connection", return_value=nullcontext(tls)):
                    with self.assertRaisesRegex(link.LinkFailure, "mismatched_" + field):
                        link.join("localhost", 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello, expected_node_id="test-node")
                raw = bytes(tls.sent)
                self.assertEqual(len(raw), 4 + struct.unpack(">I", raw[:4])[0],
                                 "no heartbeat or Close may follow a malformed HelloAck")

        for invalid_version in ({"major": True, "minor": 0},
                                {"major": 1, "minor": 0.0}):
            with self.subTest(version=invalid_version):
                ack = {"kind": "hello_ack", "payload": {
                    "node_id": "test-node", "node_generation": 1,
                    "connection_epoch": 2, "selected_version": invalid_version}}
                payload = json.dumps(ack).encode("utf-8")
                tls = FakeTLS(struct.pack(">I", len(payload)) + payload)
                with patch.object(link.ssl, "SSLContext", FakeContext), patch.object(
                    link.socket, "create_connection", return_value=nullcontext(tls)):
                    with self.assertRaisesRegex(link.LinkFailure, "wrong_e01_version"):
                        link.join("localhost", 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello, expected_node_id="test-node")
                raw = bytes(tls.sent)
                self.assertEqual(len(raw), 4 + struct.unpack(">I", raw[:4])[0])

        valid = {"kind": "hello_ack", "payload": {
            "node_id": "test-node", "node_generation": 1,
            "connection_epoch": 2, "selected_version": {"major": 1, "minor": 0}}}
        payload = json.dumps(valid).encode("utf-8")
        tls = FakeTLS(struct.pack(">I", len(payload)) + payload)
        with patch.object(link.ssl, "SSLContext", FakeContext), patch.object(
            link.socket, "create_connection", return_value=nullcontext(tls)):
            result = link.join("localhost", 2345, Path("ca"), Path("cert"),
                               Path("key"), hello=hello, expected_node_id="test-node")
        self.assertEqual(result["heartbeats_sent"], 2)
        self.assertFalse(result["remote_execution_claimed"])
        kinds = []
        sent = memoryview(tls.sent)
        while sent:
            size = struct.unpack(">I", sent[:4])[0]
            kinds.append(json.loads(bytes(sent[4:4+size]))["kind"])
            sent = sent[4+size:]
        self.assertEqual(kinds, ["hello", "heartbeat", "heartbeat", "close"])


    def test_hello_file_preflight_rejects_ambiguous_unbounded_and_malformed_input(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            valid = b'{"node_id":"test-node","node_generation":1,"connection_epoch":2}'
            cases = (
                valid[:-1] + b',"node_id":"test-node"}',
                valid[:-1] + b',"ignored":NaN}',
                valid[:-1] + b',"ignored":1e999}',
                b'{"node_id":' + b'[' * 33 + b'0' + b']' * 33 + b'}',
                b'{"node_id":"test-node",',
                b'{"node_id":"\xff"}',
                valid + b" " * 1_048_577,
            )
            for data in cases:
                with self.subTest(data=data[:70]):
                    path.write_bytes(data)
                    with self.assertRaises(link.LinkFailure):
                        link._load_hello_json(path)
            path.write_bytes(valid)
            self.assertEqual(link._load_hello_json(path),
                             {"node_id": "test-node", "node_generation": 1,
                              "connection_epoch": 2})

    def test_cli_invalid_hello_returns_structured_failure_before_transport(self):
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            path.write_text('{"node_id":', encoding="utf-8")
            argv = ["ptah_e07_node_link", "--address", "localhost", "--port",
                    "1", "--ca", "ca", "--client-cert", "cert",
                    "--client-key", "key", "--hello-json", str(path)]
            output = io.StringIO()
            with patch("sys.argv", argv), patch.object(
                    link, "join", side_effect=AssertionError("transport invoked")):
                with redirect_stdout(output):
                    self.assertEqual(link.main(), 2)
            self.assertEqual(json.loads(output.getvalue())["result"],
                             "e07_connection_failed")


if __name__=="__main__":
    unittest.main()
