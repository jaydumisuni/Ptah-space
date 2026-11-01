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

    def test_outgoing_frame_rejects_non_object_root_before_wire_write(self):
        # The E01 tagged frame is a JSON object, never a bare JSON
        # scalar or array. Incoming decoding already enforces this.
        for invalid in ([], ["hello"], "hello", None, False, 7):
            with self.subTest(invalid=repr(invalid)):
                wire = MemorySocket()
                with self.assertRaisesRegex(link.LinkFailure, "invalid_outgoing_frame"):
                    link._write_frame(wire, invalid)
                self.assertEqual(wire.sent, bytearray())
        # A valid object still round-trips without a network transport.
        valid = {"kind": "close"}
        wire = MemorySocket()
        link._write_frame(wire, valid)
        self.assertEqual(link._read_frame(MemorySocket(bytes(wire.sent))), valid)

    def test_no_second_workspace_user_approval_in_client(self):
        source=Path(link.__file__).read_text()
        self.assertNotIn("PTAH_OWNER_LOGIN",source)
        self.assertNotIn("PTAH_GRANTS",source)
        self.assertIn("ptah_second_user_login",source)


    def test_join_rejects_unicode_host_aliases_before_tls_setup(self):
        from unittest.mock import patch
        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2}
        invalid = ("ｌｏｃａｌｈｏｓｔ", "K.example", "e\u0301.example",
                   "host\u200dname", "host\u202ename")
        for address in invalid:
            with self.subTest(address=repr(address)):
                with patch.object(link.ssl, "SSLContext",
                                  side_effect=AssertionError("TLS setup started")):
                    with self.assertRaisesRegex(ValueError, "address must"):
                        link.join(address, 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")
        for address in ("localhost", "127.0.0.1", "::1", "café.example"):
            with self.subTest(valid_address=address):
                with patch.object(link.ssl, "SSLContext",
                                  side_effect=AssertionError("TLS setup started")):
                    with self.assertRaisesRegex(AssertionError, "TLS setup started"):
                        link.join(address, 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")

    def test_join_rejects_idna_ignored_unicode_host_aliases_before_tls(self):
        # Python's built-in IDNA codec erases these Unicode scalars. A
        # displayed host must not silently resolve to another host identity.
        from unittest.mock import patch
        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2}
        for address in ("host\u034f.example", "host\u180b.example",
                        "host\ufe0f.example", "host\ufe00.example"):
            with self.subTest(address=repr(address)):
                self.assertEqual(address.encode("idna"), b"host.example")
                with patch.object(
                        link.ssl, "SSLContext",
                        side_effect=AssertionError("TLS_SETUP_REACHED")):
                    with self.assertRaisesRegex(ValueError, "address must"):
                        link.join(address, 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")

    def test_join_rejects_idna_rewritten_host_identities_before_tls(self):
        # Python's IDNA2003 mapping can rewrite otherwise NFKC-stable
        # Unicode hostnames (including label separators) before TLS.
        from unittest.mock import patch
        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2}
        aliases = (
            ("fa\u00df.example", "fass.example"),
            ("host\u03c2.example", "host\u03c3.example"),
            ("host\u3002example", "host.example"),
        )
        for address, rewritten in aliases:
            with self.subTest(address=repr(address)):
                self.assertEqual(address.encode("idna"),
                                 rewritten.encode("idna"))
                with patch.object(
                        link.ssl, "SSLContext",
                        side_effect=AssertionError("TLS_SETUP_REACHED")):
                    with self.assertRaisesRegex(ValueError, "address must"):
                        link.join(address, 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")
        # Unicode's capital sharp S has changed IDNA mapping across
        # supported Python versions. Verify the actual codec's identity
        # mapping instead of asserting one version's encoded spelling.
        capital_sharp_s = "fa\u1e9e.example"
        rewritten = (capital_sharp_s.encode("idna").decode("idna")
                     != capital_sharp_s)
        with patch.object(
                link.ssl, "SSLContext",
                side_effect=AssertionError("TLS_SETUP_REACHED")):
            if rewritten:
                with self.assertRaisesRegex(ValueError, "address must"):
                    link.join(capital_sharp_s, 2345, Path("ca"),
                              Path("cert"), Path("key"), hello=hello,
                              expected_node_id="test-node")
            else:
                with self.assertRaisesRegex(AssertionError, "TLS_SETUP_REACHED"):
                    link.join(capital_sharp_s, 2345, Path("ca"),
                              Path("cert"), Path("key"), hello=hello,
                              expected_node_id="test-node")
        for address in ("caf\u00e9.example", "b\u00fccher.example",
                        "host\u03c3.example", "CLOUD.caf\u00e9.example",
                        "xn--caf-dma.example", "::1"):
            with self.subTest(valid_address=repr(address)):
                with patch.object(
                        link.ssl, "SSLContext",
                        side_effect=AssertionError("TLS_SETUP_REACHED")):
                    with self.assertRaisesRegex(AssertionError, "TLS_SETUP_REACHED"):
                        link.join(address, 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")

    def test_join_rejects_non_host_endpoint_syntax_before_tls(self):
        # The address parameter is a hostname/IP literal, not a URL,
        # userinfo authority, embedded port, or interface-scoped address.
        from unittest.mock import patch
        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2}
        invalid = (
            "https://host.example", "host.example/path",
            "user@host.example", "host.example:443",
            "host..example", ".host.example",
            "host.example?query", "[::1]", "fe80::1%eth0",
        )
        for address in invalid:
            with self.subTest(invalid_address=address):
                with patch.object(
                        link.ssl, "SSLContext",
                        side_effect=AssertionError("TLS_SETUP_REACHED")):
                    with self.assertRaisesRegex(ValueError, "address must"):
                        link.join(address, 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")
        for address in ("host.example.", "localhost", "::1",
                        "2001:db8::1", "café.example", "xn--caf-dma.example"):
            with self.subTest(valid_address=address):
                with patch.object(
                        link.ssl, "SSLContext",
                        side_effect=AssertionError("TLS_SETUP_REACHED")):
                    with self.assertRaisesRegex(AssertionError,
                                                "TLS_SETUP_REACHED"):
                        link.join(address, 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")

    def test_join_rejects_noncanonical_address_before_tls_setup(self):
        from unittest.mock import patch
        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2}
        for address in ("", None, 7, b"localhost", " localhost",
                        "localhost ", "bad\x00host", "\tlocalhost",
                        "localhost\n", "host\x7f"):
            with self.subTest(address=repr(address)):
                with patch.object(link.ssl, "SSLContext",
                                  side_effect=AssertionError("TLS setup started")):
                    with self.assertRaisesRegex(ValueError, "address must"):
                        link.join(address, 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")
        # Ordinary DNS, IPv4 and IPv6 targets remain admissible to TLS setup.
        for address in ("localhost", "127.0.0.1", "::1", "example.com"):
            with self.subTest(valid_address=address):
                with patch.object(link.ssl, "SSLContext",
                                  side_effect=AssertionError("TLS setup started")):
                    with self.assertRaisesRegex(AssertionError, "TLS setup started"):
                        link.join(address, 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")

    def test_join_binds_tls_verification_to_selected_endpoint(self):
        # A TLS certificate for localhost must not authenticate a different
        # selected network endpoint. Canonical NodeId is checked separately.
        from contextlib import nullcontext
        from unittest.mock import patch

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
            observed_names = []
            def __init__(self, *args):
                pass
            def load_verify_locations(self, **kwargs):
                pass
            def load_cert_chain(self, **kwargs):
                pass
            def wrap_socket(self, sock, *, server_hostname):
                self.observed_names.append(server_hostname)
                return sock

        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2}
        ack = {"kind": "hello_ack", "payload": {
            **hello, "selected_version": {"major": 1, "minor": 0}}}
        payload = json.dumps(ack).encode("utf-8")
        for endpoint in ("ptah-node.example", "192.0.2.25"):
            with self.subTest(endpoint=endpoint):
                FakeContext.observed_names.clear()
                tls = FakeTLS(struct.pack(">I", len(payload)) + payload)
                with patch.object(link.ssl, "SSLContext", FakeContext), patch.object(
                    link.socket, "create_connection", return_value=nullcontext(tls)):
                    result = link.join(endpoint, 2345, Path("ca"), Path("cert"),
                                       Path("key"), hello=hello,
                                       expected_node_id="test-node", heartbeats=1)
                self.assertEqual(FakeContext.observed_names, [endpoint])
                self.assertEqual(result["heartbeats_sent"], 1)

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

    def test_join_rejects_non_scalar_node_identity_before_tls_setup(self):
        # Rust's E01 NodeId is UTF-8. A direct Python join() caller must
        # not open TLS with a lone UTF-16 surrogate identity, even when
        # the caller-provided expected identity matches the Hello.
        from unittest.mock import patch
        for node_id in ("\ud800", "\udfff", "node-\ud800"):
            with self.subTest(node_id=ascii(node_id)):
                hello = {"node_id": node_id, "node_generation": 1,
                         "connection_epoch": 2}
                with patch.object(link.ssl, "SSLContext",
                                  side_effect=AssertionError("TLS setup started")):
                    with self.assertRaisesRegex(link.LinkFailure, "invalid_node_hello"):
                        link.join("localhost", 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id=node_id)

    def test_join_preflights_complete_hello_payload_before_tls(self):
        # Direct join() bypasses the Hello-file decoder. Malformed nested
        # metadata must never trigger credential loading or TLS setup.
        from unittest.mock import patch
        valid = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2}
        cyclic = []
        cyclic.append(cyclic)
        nested = 0
        for _ in range(33):
            nested = [nested]
        cases = (
            ("surrogate", {"label": "\ud800"}),
            ("nonfinite", {"confidence": float("nan")}),
            ("nonstring_key", {7: "alias"}),
            ("cyclic", cyclic),
            ("too_deep", nested),
        )
        for name, metadata in cases:
            with self.subTest(case=name):
                hello = dict(valid, metadata=metadata)
                with patch.object(link.ssl, "SSLContext",
                                  side_effect=AssertionError("TLS setup started")):
                    with self.assertRaises(link.LinkFailure):
                        link.join("localhost", 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")

    def test_join_sends_preflighted_hello_snapshot_after_credential_loading(self):
        # The caller's mutable Hello must not change between validation and
        # the first authenticated E01 write.
        from contextlib import nullcontext
        from unittest.mock import patch

        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2, "metadata": {"label": "original"}}
        ack = {"kind": "hello_ack", "payload": {
            "node_id": "test-node", "node_generation": 1,
            "connection_epoch": 2, "selected_version": {"major": 1, "minor": 0}}}
        data = json.dumps(ack).encode("utf-8")

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
                hello["metadata"]["label"] = "mutated-after-preflight"
                hello["node_generation"] = 99
                hello["connection_epoch"] = 99
            def wrap_socket(self, sock, **kwargs):
                return sock

        tls = FakeTLS(struct.pack(">I", len(data)) + data)
        with patch.object(link.ssl, "SSLContext", FakeContext), patch.object(
                link.socket, "create_connection", return_value=nullcontext(tls)):
            result = link.join("localhost", 2345, Path("ca"), Path("cert"),
                               Path("key"), hello=hello,
                               expected_node_id="test-node", heartbeats=1)
        first_length = struct.unpack(">I", tls.sent[:4])[0]
        first = json.loads(bytes(tls.sent[4:4 + first_length]))
        self.assertEqual(first["payload"]["metadata"]["label"], "original")
        self.assertEqual(first["payload"]["node_generation"], 1)
        self.assertEqual(first["payload"]["connection_epoch"], 2)
        self.assertEqual(hello["metadata"]["label"], "mutated-after-preflight")
        second_offset = 4 + first_length
        heartbeat_length = struct.unpack(">I", tls.sent[second_offset:second_offset + 4])[0]
        heartbeat = json.loads(bytes(tls.sent[second_offset + 4:
                                              second_offset + 4 + heartbeat_length]))
        self.assertEqual(heartbeat["payload"]["node_generation"], 1)
        self.assertEqual(heartbeat["payload"]["connection_epoch"], 2)
        self.assertEqual(result["heartbeats_sent"], 1)

    def test_join_rejects_identity_mutation_during_hello_freeze(self):
        # Interleaving a caller mutation between initial validation and
        # serialization must fail before TLS or credential loading.
        from unittest.mock import patch

        original_encode = link._encode_frame
        changes = (
            {"node_id": "other-node"},
            {"node_generation": 99},
            {"connection_epoch": 99},
        )
        for mutation in changes:
            with self.subTest(mutation=mutation):
                hello = {"node_id": "test-node", "node_generation": 1,
                         "connection_epoch": 2}

                def mutate_then_encode(frame):
                    hello.update(mutation)
                    return original_encode(frame)

                with patch.object(link, "_encode_frame",
                                  side_effect=mutate_then_encode), patch.object(
                        link.ssl, "SSLContext",
                        side_effect=AssertionError("TLS setup started")):
                    with self.assertRaisesRegex(link.LinkFailure, "invalid_node_hello"):
                        link.join("localhost", 2345, Path("ca"), Path("cert"),
                                  Path("key"), hello=hello,
                                  expected_node_id="test-node")

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


    def test_hello_ack_refuses_unbound_envelope_and_body_fields(self):
        # The Rust E01 HelloAck has exactly four fields. Unknown members
        # must not masquerade as additional authenticated control authority.
        hello_ack = {"kind": "hello_ack", "payload": {
            "node_id": "test-node", "node_generation": 1,
            "connection_epoch": 2,
            "selected_version": {"major": 1, "minor": 0}}}
        link._validate_hello_ack(hello_ack, "test-node", 1, 2)
        variants = (
            ("outer", {**hello_ack, "dispatch_authorized": True}),
            ("body", {**hello_ack, "payload": {
                **hello_ack["payload"], "lease_ref": "unbound"}}),
            ("missing", {**hello_ack, "payload": {
                key: value for key, value in hello_ack["payload"].items()
                if key != "selected_version"}}),
            ("scalar", {**hello_ack, "payload": "trusted"}),
        )
        for label, ack in variants:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                        link.LinkFailure, "missing_canonical_hello_ack"):
                    link._validate_hello_ack(ack, "test-node", 1, 2)

    def test_cli_rejects_noncanonical_native_node_id_before_transport(self):
        # Rust ptah-identifiers::NodeId is a lowercase canonical UUIDv7,
        # not an arbitrary nonempty UTF-8 string accepted by codec fixtures.
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        canonical = "018f0f4e-7b5c-7abc-8abc-0123456789ab"
        link._validate_canonical_native_node_id(canonical)
        invalid = (
            "test-node",
            canonical.upper(),
            "{" + canonical + "}",
            "018f0f4e-7b5c-4abc-8abc-0123456789ab",  # UUIDv4
            "018f0f4e-7b5c-7abc-0abc-0123456789ab",  # wrong variant
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            argv = ["ptah_e07_node_link", "--address", "localhost",
                    "--port", "1", "--ca", "ca", "--client-cert", "cert",
                    "--client-key", "key", "--hello-json", str(path)]
            for node_id in invalid:
                with self.subTest(node_id=node_id):
                    path.write_text(json.dumps({
                        "node_id": node_id, "node_generation": 1,
                        "connection_epoch": 2}), encoding="utf-8")
                    output = io.StringIO()
                    with patch("sys.argv", argv), patch.object(
                            link, "join",
                            side_effect=AssertionError("transport invoked")):
                        with redirect_stdout(output):
                            self.assertEqual(link.main(), 2)
                    result = json.loads(output.getvalue())
                    self.assertEqual(result["result"], "e07_connection_failed")
                    self.assertIn("noncanonical UUIDv7", result["detail"])


    def test_cli_rejects_unbound_native_hello_members_before_transport(self):
        # The native Rust NodeHello ignores unknown Serde fields. An input
        # file must not smuggle an apparent approval or dispatch decision.
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        canonical = "018f0f4e-7b5c-7abc-8abc-0123456789ab"
        base = {"node_id": canonical, "node_generation": 1,
                "connection_epoch": 2}
        argv_prefix = ["ptah_e07_node_link", "--address", "localhost",
                       "--port", "1", "--ca", "ca", "--client-cert", "cert",
                       "--client-key", "key", "--hello-json"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            for field, value in (
                ("dispatch_authorized", True),
                ("lease_ref", "fake-lease"),
                ("approval", {"granted": True}),
                ("unexpected", None),
            ):
                with self.subTest(field=field):
                    path.write_text(json.dumps({**base, field: value}),
                                    encoding="utf-8")
                    output = io.StringIO()
                    with patch("sys.argv", argv_prefix + [str(path)]), patch.object(
                            link, "join", side_effect=AssertionError(
                                "transport invoked before native Hello custody")):
                        with redirect_stdout(output):
                            self.assertEqual(link.main(), 2)
                    result = json.loads(output.getvalue())
                    self.assertEqual(result["result"], "e07_connection_failed")
                    self.assertIn("unbound native Hello field", result["detail"])

        # The eight non-Option Rust NodeHello members are required. Only
        # capability_snapshot_ref may be absent, matching Serde Option.
        complete = {
            **base, "supported_major": 1, "minimum_minor": 0,
            "maximum_minor": 0, "enrollment_ref": {"entity_id": "018f0f4e-7b5c-7abc-8abc-0123456789ab", "entity_kind": "ptah.enrollment"},
            "agent_revision": "revision", "capability_snapshot_ref": None,
        }
        link._validate_native_node_hello_fields(complete)
        link._validate_native_node_hello_fields({
            key: value for key, value in complete.items()
            if key != "capability_snapshot_ref"
        })
        with self.assertRaisesRegex(link.LinkFailure, "missing native Hello field"):
            link._validate_native_node_hello_fields(base)
        for required in sorted(link._NATIVE_NODE_HELLO_REQUIRED_FIELDS):
            with self.subTest(required=required):
                with self.assertRaisesRegex(
                        link.LinkFailure, "missing native Hello field"):
                    link._validate_native_node_hello_fields({
                        key: value for key, value in complete.items()
                        if key != required
                    })

    def test_cli_rejects_missing_rust_hello_fields_before_transport(self):
        # The native Rust Serde NodeHello requires eight members. Missing
        # protocol or enrollment fields must fail before TLS or join().
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        complete = {
            "node_id": "018f0f4e-7b5c-7abc-8abc-0123456789ab",
            "node_generation": 1, "connection_epoch": 2,
            "supported_major": 1, "minimum_minor": 0, "maximum_minor": 0,
            "enrollment_ref": {"entity_id": "018f0f4e-7b5c-7abc-8abc-0123456789ab", "entity_kind": "ptah.enrollment"}, "agent_revision": "revision",
        }
        argv_prefix = ["ptah_e07_node_link", "--address", "localhost",
                       "--port", "1", "--ca", "ca", "--client-cert", "cert",
                       "--client-key", "key", "--hello-json"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            for required in ("supported_major", "minimum_minor",
                             "maximum_minor", "enrollment_ref",
                             "agent_revision"):
                with self.subTest(required=required):
                    path.write_text(json.dumps({
                        key: value for key, value in complete.items()
                        if key != required
                    }), encoding="utf-8")
                    output = io.StringIO()
                    with patch("sys.argv", argv_prefix + [str(path)]), patch.object(
                            link, "join", side_effect=AssertionError(
                                "transport invoked before required Hello custody")):
                        with redirect_stdout(output):
                            self.assertEqual(link.main(), 2)
                    result = json.loads(output.getvalue())
                    self.assertEqual(result["result"], "e07_connection_failed")
                    self.assertIn("missing native Hello field", result["detail"])


    def test_cli_rejects_non_u16_native_protocol_fields_before_transport(self):
        # Rust NodeHello uses u16 for all three version members. Python
        # booleans, numeric strings, floats and out-of-range ints are not
        # wire-equivalent even when they compare equal to ordinary integers.
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        complete = {
            "node_id": "018f0f4e-7b5c-7abc-8abc-0123456789ab",
            "node_generation": 1, "connection_epoch": 2,
            "supported_major": 1, "minimum_minor": 0, "maximum_minor": 0,
            "enrollment_ref": {"entity_id": "018f0f4e-7b5c-7abc-8abc-0123456789ab", "entity_kind": "ptah.enrollment"}, "agent_revision": "revision",
        }
        argv_prefix = ["ptah_e07_node_link", "--address", "localhost",
                       "--port", "1", "--ca", "ca", "--client-cert", "cert",
                       "--client-key", "key", "--hello-json"]
        invalid = (True, False, -1, 65536, 1.0, "1", None)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            for field in ("supported_major", "minimum_minor", "maximum_minor"):
                for value in invalid:
                    with self.subTest(field=field, value=repr(value)):
                        path.write_text(json.dumps({**complete, field: value}),
                                        encoding="utf-8")
                        output = io.StringIO()
                        with patch("sys.argv", argv_prefix + [str(path)]), patch.object(
                                link, "join", side_effect=AssertionError(
                                    "transport invoked before native u16 custody")):
                            with redirect_stdout(output):
                                self.assertEqual(link.main(), 2)
                        result = json.loads(output.getvalue())
                        self.assertEqual(result["result"], "e07_connection_failed")
                        self.assertIn("noncanonical native protocol u16",
                                      result["detail"])

        # Native u16 extrema remain admissible when the advertised minor
        # interval is ordered. Remote compatibility is a separate gate.
        for field in ("supported_major", "minimum_minor", "maximum_minor"):
            for value in (0, 65535):
                with self.subTest(valid_field=field, valid_value=value):
                    candidate = {**complete, field: value}
                    if field == "minimum_minor":
                        candidate["maximum_minor"] = value
                    link._validate_native_node_hello_fields(candidate)


    def test_cli_rejects_reversed_native_minor_interval_before_transport(self):
        # Rust's u16 fields can deserialize individually while describing
        # an empty protocol interval. Fail before credentials or TLS; do not
        # invent a policy about remote minor-version compatibility.
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        canonical = "018f0f4e-7b5c-7abc-8abc-0123456789ab"
        complete = {
            "node_id": canonical, "node_generation": 1,
            "connection_epoch": 2, "supported_major": 1,
            "minimum_minor": 0, "maximum_minor": 0,
            "enrollment_ref": {
                "entity_id": canonical, "entity_kind": "ptah.enrollment",
            },
            "agent_revision": "revision",
        }
        argv_prefix = [
            "ptah_e07_node_link", "--address", "localhost",
            "--port", "1", "--ca", "ca", "--client-cert", "cert",
            "--client-key", "key", "--hello-json",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            for minimum, maximum in ((1, 0), (5, 4), (65535, 65534)):
                with self.subTest(minimum=minimum, maximum=maximum):
                    hello = {
                        **complete, "minimum_minor": minimum,
                        "maximum_minor": maximum,
                    }
                    with self.assertRaisesRegex(
                            link.LinkFailure, "impossible native minor version interval"):
                        link._validate_native_node_hello_fields(hello)
                    path.write_text(json.dumps(hello), encoding="utf-8")
                    output = io.StringIO()
                    with patch("sys.argv", argv_prefix + [str(path)]), patch.object(
                            link, "join", side_effect=AssertionError(
                                "reversed native interval reached transport")):
                        with redirect_stdout(output):
                            self.assertEqual(link.main(), 2)
                    result = json.loads(output.getvalue())
                    self.assertEqual(result["result"], "e07_connection_failed")
                    self.assertIn("impossible native minor version interval",
                                  result["detail"])

        for minimum, maximum in ((0, 0), (0, 65535), (65535, 65535)):
            with self.subTest(valid_minimum=minimum, valid_maximum=maximum):
                link._validate_native_node_hello_fields({
                    **complete, "minimum_minor": minimum,
                    "maximum_minor": maximum,
                })


    def test_cli_rejects_non_string_native_agent_revision_before_transport(self):
        # Rust NodeHello.agent_revision is a Serde String. Python JSON
        # booleans, numbers, arrays, objects and null must fail before TLS.
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        complete = {
            "node_id": "018f0f4e-7b5c-7abc-8abc-0123456789ab",
            "node_generation": 1, "connection_epoch": 2,
            "supported_major": 1, "minimum_minor": 0, "maximum_minor": 0,
            "enrollment_ref": {"entity_id": "018f0f4e-7b5c-7abc-8abc-0123456789ab", "entity_kind": "ptah.enrollment"}, "agent_revision": "revision",
        }
        invalid = (None, True, False, 0, 1, 1.0, [], ["rev"], {},
                   {"version": "rev"})
        argv_prefix = ["ptah_e07_node_link", "--address", "localhost",
                       "--port", "1", "--ca", "ca", "--client-cert", "cert",
                       "--client-key", "key", "--hello-json"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            for value in invalid:
                with self.subTest(value=repr(value)):
                    # Direct helper and CLI must agree on the native type.
                    with self.assertRaisesRegex(
                            link.LinkFailure, "noncanonical native agent revision"):
                        link._validate_native_node_hello_fields({
                            **complete, "agent_revision": value
                        })
                    path.write_text(json.dumps({
                        **complete, "agent_revision": value
                    }), encoding="utf-8")
                    output = io.StringIO()
                    with patch("sys.argv", argv_prefix + [str(path)]), patch.object(
                            link, "join", side_effect=AssertionError(
                                "transport invoked before native String custody")):
                        with redirect_stdout(output):
                            self.assertEqual(link.main(), 2)
                    result = json.loads(output.getvalue())
                    self.assertEqual(result["result"], "e07_connection_failed")
                    self.assertIn("noncanonical native agent revision",
                                  result["detail"])

        # Serde String admits empty and ordinary UTF-8 text; do not invent
        # a new revision-enrollment or semantic version policy.
        for revision in ("", "revision-1"):
            with self.subTest(valid_revision=revision):
                link._validate_native_node_hello_fields({
                    **complete, "agent_revision": revision
                })


    def test_native_entity_kind_first_segment_matches_rust_grammar(self):
        # ptah-identifiers::valid_kind_segment(first, false) allows ASCII
        # digits after the initial lowercase letter. Python must not reject
        # a Rust-valid reference before credentials or TLS.
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        canonical = "018f0f4e-7b5c-7abc-8abc-0123456789ab"
        reference = {"entity_id": canonical, "entity_kind": "ptah.enrollment"}
        complete = {
            "node_id": canonical, "node_generation": 1, "connection_epoch": 2,
            "supported_major": 1, "minimum_minor": 0, "maximum_minor": 0,
            "enrollment_ref": reference, "agent_revision": "revision",
        }
        valid = ("core2.node", "a1.b2", "core9.node9_part-2",
                 "core.node", "ptah.enrollment")
        invalid = ("2core.node", "core-.node", "core.2node",
                   "core..node", "Core2.node", "core.node?", "core.node.")
        for field in ("enrollment_ref", "capability_snapshot_ref"):
            for kind in valid:
                with self.subTest(field=field, valid_kind=kind):
                    link._validate_native_node_hello_fields({
                        **complete, field: {**reference, "entity_kind": kind}
                    })
            for kind in invalid:
                with self.subTest(field=field, invalid_kind=kind):
                    with self.assertRaisesRegex(
                            link.LinkFailure, "noncanonical native EntityRef"):
                        link._validate_native_node_hello_fields({
                            **complete, field: {**reference, "entity_kind": kind}
                        })

        # The real CLI preflight must accept a Rust-valid digit-bearing
        # namespace without opening a socket or loading credentials here.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            path.write_text(json.dumps({
                **complete, "enrollment_ref": {
                    **reference, "entity_kind": "core2.node"
                }
            }), encoding="utf-8")
            argv = ["ptah_e07_node_link", "--address", "localhost",
                    "--port", "1", "--ca", "ca", "--client-cert", "cert",
                    "--client-key", "key", "--hello-json", str(path)]
            output = io.StringIO()
            with patch("sys.argv", argv), patch.object(
                    link, "join", return_value={"result": "preflight_only"}) as joined:
                with redirect_stdout(output):
                    self.assertEqual(link.main(), 0)
            joined.assert_called_once()
            self.assertEqual(json.loads(output.getvalue())["result"],
                             "preflight_only")


    def test_cli_rejects_noncanonical_native_entity_refs_before_transport(self):
        # Rust ptah-identifiers::EntityRef is a structured object with a
        # canonical UUIDv7, validated namespaced kind and bounded counters.
        # Both mandatory enrollment and optional snapshot references must
        # be preflighted before credentials or network transport.
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        canonical = "018f0f4e-7b5c-7abc-8abc-0123456789ab"
        reference = {"entity_id": canonical, "entity_kind": "ptah.enrollment"}
        complete = {
            "node_id": canonical, "node_generation": 1, "connection_epoch": 2,
            "supported_major": 1, "minimum_minor": 0, "maximum_minor": 0,
            "enrollment_ref": reference, "agent_revision": "revision",
        }
        invalid = (
            None, "reference", True, [], {},
            {"entity_id": canonical},
            {"entity_kind": "ptah.enrollment"},
            {"entity_id": "018f0f4e-7b5c-4abc-8abc-0123456789ab",
             "entity_kind": "ptah.enrollment"},
            {**reference, "entity_kind": "ptah..enrollment"},
            {**reference, "record_revision": 0},
            {**reference, "node_generation": True},
            {**reference, "connection_epoch": -1},
            {**reference, "dispatch_authorized": True},
        )
        argv_prefix = ["ptah_e07_node_link", "--address", "localhost",
                       "--port", "1", "--ca", "ca", "--client-cert", "cert",
                       "--client-key", "key", "--hello-json"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hello.json"
            for field in ("enrollment_ref", "capability_snapshot_ref"):
                for value in invalid:
                    if field == "capability_snapshot_ref" and value is None:
                        continue  # Optional Rust EntityRef accepts null.
                    with self.subTest(field=field, value=repr(value)):
                        hello = {**complete, field: value}
                        with self.assertRaisesRegex(
                                link.LinkFailure, "noncanonical native EntityRef"):
                            link._validate_native_node_hello_fields(hello)
                        path.write_text(json.dumps(hello), encoding="utf-8")
                        output = io.StringIO()
                        with patch("sys.argv", argv_prefix + [str(path)]), patch.object(
                                link, "join", side_effect=AssertionError(
                                    "invalid EntityRef reached transport")):
                            with redirect_stdout(output):
                                self.assertEqual(link.main(), 2)
                        result = json.loads(output.getvalue())
                        self.assertEqual(result["result"], "e07_connection_failed")
                        self.assertIn("noncanonical native EntityRef", result["detail"])

        # Serde Option fields accept absent/null; a complete reference with
        # a positive revision and zero-valued generation is also valid.
        for snapshot in (None, reference, {
                **reference, "record_revision": 1, "node_generation": 0}):
            with self.subTest(valid_snapshot=snapshot):
                link._validate_native_node_hello_fields({
                    **complete, "capability_snapshot_ref": snapshot
                })
        link._validate_native_node_hello_fields(complete)



    def test_ack_selected_version_must_belong_to_advertised_hello_range(self):
        # A fixed E01 1.0 ACK is not authorized by an offered 1.1..1.2
        # interval, even when its NodeId/Generation/Epoch are correct.
        ack = {"kind": "hello_ack", "payload": {
            "selected_version": {"major": 1, "minor": 0},
            "node_id": "test-node", "node_generation": 1,
            "connection_epoch": 2}}
        invalid_offers = (
            {"supported_major": 1, "minimum_minor": 1, "maximum_minor": 2},
            {"supported_major": 2, "minimum_minor": 0, "maximum_minor": 0},
            {"supported_major": True, "minimum_minor": 0, "maximum_minor": 0},
            {"supported_major": 1, "minimum_minor": "0", "maximum_minor": 0},
        )
        for offered in invalid_offers:
            with self.subTest(offered=offered):
                with self.assertRaisesRegex(
                        link.LinkFailure, "hello_ack_version_not_advertised"):
                    link._validate_hello_ack(
                        ack, "test-node", 1, 2, offered_hello=offered)
        for offered in (
                {"supported_major": 1, "minimum_minor": 0, "maximum_minor": 0},
                {"supported_major": 1, "minimum_minor": 0, "maximum_minor": 2}):
            with self.subTest(valid_offer=offered):
                link._validate_hello_ack(
                    ack, "test-node", 1, 2, offered_hello=offered)
        # Older direct codec callers did not advertise a version range.
        link._validate_hello_ack(ack, "test-node", 1, 2)



    def test_join_rejects_unoffered_ack_before_heartbeat_or_close(self):
        # Exercise the real join() call site: checking only the helper would
        # not catch accidentally omitting the frozen Hello offer argument.
        from contextlib import nullcontext
        from unittest.mock import patch

        class FakeTLS(MemorySocket):
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def settimeout(self, _value):
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
            def wrap_socket(self, sock, *, server_hostname):
                return sock

        ack = {"kind": "hello_ack", "payload": {
            "selected_version": {"major": 1, "minor": 0},
            "node_id": "test-node", "node_generation": 1,
            "connection_epoch": 2}}
        payload = json.dumps(ack).encode("utf-8")
        hello = {"node_id": "test-node", "node_generation": 1,
                 "connection_epoch": 2, "supported_major": 1,
                 "minimum_minor": 1, "maximum_minor": 2}
        tls = FakeTLS(struct.pack(">I", len(payload)) + payload)
        with patch.object(link.ssl, "SSLContext", FakeContext), patch.object(
                link.socket, "create_connection", return_value=nullcontext(tls)):
            with self.assertRaisesRegex(
                    link.LinkFailure, "hello_ack_version_not_advertised"):
                link.join("localhost", 1234, Path("ca"), Path("cert"),
                          Path("key"), hello=hello,
                          expected_node_id="test-node", heartbeats=1)
        sent = bytes(tls.sent)
        first_frame_size = struct.unpack(">I", sent[:4])[0]
        self.assertEqual(len(sent), first_frame_size + 4)
        self.assertEqual(json.loads(sent[4:])["kind"], "hello")



    def test_partial_native_version_offer_fails_before_tls_and_ack(self):
        # Legacy direct codec callers may omit the entire version triple,
        # but a partial native offer cannot silently bypass ACK membership.
        from unittest.mock import patch
        ack = {"kind": "hello_ack", "payload": {
            "selected_version": {"major": 1, "minor": 0},
            "node_id": "test-node", "node_generation": 1,
            "connection_epoch": 2}}
        for offered in (
            {"supported_major": 1},
            {"minimum_minor": 0, "maximum_minor": 0},
            {"supported_major": 1, "minimum_minor": 0},
            {"supported_major": 1, "maximum_minor": 0},
        ):
            with self.subTest(offered=offered):
                with self.assertRaisesRegex(
                        link.LinkFailure, "hello_ack_version_not_advertised"):
                    link._validate_hello_ack(
                        ack, "test-node", 1, 2, offered_hello=offered)
                hello = {"node_id": "test-node", "node_generation": 1,
                         "connection_epoch": 2, **offered}
                with patch.object(
                        link.ssl, "SSLContext",
                        side_effect=AssertionError("TLS setup reached")):
                    with self.assertRaisesRegex(
                            link.LinkFailure, "missing native Hello field"):
                        link.join(
                            "localhost", 1234, Path("ca"), Path("cert"),
                            Path("key"), hello=hello,
                            expected_node_id="test-node", heartbeats=1)
        # Full absence is the documented direct-codec compatibility path.
        link._validate_hello_ack(ack, "test-node", 1, 2, offered_hello={})


    def test_join_complete_native_offer_is_validated_before_tls(self):
        # Direct join() must enforce the same native u16 and interval
        # preflight as the CLI, not defer malformed offers until ACK.
        from unittest.mock import patch
        base = {"node_id": "test-node", "node_generation": 1,
                "connection_epoch": 2}
        offers = (
            {"supported_major": True, "minimum_minor": 0, "maximum_minor": 0},
            {"supported_major": -1, "minimum_minor": 0, "maximum_minor": 0},
            {"supported_major": 65536, "minimum_minor": 0, "maximum_minor": 0},
            {"supported_major": 1, "minimum_minor": "0", "maximum_minor": 0},
            {"supported_major": 1, "minimum_minor": 0.0, "maximum_minor": 0},
            {"supported_major": 1, "minimum_minor": 0, "maximum_minor": 65536},
            {"supported_major": 1, "minimum_minor": 2, "maximum_minor": 1},
            {"supported_major": 1, "minimum_minor": 65535, "maximum_minor": 0},
        )
        for offer in offers:
            with self.subTest(offer=offer):
                with patch.object(
                        link.ssl, "SSLContext",
                        side_effect=AssertionError("TLS_SETUP_REACHED")):
                    with self.assertRaisesRegex(
                            link.LinkFailure,
                            "noncanonical native protocol u16|impossible native minor version interval"):
                        link.join("localhost", 1234, Path("ca"), Path("cert"),
                                  Path("key"), hello={**base, **offer},
                                  expected_node_id="test-node")

    def test_direct_join_native_offer_positive_preflight(self):
        base = {"node_id": "test-node", "node_generation": 1,
                "connection_epoch": 2}
        # Compatibility negotiation is still decided by the peer.
        for offer in (
            {},
            {"supported_major": 1, "minimum_minor": 0, "maximum_minor": 0},
            {"supported_major": 2, "minimum_minor": 1, "maximum_minor": 2},
            {"supported_major": 65535, "minimum_minor": 0, "maximum_minor": 65535},
        ):
            with self.subTest(offer=offer):
                link._validate_node_hello({**base, **offer}, "test-node")


if __name__=="__main__":
    unittest.main()
