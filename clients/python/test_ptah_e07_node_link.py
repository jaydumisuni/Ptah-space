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

    def test_oversized_outgoing_refused(self):
        with self.assertRaisesRegex(link.LinkFailure,"invalid_frame_size"):
            link._write_frame(MemorySocket(),{"payload":"x"*1_048_577})

    def test_no_second_workspace_user_approval_in_client(self):
        source=Path(link.__file__).read_text()
        self.assertNotIn("PTAH_OWNER_LOGIN",source)
        self.assertNotIn("PTAH_GRANTS",source)
        self.assertIn("ptah_second_user_login",source)


if __name__=="__main__":
    unittest.main()
