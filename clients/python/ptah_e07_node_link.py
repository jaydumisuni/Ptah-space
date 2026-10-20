"""Ptah E07 native Control E01 protocol bridge for existing upstream-admitted callers.

No extra Ptah user login/approval, no dispatch, no installation. mTLS is
the optional protocol transport's peer integrity (not workspace admission).
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import struct
from pathlib import Path


class LinkFailure(RuntimeError):
    pass


def _receive_exact(connection: ssl.SSLSocket, count: int) -> bytes:
    output = bytearray()
    while len(output) < count:
        block = connection.recv(count - len(output))
        if not block:
            raise LinkFailure("connection_closed_before_full_frame")
        output.extend(block)
    return bytes(output)


def _write_frame(connection: ssl.SSLSocket, message: dict) -> None:
    data = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if not data or len(data) > 1_048_576:
        raise LinkFailure("invalid_frame_size")
    connection.sendall(struct.pack(">I", len(data)) + data)


def _read_frame(connection: ssl.SSLSocket) -> dict:
    size = struct.unpack(">I", _receive_exact(connection, 4))[0]
    if not 0 < size <= 1_048_576:
        raise LinkFailure("invalid_incoming_frame_size")
    obj = json.loads(_receive_exact(connection, size).decode("utf-8"))
    if not isinstance(obj, dict):
        raise LinkFailure("invalid_incoming_frame")
    return obj


def join(
    address: str,
    port: int,
    ca: Path,
    client_cert: Path,
    client_key: Path,
    *,
    hello: dict,
    expected_node_id: str,
    heartbeats: int = 2,
    timeout: float = 7.0,
) -> dict:
    """Prove TLS 1.3, canonical HelloAck, heartbeat and Close on one E01 link.

    Records wire evidence, does not make caller permission decisions or
    claim E02 remote dispatch.
    """
    if not 1 <= heartbeats <= 10:
        raise ValueError("heartbeats must be 1..10")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=str(ca))
    ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    with socket.create_connection((address, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
            tls.settimeout(timeout)
            if tls.version() != "TLSv1.3":
                raise LinkFailure("tls13_required")
            _write_frame(tls, {"kind": "hello", "payload": hello})
            ack = _read_frame(tls)
            body = ack.get("payload")
            if ack.get("kind") != "hello_ack" or not isinstance(body, dict):
                raise LinkFailure("missing_canonical_hello_ack")
            if body.get("node_id") != expected_node_id:
                raise LinkFailure("wrong_node_ack")
            for field in ("node_generation", "connection_epoch"):
                if body.get(field) != hello.get(field):
                    raise LinkFailure("mismatched_" + field)
            if body.get("selected_version") != {"major": 1, "minor": 0}:
                raise LinkFailure("wrong_e01_version")
            for sequence in range(1, heartbeats + 1):
                _write_frame(tls, {"kind": "heartbeat", "payload": {
                    "node_id": expected_node_id,
                    "node_generation": hello["node_generation"],
                    "connection_epoch": hello["connection_epoch"],
                    "sequence": sequence,
                }})
            _write_frame(tls, {"kind": "close"})
            return {
                "result": "e07_physical_e01_authenticated_hello_heartbeat_close",
                "transport": "tls1.3_mutual_certificate",
                "node_id": expected_node_id,
                "heartbeats_sent": heartbeats,
                "remote_execution_claimed": False,
                "ptah_second_user_login": False,
                "system_configuration_changed": False,
            }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded Ptah E07 mTLS Node-link client")
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--client-cert", type=Path, required=True)
    parser.add_argument("--client-key", type=Path, required=True)
    parser.add_argument("--hello-json", type=Path, required=True)
    parser.add_argument("--heartbeats", type=int, default=2)
    args = parser.parse_args()
    hello = json.loads(args.hello_json.read_text(encoding="utf-8"))
    if not isinstance(hello, dict) or not isinstance(hello.get("node_id"), str):
        parser.error("invalid NodeHello input")
    try:
        result = join(args.address,args.port,args.ca,args.client_cert,args.client_key,
                      hello=hello,expected_node_id=hello["node_id"],heartbeats=args.heartbeats)
    except (LinkFailure, ValueError, OSError, ssl.SSLError, json.JSONDecodeError) as error:
        print(json.dumps({"result": "e07_connection_failed",
                          "technical_error": type(error).__name__,
                          "detail": str(error)[:280]}))
        return 2
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
