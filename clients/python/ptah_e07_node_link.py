"""Ptah E07 native Control E01 protocol bridge for existing upstream-admitted callers.

No extra Ptah user login/approval, no dispatch, no installation. mTLS is
the optional protocol transport's peer integrity (not workspace admission).
"""
from __future__ import annotations

import argparse
import json
import math
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


def _require_json_nesting_budget(text: str, direction: str) -> None:
    # E01 has shallow, versioned JSON frames in either direction. Scan the
    # encoded structure iteratively: brackets inside escaped JSON strings
    # must not consume the nesting budget.
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 32:
                raise LinkFailure(f"invalid_{direction}_frame: excessive JSON nesting")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise LinkFailure(f"invalid_{direction}_frame: malformed JSON")


def _write_frame(connection: ssl.SSLSocket, message: dict) -> None:
    # Python emits NaN and Infinity by default, although they are not JSON
    # numbers accepted by the E01 Rust peer. Reject before sending any bytes.
    # Normalize unsupported values into a bounded protocol failure as well.
    # json.dumps silently coerces non-string dict keys into JSON strings.
    # Preserve the source identity of every nested E01 object before
    # serialization, including objects inside arrays. Cyclic references
    # remain rejected by the JSON encoder below.
    # E01 uses a tagged JSON object. The incoming decoder rejects bare
    # arrays/scalars; reject them here before any wire effect as well.
    if not isinstance(message, dict):
        raise LinkFailure("invalid_outgoing_frame: expected JSON object")
    pending = [message]
    seen = set()
    while pending:
        value = pending.pop()
        if isinstance(value, (dict, list, tuple)):
            if id(value) in seen:
                continue
            seen.add(id(value))
            if isinstance(value, dict):
                if any(type(key) is not str for key in value):
                    raise LinkFailure("invalid_outgoing_frame: nonstring JSON object key")
                pending.extend(value.values())
            else:
                pending.extend(value)
    try:
        # Serialize Unicode scalars directly: strict UTF-8 encoding then
        # rejects lone surrogate code points that Python's default ASCII
        # escaping would send but the Rust E01 peer cannot deserialize.
        text = json.dumps(message, separators=(",", ":"), sort_keys=True,
                          allow_nan=False, ensure_ascii=False)
        _require_json_nesting_budget(text, "outgoing")
        data = text.encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError,
            UnicodeError) as error:
        raise LinkFailure("invalid_outgoing_frame") from error
    if not data or len(data) > 1_048_576:
        raise LinkFailure("invalid_frame_size")
    connection.sendall(struct.pack(">I", len(data)) + data)


def _decode_strict_json(text: str, direction: str) -> object:
    # Authenticated wire frames and local Hello files must share one
    # unambiguous JSON decoder; duplicate identities and nonfinite numbers
    # cannot be normalized before E01 identity checks.
    _require_json_nesting_budget(text, direction)

    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise LinkFailure(f"invalid_{direction}_frame: duplicate JSON field")
            result[key] = value
        return result

    def reject_nonfinite(_token):
        raise LinkFailure(f"invalid_{direction}_frame: nonfinite JSON number")

    def finite_float(token):
        value = float(token)
        if not math.isfinite(value):
            raise LinkFailure(f"invalid_{direction}_frame: nonfinite JSON number")
        return value

    try:
        decoded = json.loads(text, object_pairs_hook=unique_fields,
                             parse_constant=reject_nonfinite,
                             parse_float=finite_float)
        # Python accepts lone UTF-16 surrogate escapes as str values and
        # object keys, but the native Rust E01 JSON peer rejects them.
        # Check every decoded scalar iteratively (the frame is size-bounded)
        # so local Hello and authenticated incoming wire use identical rules.
        pending = [decoded]
        while pending:
            value = pending.pop()
            if type(value) is str:
                value.encode("utf-8", errors="strict")
            elif isinstance(value, dict):
                pending.extend(value.keys())
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        return decoded
    except (ValueError, UnicodeError, RecursionError) as error:
        raise LinkFailure(f"invalid_{direction}_frame: malformed JSON") from error


def _read_frame(connection: ssl.SSLSocket) -> dict:
    size = struct.unpack(">I", _receive_exact(connection, 4))[0]
    if not 0 < size <= 1_048_576:
        raise LinkFailure("invalid_incoming_frame_size")
    try:
        text = _receive_exact(connection, size).decode("utf-8")
    except UnicodeError as error:
        raise LinkFailure("invalid_incoming_frame: malformed JSON") from error
    obj = _decode_strict_json(text, "incoming")
    if not isinstance(obj, dict):
        raise LinkFailure("invalid_incoming_frame")
    return obj


def _canonical_u64(value: object) -> bool:
    # E01 NodeGeneration and ConnectionEpoch are serde-transparent Rust u64.
    # Python bool and float compare equal to integers but are not wire-equivalent.
    return type(value) is int and 0 <= value <= (1 << 64) - 1


def _validate_node_hello(hello: dict, expected_node_id: str) -> None:
    if (not isinstance(hello, dict) or type(expected_node_id) is not str
            or not expected_node_id or type(hello.get("node_id")) is not str
            or hello["node_id"] != expected_node_id
            or not all(_canonical_u64(hello.get(field))
                       for field in ("node_generation", "connection_epoch"))):
        raise LinkFailure("invalid_node_hello")


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
    # Reject noncanonical caller values before TLS setup or network access.
    # A malformed destination must not reach certificate loading or socket
    # setup. Preserve ordinary DNS, IPv4 and IPv6 names without normalizing
    # the caller's address into a different transport target.
    if (type(address) is not str or not address
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127
                   for char in address)):
        raise ValueError("address must be a nonempty host without whitespace/control characters")
    # bool is an int subclass, but is not a valid E01 sequence count or port.
    if type(heartbeats) is not int or not 1 <= heartbeats <= 10:
        raise ValueError("heartbeats must be an integer in 1..10")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer in 1..65535")
    if (type(timeout) not in (int, float)
            or not 0 < timeout <= 300 or not math.isfinite(timeout)):
        raise ValueError("timeout must be finite seconds in (0, 300]")
    _validate_node_hello(hello, expected_node_id)
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
                if not _canonical_u64(body.get(field)) or body[field] != hello[field]:
                    raise LinkFailure("mismatched_" + field)
            selected = body.get("selected_version")
            if (not isinstance(selected, dict)
                    or set(selected) != {"major", "minor"}
                    or type(selected["major"]) is not int
                    or type(selected["minor"]) is not int
                    or selected != {"major": 1, "minor": 0}):
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


def _load_hello_json(path: Path) -> dict:
    # Read at most one byte beyond the E01 frame limit. A caller-provided
    # file must not allocate unbounded memory or bypass wire JSON custody.
    with path.open("rb") as stream:
        raw = stream.read(1_048_577)
    if not 0 < len(raw) <= 1_048_576:
        raise LinkFailure("invalid_hello_frame_size")
    try:
        hello = _decode_strict_json(raw.decode("utf-8"), "hello")
    except UnicodeError as error:
        raise LinkFailure("invalid_hello_frame: malformed UTF-8") from error
    if not isinstance(hello, dict) or type(hello.get("node_id")) is not str:
        raise LinkFailure("invalid_node_hello")
    _validate_node_hello(hello, hello["node_id"])
    return hello


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
    try:
        hello = _load_hello_json(args.hello_json)
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
