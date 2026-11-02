"""Ptah E07 native Control E01 protocol bridge for existing upstream-admitted callers.

No extra Ptah user login/approval, no dispatch, no installation. mTLS is
the optional protocol transport's peer integrity (not workspace admission).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import stat
import struct
import unicodedata
import uuid
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


def _encode_frame(message: dict) -> bytes:
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
    return struct.pack(">I", len(data)) + data


def _write_frame(connection: ssl.SSLSocket, message: dict) -> None:
    connection.sendall(_encode_frame(message))


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


def _validate_canonical_native_node_id(value: object) -> None:
    # ptah-identifiers::NodeId wraps EntityId, whose frozen Rust contract
    # admits only lowercase hyphenated RFC-variant UUIDv7 identities.
    # Keep this CLI admission separate from legacy Python codec fixtures.
    if type(value) is not str:
        raise LinkFailure("invalid_node_hello: noncanonical UUIDv7")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise LinkFailure("invalid_node_hello: noncanonical UUIDv7") from error
    if (str(parsed) != value or parsed.version != 7
            or parsed.variant != uuid.RFC_4122):
        raise LinkFailure("invalid_node_hello: noncanonical UUIDv7")


_NATIVE_NODE_HELLO_FIELDS = frozenset({
    "supported_major", "minimum_minor", "maximum_minor",
    "node_id", "node_generation", "connection_epoch",
    "enrollment_ref", "agent_revision", "capability_snapshot_ref",
})
# The Rust NodeHello serde contract requires all non-Option members.
# Only capability_snapshot_ref is Option<EntityRef> and may be omitted.
_NATIVE_NODE_HELLO_REQUIRED_FIELDS = (
    _NATIVE_NODE_HELLO_FIELDS - {"capability_snapshot_ref"}
)


def _validate_native_version_offer(hello: dict) -> None:
    # Shared by native CLI and direct join() callers: Rust serde u16 fields
    # and nonempty advertised intervals are pre-TLS requirements, while
    # actual peer compatibility remains a separate authenticated ACK gate.
    for field in ("supported_major", "minimum_minor", "maximum_minor"):
        value = hello[field]
        if type(value) is not int or not 0 <= value <= 0xffff:
            raise LinkFailure("invalid_node_hello: noncanonical native protocol u16")
    if hello["minimum_minor"] > hello["maximum_minor"]:
        raise LinkFailure("invalid_node_hello: impossible native minor version interval")


_NATIVE_ENTITY_REF_KEYS = frozenset({
    "entity_id", "entity_kind", "record_revision", "node_generation",
    "provider_generation", "workload_generation", "connection_epoch",
})


def _validate_native_entity_ref(value: object, field: str) -> None:
    # Rust ptah-identifiers::EntityRef is a structured Serde object, not
    # an opaque string or an arbitrary JSON mapping. Refuse unknown apparent
    # authority members and noncanonical identity/counter aliases before TLS.
    failure = f"invalid_node_hello: noncanonical native EntityRef {field}"
    if (type(value) is not dict
            or not {"entity_id", "entity_kind"}.issubset(value)
            or not set(value).issubset(_NATIVE_ENTITY_REF_KEYS)):
        raise LinkFailure(failure)
    try:
        _validate_canonical_native_node_id(value["entity_id"])
    except LinkFailure as error:
        raise LinkFailure(failure) from error
    # Mirror Rust valid_kind_segment(first, false): the first namespace
    # segment may contain ASCII digits after its initial lowercase letter.
    kind = value["entity_kind"]
    if (type(kind) is not str
            or re.fullmatch(r"[a-z][a-z0-9]*\.[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*", kind) is None):
        raise LinkFailure(failure)
    for key in _NATIVE_ENTITY_REF_KEYS - {"entity_id", "entity_kind"}:
        if key not in value or value[key] is None:
            continue  # Serde Option<u64> accepts absent/null.
        if not _canonical_u64(value[key]):
            raise LinkFailure(failure)
        if key == "record_revision" and value[key] == 0:
            raise LinkFailure(failure)


def _validate_native_node_hello_fields(hello: object) -> None:
    # Rust Serde ignores unknown members but rejects absent required members.
    # Reject both before credential loading or TLS, so a CLI cannot present
    # an unbound authority field or attempt a handshake that Rust cannot parse.
    # Legacy direct join() fixtures retain their existing separate contract.
    if type(hello) is not dict or not set(hello).issubset(_NATIVE_NODE_HELLO_FIELDS):
        raise LinkFailure("invalid_node_hello: unbound native Hello field")
    if not _NATIVE_NODE_HELLO_REQUIRED_FIELDS.issubset(hello):
        raise LinkFailure("invalid_node_hello: missing native Hello field")
    _validate_native_version_offer(hello)
    # Rust NodeHello.agent_revision is a Serde String, not a JSON scalar
    # that Python may coerce or truth-test. Refuse mismatched types before
    # credentials, transport, or native deserialization.
    if type(hello["agent_revision"]) is not str:
        raise LinkFailure("invalid_node_hello: noncanonical native agent revision string")
    _validate_native_entity_ref(hello["enrollment_ref"], "enrollment_ref")
    snapshot = hello.get("capability_snapshot_ref")
    if snapshot is not None:
        _validate_native_entity_ref(snapshot, "capability_snapshot_ref")


def _node_id_nonrendering_scalar(char: str) -> bool:
    # Some visually blank Mn/Lo/So scalars are not Cf or whitespace.
    # Include Mongolian selector four, Khmer inherent vowels and Braille
    # blank; retain ordinary combining accents and visible international text.
    point = ord(char)
    return (point in {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5,
                      0x180F, 0x2800, 0x3164, 0xFFA0}
            or 0x180B <= point <= 0x180D
            or 0xFE00 <= point <= 0xFE0F
            or 0xE0100 <= point <= 0xE01EF)


def _validate_node_hello(hello: dict, expected_node_id: str) -> None:
    if (not isinstance(hello, dict) or type(expected_node_id) is not str
            or not expected_node_id or type(hello.get("node_id")) is not str
            or hello["node_id"] != expected_node_id
            or not all(_canonical_u64(hello.get(field))
                       for field in ("node_generation", "connection_epoch"))):
        raise LinkFailure("invalid_node_hello")
    # The Rust E01 NodeId is a UTF-8 scalar string. Direct join() callers
    # bypass the local JSON Hello loader, so reject surrogate identities
    # before TLS credential loading or any network connection.
    try:
        expected_node_id.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise LinkFailure("invalid_node_hello") from error
    # Direct join() intentionally supports legacy textual test NodeIds, but
    # cannot admit invisible/format/control/unassigned scalars as an E01
    # identity. Those strings could appear different in reviewed evidence
    # while comparing byte-for-byte equal before credential/TLS setup.
    if any(char.isspace()
           or unicodedata.category(char) in {"Cc", "Cf", "Cs", "Cn"}
           or _node_id_nonrendering_scalar(char)
           for char in expected_node_id):
        raise LinkFailure("invalid_node_hello: noncanonical identity scalar")
    # Legacy direct codec callers may omit the entire version triple.
    # A partially supplied native offer is neither legacy nor a complete
    # Rust NodeHello: refuse it before credentials or TLS are opened.
    version_fields = ("supported_major", "minimum_minor", "maximum_minor")
    if (any(key in hello for key in version_fields)
            and not all(key in hello for key in version_fields)):
        raise LinkFailure("invalid_node_hello: missing native Hello field")
    if all(key in hello for key in version_fields):
        _validate_native_version_offer(hello)


def _validate_hello_ack(
    ack: dict, expected_node_id: str,
    node_generation: int, connection_epoch: int,
    offered_hello: dict | None = None,
) -> None:
    # The frozen E01 Rust HelloAck has exactly four fields. Refuse extra
    # envelope or body members rather than admitting an unbound authority
    # projection that the Rust peer would silently ignore.
    if (type(ack) is not dict or set(ack) != {"kind", "payload"}
            or ack["kind"] != "hello_ack"):
        raise LinkFailure("missing_canonical_hello_ack")
    body = ack["payload"]
    if (type(body) is not dict or set(body) != {
            "selected_version", "node_id", "node_generation", "connection_epoch"}):
        raise LinkFailure("missing_canonical_hello_ack")
    if body["node_id"] != expected_node_id:
        raise LinkFailure("wrong_node_ack")
    for field in ("node_generation", "connection_epoch"):
        expected_value = (node_generation if field == "node_generation"
                          else connection_epoch)
        if not _canonical_u64(body[field]) or body[field] != expected_value:
            raise LinkFailure("mismatched_" + field)
    selected = body["selected_version"]
    if (type(selected) is not dict or set(selected) != {"major", "minor"}
            or type(selected["major"]) is not int
            or type(selected["minor"]) is not int
            or selected != {"major": 1, "minor": 0}):
        raise LinkFailure("wrong_e01_version")
    # The fixed E01 selection must also belong to the minor range the
    # Node actually advertised. Otherwise a 1.1-only Node can accept 1.0.
    # Legacy direct join() fixtures without version fields remain supported.
    fields = ("supported_major", "minimum_minor", "maximum_minor")
    if offered_hello is not None and any(key in offered_hello for key in fields):
        if not all(key in offered_hello for key in fields):
            raise LinkFailure("hello_ack_version_not_advertised")
        major, lower, upper = (offered_hello[key] for key in fields)
        if (any(type(value) is not int for value in (major, lower, upper))
                or major != selected["major"]
                or not lower <= selected["minor"] <= upper):
            raise LinkFailure("hello_ack_version_not_advertised")



def _idna_ignored_host_scalar(char: str) -> bool:
    # Python's IDNA codec silently drops these non-Cf format/variation
    # scalars. Keep the caller's reviewed endpoint identity unchanged.
    point = ord(char)
    return (point == 0x034f or 0x180b <= point <= 0x180d
            or 0xfe00 <= point <= 0xfe0f)


def _idna_host_identity_is_canonical(address: str) -> bool:
    # Python's IDNA2003 codec may rewrite NFKC-stable host labels (ß -> ss,
    # final sigma -> sigma, ideographic full stop -> ASCII dot). Reject such
    # Unicode aliases before credentials or TLS; keep ASCII DNS/IP literals
    # and punycode names unchanged.
    if address.isascii():
        return True
    try:
        canonical = address.encode("idna").decode("idna")
    except UnicodeError:
        return False
    # The codec preserves ASCII label case; require exact Unicode scalar
    # identity rather than casefolding away a rewritten destination.
    return canonical == address


def _canonical_endpoint_host_syntax(address: str) -> bool:
    # The port is supplied separately. A URL, userinfo, path, query,
    # bracketed IPv6, or interface-scoped IPv6 is not a host identity.
    if any(char in address for char in "/\\@?#[]%"):
        return False
    if ":" in address:
        try:
            ipv6 = ipaddress.IPv6Address(address)
        except ValueError:
            return False
        # A resolver accepts expanded, mixed-case and alternate IPv4-mapped
        # spellings for the same destination. Python versions disagree on
        # whether str(IPv6Address) prints mapped IPv4 as hex or dotted text.
        # Fix one reviewed identity across runtimes before credentials/TLS.
        canonical = (f"::ffff:{ipv6.ipv4_mapped}"
                     if ipv6.ipv4_mapped is not None else str(ipv6))
        return ipv6.scope_id is None and canonical == address
    # Legacy libc resolvers interpret numeric, shortened, octal and hex
    # host spellings as IPv4 literals (for example 127.1 -> 127.0.0.1).
    # Refuse those alternate identities before TLS or DNS. Use the strict
    # dotted-decimal IPv4 parser for canonical literals and a lexical
    # guard for resolver-dependent aliases; ordinary DNS remains allowed.
    try:
        ipv4 = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError:
        if (re.fullmatch(r"[0-9.]+", address)
                or any(re.fullmatch(r"0[xX][0-9a-fA-F]+", part)
                       for part in address.split("."))):
            return False
    else:
        return str(ipv4) == address
    # A terminal dot denotes an absolute DNS name; an empty internal
    # label cannot name a canonical DNS endpoint.
    labels = (address[:-1] if address.endswith(".") else address).split(".")
    if not all(labels):
        return False
    # DNS wire names are bounded by 63 octets per IDNA-encoded label and
    # 253 octets without the optional terminal root dot. Check before TLS
    # credential loading, preserving the caller's exact Unicode hostname.
    try:
        encoded_labels = [label.encode("idna") for label in labels]
    except UnicodeError:
        return False
    # The ASCII IDNA encoder leaves apparent xn-- A-labels untouched.
    # Require each reserved A-label to decode and round-trip canonically;
    # otherwise a malformed punycode name reaches certificate/TLS setup.
    for label in encoded_labels:
        if label.lower().startswith(b"xn--"):
            try:
                decoded = label.decode("idna")
                if decoded.encode("idna").lower() != label.lower():
                    return False
            except UnicodeError:
                return False
    # A TLS endpoint host is an LDH hostname, not an arbitrary DNS owner
    # name. Python's IDNA codec passes ASCII punctuation and leading or
    # trailing hyphens through unchanged; refuse those before TLS setup.
    # Check encoded labels so valid internationalized names remain accepted.
    return (all(0 < len(label) <= 63
                and re.fullmatch(
                    rb"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
                for label in encoded_labels)
            and sum(map(len, encoded_labels)) + len(encoded_labels) - 1 <= 253)


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
    # Socket/IDNA libraries can normalize compatibility host aliases into a
    # different destination. Do not silently reinterpret the caller's host.
    # Reject invisible controls and unassigned Unicode scalars before TLS.
    # IDNA2003 may preserve Cn scalars that later Unicode releases reassign.
    if (type(address) is not str or not address
            or unicodedata.normalize("NFKC", address) != address
            or any(char.isspace()
                   or unicodedata.category(char) in {"Cc", "Cf", "Cs", "Cn"}
                   or _idna_ignored_host_scalar(char) for char in address)
            or not _idna_host_identity_is_canonical(address)
            or not _canonical_endpoint_host_syntax(address)):
        raise ValueError("address must be a canonical hostname or unscoped IP literal without URL syntax or controls")
    # bool is an int subclass, but is not a valid E01 sequence count or port.
    if type(heartbeats) is not int or not 1 <= heartbeats <= 10:
        raise ValueError("heartbeats must be an integer in 1..10")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer in 1..65535")
    if (type(timeout) not in (int, float)
            or not 0 < timeout <= 300 or not math.isfinite(timeout)):
        raise ValueError("timeout must be finite seconds in (0, 300]")
    _validate_node_hello(hello, expected_node_id)
    node_generation = hello["node_generation"]
    connection_epoch = hello["connection_epoch"]
    # The caller may mutate Hello while it is being encoded. Revalidate the
    # exact bounded bytes that will be sent, not just the earlier dict view.
    hello_frame = _encode_frame({"kind": "hello", "payload": hello})
    frozen = _decode_strict_json(hello_frame[4:].decode("utf-8"), "outgoing")
    frozen_hello = frozen["payload"]
    _validate_node_hello(frozen_hello, expected_node_id)
    if (frozen_hello["node_generation"] != node_generation
            or frozen_hello["connection_epoch"] != connection_epoch):
        raise LinkFailure("invalid_node_hello: identity changed during freeze")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=str(ca))
    ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    with socket.create_connection((address, port), timeout=timeout) as sock:
        # Verify the selected TLS endpoint, not an unrelated loopback name.
        # The E01 NodeId/Generation/Epoch remain separately authenticated.
        with ctx.wrap_socket(sock, server_hostname=address) as tls:
            tls.settimeout(timeout)
            if tls.version() != "TLSv1.3":
                raise LinkFailure("tls13_required")
            tls.sendall(hello_frame)
            ack = _read_frame(tls)
            _validate_hello_ack(ack, expected_node_id,
                                node_generation, connection_epoch,
                                offered_hello=frozen_hello)
            for sequence in range(1, heartbeats + 1):
                _write_frame(tls, {"kind": "heartbeat", "payload": {
                    "node_id": expected_node_id,
                    "node_generation": node_generation,
                    "connection_epoch": connection_epoch,
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
    # A supplied Hello pathname must not open a FIFO, socket or symlink as
    # protocol input. On Linux, O_PATH pins a regular inode without opening
    # it for reading; /proc/self/fd then reopens that exact inode, not a
    # potentially replaced pathname. The fallback rejects special leaves
    # before opening and rechecks the resulting descriptor.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        if hasattr(os, "O_PATH") and Path("/proc/self/fd").is_dir():
            pinned = os.open(path, os.O_PATH | os.O_NOFOLLOW)
            try:
                identity = os.fstat(pinned)
                if not stat.S_ISREG(identity.st_mode):
                    raise LinkFailure("invalid_hello_source: not a regular file")
                reader = os.open(f"/proc/self/fd/{pinned}", flags)
                try:
                    actual = os.fstat(reader)
                    if (not stat.S_ISREG(actual.st_mode)
                            or (actual.st_dev, actual.st_ino)
                            != (identity.st_dev, identity.st_ino)):
                        raise LinkFailure("invalid_hello_source: changed inode")
                    with os.fdopen(reader, "rb", closefd=False) as stream:
                        raw = stream.read(1_048_577)
                finally:
                    os.close(reader)
            finally:
                os.close(pinned)
        else:
            identity = path.lstat()
            if not stat.S_ISREG(identity.st_mode):
                raise LinkFailure("invalid_hello_source: not a regular file")
            reader = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
            try:
                actual = os.fstat(reader)
                if (not stat.S_ISREG(actual.st_mode)
                        or (actual.st_dev, actual.st_ino)
                        != (identity.st_dev, identity.st_ino)):
                    raise LinkFailure("invalid_hello_source: changed inode")
                with os.fdopen(reader, "rb", closefd=False) as stream:
                    raw = stream.read(1_048_577)
            finally:
                os.close(reader)
    except OSError as error:
        raise LinkFailure("invalid_hello_source: cannot open regular file") from error
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
        _validate_canonical_native_node_id(hello["node_id"])
        _validate_native_node_hello_fields(hello)
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
