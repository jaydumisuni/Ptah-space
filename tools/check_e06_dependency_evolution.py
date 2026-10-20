"""Exact additive E06 Cargo.lock evolution; historical E01 SHA remains immutable.

The ONLY allowed extension is the one private workspace package with existing
pinned dependencies. A new external crate, changed checksum or any other drift
must fail the original historical proof.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

E06_LOCK_STANZA = (b'[[package]]\n'
                   b'name = "ptah-offline-intent"\n'
                   b'version = "0.1.0"\n'
                   b'dependencies = [\n'
                   b' "rusqlite",\n'
                   b' "serde_json",\n'
                   b']\n\n')

# E07 changes ONLY these two local service dependency lists.
# The transformation is byte exact and cannot admit external registry drift.
_E07_NODE_BEFORE = (b'[[package]]\nname = "ptah-node"\nversion = "0.0.0-phase0c"\n'
    b'dependencies = [\n "native-process",\n "ptah-activity-runtime",\n'
    b' "ptah-identifiers",\n "ptah-node-agent",\n "ptah-node-link",\n'
    b' "ptah-node-transfer",\n "ptah-provider-api",\n "ptah-transfer",\n'
    b' "sha2",\n "tokio",\n]\n\n')
_E07_NODE_AFTER = (b'[[package]]\nname = "ptah-node"\nversion = "0.0.0-phase0c"\n'
    b'dependencies = [\n "native-process",\n "ptah-activity-runtime",\n'
    b' "ptah-control",\n "ptah-identifiers",\n "ptah-node-agent",\n'
    b' "ptah-node-link",\n "ptah-node-transfer",\n'
    b' "ptah-placement-runtime",\n "ptah-platform-admission",\n'
    b' "ptah-provider-api",\n "ptah-transfer",\n "ring",\n "rusqlite",\n'
    b' "serde",\n "serde_json",\n "sha2",\n "tokio",\n]\n\n')
_E07_CONTROL_BEFORE = (b'[[package]]\nname = "ptah-control"\nversion = "0.0.0-phase0c"\n'
    b'dependencies = [\n "ptah-android-runtime",\n "ptah-application-runtime",\n'
    b' "ptah-device-runtime",\n "ptah-identifiers",\n "ptah-node-agent",\n'
    b' "ptah-node-link",\n "ptah-placement-runtime",\n "ptah-platform-admission",\n'
    b' "ptah-provider-api",\n "ptah-transfer",\n'
    b' "serde",\n "serde_json",\n]\n\n')
_E07_CONTROL_AFTER = (b'[[package]]\nname = "ptah-control"\nversion = "0.0.0-phase0c"\n'
    b'dependencies = [\n "ptah-android-runtime",\n "ptah-application-runtime",\n'
    b' "ptah-device-runtime",\n "ptah-identifiers",\n "ptah-node-agent",\n'
    b' "ptah-node-link",\n "ptah-placement-runtime",\n "ptah-platform-admission",\n'
    b' "ptah-provider-api",\n "ptah-transfer",\n "ring",\n "rusqlite",\n'
    b' "serde",\n "serde_json",\n "sha2",\n "tokio",\n]\n\n')

def strip_exact_e07_local_service_extension(raw: bytes) -> bytes:
    """Remove E07's two exact local dep stanzas (not arbitrary edits)."""
    if raw.count(_E07_CONTROL_AFTER) != 1 or raw.count(_E07_NODE_AFTER) != 1:
        raise ValueError("unreviewed_e07_lock_extension")
    return raw.replace(_E07_CONTROL_AFTER,_E07_CONTROL_BEFORE,1).replace(
        _E07_NODE_AFTER,_E07_NODE_BEFORE,1)

def verified_local_extension(lock_path: Path, historical_sha256: str) -> int:
    """Return 0 for exact historic lock, 1 for one exact E06 local addition.

    Never rewrite persisted historical evidence or silently bless an altered
    external dependency graph. Only the canonical Cargo package stanza is
    permitted, and its removal MUST reconstruct the frozen old byte stream.
    """
    raw = lock_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() == historical_sha256:
        return 0
    if _E07_CONTROL_AFTER in raw or _E07_NODE_AFTER in raw:
        raw = strip_exact_e07_local_service_extension(raw)
    if raw.count(E06_LOCK_STANZA) != 1:
        raise ValueError("unreviewed_e06_lock_extension")
    prior = raw.replace(E06_LOCK_STANZA, b"", 1)
    if hashlib.sha256(prior).hexdigest() != historical_sha256:
        raise ValueError("historical_cargo_digest_changed_outside_e06")
    return 1
