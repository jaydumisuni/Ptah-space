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

def verified_local_extension(lock_path: Path, historical_sha256: str) -> int:
    """Return 0 for exact historic lock, 1 for one exact E06 local addition.

    Never rewrite persisted historical evidence or silently bless an altered
    external dependency graph. Only the canonical Cargo package stanza is
    permitted, and its removal MUST reconstruct the frozen old byte stream.
    """
    raw = lock_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() == historical_sha256:
        return 0
    if raw.count(E06_LOCK_STANZA) != 1:
        raise ValueError("unreviewed_e06_lock_extension")
    prior = raw.replace(E06_LOCK_STANZA, b"", 1)
    if hashlib.sha256(prior).hexdigest() != historical_sha256:
        raise ValueError("historical_cargo_digest_changed_outside_e06")
    return 1
