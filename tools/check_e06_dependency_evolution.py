"""Strict additive E06/E07 private package lock evolution.

Reconstruct the historical E01 Cargo.lock byte-for-byte. Never alter frozen
selection, registry package checksums, external sources, or prior proof hashes.
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

# Existing pinned dependencies only, all private-local workspace linkages.
CONTROL_DEPENDENCIES = ("ring", "rusqlite", "sha2", "tokio")
NODE_DEPENDENCIES = (
    "ptah-control", "ptah-placement-runtime", "ptah-platform-admission",
    "ring", "rusqlite", "serde", "serde_json",
)

def _strip_selected_local_additions(raw: bytes, package_name: str, additions: tuple[str, ...]) -> tuple[bytes, bool]:
    prefix = b'[[package]]\nname = "' + package_name.encode("ascii") + b'"\n'
    if raw.count(prefix) != 1:
        raise ValueError("missing_or_duplicate_private_package:" + package_name)
    start = raw.index(prefix)
    next_package = raw.find(b"[[package]]\n", start + len(prefix))
    if next_package < 0:
        next_package = len(raw)
    previous, package, after = raw[:start], raw[start:next_package], raw[next_package:]
    lines = [b' "' + x.encode("ascii") + b'",\n' for x in additions]
    present = [line in package for line in lines]
    if any(present) and not all(present):
        raise ValueError("partial_private_package_extension:" + package_name)
    if all(present):
        for line in lines:
            if package.count(line) != 1:
                raise ValueError("duplicate_private_dependency:" + package_name)
            package = package.replace(line, b"", 1)
    return previous + package + after, all(present)

def verified_local_extension(lock_path: Path, historical_sha256: str) -> int:
    """Return 0 when frozen unchanged, 1 for exact E06 and optional gateway extension.

    The reconstruction check protects every byte of the prior registry universe,
    historic package ordering, checksum and unmodified package manifests.
    """
    raw = lock_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() == historical_sha256:
        return 0
    if raw.count(E06_LOCK_STANZA) != 1:
        raise ValueError("unreviewed_e06_lock_extension")
    raw = raw.replace(E06_LOCK_STANZA, b"", 1)
    raw, control = _strip_selected_local_additions(raw, "ptah-control", CONTROL_DEPENDENCIES)
    raw, node = _strip_selected_local_additions(raw, "ptah-node", NODE_DEPENDENCIES)
    if control != node:
        raise ValueError("partial_gateway_private_dependency_extension")
    if hashlib.sha256(raw).hexdigest() != historical_sha256:
        raise ValueError("historical_cargo_digest_changed_outside_e06_e07_private_scope")
    return 1
