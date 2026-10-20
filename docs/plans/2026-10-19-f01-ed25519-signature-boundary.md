# F01 signed artifact integrity — candidate, not production admission

Date: 2026-10-19. This is standalone Ptah F01 work, not Prime OS integration.

The earlier deterministic F01 archive is an unsigned candidate. This new,
additive tool signs exact archive bytes with a supplied Ed25519 private key
and verifies detached evidence using a separately supplied trusted public key
and its expected canonical DER SHA-256 fingerprint.

No production signing keys are generated, embedded, or published. Verification
rejects a modified archive, forged release authority, wrong signer or source
commit, duplicate JSON keys, symlinks and malformed signatures. Signing
rejects weak private key file permissions and never overwrites existing files.
Detached sidecars contain no private keys or embedded trust anchors.

Result is always SIGNED_ARTIFACT_INTEGRITY_VERIFIED_NOT_ADMITTED.
Execution and release authority remain false. This is signature integrity,
not proof of reproducible source provenance, approver sign-off or safe
production installation.

KRATOS evidence:
- 44 combined F01/foundation local tests passed (17 new signing tests).
- cargo build -p ptah-control -p ptah-node --bins --locked --offline passed.
- A real 66,652,160-byte locally compiled Control/Node candidate was signed
  and verified using an ephemeral development-only Ed25519 key, with a
  593-byte signed sidecar. Temporary key and archive copies auto-removed.
- Archive digest SHA256:
  e9bd41040b1801eeeb03e75173ea1f1754fb097bb5ab93d9edb5a428592311fd.
- No Node services, routes, host settings or production credentials changed.

F01 still requires an independently approved real signer, reproducible and
verified source-to-binary provenance, deployment dependency closure, failing
startup and recovery tests on admitted hosts, independent review, owner GO.
F02 and F03 acceptance remain separate. Prime OS F04-F07 integration is last.

Oracle is authenticated machine transport; Ptah is shared workspace.
