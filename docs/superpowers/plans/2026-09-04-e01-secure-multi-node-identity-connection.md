# E01 Secure Multi-Node Identity and Connection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Programme E01 secure multi-Node enrollment, authenticated connection, capability announcements and reconnect without changing Ptah canonical Node identity semantics.

**Architecture:** Add a transport-neutral `ptah-node-link` crate whose protocol/framing/session logic is generic over async byte streams. Implement TLS 1.3 mutual authentication with Rustls over Tokio TCP as the first transport, bind the peer certificate fingerprint to an approved Node enrollment, reuse `ptah-node-agent` for NodeId/Generation/ConnectionEpoch truth, and expose thin Node/control service entry points.

**Tech Stack:** Rust 1.97.1, Tokio, Rustls, tokio-rustls, rustls-pemfile, SHA-256, Serde/JSON, existing Ptah identifiers/node-agent/ledger/provenance crates, GitHub Actions exact-head proof.

**Spec:** `docs/superpowers/specs/2026-09-04-e01-secure-multi-node-identity-connection-design.md`

## Global Constraints

- Accepted predecessor is exact D09 merge `f22d23c9bbf3c9c43884535e3483486c4bc0826f`.
- E01 implements only enrollment, secure connection, capability announcement and reconnect; E02–E06 semantics are excluded.
- `NodeId`, `NodeGeneration` and `ConnectionEpoch` remain canonical A02 truth; endpoint/certificate/backend IDs remain evidence only.
- Protocol is `ptah.node.link.v1`; maximum serialized frame is 1 MiB.
- TLS 1.3 mutual authentication is the first transport, not canonical protocol identity.
- Private key bytes must never enter Ptah ledger records, logs or proof artifacts.
- No Git Cargo dependencies; all new registry dependencies are exact-pinned and audited.
- No new database migration or Core entity family unless an evidenced implementation blocker proves one necessary.
- Every protected message is rechecked against current session Generation/epoch, not only at handshake.

---

### Task 1: E01 crate boundary, dependency lock and RED protocol tests

**Files:**
- Modify: `Cargo.toml`
- Modify: `dependencies/rust-direct-lock.json`
- Modify: `evidence/rust-dependency-lock/Cargo.toml`
- Create: `crates/ptah-node-link/Cargo.toml`
- Create: `crates/ptah-node-link/src/lib.rs`
- Create: `crates/ptah-node-link/tests/protocol.rs`

**Interfaces:**
- Produces crate `ptah-node-link`.
- Produces constants `PROTOCOL_ID: &str = "ptah.node.link.v1"` and `MAX_FRAME_BYTES: usize = 1_048_576`.
- Produces later modules `protocol`, `framing`, `enrollment`, `session`, `tls`, `error`.

- [ ] **Step 1: add failing protocol tests**

Create `crates/ptah-node-link/tests/protocol.rs` with tests that import `ProtocolVersion`, `NodeHello`, `LinkMessage`, `PROTOCOL_ID` and `MAX_FRAME_BYTES`, construct one hello with an A02 `NodeAgent`, and assert:

```rust
assert_eq!(PROTOCOL_ID, "ptah.node.link.v1");
assert_eq!(MAX_FRAME_BYTES, 1_048_576);
assert_eq!(hello.node_id, agent.node_id());
assert_eq!(hello.node_generation, agent.generation());
assert_eq!(hello.connection_epoch, agent.connection_epoch());
assert_eq!(LinkMessage::Hello(hello).kind(), "hello");
```

Also assert incompatible protocol-major negotiation returns `LinkError::ProtocolIncompatible`.

- [ ] **Step 2: run the targeted test and confirm RED**

Run:

```bash
cargo test -p ptah-node-link --test protocol --locked
```

Expected: compile failure because the crate/types do not yet exist.

- [ ] **Step 3: add exact dependency selections and crate scaffold**

Add `crates/ptah-node-link` to workspace members. Add exact workspace selections for the Rustls ecosystem chosen for the implementation and mirror those selections into `dependencies/rust-direct-lock.json` and `evidence/rust-dependency-lock/Cargo.toml`. Keep Tokio/Serde/SHA2/thiserror reused from existing workspace selections. Create a minimal library exposing the required modules/constants but no fake behavior.

- [ ] **Step 4: regenerate and verify Cargo lock**

Run:

```bash
cargo generate-lockfile
python3 tools/check_rust_dependency_lock.py --output /tmp/e01-dependency-lock.json
cargo metadata --locked --format-version 1 > /tmp/e01-cargo-metadata.json
```

Expected: zero Git dependencies and the new exact direct dependency selections resolve from canonical crates.io with checksums.

- [ ] **Step 5: commit**

```bash
git add Cargo.toml Cargo.lock dependencies/rust-direct-lock.json evidence/rust-dependency-lock/Cargo.toml crates/ptah-node-link
git commit -m "feat(e01): establish secure node-link crate"
```

### Task 2: Versioned bounded protocol and framing

**Files:**
- Create: `crates/ptah-node-link/src/protocol.rs`
- Create: `crates/ptah-node-link/src/framing.rs`
- Create: `crates/ptah-node-link/src/error.rs`
- Modify: `crates/ptah-node-link/src/lib.rs`
- Modify: `crates/ptah-node-link/tests/protocol.rs`
- Create: `crates/ptah-node-link/tests/framing.rs`

**Interfaces:**
- Produces `ProtocolVersion { major: u16, minor: u16 }` and `negotiate_version(local, remote) -> Result<ProtocolVersion, LinkError>`.
- Produces `NodeHello`, `HelloAck`, `CapabilityAnnouncement`, `Heartbeat`, `LinkAck`, `LinkErrorFrame`, `LinkMessage`.
- Produces async `read_frame<R: AsyncRead + Unpin>` and `write_frame<W: AsyncWrite + Unpin>`.
- `LinkError` exposes stable mechanical variants including `ProtocolIncompatible`, `FrameTooLarge`, `MalformedFrame`.

- [ ] **Step 1: add RED framing tests**

Use `tokio::io::duplex` to prove one encoded `NodeHello` round-trips and a declared payload length greater than `MAX_FRAME_BYTES` returns exactly `LinkError::FrameTooLarge` without reading an unbounded body.

- [ ] **Step 2: run targeted tests and confirm RED**

```bash
cargo test -p ptah-node-link --test protocol --test framing --locked
```

Expected: missing protocol/framing implementations.

- [ ] **Step 3: implement minimal versioned message model**

Use Serde tagged enums. `NodeHello` must contain:

```rust
pub struct NodeHello {
    pub supported_major: u16,
    pub minimum_minor: u16,
    pub maximum_minor: u16,
    pub node_id: NodeId,
    pub node_generation: NodeGeneration,
    pub connection_epoch: ConnectionEpoch,
    pub enrollment_ref: EntityRef,
    pub agent_revision: String,
    pub capability_snapshot_ref: Option<EntityRef>,
}
```

Use a 4-byte big-endian frame length followed by JSON. Reject zero, malformed and >1 MiB frames with stable errors. `write_frame` must serialize first, check size, then write length and bytes.

- [ ] **Step 4: run tests GREEN**

```bash
cargo test -p ptah-node-link --test protocol --test framing --locked
cargo clippy -p ptah-node-link --all-targets -- -D warnings
```

- [ ] **Step 5: commit**

```bash
git add crates/ptah-node-link
git commit -m "feat(e01): add bounded node-link protocol"
```

### Task 3: Enrollment authority, credential rotation and session fencing

**Files:**
- Create: `crates/ptah-node-link/src/enrollment.rs`
- Create: `crates/ptah-node-link/src/session.rs`
- Create: `crates/ptah-node-link/tests/enrollment_session.rs`
- Modify: `crates/ptah-node-link/src/error.rs`
- Modify: `crates/ptah-node-link/src/lib.rs`

**Interfaces:**
- Produces `CredentialFingerprint([u8; 32])` with lowercase hex display/parse and `from_der(&[u8])`.
- Produces `EnrollmentLifecycle::{Requested, UnderReview, Approved, Rejected, Revoked, Expired}`.
- Produces `ApprovedNodeEnrollment` containing enrollment ref, stable NodeId, lifecycle, approved role keys, credential fingerprints and optional expiry epoch seconds.
- Produces `SessionBinding` containing NodeId, NodeGeneration, ConnectionEpoch, enrollment ref, credential fingerprint and negotiated protocol.
- Produces `SessionRegistry::accept_hello(...)`, `SessionRegistry::assert_current(...)`, and `SessionRegistry::revoke_credential(...)`.

- [ ] **Step 1: write adversarial RED tests**

Tests must cover:

```text
approved enrollment + bound fingerprint -> accepted
requested/rejected/revoked/expired -> rejected
trusted credential bound to another NodeId -> NodeIdentityMismatch
unbound fingerprint -> CredentialNotBound
same generation + higher epoch -> accepted and supersedes old session
same generation + equal/older epoch -> StaleConnectionEpoch
higher generation -> accepted and fences old generation
older generation -> StaleNodeGeneration
superseded session assert_current -> SupersededConnection
credential rotation accepts old+new during overlap, then old fails after revoke
```

- [ ] **Step 2: run RED**

```bash
cargo test -p ptah-node-link --test enrollment_session --locked
```

- [ ] **Step 3: implement enrollment/session mechanics**

Do not infer approval from TLS. `ApprovedNodeEnrollment::authorize_peer` must require lifecycle `Approved`, not expired, matching NodeId and a fingerprint present in the active credential set. `SessionRegistry` is authoritative only for active secure-link sessions; it must not become canonical Node storage.

- [ ] **Step 4: run GREEN + regression**

```bash
cargo test -p ptah-node-link --test enrollment_session --locked
cargo test -p ptah-node-agent --locked
```

- [ ] **Step 5: commit**

```bash
git add crates/ptah-node-link
git commit -m "feat(e01): fence enrolled node sessions"
```

### Task 4: TLS 1.3 mutual-auth transport

**Files:**
- Create: `crates/ptah-node-link/src/tls.rs`
- Create: `crates/ptah-node-link/tests/tls_transport.rs`
- Modify: `crates/ptah-node-link/src/error.rs`
- Modify: `crates/ptah-node-link/src/lib.rs`

**Interfaces:**
- Produces `TlsIdentity` containing public certificate chain and a private-key handle/DER value used only in process memory.
- Produces `TlsTrustRoots`.
- Produces `TlsServerConfig::new(...)` and `TlsClientConfig::new(...)` that negotiate TLS 1.3 only.
- Produces `accept_tls(TcpStream, Arc<ServerConfig>) -> Result<AuthenticatedServerStream, LinkError>`.
- Produces `connect_tls(TcpStream, ServerName<'static>, Arc<ClientConfig>) -> Result<AuthenticatedClientStream, LinkError>`.
- `AuthenticatedServerStream` exposes only SHA-256 end-entity peer fingerprint plus its async stream; no private key content is printable/debuggable.

- [ ] **Step 1: write RED physical-loopback TLS tests**

Generate ephemeral test CA/server/client certificates at test runtime. Prove:

```text
correct CA + client cert -> mutual TLS succeeds
client with wrong CA -> handshake fails
server receiving client signed by wrong CA -> handshake fails
plaintext bytes sent to TLS listener -> handshake fails
server extracts client end-entity SHA-256 fingerprint
protocol can round-trip one NodeHello over the negotiated TLS stream
```

Tests must assert no formatted error/debug output contains the test private-key PEM marker.

- [ ] **Step 2: run RED**

```bash
cargo test -p ptah-node-link --test tls_transport --locked
```

- [ ] **Step 3: implement Rustls transport adapter**

Configure TLS 1.3 only and mutual client authentication. Parse certificate/key material with Rustls PKI types. Compute SHA-256 over peer end-entity DER. Keep protocol/framing generic over `AsyncRead + AsyncWrite` so TLS remains an adapter.

- [ ] **Step 4: run GREEN and strict lint**

```bash
cargo test -p ptah-node-link --test tls_transport --locked
cargo clippy -p ptah-node-link --all-targets -- -D warnings
```

- [ ] **Step 5: commit**

```bash
git add crates/ptah-node-link
git commit -m "feat(e01): add mutual TLS node transport"
```

### Task 5: Node/control service integration and capability acceptance

**Files:**
- Modify: `services/ptah-node/Cargo.toml`
- Replace: `services/ptah-node/src/main.rs`
- Create: `services/ptah-node/src/lib.rs`
- Create: `services/ptah-node/tests/e01_node_client.rs`
- Modify: `services/ptah-control/Cargo.toml`
- Modify: `services/ptah-control/src/lib.rs`
- Create: `services/ptah-control/src/node_link.rs`
- Create: `services/ptah-control/tests/e01_node_link.rs`

**Interfaces:**
- Node service produces `NodeLinkClientConfig` and `run_node_link_client`.
- Control service produces `NodeLinkControl`, `accept_hello`, `accept_capability`, and current-session query functions.
- Capability acceptance consumes the existing `NodeCapabilitySnapshot` and rejects NodeId/Generation/ConnectionEpoch mismatch before persistence/projection.

- [ ] **Step 1: write RED service integration tests**

Use two independently bootstrapped `NodeAgent`s and two approved enrollments. Prove concurrent hello acceptance creates two independent active bindings. Prove a capability snapshot whose Node/Generation/epoch differs from the authenticated binding is rejected. Prove superseded connection capability publication fails.

- [ ] **Step 2: run RED**

```bash
cargo test -p ptah-control --test e01_node_link --locked
cargo test -p ptah-node --test e01_node_client --locked
```

- [ ] **Step 3: implement thin service boundaries**

`ptah-node` is configuration/orchestration only; identity remains in `ptah-node-agent`. `ptah-control::node_link` owns the current in-process secure-session registry but writes no new database schema. Keep the existing human HTTP control service behavior unchanged.

- [ ] **Step 4: prove service integration and full workspace**

```bash
cargo test -p ptah-node-link -p ptah-node -p ptah-control --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

- [ ] **Step 5: commit**

```bash
git add services/ptah-node services/ptah-control
git commit -m "feat(e01): connect enrolled nodes to control"
```

### Task 6: Durable E01 acceptance corpus and exact-head proof

**Files:**
- Create: `conformance/e01/secure-multi-node-cases.v0.1.0.json`
- Create: `tools/check_e01_secure_multi_node.py`
- Create: `tools/test_check_e01_secure_multi_node.py`
- Create: `E01_SECURE_MULTI_NODE_IDENTITY_CONNECTION.md`
- Create: `.github/workflows/e01-secure-multi-node-identity-connection.yml`

**Interfaces:**
- Corpus records every required positive, negative and recovery case from the design.
- Checker validates corpus coverage and required report bundle files.
- Permanent workflow binds the exact candidate SHA, accepted D09 predecessor, reviewed E01 delta, dependency/source/licence state and all retained reports.

- [ ] **Step 1: write checker tests RED**

Require cases for two-node concurrency, reconnect, Node restart, control restart, credential rotation, plaintext, wrong CA, wrong enrollment binding, revoked/expired enrollment, stale Generation, stale/equal epoch, superseded publish, capability identity mismatch, malformed/oversized frame and unsupported protocol.

- [ ] **Step 2: implement corpus/checker GREEN**

```bash
python3 -m unittest tools/test_check_e01_secure_multi_node.py -v
python3 tools/check_e01_secure_multi_node.py --repo-root . --output /tmp/e01-corpus.json
```

- [ ] **Step 3: add durable milestone record**

Record predecessor, exact design/plan authority, dependency delta, transport neutrality, explicit E02–E06 non-claims, known limitations and release procedure.

- [ ] **Step 4: add permanent exact-head workflow**

The workflow must use immutable external Action SHA pins and prove, on one exact head:

```text
exact D09 predecessor and reviewed E01 delta
immutable Action refs
current Cargo dependency/source/licence policy
E01 checker regression + corpus
ptah-node-link protocol/framing/enrollment/session/TLS tests
ptah-node and ptah-control E01 tests
ptah-node-agent A02 regression
D09/deep Workspace checker regression without reinterpreting D09's historical exact dependency snapshot
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
secret/private-key marker scan
clean exact candidate after proof
retained E01 proof bundle + SHA-256 manifest
```

- [ ] **Step 5: freeze and prove exact candidate**

Require one immutable SHA and retained artifact `e01-secure-multi-node-${SHA}`. Inspect artifact checksums and authority flags before PR creation.

- [ ] **Step 6: guarded merge and independent main verification**

Open PR against `main`, require base `f22d23c9bbf3c9c43884535e3483486c4bc0826f`, unchanged proven head and reviewed changed paths, then merge with `expected_head_sha=<proven E01 SHA>`. Independently verify merge parents and tree identity before marking E01 COMPLETE.
