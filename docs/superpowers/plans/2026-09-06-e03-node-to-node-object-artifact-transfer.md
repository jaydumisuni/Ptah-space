# E03 Node-to-Node Object and Artifact Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a separate authenticated E03 bulk data plane that moves exact A08/B01 bytes directly or through an explicit relay between current E01 Nodes, resumes by verified ranges, applies explicit cache policy, and never manufactures A07 canonical truth.

**Architecture:** `ptah-control` issues short-lived transfer tickets bound to exact E01 source/target sessions and exact A08 transfer identities. A new `ptah-node-transfer` crate carries bounded E03 control frames plus raw range payloads over the existing TLS 1.3 identity/trust machinery; `ptah-transfer` owns E03 ticket/route/cache mechanics and reuses B01/A08 resume truth. Direct and relay routes are explicit inputs; E06 discovery/relay selection remains out of scope.

**Tech Stack:** Rust 1.97.1, Tokio 1.48.0, Rustls 0.23.43, tokio-rustls 0.26.4, Serde/serde_json, SHA-256 via sha2, existing `ptah-identifiers`, `ptah-node-link`, `ptah-transfer`, `ptah-object-store`, `ptah-ledger` and service crates.

**Spec:** `docs/superpowers/specs/2026-09-06-e03-node-to-node-object-artifact-transfer-design.md`

## Global Constraints

- Accepted predecessor is E02 release `4b745e7ee0712df0458c1adf55feafdbcc42d9d4`.
- E03 roadmap dependencies are E01 and B01; E03 must not require E02 dispatch Lease/Fence authority for byte transfer.
- Bulk payload bytes never use the E01 `ptah.node.link.v1` JSON frame stream.
- E03 reuses E01 TLS 1.3 certificate/trust machinery and introduces no second PKI or Node identity family.
- A08 Request/Run/Manifest/Progress/Verification remains canonical transfer truth.
- B01 verified-range resume/source-digest mechanics remain canonical transfer mechanics.
- A07 remains the sole canonical Content/Object/Revision/Artifact/Location acceptance boundary.
- Route candidates are explicit; no automatic LAN discovery, relay discovery, relay selection, offline queue or local-first reconciliation.
- Initial relay is single-hop.
- Rust remains `#![forbid(unsafe_code)]`; workspace Clippy warnings are denied at release.
- No new registry dependency is authorized unless evidence proves the existing pinned workspace cannot implement the requirement.

---

## File Structure Lock

### `crates/ptah-transfer`

- Create `src/e03/mod.rs` — public E03 domain exports and stable error type.
- Create `src/e03/authority.rs` — Node binding, route candidate and `TransferTicket` validation.
- Create `src/e03/cache.rs` — explicit verified-cache policy/decision mechanics.
- Create `src/e03/resume.rs` — bridge between E03 ticket identity and existing B01 `DownloadCursor`/verified ranges without a second cursor family.
- Create `tests/e03_authority.rs` — ticket/session/route negative and positive cases.
- Create `tests/e03_cache_resume.rs` — cache and retained-range cases.
- Modify `src/lib.rs` — export E03 module.
- Modify `Cargo.toml` — add explicit E03 test targets only; no new third-party dependency.

### `crates/ptah-node-transfer`

- Create `Cargo.toml` — path dependencies on `ptah-identifiers`, `ptah-node-link`, `ptah-transfer`; workspace serde/serde_json/sha2/thiserror/tokio.
- Create `src/lib.rs` — protocol constants and public exports.
- Create `src/protocol.rs` — versioned E03 control messages.
- Create `src/framing.rs` — bounded JSON control framing plus bounded raw range payload framing.
- Create `src/direct.rs` — direct source/target range session orchestration over E01 TLS helpers.
- Create `src/relay.rs` — explicit single-hop relay broker/pairing and forwarding.
- Create `src/error.rs` — stable data-plane failure classes.
- Create `tests/protocol.rs` — serialization/version/size tests.
- Create `tests/framing.rs` — oversize/short-payload/corruption tests.
- Create `tests/direct_tls.rs` — real loopback TLS direct transfer.
- Create `tests/relay_tls.rs` — real loopback TLS relay path.

### `services/ptah-control`

- Create `src/transfer.rs` — E03 ticket issuer/registry using current E01 `SessionBinding` only.
- Create `tests/e03_transfer_authority.rs` — source/target currentness, expiry, route and reissue tests.
- Modify `src/e01_lib.rs` — export `transfer`.
- Modify `Cargo.toml` — add `ptah-transfer` and test dependencies needed by the authority tests.

### `services/ptah-node`

- Create `src/transfer.rs` — Node-local accepted-ticket guard and E03 source/target service configuration.
- Create `tests/e03_transfer_guard.rs` — stale Node/session/credential/ticket tests.
- Create `tests/e03_direct_resume.rs` — multi-megabyte direct interruption/resume using real E03 TLS data plane.
- Create `tests/e03_relay_resume.rs` — direct failure followed by explicit relay continuation of missing ranges.
- Modify `src/lib.rs` — export Node transfer guard/service surface without mixing it into E02 dispatch logic.
- Modify `Cargo.toml` — add `ptah-node-transfer`, `ptah-transfer`, `sha2`, and test-only object-store helpers as needed.

### Proof and release

- Create `conformance/e03/node-transfer-cases.v0.1.0.json`.
- Create `tools/check_e03_node_transfer.py`.
- Create `tools/test_check_e03_node_transfer.py`.
- Create `.github/workflows/e03-tdd.yml`.
- Create `.github/workflows/e03-node-to-node-object-artifact-transfer.yml`.
- Create `E03_NODE_TO_NODE_OBJECT_ARTIFACT_TRANSFER.md`.

---

### Task 1: E03 Transfer Authority, Route and Cache Domain

**Files:**
- Create: `crates/ptah-transfer/src/e03/mod.rs`
- Create: `crates/ptah-transfer/src/e03/authority.rs`
- Create: `crates/ptah-transfer/src/e03/cache.rs`
- Create: `crates/ptah-transfer/src/e03/resume.rs`
- Create: `crates/ptah-transfer/tests/e03_authority.rs`
- Create: `crates/ptah-transfer/tests/e03_cache_resume.rs`
- Modify: `crates/ptah-transfer/src/lib.rs`
- Modify: `crates/ptah-transfer/Cargo.toml`

**Interfaces:**
- Consumes: `ptah_identifiers::{NodeId, NodeGeneration, ConnectionEpoch, EntityRef}`, B01 `DownloadCursor`/`VerifiedRange`, A08 `TransferMode`.
- Produces:
  - `TransferPeerRole::{Source, Target}`
  - `TransferPeerBinding { node_id, node_generation, connection_epoch, credential_fingerprint }`
  - `TransferRouteKind::{Direct, Relay}`
  - `TransferRouteCandidate { kind, endpoint, server_name, expected_peer_fingerprint, relay_ref }`
  - `TransferCachePolicy::{RequireNetworkTransfer, ReuseVerifiedLocalContent}`
  - `TransferTicket`
  - `VerifiedCacheEvidence`
  - `CacheDecision::{NetworkTransfer, ReuseVerified { content_ref, location_ref }}`
  - `validate_resume_cursor(&TransferTicket, &DownloadCursor, &Path) -> Result<(), E03TransferError>`

- [ ] **Step 1: Write RED authority tests**

Create tests that construct two exact peer bindings and one `TransferTicket`:

```rust
let ticket = TransferTicket::new(
    reference("transfer.ticket"),
    reference("transfer.request"),
    reference("transfer.run"),
    reference("activity.attempt"),
    source_binding(),
    target_binding(),
    Some(reference("storage.content")),
    Some(reference("storage.artifact")),
    5 * 1024 * 1024,
    digest('a'),
    1024 * 1024,
    vec![direct_route(), relay_route()],
    100,
    200,
    7,
)?;
assert_eq!(ticket.transfer_mode(), TransferMode::NodeToNode);
assert!(ticket.authorize_peer(TransferPeerRole::Source, &source_binding(), 150).is_ok());
assert!(matches!(
    ticket.authorize_peer(TransferPeerRole::Source, &stale_source_generation(), 150),
    Err(E03TransferError::NodeGenerationMismatch)
));
assert!(matches!(ticket.authorize_peer(TransferPeerRole::Target, &target_binding(), 201), Err(E03TransferError::ExpiredTicket)));
```

Also prove zero-size invalidity for a non-empty declared content transfer, zero range size rejection, malformed digest rejection, duplicate route rejection and unauthorized route rejection.

- [ ] **Step 2: Run RED test**

Run:

```bash
cargo test -p ptah-transfer --test e03_authority --locked
```

Expected: compile failure because E03 types do not exist.

- [ ] **Step 3: Implement minimal authority types**

Use Serde-compatible structs and typed errors. `TransferTicket::new` validates:

```rust
if expected_size == 0 || range_size == 0 { return Err(E03TransferError::InvalidGeometry); }
if !is_sha256(&canonical_sha256) { return Err(E03TransferError::InvalidCanonicalDigest); }
if issued_at_unix_seconds >= expires_at_unix_seconds { return Err(E03TransferError::InvalidLifetime); }
if routes.is_empty() { return Err(E03TransferError::NoAuthorizedRoute); }
```

`authorize_peer` must compare stable Node identity, Generation, ConnectionEpoch and credential fingerprint exactly before checking expiry success.

- [ ] **Step 4: Run authority GREEN**

```bash
cargo test -p ptah-transfer --test e03_authority --locked
```

Expected: PASS.

- [ ] **Step 5: Write RED cache/resume tests**

Prove:

```rust
assert_eq!(
    decide_cache(&ticket, TransferCachePolicy::ReuseVerifiedLocalContent, Some(&verified_match()))?,
    CacheDecision::ReuseVerified { content_ref: reference("storage.content"), location_ref: reference("storage.location") }
);
assert!(matches!(
    decide_cache(&ticket, TransferCachePolicy::ReuseVerifiedLocalContent, Some(&unverified_match())),
    Err(E03TransferError::UnverifiedCacheEvidence)
));
```

Create a 2 MiB partial file, retain one `VerifiedRange`, mutate one retained byte and prove `validate_resume_cursor` returns `RetainedRangeDigestMismatch`.

- [ ] **Step 6: Implement cache and resume bridge**

`decide_cache` compares exact size and canonical SHA-256 and requires `verified == true`. `validate_resume_cursor` delegates geometry truth to existing B01 cursor semantics and re-reads retained ranges from the partial file before reuse; do not define a second verified-range map.

- [ ] **Step 7: Run Task 1 GREEN**

```bash
cargo test -p ptah-transfer --test e03_authority --test e03_cache_resume --locked
cargo test -p ptah-transfer --test b01 --test b01_source_mutation --locked
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/ptah-transfer
git commit -m "feat(e03): add transfer ticket route and cache authority"
```

---

### Task 2: Separate E03 Protocol and Framing Crate

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/ptah-node-transfer/Cargo.toml`
- Create: `crates/ptah-node-transfer/src/lib.rs`
- Create: `crates/ptah-node-transfer/src/protocol.rs`
- Create: `crates/ptah-node-transfer/src/framing.rs`
- Create: `crates/ptah-node-transfer/src/error.rs`
- Create: `crates/ptah-node-transfer/tests/protocol.rs`
- Create: `crates/ptah-node-transfer/tests/framing.rs`

**Interfaces:**
- Consumes: E01 TLS helpers and `CredentialFingerprint`; E03 ticket references/types.
- Produces:
  - `PROTOCOL_ID: &str = "ptah.node.transfer.v1"`
  - `MAX_CONTROL_FRAME_BYTES: usize = 65_536`
  - `MAX_RANGE_BYTES: usize = 1_048_576`
  - `TransferProtocolVersion { major: u16, minor: u16 }`
  - `TransferHello`, `TransferHelloAck`, `RangeRequest`, `RangeDataHeader`, `RangeAck`, `TransferComplete`, `TransferErrorFrame`, `TransferControlMessage`
  - `read_control_frame`, `write_control_frame`, `read_range_payload`, `write_range_payload`

- [ ] **Step 1: Write RED protocol tests**

```rust
assert_eq!(PROTOCOL_ID, "ptah.node.transfer.v1");
assert_eq!(MAX_CONTROL_FRAME_BYTES, 65_536);
assert_eq!(MAX_RANGE_BYTES, 1_048_576);
let encoded = serde_json::to_vec(&TransferControlMessage::RangeRequest(RangeRequest {
    ticket_ref: reference("transfer.ticket"),
    start: 0,
    len: 1_048_576,
}))?;
let decoded: TransferControlMessage = serde_json::from_slice(&encoded)?;
assert_eq!(decoded.kind(), "range_request");
```

- [ ] **Step 2: Run RED protocol test**

```bash
cargo test -p ptah-node-transfer --test protocol --locked
```

Expected: package not found.

- [ ] **Step 3: Add crate and protocol types**

Add `crates/ptah-node-transfer` to workspace members. Keep protocol major `1`; incompatible majors return `TransferDataError::ProtocolIncompatible`.

- [ ] **Step 4: Write RED framing tests**

Use `tokio::io::duplex` to prove:

- control frame `MAX_CONTROL_FRAME_BYTES + 1` is rejected;
- `RangeDataHeader.len > MAX_RANGE_BYTES` is rejected before allocation;
- short payload EOF is rejected;
- payload SHA-256 mismatch returns `RangeDigestMismatch`;
- exact 1 MiB payload passes.

- [ ] **Step 5: Implement framing**

Control framing is 4-byte network-order length + JSON payload. Range payload framing is a validated `RangeDataHeader` control frame followed by exactly `len` raw bytes. Hash raw payload before returning success.

- [ ] **Step 6: Run Task 2 GREEN**

```bash
cargo test -p ptah-node-transfer --test protocol --test framing --locked
cargo test -p ptah-node-link --locked
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/ptah-node-transfer
git commit -m "feat(e03): add bounded node transfer data-plane protocol"
```

---

### Task 3: Control-Issued Transfer Ticket Authority

**Files:**
- Create: `services/ptah-control/src/transfer.rs`
- Create: `services/ptah-control/tests/e03_transfer_authority.rs`
- Modify: `services/ptah-control/src/e01_lib.rs`
- Modify: `services/ptah-control/Cargo.toml`

**Interfaces:**
- Consumes: `NodeLinkControl`/`SessionRegistry` current E01 `SessionBinding`, `CredentialFingerprint`, E03 `TransferTicket`.
- Produces:
  - `TransferTicketSpec`
  - `TransferAuthorityOwner::issue_ticket(...) -> Result<TransferTicket, TransferAuthorityError>`
  - `TransferAuthorityOwner::assert_current(&TransferTicket) -> Result<(), TransferAuthorityError>`
  - `TransferAuthorityOwner::revoke_ticket(&EntityRef)`

- [ ] **Step 1: Write RED authority-owner tests**

Register two current E01 sessions, then prove issuance copies exact Node/Generation/epoch/fingerprint into the ticket. Replace the source session with a newer epoch and prove `assert_current(old_ticket)` returns `SupersededSourceSession`.

Also prove:

- same Node cannot be source and target for E03 NodeToNode ticket;
- source/target must both be current;
- `expires_at <= now` rejects;
- route list is preserved exactly and not discovered/expanded;
- revocation blocks subsequent use;
- reissue after source reconnect creates new ticket identity/nonce while retaining the exact A08 Run binding supplied by caller.

- [ ] **Step 2: Run RED test**

```bash
cargo test -p ptah-control --test e03_transfer_authority --locked
```

Expected: compile failure because transfer authority owner does not exist.

- [ ] **Step 3: Implement minimal issuer**

Do not persist ephemeral tickets as canonical A08 truth. Store active tickets only for current control-process admission/revocation. `assert_current` must recheck both source and target through `SessionRegistry::assert_current` or exact current-session access.

- [ ] **Step 4: Run Task 3 GREEN**

```bash
cargo test -p ptah-control --test e03_transfer_authority --locked
cargo test -p ptah-control --test e02_placement --locked
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/ptah-control
git commit -m "feat(e03): issue session-bound transfer tickets from control"
```

---

### Task 4: Node-Local Ticket Guard

**Files:**
- Create: `services/ptah-node/src/transfer.rs`
- Create: `services/ptah-node/tests/e03_transfer_guard.rs`
- Modify: `services/ptah-node/src/lib.rs`
- Modify: `services/ptah-node/Cargo.toml`

**Interfaces:**
- Consumes: live `NodeAgent`, E03 `TransferTicket`, authenticated peer `CredentialFingerprint`.
- Produces:
  - `NodeTransferGuard::for_agent(&NodeAgent) -> Self`
  - `accept_ticket(&mut self, &NodeAgent, TransferPeerRole, &TransferTicket, now) -> Result<(), NodeTransferError>`
  - `authorize_peer(&self, &NodeAgent, &TransferTicket, peer_fingerprint, now) -> Result<(), NodeTransferError>`
  - `ticket(&EntityRef) -> Option<&TransferTicket>`

- [ ] **Step 1: Write RED guard tests**

Prove source and target accept only their own exact side of the ticket. Reboot/reconnect the `NodeAgent` so Generation/epoch changes and prove old ticket rejection before any range is authorized. Present wrong peer fingerprint and wrong ticket role and prove fail-closed errors.

- [ ] **Step 2: Run RED test**

```bash
cargo test -p ptah-node --test e03_transfer_guard --locked
```

Expected: compile failure because guard does not exist.

- [ ] **Step 3: Implement Node guard**

Keep E03 state separate from `NodeDispatchGuard`; no E02 Fence fields or scheduling policy are imported into E03.

- [ ] **Step 4: Run Task 4 GREEN**

```bash
cargo test -p ptah-node --test e03_transfer_guard --locked
cargo test -p ptah-node --test e02_dispatch_guard --locked
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/ptah-node
git commit -m "feat(e03): add node transfer ticket guard"
```

---

### Task 5: Real Direct TLS Range Transfer

**Files:**
- Create: `crates/ptah-node-transfer/src/direct.rs`
- Create: `crates/ptah-node-transfer/tests/direct_tls.rs`
- Create: `services/ptah-node/tests/e03_direct_resume.rs`
- Modify: `crates/ptah-node-transfer/src/lib.rs`

**Interfaces:**
- Consumes: E01 `TlsServerConfig`, `TlsClientConfig`, `accept_tls`, `connect_tls`; accepted E03 ticket; exact-range source adapter; B01 `DownloadCursor`.
- Produces:
  - `ExactRangeSource` trait with `len()`, `canonical_sha256()`, `read_exact_range(start, len)`
  - `DirectSourceSession::serve(...)`
  - `DirectTargetSession::pull_missing_ranges(...) -> DirectTransferReport`
  - report fields: route kind, requested ranges, accepted ranges, network bytes, whole SHA-256, failures.

- [ ] **Step 1: Write RED real-TLS handshake test**

Generate test CA/source/target certificates using the existing E01 test-certificate fixture pattern. Bind a loopback `TcpListener`, authenticate the stream with existing E01 TLS helpers, exchange `TransferHello`/Ack and assert the authenticated peer fingerprint equals the ticket-bound fingerprint.

- [ ] **Step 2: Run RED direct test**

```bash
cargo test -p ptah-node-transfer --test direct_tls --locked
```

Expected: compile failure because direct session API does not exist.

- [ ] **Step 3: Implement direct pull protocol**

Target requests each missing fixed-size range. Source validates range against ticket geometry before reading. Target writes to private partial file, `sync_data`, re-reads, verifies digest, then marks the existing B01 cursor range verified.

- [ ] **Step 4: Add multi-megabyte interruption/resume test**

Use deterministic 5 MiB + 123 byte source bytes and 1 MiB range size. First pass accepts exactly two ranges, closes transport, then reconnects with a fresh route session under the same still-current ticket and requests only remaining ranges.

Assert:

```rust
assert_eq!(first.network_bytes, 2 * 1024 * 1024);
assert_eq!(second.resumed_ranges, 2);
assert_eq!(second.network_bytes, source.len() as u64 - first.network_bytes);
assert_eq!(sha256_file(&destination), source_sha256);
assert!(source.len() > ptah_node_link::MAX_FRAME_BYTES);
```

- [ ] **Step 5: Run Task 5 GREEN**

```bash
cargo test -p ptah-node-transfer --test direct_tls --locked
cargo test -p ptah-node --test e03_direct_resume --locked
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/ptah-node-transfer services/ptah-node
git commit -m "feat(e03): transfer exact ranges directly between authenticated nodes"
```

---

### Task 6: Explicit Single-Hop Relay Fallback

**Files:**
- Create: `crates/ptah-node-transfer/src/relay.rs`
- Create: `crates/ptah-node-transfer/tests/relay_tls.rs`
- Create: `services/ptah-node/tests/e03_relay_resume.rs`
- Modify: `crates/ptah-node-transfer/src/lib.rs`

**Interfaces:**
- Consumes: ticket-authorized relay route, source/target E03 TLS sessions, same range protocol used by direct path.
- Produces:
  - `RelayBroker::new(ticket_registry)`
  - `RelayBroker::register_source(...)`
  - `RelayBroker::register_target(...)`
  - single-hop `forward_range` behavior with no canonical storage API.

- [ ] **Step 1: Write RED relay-auth tests**

Prove relay rejects:

- ticket without its exact relay candidate;
- wrong relay TLS fingerprint;
- two source peers for one ticket;
- target for another ticket;
- expired ticket.

- [ ] **Step 2: Run RED relay test**

```bash
cargo test -p ptah-node-transfer --test relay_tls --locked
```

Expected: compile failure because relay API does not exist.

- [ ] **Step 3: Implement bounded relay pairing/forwarding**

Relay keeps only bounded in-flight range bytes and ticket/session pairing state. It forwards `RangeRequest` and exact `RangeDataHeader + payload`; target still owns destination verification.

- [ ] **Step 4: Add direct-failure→relay-resume integration**

First direct route transfers one verified range then force-closes. The explicit second route is relay. Reconnect source and target to relay, continue only missing ranges, and assert final whole SHA-256 equals source.

Retain a report entry equivalent to:

```rust
RouteFailure { kind: TransferRouteKind::Direct, error: "connection_lost" }
```

and assert relay success does not erase it.

- [ ] **Step 5: Run Task 6 GREEN**

```bash
cargo test -p ptah-node-transfer --test relay_tls --locked
cargo test -p ptah-node --test e03_relay_resume --locked
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/ptah-node-transfer services/ptah-node
git commit -m "feat(e03): add explicit relay continuation for node transfer"
```

---

### Task 7: A08 Verification and A07 Cache/Acceptance Composition

**Files:**
- Create: `crates/ptah-transfer/tests/e03_a08_composition.rs`
- Create: `crates/ptah-object-store/tests/e03_cache_acceptance.rs`
- Modify: `crates/ptah-transfer/src/e03/cache.rs` only if tests expose missing exact evidence projection.
- Modify: minimal object-store public query surface only if no existing verified-location lookup can express exact Content digest/size verification.

**Interfaces:**
- Consumes: A08 `TransferEngine`, `VerificationDomain`, `AcceptedOutputRefs`; A07 verified Location read-back.
- Produces no new canonical record family.

- [ ] **Step 1: Write RED A08 nonclaim test**

Drive a successful E03 direct transfer to transport completion but do not perform required destination read-back/A07 acceptance. Assert the A08 Run cannot be accepted as fully verified solely from E03 route acknowledgement.

- [ ] **Step 2: Write RED verified-cache test**

Register exact bytes through A07, independently verify the Location, then call E03 cache decision with matching size/digest. Assert zero network bytes and exact existing Content/Location references are retained.

Mutate/unverify the local materialization and assert cache reuse fails closed.

- [ ] **Step 3: Implement the narrow composition**

Do not add new schemas. E03 emits transport evidence; A08 consumes it under existing verification domains. A07 acceptance occurs only through existing register/verify APIs.

- [ ] **Step 4: Run Task 7 GREEN**

```bash
cargo test -p ptah-transfer --test e03_a08_composition --locked
cargo test -p ptah-object-store --test e03_cache_acceptance --locked
cargo test -p ptah-transfer --test a08 --test b01 --locked
cargo test -p ptah-object-store --locked
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/ptah-transfer crates/ptah-object-store
git commit -m "test(e03): prove a08 and a07 transfer truth boundaries"
```

---

### Task 8: Restart, Reconnect and Concurrent Isolation

**Files:**
- Create: `services/ptah-node/tests/e03_recovery.rs`
- Modify: E03 guard/session files only when the RED recovery case identifies the necessary behavior.

**Interfaces:**
- Consumes: E01 reconnect semantics, A08/B01 durable resume state, control ticket reissue.
- Produces: no durable E03 ticket claim; old tickets become unusable after restart/reconnect.

- [ ] **Step 1: Write RED recovery tests**

Prove:

1. source Node Generation increments -> old ticket rejects;
2. target ConnectionEpoch increments -> old ticket rejects;
3. fresh ticket bound to same exact A08 Run can resume retained verified ranges;
4. control authority owner restart loses old ephemeral ticket admission, but reconstructed A08/B01 resume state remains usable after fresh ticket issuance;
5. two simultaneous transfers with distinct ticket/run refs cannot read or mark each other's ranges.

- [ ] **Step 2: Run RED recovery test**

```bash
cargo test -p ptah-node --test e03_recovery --locked
```

Expected: one or more explicit recovery cases fail.

- [ ] **Step 3: Implement minimum recovery fixes**

Do not persist E03 tickets as replacement A08 truth. Reissue after reconnect uses new ticket identity/nonce and exact current session bindings.

- [ ] **Step 4: Run Task 8 GREEN**

```bash
cargo test -p ptah-node --test e03_recovery --locked
cargo test -p ptah-node-link --locked
cargo test -p ptah-transfer --locked
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/ptah-node crates/ptah-transfer crates/ptah-node-transfer services/ptah-control
git commit -m "feat(e03): fence stale transfer tickets across recovery"
```

---

### Task 9: Freeze the 28-Case E03 Conformance Corpus

**Files:**
- Create: `conformance/e03/node-transfer-cases.v0.1.0.json`
- Create: `tools/check_e03_node_transfer.py`
- Create: `tools/test_check_e03_node_transfer.py`

**Interfaces:**
- Corpus fixed authority fields:
  - schema version `0.1.0`
  - record type `ptah.e03.node_transfer_acceptance_corpus`
  - accepted predecessor `4b745e7ee0712df0458c1adf55feafdbcc42d9d4`
  - control protocol `ptah.node.link.v1`
  - data protocol `ptah.node.transfer.v1`
  - exact case count `28`
- Scope-false fields include `workspace_movement_added`, `platform_node_admission_added`, `automatic_discovery_added`, `automatic_relay_selection_added`, `offline_queue_added`, `new_core_entity_required`.

- [ ] **Step 1: Write RED checker regression**

Use `unittest` to prove checker rejects missing case, duplicate case, unexpected case, false `passed`, changed predecessor/protocol, and any scope-false field set true.

- [ ] **Step 2: Run RED checker test**

```bash
python3 -m unittest -v tools/test_check_e03_node_transfer.py
```

Expected: FAIL until checker/corpus exist.

- [ ] **Step 3: Create exact 28-case corpus**

Case IDs must map one-to-one to design section 15:

```text
two_authenticated_nodes_large_object
bulk_bytes_not_e01_control_frame
direct_exact_integrity
interrupt_resume_missing_ranges_only
direct_failure_relay_continuation
route_change_preserves_verified_ranges
stale_source_generation_rejected
stale_target_epoch_rejected
wrong_peer_fingerprint_rejected
expired_ticket_rejected
wrong_a08_binding_rejected
wrong_content_artifact_binding_rejected
source_size_digest_mismatch_rejected
out_of_bounds_range_rejected
payload_length_mismatch_rejected
corrupt_range_rejected
corrupt_retained_partial_rejected
whole_digest_mismatch_rejected
verified_cache_hit_zero_network
unverified_cache_rejected
relay_no_a07_truth
a08_ack_not_final_verification
a07_acceptance_after_a08_verification_only
reconnect_fresh_ticket_resume
control_restart_ephemeral_ticket_loss
concurrent_transfer_state_isolation
no_e04_e05_e06_scope
inherited_regressions_exact_head
```

- [ ] **Step 4: Implement checker**

Require exact set equality, exact classes, expected==observed, `passed == true`, non-empty unique evidence arrays and false scope fields.

- [ ] **Step 5: Run Task 9 GREEN**

```bash
python3 -m unittest -v tools/test_check_e03_node_transfer.py
python3 tools/check_e03_node_transfer.py --repo-root . --output /tmp/e03-validation.json
```

Expected: PASS and validation report `status=pass`, `case_count=28`.

- [ ] **Step 6: Commit**

```bash
git add conformance/e03 tools/check_e03_node_transfer.py tools/test_check_e03_node_transfer.py
git commit -m "test(e03): freeze node transfer conformance corpus"
```

---

### Task 10: Development CI and Full Review

**Files:**
- Create: `.github/workflows/e03-tdd.yml`

**Interfaces:**
- Development workflow runs only branch-scoped E03 tests plus inherited E01/E02/A08/B01 tests, format and strict Clippy.
- External Actions remain immutable SHA pins matching repository policy.

- [ ] **Step 1: Add branch development workflow**

Use `ubuntu-24.04`, Rust `1.97.1`, Python `3.13`, immutable existing Action pins. Commands:

```bash
python3 -m unittest -v tools/test_check_e03_node_transfer.py
python3 tools/check_e03_node_transfer.py --repo-root . --output "$RUNNER_TEMP/e03-validation.json"
cargo test -p ptah-transfer --locked
cargo test -p ptah-node-transfer --locked
cargo test -p ptah-control --test e03_transfer_authority --locked
cargo test -p ptah-node --test e03_transfer_guard --test e03_direct_resume --test e03_relay_resume --test e03_recovery --locked
cargo test -p ptah-node-link --locked
cargo test -p ptah-placement-runtime --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

- [ ] **Step 2: Run branch workflow and inspect any failure as evidence**

Do not edit around an unknown failure. Read the exact failed step/log, correct the smallest observed defect, and rerun on the new SHA.

- [ ] **Step 3: Review complete diff against E03 design**

Check:

- no `schemas/` or `migrations/` drift;
- no raw secret/private-key output;
- no bulk bytes in `LinkMessage`;
- no E02 Lease/Fence dependency in E03 transfer admission;
- no automatic discovery/relay selection;
- no A07 truth claim from relay/cache/transport acknowledgement;
- every design proof case has a concrete automated test/evidence source.

- [ ] **Step 4: Commit review corrections only if evidence requires them**

Use focused commit messages naming the observed defect.

---

### Task 11: Permanent Exact-Head Proof and Milestone Record

**Files:**
- Create: `.github/workflows/e03-node-to-node-object-artifact-transfer.yml`
- Create: `E03_NODE_TO_NODE_OBJECT_ARTIFACT_TRANSFER.md`

**Interfaces:**
- Accepted predecessor: `4b745e7ee0712df0458c1adf55feafdbcc42d9d4`.
- Exact candidate is `${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}`.
- Retained artifact name: `e03-node-transfer-${TARGET_SHA}`.

- [ ] **Step 1: Write milestone record**

Record delivered boundary, 28-case corpus, nonclaims, accepted predecessor and release rule. Do not insert a candidate SHA before freeze; the workflow artifact supplies exact candidate identity.

- [ ] **Step 2: Add permanent exact-head workflow**

The workflow must prove, in order:

1. exact Rust/Python versions and exact candidate checkout;
2. `origin/main` still equals accepted predecessor before merge;
3. branch is linear from predecessor with no merge commit before release;
4. exact reviewed changed-path set and `git diff --check`;
5. immutable Action pins;
6. current dependency/source/licence policy and no new registry dependency;
7. E03 checker regression and exact 28-case corpus;
8. E03 authority/cache/resume tests;
9. real direct TLS multi-megabyte test;
10. real relay continuation test;
11. restart/reconnect/concurrency tests;
12. A08/A07 composition tests;
13. E01 and E02 regressions;
14. B01/A08 regressions;
15. D09/deep-Workspace checker regression;
16. rustfmt;
17. workspace Clippy `-D warnings`;
18. `cargo test --workspace --locked`;
19. textual secret/private-key scan;
20. retained proof-bundle validation and clean exact candidate;
21. immutable proof artifact upload.

- [ ] **Step 3: Freeze one exact candidate SHA**

After review corrections and temporary-tool cleanup, create a no-tree-change freeze commit if necessary so the candidate SHA itself contains the permanent workflow and milestone record.

- [ ] **Step 4: Prove push context**

Require permanent E03 run conclusion `success` and artifact bound to exact candidate SHA.

- [ ] **Step 5: Open release PR and prove the same SHA in PR context**

PR base must still be `main` at `4b745e7ee0712df0458c1adf55feafdbcc42d9d4`; PR head must equal the push-proven candidate SHA.

- [ ] **Step 6: Guarded merge**

Merge using GitHub expected-head protection:

```text
expected_head_sha = <exact push+PR proven E03 candidate>
merge_method = merge
```

- [ ] **Step 7: Post-merge verification**

Verify the merge commit has exactly:

```text
parent 1 = 4b745e7ee0712df0458c1adf55feafdbcc42d9d4
parent 2 = <proven E03 candidate>
tree     = <proven E03 candidate tree>
```

If any value differs, E03 is not complete.

- [ ] **Step 8: Final completion record**

Report merge commit, candidate SHA/tree, push run, PR run, artifact digests, PR number and next roadmap frontier E04.
