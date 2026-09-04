# E01 Secure Multi-Node Identity and Connection Design

## Status and authority

Approved design for Programme E01 — Secure multi-Node identity and connection.

Accepted implementation predecessor:

`f22d23c9bbf3c9c43884535e3483486c4bc0826f`

That commit is the independently verified D09 Full Workspace Release merge.

Accepted delivery authority:

- repository: `jaydumisuni/ptah-roadmap-`
- authority commit: `98dc8c4e8639cda80510bee0625db34b4fdf9384`
- package: Programme E01 — Secure multi-Node identity and connection
- dependencies: A15 and D06

The roadmap requires E01 to deliver Node enrollment, revision/Generation, a secure channel, capability announcements and reconnect. Placement, Reservation, Lease/Fence scheduling, Node-to-Node Object transfer, Workspace movement, platform-specific Node admission and intermittent/local-first reconciliation belong to E02–E06 and are explicitly outside E01.

## Goal

Allow several Ptah Nodes to enroll and establish authenticated, reconnectable control-plane links while preserving canonical `NodeId`, Node Generation, ConnectionEpoch, approved enrollment authority, evidence-bound capability truth and stale-owner fencing.

E01 must not make transport endpoints, certificate serial numbers, socket identifiers or backend connection IDs canonical Ptah identity.

## Architectural decision

E01 introduces a transport-neutral secure-link layer with TLS 1.3 mutual authentication as its first concrete transport.

The new crate is `crates/ptah-node-link`. It owns protocol framing, protocol negotiation, authenticated peer binding, connection fencing and transport abstraction. The existing `ptah-node-agent` remains the owner of canonical Node identity, Node Generation, ConnectionEpoch and evidence-bound capability snapshots. The existing `ptah-ledger` remains the durable canonical record repository. No E01-specific database migration or new Core entity family is introduced.

The concrete E01 transport is `TlsTcpTransport` implemented with Rustls over Tokio TCP. TLS provides channel confidentiality, peer authentication and key establishment; it does not define Ptah identity or protocol semantics. The Ptah application protocol is independently versioned as `ptah.node.link.v1`.

This separation is intentional so E03 or E06 may later add QUIC, direct-LAN, relay or other transports without changing Node identity, enrollment, generation or capability semantics.

## Canonical identity and non-identity

Canonical:

- `NodeId`;
- Node record revision;
- `NodeGeneration`;
- `ConnectionEpoch`;
- approved `core.node_enrollment` identity;
- configured Policy and trust-policy references;
- evidence and Receipt references;
- capability snapshot identity and its exact Node/Generation/epoch binding.

Non-canonical transport evidence:

- IP address;
- hostname;
- DNS name;
- TCP port;
- socket handle;
- TLS session identifier;
- certificate serial number;
- backend connection ID.

Changing network location, certificate or transport implementation must not create a new canonical Node when the approved enrollment and `NodeId` remain the same.

## Frozen contracts reused

E01 consumes the already frozen runtime model:

- `urn:ptah:schema:runtime:node:0.1.0`;
- `urn:ptah:schema:runtime:node-enrollment:0.1.0`;
- `urn:ptah:schema:runtime:node-observation:0.1.0`;
- `urn:ptah:schema:runtime:node-capability-snapshot:0.1.0`;
- `node.enrollment.lifecycle` v0.1.1;
- `node.lifecycle` v0.1.0.

E01 also consumes D06 `TrustPolicyProjection` as trust configuration evidence. It does not reinterpret D06 signing/provenance verdicts as Node enrollment approval.

## Components

### `ptah-node-agent`

Remains the canonical Node runtime substrate.

E01 may extend it only where required to expose safe mechanical checks over existing identity state. It must not make certificates or network endpoints part of `NodeId`.

### `ptah-node-link`

New library crate with focused modules:

- `protocol.rs` — versioned message envelope and bounded E01 messages;
- `framing.rs` — length-delimited bounded framing;
- `transport.rs` — transport-neutral async connection traits;
- `tls.rs` — TLS 1.3 mutual-auth transport implementation and peer certificate evidence extraction;
- `enrollment.rs` — approved enrollment projection used to bind a peer certificate fingerprint to a `NodeId` and accepted role scope;
- `session.rs` — authenticated Node/Generation/epoch session state, supersession and stale-link fencing;
- `error.rs` — stable E01 failure classes.

### `services/ptah-node`

Becomes the Node-side E01 client process boundary. It loads caller-configured Node restart/enrollment/trust material, establishes the secure transport, sends `NodeHello`, announces capability snapshots, emits heartbeats and reconnects using the next `ConnectionEpoch` supplied by the canonical Node runtime state.

The service does not invent enrollment approval, placement or work dispatch.

### `services/ptah-control`

Adds the accepting E01 control-plane boundary. It accepts secure links, verifies the authenticated certificate against an approved enrollment, negotiates `ptah.node.link.v1`, applies Node Generation/ConnectionEpoch fencing and persists accepted canonical enrollment/Node/capability records through existing repository boundaries.

## Enrollment authority

Enrollment follows the frozen `core.node_enrollment` lifecycle.

1. A request is recorded with proposed Node identity evidence, requested role keys, Policy and requestor.
2. Review is explicit and separate from transport establishment.
3. Approval requires authorized approver evidence plus credential/certificate evidence as required by the frozen lifecycle.
4. Only approved, unexpired and unrevoked enrollment authority may authenticate an E01 link.
5. Rejected, revoked and expired enrollment identities fail closed.
6. E01 never self-approves an enrollment because a TLS handshake succeeds.

Approved enrollment stores certificate/key references or fingerprints as evidence. Private key bytes are never written to the Ptah ledger, Events, Receipts or logs.

## Certificate rotation

Credential rotation must not change `NodeId`.

An approved enrollment projection may contain more than one currently valid credential fingerprint during an explicit overlap window. A connection is accepted when its authenticated certificate fingerprint matches one currently approved credential reference and all enrollment lifecycle/expiry checks pass.

Removal/revocation of the old credential prevents new sessions with it. Existing sessions using a revoked credential are fenced when revocation is observed by the control plane.

## Wire protocol

Protocol identifier: `ptah.node.link.v1`.

Every frame has:

- protocol identifier;
- protocol minor version;
- message kind;
- message identifier;
- payload length;
- payload.

Maximum serialized frame size is 1 MiB in E01. Frames larger than the limit are rejected before allocation of an unbounded payload.

E01 message kinds:

- `hello`;
- `hello_ack`;
- `capability_announcement`;
- `heartbeat`;
- `ack`;
- `error`;
- `close`.

No E01 message carries remote Activity dispatch, Reservation, Lease allocation, Object bytes or Workspace checkpoint bundles.

## Protocol negotiation

`NodeHello` carries:

- supported protocol major/minor range;
- exact `NodeId`;
- exact `NodeGeneration`;
- requested `ConnectionEpoch`;
- exact approved enrollment reference;
- agent revision;
- optional current capability snapshot reference.

Control selects a mutually supported protocol version. Unsupported major versions fail closed with a stable protocol-incompatible outcome. Minor negotiation may select the highest mutually supported minor version without changing canonical identity.

## TLS transport

E01 TLS rules:

- TLS 1.3 only;
- mutual certificate authentication;
- no plaintext downgrade;
- trust roots supplied from configured D06-compatible trust policy material;
- peer certificate evidence is extracted and mechanically bound to the approved Node enrollment;
- hostname/IP identity is not sufficient to establish a Ptah Node identity;
- certificate verification success alone is not sufficient to establish enrollment approval;
- private key material is supplied from configured files/secret handles and never retained as Ptah record content.

`TlsTcpTransport` is only the first implementation of the transport interface.

## Session binding and fencing

An authenticated E01 session is bound to:

`NodeId + NodeGeneration + ConnectionEpoch + approved enrollment + authenticated credential fingerprint`.

Rules:

- different `NodeId` on an otherwise valid credential binding fails;
- older Node Generation fails;
- same Generation with an older or equal already-consumed ConnectionEpoch fails;
- a higher ConnectionEpoch on the same Generation is a reconnect and supersedes the previous active connection;
- a higher accepted Node Generation preserves `NodeId` but creates fresh runtime authority and fences all older-generation connections;
- after supersession, the old connection may not publish capability or heartbeat state even if the socket remains physically open;
- generation/epoch checks happen again at message acceptance, not only during `hello`.

## Capability announcements

Capability truth remains evidence-bound.

A capability announcement contains the serialized existing `NodeCapabilitySnapshot` projection plus supporting canonical references. Control accepts it only when:

- the channel is authenticated;
- enrollment is still approved/current;
- snapshot `node_ref` identifies the authenticated Node;
- snapshot Node Generation equals the session Generation;
- snapshot ConnectionEpoch equals the session epoch;
- required observation, verification and Receipt references satisfy the existing A02 constructor rules;
- the session has not been superseded.

Transport receipt of a capability claim does not make the capability semantically useful or eligible for placement. E02 owns dispatch eligibility and placement.

## Reconnect and recovery

Network disconnect does not change `NodeId` or Node Generation.

Reconnect within the same running Node agent advances `ConnectionEpoch` and establishes a new E01 session. Agent/Node restart advances both Node Generation and ConnectionEpoch according to the existing A02 restart rules.

Control restart must recover approved enrollment and latest canonical Node state from the ledger. A reconnect is accepted only after the recovered state passes the same Generation/epoch and enrollment checks as a continuously running control plane.

## Backpressure and bounded resources

- maximum frame size: 1 MiB;
- per-connection inbound frame queue: bounded;
- per-connection outbound frame queue: bounded;
- heartbeat processing is constant-space;
- repeated invalid frames terminate the connection rather than growing retained state;
- capability announcements are snapshots/references, not unbounded Object payloads;
- large transfer semantics remain E03.

## Error classes

E01 exposes stable mechanical failure classes including:

- protocol incompatible;
- frame too large;
- malformed frame;
- TLS peer unauthenticated;
- unapproved enrollment;
- enrollment revoked;
- enrollment expired;
- credential not bound to enrollment;
- Node identity mismatch;
- stale Node Generation;
- stale ConnectionEpoch;
- superseded connection;
- capability identity mismatch;
- capability evidence incomplete;
- trust configuration invalid.

Errors may retain bounded evidence but may not leak private key material or unrestricted certificate contents.

## Security and adversarial proof

E01 must mechanically prove failure for:

- plaintext connection attempt;
- wrong CA;
- certificate signed by a trusted CA but not bound to the claimed enrollment;
- certificate bound to a different `NodeId`;
- unapproved enrollment;
- rejected enrollment;
- revoked enrollment;
- expired enrollment;
- replayed stale Node Generation;
- replayed/equal consumed ConnectionEpoch;
- superseded connection publishing after a newer epoch is accepted;
- capability snapshot with another Node identity;
- capability snapshot with stale Generation;
- capability snapshot with stale epoch;
- malformed frame;
- frame larger than 1 MiB;
- unsupported protocol major;
- private-key material appearing in logs or retained proof.

## Positive and recovery proof

E01 must prove:

- two independently enrolled Nodes connect concurrently;
- each retains its own stable `NodeId`;
- both announce independently evidence-bound capability snapshots;
- disconnect/reconnect preserves Node identity and advances epoch;
- Node-agent restart preserves Node identity and advances Generation;
- old Generation and old epoch are fenced;
- control-plane restart/reopen preserves enrollment and stale-link protection;
- credential rotation preserves Node identity while accepting only currently approved credentials;
- full locked workspace tests remain green;
- D09 acceptance remains green as predecessor regression evidence.

## Dependency policy

Use the repository's existing Rust 1.97.1 exact-pin policy.

New cryptographic/network dependencies must be exact-pinned in workspace dependencies and included in the current dependency/source/licence audit. Prefer Rustls ecosystem crates with no OpenSSL/native TLS dependency.

No dependency may introduce a Git source.

## Public/private boundary

E01 is public, generic distributed-Ptah infrastructure. No THETECHGUY private hostnames, private CA material, customer information, machine-specific credentials or secret paths enter source, fixtures or retained public evidence.

Test certificates/keys must be ephemeral or static non-production fixtures clearly marked test-only and may not resemble production credentials.

## Explicit non-goals

E01 does not implement:

- automatic Node placement;
- resource Reservation;
- work Lease allocation;
- E02 scheduling Fence ownership;
- Activity dispatch;
- Node-to-Node Object transfer;
- large binary transfer over the control link;
- Workspace migration;
- platform-specific Windows/macOS/Android Node admission;
- offline queue reconciliation;
- shared POSIX storage;
- semantic capability selection;
- autonomous enrollment approval.

## Exit gate

E01 is complete only when one frozen exact candidate:

1. passes all positive, negative and recovery E01 tests;
2. passes format, strict Clippy and full locked workspace tests;
3. retains exact dependency/source/licence evidence;
4. retains a permanent exact-head E01 proof artifact;
5. passes review with no unresolved authority drift;
6. is merged with an expected-head guard;
7. is independently verified on `main`, including merge parents and tree identity.

Only then may E02 begin from the accepted E01 merge.