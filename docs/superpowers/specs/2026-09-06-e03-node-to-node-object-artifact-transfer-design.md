# E03 Node-to-Node Object and Artifact Transfer — Design

**Date:** 2026-09-06
**Status:** Approved implementation baseline under continuous Programme E execution
**Accepted predecessor:** E02 release `4b745e7ee0712df0458c1adf55feafdbcc42d9d4`

## 1. Purpose

E03 implements the Programme E distributed byte-movement boundary described by the accepted Ptah roadmap:

> Node-to-Node Object and Artifact transfer with direct and relay routes, resumable movement, cache policy and exact integrity verification.

E03 answers one question mechanically:

> Can this exact A08 transfer move the exact declared bytes from this exact current source Node to this exact current target Node, through an explicitly authorized route, and prove the destination bytes without inventing canonical Object/Artifact truth?

E03 does not replace A07 Object/Revision/Artifact/Location truth, A08 Request/Run/Manifest/Progress/Verification truth, B01 transfer mechanics, E01 Node identity/session truth, or E02 placement/Lease/Fence authority.

## 2. Architectural rule

E03 separates the control plane from the bulk data plane.

- E01 remains the authenticated Node-to-control control channel.
- `ptah-control` issues bounded E03 transfer authority over current E01 sessions.
- A new `ptah-node-transfer` data-plane protocol carries bulk ranges over TLS 1.3 using the already-proven E01 certificate and trust material.
- Direct Node-to-Node transfer is preferred only when an explicit direct route is supplied.
- Relay transfer uses an explicit relay endpoint when supplied; E03 does not discover peers or relays automatically.
- A08/B01 remain authoritative for logical transfer identity, resume state and transfer verification.
- A07 remains authoritative for canonical Content/Object/Revision/Artifact/Location acceptance.

The canonical progression is:

`A08 request/run -> current E01 source+target sessions -> E03 ticket -> explicit route -> range transfer -> exact range verification -> whole-byte verification -> A08 verification -> optional A07 acceptance`

No stage may infer the authority or success of a later stage.

## 3. Existing authorities retained

### 3.1 E01 Node/session truth

Every E03 authority is bound to exact current:

- `NodeId`;
- `NodeGeneration`;
- `ConnectionEpoch`;
- enrollment/credential identity;
- authenticated session currentness.

A reconnect with a newer Generation or ConnectionEpoch invalidates old E03 authority. E03 never treats IP address, DNS name, socket address, hostname or certificate alias as canonical Node identity.

### 3.2 A08 transfer truth

E03 consumes the existing A08 transfer vocabulary rather than creating a second transfer identity family.

The E03 ticket binds to existing A08 identities, at minimum:

- Transfer Request reference;
- Transfer Run reference;
- A04 Activity/Operation/Attempt evidence for the current physical try;
- `TransferMode::NodeToNode`;
- source descriptor;
- destination descriptor;
- resumability policy;
- requested verification domains.

Retry or resume under a new physical Attempt remains an A08 concern. E03 transport authority may be reissued for the same logical Run only when A08 permits the resume.

### 3.3 B01 mechanics

E03 reuses B01:

- verified-range resume cursor semantics;
- exact source-size/digest fencing;
- multi-source/range fallback mechanics where applicable;
- retained failed source attempts;
- deterministic local/remote queue policy;
- bounded export adapter semantics;
- explicit cache/dedup/retention distinctions.

E03 does not create an incompatible resume cursor.

### 3.4 A07 canonical byte/object truth

A successful E03 route proves only bounded transport evidence. It cannot by itself claim:

- Content registration;
- Object Revision acceptance;
- Artifact promotion;
- verified Storage Location registration;
- Workspace recovery.

Destination bytes become canonical A07 truth only through the existing independent acceptance/verification boundary.

### 3.5 E02 independence

E03 does not require E02 Reservation/Lease/Fence authority for the byte stream itself because the accepted roadmap defines E03 as depending on E01 and B01. E02 remains available to schedule Activities that happen to request E03 work, but E03 transport authority is not silently derived from an E02 dispatch Lease.

## 4. Transfer authority

`ptah-control` is the sole issuer of one short-lived `TransferTicket`.

A ticket binds:

- canonical ticket reference;
- exact A08 Request reference;
- exact A08 Run reference;
- exact current A04 Attempt reference;
- source Node identity, Generation and ConnectionEpoch;
- target Node identity, Generation and ConnectionEpoch;
- source and target enrollment/credential fingerprints or exact credential references required to validate the presented peers;
- exact canonical Content reference when available;
- optional exact Artifact reference when the requested source is an Artifact;
- exact expected byte count;
- exact canonical-content SHA-256;
- nominal range size;
- permitted route kinds;
- explicit ordered route candidates supplied by control/caller policy;
- issuance and expiry instants;
- bounded transfer nonce.

A ticket is authority to exchange only the declared byte range set for that exact A08 transfer. It is not authority to execute arbitrary Node work, access unrelated Objects, move a Workspace, discover Nodes, or mint new tickets.

Tickets are session-bound and fail closed after source or target session supersession. Control restart may discard live tickets; A08 durable resume state remains canonical and a fresh ticket may be issued after current authority is re-established.

## 5. Route model

### 5.1 Explicit route candidates

E03 supports two route kinds:

- `Direct` — source and target establish an authenticated E03 TLS stream directly.
- `Relay` — source and target establish authenticated E03 data-plane streams to a configured relay which forwards only ticket-authorized data.

Route candidates are explicit input. E03 does not scan LANs, discover Nodes, discover relays or choose from an ambient network. Those concerns remain E06.

### 5.2 Route fallback

A ticket may authorize an ordered route plan such as:

`Direct(endpoint A) -> Relay(endpoint R)`

A failed direct route may advance to the next explicitly authorized candidate without changing A08 logical transfer identity. Already verified destination ranges are retained and are not resent merely because the route changed.

The failure of the direct route remains evidence; relay success does not erase it.

### 5.3 Route endpoints are not identity

An endpoint is transport configuration only. Successful TLS plus ticket/session validation must resolve to the exact ticket-bound Node/relay authority. Socket address or DNS equality cannot substitute for Node identity.

## 6. E03 data-plane protocol

The stable protocol identifier is initially:

`ptah.node.transfer.v1`

The data plane uses the existing TLS 1.3 mutual-authentication machinery from `ptah-node-link`; it does not introduce a second PKI or enrollment system.

The protocol is separate from the E01 JSON frame stream so bulk bytes cannot head-of-line-block control-plane heartbeat, placement or dispatch traffic.

The initial protocol contains bounded control frames plus raw byte payloads:

1. `TransferHello` — protocol version, ticket reference, role, Node/session identity, nonce and requested range geometry.
2. `TransferHelloAck` — accepted protocol version, peer/session/ticket confirmation and maximum accepted chunk/range size.
3. `RangeRequest` — exact offset and length requested by the target or relay.
4. `RangeDataHeader` — exact offset, length and transport-chunk SHA-256 followed by raw payload bytes.
5. `RangeAck` — exact range digest accepted after destination write/read-back.
6. `TransferComplete` — whole-byte count and whole canonical-content SHA-256 observed at the destination.
7. `TransferError` — stable machine-readable failure code and bounded detail.
8. `Close` — graceful route termination.

Control frames are length-bounded. Payload length is independently bounded and must exactly match the declared range.

## 7. Direct transfer flow

1. Control validates both E01 sessions are current and issues matching ticket projections to source and target.
2. Target opens or already owns a configured E03 listener endpoint; endpoint configuration is explicit, not discovered.
3. Source connects with E01-proven TLS identity.
4. Both peers validate TLS 1.3, presented credential fingerprint, ticket identity, exact Node identity/Generation/epoch, role, expiry and nonce.
5. Target compares its retained B01/A08 resume state with the exact ticket source size/digest.
6. Target requests only missing ranges.
7. Source reads exact ranges from the authorized source materialization/provider boundary.
8. Target writes each range to private partial storage, flushes it, re-reads it and validates the chunk digest before marking it verified.
9. After all ranges are verified, target performs whole-byte SHA-256 verification.
10. E03 emits bounded transport evidence to A08. A08 then decides whether its requested verification domains are satisfied.
11. A07 acceptance occurs only if separately requested and independently verified.

## 8. Relay transfer flow

Relay is a transport intermediary, never canonical storage truth.

- Relay accepts only streams carrying a live ticket that explicitly permits the relay endpoint.
- Relay validates both source and target session/ticket projections before forwarding bytes.
- Relay cannot rewrite Request/Run/Content/Artifact identity, range geometry or expected digest.
- Relay may buffer only bounded transport chunks required for forwarding; it cannot claim Content/Location registration from that buffer.
- Target remains responsible for range and whole-byte destination verification.
- Relay failure is explicit and resumable through any remaining ticket-authorized route candidate.

The initial relay is single-hop. Multi-relay routing is outside E03 unless later evidence requires it.

## 9. Cache policy

E03 exposes an explicit cache decision before network transfer:

- `RequireNetworkTransfer` — transfer exact bytes even if a matching digest is locally available.
- `ReuseVerifiedLocalContent` — use a target-local A07-verified materialization only when exact size and canonical SHA-256 match the ticket.

A cache hit records:

- the ticket/Run identity;
- exact existing Content/Location evidence used;
- zero network bytes transferred;
- the exact policy that allowed reuse.

A cache hit cannot manufacture a new Artifact or silently create a new Location. Any requested replica/Location relationship still uses A07.

Unverified local bytes never satisfy cache reuse.

## 10. Resume and corruption semantics

Resume state is exact and fail-closed.

- The source size and canonical SHA-256 in retained state must match the current ticket.
- Every retained verified range is re-read before reuse.
- Corrupt retained partial bytes invalidate that range and block silent reuse.
- A received range whose payload length or SHA-256 differs from its header is rejected before it becomes verified.
- Wrong-range, overlapping or out-of-bounds data is rejected.
- Route change does not reset verified ranges.
- A target restart may resume only from durable B01/A08 state after current E01 session and a fresh compatible ticket are established.

## 11. Failure model

Stable failure classes include at minimum:

- incompatible data-plane protocol;
- unknown/expired/revoked ticket;
- source session stale;
- target session stale;
- wrong Node identity;
- wrong credential fingerprint;
- wrong A08 Request/Run/Attempt binding;
- wrong Content/Artifact binding;
- source-size mismatch;
- canonical digest mismatch;
- invalid route candidate;
- unauthorized relay;
- range out of bounds;
- range payload length mismatch;
- range digest mismatch;
- retained-partial digest mismatch;
- whole-content digest mismatch;
- route connect/transport failure;
- no remaining authorized route;
- target cache evidence absent/unverified.

A transport acknowledgement never equals destination verification.

## 12. Security and privacy boundary

- TLS 1.3 mutual authentication is mandatory for source, target and relay data-plane streams.
- Raw private keys never enter E03 records or logs.
- Tickets contain references/fingerprints, not secret credential material.
- Ticket scope is least-privilege: exact transfer, peers, routes, content identity, size, digest and expiry.
- Relay cannot enumerate unrelated tickets or Objects.
- Range requests outside the ticket byte domain fail closed.
- Error details are bounded and must not leak private paths, credentials or unrelated metadata.
- Existing repository secret and private-data scans remain release gates.

## 13. Scope exclusions

E03 does **not** implement or authorize:

- E04 Workspace movement/checkpoint restore;
- E05 platform-specific Node admission;
- E06 automatic discovery, relay discovery/selection, offline queues or local-first reconciliation;
- distributed shared POSIX storage;
- arbitrary peer file browsing;
- implicit global Object access;
- new canonical Content/Object/Artifact/Location identity families;
- new Node identity/enrollment/PKI;
- automatic conflict resolution;
- multi-hop relay meshes;
- QUIC unless later evidence demonstrates it is necessary.

## 14. Initial implementation decomposition

1. E03 domain/ticket/route/cache primitives in `ptah-transfer` or a narrow E03 module reusing A08/B01 types.
2. Separate `ptah-node-transfer` protocol/framing crate using existing E01 TLS identity/trust.
3. Node-side ticket registry and source/target guards.
4. Control-side ticket issuer bound to current E01 sessions.
5. Direct authenticated range transfer over real TCP/TLS.
6. Explicit single-hop relay path.
7. Durable resume composition with B01 verified ranges/A08 Run state.
8. A07 verified-cache lookup and post-transfer acceptance integration.
9. E03 conformance corpus, exact-head CI and retained proof bundle.

## 15. Proof boundary

E03 is not complete until retained exact-head evidence proves at least:

1. two concurrently authenticated Nodes exchange a multi-megabyte object over the E03 data plane;
2. E01 control framing remains bounded and is not used for bulk payload bytes;
3. direct transfer final byte count and SHA-256 equal the declared source;
4. interruption retains verified ranges and resume sends only missing ranges;
5. direct-route failure remains visible and an explicitly authorized relay continues the same A08 Run;
6. route change does not discard verified ranges;
7. stale source Generation rejects before payload bytes;
8. stale target ConnectionEpoch rejects before payload bytes;
9. wrong peer credential fingerprint rejects;
10. expired ticket rejects;
11. wrong Request/Run/Attempt binding rejects;
12. wrong Content/Artifact binding rejects;
13. wrong source size or digest rejects;
14. out-of-bounds range request rejects;
15. short/oversized range payload rejects;
16. corrupted range payload rejects and cannot become verified;
17. corrupted retained partial range is detected before reuse;
18. whole-content digest mismatch blocks completion;
19. exact verified target cache hit records zero network bytes;
20. unverified cache bytes cannot satisfy the transfer;
21. relay cannot claim A07 Location/Artifact success;
22. A08 transport acknowledgement alone cannot claim final transfer verification;
23. A07 acceptance occurs only after required A08 verification succeeds;
24. source/target reconnect invalidates old ticket and fresh compatible authority can resume;
25. control restart loses ephemeral ticket authority without losing durable A08 resume truth;
26. two independent E03 transfers do not alias ticket/run/range state;
27. no E04/E05/E06 scope is introduced;
28. full inherited E01, E02, A08, B01 and workspace regressions remain green at the exact release head.

## 16. Release discipline

E03 follows the established Programme E release process:

1. review the complete branch delta against this design;
2. correct findings before freeze;
3. remove temporary maintenance tooling;
4. freeze one exact candidate SHA;
5. prove that SHA in push context;
6. prove the same SHA in PR context;
7. retain exact-head proof artifacts;
8. guarded merge with expected head SHA;
9. verify merge parents and merged tree exactly equal the accepted predecessor plus proven candidate tree.

A green run for any other SHA is not E03 release evidence.
