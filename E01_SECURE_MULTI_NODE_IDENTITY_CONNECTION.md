# E01 Secure Multi-Node Identity and Connection

## Authority

Programme E01 is implemented from the independently accepted D09 predecessor:

`f22d23c9bbf3c9c43884535e3483486c4bc0826f`

Roadmap authority remains:

`98dc8c4e8639cda80510bee0625db34b4fdf9384`

The approved design and implementation plan are:

- `docs/superpowers/specs/2026-09-04-e01-secure-multi-node-identity-connection-design.md`
- `docs/superpowers/plans/2026-09-04-e01-secure-multi-node-identity-connection.md`

## Delivered E01 boundary

E01 adds the transport-neutral `ptah.node.link.v1` application protocol and a first concrete TLS 1.3 mutual-authentication transport over Tokio TCP. Canonical identity continues to be owned by A02 `ptah-node-agent`; certificate serial numbers, sockets, hostnames and transport endpoints are not Ptah identity.

The implementation provides:

- approved `core.node_enrollment` projection and lifecycle enforcement;
- end-entity credential SHA-256 binding and overlap-safe credential rotation;
- TLS 1.3 mutual authentication with plaintext downgrade rejection;
- bounded transport-neutral framing and protocol-major rejection;
- current-session fencing by canonical `NodeId`, Node Generation and `ConnectionEpoch`;
- concurrent independent secure sessions for multiple Nodes;
- thin `ptah-node` client orchestration using the existing A02 identity owner;
- `ptah-control` secure-session authority and capability acceptance;
- capability rejection when NodeId, Generation or ConnectionEpoch differs from the authenticated current session;
- reconnect, Node restart and control restart recovery semantics without granting stale authority.

## Dependency delta

E01 adds three exact direct dependencies to the pre-existing frozen workspace dependency set:

- `rustls = 0.23.43` with `ring,std`;
- `rustls-pemfile = 2.2.0` with `std`;
- `tokio-rustls = 0.26.4` with `ring`.

The committed `Cargo.lock` is the CI-resolved lock for the E01 dependency graph. `dependencies/rust-direct-lock.json` records the exact selected versions, crates.io checksums, purpose, licence expectation and current lock identity. Git dependencies remain forbidden.

## Transport neutrality

TLS-over-TCP is the first E01 transport, not a canonical identity rule. E01 protocol framing operates over generic asynchronous read/write streams. Future transports may implement the same authenticated application semantics without changing `NodeId`, enrollment identity, Generation, ConnectionEpoch or capability truth.

## Explicit non-claims

E01 does **not** implement or authorize:

- E02 placement, Reservation, Lease/Fence scheduling or workload placement;
- E03 Node-to-Node Object transfer or overlay data plane;
- E04 Workspace movement or collaboration transport;
- E05 platform-specific Node admission;
- E06 automatic discovery, relay selection or intermittent/local-first reconciliation.

E01 introduces no new Core entity family and no database migration. The existing canonical Node, enrollment, capability and evidence contracts remain authoritative.

## Acceptance corpus

The durable corpus is:

`conformance/e01/secure-multi-node-cases.v0.1.0.json`

It requires mechanical evidence for positive, recovery and adversarial cases including two-Node concurrency, reconnect, Node restart, control restart, credential rotation, plaintext, wrong CA, wrong enrollment reference, revoked/expired enrollment, stale Generation/epoch, superseded publication, capability identity mismatch, malformed/oversized frame and unsupported protocol.

`tools/check_e01_secure_multi_node.py` fails closed if required case coverage or E01 scope fences drift.

## Exact-head release proof

`.github/workflows/e01-secure-multi-node-identity-connection.yml` is the permanent release proof. It must run against one exact branch/PR head and prove all of the following on that same SHA:

- the accepted D09 predecessor and reviewed E01-only delta;
- immutable external GitHub Action SHA pins;
- the current exact Rust dependency/source/licence boundary;
- E01 corpus/checker regression;
- Node-link protocol, framing, enrollment/session and TLS tests;
- `ptah-node` and `ptah-control` E01 service tests;
- A02 `ptah-node-agent` regression;
- D09 and deep-Workspace checker regression without using D09's historical Cargo snapshot as a current E01 dependency gate;
- workspace formatting;
- workspace Clippy with warnings denied;
- full locked workspace tests;
- dependency policy checks;
- textual secret/private-key marker scan;
- a clean exact candidate after proof;
- retained proof files with SHA-256 manifest.

The retained artifact name is `e01-secure-multi-node-${SHA}`. A branch head is not an accepted E01 release candidate until that exact-head artifact and workflow are successful.

## Merge rule

A pull request may be merged only when:

1. `main` still equals the accepted D09 predecessor above;
2. the PR head equals the independently proven E01 candidate SHA;
3. the reviewed changed-path set is unchanged;
4. the permanent E01 exact-head proof succeeds in PR context;
5. the guarded merge uses the proven expected head SHA.

After merge, E01 is complete only after independently verifying the merge parents and confirming that the merged E01 side tree is the proven candidate tree. The merge itself must not be treated as proof.
