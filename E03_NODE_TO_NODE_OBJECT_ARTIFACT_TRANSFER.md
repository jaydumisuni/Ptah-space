# E03 Node-to-Node Object and Artifact Transfer

## Authority

Programme E03 is implemented from the accepted E02 release predecessor:

`4b745e7ee0712df0458c1adf55feafdbcc42d9d4`

The approved design and implementation plan are:

- `docs/superpowers/specs/2026-09-06-e03-node-to-node-object-artifact-transfer-design.md`
- `docs/superpowers/plans/2026-09-06-e03-node-to-node-object-artifact-transfer.md`

## Delivered E03 boundary

E03 adds an explicitly authorized Node-to-Node data plane for exact Content/Object transfer while retaining existing E01 control, A07 object truth, A08 transfer truth and B01 resume truth.

The implementation provides:

- exact transfer tickets bound to source/target Node generation, ConnectionEpoch, peer TLS fingerprints, A08 Request/Run/Attempt, Content/Artifact identity, source size/digest, expiry and an explicit route set;
- `ptah.node.transfer.v1` bounded framing separate from the `ptah.node.link.v1` E01 control envelope;
- mutually authenticated TLS 1.3 direct transfer using existing Node credential identity;
- bounded range transfer with per-range digest verification and durable re-read before verified cursor authority advances;
- interruption/resume that retains verified ranges and requests only missing ranges;
- explicit single-hop relay admission and forwarding, with relay authorization bound to the frozen ticket and TLS fingerprint;
- production-originated direct connection-loss evidence retained across explicit relay continuation;
- exact verified-cache reuse without network transfer, while unverified or identity-mismatched local bytes fail closed;
- stale NodeGeneration, ConnectionEpoch, peer fingerprint, ticket expiry, route, binding, geometry and digest rejection;
- composition with A08 verification and A07 acceptance without allowing route acknowledgement, relay forwarding or cache presence to manufacture canonical A07 truth.

## Explicit non-claims

E03 does **not** implement or authorize:

- E04 Workspace movement or collaboration transport;
- E05 platform-specific Node admission;
- E06 automatic discovery, automatic relay selection or offline queue/reconciliation;
- automatic route choice outside the exact ticket route set;
- a durable E03 ticket authority replacing A08/B01 resume truth;
- relay-hosted canonical object storage or A07 Location/Artifact acceptance;
- a new Core entity family, schema or migration.

## Acceptance corpus

The frozen E03 corpus is `conformance/e03/node-transfer-cases.v0.1.0.json`. It contains exactly 28 mandatory cases matching design section 15.

`tools/check_e03_node_transfer.py` fails closed on missing, duplicate or unexpected cases, false pass claims, changed predecessor/protocol identity, mismatched observations, invalid evidence arrays or scope expansion. Its regression suite is `tools/test_check_e03_node_transfer.py`.

## Exact-head release proof

`.github/workflows/e03-node-to-node-object-artifact-transfer.yml` is the permanent E03 release proof. It binds proof to the exact push SHA or pull-request head SHA and requires:

- accepted E02 predecessor and a linear reviewed E03-only path set;
- immutable external Action pins;
- Rust 1.97.1, Python 3.13, current dependency/source/licence policy and no unreviewed dependency drift;
- the exact 28-case conformance corpus and checker regressions;
- authority, cache, range framing, direct TLS, interruption/resume and explicit relay proofs;
- restart/reconnect/concurrency and A08/A07 composition regressions;
- inherited E01, E02, A08, B01, D09 and deep-Workspace regressions;
- rustfmt, strict workspace Clippy and full locked workspace tests;
- repository textual secret/private-key scanning;
- a clean exact candidate and retained proof bundle with SHA-256 manifest.

A development-CI green branch is not by itself an accepted E03 release. One exact candidate SHA must pass this permanent workflow in push context, retain `e03-node-transfer-<SHA>`, and then pass the same workflow in PR context before guarded merge.

## Merge rule

A release PR may be merged only when:

1. `main` still equals `4b745e7ee0712df0458c1adf55feafdbcc42d9d4`;
2. push and PR permanent-proof runs both succeed for the same exact candidate SHA;
3. the retained proof artifact is bound to that SHA;
4. the reviewed changed-path set remains exact;
5. merge uses expected-head protection for that proven candidate;
6. post-merge verification proves parent 1 is accepted E02, parent 2 is the proven E03 candidate, and the merge tree equals the proven candidate tree.

No candidate SHA is recorded in this milestone before freeze. The workflow artifact is the candidate-identity authority.
