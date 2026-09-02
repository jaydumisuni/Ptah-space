# D06 — Provenance, SBOM, Signing and Proof Bundles

## Status

Programme D06 implementation and exact-head proof record.

Accepted predecessor: `d8202855a234b9bb4b45d34d96bd45d4d68e80fa` (verified D05 merge).

D06 implements exact provenance subject/digest binding, Package Observation and SBOM coverage/inventory evidence, in-toto/DSSE-compatible attestation projections, versioned Trust Policy, signature and transparency verification evidence, OCI/ORAS exact-digest referrer relationships, proof-bundle domain separation, and independent reproduction/comparison evidence. It adds no new canonical identity family, release authority, secret store, mandatory supply-chain backend, semantic correctness verdict, vulnerability approval, licence approval, or automatic publication authority.

## Authority boundaries

- A03 remains canonical persistence and frozen-schema validation authority.
- A04 remains Activity/Operation/Attempt/Receipt execution and proof authority.
- A07 remains exact Object/Revision/Artifact bytes and digest authority.
- A09 remains exact Git source-material evidence authority.
- A10 remains replaceable Provider/backend generation and container execution evidence authority.
- D04 remains Recipe/Plan/service composition authority.
- D05 remains exact Package/Plugin lifecycle evidence authority.
- in-toto/Witness, Syft, SPDX, CycloneDX, Sigstore/Cosign, ORAS/OCI registries, transparency services, KMS/HSM systems and external tool/backend IDs remain replaceable representations/providers/evidence only.

## Delivered package

`crates/ptah-provenance` provides:

- exact immutable `ExactSubject` binding with mutable aliases retained outside identity;
- bounded A03 canonical ingest for all 15 frozen D06/WP07 provenance schema/kind pairs;
- explicit Package Observation, SBOM Coverage and SBOM projections with native-format and lossy-conversion evidence;
- SBOM claim scoping that cannot assert vulnerability state, licence acceptance or release acceptance;
- in-toto/DSSE-compatible attestation projection with declared-vs-observed material/product origin and deterministic statement digest evidence;
- frozen Trust Policy, signing-method, transparency and verification-result vocabularies;
- exact signature-to-subject verification under one exact Trust Policy identity/version;
- explicit public-transparency identity-disclosure acknowledgement and honest offline/no-log evidence;
- exact lowercase SHA-256 OCI subject/referrer descriptors with ORAS/OCI discovery kept separate from trust;
- proof-bundle manifests preserving execution, integrity, export, SBOM, attestation, signature, functional-test, review, reproduction and release as separate proof domains;
- frozen reproduction independence/cache/comparison vocabularies;
- reproduction admission requiring a distinct fresh Build Run plus explicit independence evidence;
- backend/tool replacement evidence that cannot re-key Ptah reproduction/proof identity.

## Canonical persistence

`ProvenanceStore` is a bounded A03-backed store accepting only the following frozen schema/kind pairs:

- `provenance.package_observation`
- `provenance.sbom_coverage`
- `provenance.sbom`
- `provenance.trust_policy`
- `provenance.transparency_evidence`
- `provenance.attestation`
- `provenance.attestation_verification`
- `provenance.signature`
- `provenance.signature_verification`
- `provenance.proof_bundle`
- `provenance.verification_run`
- `provenance.reproduction_request`
- `proof.reproduction_run`
- `proof.comparison`
- `provenance.graph_revision`

The D06 store does not implement a parallel schema engine. Complete documents are validated by A03 `CanonicalRecord::from_document` before persistence. A dedicated `store_roundtrip` test proves a real frozen `provenance.package_observation` can be persisted and read back through A03.

## Evidence laws

- mutable aliases, paths, tags, workflow IDs and backend IDs never become exact proof subject identity;
- Package Observation != SBOM != SBOM Coverage;
- partial/skipped/unsupported/error/unknown scan scope cannot claim complete coverage;
- SBOM format conversion may be explicitly lossy;
- SBOM inventory cannot prove vulnerability state, licence approval, runtime use, functionality, safety or release acceptance;
- attestation creation != attestation verification;
- declared and observed materials/products remain distinct;
- signature creation != signature verification;
- a valid signature proves exact subject/digest binding under one Trust Policy, not semantic correctness or release acceptance;
- Trust Policy changes create new verification history and never rewrite prior results;
- public transparency requires explicit identity-disclosure acknowledgement;
- offline/no-log verification never fabricates a transparency entry;
- OCI/ORAS referrer discovery != trust;
- proof domains remain independently represented and may disagree;
- downstream SBOM/signing failure cannot delete already-valid output evidence;
- reproduction requires a distinct fresh Build Run and explicit independence evidence;
- cache hits and repeated verification cannot impersonate reproduction;
- byte identity and functional equivalence remain different comparison classes;
- failed/inconclusive reproduction remains evidence without rewriting the original Build Run;
- backend/tool replacement creates new evidence while preserving Ptah proof identity.

## Acceptance evidence

The frozen D06 milestone corpus contains exactly **30 acceptance tests**, corresponding one-for-one to the committed D06 design specification. A separate canonical-store round-trip test covers the A03 persistence path without changing the 30-case milestone count.

Pre-freeze proof includes strict `clippy -D warnings -W clippy::pedantic`, zero D06 lint suppressions, A09/A10/D04/D05 targeted regressions, A03/A04/A07-related workspace coverage, and complete `cargo test --workspace --locked`. The inherited `ptah-control` missing-documentation warnings remain pre-existing baseline warning debt.

## Dependency / lock delta

D06 introduces no new external dependency version and no git dependency. `Cargo.lock` adds only one workspace package stanza: `ptah-provenance`, whose dependencies are existing `ptah-identifiers`, `ptah-ledger` plus already-pinned `serde`, `serde_json`, `sha2` and `thiserror 2.0.17`. No pre-existing package version/source entry moves.

## Exact-head proof requirements

The final D06 workflow proves on the frozen candidate SHA: exact D05 predecessor, linear history, approved path scope, no frozen contract/schema/migration/generated drift, exact one-package lock delta, Rust/Cargo 1.97.1, fmt, strict Clippy, no D06 lint suppressions/unsafe/TODO/FIXME/unimplemented/raw-secret/public-authority escape, the exact 15-schema bounded store map, exactly 30 D06 acceptance tests, canonical A03 store round-trip, targeted A09/A10/D04/D05 regressions, complete locked workspace, and a retained candidate/file SHA-256 proof artifact.

## Explicit deferrals

D06 does not select/install/deploy Syft, Cosign, Witness, in-toto, ORAS, Rekor, Fulcio, a KMS/HSM, registry or transparency backend. It does not implement D07 security finding/remediation extensions, D08 platform expansion, D09 full-workspace release acceptance, Programme E distribution or Programme F OS-ready mechanics.
