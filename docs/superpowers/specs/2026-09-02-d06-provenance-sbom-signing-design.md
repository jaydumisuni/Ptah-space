# D06 — Provenance, SBOM, Signing and Proof Bundles Design

## Authority

Roadmap authority: `ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`.
Accepted predecessor: D05 merge `d8202855a234b9bb4b45d34d96bd45d4d68e80fa`.

D06 implements the existing WP07 provenance family without selecting a mandatory supply-chain backend. It delivers in-toto/Witness-compatible statement projections, SBOM inventory/coverage, Cosign/Sigstore-compatible signing and bundle projections, OCI/ORAS relationship projections, versioned trust policy, transparency evidence, independent verification, proof bundles and reproduction evidence.

## Architecture

Add one composition crate: `crates/ptah-provenance`.

The crate composes:

- A03 ledger for canonical frozen WP07 records;
- A04 Activity/Operation/Attempt/Receipt identities for provenance-producing and verification work;
- A07 Object/Revision/Artifact truth for statement, SBOM, signature and proof-bundle bytes;
- A09 Git exact-commit/source evidence where source provenance is used;
- A10 Provider generation/backend evidence where isolated generators/verifiers are used;
- D04 Recipe/Plan/operation inputs;
- D05 Package/Plugin exact package evidence where SBOM package observations consume it;
- `ptah-contracts` frozen WP07 schema identities.

Syft, SPDX/CycloneDX generators, in-toto/Witness, Cosign/Sigstore, ORAS/OCI registries and transparency services remain replaceable Facilities/Providers or external representations. None becomes Ptah identity, trust policy or release authority.

## Components

### 1. Canonical provenance store

`ProvenanceStore` persists complete frozen WP07 provenance documents through A03. The public ingest surface is bounded to the D06 schema/kind pairs and delegates structural schema enforcement to `CanonicalRecord::from_document`, avoiding a second canonical schema implementation.

D06 directly covers Package Observation, SBOM Coverage, SBOM, Trust Policy, Transparency Evidence, Attestation, Attestation Verification, Signature, Signature Verification, Proof Bundle, Verification Run, Reproduction Request, Reproduction Run, Reproduction Comparison and Provenance Graph Revision.

### 2. Exact subject and digest binding

Every proof object binds exact Ptah `EntityRef` subjects plus exact digest references. Paths, Git branch names, OCI tags, registry URLs, workflow IDs, Rekor/log entry numbers, Cosign bundle filenames and backend job IDs remain aliases/evidence.

A proof record cannot upgrade mutable coordinates into immutable subjects. A07 Object Revision and Artifact identities remain canonical bytes/release-related truth.

### 3. SBOM projection and coverage

D06 separates `provenance.package_observation`, `provenance.sbom_coverage` and immutable `provenance.sbom`. Coverage is mandatory and retains requested/scanned scope, skipped/unsupported/error/unknown gaps.

Native formats include the frozen WP07 vocabulary: Syft JSON, SPDX JSON/tag-value, CycloneDX JSON/XML and registered other formats. Conversion between formats is a derived representation and may record information loss.

An SBOM is inventory evidence only. It cannot prove complete coverage, vulnerability absence, licence approval, runtime use, functionality, safety or release acceptance. Generator/configuration changes create new SBOM evidence even for unchanged subject bytes.

### 4. Attestation interoperability

`AttestationStatement` is a D06 mechanical projection supporting unsigned statements, DSSE and in-toto statement envelopes. It preserves exact subject/material/product digest bindings and declared-vs-observed origin.

Witness/in-toto compatibility is representational: external statement bytes become A07 objects and canonical `provenance.attestation` records. Creation never implies verification. Verification creates a separate `provenance.attestation_verification` under one exact Trust Policy.

### 5. Signature and Sigstore/Cosign compatibility

`SignatureEnvelope` preserves exact subject digest, signing method, signer/key identity reference and signature artifact reference. Cosign-compatible bundles are imported/projected as evidence; D06 does not shell out to Cosign as authority.

Cryptographic validity is separate from policy trust. `provenance.signature_verification` binds one exact signature, subject/digest, verifier revision and Trust Policy. A Trust Policy change creates a new verification record and never rewrites historical results.

No-log/offline verification is valid when allowed by policy. Public transparency evidence requires explicit identity-disclosure acknowledgement. D06 never fabricates a Rekor/log service, inclusion proof or online check.

### 6. OCI/ORAS relationships

`OciReferrerProjection` models OCI 1.1 subject/referrer relationships by exact digest and media/artifact type. The OCI `subject` association or ORAS discovery result is a weak external relationship/evidence projection only.

D06 may relate SBOM, attestation, signature and proof artifacts to an exact OCI subject digest, but registry referrer discovery does not prove signature validity, policy trust, completeness or release acceptance. Unsupported-registry fallback aliases remain explicit evidence, not canonical relationship identity.

### 7. Trust and verification

Trust Policy stays versioned and lifecycle-bound using the frozen trust modes/transparency/offline policy vocabulary. Verification results retain requirement-level evidence and the exact policy used.

D06 exposes mechanical verification-domain outcomes only. It never converts signature/attestation/SBOM validity into semantic correctness, safety, review approval or release acceptance. Negative, blocked and inconclusive verification remains history.

### 8. Proof bundles

`ProofBundleManifest` collects distinct proof-domain record references plus one A07 manifest Artifact. Domains remain distinct: execution, integrity, export, SBOM, attestation, signature, functional test, review, reproduction and release.

Bundle completeness is mechanical against caller-declared required domains. A bundle never collapses those domains into a universal verdict. A valid signed output may still have a failed review or unsatisfied functional/reproduction requirement.

### 9. Independent reproduction

Reproduction Request, Run and Comparison remain separate frozen WP07 records. An independent reproduction requires a distinct Build Run identity and evidence satisfying caller-authored independence requirements. Cache hits or repeated verification of original outputs cannot impersonate reproduction.

Comparison classes preserve byte identity, functional equivalence, accepted variance, non-equivalence, inconclusive and blocked outcomes. Reproduction never rewrites the original Build/provenance history.

## Failure model

D06 fails closed on:

- mutable or mismatched subject/digest bindings;
- SBOM without coverage or with false completeness;
- format conversion presented as lossless without evidence;
- attestation/signature creation presented as verification;
- signature validity presented as correctness/release authority;
- changed Trust Policy rewriting prior verification;
- public transparency without disclosure acknowledgement;
- offline/no-log verification with fabricated transparency evidence;
- OCI/ORAS discovery presented as trust;
- proof-bundle domain collapse;
- reproduction using the original Build Run or insufficient independence evidence;
- raw secret/credential material in provenance/SBOM/attestation/signature/proof surfaces;
- downstream SBOM/signing failure deleting valid prior outputs.

## Acceptance corpus

D06 freezes exactly 30 milestone cases:

1. exact immutable subject + digest required;
2. mutable alias cannot become proof subject identity;
3. Package Observation != SBOM;
4. SBOM Coverage is mandatory;
5. partial coverage cannot claim complete;
6. skipped/unsupported/error scope remains visible;
7. SBOM format conversion may be lossy;
8. SBOM cannot prove vulnerability state;
9. SBOM cannot prove licence/release acceptance;
10. generator/configuration change creates distinct SBOM evidence;
11. attestation creation remains unverified;
12. declared and observed materials/products remain distinct;
13. in-toto/DSSE projection preserves exact subjects/materials/products;
14. signature creation != verification;
15. valid signature proves exact digest binding only;
16. signature/attestation verification requires exact Trust Policy;
17. changed Trust Policy creates new verification history;
18. offline verification is representable without a fabricated log;
19. public transparency requires disclosure acknowledgement;
20. invalid/unavailable/inconclusive transparency remains explicit;
21. OCI/ORAS subject-referrer relationship is exact-digest bound;
22. OCI/ORAS referrer discovery does not imply trust;
23. Proof Bundle retains separate proof domains;
24. signed output may still fail independent review;
25. downstream SBOM/signing failure cannot delete valid output evidence;
26. independent reproduction requires a distinct Build Run;
27. cache/repeated verification cannot impersonate reproduction;
28. byte-identical and functional-equivalence comparison remain distinct;
29. failed/inconclusive reproduction remains retained without rewriting original;
30. backend/tool replacement preserves Ptah subject/proof identities while creating new provider/evidence records.

Inherited A07/A09/A10/D04/D05 and WP07-related regressions plus the complete locked workspace must remain green.

## External interoperability baseline

The interoperability projection targets the stable in-toto Attestation Framework v1 model, Sigstore/Cosign bundle-based signing/verification semantics, and OCI image-spec subject/referrer artifact relationships. D06 does not pin external CLI behavior into canonical truth; exact external tool versions belong to Provider Revision evidence when/if a provider is later enabled.

## Proof and shipping

D06 follows the established milestone lane: bounded implementation commits, strict fmt/Clippy with no D06 warnings/suppressions, frozen-contract and Cargo-lock audits, exactly 30 acceptance cases, targeted predecessor regressions, complete `cargo test --workspace --locked`, exact-head GitHub workflow, frozen candidate SHA, PR, D06-specific CI proof, merge-only-the-proven-head and merge-parent verification.

## Explicit deferrals

D06 does not select/install/deploy Syft, Cosign, Witness, in-toto, ORAS, Rekor, Fulcio, a KMS/HSM or registry. It does not implement D07 Security Finding/Remediation/Reproduction extensions, D08 application-platform expansion, D09 release acceptance, Programme E distribution or Programme F OS-ready mechanics.
