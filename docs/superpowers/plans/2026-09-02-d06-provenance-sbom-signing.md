# D06 Provenance SBOM Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement D06 as a provider-neutral provenance composition crate with exactly 30 acceptance cases and exact-head proof.

**Architecture:** Add `crates/ptah-provenance` over frozen WP07 schemas and existing A03/A04/A07/D04/D05 authority. Typed projections enforce exact subject/digest, coverage, policy, proof-domain and independence invariants; complete canonical documents are persisted through A03 so D06 never redefines frozen schemas. External in-toto/Sigstore/OCI shapes remain interoperability projections/evidence rather than Ptah authority.

**Tech Stack:** Rust 1.97.1, serde/serde_json, sha2, thiserror, existing Ptah workspace crates, frozen WP07 JSON schemas.

**Spec:** `docs/superpowers/specs/2026-09-02-d06-provenance-sbom-signing-design.md`

## Global Constraints

- Accepted predecessor is D05 merge `d8202855a234b9bb4b45d34d96bd45d4d68e80fa`.
- No frozen contract/schema/migration/generated-binding edits.
- No external supply-chain CLI/library is selected as canonical authority.
- Raw secret/credential values are absent from public D06 contracts/evidence.
- Acceptance corpus is exactly 30 tests.
- Every mutating/provenance-producing runtime action retains exact A04 Activity/Operation/Attempt evidence.
- A03 remains canonical schema validation/persistence authority.
- A07 remains exact bytes/Object/Artifact authority.
- Strict `cargo clippy -p ptah-provenance --all-targets --locked -- -D warnings -W clippy::pedantic` must pass.

---

### Task 1: Exact subject binding and canonical store

**Files:**
- Create: `crates/ptah-provenance/Cargo.toml`
- Create: `crates/ptah-provenance/src/lib.rs`
- Create: `crates/ptah-provenance/src/error.rs`
- Create: `crates/ptah-provenance/src/subject.rs`
- Create: `crates/ptah-provenance/src/store.rs`
- Create: `crates/ptah-provenance/tests/d06_acceptance.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

**Interfaces:**
- Produces `ExactSubject { subject_ref: EntityRef, digest_refs: Vec<EntityRef> }`.
- Produces `ProvenanceStore::open(path)`, `record_document(Value) -> Result<EntityRef, D06Error>`, `read(EntityRef) -> Result<Value, D06Error>`.
- Store accepts only the 15 D06 frozen WP07 schema/kind pairs listed in the design.

- [ ] Write acceptance cases 1–2 proving exact immutable subject/digest is required and mutable aliases cannot become subject identity.
- [ ] Run `cargo test -p ptah-provenance --test d06_acceptance --locked` and confirm RED because the crate/types do not exist.
- [ ] Implement `ExactSubject::validate()` requiring non-empty exact Ptah subject kind plus non-empty digest refs whose kinds are frozen digest/evidence identities; aliases are a separate `Vec<String>` field and never accepted as subject refs.
- [ ] Implement bounded A03 `ProvenanceStore` canonical ingest using `CanonicalRecord::from_document`; reject any schema/kind pair outside D06.
- [ ] Run the D06 package tests and strict Clippy; confirm cases 1–2 green.
- [ ] Commit `feat(d06): add exact provenance subject store`.

### Task 2: SBOM inventory and coverage

**Files:**
- Create: `crates/ptah-provenance/src/sbom.rs`
- Modify: `crates/ptah-provenance/src/lib.rs`
- Modify: `crates/ptah-provenance/tests/d06_acceptance.rs`

**Interfaces:**
- Produces `CoverageState::{Complete,Partial,Failed,Inconclusive}`.
- Produces `SbomCoverage { requested, scanned, skipped, unsupported, errors, unknown_gaps, state }`.
- Produces `SbomProjection { subject, generator_facility_revision_ref, generator_provider_revision_ref, generator_configuration_ref, native_report_artifact_ref, format, format_version, package_observation_refs, coverage_ref }`.
- `SbomProjection::claims_complete(&SbomCoverage)` succeeds only when state is Complete and skipped/unsupported/errors/unknown_gaps are empty.

- [ ] Add acceptance cases 3–10 matching the design: Package Observation separation, mandatory Coverage, false-complete rejection, retained gaps, lossy format conversion, no vulnerability/licence/release authority, and distinct evidence for changed generator/configuration.
- [ ] Run those cases and confirm RED for missing SBOM types.
- [ ] Implement mechanical coverage and conversion projections; add `SbomClaimScope` that explicitly excludes vulnerability/licence/runtime/functionality/release claims.
- [ ] Persist representative complete `provenance.package_observation`, `provenance.sbom_coverage`, and `provenance.sbom` fixture documents through `ProvenanceStore` to prove frozen A03 round-trip.
- [ ] Run D06 tests + strict Clippy + A07 regression.
- [ ] Commit `feat(d06): add sbom coverage evidence`.

### Task 3: Attestation and in-toto/DSSE projection

**Files:**
- Create: `crates/ptah-provenance/src/attestation.rs`
- Modify: `crates/ptah-provenance/src/lib.rs`
- Modify: `crates/ptah-provenance/tests/d06_acceptance.rs`

**Interfaces:**
- Produces `EnvelopeType::{UnsignedStatement,Dsse,InTotoStatement,OtherRegistered(String)}`.
- Produces `MaterialOrigin::{Declared,Observed}` and `BoundMaterial { subject: ExactSubject, origin: MaterialOrigin }`.
- Produces `AttestationProjection { subjects, predicate_type, predicate_version, statement_artifact_ref, producer_ref, producer_facility_revision_ref, materials, products, envelope_type }`.
- `AttestationProjection::is_verified()` always returns false; verification is represented only by a separate verification projection/store record.

- [ ] Add acceptance cases 11–13: creation remains unverified, declared/observed origin stays distinct, and in-toto/DSSE shape preserves exact subjects/materials/products.
- [ ] Run and confirm RED.
- [ ] Implement projection plus deterministic JSON statement digest helper; no external in-toto/Witness runtime dependency.
- [ ] Round-trip a canonical `provenance.attestation` record through A03.
- [ ] Run D06 tests + strict Clippy.
- [ ] Commit `feat(d06): add attestation projections`.

### Task 4: Signature, Trust Policy and transparency

**Files:**
- Create: `crates/ptah-provenance/src/trust.rs`
- Create: `crates/ptah-provenance/src/signature.rs`
- Modify: `crates/ptah-provenance/src/lib.rs`
- Modify: `crates/ptah-provenance/tests/d06_acceptance.rs`

**Interfaces:**
- `TrustMode`, `TransparencyPolicy`, `OfflinePolicy` mirror frozen WP07 enums.
- `TrustPolicyProjection` binds exact policy ref/version, trusted roots, identity rules and validity interval.
- `SignatureProjection` binds exact subject/digests, signature artifact, signing method and signer/key reference.
- `VerificationDecision::{Valid,ValidWithLimitations,Invalid,Unavailable,Inconclusive,NotApplicable}` remains mechanical.
- `verify_signature_binding(signature, observed_subject, policy)` checks exact subject/digest/policy binding only; it never emits correctness/release acceptance.

- [ ] Add acceptance cases 14–20: signature != verification, digest-only cryptographic meaning, exact policy requirement, policy-change history, honest offline/no-log mode, public disclosure acknowledgement, and retained invalid/unavailable/inconclusive transparency.
- [ ] Run and confirm RED.
- [ ] Implement signature/trust/transparency projections and `DisclosureAcknowledgement { principal_ref, policy_ref, acknowledged_at }`; public-log transparency requires a matching acknowledgement while offline/no-log must not contain fabricated log-entry evidence.
- [ ] Round-trip canonical Trust Policy, Transparency Evidence, Signature, Signature Verification, Attestation Verification and Verification Run documents through A03.
- [ ] Run D06 tests + strict Clippy.
- [ ] Commit `feat(d06): add trust and signature verification`.

### Task 5: OCI/ORAS exact referrer relationships

**Files:**
- Create: `crates/ptah-provenance/src/oci.rs`
- Modify: `crates/ptah-provenance/src/lib.rs`
- Modify: `crates/ptah-provenance/tests/d06_acceptance.rs`

**Interfaces:**
- `OciDescriptor { media_type, digest, size }` validates `sha256:<64 lowercase hex>` and non-empty media type.
- `OciReferrerProjection { subject, referrer, artifact_type, registry_alias, discovery_method }`.
- `OciReferrerProjection::grants_trust()` is always false.

- [ ] Add acceptance cases 21–22 for exact-digest subject/referrer binding and discovery-not-trust.
- [ ] Run and confirm RED.
- [ ] Implement OCI 1.1-compatible descriptor/referrer projection and ORAS discovery evidence enum; registry/tag aliases remain strings outside canonical identity.
- [ ] Add dev-only compatibility assertion using A10 exact container digest format where useful, without exporting A10 types publicly.
- [ ] Run D06 tests + strict Clippy + A10 regression.
- [ ] Commit `feat(d06): add oci referrer evidence`.

### Task 6: Proof Bundle domain separation and failure isolation

**Files:**
- Create: `crates/ptah-provenance/src/proof_bundle.rs`
- Modify: `crates/ptah-provenance/src/lib.rs`
- Modify: `crates/ptah-provenance/tests/d06_acceptance.rs`

**Interfaces:**
- `ProofDomain::{Execution,Integrity,Export,Sbom,Attestation,Signature,FunctionalTest,Review,Reproduction,Release}`.
- `ProofEntry { domain, record_ref }`.
- `ProofBundleManifest { subjects, manifest_artifact_ref, entries, creator_ref }`.
- `coverage(required_domains)` returns `Complete` or explicit missing domains; no universal pass/fail verdict.

- [ ] Add acceptance cases 23–25: domain separation, signed output can still fail review, and downstream SBOM/signing failure preserves prior valid output evidence.
- [ ] Run and confirm RED.
- [ ] Implement proof-domain manifest/coverage and failure-isolation projection; prohibit duplicate domain+record entries.
- [ ] Round-trip canonical `provenance.proof_bundle` and `provenance.graph_revision` records.
- [ ] Run D06 tests + strict Clippy + D04/D05 regressions.
- [ ] Commit `feat(d06): add proof bundle domain separation`.

### Task 7: Independent reproduction and backend replacement

**Files:**
- Create: `crates/ptah-provenance/src/reproduction.rs`
- Modify: `crates/ptah-provenance/src/lib.rs`
- Modify: `crates/ptah-provenance/tests/d06_acceptance.rs`

**Interfaces:**
- `ReproductionRequestProjection` binds original Build Run, Recipe Revision, comparison protocol, independence requirements and cache policy.
- `ReproductionRunProjection` requires reproduction Build Run ref != original Build Run ref and non-empty independence evidence.
- `ComparisonClass::{ByteIdentical,FunctionalEquivalent,AcceptedVariance,NonEquivalent,Inconclusive,Blocked}`.
- `BackendEvidence { provider_revision_ref, provider_generation, tool_revision_ref }` is replaceable evidence and never changes subject/proof record identity.

- [ ] Add acceptance cases 26–30: distinct Build Run, cache/reverification not reproduction, byte vs functional comparison separation, negative/inconclusive history preservation, and backend/tool replacement without rekeying subject/proof identities.
- [ ] Run and confirm RED.
- [ ] Implement mechanical independence/comparison validation and replacement evidence projection.
- [ ] Round-trip canonical Reproduction Request, Reproduction Run and Reproduction Comparison records.
- [ ] Assert exactly 30 tests using `cargo test -p ptah-provenance --test d06_acceptance --locked -- --list`.
- [ ] Run D06 tests + strict Clippy + A09/A10/D04/D05 regressions.
- [ ] Commit `feat(d06): add independent reproduction evidence`.

### Task 8: Durable record, exact-head proof and ship

**Files:**
- Create: `D06_PROVENANCE_SBOM_SIGNING.md`
- Create: `.github/workflows/d06-provenance-sbom-signing-proof.yml`

**Interfaces:**
- Workflow pins accepted D05 predecessor, exact PR head, Rust/Cargo 1.97.1, approved path scope and D06-only lock delta.

- [ ] Write `D06_PROVENANCE_SBOM_SIGNING.md` documenting authority, delivered surface, canonical persistence, interoperability boundaries, 30-case corpus, regression evidence, lock delta and explicit deferrals.
- [ ] Run `cargo fmt --all -- --check`, strict D06 Clippy, raw-secret/public-authority/static guards, exact 30-count, targeted A07/A09/A10/D04/D05/WP07-related regressions, and `cargo test --workspace --locked`.
- [ ] Write exact-head workflow that repeats those gates and uploads candidate/file SHA-256 proof evidence.
- [ ] Commit proof artifacts; record frozen candidate SHA and make no further edits unless a proof gate fails.
- [ ] Re-run predecessor/scope/lock, fmt, strict Clippy/static guards, exact 30 D06 tests, targeted regressions and complete locked workspace on the frozen SHA.
- [ ] Push `d06-provenance-sbom-signing`; verify remote ref equals frozen SHA.
- [ ] Create PR against unchanged D05 `main`; follow only the D06 exact-head workflow as the decisive milestone gate while identifying historical predecessor exact-head failures separately.
- [ ] Merge with `gh pr merge --merge --match-head-commit <frozen-sha>` only after D06 exact-head CI is green and repository policy permits merge.
- [ ] Fetch `origin/main`; verify merge commit parents are exact D05 predecessor + frozen D06 candidate and worktree remains clean.
