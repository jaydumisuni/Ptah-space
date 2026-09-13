# Prime Manager — Review / Cookpit Transfer Handoff

Status: DOCUMENTED FOR MANUAL TRANSFER  
Prime Manager repository replacement: NOT AUTHORIZED / NOT PERFORMED  
Owner will handle transfer manually.

## 1. Authoritative Prime Manager baseline

- Repository: `jaydumisuni/Prime-Manager`
- Branch: `main`
- Required baseline HEAD: `375ca5475d97d9378e5ecfd86ff2c24b5137c103`
- KRATOS authority path: `/home/kratos/Prime-Manager`
- Verified before and after Cookpit review runs: clean worktree, `main...origin/main`, exact HEAD above.
- No Prime Manager repository file was replaced, committed, or pushed during this review work.

The committed repository still contains the older roadmap baseline. The saturated candidate remains outside the Prime Manager authority repository until the owner explicitly transfers it.

## 2. Review candidate authority

The review candidate is represented by two layers:

1. Exact base candidate whose SHA-256 is:
   `65d754df5f9d5bbca74f3385945d01486845fa255cc44f9c2cf32ca29c521dc3`
2. Accepted post-candidate chat amendments in:
   `CHAT_AUTHORITY_AMENDMENTS.md`

Accepted amendment overlay SHA-256 observed on KRATOS:
`d8956f039875c862320f983ada537d39f659d81ad1e8d4c4c3fb0f0ec0ef7e18`

Cookpit execution layer used for the verified review world:
- KRATOS path: `/home/kratos/cookpit`
- branch: `feat/durable-evidence-replay-20260910`
- HEAD: `045ff85a48a54dfb1c6905ca9802fe33b47c29e8`
- clean during verified run.

Composite verified review-world SHA-256:
`67730a2a04d621d38487534af5dc59a16377550bfce15e544fc373308fb02d3c`

This composite binds:
- base roadmap SHA;
- accepted chat-amendment SHA;
- Prime Manager authority HEAD;
- Cookpit execution-layer HEAD.

## 3. Temporary transport branch and files

Temporary transport repository: `jaydumisuni/Ptah-space`

Payload branch:
`tmp/prime-manager-review-payload-20260913`

KRATOS workflow branch:
`tmp/prime-manager-cookpit-kratos-20260913`

Payload directory:
`tmp/prime-manager-review/`

Important files:
- `CHAT_AUTHORITY_AMENDMENTS.md` — accepted post-candidate contracts and proof subjects.
- `review_gate.py` — deterministic review-world structural gate.
- `test_review_gate.py` — TDD/regression tests for the gate.
- `prime-manager-review.json` — isolated Cookpit project profile.
- `base_00` … `base_08` — transport chunks for the exact base roadmap candidate.
- `TRANSFER_HANDOFF.md` — this document.

KRATOS isolated work area:
`/home/kratos/.oracle-work/prime-manager-review-cookpit`

Cookpit durable state/evidence root:
`/home/kratos/.local/state/ttg-cookpit/projects/prime-manager-review`

## 4. Exact base reconstruction and transport quirk

The authoritative base candidate is exactly 103,455 bytes and must hash to:
`65d754df5f9d5bbca74f3385945d01486845fa255cc44f9c2cf32ca29c521dc3`

A temporary transport defect occurred while staging the chunks:
- `base_07` on the payload branch is 19,455 bytes.
- The first 12,000 bytes of `base_07` are the correct authoritative `base_07` chunk.
- The remaining 7,455 bytes are a duplicated copy of `base_08`.
- `base_08` separately contains the correct final 7,455-byte tail.

This was physically diagnosed on KRATOS. The first 12,000 bytes of `base_07` hash to:
`aea95ff13b3fc82ff08c12f94d3a30901a4305ad7fe7031785c33946794380c5`

Correct reconstruction used during all passing Cookpit runs:

```bash
cd /home/kratos/.oracle-work/prime-manager-review-cookpit
head -c 12000 base_07 > base_07.authority
cat base_00 base_01 base_02 base_03 base_04 base_05 base_06 base_07.authority base_08 > ROADMAP_BASE.md
wc -c ROADMAP_BASE.md
sha256sum ROADMAP_BASE.md
```

Expected result:
- bytes: `103455`
- SHA-256: `65d754df5f9d5bbca74f3385945d01486845fa255cc44f9c2cf32ca29c521dc3`

Do not concatenate the full 19,455-byte `base_07` and `base_08`; that duplicates the final tail and produces the wrong review world.

## 5. Accepted post-candidate contracts

The overlay is the authoritative record of chat findings accepted after the 103,455-byte base candidate was materialized. It closes the later architecture gaps discovered in review.

Contract families added/tightened:

### Closure qualification and composition
- `PM-CLOSE-005` Closure Authority Binding
- `PM-CLOSE-006` ClosureCertificate
- `PM-CLOSE-007` Aggregate Closure Composition
- `PM-CLOSE-008` ClosureQualification Lifecycle

### Coherent admission / commit world
- `PM-WORLD-004` DecisionWorldFence
- `PM-WORLD-005` Coherence Modes
- `PM-WORLD-006` Positive Coherence Window
- `PM-COMMIT-GUARD-001` EffectCommitGuard
- `PM-COMMIT-001` EffectCommitPlan

### Protected disclosure descriptors / release cutover
- `PM-DISCOP-001` DisclosureOperationDescriptor
- `PM-DISCOP-002` Disclosure Obligation Set
- `PM-DISCOP-003` Missing Descriptor Fails Closed
- `PM-DISCOP-004` Disclosure Descriptor Resolution
- `PM-DISCRELEASE-001` DisclosureReleaseGuard

### Authorization lifetime / emergency revocation
- `PM-AUTHZ-004` Authorization Validity Cutover
- `PM-AUTHZ-005` SecurityRevocationNotice

### Human-consent coherence / trusted rendering
- `PM-CONSENT-001` ConsentSemanticDigest
- `PM-CONSENT-RENDER-001` TrustedConsentRenderer

### Obligation universe / rule graph
- `PM-OBLIG-001` Active Obligation Universe
- `PM-OBLIG-002` ObligationResolutionReceipt
- `PM-OBLIG-003` Obligation Evaluation Graph

### CAB cutover
- `PM-CAB-005` CAB Cutover

### Quiescence future-work closure
- `PM-QUIESCE-ADMIT-001` WorkAdmissionUniverse
- `PM-QUIESCE-ADMIT-002` WorkAdmissionFence

### Durable evidence / audit capacity
- `PM-RESERVE-001` DurableCapacityReservation
- `PM-AUDIT-RESERVE-001` Mandatory Audit Reserve

### Managed-control session lifetime
- `PM-CTRLSESS-006` ControlSessionFence

Important ID correction: the final accepted control-session fence uses `PM-CTRLSESS-006`, not `PM-CTRLSESS-005`, because `005` was already owned in the base candidate. This avoids a stable-ID collision.

### Policy composition
- `PM-POLICY-003` Constraint Composition Algebra

### Admission proof / evidence qualification / descriptor resolution
- `PM-ADMISSION-RECEIPT-001` AdmissionReceipt
- `PM-EVID-QUAL-001` Evidence Strength Qualification
- `PM-DESC-RESOLVE-001` Privileged Effect Descriptor Resolution
- `PM-REQUEST-002` Rejected Request Effect Precision

The overlay also contains corresponding proof subjects for closure authority, DecisionWorld fencing, disclosure descriptors, authorization cutover, consent staleness/rendering, obligation cycles/universe closure, CAB cutover, work-admission closure, commit plans/guards, reserve hoarding, control-session fencing, policy composition, audit reserve, disclosure cutover, admission receipts, evidence qualification, descriptor resolution, atomicity, and multi-phase safety.

## 6. Review-gate TDD history

The gate was built using red/green proof on physical KRATOS.

### Initial RED

The first valid RED staged the exact authority base successfully, verified Prime Manager clean at the expected HEAD, then failed because `review_gate.py` did not yet exist:

`ModuleNotFoundError: review_gate`

That failure occurred after authority staging, so it was a valid test failure rather than a setup failure.

### First GREEN implementation

`review_gate.py` was added with:
- exact base SHA enforcement;
- stable-ID extraction;
- duplicate-ID rejection;
- required latest-contract coverage;
- proof-subject closure checks;
- Prime Manager HEAD/clean-worktree verification;
- Cookpit HEAD binding;
- composite review-world hashing;
- micro/heavy reporting.

### Parser defect found by Cookpit

Cookpit micro initially failed because the stable-ID parser recognized only headings of form:
`### PM-ID — Title`

Several valid proof headings in the overlay intentionally use:
`### PM-PROOF-...`
with no title suffix.

The false failure reported 22 proof IDs as missing.

A new regression test was added first:
`test_titleless_stable_id_heading_is_recognized`

The test failed on KRATOS exactly as expected:
`[] != ['PM-PROOF-WORLD-FENCE-001']`

The parser was then tightened to accept both titled and titleless stable-ID headings. The same regression suite subsequently passed 5/5.

## 7. Verified Cookpit run

Final verified KRATOS run:
- workflow run ID: `34769495440`
- job: `green-cookpit`
- runner: `KRATOS-PTAH`
- machine: `kratos-HP-290-G4-Microtower-PC`

Fresh verified results:

### Unit regression tests

`5/5 PASS`

Tests cover:
- exact base assembly/hash enforcement;
- review-world hash sensitivity;
- duplicate stable-ID rejection;
- latest required-contract/proof-subject closure;
- titleless stable-ID heading recognition.

### Cookpit micro

Status: `PASS`

Observed structural result:
- base stable IDs: `405`
- overlay stable IDs: `54`
- unique stable IDs: `459`
- duplicate IDs: `[]`
- missing required IDs: `[]`
- missing proof IDs: `[]`
- missing proof subjects: `{}`
- Prime Manager clean: `true`
- Prime Manager HEAD: exact expected baseline
- review-world SHA: `67730a2a04d621d38487534af5dc59a16377550bfce15e544fc373308fb02d3c`

Cookpit micro evidence:
`/home/kratos/.local/state/ttg-cookpit/projects/prime-manager-review/evidence/20260913T164455Z-micro-473a2edcb85b.json`

Latest pointer:
`/home/kratos/.local/state/ttg-cookpit/projects/prime-manager-review/evidence/micro-latest.json`

### Cookpit heavy

Status: `PASS`

Heavy checks:
- all overlay proofs mapped: `true`
- exact base bytes: `true`
- latest amendment IDs present: `true`
- duplicate IDs: none
- missing required IDs: none
- missing proof IDs: none
- missing proof subjects: none

Cookpit heavy evidence:
`/home/kratos/.local/state/ttg-cookpit/projects/prime-manager-review/evidence/20260913T164455Z-heavy-473a2edcb85b.json`

Latest pointer:
`/home/kratos/.local/state/ttg-cookpit/projects/prime-manager-review/evidence/heavy-latest.json`

Cookpit status after both runs:

```json
{
  "head": "375ca5475d97d9378e5ecfd86ff2c24b5137c103",
  "name": "Prime Manager Pre-Freeze Review",
  "project_id": "prime-manager-review",
  "proof_status": "PASS",
  "work_status": "ACTIVE"
}
```

Prime Manager authority after all verification remained:
- branch: `main`
- HEAD: `375ca5475d97d9378e5ecfd86ff2c24b5137c103`
- clean worktree.

## 8. What the Cookpit PASS means

The verified Cookpit PASS proves structural closure of this exact review world for the checks encoded in `review_gate.py`:
- exact base authority bytes;
- exact chat-amendment overlay;
- unique stable IDs;
- required accepted IDs present;
- accepted proof IDs present;
- proof-subject mapping closed for the added amendment family;
- Prime Manager authority was not modified;
- Cookpit execution authority was stable and clean.

It does NOT by itself mean:
- PM0 has started;
- the roadmap has been frozen;
- independent falsification has been performed;
- the saturated candidate has replaced repository `ROADMAP.md`;
- physical PM1/PM1.5 implementation proofs exist.

## 9. Independent review / transfer disposition

The roadmap itself requires independent falsification after internal gates. Cookpit on the current KRATOS branch has no built-in independent-review/handoff implementation discovered during this session.

The owner explicitly chose to handle transfer/reviewer handoff manually. Therefore:
- no separate reviewer was invoked here;
- no independent-review PASS is claimed here;
- no Roadmap Assurance Capsule/freeze is claimed here;
- no repository replacement is claimed here.

This handoff preserves everything required for the owner to transfer the exact review world to a second reviewer without losing the base candidate, accepted amendment contracts, proof subjects, hashes, or Cookpit evidence.

## 10. Recommended transfer package

For a manual transfer, hand the next reviewer all of:

1. reconstructed `ROADMAP_BASE.md` with exact SHA `65d754df...`;
2. `CHAT_AUTHORITY_AMENDMENTS.md` with SHA `d8956f...`;
3. this `TRANSFER_HANDOFF.md`;
4. `review_gate.py`;
5. `test_review_gate.py`;
6. `prime-manager-review.json`;
7. Cookpit micro evidence JSON;
8. Cookpit heavy evidence JSON;
9. Prime Manager baseline identity `375ca547...`;
10. Cookpit execution-layer identity `045ff85...`;
11. composite review-world SHA `67730a2a...`.

The reviewer must review the same materialized world. If the base or overlay changes, compute a new review-world hash and rerun affected internal gates before treating earlier review evidence as applicable.

## 11. Transfer/freeze sequence after reviewer work

The safe sequence remains:

```text
exact base + accepted overlay
→ materialize one review candidate
→ compute new exact digest
→ run internal definition/stable-ID/regression/mechanism/state-machine/proof/phase gates
→ independent reviewer attacks that exact world
→ reconcile evidence-backed findings
→ any accepted correction creates a new world and reruns affected gates/review
→ owner approval
→ freeze / Roadmap Assurance Capsule
→ only then replace Prime Manager ROADMAP.md when explicitly authorized
→ PM0 starts afterward
```

## 12. Explicit non-actions

During this work we did NOT:
- replace `jaydumisuni/Prime-Manager/ROADMAP.md`;
- push the saturated roadmap to Prime Manager `main`;
- start PM0;
- claim independent-review PASS;
- claim roadmap freeze;
- claim implementation completion.

All Prime Manager authority remained untouched while the review candidate and Cookpit machinery lived in isolated temporary review space.
