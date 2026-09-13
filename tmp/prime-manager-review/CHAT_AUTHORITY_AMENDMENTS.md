# Prime Manager — Accepted Chat Authority Amendments

Status: ACCEPTED REVIEW AUTHORITY OVERLAY
Base roadmap SHA-256: `65d754df5f9d5bbca74f3385945d01486845fa255cc44f9c2cf32ca29c521dc3`
Repository ROADMAP replacement: NOT AUTHORIZED

These contracts are accepted amendments discovered after the base candidate was materialized. They extend or tighten the base candidate without mutating the Prime Manager repository. Stable IDs in this overlay are unique relative to the base candidate.

## Closure qualification and composition

### PM-CLOSE-005 — Closure Authority Binding
`EXACT` is not self-assertable. For every omission-sensitive collection, the active contract registry defines the collection kind, scope, authority permitted to certify closure, maximum grade, enumeration method, required qualification, authority incarnation, and limitations. Unqualified `EXACT` is invalid.

### PM-CLOSE-006 — ClosureCertificate
A ClosureCertificate binds certificate ID, collection kind, declared scope, authority and authority epoch/incarnation, enumeration method, universe revision, closure grade, witness, qualification reference, validity/invalidation basis, and limitations. Lifecycle is ISSUED → VALID → INVALIDATED|EXPIRED; terminal certificates never resurrect.

### PM-CLOSE-007 — Aggregate Closure Composition
Exact child collections imply an exact aggregate only when the source/member universe itself has sufficient closure and every required member source has the required closure grade. Exact members plus an unknown universe never produce exact aggregate closure. Closure grade is purpose-specific; a conservative superset may satisfy blocker discovery while being insufficient for a destructive target set.

### PM-CLOSE-008 — ClosureQualification Lifecycle
Closure authority qualification is operation/scope specific and has ACTIVE, REVOKED, EXPIRED, SUPERSEDED semantics. Closure certificates are usable for new positive decisions only while their qualification remains valid. Revocation does not rewrite historical decisions legitimately made under the prior qualification.

## Coherent admission and commit worlds

### PM-WORLD-004 — DecisionWorldFence
Every candidate privileged effect binds its safety-bearing inputs into a candidate-specific DecisionWorldFence, including Host identity, Security-State version, Core authority epoch, Auth/session state, target revisions, control-session registry revision, dependency revision, ClosureCertificate IDs, Provider incarnations, placement revisions, assessment revisions, support/policy revisions, and active CAB generation.

### PM-WORLD-005 — Coherence Modes
Every safety-bearing input declares one permitted coherence mechanism: CORE_ATOMIC, FENCED_REVISION, LEASED_ASSERTION, REVALIDATE_AT_COMMIT, or HISTORICAL_ONLY. Mandatory safety inputs without a defined coherence mechanism cannot support positive admission.

### PM-WORLD-006 — Positive Coherence Window
All mandatory safety facts must be contractually valid across the same admission commit boundary. Prime does not require an impossible global distributed snapshot; independently changing authorities instead provide revisions, fences, leases, or commit-time revalidation. If required coherence cannot be achieved, the operation is unavailable.

### PM-COMMIT-GUARD-001 — EffectCommitGuard
Admission-safe is not automatically commit-safe. Every safety obligation declares a validity horizon: ADMISSION_FINAL, VALID_UNTIL_COMMIT, REVALIDATE_AT_PHASE, or CONTINUOUS_LEASE. A commit-sensitive effect uses an action-bound guard that binds candidate/action ID, executor incarnation, DecisionWorldFence digest, exact commit boundary, and relevant safety revisions. Lifecycle is ISSUED → VALID → CONSUMED|EXPIRED|INVALIDATED. Replay cannot produce another effect. Remote executors unable to enforce the required guard cannot expose that mutation.

### PM-COMMIT-001 — EffectCommitPlan
Every privileged effect declares commit topology: ATOMIC_SINGLE_COMMIT, SEQUENTIAL_COMMIT_UNITS, PARALLEL_INDEPENDENT_COMMIT_UNITS, DOMAIN_TRANSACTIONAL_COMMIT, or an explicitly frozen equivalent. Every non-atomic commit unit declares target/subset, unit digest, dependencies, guard, postcondition/evidence, and whether prior units can alter later safety. Later units re-resolve obligations and obtain fresh guards where required. `ALL_TARGETS_MUST_ADMIT` constrains admission-set shrinkage; it does not assert atomic machine effects.

## Protected read descriptors and release guards

### PM-DISCOP-001 — DisclosureOperationDescriptor
Every protected read/query operation has a versioned descriptor declaring operation kind, object family, field classes, permission, AssurancePredicate, required closure grade, ObservationCostDescriptor, classification floor, allowed presentation classes, mandatory audit class, filter/sort/search permissions, declassification transforms, externalization eligibility, rate/cardinality/size limits, freshness requirements, existence-disclosure behavior, and long-lived disclosure semantics.

### PM-DISCOP-002 — Disclosure Obligation Set
Disclosure obligations equal the DisclosureOperationDescriptor plus classification policy, applicable Prime security policy, current DisclosureContext, and contextual obligation instances. Every mandatory obligation closes before protected bytes leave Prime authority.

### PM-DISCOP-003 — Missing Descriptor Fails Closed
Missing, unknown, incomplete, or incompatible protected-read descriptor means UNSUPPORTED/DISCLOSURE_UNAVAILABLE, never permissive defaults.

### PM-DISCOP-004 — Disclosure Descriptor Resolution
For an active CAB + disclosure operation + object/field class, descriptor selection is deterministic. Zero matches is unsupported; exactly one selects it; multiple ambiguous matches fail closed unless an explicit composition contract applies. No first-match, most-specific, or weakest-descriptor fallback is allowed.

### PM-DISCRELEASE-001 — DisclosureReleaseGuard
A one-shot protected response validates the complete disclosure world at the release boundary. Long-lived projections, streams, and fetches use bounded release leases/windows binding descriptor identity, Disclosure Obligation Set digest, DisclosureContext, policy/classification revisions, transform, source/projection identity, CAB validity, and audit semantics. Relevant invalidation stops future protected bytes; already released bytes are not fictionally recalled.

## Authorization validity and security revocation

### PM-AUTHZ-004 — Authorization Validity Cutover
Authorization must be valid at durable admission. Ordinary later logout, session expiry, lock, UI close, or grant expiry does not retroactively make already-admitted work unauthorized and does not automatically cancel it. Every PrivilegedEffectDescriptor declares post-admission validity/cutover semantics.

### PM-AUTHZ-005 — SecurityRevocationNotice
Authoritative emergency security revocation binds revocation ID, issuer/epoch, affected principal/session/claim, revocation class, effective sequence/time basis, scope, reason class, and audit correlation. Effect descriptors declare ADMISSION_FINAL, SECURITY_FENCE_UNTIL_COMMIT, REAUTHORIZE_AT_PHASE, or another explicitly frozen cutover mode. Committed effects remain historical truth; remediation is a new effect/transaction.

## Human-consent coherence and trusted rendering

### PM-CONSENT-001 — ConsentSemanticDigest
Trusted human approval binds the semantic facts the human approved: effect/disclosure descriptor and version, candidate ID, target/target-set digest, requested state/value, human-facing Impact/Protection/Risk projection, expected disconnect, irreversible phase, material limitations, and human-relevant UNKNOWNs. Inputs are classified CONSENT_RELEVANT or MACHINE_ONLY. A consent-relevant change after approval yields CONSENT_STALE and requires new trusted approval.

### PM-CONSENT-RENDER-001 — TrustedConsentRenderer
Security-critical approval wording is rendered from canonical machine facts through a trusted presentation implementation and trusted input path. It binds renderer/template/localization identities and digests, canonical values/units, stable target identity, descriptor version, and ConsentSemanticDigest. Provider strings and ordinary renderer text cannot define the security meaning. If a trusted approved presentation cannot be produced, high-risk human confirmation is unavailable.

## Obligation-universe closure and rule evaluation

### PM-OBLIG-001 — Active Obligation Universe
All potential mandatory policy, contract, external-constraint, and contextual obligation instances for an effect/disclosure belong to an authority-owned universe whose contributing registries/source universes have explicit closure. An operation cannot prove “all applicable obligations passed” without sufficient closure over the universe that could contribute obligations.

### PM-OBLIG-002 — ObligationResolutionReceipt
Resolution records the exact obligation-set digest, applicability result for each potential mandatory instance, source registry/policy revisions, closure witnesses, limitations, and unresolved UNKNOWNs. If a contributing source revision changes before a commit-sensitive effect/release, Core re-resolves the complete obligation universe; it does not merely recheck obligations previously known.

### PM-OBLIG-003 — Obligation Evaluation Graph
Safety-bearing obligation dependencies are stratified/acyclic by default. Each rule type declares allowed dependency layers. Unexpected direct/indirect cycles, dependency-depth overflow, or work-budget exhaustion yield OBLIGATION_CYCLE/UNKNOWN and block positive admission/release. No arbitrary evaluation order or permissive fixed point is allowed.

## CAB cutover

### PM-CAB-005 — CAB Cutover
CAB lifecycle distinguishes CANDIDATE, TEST_ELIGIBLE, ACTIVE, SUPERSEDED, RETIRED, and emergency EMERGENCY_REVOKED as applicable. Only ACTIVE authorizes new normal-production admission. Effects/disclosures bind the exact CAB generation and declare a validity horizon: CAB_VALID_AT_ADMISSION, CAB_VALID_UNTIL_COMMIT, CAB_REVALIDATE_AT_PHASE, or CAB_CONTINUOUS_FOR_RELEASE. Emergency revocation can block future commit/release according to that horizon; historical committed effects are not rewritten.

## Quiescence future-work closure

### PM-QUIESCE-ADMIT-001 — WorkAdmissionUniverse
Transition-specific quiescence identifies every Prime-observable authority/path capable of creating relevant future blockers, including Prime Exec, service activation, timers/schedules, Terminal, Provider callbacks, watchdog/restart policy, update/component authority, automation, and queued/pending admissions. The universe itself carries scope, revision, closure certificate, and unresolved sources.

### PM-QUIESCE-ADMIT-002 — WorkAdmissionFence
During destructive transition preparation, relevant work-admission authorities reject conflicting work, queue it beyond the transition, classify it as non-conflicting under a frozen rule, or participate through an equivalent fence. SAFE requires sufficient closure over both current blockers and future blocker-producing admission sources.

## Durable reservations and audit reserve

### PM-RESERVE-001 — DurableCapacityReservation
Evidence/audit capacity reservations bind reservation ID, owner client/system authority, principal where relevant, candidate/action/transaction identity, durability class, required records/bytes, priority class, lifecycle, consumption, and release condition. Per-client/system/principal/unresolved limits and protected Host-survival/security reserves prevent hoarding. Unresolved admitted effects retain accounted capacity needed for mandatory final evidence; once budgets are exhausted, new work is rejected/throttled rather than sacrificing existing evidence obligations.

### PM-AUDIT-RESERVE-001 — Mandatory Audit Reserve
Mandatory-audit protected reads/admissions have protected capacity/priority independent of ordinary noisy denial/audit traffic. Reservations are bounded, request-bound, crash-recoverable, and released/consumed by lifecycle. When canonical Host Action Evidence explicitly satisfies the mandatory audit contract, duplicate reserve is not required. Media failure still fails closed.

## Management control-session fencing

### PM-CTRLSESS-006 — ControlSessionFence
Every new privileged request from a managed control client binds control_session_id, control-session incarnation, active lease/fence, and client/system identity. Core verifies the session is currently ACTIVE. Lease expiry, explicit revocation, unproven transport loss, or client reincarnation prevents future privileged requests. Already-admitted effects follow Authorization Validity Cutover rather than being retroactively cancelled by default.

## Policy composition algebra

### PM-POLICY-003 — Constraint Composition Algebra
Every composable policy/resource/security field defines its domain, partial order where applicable, lawful meet/intersection operation, explicit broadening/override mechanism, conflict semantics, and UNKNOWN behavior. There is no generic “pick the stricter-looking rule.” Empty/incompatible intersections yield POLICY_CONFLICT/UNSATISFIABLE and block positive admission.

## Admission proof and evidence qualification

### PM-ADMISSION-RECEIPT-001 — AdmissionReceipt
Every durably admitted privileged effect records an immutable receipt binding descriptor ID/version, exact Admission Obligation Set digest, ObligationResolutionReceipt, DecisionWorldFence, ClosureCertificates, AuthorizationDecision, SupportAssessment, evidence/audit reservations, authorization cutover class, commit-guard policy, CAB generation, and durable admission identity. Investigators can therefore prove which complete obligation world actually passed.

### PM-EVID-QUAL-001 — Evidence Strength Qualification
Evidence-strength values are authority-qualified. Provider attestation cannot self-promote to CAUSALITY_PROVEN. Each strength class defines acceptable evidence forms and authority. Later reconciliation may append stronger evidence without rewriting earlier knowledge.

### PM-DESC-RESOLVE-001 — Privileged Effect Descriptor Resolution
For active CAB + operation/effect kind + target/object class, descriptor resolution is deterministic. Zero matching descriptor means unsupported. One match is used. Multiple ambiguous matches fail closed unless the registry explicitly defines composition. No first-match, specificity shortcut, or weaker-descriptor choice is allowed.

### PM-REQUEST-002 — Rejected Request Effect Precision
A rejected pre-admission request guarantees that the requested target effect was not admitted/committed on behalf of that request. Separately authorized observation or Provider-activation effects that already occurred remain independently identified/evidenced; they are not erased by rejection of the target request.

## Latest proof subjects

### PM-PROOF-CLOSURE-AUTH-001
Attack unqualified Provider EXACT assertions, stale/forged ClosureCertificates, incomplete source universes, aggregate closure with missing sources, late omitted members, and ClosureQualification revocation. Positive admission must fail without sufficient qualified closure.

### PM-PROOF-WORLD-FENCE-001
Change Auth, ManagementControlSession registry, DependencyGraph, Provider incarnation, support, protection, target revision, or policy after preflight/approval but before admission/commit. Stale worlds must not admit/commit.

### PM-PROOF-DISCOP-001
Attempt protected reads with missing/ambiguous descriptors, insufficient assurance, missing mandatory audit, forbidden presentation path, hidden-field predicates, oversized requests, expired contexts, and stale classification. Fail closed.

### PM-PROOF-AUTH-CUTOVER-001
Exercise ordinary expiry/logout and emergency security revocation before dispatch, before commit, after commit, and at multi-phase checkpoints. Behavior must match the descriptor cutover class.

### PM-PROOF-CONSENT-STALE-001
Mutate target set, impact, protection, risk, expected disconnect, irreversible phase, or human-relevant UNKNOWN after trusted approval. Consent-relevant changes must require fresh approval while permitted machine-only changes can revalidate without reprompting.

### PM-PROOF-CONSENT-RENDER-001
Attack Provider labels, localization/template content, unit conversion, bidi text, stale template, and mismatched ConsentSemanticDigest. Trusted approval cannot be earned from altered security semantics.

### PM-PROOF-OBLIGATION-CYCLE-001
Inject direct/indirect obligation cycles, dependency-depth overflow, and work-budget exhaustion. None may produce positive admission/release.

### PM-PROOF-CAB-CUTOVER-001
Exercise normal supersession and emergency CAB revocation before admission, after admission/before commit, after commit, during multi-phase transactions, and during long-lived disclosure.

### PM-PROOF-WORK-ADMISSION-CLOSURE-001
Create new blockers through Prime Exec, service restart, timers, Terminal, Provider callback, watchdog, and automation while quiescing. SAFE cannot survive an unfenced relevant source.

### PM-PROOF-COMMIT-PLAN-001
For multi-unit effects, change topology/protection/support/control-session state after early units commit. Later units must re-resolve and acquire required fresh guards; partial outcomes remain truthful.

### PM-PROOF-RESERVE-HOARD-001
Use one/many clients to hoard evidence/audit reservations. Verify hierarchical quotas and protected Host-survival/security capacity.

### PM-PROOF-CONTROLSESSION-FENCE-001
Expire/revoke a control-session lease while its transport remains physically open. New privileged requests must fail.

### PM-PROOF-POLICY-COMPOSE-001
Exercise compatible tightening, incomparable constraints, empty intersections, UNKNOWN constraints, unauthorized broadening, and conflicting Prime/Host/Provider constraints. Require deterministic composition or fail-closed conflict.

### PM-PROOF-OBLIGATION-UNIVERSE-001
Omit an applicable policy source, introduce a newly applicable policy between admission and commit, revoke a closure qualification, and change obligation registries. Positive effect/release must require full re-resolution where the validity horizon requires it.

### PM-PROOF-AUDIT-RESERVE-001
Flood ordinary/denial audit storage then attempt mandatory-audit protected disclosure and security-critical admission. Protected reserve must remain available until genuine storage/media failure.

### PM-PROOF-DISCLOSURE-CUTOVER-001
Change classification/policy/Auth/session/CAB/source during a long-lived protected stream. Future bytes must stop at the defined release-guard boundary.

### PM-PROOF-COMMIT-GUARD-001
Invalidate, expire, replay, transplant, or use a guard with the wrong executor/incarnation/world digest. No unintended commit may occur.

### PM-PROOF-ADMISSION-RECEIPT-001
Tamper with or omit descriptor/obligation/closure/authorization/support/reservation fields. Admission evidence must detect the mismatch.

### PM-PROOF-EVIDENCE-QUAL-001
Attempt Provider/self-reported evidence-strength escalation and conflicting evidence. Prime must preserve provenance and unresolved conflict.

### PM-PROOF-DESCRIPTOR-RESOLUTION-001
Create zero, one, multiple overlapping privileged-effect and disclosure descriptors. Ambiguity must fail closed unless explicit composition exists.

### PM-PROOF-ATOMICITY-001
Distinguish all-target admission from effect atomicity. Inject runtime failure after partial machine effect and require per-unit/target evidence without claiming transactional rollback.

### PM-PROOF-MULTIPHASE-SAFETY-001
Change safety inputs between privileged Domain Transaction phases. Every irreversible phase must use its descriptor/checkpoint, fresh DecisionWorldFence, and required EffectCommitGuard.
