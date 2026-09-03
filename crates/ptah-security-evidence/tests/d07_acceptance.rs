//! D07 milestone acceptance corpus.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::Arc,
};

use ptah_activity_runtime::{ActivityRuntime, AttemptContext, MemoryJournal};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_security_evidence::{
    AssessmentAdmission, AssessmentAdmissionRequest, AssessmentAuthorization, AssessmentPlan,
    AssessmentTarget, CoverageProjection, D07Error, RawReportAlias, ScannerRevision,
    SecurityTestClass,
};
use ptah_workspace::{IssueGrant, WorkspaceStore};

fn er(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid ref")
}

fn db_path(label: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("ptah-d07-{label}-{}.sqlite3", EntityId::new_v7()));
    let _ = fs::remove_file(&path);
    path
}

fn clock_at(value: &'static str) -> Arc<dyn Fn() -> String + Send + Sync> {
    Arc::new(move || value.to_owned())
}

fn runtime() -> ActivityRuntime {
    ActivityRuntime::new(
        2,
        Arc::new(MemoryJournal::default()),
        clock_at("2026-09-03T00:00:00Z"),
    )
    .expect("runtime")
}

fn context() -> AttemptContext {
    AttemptContext {
        node_ref: er("core.node"),
        node_generation: 1,
        provider_ref: er("runtime.provider"),
        provider_generation: 1,
        workload_generation: 1,
        connection_epoch: 1,
        facility_ref: er("runtime.facility"),
        producer_instance_ref: er("runtime.provider_instance"),
        producer_version: "1.0.0".into(),
    }
}

struct AuthFixture {
    path: PathBuf,
    target: AssessmentTarget,
    authorization: AssessmentAuthorization,
}

fn auth_fixture() -> AuthFixture {
    let path = db_path("assessment-auth");
    let actor = er("identity.principal");
    let target = AssessmentTarget::new(
        er("core.object_revision"),
        "11".repeat(32),
        Some("src/lib.rs:1-10".into()),
    )
    .expect("target");
    let mut store =
        WorkspaceStore::open(&path, clock_at("2026-09-03T00:00:00Z")).expect("workspace");
    let grant = store
        .issue_grant(IssueGrant {
            subject_ref: target.target_ref.clone(),
            grantee_ref: actor.clone(),
            scopes: vec!["security.assess.source_static".into()],
            policy_ref: er("policy.security"),
            provider_generation: 1,
            fence_token: 77,
            expires_at: "2026-09-03T02:00:00Z".into(),
            authority_ref: er("authority.owner"),
        })
        .expect("grant");
    let authorization = AssessmentAuthorization {
        workspace_ref: er("core.workspace"),
        actor_ref: actor,
        grant_ref: grant,
        policy_refs: vec![er("policy.security")],
        target_refs: vec![target.target_ref.clone()],
        allowed_test_classes: BTreeSet::from([SecurityTestClass::SourceStatic]),
        forbidden_action_keys: BTreeSet::from(["security.destructive".into()]),
        valid_from: "2026-09-02T23:00:00Z".into(),
        expires_at: "2026-09-03T01:00:00Z".into(),
        privacy_policy_refs: vec![er("policy.privacy")],
        emergency_stop_required: true,
        cleanup_readback_required: true,
    };
    AuthFixture {
        path,
        target,
        authorization,
    }
}

fn scanner() -> ScannerRevision {
    ScannerRevision {
        provider_revision_ref: er("runtime.provider_revision"),
        package_or_plugin_revision_ref: Some(er("package.revision")),
        ruleset_ref: Some(er("core.object_revision")),
        advisory_database_ref: Some(er("core.object_revision")),
        policy_ref: Some(er("policy.security")),
        model_ref: None,
        configuration_digest: "22".repeat(32),
    }
}

fn plan(
    auth: &AssessmentAuthorization,
    target: &AssessmentTarget,
    scanner: ScannerRevision,
) -> AssessmentPlan {
    AssessmentPlan {
        authorization_digest: auth.digest().expect("auth digest"),
        targets: vec![target.clone()],
        scanner_revision: scanner,
        recipe_revision_ref: er("build.recipe_revision"),
        compiled_plan_ref: er("build.compiled_plan"),
        operation_descriptor_digests: vec!["33".repeat(32)],
        expected_scope: BTreeSet::from(["src/lib.rs".into()]),
        stop_conditions: vec!["budget_exhausted".into()],
        output_policy_refs: vec![er("policy.evidence")],
    }
}

#[test]
fn exact_target_and_current_grant_are_required_before_assessment_work() {
    let f = auth_fixture();
    let store = WorkspaceStore::open(&f.path, clock_at("2026-09-03T00:00:00Z")).expect("reopen");
    let rt = runtime();
    let p = plan(&f.authorization, &f.target, scanner());
    let mapping = AssessmentAdmission::admit(
        &rt,
        &store,
        AssessmentAdmissionRequest {
            authorization: &f.authorization,
            plan: &p,
            target: &f.target,
            class: SecurityTestClass::SourceStatic,
            now: "2026-09-03T00:00:00Z",
            attempt_context: context(),
        },
    )
    .expect("admit");
    assert_eq!(rt.activity_count().expect("count"), 1);
    assert!(rt.attempt(mapping.attempt_id).expect("attempt").is_some());
}

#[test]
fn expired_authorization_blocks_before_a04_activity_creation() {
    let f = auth_fixture();
    let store = WorkspaceStore::open(&f.path, clock_at("2026-09-03T01:30:00Z")).expect("reopen");
    let rt = runtime();
    let p = plan(&f.authorization, &f.target, scanner());
    assert!(matches!(
        AssessmentAdmission::admit(
            &rt,
            &store,
            AssessmentAdmissionRequest {
                authorization: &f.authorization,
                plan: &p,
                target: &f.target,
                class: SecurityTestClass::SourceStatic,
                now: "2026-09-03T01:30:00Z",
                attempt_context: context(),
            },
        ),
        Err(D07Error::AuthorizationExpired)
    ));
    assert_eq!(rt.activity_count().expect("count"), 0);
}

#[test]
fn out_of_scope_test_class_or_target_fails_before_workload_invocation() {
    let f = auth_fixture();
    let store = WorkspaceStore::open(&f.path, clock_at("2026-09-03T00:00:00Z")).expect("reopen");
    let rt = runtime();
    let p = plan(&f.authorization, &f.target, scanner());
    assert!(matches!(
        AssessmentAdmission::admit(
            &rt,
            &store,
            AssessmentAdmissionRequest {
                authorization: &f.authorization,
                plan: &p,
                target: &f.target,
                class: SecurityTestClass::ExploitValidation,
                now: "2026-09-03T00:00:00Z",
                attempt_context: context(),
            },
        ),
        Err(D07Error::TestClassOutOfScope)
    ));
    let other =
        AssessmentTarget::new(er("core.object_revision"), "44".repeat(32), None).expect("other");
    assert!(matches!(
        f.authorization.authorize_at(
            &store,
            &other,
            SecurityTestClass::SourceStatic,
            "2026-09-03T00:00:00Z"
        ),
        Err(D07Error::TargetOutOfScope)
    ));
    assert_eq!(rt.activity_count().expect("count"), 0);
}

#[test]
fn newly_discovered_target_never_extends_its_own_authorization() {
    let f = auth_fixture();
    let store = WorkspaceStore::open(&f.path, clock_at("2026-09-03T00:00:00Z")).expect("reopen");
    let discovered = AssessmentTarget::new(
        er("core.object_revision"),
        "55".repeat(32),
        Some("https://new.example".into()),
    )
    .expect("discovered");
    assert!(matches!(
        f.authorization.authorize_at(
            &store,
            &discovered,
            SecurityTestClass::SourceStatic,
            "2026-09-03T00:00:00Z"
        ),
        Err(D07Error::TargetOutOfScope)
    ));
    assert_eq!(f.authorization.target_refs.len(), 1);
}

#[test]
fn assessment_plan_binds_exact_authorization_target_and_scanner_revision() {
    let f = auth_fixture();
    let p = plan(&f.authorization, &f.target, scanner());
    p.validate(&f.authorization).expect("valid plan");
    assert_eq!(p.targets[0], f.target);
    assert_eq!(
        p.authorization_digest,
        f.authorization.digest().expect("digest")
    );
}

#[test]
fn scanner_rules_database_or_configuration_drift_changes_plan_identity() {
    let f = auth_fixture();
    let first = plan(&f.authorization, &f.target, scanner());
    let mut changed_scanner = scanner();
    changed_scanner.configuration_digest = "66".repeat(32);
    let second = plan(&f.authorization, &f.target, changed_scanner);
    assert_ne!(
        first.digest().expect("first"),
        second.digest().expect("second")
    );
}

#[test]
fn zero_findings_cannot_claim_complete_coverage_with_gaps() {
    let coverage = CoverageProjection {
        expected_scope: BTreeSet::from(["a".into(), "b".into()]),
        resolved_scope: BTreeSet::from(["a".into(), "b".into()]),
        scanned_scope: BTreeSet::from(["a".into()]),
        skipped_scope: BTreeSet::from(["b".into()]),
        unsupported_scope: BTreeSet::new(),
        error_scope: BTreeMap::new(),
        limitations: vec!["b skipped".into()],
        complete: true,
    };
    assert!(matches!(
        coverage.validate(),
        Err(D07Error::CoverageOverclaim)
    ));
}

#[test]
fn raw_report_path_and_backend_run_id_are_aliases_not_identity() {
    let alias = RawReportAlias {
        path: "/tmp/report.json".into(),
        backend_run_id: "scanner-run-42".into(),
    };
    assert!(!alias.grants_identity());
    assert!(!alias.grants_authority());
}

use ptah_security_evidence::{
    ClaimProjection, CorrelationRelation, EvidenceBundleProjection, EvidenceCoverage,
    EvidenceItemBinding, FindingDraft, ObservationCorrelation, ObservationProjection,
};

#[test]
fn observation_is_not_a_finding_identity() {
    let observation = ObservationProjection {
        observation_ref: er("security.observation"),
        subject_refs: vec![er("core.object_revision")],
        evidence_refs: vec![er("security.evidence_item")],
        scanner_aliases: vec!["scanner-rule-7".into()],
        observed_facts: vec!["bounded fact".into()],
    };
    assert!(observation.finding_identity().is_none());
}

#[test]
fn scanner_candidate_requires_explicit_bounded_review_before_confirmation() {
    let observation_ref = er("security.observation");
    let draft = FindingDraft {
        subject_refs: vec![er("core.object_revision")],
        observation_refs: vec![observation_ref.clone()],
        correlations: vec![ObservationCorrelation {
            observation_ref,
            relation: CorrelationRelation::Supports,
        }],
        severity: "high".into(),
        confidence: 0.9,
        exploitability: "conditional".into(),
    };
    assert!(matches!(
        draft.validate_confirmation(None),
        Err(D07Error::ReviewRequired)
    ));
    draft
        .validate_confirmation(Some(&er("security.review_decision")))
        .expect("bounded review permits confirmation");
}

#[test]
fn contradictory_observations_both_remain_visible() {
    let supports = er("security.observation");
    let contradicts = er("security.observation");
    let draft = FindingDraft {
        subject_refs: vec![er("core.object_revision")],
        observation_refs: vec![supports.clone(), contradicts.clone()],
        correlations: vec![
            ObservationCorrelation {
                observation_ref: supports.clone(),
                relation: CorrelationRelation::Supports,
            },
            ObservationCorrelation {
                observation_ref: contradicts.clone(),
                relation: CorrelationRelation::Contradicts,
            },
        ],
        severity: "medium".into(),
        confidence: 0.5,
        exploitability: "unknown".into(),
    };
    draft
        .validate_confirmation(Some(&er("security.review_decision")))
        .expect("contradiction is retained, not erased");
    let retained = draft.correlated_observation_refs();
    assert!(retained.contains(&supports));
    assert!(retained.contains(&contradicts));
    assert_eq!(retained.len(), 2);
}

#[test]
fn bounded_claim_requires_claimant_authority_scope_and_evidence() {
    assert!(matches!(
        ClaimProjection::new(
            "bounded security claim".into(),
            None,
            Vec::new(),
            vec![er("core.object_revision")],
            vec![er("security.evidence_bundle")],
        ),
        Err(D07Error::InvalidClaim)
    ));
    let claim = ClaimProjection::new(
        "bounded security claim".into(),
        Some(er("identity.principal")),
        vec!["security.review".into()],
        vec![er("core.object_revision")],
        vec![er("security.evidence_bundle")],
    )
    .expect("valid bounded claim");
    assert_eq!(claim.statement, "bounded security claim");
    assert_eq!(claim.evidence_bundle_refs.len(), 1);
}

#[test]
fn evidence_item_binds_exact_content_digest_collector_activity_and_attempt() {
    let binding = EvidenceItemBinding::new(
        er("core.object_revision"),
        "aa".repeat(32),
        er("identity.agent"),
        er("core.activity"),
        er("core.attempt"),
    )
    .expect("exact evidence binding");
    assert_eq!(binding.sha256, "aa".repeat(32));
    assert!(matches!(
        EvidenceItemBinding::new(
            er("core.object_revision"),
            "not-a-digest".into(),
            er("identity.agent"),
            er("core.activity"),
            er("core.attempt"),
        ),
        Err(D07Error::InvalidEvidenceBinding)
    ));
}

#[test]
fn evidence_bundle_cannot_overclaim_partial_or_unknown_coverage() {
    let coverage = CoverageProjection {
        expected_scope: BTreeSet::from(["a".into(), "b".into()]),
        resolved_scope: BTreeSet::from(["a".into(), "b".into()]),
        scanned_scope: BTreeSet::from(["a".into()]),
        skipped_scope: BTreeSet::from(["b".into()]),
        unsupported_scope: BTreeSet::new(),
        error_scope: BTreeMap::new(),
        limitations: vec!["b skipped".into()],
        complete: false,
    };
    let bundle = EvidenceBundleProjection {
        evidence_item_refs: vec![er("security.evidence_item")],
        coverage: EvidenceCoverage::CompleteForClaimScope,
        limitations: Vec::new(),
    };
    assert!(matches!(
        bundle.validate_against(&coverage),
        Err(D07Error::EvidenceCoverageOverclaim)
    ));
}

use ptah_security_evidence::{
    AcceptedRiskProjection, DisclosurePolicy, DisputeProjection, ReviewDecisionProjection,
    ReviewOutcome, ValidationRequest,
};

#[test]
fn validation_run_requires_fresh_attempt_and_exact_environment_evidence() {
    let prior = er("core.attempt");
    let request = ValidationRequest {
        finding_refs: vec![er("security.finding")],
        claim_refs: vec![er("security.claim")],
        environment_refs: vec![er("core.object_revision")],
        prior_attempt_refs: vec![prior.clone()],
        attempt_context: context(),
    };
    assert!(matches!(
        request.validate_attempt(&prior),
        Err(D07Error::FreshAttemptRequired)
    ));
    request
        .validate_attempt(&er("core.attempt"))
        .expect("fresh exact Attempt accepted");
    let mut missing_environment = request.clone();
    missing_environment.environment_refs.clear();
    assert!(matches!(
        missing_environment.validate_attempt(&er("core.attempt")),
        Err(D07Error::MissingEnvironmentEvidence)
    ));
}

#[test]
fn review_decision_references_but_never_rewrites_observation_or_evidence_history() {
    let observation = ObservationProjection {
        observation_ref: er("security.observation"),
        subject_refs: vec![er("core.object_revision")],
        evidence_refs: vec![er("security.evidence_item")],
        scanner_aliases: vec!["scanner-1".into()],
        observed_facts: vec!["immutable fact".into()],
    };
    let before = observation.clone();
    let review = ReviewDecisionProjection {
        finding_refs: vec![er("security.finding")],
        claim_refs: vec![er("security.claim")],
        validation_run_refs: vec![er("security.validation_run")],
        reviewer_ref: er("identity.principal"),
        authority_scope: vec!["security.review".into()],
        outcome: ReviewOutcome::AcceptedWithLimitations,
        reasons: vec!["bounded review".into()],
    };
    review.validate().expect("review projection");
    assert_eq!(observation, before);
}

#[test]
fn accepted_risk_expires_without_deleting_the_finding() {
    let finding = er("security.finding");
    let risk = AcceptedRiskProjection {
        finding_refs: vec![finding.clone()],
        authority_ref: er("identity.principal"),
        expires_at: "2026-09-04T00:00:00Z".into(),
    };
    assert!(risk.is_active_at("2026-09-03T12:00:00Z").expect("active"));
    assert!(!risk.is_active_at("2026-09-04T00:00:00Z").expect("expired"));
    assert_eq!(risk.finding_refs, vec![finding]);
}

#[test]
fn dispute_retains_all_competing_claims_and_evidence() {
    let first_claim = er("security.claim");
    let second_claim = er("security.claim");
    let first_evidence = er("security.evidence_bundle");
    let second_evidence = er("security.evidence_bundle");
    let dispute = DisputeProjection {
        finding_refs: vec![er("security.finding")],
        claim_refs: vec![first_claim.clone(), second_claim.clone()],
        evidence_bundle_refs: vec![first_evidence.clone(), second_evidence.clone()],
    };
    dispute.validate().expect("complete dispute");
    assert_eq!(dispute.claim_refs, vec![first_claim, second_claim]);
    assert_eq!(
        dispute.evidence_bundle_refs,
        vec![first_evidence, second_evidence]
    );
}

#[test]
fn public_disclosure_requires_explicit_redacted_content_and_privacy_authority() {
    let restricted = er("security.evidence_item");
    let policy = DisclosurePolicy {
        audience: "public".into(),
        redaction_policy_refs: vec![er("policy.redaction")],
        privacy_policy_refs: vec![er("policy.privacy")],
        authority_ref: er("identity.principal"),
    };
    assert!(matches!(
        policy.authorize(std::slice::from_ref(&restricted), &[]),
        Err(D07Error::DisclosureDenied)
    ));
    policy
        .authorize(&[restricted], &[er("core.object_revision")])
        .expect("explicit redacted disclosed content");
}

use ptah_security_evidence::{
    PatchBinding, PostFixDecision, PostFixVerificationRequest, RemediationAcknowledgement,
    RemediationExecutionRequest,
};

#[test]
fn remediation_proposal_is_not_a_patch() {
    assert!(matches!(
        PatchBinding::new(
            er("security.remediation_proposal"),
            er("security.remediation_proposal"),
            vec![er("core.object_revision")],
            er("runtime.provider_revision"),
            "aa".repeat(32),
            Some("src/lib.rs".into()),
        ),
        Err(D07Error::InvalidPatchBinding)
    ));
}

#[test]
fn patch_requires_exact_a07_object_base_revision_and_digest_while_path_is_alias_only() {
    let patch_object = er("core.object_revision");
    let patch = PatchBinding::new(
        er("security.remediation_proposal"),
        patch_object.clone(),
        vec![er("core.object_revision")],
        er("runtime.provider_revision"),
        "bb".repeat(32),
        Some("/workspace/src/lib.rs".into()),
    )
    .expect("exact patch binding");
    assert_eq!(patch.patch_identity(), &patch_object);
    assert_eq!(patch.path_alias.as_deref(), Some("/workspace/src/lib.rs"));
    assert!(matches!(
        PatchBinding::new(
            er("security.remediation_proposal"),
            er("core.object_revision"),
            Vec::new(),
            er("runtime.provider_revision"),
            "bad-digest".into(),
            None,
        ),
        Err(D07Error::InvalidPatchBinding)
    ));
}

#[test]
fn patch_application_acknowledgement_remains_applied_unverified() {
    let request = RemediationExecutionRequest {
        proposal_ref: er("security.remediation_proposal"),
        patch_ref: er("security.patch"),
        target_refs: vec![er("core.object_revision")],
        backup_refs: vec![er("core.object_revision")],
        activity_request_ref: er("core.activity_request"),
        authority_ref: er("identity.principal"),
        attempt_context: context(),
    };
    request.validate().expect("bounded execution request");
    let ack = RemediationAcknowledgement::applied_unverified(er("security.remediation_run"));
    assert_eq!(ack.outcome(), "applied_unverified");
    assert!(!ack.satisfies_post_fix_verification());
}

#[test]
fn post_fix_verification_requires_fresh_attempt_and_retains_regression_after_prior_closure() {
    let old_attempt = er("core.attempt");
    let request = PostFixVerificationRequest {
        remediation_run_ref: er("security.remediation_run"),
        finding_refs: vec![er("security.finding")],
        target_refs: vec![er("core.object_revision")],
        environment_refs: vec![er("core.object_revision")],
        prior_attempt_refs: vec![old_attempt.clone()],
        decision: PostFixDecision::Regressed,
        evidence_bundle_refs: vec![er("security.evidence_bundle")],
    };
    assert!(matches!(
        request.validate_attempt(&old_attempt),
        Err(D07Error::FreshAttemptRequired)
    ));
    request
        .validate_attempt(&er("core.attempt"))
        .expect("fresh verification Attempt");
    let history = request.history_after(Some(PostFixDecision::FixedVerified));
    assert_eq!(
        history,
        vec![PostFixDecision::FixedVerified, PostFixDecision::Regressed]
    );
}
