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
