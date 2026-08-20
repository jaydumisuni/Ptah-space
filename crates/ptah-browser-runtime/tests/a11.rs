//! A11 discriminating acceptance corpus for the canonical Browser runtime.

use ptah_activity_runtime::{ACTIVITY_SCHEMA_ID, ATTEMPT_SCHEMA_ID, OPERATION_SCHEMA_ID};
use ptah_browser_runtime::{
    A11_SCHEMA_VERSION, BROWSER_BINARY_REVISION_SCHEMA_ID, BROWSER_BINARY_SCHEMA_ID,
    BROWSER_CONTEXT_SCHEMA_ID, BROWSER_DOWNLOAD_SCHEMA_ID, BROWSER_EVIDENCE_BUNDLE_SCHEMA_ID,
    BROWSER_PROCESS_SCHEMA_ID, BROWSER_PROFILE_REVISION_SCHEMA_ID, BROWSER_PROFILE_SCHEMA_ID,
    BrowserChallengeState, BrowserContextSpec, BrowserDownloadSpec, BrowserError,
    BrowserEvidenceBundleSpec, BrowserEvidenceClass, BrowserPageSpec, BrowserProcessSpec,
    BrowserProfileMode, BrowserProfileSpec, BrowserRuntime, ChallengeSpec, EvidenceCoverage,
    EvidenceMemberSpec, FENCE_OBSERVATION_SCHEMA_ID, LEASE_SCHEMA_ID, NavigationSpec,
    NavigationState, WORKSPACE_MATERIALIZATION_SCHEMA_ID, WritableSharingPolicy,
};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::{CanonicalRecord, Ledger};
use ptah_object_store::{CONTENT_SCHEMA_ID, OBJECT_SCHEMA_ID};
use ptah_provider_api::{
    ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind, ProviderReachability,
    ProviderReadiness, ProviderRevision,
};
use ptah_transfer::TRANSFER_REQUEST_SCHEMA_ID;
use serde_json::{Map, Value, json};
use std::fs;
use std::path::PathBuf;

const NOW: &str = "2026-08-20T20:00:00Z";

struct Fixture {
    path: PathBuf,
    runtime: BrowserRuntime,
    workspace: EntityRef,
    authority: EntityRef,
    materialization: EntityRef,
    binary: EntityRef,
    binary_revision: EntityRef,
    content: EntityRef,
    storage_object: EntityRef,
    activity: EntityRef,
    operation: EntityRef,
    startup_attempt: EntityRef,
    provider_revision: ProviderRevision,
    provider_instance: ProviderInstance,
    native_process: EntityRef,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(self.path.with_extension("db-shm"));
        let _ = fs::remove_file(self.path.with_extension("db-wal"));
    }
}

impl Fixture {
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("ptah-a11-{}.db", EntityId::new_v7()));
        let mut ledger = Ledger::open(&path).expect("open ledger");
        let workspace = reference("workspace.workspace");
        let authority = reference("authority.owner");
        let materialization = reference("workspace.materialization");
        let binary = reference("browser.binary");
        let binary_revision = reference("browser.binary_revision");
        let content = reference("object.content");
        let storage_object = reference("object.object");
        let activity = reference("core.activity");
        let operation = reference("core.operation");
        let startup_attempt = reference("core.attempt");
        let native_process = reference("runtime.native_process");

        seed(
            &mut ledger,
            &materialization,
            WORKSPACE_MATERIALIZATION_SCHEMA_ID,
            &workspace,
            &authority,
            json!({"materialization_generation": 7}),
        );
        seed(
            &mut ledger,
            &binary,
            BROWSER_BINARY_SCHEMA_ID,
            &workspace,
            &authority,
            json!({"name":"chromium","version":"148.0.7778.96"}),
        );
        seed(
            &mut ledger,
            &binary_revision,
            BROWSER_BINARY_REVISION_SCHEMA_ID,
            &workspace,
            &authority,
            json!({"browser_binary_ref": binary, "revision":"1223"}),
        );
        seed(
            &mut ledger,
            &content,
            CONTENT_SCHEMA_ID,
            &workspace,
            &authority,
            json!({"digest":"sha256:profile"}),
        );
        seed(
            &mut ledger,
            &storage_object,
            OBJECT_SCHEMA_ID,
            &workspace,
            &authority,
            json!({"purpose":"browser_profile_storage"}),
        );
        seed(
            &mut ledger,
            &activity,
            ACTIVITY_SCHEMA_ID,
            &workspace,
            &authority,
            json!({"purpose":"browser"}),
        );
        seed(
            &mut ledger,
            &operation,
            OPERATION_SCHEMA_ID,
            &workspace,
            &authority,
            json!({"activity_ref": activity}),
        );
        seed(
            &mut ledger,
            &startup_attempt,
            ATTEMPT_SCHEMA_ID,
            &workspace,
            &authority,
            json!({"activity_ref": activity, "operation_ref": operation}),
        );

        let provider_revision_ref = reference("runtime.provider_revision");
        let provider_ref = reference("runtime.provider");
        let provider_revision = ProviderRevision {
            revision_ref: provider_revision_ref.clone(),
            provider_ref,
            provider_kind: ProviderKind::Browser,
            implementation_name: "ptah-browser-provider".into(),
            implementation_version: "1.60.0".into(),
            build_or_package_digest: "sha256:playwright-1.60.0".into(),
            configuration_digest: "sha256:chromium-1223".into(),
            supported_facility_refs: vec![reference("runtime.facility")],
            capability_claim_refs: vec![reference("proof.capability")],
            dependency_refs: vec![reference("proof.dependency")],
            node_requirements: vec!["node 24.18.0".into()],
            security_requirements: vec!["privacy filtering".into()],
            known_limitations: vec!["human challenges require external completion".into()],
        };
        let provider_instance = ProviderInstance {
            instance_ref: reference("runtime.provider_instance"),
            provider_revision_ref,
            node_ref: reference("core.node"),
            node_generation: 3,
            provider_generation: ProviderGeneration::new(4).expect("provider generation"),
            connection_epoch: 9,
            reachability: ProviderReachability::Reachable,
            readiness: ProviderReadiness::Ready,
            health: ProviderHealth::Healthy,
            endpoint_aliases: Vec::new(),
            process_or_service_refs: vec![native_process.clone()],
            observation_refs: vec![reference("proof.evidence")],
            started_at: NOW.into(),
            limitations: Vec::new(),
        };
        Self {
            path,
            runtime: BrowserRuntime::new(ledger),
            workspace,
            authority,
            materialization,
            binary,
            binary_revision,
            content,
            storage_object,
            activity,
            operation,
            startup_attempt,
            provider_revision,
            provider_instance,
            native_process,
        }
    }

    fn persistent_profile(&mut self) -> (EntityRef, EntityRef) {
        let handle = self
            .runtime
            .create_profile(
                &BrowserProfileSpec {
                    workspace_ref: self.workspace.clone(),
                    authority_ref: self.authority.clone(),
                    mode: BrowserProfileMode::PersistentExclusive,
                    writable_sharing_policy: WritableSharingPolicy::SerializedWriter,
                    storage_object_refs: vec![self.storage_object.clone()],
                    content_digest_refs: vec![self.content.clone()],
                    policy_refs: vec![reference("policy.browser_profile")],
                    browser_binary_revision_refs: vec![self.binary_revision.clone()],
                    privacy_policy_refs: vec![reference("policy.privacy")],
                    retention_policy_refs: vec![reference("policy.retention")],
                    encryption_policy_ref: None,
                },
                NOW,
            )
            .expect("profile");
        (handle.profile_ref, handle.profile_revision_ref)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn process(&mut self, profile: Option<(EntityRef, EntityRef)>) -> EntityRef {
        let process = self
            .runtime
            .create_process(
                &BrowserProcessSpec {
                    workspace_ref: self.workspace.clone(),
                    authority_ref: self.authority.clone(),
                    materialization_ref: self.materialization.clone(),
                    materialization_generation: 7,
                    browser_binary_ref: self.binary.clone(),
                    browser_binary_revision_ref: self.binary_revision.clone(),
                    profile_ref: profile.as_ref().map(|pair| pair.0.clone()),
                    profile_revision_ref: profile.as_ref().map(|pair| pair.1.clone()),
                    runtime_process_ref: self.native_process.clone(),
                    activity_ref: self.activity.clone(),
                    operation_ref: self.operation.clone(),
                    attempt_ref: self.startup_attempt.clone(),
                    provider_revision: self.provider_revision.clone(),
                    provider_instance: self.provider_instance.clone(),
                    privacy_policy_refs: vec![reference("policy.privacy")],
                    backend_aliases: vec![json!({"type":"process_id","value":"4242"})],
                },
                NOW,
            )
            .expect("process");
        self.runtime
            .mark_process_ready(
                &process,
                1,
                &self.authority,
                &[reference("proof.readiness")],
                NOW,
            )
            .expect("ready");
        process
    }

    #[allow(clippy::needless_pass_by_value)]
    fn readonly_context(
        &mut self,
        process: &EntityRef,
        profile: Option<(EntityRef, EntityRef)>,
    ) -> EntityRef {
        self.runtime
            .create_context(
                &BrowserContextSpec {
                    workspace_ref: self.workspace.clone(),
                    authority_ref: self.authority.clone(),
                    browser_process_ref: process.clone(),
                    process_generation: 1,
                    context_generation: 1,
                    profile_ref: profile.as_ref().map(|pair| pair.0.clone()),
                    profile_revision_ref: profile.as_ref().map(|pair| pair.1.clone()),
                    storage_mode: if profile.is_some() {
                        "persistent_readonly".into()
                    } else {
                        "ephemeral".into()
                    },
                    writable_profile_lease_ref: None,
                    writable_profile_fence_ref: None,
                    network_policy_refs: vec![reference("policy.network")],
                    permission_policy_refs: vec![reference("policy.permission")],
                    privacy_policy_refs: vec![reference("policy.privacy")],
                },
                NOW,
            )
            .expect("context")
    }

    fn page(
        &mut self,
        process: &EntityRef,
        context: &EntityRef,
        profile: Option<EntityRef>,
    ) -> EntityRef {
        self.runtime
            .create_page(
                &BrowserPageSpec {
                    workspace_ref: self.workspace.clone(),
                    authority_ref: self.authority.clone(),
                    context_ref: context.clone(),
                    browser_process_ref: process.clone(),
                    process_generation: 1,
                    context_generation: 1,
                    page_generation: 1,
                    profile_ref: profile,
                    privacy_policy_refs: vec![reference("policy.privacy")],
                    backend_aliases: vec![json!({"type":"playwright_page","value":"opaque-1"})],
                },
                NOW,
            )
            .expect("page")
    }

    fn fresh_attempt(&mut self) -> EntityRef {
        let attempt = reference("core.attempt");
        let mut ledger = self.runtime_into_ledger();
        seed(
            &mut ledger,
            &attempt,
            ATTEMPT_SCHEMA_ID,
            &self.workspace,
            &self.authority,
            json!({"activity_ref": self.activity, "operation_ref": self.operation}),
        );
        self.runtime = BrowserRuntime::new(ledger);
        attempt
    }

    fn seed_runtime(&mut self, reference: &EntityRef, schema: &str, fields: Value) {
        let mut ledger = self.runtime_into_ledger();
        seed(
            &mut ledger,
            reference,
            schema,
            &self.workspace,
            &self.authority,
            fields,
        );
        self.runtime = BrowserRuntime::new(ledger);
    }

    fn runtime_into_ledger(&mut self) -> Ledger {
        let replacement = Ledger::open(
            std::env::temp_dir().join(format!("ptah-a11-swap-{}.db", EntityId::new_v7())),
        )
        .expect("temporary replacement ledger");
        let runtime = std::mem::replace(&mut self.runtime, BrowserRuntime::new(replacement));
        runtime.into_ledger()
    }
}

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("reference")
}

fn seed(
    ledger: &mut Ledger,
    reference: &EntityRef,
    schema: &str,
    workspace: &EntityRef,
    authority: &EntityRef,
    fields: Value,
) {
    let envelope = json!({
        "entity_id": reference.entity_id.to_string(),
        "entity_kind": reference.entity_kind.as_str(),
        "schema_id": schema,
        "schema_version": A11_SCHEMA_VERSION,
        "record_revision": 1,
        "created_at": NOW,
        "updated_at": NOW,
        "workspace_ref": workspace,
        "authority_ref": authority,
        "privacy_class": "internal",
        "audience": "workspace",
        "redaction_policy": "test",
        "retention_policy": {
            "policy_id":"test",
            "policy_version":"0.1.0",
            "retention_class":"historical",
            "delete_bytes_when_unreferenced":false
        },
        "extensions": {}
    });
    let mut root = Map::new();
    root.insert("envelope".into(), envelope);
    if let Value::Object(values) = fields {
        root.extend(values);
    }
    let record = CanonicalRecord::from_document(Value::Object(root)).expect("canonical fixture");
    let write = ledger.begin_write().expect("write");
    write.insert(&record).expect("insert fixture");
    write.commit().expect("commit fixture");
}

fn nav_spec(
    fixture: &Fixture,
    process: &EntityRef,
    context: &EntityRef,
    page: &EntityRef,
    attempt: &EntityRef,
    sequence: u64,
) -> NavigationSpec {
    NavigationSpec {
        workspace_ref: fixture.workspace.clone(),
        authority_ref: fixture.authority.clone(),
        page_ref: page.clone(),
        context_ref: context.clone(),
        browser_process_ref: process.clone(),
        process_generation: 1,
        context_generation: 1,
        page_generation: 1,
        navigation_sequence: sequence,
        requested_url: format!("https://example.test/{sequence}"),
        activity_ref: fixture.activity.clone(),
        operation_ref: fixture.operation.clone(),
        attempt_ref: attempt.clone(),
        evidence_refs: vec![reference("proof.navigation_request")],
    }
}

#[test]
fn persistent_profile_survives_reopen_and_omits_absent_optionals() {
    let mut fixture = Fixture::new();
    let (profile, _revision) = fixture.persistent_profile();
    let document = fixture
        .runtime
        .latest_document(&profile)
        .expect("profile document");
    assert_eq!(document["state_projection"]["state"], "available");
    assert!(document.get("encryption_policy_ref").is_none());

    let ledger = fixture.runtime_into_ledger();
    drop(ledger);
    let reopened = Ledger::open(&fixture.path).expect("reopen durable ledger");
    fixture.runtime = BrowserRuntime::new(reopened);
    let reopened_document = fixture
        .runtime
        .latest_document(&profile)
        .expect("reopened profile");
    assert_eq!(reopened_document["state_projection"]["state"], "available");
}

#[test]
fn process_requires_exact_materialization_binary_provider_and_runtime_process_binding() {
    let mut fixture = Fixture::new();
    let profile = fixture.persistent_profile();
    let mut spec = BrowserProcessSpec {
        workspace_ref: fixture.workspace.clone(),
        authority_ref: fixture.authority.clone(),
        materialization_ref: fixture.materialization.clone(),
        materialization_generation: 8,
        browser_binary_ref: fixture.binary.clone(),
        browser_binary_revision_ref: fixture.binary_revision.clone(),
        profile_ref: Some(profile.0.clone()),
        profile_revision_ref: Some(profile.1.clone()),
        runtime_process_ref: fixture.native_process.clone(),
        activity_ref: fixture.activity.clone(),
        operation_ref: fixture.operation.clone(),
        attempt_ref: fixture.startup_attempt.clone(),
        provider_revision: fixture.provider_revision.clone(),
        provider_instance: fixture.provider_instance.clone(),
        privacy_policy_refs: vec![reference("policy.privacy")],
        backend_aliases: Vec::new(),
    };
    assert!(matches!(
        fixture.runtime.create_process(&spec, NOW),
        Err(BrowserError::StaleGeneration)
    ));
    spec.materialization_generation = 7;
    spec.runtime_process_ref = reference("runtime.native_process");
    assert!(matches!(
        fixture.runtime.create_process(&spec, NOW),
        Err(BrowserError::MissingEvidence(_))
    ));
    spec.runtime_process_ref = fixture.native_process.clone();
    let wrong_binary = reference("browser.binary");
    spec.browser_binary_ref = wrong_binary;
    assert!(matches!(
        fixture.runtime.create_process(&spec, NOW),
        Err(BrowserError::NotFound(_))
    ));
    spec.browser_binary_ref = fixture.binary.clone();
    let process = fixture
        .runtime
        .create_process(&spec, NOW)
        .expect("valid process");
    let doc = fixture
        .runtime
        .latest_document(&process)
        .expect("process document");
    assert_eq!(doc["provider_generation"], 4);
    assert_eq!(doc["state_projection"]["state"], "starting");
}

#[test]
fn stale_context_and_page_generation_fail_closed() {
    let mut fixture = Fixture::new();
    let profile = fixture.persistent_profile();
    let process = fixture.process(Some(profile.clone()));
    let bad_context = BrowserContextSpec {
        workspace_ref: fixture.workspace.clone(),
        authority_ref: fixture.authority.clone(),
        browser_process_ref: process.clone(),
        process_generation: 2,
        context_generation: 1,
        profile_ref: Some(profile.0.clone()),
        profile_revision_ref: Some(profile.1.clone()),
        storage_mode: "persistent_readonly".into(),
        writable_profile_lease_ref: None,
        writable_profile_fence_ref: None,
        network_policy_refs: vec![reference("policy.network")],
        permission_policy_refs: vec![reference("policy.permission")],
        privacy_policy_refs: vec![reference("policy.privacy")],
    };
    assert!(matches!(
        fixture.runtime.create_context(&bad_context, NOW),
        Err(BrowserError::StaleGeneration)
    ));
    let context = fixture.readonly_context(&process, Some(profile.clone()));
    let bad_page = BrowserPageSpec {
        workspace_ref: fixture.workspace.clone(),
        authority_ref: fixture.authority.clone(),
        context_ref: context.clone(),
        browser_process_ref: process,
        process_generation: 1,
        context_generation: 2,
        page_generation: 1,
        profile_ref: Some(profile.0),
        privacy_policy_refs: vec![reference("policy.privacy")],
        backend_aliases: Vec::new(),
    };
    assert!(matches!(
        fixture.runtime.create_page(&bad_page, NOW),
        Err(BrowserError::StaleGeneration)
    ));
}

#[test]
fn navigation_ack_is_not_success_and_a04_attempt_identity_cannot_be_reused() {
    let mut fixture = Fixture::new();
    let profile = fixture.persistent_profile();
    let process = fixture.process(Some(profile.clone()));
    let context = fixture.readonly_context(&process, Some(profile.clone()));
    let page = fixture.page(&process, &context, Some(profile.0));

    let startup_spec = nav_spec(
        &fixture,
        &process,
        &context,
        &page,
        &fixture.startup_attempt,
        1,
    );
    assert!(matches!(
        fixture.runtime.begin_navigation(&startup_spec, NOW),
        Err(BrowserError::AttemptReuseForbidden)
    ));

    let attempt = fixture.fresh_attempt();
    let navigation = fixture
        .runtime
        .begin_navigation(
            &nav_spec(&fixture, &process, &context, &page, &attempt, 1),
            NOW,
        )
        .expect("navigation");
    let nav_doc = fixture
        .runtime
        .latest_document(&navigation)
        .expect("nav doc");
    assert_eq!(nav_doc["provider_acknowledged"], true);
    assert_eq!(nav_doc["postcondition_verified"], false);
    assert_eq!(
        fixture.runtime.latest_document(&page).expect("page")["state_projection"]["state"],
        "navigating"
    );
    fixture
        .runtime
        .observe_navigation(
            &navigation,
            &page,
            NavigationState::LoadComplete,
            &fixture.authority,
            &[reference("proof.load")],
            NOW,
        )
        .expect("verify navigation");
    let nav_doc = fixture
        .runtime
        .latest_document(&navigation)
        .expect("nav verified");
    assert_eq!(nav_doc["postcondition_verified"], true);
    assert_eq!(
        fixture.runtime.latest_document(&page).expect("page ready")["state_projection"]["state"],
        "ready"
    );
    assert!(matches!(
        fixture.runtime.begin_navigation(
            &nav_spec(&fixture, &process, &context, &page, &attempt, 2),
            NOW
        ),
        Err(BrowserError::AttemptReuseForbidden)
    ));
}

#[test]
fn mfa_or_human_challenge_fences_navigation_until_evidenced_resolution() {
    let mut fixture = Fixture::new();
    let profile = fixture.persistent_profile();
    let process = fixture.process(Some(profile.clone()));
    let context = fixture.readonly_context(&process, Some(profile.clone()));
    let page = fixture.page(&process, &context, Some(profile.0.clone()));
    let attempt = fixture.fresh_attempt();
    let navigation = fixture
        .runtime
        .begin_navigation(
            &nav_spec(&fixture, &process, &context, &page, &attempt, 1),
            NOW,
        )
        .expect("navigation");
    let challenge = fixture
        .runtime
        .record_challenge(
            &ChallengeSpec {
                workspace_ref: fixture.workspace.clone(),
                authority_ref: fixture.authority.clone(),
                page_ref: page.clone(),
                navigation_ref: Some(navigation.clone()),
                context_ref: context.clone(),
                profile_ref: profile.0,
                browser_process_ref: process.clone(),
                process_generation: 1,
                state: BrowserChallengeState::MfaRequired,
                required_actor_class: "human".into(),
                automation_pause_required: true,
                human_completion_allowed: true,
                policy_refs: vec![reference("policy.challenge")],
                evidence_refs: vec![reference("proof.challenge")],
                privacy_policy_refs: vec![reference("policy.privacy")],
            },
            NOW,
        )
        .expect("challenge");
    assert!(matches!(
        fixture.runtime.observe_navigation(
            &navigation,
            &page,
            NavigationState::LoadComplete,
            &fixture.authority,
            &[reference("proof.load")],
            NOW
        ),
        Err(BrowserError::ChallengeBypassForbidden)
    ));
    let attempt2 = fixture.fresh_attempt();
    assert!(matches!(
        fixture.runtime.begin_navigation(
            &nav_spec(&fixture, &process, &context, &page, &attempt2, 2),
            NOW
        ),
        Err(BrowserError::ChallengeBypassForbidden)
    ));
    fixture
        .runtime
        .resolve_challenge(
            &challenge,
            &fixture.authority,
            &[reference("proof.human_completion")],
            &[reference("proof.receipt")],
            NOW,
        )
        .expect("resolve challenge");
    assert_eq!(
        fixture
            .runtime
            .latest_document(&page)
            .expect("still challenged")["state_projection"]["state"],
        "challenged"
    );
    fixture
        .runtime
        .observe_navigation(
            &navigation,
            &page,
            NavigationState::LoadComplete,
            &fixture.authority,
            &[reference("proof.load_after_mfa")],
            NOW,
        )
        .expect("post-resolution readiness");
    assert_eq!(
        fixture.runtime.latest_document(&page).expect("ready")["state_projection"]["state"],
        "ready"
    );
}

#[test]
fn browser_download_requires_a08_transfer_truth_and_does_not_manufacture_a07_identity() {
    let mut fixture = Fixture::new();
    let profile = fixture.persistent_profile();
    let process = fixture.process(Some(profile.clone()));
    let context = fixture.readonly_context(&process, Some(profile.clone()));
    let page = fixture.page(&process, &context, Some(profile.0.clone()));
    let attempt = fixture.fresh_attempt();
    let navigation = fixture
        .runtime
        .begin_navigation(
            &nav_spec(&fixture, &process, &context, &page, &attempt, 1),
            NOW,
        )
        .expect("navigation");
    let missing_transfer = reference("transfer.request");
    let mut spec = BrowserDownloadSpec {
        workspace_ref: fixture.workspace.clone(),
        authority_ref: fixture.authority.clone(),
        page_ref: page,
        context_ref: context,
        profile_ref: profile.0,
        browser_process_ref: process,
        process_generation: 1,
        navigation_ref: navigation,
        initiating_event_ref: reference("event.event"),
        initiating_action_ref: None,
        transfer_request_ref: missing_transfer.clone(),
        suggested_filename: None,
        source_url: None,
        privacy_policy_refs: vec![reference("policy.privacy")],
    };
    assert!(matches!(
        fixture.runtime.create_download(&spec, NOW),
        Err(BrowserError::TransferRequestRequired)
    ));
    fixture.seed_runtime(
        &missing_transfer,
        TRANSFER_REQUEST_SCHEMA_ID,
        json!({"mode":"download"}),
    );
    spec.transfer_request_ref = missing_transfer;
    let download = fixture
        .runtime
        .create_download(&spec, NOW)
        .expect("download");
    let doc = fixture
        .runtime
        .latest_document(&download)
        .expect("download doc");
    assert_eq!(doc["envelope"]["schema_id"], BROWSER_DOWNLOAD_SCHEMA_ID);
    assert!(doc.get("suggested_filename").is_none());
    assert!(doc.get("source_url").is_none());
    assert!(doc.get("content_ref").is_none());
    assert!(doc.get("object_ref").is_none());
}

#[test]
fn evidence_bundle_preserves_dom_screenshot_and_network_as_distinct_a07_objects() {
    let mut fixture = Fixture::new();
    let profile = fixture.persistent_profile();
    let process = fixture.process(Some(profile.clone()));
    let context = fixture.readonly_context(&process, Some(profile.clone()));
    let page = fixture.page(&process, &context, Some(profile.0));
    let attempt = fixture.fresh_attempt();
    let navigation = fixture
        .runtime
        .begin_navigation(
            &nav_spec(&fixture, &process, &context, &page, &attempt, 1),
            NOW,
        )
        .expect("navigation");
    let manifest = reference("object.object");
    let dom = reference("object.object");
    let screenshot = reference("object.object");
    let network = reference("object.object");
    for reference in [&manifest, &dom, &screenshot, &network] {
        fixture.seed_runtime(reference, OBJECT_SCHEMA_ID, json!({"evidence":true}));
    }
    let bundle = fixture
        .runtime
        .create_evidence_bundle(
            &BrowserEvidenceBundleSpec {
                workspace_ref: fixture.workspace.clone(),
                authority_ref: fixture.authority.clone(),
                page_ref: page,
                context_ref: context,
                browser_process_ref: process,
                process_generation: 1,
                navigation_ref: navigation,
                manifest_object_ref: manifest,
                evidence_members: vec![
                    EvidenceMemberSpec {
                        evidence_class: BrowserEvidenceClass::DomSnapshot,
                        object_ref: dom.clone(),
                        artifact_ref: None,
                        captured_at: NOW.into(),
                        coverage: EvidenceCoverage::CompleteForDeclaredScope,
                    },
                    EvidenceMemberSpec {
                        evidence_class: BrowserEvidenceClass::Screenshot,
                        object_ref: screenshot.clone(),
                        artifact_ref: None,
                        captured_at: NOW.into(),
                        coverage: EvidenceCoverage::CompleteForDeclaredScope,
                    },
                    EvidenceMemberSpec {
                        evidence_class: BrowserEvidenceClass::NetworkLog,
                        object_ref: network.clone(),
                        artifact_ref: None,
                        captured_at: NOW.into(),
                        coverage: EvidenceCoverage::Redacted,
                    },
                ],
                integrity_state: "verified".into(),
                privacy_policy_refs: vec![reference("policy.privacy")],
            },
            NOW,
        )
        .expect("evidence bundle");
    let doc = fixture
        .runtime
        .latest_document(&bundle)
        .expect("bundle doc");
    assert_eq!(
        doc["envelope"]["schema_id"],
        BROWSER_EVIDENCE_BUNDLE_SCHEMA_ID
    );
    let members = doc["evidence_members"].as_array().expect("members");
    assert_eq!(members.len(), 3);
    assert_ne!(members[0]["object_ref"], members[1]["object_ref"]);
    assert_ne!(members[1]["object_ref"], members[2]["object_ref"]);
}

#[test]
fn detach_and_reconnect_preserve_process_identity_and_generation() {
    let mut fixture = Fixture::new();
    let profile = fixture.persistent_profile();
    let process = fixture.process(Some(profile));
    fixture
        .runtime
        .detach_process(&process, 1, &fixture.authority, NOW)
        .expect("detach");
    let detached = fixture.runtime.latest_document(&process).expect("detached");
    assert_eq!(detached["state_projection"]["state"], "detached");
    assert_eq!(detached["process_generation"], 1);
    fixture
        .runtime
        .reconnect_process(
            &process,
            1,
            &fixture.authority,
            &[reference("proof.reconnect")],
            NOW,
        )
        .expect("reconnect");
    let ready = fixture.runtime.latest_document(&process).expect("ready");
    assert_eq!(ready["state_projection"]["state"], "ready");
    assert_eq!(ready["process_generation"], 1);
    assert_eq!(
        ready["envelope"]["entity_id"],
        process.entity_id.to_string()
    );
}

#[test]
fn writable_profile_uses_current_lease_fence_serializes_writer_and_releases_on_close() {
    let mut fixture = Fixture::new();
    let profile = fixture.persistent_profile();
    let process = fixture.process(Some(profile.clone()));
    let lease = reference("isolation.lease");
    let fence = reference("isolation.fence_observation");
    fixture.seed_runtime(
        &lease,
        LEASE_SCHEMA_ID,
        json!({"state_projection":{"machine":"lease","machine_version":"0.1.0","state":"active","transition_sequence":1,"changed_at":NOW,"changed_by_ref":fixture.authority,"receipt_refs":[]}}),
    );
    fixture.seed_runtime(
        &fence,
        FENCE_OBSERVATION_SCHEMA_ID,
        json!({"state_projection":{"machine":"fence","machine_version":"0.1.0","state":"current","transition_sequence":1,"changed_at":NOW,"changed_by_ref":fixture.authority,"receipt_refs":[]}}),
    );
    let context_spec = BrowserContextSpec {
        workspace_ref: fixture.workspace.clone(),
        authority_ref: fixture.authority.clone(),
        browser_process_ref: process.clone(),
        process_generation: 1,
        context_generation: 1,
        profile_ref: Some(profile.0.clone()),
        profile_revision_ref: Some(profile.1.clone()),
        storage_mode: "persistent_writable".into(),
        writable_profile_lease_ref: Some(lease.clone()),
        writable_profile_fence_ref: Some(fence.clone()),
        network_policy_refs: vec![reference("policy.network")],
        permission_policy_refs: vec![reference("policy.permission")],
        privacy_policy_refs: vec![reference("policy.privacy")],
    };
    let context = fixture
        .runtime
        .create_context(&context_spec, NOW)
        .expect("writer context");
    let profile_doc = fixture
        .runtime
        .latest_document(&profile.0)
        .expect("leased profile");
    assert_eq!(profile_doc["state_projection"]["state"], "leased_writable");
    assert!(matches!(
        fixture.runtime.create_context(&context_spec, NOW),
        Err(BrowserError::WritableProfileInUse)
    ));
    fixture
        .runtime
        .close_context(
            &context,
            1,
            &fixture.authority,
            &[reference("proof.reconciliation_receipt")],
            NOW,
        )
        .expect("close writer");
    assert_eq!(
        fixture
            .runtime
            .latest_document(&profile.0)
            .expect("released profile")["state_projection"]["state"],
        "available"
    );
    let replacement = fixture
        .runtime
        .create_context(&context_spec, NOW)
        .expect("replacement writer");
    assert_ne!(replacement.entity_id, context.entity_id);
}

#[test]
fn ephemeral_context_and_page_can_omit_profile_without_serializing_null() {
    let mut fixture = Fixture::new();
    let process = fixture.process(None);
    let context = fixture.readonly_context(&process, None);
    let page = fixture.page(&process, &context, None);
    let context_doc = fixture
        .runtime
        .latest_document(&context)
        .expect("context doc");
    let page_doc = fixture.runtime.latest_document(&page).expect("page doc");
    assert_eq!(
        context_doc["envelope"]["schema_id"],
        BROWSER_CONTEXT_SCHEMA_ID
    );
    assert!(context_doc.get("profile_ref").is_none());
    assert!(context_doc.get("profile_revision_ref").is_none());
    assert!(page_doc.get("profile_ref").is_none());
}

#[test]
fn canonical_process_keeps_provider_binding_and_backend_aliases_out_of_identity() {
    let mut fixture = Fixture::new();
    let profile = fixture.persistent_profile();
    let process = fixture.process(Some(profile));
    let doc = fixture
        .runtime
        .latest_document(&process)
        .expect("process doc");
    assert_eq!(doc["envelope"]["schema_id"], BROWSER_PROCESS_SCHEMA_ID);
    assert_eq!(doc["provider_generation"], 4);
    assert_eq!(
        doc["runtime_process_ref"]["entity_kind"],
        "runtime.native_process"
    );
    assert_eq!(doc["backend_aliases"][0]["value"], "4242");
    assert_ne!(doc["envelope"]["entity_id"], "4242");
    assert_eq!(
        fixture
            .runtime
            .latest_document(&reference_with_id(process.entity_id, "browser.process"))
            .expect("same canonical identity")["envelope"]["entity_id"],
        process.entity_id.to_string()
    );
    let profile_revision = fixture
        .runtime
        .latest_document(&reference("browser.profile_revision"));
    assert!(profile_revision.is_err());
    let _ = BROWSER_PROFILE_SCHEMA_ID;
    let _ = BROWSER_PROFILE_REVISION_SCHEMA_ID;
}

fn reference_with_id(id: EntityId, kind: &str) -> EntityRef {
    EntityRef::from_id(id, kind).expect("reference with id")
}
