#![forbid(unsafe_code)]
//! A11 canonical Browser runtime projections.
//!
//! Playwright/Chromium remains a mechanical Provider. This crate owns durable
//! Ptah Browser Profile, Process, Context, Page, Navigation, Challenge,
//! Download and evidence projections, exact Provider/Generation fencing, and
//! canonical Lease/fence enforcement for writable profiles.

use ptah_activity_runtime::{ACTIVITY_SCHEMA_ID, ATTEMPT_SCHEMA_ID, OPERATION_SCHEMA_ID};
use ptah_identifiers::{EntityId, EntityRef, IdentifierError};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger, LedgerError};
use ptah_object_store::{ARTIFACT_SCHEMA_ID, CONTENT_SCHEMA_ID, OBJECT_SCHEMA_ID};
use ptah_provider_api::{ProviderContext, ProviderError, ProviderInstance, ProviderRevision};
use ptah_transfer::TRANSFER_REQUEST_SCHEMA_ID;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use thiserror::Error;

/// Frozen A11 Browser schema version.
pub const A11_SCHEMA_VERSION: &str = "0.1.0";
/// Frozen Browser Profile schema.
pub const BROWSER_PROFILE_SCHEMA_ID: &str = "urn:ptah:schema:application:browser-profile:0.1.0";
/// Frozen Browser Profile Revision schema.
pub const BROWSER_PROFILE_REVISION_SCHEMA_ID: &str =
    "urn:ptah:schema:application:browser-profile-revision:0.1.0";
/// Frozen Browser Binary schema.
pub const BROWSER_BINARY_SCHEMA_ID: &str = "urn:ptah:schema:application:browser-binary:0.1.0";
/// Frozen Browser Binary Revision schema.
pub const BROWSER_BINARY_REVISION_SCHEMA_ID: &str =
    "urn:ptah:schema:application:browser-binary-revision:0.1.0";
/// Frozen Browser Process schema.
pub const BROWSER_PROCESS_SCHEMA_ID: &str = "urn:ptah:schema:application:browser-process:0.1.0";
/// Frozen Browser Context schema.
pub const BROWSER_CONTEXT_SCHEMA_ID: &str = "urn:ptah:schema:application:browser-context:0.1.0";
/// Frozen Browser Page schema.
pub const BROWSER_PAGE_SCHEMA_ID: &str = "urn:ptah:schema:application:browser-page:0.1.0";
/// Frozen Browser Navigation schema.
pub const BROWSER_NAVIGATION_SCHEMA_ID: &str =
    "urn:ptah:schema:application:browser-navigation:0.1.0";
/// Frozen Browser Challenge schema.
pub const BROWSER_CHALLENGE_SCHEMA_ID: &str = "urn:ptah:schema:application:browser-challenge:0.1.0";
/// Frozen Browser Challenge State schema.
pub const BROWSER_CHALLENGE_STATE_SCHEMA_ID: &str =
    "urn:ptah:schema:application:browser-challenge-state:0.1.0";
/// Frozen Browser Download schema.
pub const BROWSER_DOWNLOAD_SCHEMA_ID: &str = "urn:ptah:schema:application:browser-download:0.1.0";
/// Frozen Browser evidence-bundle schema.
pub const BROWSER_EVIDENCE_BUNDLE_SCHEMA_ID: &str =
    "urn:ptah:schema:application:browser-evidence-bundle:0.1.0";
/// Frozen Workspace materialization schema consumed by Browser Process.
pub const WORKSPACE_MATERIALIZATION_SCHEMA_ID: &str =
    "urn:ptah:schema:workspace:workspace-materialization:0.1.0";
/// Frozen canonical Lease schema consumed by writable Browser Contexts.
pub const LEASE_SCHEMA_ID: &str = "urn:ptah:schema:isolation:lease:0.1.0";
/// Frozen fence observation schema consumed by writable Browser Contexts.
pub const FENCE_OBSERVATION_SCHEMA_ID: &str = "urn:ptah:schema:isolation:fence-observation:0.1.0";

const PROFILE_KIND: &str = "browser.profile";
const PROFILE_REVISION_KIND: &str = "browser.profile_revision";
const PROCESS_KIND: &str = "browser.process";
const CONTEXT_KIND: &str = "browser.context";
const PAGE_KIND: &str = "browser.page";
const NAVIGATION_KIND: &str = "browser.navigation";
const CHALLENGE_KIND: &str = "browser.challenge";
const CHALLENGE_STATE_KIND: &str = "browser.challenge_state";
const DOWNLOAD_KIND: &str = "browser.download";
const EVIDENCE_BUNDLE_KIND: &str = "browser.evidence_bundle";

/// A11 Browser runtime failures.
#[derive(Debug, Error)]
pub enum BrowserError {
    /// Durable ledger failure.
    #[error("browser ledger failure: {0}")]
    Ledger(#[from] LedgerError),
    /// Canonical identifier failure.
    #[error("browser identifier failure: {0}")]
    Identifier(#[from] IdentifierError),
    /// Provider validation failure.
    #[error("browser provider failure: {0}")]
    Provider(#[from] ProviderError),
    /// JSON conversion failure.
    #[error("browser JSON failure: {0}")]
    Json(#[from] serde_json::Error),
    /// A canonical dependency was not found.
    #[error("required canonical browser dependency not found: {0}")]
    NotFound(EntityId),
    /// A canonical dependency had the wrong schema/kind.
    #[error("canonical browser dependency type mismatch")]
    TypeMismatch,
    /// A canonical dependency belonged to another Workspace.
    #[error("browser dependency belongs to another Workspace")]
    WorkspaceMismatch,
    /// A mandatory Policy reference was omitted.
    #[error("required browser policy evidence is missing: {0}")]
    MissingPolicy(&'static str),
    /// Profile mode and writable-sharing policy disagree.
    #[error("browser profile mode and writable sharing policy are incompatible")]
    InvalidProfileSharing,
    /// Writable persistent Profile omitted its canonical Lease/fence pair.
    #[error("writable browser profile requires a current canonical Lease and fence")]
    WritableProfileLeaseRequired,
    /// A readonly/forbidden mode attempted writable access.
    #[error("browser profile mode forbids writable sharing")]
    WritableProfileForbidden,
    /// Another Context already owns the writable Profile authority.
    #[error("browser profile already has an active writer")]
    WritableProfileInUse,
    /// A stale process/context/page/provider generation was supplied.
    #[error("stale browser generation")]
    StaleGeneration,
    /// Requested lifecycle transition is invalid.
    #[error("invalid browser lifecycle transition")]
    InvalidTransition,
    /// Required evidence was missing.
    #[error("required browser evidence is missing: {0}")]
    MissingEvidence(&'static str),
    /// Navigation observation does not identify the current navigation.
    #[error("stale browser navigation observation")]
    StaleNavigation,
    /// Required string was empty.
    #[error("required browser field is empty: {0}")]
    EmptyField(&'static str),
    /// Browser Download did not reference durable A08 transfer truth.
    #[error("browser download requires an A08 Transfer Request")]
    TransferRequestRequired,
    /// Browser evidence did not reference durable A07 Object truth.
    #[error("browser evidence requires A07 Object truth")]
    ObjectEvidenceRequired,
    /// Caller attempted to bypass a human/external challenge boundary.
    #[error("browser challenge cannot be bypassed by A11")]
    ChallengeBypassForbidden,
    /// A04 Attempt identity was reused for another Browser navigation.
    #[error("browser navigation requires a fresh A04 Attempt")]
    AttemptReuseForbidden,
    /// Canonical record revision arithmetic overflowed.
    #[error("browser record revision overflow")]
    RevisionOverflow,
}

/// Frozen Browser Profile mode vocabulary used by A11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProfileMode {
    /// Durable single-writer profile.
    PersistentExclusive,
    /// Durable profile exposed read-only to this Browser operation.
    PersistentSharedReadonly,
    /// Non-durable ephemeral profile.
    Ephemeral,
    /// Incognito/private ephemeral profile.
    Incognito,
    /// Durable profile whose mechanical storage is managed remotely.
    ManagedRemote,
    /// Contract-compatible registered mode not narrowed by this implementation.
    OtherRegistered,
}

/// Frozen Browser Profile sharing policy vocabulary used by A11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WritableSharingPolicy {
    /// Exactly one Context may write.
    ExclusiveOneContext,
    /// Exactly one Browser Process may write.
    ExclusiveOneProcess,
    /// Multiple readers; no writers.
    SharedReadonly,
    /// Writers are serialized through canonical Lease/fence authority.
    SerializedWriter,
    /// Writes are forbidden.
    Forbidden,
    /// Contract-compatible registered policy outside the narrower vocabulary.
    OtherRegistered,
}

/// Frozen Browser challenge-state vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserChallengeState {
    /// No challenge.
    None,
    /// Login is required.
    LoginRequired,
    /// Multi-factor authentication is required.
    MfaRequired,
    /// CAPTCHA or anti-bot challenge is active.
    CaptchaOrAntiBot,
    /// Consent/terms completion is required.
    ConsentOrTerms,
    /// Certificate/device approval is required.
    CertificateOrDeviceApproval,
    /// Explicit human completion is required.
    HumanCompletionRequired,
    /// Policy blocks continuation.
    BlockedByPolicy,
    /// Challenge expired.
    Expired,
    /// Challenge was externally/human resolved with evidence.
    Resolved,
}

/// Browser navigation observation states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavigationState {
    /// Request submitted/acknowledged only.
    Requested,
    /// Main document commit observed.
    Committed,
    /// `DOMContentLoaded` observed.
    DomContentLoaded,
    /// Load completion observed.
    LoadComplete,
    /// Same-document transition observed.
    SameDocument,
    /// Navigation failed.
    Failed,
    /// Navigation was cancelled.
    Cancelled,
    /// Browser/Page crashed.
    Crashed,
    /// Current state is unknown.
    Unknown,
}

/// Browser evidence classes remain separate rather than collapsing into one proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserEvidenceClass {
    /// HTTP/source response evidence.
    SourceResponse,
    /// DOM snapshot evidence.
    DomSnapshot,
    /// Accessibility-tree evidence.
    AccessibilitySnapshot,
    /// Screenshot evidence.
    Screenshot,
    /// Video evidence.
    Video,
    /// Browser trace evidence.
    Trace,
    /// Network evidence.
    NetworkLog,
    /// Console evidence.
    ConsoleLog,
    /// Download-byte evidence.
    DownloadBytes,
    /// Visible-state evidence.
    VisibleState,
    /// Human/manual completion Receipt evidence.
    ManualReceipt,
    /// Registered evidence class outside the narrower vocabulary.
    OtherRegistered,
}

/// Declared evidence coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCoverage {
    /// Complete for the explicitly declared collection scope.
    CompleteForDeclaredScope,
    /// Partial evidence only.
    Partial,
    /// Evidence exists but is redacted.
    Redacted,
    /// Evidence is unavailable.
    Unavailable,
    /// Coverage is unknown.
    Unknown,
}

/// One Browser evidence member backed by A07 Object truth.
#[derive(Debug, Clone)]
pub struct EvidenceMemberSpec {
    /// Evidence class.
    pub evidence_class: BrowserEvidenceClass,
    /// A07 Object containing evidence bytes/structure.
    pub object_ref: EntityRef,
    /// Optional promoted A07 Artifact.
    pub artifact_ref: Option<EntityRef>,
    /// Capture time.
    pub captured_at: String,
    /// Evidence coverage.
    pub coverage: EvidenceCoverage,
}

/// Browser Profile creation request.
#[derive(Debug, Clone)]
pub struct BrowserProfileSpec {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Authority creating the Profile.
    pub authority_ref: EntityRef,
    /// Profile mode.
    pub mode: BrowserProfileMode,
    /// Writable sharing policy.
    pub writable_sharing_policy: WritableSharingPolicy,
    /// A07 storage Objects backing durable profile state.
    pub storage_object_refs: Vec<EntityRef>,
    /// A07 Content digests associated with profile state.
    pub content_digest_refs: Vec<EntityRef>,
    /// Profile policy refs.
    pub policy_refs: Vec<EntityRef>,
    /// Compatible exact Browser Binary Revisions.
    pub browser_binary_revision_refs: Vec<EntityRef>,
    /// Privacy policy refs.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Retention policy refs.
    pub retention_policy_refs: Vec<EntityRef>,
    /// Optional encryption policy.
    pub encryption_policy_ref: Option<EntityRef>,
}

/// Created Browser Profile and immutable first Profile Revision.
#[derive(Debug, Clone)]
pub struct BrowserProfileHandle {
    /// Stable Profile reference.
    pub profile_ref: EntityRef,
    /// Exact first Profile Revision.
    pub profile_revision_ref: EntityRef,
}

/// Browser Process creation request.
#[derive(Debug, Clone)]
pub struct BrowserProcessSpec {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Authority creating the Process.
    pub authority_ref: EntityRef,
    /// Exact Workspace Materialization.
    pub materialization_ref: EntityRef,
    /// Expected materialization generation.
    pub materialization_generation: u64,
    /// Exact Browser Binary.
    pub browser_binary_ref: EntityRef,
    /// Exact Browser Binary Revision.
    pub browser_binary_revision_ref: EntityRef,
    /// Optional persistent Profile.
    pub profile_ref: Option<EntityRef>,
    /// Optional exact Profile Revision.
    pub profile_revision_ref: Option<EntityRef>,
    /// Canonical runtime process/service ref owned by the Provider Instance.
    pub runtime_process_ref: EntityRef,
    /// A04 Activity.
    pub activity_ref: EntityRef,
    /// A04 Operation.
    pub operation_ref: EntityRef,
    /// Fresh startup A04 Attempt.
    pub attempt_ref: EntityRef,
    /// Exact Browser Provider Revision.
    pub provider_revision: ProviderRevision,
    /// Exact Browser Provider Instance/Generation.
    pub provider_instance: ProviderInstance,
    /// Privacy policy refs.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Backend aliases/evidence only; never canonical identity.
    pub backend_aliases: Vec<Value>,
}

/// Browser Context creation request.
#[derive(Debug, Clone)]
pub struct BrowserContextSpec {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Authority creating the Context.
    pub authority_ref: EntityRef,
    /// Parent Browser Process.
    pub browser_process_ref: EntityRef,
    /// Expected Process generation.
    pub process_generation: u64,
    /// New positive Context generation.
    pub context_generation: u64,
    /// Optional persistent Profile.
    pub profile_ref: Option<EntityRef>,
    /// Optional exact Profile Revision.
    pub profile_revision_ref: Option<EntityRef>,
    /// Storage mode, such as `persistent_writable`, `persistent_readonly`, `ephemeral` or `incognito`.
    pub storage_mode: String,
    /// Canonical writable Profile Lease.
    pub writable_profile_lease_ref: Option<EntityRef>,
    /// Canonical writable Profile fence observation.
    pub writable_profile_fence_ref: Option<EntityRef>,
    /// Network policy refs.
    pub network_policy_refs: Vec<EntityRef>,
    /// Permission policy refs.
    pub permission_policy_refs: Vec<EntityRef>,
    /// Privacy policy refs.
    pub privacy_policy_refs: Vec<EntityRef>,
}

/// Browser Page creation request.
#[derive(Debug, Clone)]
pub struct BrowserPageSpec {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Authority creating the Page.
    pub authority_ref: EntityRef,
    /// Parent Context.
    pub context_ref: EntityRef,
    /// Parent Browser Process.
    pub browser_process_ref: EntityRef,
    /// Expected Process generation.
    pub process_generation: u64,
    /// Expected Context generation.
    pub context_generation: u64,
    /// New positive Page generation.
    pub page_generation: u64,
    /// Optional Profile. Must exactly match the Context when one exists.
    pub profile_ref: Option<EntityRef>,
    /// Privacy policy refs.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Backend aliases/evidence only.
    pub backend_aliases: Vec<Value>,
}

/// Browser Navigation creation request.
#[derive(Debug, Clone)]
pub struct NavigationSpec {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Authority requesting navigation.
    pub authority_ref: EntityRef,
    /// Page.
    pub page_ref: EntityRef,
    /// Context.
    pub context_ref: EntityRef,
    /// Browser Process.
    pub browser_process_ref: EntityRef,
    /// Expected Process generation.
    pub process_generation: u64,
    /// Expected Context generation.
    pub context_generation: u64,
    /// Expected Page generation.
    pub page_generation: u64,
    /// Monotonic Page-local navigation sequence.
    pub navigation_sequence: u64,
    /// Requested URL retained under Browser privacy policy.
    pub requested_url: String,
    /// A04 Activity.
    pub activity_ref: EntityRef,
    /// A04 Operation.
    pub operation_ref: EntityRef,
    /// Fresh A04 Attempt dedicated to this navigation.
    pub attempt_ref: EntityRef,
    /// Evidence refs available at request time.
    pub evidence_refs: Vec<EntityRef>,
}

/// Browser Challenge creation request.
#[derive(Debug, Clone)]
pub struct ChallengeSpec {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Authority observing the Challenge.
    pub authority_ref: EntityRef,
    /// Affected Page.
    pub page_ref: EntityRef,
    /// Optional current Navigation.
    pub navigation_ref: Option<EntityRef>,
    /// Parent Context.
    pub context_ref: EntityRef,
    /// Profile involved in challenge completion.
    pub profile_ref: EntityRef,
    /// Parent Browser Process.
    pub browser_process_ref: EntityRef,
    /// Expected Process generation.
    pub process_generation: u64,
    /// Challenge state.
    pub state: BrowserChallengeState,
    /// Required actor class, such as `human` or `external_system`.
    pub required_actor_class: String,
    /// Whether automation must pause.
    pub automation_pause_required: bool,
    /// Whether human completion is allowed.
    pub human_completion_allowed: bool,
    /// Challenge policy refs.
    pub policy_refs: Vec<EntityRef>,
    /// Observation evidence refs.
    pub evidence_refs: Vec<EntityRef>,
    /// Privacy policy refs.
    pub privacy_policy_refs: Vec<EntityRef>,
}

/// Browser Download creation request.
#[derive(Debug, Clone)]
pub struct BrowserDownloadSpec {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Authority recording the Download.
    pub authority_ref: EntityRef,
    /// Source Page.
    pub page_ref: EntityRef,
    /// Parent Context.
    pub context_ref: EntityRef,
    /// Persistent Profile used by the download.
    pub profile_ref: EntityRef,
    /// Parent Browser Process.
    pub browser_process_ref: EntityRef,
    /// Expected Process generation.
    pub process_generation: u64,
    /// Navigation initiating the Download.
    pub navigation_ref: EntityRef,
    /// Browser event evidence.
    pub initiating_event_ref: EntityRef,
    /// Optional action evidence.
    pub initiating_action_ref: Option<EntityRef>,
    /// Durable A08 Transfer Request owning bytes/materialization.
    pub transfer_request_ref: EntityRef,
    /// Optional filename suggestion.
    pub suggested_filename: Option<String>,
    /// Optional source URL subject to privacy policy.
    pub source_url: Option<String>,
    /// Privacy policy refs.
    pub privacy_policy_refs: Vec<EntityRef>,
}

/// Browser evidence-bundle creation request.
#[derive(Debug, Clone)]
pub struct BrowserEvidenceBundleSpec {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Authority recording evidence.
    pub authority_ref: EntityRef,
    /// Page.
    pub page_ref: EntityRef,
    /// Context.
    pub context_ref: EntityRef,
    /// Browser Process.
    pub browser_process_ref: EntityRef,
    /// Expected Process generation.
    pub process_generation: u64,
    /// Navigation being evidenced.
    pub navigation_ref: EntityRef,
    /// A07 Object containing the evidence manifest.
    pub manifest_object_ref: EntityRef,
    /// Separate evidence members.
    pub evidence_members: Vec<EvidenceMemberSpec>,
    /// Integrity state label.
    pub integrity_state: String,
    /// Privacy policy refs.
    pub privacy_policy_refs: Vec<EntityRef>,
}

/// Durable A11 Browser runtime over the A03 repository boundary.
pub struct BrowserRuntime {
    ledger: Ledger,
}

impl BrowserRuntime {
    /// Construct from an already-open A03 ledger.
    #[must_use]
    pub const fn new(ledger: Ledger) -> Self {
        Self { ledger }
    }

    /// Return the underlying ledger when the caller needs to transfer ownership.
    #[must_use]
    pub fn into_ledger(self) -> Ledger {
        self.ledger
    }

    /// Read the latest durable JSON projection for one Browser entity.
    ///
    /// # Errors
    /// Returns a ledger failure or [`BrowserError::NotFound`].
    pub fn latest_document(&self, reference: &EntityRef) -> Result<Value, BrowserError> {
        self.latest(reference)
            .map(|record| record.document().clone())
    }

    /// Create a Browser Profile and immutable first Profile Revision.
    ///
    /// # Errors
    /// Fails closed for incompatible sharing, missing policy/evidence, cross-Workspace
    /// references, or durable write failure.
    #[allow(clippy::too_many_lines)]
    pub fn create_profile(
        &mut self,
        spec: &BrowserProfileSpec,
        now: &str,
    ) -> Result<BrowserProfileHandle, BrowserError> {
        require_nonempty(&spec.policy_refs, "profile policy")?;
        require_nonempty(&spec.privacy_policy_refs, "privacy policy")?;
        require_nonempty(&spec.content_digest_refs, "content digest refs")?;
        validate_profile_sharing(spec.mode, spec.writable_sharing_policy)?;
        for reference in &spec.content_digest_refs {
            self.require_record(reference, CONTENT_SCHEMA_ID, &spec.workspace_ref)?;
        }
        for reference in &spec.storage_object_refs {
            self.require_record(reference, OBJECT_SCHEMA_ID, &spec.workspace_ref)?;
        }
        for reference in &spec.browser_binary_revision_refs {
            self.require_record(
                reference,
                BROWSER_BINARY_REVISION_SCHEMA_ID,
                &spec.workspace_ref,
            )?;
        }
        if is_persistent(spec.mode) && spec.storage_object_refs.is_empty() {
            return Err(BrowserError::MissingEvidence(
                "persistent profile storage object",
            ));
        }

        let profile_ref = EntityRef::new(PROFILE_KIND)?;
        let profile_revision_ref = EntityRef::new(PROFILE_REVISION_KIND)?;
        let mut profile_fields = Map::new();
        profile_fields.insert("mode".into(), serde_json::to_value(spec.mode)?);
        profile_fields.insert(
            "writable_sharing_policy".into(),
            serde_json::to_value(spec.writable_sharing_policy)?,
        );
        profile_fields.insert(
            "storage_object_refs".into(),
            refs(&spec.storage_object_refs)?,
        );
        profile_fields.insert(
            "content_digest_refs".into(),
            refs(&spec.content_digest_refs)?,
        );
        profile_fields.insert("policy_refs".into(), refs(&spec.policy_refs)?);
        profile_fields.insert(
            "browser_binary_revision_refs".into(),
            refs(&spec.browser_binary_revision_refs)?,
        );
        profile_fields.insert(
            "privacy_policy_refs".into(),
            refs(&spec.privacy_policy_refs)?,
        );
        profile_fields.insert(
            "retention_policy_refs".into(),
            refs(&spec.retention_policy_refs)?,
        );
        if let Some(reference) = &spec.encryption_policy_ref {
            profile_fields.insert(
                "encryption_policy_ref".into(),
                serde_json::to_value(reference)?,
            );
        }
        profile_fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_profile",
                "available",
                1,
                now,
                &spec.authority_ref,
                &[],
            )?,
        );

        let profile_doc = document(
            &profile_ref,
            BROWSER_PROFILE_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            profile_fields,
        )?;
        let mut revision_fields = Map::new();
        revision_fields.insert("profile_ref".into(), serde_json::to_value(&profile_ref)?);
        revision_fields.insert("profile_record_revision".into(), json!(1));
        revision_fields.insert(
            "content_digest_refs".into(),
            refs(&spec.content_digest_refs)?,
        );
        revision_fields.insert(
            "storage_object_refs".into(),
            refs(&spec.storage_object_refs)?,
        );
        revision_fields.insert(
            "browser_binary_revision_refs".into(),
            refs(&spec.browser_binary_revision_refs)?,
        );
        revision_fields.insert("created_from_state".into(), json!("available"));
        let revision_doc = document(
            &profile_revision_ref,
            BROWSER_PROFILE_REVISION_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            revision_fields,
        )?;
        self.write_documents(vec![profile_doc, revision_doc])?;
        Ok(BrowserProfileHandle {
            profile_ref,
            profile_revision_ref,
        })
    }

    /// Create a Browser Process in `starting` state after exact dependency fencing.
    ///
    /// Provider acknowledgement never makes the Process ready; call
    /// [`Self::mark_process_ready`] after independent readiness observation.
    ///
    /// # Errors
    /// Fails closed for stale materialization/provider/process evidence or A04 drift.
    #[allow(clippy::too_many_lines)]
    pub fn create_process(
        &mut self,
        spec: &BrowserProcessSpec,
        now: &str,
    ) -> Result<EntityRef, BrowserError> {
        require_nonempty(&spec.privacy_policy_refs, "privacy policy")?;
        if spec.materialization_generation == 0 {
            return Err(BrowserError::StaleGeneration);
        }
        let materialization = self.require_record(
            &spec.materialization_ref,
            WORKSPACE_MATERIALIZATION_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        if field_u64(materialization.document(), "materialization_generation")?
            != spec.materialization_generation
        {
            return Err(BrowserError::StaleGeneration);
        }
        self.require_record(
            &spec.browser_binary_ref,
            BROWSER_BINARY_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        let binary_revision = self.require_record(
            &spec.browser_binary_revision_ref,
            BROWSER_BINARY_REVISION_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        require_ref_field(
            binary_revision.document(),
            "browser_binary_ref",
            &spec.browser_binary_ref,
        )?;

        match (&spec.profile_ref, &spec.profile_revision_ref) {
            (Some(profile_ref), Some(profile_revision_ref)) => {
                self.require_record(profile_ref, BROWSER_PROFILE_SCHEMA_ID, &spec.workspace_ref)?;
                let revision = self.require_record(
                    profile_revision_ref,
                    BROWSER_PROFILE_REVISION_SCHEMA_ID,
                    &spec.workspace_ref,
                )?;
                require_ref_field(revision.document(), "profile_ref", profile_ref)?;
                if let Some(values) = revision.document().get("browser_binary_revision_refs") {
                    let compatible: Vec<EntityRef> = serde_json::from_value(values.clone())?;
                    if !compatible.is_empty()
                        && !compatible.iter().any(|reference| {
                            same_entity(reference, &spec.browser_binary_revision_ref)
                        })
                    {
                        return Err(BrowserError::TypeMismatch);
                    }
                }
            }
            (None, None) => {}
            _ => {
                return Err(BrowserError::MissingEvidence(
                    "profile/profile revision pair",
                ));
            }
        }

        let provider =
            ProviderContext::from_browser(&spec.provider_revision, &spec.provider_instance)?;
        if !spec
            .provider_instance
            .process_or_service_refs
            .iter()
            .any(|reference| same_entity(reference, &spec.runtime_process_ref))
        {
            return Err(BrowserError::MissingEvidence(
                "provider-owned runtime process/service",
            ));
        }
        self.validate_a04_chain(
            &spec.workspace_ref,
            &spec.activity_ref,
            &spec.operation_ref,
            &spec.attempt_ref,
        )?;

        let process_ref = EntityRef::new(PROCESS_KIND)?;
        let mut fields = Map::new();
        fields.insert(
            "materialization_ref".into(),
            serde_json::to_value(&spec.materialization_ref)?,
        );
        fields.insert(
            "materialization_generation".into(),
            json!(spec.materialization_generation),
        );
        fields.insert(
            "browser_binary_ref".into(),
            serde_json::to_value(&spec.browser_binary_ref)?,
        );
        fields.insert(
            "browser_binary_revision_ref".into(),
            serde_json::to_value(&spec.browser_binary_revision_ref)?,
        );
        if let Some(reference) = &spec.profile_ref {
            fields.insert("profile_ref".into(), serde_json::to_value(reference)?);
        }
        if let Some(reference) = &spec.profile_revision_ref {
            fields.insert(
                "profile_revision_ref".into(),
                serde_json::to_value(reference)?,
            );
        }
        fields.insert(
            "runtime_process_ref".into(),
            serde_json::to_value(&spec.runtime_process_ref)?,
        );
        fields.insert(
            "activity_ref".into(),
            serde_json::to_value(&spec.activity_ref)?,
        );
        fields.insert(
            "operation_ref".into(),
            serde_json::to_value(&spec.operation_ref)?,
        );
        fields.insert(
            "startup_attempt_ref".into(),
            serde_json::to_value(&spec.attempt_ref)?,
        );
        fields.insert(
            "provider_ref".into(),
            serde_json::to_value(&provider.provider_ref)?,
        );
        fields.insert(
            "provider_revision_ref".into(),
            serde_json::to_value(&provider.provider_revision_ref)?,
        );
        fields.insert(
            "provider_instance_ref".into(),
            serde_json::to_value(&provider.provider_instance_ref)?,
        );
        fields.insert(
            "provider_generation".into(),
            json!(provider.provider_generation.value()),
        );
        fields.insert("node_ref".into(), serde_json::to_value(&provider.node_ref)?);
        fields.insert("node_generation".into(), json!(provider.node_generation));
        fields.insert("connection_epoch".into(), json!(provider.connection_epoch));
        fields.insert("process_generation".into(), json!(1));
        fields.insert(
            "privacy_policy_refs".into(),
            refs(&spec.privacy_policy_refs)?,
        );
        fields.insert(
            "backend_aliases".into(),
            Value::Array(spec.backend_aliases.clone()),
        );
        fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_process",
                "starting",
                1,
                now,
                &spec.authority_ref,
                &[],
            )?,
        );
        let doc = document(
            &process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            fields,
        )?;
        self.write_documents(vec![doc])?;
        Ok(process_ref)
    }

    /// Mark a Browser Process ready after independent readiness evidence.
    ///
    /// # Errors
    /// Fails for stale generation, missing evidence, or invalid lifecycle state.
    pub fn mark_process_ready(
        &mut self,
        process_ref: &EntityRef,
        expected_process_generation: u64,
        authority_ref: &EntityRef,
        readiness_evidence_refs: &[EntityRef],
        now: &str,
    ) -> Result<(), BrowserError> {
        require_nonempty(readiness_evidence_refs, "process readiness evidence")?;
        let latest = self.require_schema(process_ref, BROWSER_PROCESS_SCHEMA_ID)?;
        if field_u64(latest.document(), "process_generation")? != expected_process_generation {
            return Err(BrowserError::StaleGeneration);
        }
        if state(latest.document())? != "starting" && state(latest.document())? != "detached" {
            return Err(BrowserError::InvalidTransition);
        }
        let workspace_ref = workspace_ref(latest.document())?;
        let mut fields = body_fields(latest.document())?;
        let sequence = state_sequence(latest.document())?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        fields.insert(
            "readiness_evidence_refs".into(),
            refs(readiness_evidence_refs)?,
        );
        fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_process",
                "ready",
                sequence,
                now,
                authority_ref,
                readiness_evidence_refs,
            )?,
        );
        let revision = self.next_revision(process_ref)?;
        let doc = document(
            process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            revision,
            &workspace_ref,
            authority_ref,
            now,
            fields,
        )?;
        self.write_documents(vec![doc])
    }

    /// Create a Browser Context and atomically claim writable Profile authority when requested.
    ///
    /// # Errors
    /// Fails closed for stale Process state/generation, policy gaps, stale Lease/fence,
    /// Profile mismatch, or concurrent writer ownership.
    #[allow(clippy::too_many_lines)]
    pub fn create_context(
        &mut self,
        spec: &BrowserContextSpec,
        now: &str,
    ) -> Result<EntityRef, BrowserError> {
        if spec.context_generation == 0 {
            return Err(BrowserError::StaleGeneration);
        }
        require_text(&spec.storage_mode, "storage_mode")?;
        require_nonempty(&spec.network_policy_refs, "network policy")?;
        require_nonempty(&spec.permission_policy_refs, "permission policy")?;
        require_nonempty(&spec.privacy_policy_refs, "privacy policy")?;
        let process = self.require_record(
            &spec.browser_process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        require_state(process.document(), &["ready", "detached"])?;
        require_generation(
            process.document(),
            "process_generation",
            spec.process_generation,
        )?;

        let process_profile = optional_ref_field(process.document(), "profile_ref")?;
        match (&spec.profile_ref, &spec.profile_revision_ref) {
            (Some(profile_ref), Some(profile_revision_ref)) => {
                if let Some(expected) = &process_profile
                    && !same_entity(expected, profile_ref)
                {
                    return Err(BrowserError::TypeMismatch);
                }
                self.require_record(profile_ref, BROWSER_PROFILE_SCHEMA_ID, &spec.workspace_ref)?;
                let revision = self.require_record(
                    profile_revision_ref,
                    BROWSER_PROFILE_REVISION_SCHEMA_ID,
                    &spec.workspace_ref,
                )?;
                require_ref_field(revision.document(), "profile_ref", profile_ref)?;
            }
            (None, None) => {
                if process_profile.is_some() {
                    return Err(BrowserError::MissingEvidence("context Profile"));
                }
                if !matches!(spec.storage_mode.as_str(), "ephemeral" | "incognito") {
                    return Err(BrowserError::MissingEvidence("persistent Context Profile"));
                }
            }
            _ => {
                return Err(BrowserError::MissingEvidence(
                    "profile/profile revision pair",
                ));
            }
        }

        let writable = spec.storage_mode == "persistent_writable";
        if !writable
            && (spec.writable_profile_lease_ref.is_some()
                || spec.writable_profile_fence_ref.is_some())
        {
            return Err(BrowserError::WritableProfileForbidden);
        }

        let context_ref = EntityRef::new(CONTEXT_KIND)?;
        let mut profile_update = None;
        if writable {
            let profile_ref = spec
                .profile_ref
                .as_ref()
                .ok_or(BrowserError::WritableProfileLeaseRequired)?;
            let lease_ref = spec
                .writable_profile_lease_ref
                .as_ref()
                .ok_or(BrowserError::WritableProfileLeaseRequired)?;
            let fence_ref = spec
                .writable_profile_fence_ref
                .as_ref()
                .ok_or(BrowserError::WritableProfileLeaseRequired)?;
            self.require_current_authority(
                lease_ref,
                LEASE_SCHEMA_ID,
                &spec.workspace_ref,
                "active",
            )?;
            self.require_current_authority(
                fence_ref,
                FENCE_OBSERVATION_SCHEMA_ID,
                &spec.workspace_ref,
                "current",
            )?;
            let profile =
                self.require_record(profile_ref, BROWSER_PROFILE_SCHEMA_ID, &spec.workspace_ref)?;
            if state(profile.document())? != "available" {
                return Err(BrowserError::WritableProfileInUse);
            }
            let mode: BrowserProfileMode = serde_json::from_value(
                profile
                    .document()
                    .get("mode")
                    .cloned()
                    .ok_or(BrowserError::MissingEvidence("profile mode"))?,
            )?;
            let sharing: WritableSharingPolicy = serde_json::from_value(
                profile
                    .document()
                    .get("writable_sharing_policy")
                    .cloned()
                    .ok_or(BrowserError::MissingEvidence("profile sharing policy"))?,
            )?;
            if !writable_allowed(mode, sharing) {
                return Err(BrowserError::WritableProfileForbidden);
            }
            let mut fields = body_fields(profile.document())?;
            fields.insert(
                "writer_context_ref".into(),
                serde_json::to_value(&context_ref)?,
            );
            fields.insert(
                "writer_process_ref".into(),
                serde_json::to_value(&spec.browser_process_ref)?,
            );
            fields.insert("writer_lease_ref".into(), serde_json::to_value(lease_ref)?);
            fields.insert("writer_fence_ref".into(), serde_json::to_value(fence_ref)?);
            let sequence = state_sequence(profile.document())?
                .checked_add(1)
                .ok_or(BrowserError::RevisionOverflow)?;
            fields.insert(
                "state_projection".into(),
                state_projection(
                    "browser_profile",
                    "leased_writable",
                    sequence,
                    now,
                    &spec.authority_ref,
                    &[],
                )?,
            );
            let profile_revision = self.next_revision(profile_ref)?;
            profile_update = Some(document(
                profile_ref,
                BROWSER_PROFILE_SCHEMA_ID,
                profile_revision,
                &spec.workspace_ref,
                &spec.authority_ref,
                now,
                fields,
            )?);
        }

        let mut fields = Map::new();
        fields.insert(
            "browser_process_ref".into(),
            serde_json::to_value(&spec.browser_process_ref)?,
        );
        fields.insert("process_generation".into(), json!(spec.process_generation));
        fields.insert("context_generation".into(), json!(spec.context_generation));
        fields.insert("storage_mode".into(), json!(spec.storage_mode));
        if let Some(reference) = &spec.profile_ref {
            fields.insert("profile_ref".into(), serde_json::to_value(reference)?);
        }
        if let Some(reference) = &spec.profile_revision_ref {
            fields.insert(
                "profile_revision_ref".into(),
                serde_json::to_value(reference)?,
            );
        }
        if let Some(reference) = &spec.writable_profile_lease_ref {
            fields.insert(
                "writable_profile_lease_ref".into(),
                serde_json::to_value(reference)?,
            );
        }
        if let Some(reference) = &spec.writable_profile_fence_ref {
            fields.insert(
                "writable_profile_fence_ref".into(),
                serde_json::to_value(reference)?,
            );
        }
        fields.insert(
            "network_policy_refs".into(),
            refs(&spec.network_policy_refs)?,
        );
        fields.insert(
            "permission_policy_refs".into(),
            refs(&spec.permission_policy_refs)?,
        );
        fields.insert(
            "privacy_policy_refs".into(),
            refs(&spec.privacy_policy_refs)?,
        );
        fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_context",
                "active",
                1,
                now,
                &spec.authority_ref,
                &[],
            )?,
        );
        let context_doc = document(
            &context_ref,
            BROWSER_CONTEXT_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            fields,
        )?;
        let mut docs = vec![context_doc];
        if let Some(update) = profile_update {
            docs.push(update);
        }
        self.write_documents(docs)?;
        Ok(context_ref)
    }

    /// Close a Browser Context and release writable Profile authority only after verified reconciliation.
    ///
    /// # Errors
    /// Fails for stale state/generation, missing reconciliation evidence, or writer mismatch.
    pub fn close_context(
        &mut self,
        context_ref: &EntityRef,
        expected_context_generation: u64,
        authority_ref: &EntityRef,
        reconciliation_receipt_refs: &[EntityRef],
        now: &str,
    ) -> Result<(), BrowserError> {
        require_nonempty(
            reconciliation_receipt_refs,
            "context close reconciliation evidence",
        )?;
        let context = self.require_schema(context_ref, BROWSER_CONTEXT_SCHEMA_ID)?;
        require_state(context.document(), &["active"])?;
        require_generation(
            context.document(),
            "context_generation",
            expected_context_generation,
        )?;
        let workspace = workspace_ref(context.document())?;
        let mut context_fields = body_fields(context.document())?;
        let sequence = state_sequence(context.document())?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        context_fields.insert(
            "close_reconciliation_refs".into(),
            refs(reconciliation_receipt_refs)?,
        );
        context_fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_context",
                "closed",
                sequence,
                now,
                authority_ref,
                reconciliation_receipt_refs,
            )?,
        );
        let context_doc = document(
            context_ref,
            BROWSER_CONTEXT_SCHEMA_ID,
            self.next_revision(context_ref)?,
            &workspace,
            authority_ref,
            now,
            context_fields,
        )?;
        let mut docs = vec![context_doc];
        if let Some(profile_ref) = optional_ref_field(context.document(), "profile_ref")?
            && context
                .document()
                .get("writable_profile_lease_ref")
                .is_some()
        {
            let profile =
                self.require_record(&profile_ref, BROWSER_PROFILE_SCHEMA_ID, &workspace)?;
            if state(profile.document())? != "leased_writable" {
                return Err(BrowserError::InvalidTransition);
            }
            require_ref_field(profile.document(), "writer_context_ref", context_ref)?;
            let mut fields = body_fields(profile.document())?;
            fields.remove("writer_context_ref");
            fields.remove("writer_process_ref");
            fields.remove("writer_lease_ref");
            fields.remove("writer_fence_ref");
            let profile_sequence = state_sequence(profile.document())?
                .checked_add(1)
                .ok_or(BrowserError::RevisionOverflow)?;
            fields.insert(
                "state_projection".into(),
                state_projection(
                    "browser_profile",
                    "available",
                    profile_sequence,
                    now,
                    authority_ref,
                    reconciliation_receipt_refs,
                )?,
            );
            docs.push(document(
                &profile_ref,
                BROWSER_PROFILE_SCHEMA_ID,
                self.next_revision(&profile_ref)?,
                &workspace,
                authority_ref,
                now,
                fields,
            )?);
        }
        self.write_documents(docs)
    }

    /// Create a Browser Page projection under one active Context.
    ///
    /// # Errors
    /// Fails for stale generations, mismatched Profile identity, or missing privacy policy.
    pub fn create_page(
        &mut self,
        spec: &BrowserPageSpec,
        now: &str,
    ) -> Result<EntityRef, BrowserError> {
        if spec.page_generation == 0 {
            return Err(BrowserError::StaleGeneration);
        }
        require_nonempty(&spec.privacy_policy_refs, "privacy policy")?;
        let process = self.require_record(
            &spec.browser_process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        require_generation(
            process.document(),
            "process_generation",
            spec.process_generation,
        )?;
        let context = self.require_record(
            &spec.context_ref,
            BROWSER_CONTEXT_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        require_state(context.document(), &["active"])?;
        require_ref_field(
            context.document(),
            "browser_process_ref",
            &spec.browser_process_ref,
        )?;
        require_generation(
            context.document(),
            "process_generation",
            spec.process_generation,
        )?;
        require_generation(
            context.document(),
            "context_generation",
            spec.context_generation,
        )?;
        let context_profile = optional_ref_field(context.document(), "profile_ref")?;
        if context_profile
            .as_ref()
            .map(|reference| reference.entity_id)
            != spec
                .profile_ref
                .as_ref()
                .map(|reference| reference.entity_id)
        {
            return Err(BrowserError::TypeMismatch);
        }

        let page_ref = EntityRef::new(PAGE_KIND)?;
        let mut fields = Map::new();
        fields.insert(
            "context_ref".into(),
            serde_json::to_value(&spec.context_ref)?,
        );
        fields.insert(
            "browser_process_ref".into(),
            serde_json::to_value(&spec.browser_process_ref)?,
        );
        fields.insert("process_generation".into(), json!(spec.process_generation));
        fields.insert("context_generation".into(), json!(spec.context_generation));
        fields.insert("page_generation".into(), json!(spec.page_generation));
        if let Some(reference) = &spec.profile_ref {
            fields.insert("profile_ref".into(), serde_json::to_value(reference)?);
        }
        fields.insert(
            "privacy_policy_refs".into(),
            refs(&spec.privacy_policy_refs)?,
        );
        fields.insert(
            "backend_aliases".into(),
            Value::Array(spec.backend_aliases.clone()),
        );
        fields.insert("navigation_sequence".into(), json!(0));
        fields.insert("navigation_attempt_refs".into(), json!([]));
        fields.insert(
            "state_projection".into(),
            state_projection("browser_page", "created", 1, now, &spec.authority_ref, &[])?,
        );
        let doc = document(
            &page_ref,
            BROWSER_PAGE_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            fields,
        )?;
        self.write_documents(vec![doc])?;
        Ok(page_ref)
    }

    /// Begin a Browser Navigation with a fresh A04 Attempt.
    ///
    /// A successful provider ACK only creates `requested` navigation truth and a
    /// `navigating` Page. Readiness requires a later post-condition observation.
    ///
    /// # Errors
    /// Fails for stale generations, navigation sequence drift, unresolved Challenge,
    /// reused A04 Attempt, or invalid A04 hierarchy.
    #[allow(clippy::too_many_lines)]
    pub fn begin_navigation(
        &mut self,
        spec: &NavigationSpec,
        now: &str,
    ) -> Result<EntityRef, BrowserError> {
        require_text(&spec.requested_url, "requested_url")?;
        if spec.navigation_sequence == 0 {
            return Err(BrowserError::StaleNavigation);
        }
        let process = self.require_record(
            &spec.browser_process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        require_generation(
            process.document(),
            "process_generation",
            spec.process_generation,
        )?;
        let context = self.require_record(
            &spec.context_ref,
            BROWSER_CONTEXT_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        require_state(context.document(), &["active"])?;
        require_generation(
            context.document(),
            "context_generation",
            spec.context_generation,
        )?;
        let page =
            self.require_record(&spec.page_ref, BROWSER_PAGE_SCHEMA_ID, &spec.workspace_ref)?;
        require_generation(page.document(), "page_generation", spec.page_generation)?;
        require_ref_field(page.document(), "context_ref", &spec.context_ref)?;
        require_ref_field(
            page.document(),
            "browser_process_ref",
            &spec.browser_process_ref,
        )?;
        let expected_sequence = field_u64(page.document(), "navigation_sequence")?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        if expected_sequence != spec.navigation_sequence {
            return Err(BrowserError::StaleNavigation);
        }
        self.ensure_no_unresolved_page_challenge(page.document())?;
        self.validate_a04_chain(
            &spec.workspace_ref,
            &spec.activity_ref,
            &spec.operation_ref,
            &spec.attempt_ref,
        )?;
        let startup_attempt = field_ref(process.document(), "startup_attempt_ref")?;
        if same_entity(&startup_attempt, &spec.attempt_ref) {
            return Err(BrowserError::AttemptReuseForbidden);
        }
        let used_attempts = field_refs(page.document(), "navigation_attempt_refs")?;
        if used_attempts
            .iter()
            .any(|reference| same_entity(reference, &spec.attempt_ref))
        {
            return Err(BrowserError::AttemptReuseForbidden);
        }

        let navigation_ref = EntityRef::new(NAVIGATION_KIND)?;
        let mut nav_fields = Map::new();
        nav_fields.insert("page_ref".into(), serde_json::to_value(&spec.page_ref)?);
        nav_fields.insert(
            "context_ref".into(),
            serde_json::to_value(&spec.context_ref)?,
        );
        nav_fields.insert(
            "browser_process_ref".into(),
            serde_json::to_value(&spec.browser_process_ref)?,
        );
        nav_fields.insert("process_generation".into(), json!(spec.process_generation));
        nav_fields.insert("context_generation".into(), json!(spec.context_generation));
        nav_fields.insert("page_generation".into(), json!(spec.page_generation));
        nav_fields.insert(
            "navigation_sequence".into(),
            json!(spec.navigation_sequence),
        );
        nav_fields.insert("requested_url".into(), json!(spec.requested_url));
        nav_fields.insert(
            "activity_ref".into(),
            serde_json::to_value(&spec.activity_ref)?,
        );
        nav_fields.insert(
            "operation_ref".into(),
            serde_json::to_value(&spec.operation_ref)?,
        );
        nav_fields.insert(
            "attempt_ref".into(),
            serde_json::to_value(&spec.attempt_ref)?,
        );
        nav_fields.insert("evidence_refs".into(), refs(&spec.evidence_refs)?);
        nav_fields.insert("provider_acknowledged".into(), json!(true));
        nav_fields.insert("postcondition_verified".into(), json!(false));
        nav_fields.insert(
            "navigation_state".into(),
            serde_json::to_value(NavigationState::Requested)?,
        );
        nav_fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_navigation",
                "requested",
                1,
                now,
                &spec.authority_ref,
                &spec.evidence_refs,
            )?,
        );
        let nav_doc = document(
            &navigation_ref,
            BROWSER_NAVIGATION_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            nav_fields,
        )?;

        let mut page_fields = body_fields(page.document())?;
        page_fields.insert(
            "navigation_ref".into(),
            serde_json::to_value(&navigation_ref)?,
        );
        page_fields.insert(
            "navigation_sequence".into(),
            json!(spec.navigation_sequence),
        );
        let mut used_attempts = used_attempts;
        used_attempts.push(spec.attempt_ref.clone());
        page_fields.insert("navigation_attempt_refs".into(), refs(&used_attempts)?);
        let page_sequence = state_sequence(page.document())?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        page_fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_page",
                "navigating",
                page_sequence,
                now,
                &spec.authority_ref,
                &[],
            )?,
        );
        let page_doc = document(
            &spec.page_ref,
            BROWSER_PAGE_SCHEMA_ID,
            self.next_revision(&spec.page_ref)?,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            page_fields,
        )?;
        self.write_documents(vec![nav_doc, page_doc])?;
        Ok(navigation_ref)
    }

    /// Record one navigation post-condition observation.
    ///
    /// `DOMContentLoaded`, load-complete or same-document observations may make the
    /// Page ready only when no unresolved Challenge remains.
    ///
    /// # Errors
    /// Fails for stale Navigation/Page identity, missing evidence, or unresolved Challenge.
    #[allow(clippy::too_many_lines)]
    pub fn observe_navigation(
        &mut self,
        navigation_ref: &EntityRef,
        expected_page_ref: &EntityRef,
        observation: NavigationState,
        authority_ref: &EntityRef,
        evidence_refs: &[EntityRef],
        now: &str,
    ) -> Result<(), BrowserError> {
        require_nonempty(evidence_refs, "navigation post-condition evidence")?;
        let navigation = self.require_schema(navigation_ref, BROWSER_NAVIGATION_SCHEMA_ID)?;
        require_ref_field(navigation.document(), "page_ref", expected_page_ref)?;
        let workspace = workspace_ref(navigation.document())?;
        let page = self.require_record(expected_page_ref, BROWSER_PAGE_SCHEMA_ID, &workspace)?;
        require_ref_field(page.document(), "navigation_ref", navigation_ref)?;
        let current_nav_sequence = field_u64(page.document(), "navigation_sequence")?;
        if field_u64(navigation.document(), "navigation_sequence")? != current_nav_sequence {
            return Err(BrowserError::StaleNavigation);
        }
        let ready = matches!(
            observation,
            NavigationState::DomContentLoaded
                | NavigationState::LoadComplete
                | NavigationState::SameDocument
        );
        if ready {
            self.ensure_challenge_resolved_if_present(page.document())?;
        }

        let mut nav_fields = body_fields(navigation.document())?;
        nav_fields.insert(
            "navigation_state".into(),
            serde_json::to_value(observation)?,
        );
        nav_fields.insert("observation_evidence_refs".into(), refs(evidence_refs)?);
        nav_fields.insert("postcondition_verified".into(), json!(ready));
        let nav_state = if ready {
            "verified"
        } else if matches!(
            observation,
            NavigationState::Failed | NavigationState::Cancelled | NavigationState::Crashed
        ) {
            "failed"
        } else {
            "observed"
        };
        let nav_sequence = state_sequence(navigation.document())?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        nav_fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_navigation",
                nav_state,
                nav_sequence,
                now,
                authority_ref,
                evidence_refs,
            )?,
        );
        let nav_doc = document(
            navigation_ref,
            BROWSER_NAVIGATION_SCHEMA_ID,
            self.next_revision(navigation_ref)?,
            &workspace,
            authority_ref,
            now,
            nav_fields,
        )?;

        let mut page_fields = body_fields(page.document())?;
        if ready && let Some(challenge_ref) = optional_ref_field(page.document(), "challenge_ref")?
        {
            page_fields.remove("challenge_ref");
            let mut archived = optional_ref_array(page.document(), "resolved_challenge_refs")?;
            archived.push(challenge_ref);
            page_fields.insert("resolved_challenge_refs".into(), refs(&archived)?);
        }
        let page_state = if ready {
            "ready"
        } else if observation == NavigationState::Crashed {
            "crashed"
        } else if matches!(
            observation,
            NavigationState::Failed | NavigationState::Cancelled
        ) {
            "degraded"
        } else {
            "navigating"
        };
        let page_sequence = state_sequence(page.document())?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        page_fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_page",
                page_state,
                page_sequence,
                now,
                authority_ref,
                evidence_refs,
            )?,
        );
        let page_doc = document(
            expected_page_ref,
            BROWSER_PAGE_SCHEMA_ID,
            self.next_revision(expected_page_ref)?,
            &workspace,
            authority_ref,
            now,
            page_fields,
        )?;
        self.write_documents(vec![nav_doc, page_doc])
    }

    /// Record an explicit Browser Challenge and fence automation when required.
    ///
    /// # Errors
    /// Fails for stale Process/Page bindings, unsafe challenge flags, or missing policy/evidence.
    #[allow(clippy::too_many_lines)]
    pub fn record_challenge(
        &mut self,
        spec: &ChallengeSpec,
        now: &str,
    ) -> Result<EntityRef, BrowserError> {
        require_text(&spec.required_actor_class, "required_actor_class")?;
        require_nonempty(&spec.policy_refs, "challenge policy")?;
        require_nonempty(&spec.evidence_refs, "challenge evidence")?;
        require_nonempty(&spec.privacy_policy_refs, "privacy policy")?;
        if spec.state == BrowserChallengeState::Resolved
            || spec.state == BrowserChallengeState::None
        {
            return Err(BrowserError::InvalidTransition);
        }
        if dangerous_challenge(spec.state) && !spec.automation_pause_required {
            return Err(BrowserError::ChallengeBypassForbidden);
        }
        if spec.state == BrowserChallengeState::HumanCompletionRequired
            && !spec.human_completion_allowed
        {
            return Err(BrowserError::ChallengeBypassForbidden);
        }
        let process = self.require_record(
            &spec.browser_process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        require_generation(
            process.document(),
            "process_generation",
            spec.process_generation,
        )?;
        let page =
            self.require_record(&spec.page_ref, BROWSER_PAGE_SCHEMA_ID, &spec.workspace_ref)?;
        require_ref_field(page.document(), "context_ref", &spec.context_ref)?;
        require_ref_field(
            page.document(),
            "browser_process_ref",
            &spec.browser_process_ref,
        )?;
        if let Some(expected_navigation) = &spec.navigation_ref {
            require_ref_field(page.document(), "navigation_ref", expected_navigation)?;
        }
        if let Some(existing) = optional_ref_field(page.document(), "challenge_ref")? {
            let challenge =
                self.require_record(&existing, BROWSER_CHALLENGE_SCHEMA_ID, &spec.workspace_ref)?;
            if state(challenge.document())? != "resolved" {
                return Err(BrowserError::InvalidTransition);
            }
        }
        self.require_record(
            &spec.profile_ref,
            BROWSER_PROFILE_SCHEMA_ID,
            &spec.workspace_ref,
        )?;

        let challenge_ref = EntityRef::new(CHALLENGE_KIND)?;
        let challenge_state_ref = EntityRef::new(CHALLENGE_STATE_KIND)?;
        let mut state_fields = Map::new();
        state_fields.insert(
            "challenge_ref".into(),
            serde_json::to_value(&challenge_ref)?,
        );
        state_fields.insert("state".into(), serde_json::to_value(spec.state)?);
        state_fields.insert(
            "required_actor_class".into(),
            json!(spec.required_actor_class),
        );
        state_fields.insert(
            "automation_pause_required".into(),
            json!(spec.automation_pause_required),
        );
        state_fields.insert(
            "human_completion_allowed".into(),
            json!(spec.human_completion_allowed),
        );
        state_fields.insert("evidence_refs".into(), refs(&spec.evidence_refs)?);
        state_fields.insert("immutable_observation".into(), json!(true));
        let state_doc = document(
            &challenge_state_ref,
            BROWSER_CHALLENGE_STATE_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            state_fields,
        )?;

        let mut challenge_fields = Map::new();
        challenge_fields.insert("page_ref".into(), serde_json::to_value(&spec.page_ref)?);
        if let Some(reference) = &spec.navigation_ref {
            challenge_fields.insert("navigation_ref".into(), serde_json::to_value(reference)?);
        }
        challenge_fields.insert(
            "context_ref".into(),
            serde_json::to_value(&spec.context_ref)?,
        );
        challenge_fields.insert(
            "profile_ref".into(),
            serde_json::to_value(&spec.profile_ref)?,
        );
        challenge_fields.insert(
            "browser_process_ref".into(),
            serde_json::to_value(&spec.browser_process_ref)?,
        );
        challenge_fields.insert("process_generation".into(), json!(spec.process_generation));
        challenge_fields.insert(
            "current_state_ref".into(),
            serde_json::to_value(&challenge_state_ref)?,
        );
        challenge_fields.insert("current_state".into(), serde_json::to_value(spec.state)?);
        challenge_fields.insert(
            "required_actor_class".into(),
            json!(spec.required_actor_class),
        );
        challenge_fields.insert(
            "automation_pause_required".into(),
            json!(spec.automation_pause_required),
        );
        challenge_fields.insert(
            "human_completion_allowed".into(),
            json!(spec.human_completion_allowed),
        );
        challenge_fields.insert("policy_refs".into(), refs(&spec.policy_refs)?);
        challenge_fields.insert("evidence_refs".into(), refs(&spec.evidence_refs)?);
        challenge_fields.insert(
            "privacy_policy_refs".into(),
            refs(&spec.privacy_policy_refs)?,
        );
        challenge_fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_challenge",
                "detected",
                1,
                now,
                &spec.authority_ref,
                &spec.evidence_refs,
            )?,
        );
        let challenge_doc = document(
            &challenge_ref,
            BROWSER_CHALLENGE_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            challenge_fields,
        )?;

        let mut page_fields = body_fields(page.document())?;
        page_fields.insert(
            "challenge_ref".into(),
            serde_json::to_value(&challenge_ref)?,
        );
        let page_sequence = state_sequence(page.document())?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        page_fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_page",
                "challenged",
                page_sequence,
                now,
                &spec.authority_ref,
                &spec.evidence_refs,
            )?,
        );
        let page_doc = document(
            &spec.page_ref,
            BROWSER_PAGE_SCHEMA_ID,
            self.next_revision(&spec.page_ref)?,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            page_fields,
        )?;
        self.write_documents(vec![state_doc, challenge_doc, page_doc])?;
        Ok(challenge_ref)
    }

    /// Record externally/human verified Challenge resolution.
    ///
    /// Resolution creates a new immutable Challenge-State observation. It does not
    /// make the Page ready; a later navigation post-condition must still be proved.
    ///
    /// # Errors
    /// Fails when evidence/Receipt proof is missing or the Challenge is already resolved.
    pub fn resolve_challenge(
        &mut self,
        challenge_ref: &EntityRef,
        authority_ref: &EntityRef,
        resolution_evidence_refs: &[EntityRef],
        resolution_receipt_refs: &[EntityRef],
        now: &str,
    ) -> Result<EntityRef, BrowserError> {
        require_nonempty(resolution_evidence_refs, "challenge resolution evidence")?;
        require_nonempty(resolution_receipt_refs, "challenge resolution receipt")?;
        let challenge = self.require_schema(challenge_ref, BROWSER_CHALLENGE_SCHEMA_ID)?;
        if state(challenge.document())? == "resolved" {
            return Err(BrowserError::InvalidTransition);
        }
        let workspace = workspace_ref(challenge.document())?;
        let state_ref = EntityRef::new(CHALLENGE_STATE_KIND)?;
        let mut state_fields = Map::new();
        state_fields.insert("challenge_ref".into(), serde_json::to_value(challenge_ref)?);
        state_fields.insert(
            "state".into(),
            serde_json::to_value(BrowserChallengeState::Resolved)?,
        );
        state_fields.insert("evidence_refs".into(), refs(resolution_evidence_refs)?);
        state_fields.insert(
            "resolution_receipt_refs".into(),
            refs(resolution_receipt_refs)?,
        );
        state_fields.insert("immutable_observation".into(), json!(true));
        let state_doc = document(
            &state_ref,
            BROWSER_CHALLENGE_STATE_SCHEMA_ID,
            1,
            &workspace,
            authority_ref,
            now,
            state_fields,
        )?;

        let mut fields = body_fields(challenge.document())?;
        fields.insert(
            "current_state_ref".into(),
            serde_json::to_value(&state_ref)?,
        );
        fields.insert(
            "current_state".into(),
            serde_json::to_value(BrowserChallengeState::Resolved)?,
        );
        fields.insert(
            "resolution_evidence_refs".into(),
            refs(resolution_evidence_refs)?,
        );
        fields.insert(
            "resolution_receipt_refs".into(),
            refs(resolution_receipt_refs)?,
        );
        let sequence = state_sequence(challenge.document())?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        let mut combined = resolution_evidence_refs.to_vec();
        combined.extend_from_slice(resolution_receipt_refs);
        fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_challenge",
                "resolved",
                sequence,
                now,
                authority_ref,
                &combined,
            )?,
        );
        let challenge_doc = document(
            challenge_ref,
            BROWSER_CHALLENGE_SCHEMA_ID,
            self.next_revision(challenge_ref)?,
            &workspace,
            authority_ref,
            now,
            fields,
        )?;
        self.write_documents(vec![state_doc, challenge_doc])?;
        Ok(state_ref)
    }

    /// Create Browser Download metadata bound to an existing A08 Transfer Request.
    ///
    /// A11 deliberately does not manufacture Content/Object identity for downloaded bytes.
    ///
    /// # Errors
    /// Fails for stale Browser state or missing A08 transfer truth.
    #[allow(clippy::too_many_lines)]
    pub fn create_download(
        &mut self,
        spec: &BrowserDownloadSpec,
        now: &str,
    ) -> Result<EntityRef, BrowserError> {
        require_nonempty(&spec.privacy_policy_refs, "privacy policy")?;
        let process = self.require_record(
            &spec.browser_process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        require_generation(
            process.document(),
            "process_generation",
            spec.process_generation,
        )?;
        self.require_record(
            &spec.context_ref,
            BROWSER_CONTEXT_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        self.require_record(&spec.page_ref, BROWSER_PAGE_SCHEMA_ID, &spec.workspace_ref)?;
        self.require_record(
            &spec.profile_ref,
            BROWSER_PROFILE_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        self.require_record(
            &spec.navigation_ref,
            BROWSER_NAVIGATION_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        if self
            .require_record(
                &spec.transfer_request_ref,
                TRANSFER_REQUEST_SCHEMA_ID,
                &spec.workspace_ref,
            )
            .is_err()
        {
            return Err(BrowserError::TransferRequestRequired);
        }

        let download_ref = EntityRef::new(DOWNLOAD_KIND)?;
        let mut fields = Map::new();
        fields.insert("page_ref".into(), serde_json::to_value(&spec.page_ref)?);
        fields.insert(
            "context_ref".into(),
            serde_json::to_value(&spec.context_ref)?,
        );
        fields.insert(
            "profile_ref".into(),
            serde_json::to_value(&spec.profile_ref)?,
        );
        fields.insert(
            "browser_process_ref".into(),
            serde_json::to_value(&spec.browser_process_ref)?,
        );
        fields.insert("process_generation".into(), json!(spec.process_generation));
        fields.insert(
            "navigation_ref".into(),
            serde_json::to_value(&spec.navigation_ref)?,
        );
        fields.insert(
            "initiating_event_ref".into(),
            serde_json::to_value(&spec.initiating_event_ref)?,
        );
        if let Some(reference) = &spec.initiating_action_ref {
            fields.insert(
                "initiating_action_ref".into(),
                serde_json::to_value(reference)?,
            );
        }
        fields.insert(
            "transfer_request_ref".into(),
            serde_json::to_value(&spec.transfer_request_ref)?,
        );
        if let Some(filename) = &spec.suggested_filename {
            require_text(filename, "suggested_filename")?;
            fields.insert("suggested_filename".into(), json!(filename));
        }
        if let Some(url) = &spec.source_url {
            require_text(url, "source_url")?;
            fields.insert("source_url".into(), json!(url));
        }
        fields.insert(
            "privacy_policy_refs".into(),
            refs(&spec.privacy_policy_refs)?,
        );
        fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_download",
                "transferring",
                1,
                now,
                &spec.authority_ref,
                &[],
            )?,
        );
        let doc = document(
            &download_ref,
            BROWSER_DOWNLOAD_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            fields,
        )?;
        self.write_documents(vec![doc])?;
        Ok(download_ref)
    }

    /// Create a Browser Evidence Bundle backed by distinct A07 Objects.
    ///
    /// # Errors
    /// Fails for missing manifest/member Object truth, cross-Workspace refs, stale Process generation,
    /// or optional Artifact mismatch.
    #[allow(clippy::too_many_lines)]
    pub fn create_evidence_bundle(
        &mut self,
        spec: &BrowserEvidenceBundleSpec,
        now: &str,
    ) -> Result<EntityRef, BrowserError> {
        require_text(&spec.integrity_state, "integrity_state")?;
        require_nonempty(&spec.privacy_policy_refs, "privacy policy")?;
        if spec.evidence_members.is_empty() {
            return Err(BrowserError::ObjectEvidenceRequired);
        }
        let process = self.require_record(
            &spec.browser_process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        require_generation(
            process.document(),
            "process_generation",
            spec.process_generation,
        )?;
        self.require_record(
            &spec.context_ref,
            BROWSER_CONTEXT_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        self.require_record(&spec.page_ref, BROWSER_PAGE_SCHEMA_ID, &spec.workspace_ref)?;
        self.require_record(
            &spec.navigation_ref,
            BROWSER_NAVIGATION_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        self.require_record(
            &spec.manifest_object_ref,
            OBJECT_SCHEMA_ID,
            &spec.workspace_ref,
        )?;
        let mut classes = BTreeSet::new();
        for member in &spec.evidence_members {
            self.require_record(&member.object_ref, OBJECT_SCHEMA_ID, &spec.workspace_ref)?;
            if let Some(reference) = &member.artifact_ref {
                self.require_record(reference, ARTIFACT_SCHEMA_ID, &spec.workspace_ref)?;
            }
            require_text(&member.captured_at, "captured_at")?;
            classes.insert(format!("{:?}", member.evidence_class));
        }

        let evidence_ref = EntityRef::new(EVIDENCE_BUNDLE_KIND)?;
        let mut fields = Map::new();
        fields.insert("page_ref".into(), serde_json::to_value(&spec.page_ref)?);
        fields.insert(
            "context_ref".into(),
            serde_json::to_value(&spec.context_ref)?,
        );
        fields.insert(
            "browser_process_ref".into(),
            serde_json::to_value(&spec.browser_process_ref)?,
        );
        fields.insert("process_generation".into(), json!(spec.process_generation));
        fields.insert(
            "navigation_ref".into(),
            serde_json::to_value(&spec.navigation_ref)?,
        );
        fields.insert(
            "manifest_object_ref".into(),
            serde_json::to_value(&spec.manifest_object_ref)?,
        );
        let members: Vec<Value> = spec
            .evidence_members
            .iter()
            .map(|member| {
                let mut value = Map::new();
                value.insert(
                    "evidence_class".into(),
                    serde_json::to_value(member.evidence_class)?,
                );
                value.insert(
                    "object_ref".into(),
                    serde_json::to_value(&member.object_ref)?,
                );
                if let Some(reference) = &member.artifact_ref {
                    value.insert("artifact_ref".into(), serde_json::to_value(reference)?);
                }
                value.insert("captured_at".into(), json!(member.captured_at));
                value.insert("coverage".into(), serde_json::to_value(member.coverage)?);
                Ok::<Value, serde_json::Error>(Value::Object(value))
            })
            .collect::<Result<_, _>>()?;
        fields.insert("evidence_members".into(), Value::Array(members));
        fields.insert("integrity_state".into(), json!(spec.integrity_state));
        fields.insert(
            "privacy_policy_refs".into(),
            refs(&spec.privacy_policy_refs)?,
        );
        fields.insert(
            "evidence_classes".into(),
            Value::Array(classes.into_iter().map(Value::String).collect()),
        );
        fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_evidence_bundle",
                "recorded",
                1,
                now,
                &spec.authority_ref,
                &[],
            )?,
        );
        let doc = document(
            &evidence_ref,
            BROWSER_EVIDENCE_BUNDLE_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
            fields,
        )?;
        self.write_documents(vec![doc])?;
        Ok(evidence_ref)
    }

    /// Detach client control from a Browser Process without destroying durable Browser work.
    ///
    /// # Errors
    /// Fails for stale Process generation or invalid state.
    pub fn detach_process(
        &mut self,
        process_ref: &EntityRef,
        expected_process_generation: u64,
        authority_ref: &EntityRef,
        now: &str,
    ) -> Result<(), BrowserError> {
        self.transition_process(
            process_ref,
            expected_process_generation,
            authority_ref,
            "ready",
            "detached",
            now,
        )
    }

    /// Reconnect to a durable Browser Process after independent liveness/readiness verification.
    ///
    /// # Errors
    /// Fails for stale generation, missing reconnect evidence, or invalid state.
    pub fn reconnect_process(
        &mut self,
        process_ref: &EntityRef,
        expected_process_generation: u64,
        authority_ref: &EntityRef,
        reconnect_evidence_refs: &[EntityRef],
        now: &str,
    ) -> Result<(), BrowserError> {
        require_nonempty(reconnect_evidence_refs, "reconnect evidence")?;
        let latest = self.require_schema(process_ref, BROWSER_PROCESS_SCHEMA_ID)?;
        require_generation(
            latest.document(),
            "process_generation",
            expected_process_generation,
        )?;
        if state(latest.document())? != "detached" {
            return Err(BrowserError::InvalidTransition);
        }
        let workspace = workspace_ref(latest.document())?;
        let mut fields = body_fields(latest.document())?;
        fields.insert(
            "reconnect_evidence_refs".into(),
            refs(reconnect_evidence_refs)?,
        );
        let sequence = state_sequence(latest.document())?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_process",
                "ready",
                sequence,
                now,
                authority_ref,
                reconnect_evidence_refs,
            )?,
        );
        let doc = document(
            process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            self.next_revision(process_ref)?,
            &workspace,
            authority_ref,
            now,
            fields,
        )?;
        self.write_documents(vec![doc])
    }

    fn transition_process(
        &mut self,
        process_ref: &EntityRef,
        expected_generation: u64,
        authority_ref: &EntityRef,
        expected_state: &str,
        next_state: &str,
        now: &str,
    ) -> Result<(), BrowserError> {
        let latest = self.require_schema(process_ref, BROWSER_PROCESS_SCHEMA_ID)?;
        require_generation(latest.document(), "process_generation", expected_generation)?;
        if state(latest.document())? != expected_state {
            return Err(BrowserError::InvalidTransition);
        }
        let workspace = workspace_ref(latest.document())?;
        let mut fields = body_fields(latest.document())?;
        let sequence = state_sequence(latest.document())?
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)?;
        fields.insert(
            "state_projection".into(),
            state_projection(
                "browser_process",
                next_state,
                sequence,
                now,
                authority_ref,
                &[],
            )?,
        );
        let doc = document(
            process_ref,
            BROWSER_PROCESS_SCHEMA_ID,
            self.next_revision(process_ref)?,
            &workspace,
            authority_ref,
            now,
            fields,
        )?;
        self.write_documents(vec![doc])
    }

    fn validate_a04_chain(
        &self,
        workspace: &EntityRef,
        activity_ref: &EntityRef,
        operation_ref: &EntityRef,
        attempt_ref: &EntityRef,
    ) -> Result<(), BrowserError> {
        self.require_record(activity_ref, ACTIVITY_SCHEMA_ID, workspace)?;
        let operation = self.require_record(operation_ref, OPERATION_SCHEMA_ID, workspace)?;
        require_ref_field(operation.document(), "activity_ref", activity_ref)?;
        let attempt = self.require_record(attempt_ref, ATTEMPT_SCHEMA_ID, workspace)?;
        require_ref_field(attempt.document(), "activity_ref", activity_ref)?;
        require_ref_field(attempt.document(), "operation_ref", operation_ref)?;
        Ok(())
    }

    fn require_current_authority(
        &self,
        reference: &EntityRef,
        schema: &str,
        workspace: &EntityRef,
        expected_state: &str,
    ) -> Result<(), BrowserError> {
        let record = self.require_record(reference, schema, workspace)?;
        if state(record.document())? != expected_state {
            return Err(BrowserError::WritableProfileLeaseRequired);
        }
        Ok(())
    }

    fn ensure_no_unresolved_page_challenge(&self, page: &Value) -> Result<(), BrowserError> {
        if let Some(reference) = optional_ref_field(page, "challenge_ref")? {
            let challenge = self.require_schema(&reference, BROWSER_CHALLENGE_SCHEMA_ID)?;
            if state(challenge.document())? != "resolved" {
                return Err(BrowserError::ChallengeBypassForbidden);
            }
        }
        Ok(())
    }

    fn ensure_challenge_resolved_if_present(&self, page: &Value) -> Result<(), BrowserError> {
        self.ensure_no_unresolved_page_challenge(page)
    }

    fn require_schema(
        &self,
        reference: &EntityRef,
        schema: &str,
    ) -> Result<CanonicalRecord, BrowserError> {
        let record = self.latest(reference)?;
        if record.schema_id() != schema {
            return Err(BrowserError::TypeMismatch);
        }
        Ok(record)
    }

    fn require_record(
        &self,
        reference: &EntityRef,
        schema: &str,
        workspace: &EntityRef,
    ) -> Result<CanonicalRecord, BrowserError> {
        let record = self.require_schema(reference, schema)?;
        let record_workspace = workspace_ref(record.document())?;
        if !same_entity(&record_workspace, workspace) {
            return Err(BrowserError::WorkspaceMismatch);
        }
        if let Some(revision) = reference.record_revision
            && record.record_revision() != revision
        {
            return Err(BrowserError::TypeMismatch);
        }
        Ok(record)
    }

    fn latest(&self, reference: &EntityRef) -> Result<CanonicalRecord, BrowserError> {
        self.ledger
            .latest_record(reference.entity_id)?
            .ok_or(BrowserError::NotFound(reference.entity_id))
    }

    fn next_revision(&self, reference: &EntityRef) -> Result<u64, BrowserError> {
        let latest = self.latest(reference)?;
        latest
            .record_revision()
            .value()
            .checked_add(1)
            .ok_or(BrowserError::RevisionOverflow)
    }

    fn write_documents(&mut self, documents: Vec<Value>) -> Result<(), BrowserError> {
        let records = documents
            .into_iter()
            .map(CanonicalRecord::from_document)
            .collect::<Result<Vec<_>, _>>()?;
        let write = self.ledger.begin_write()?;
        for record in &records {
            write.insert(record)?;
        }
        write.commit()?;
        Ok(())
    }
}

fn validate_profile_sharing(
    mode: BrowserProfileMode,
    policy: WritableSharingPolicy,
) -> Result<(), BrowserError> {
    let valid = match mode {
        BrowserProfileMode::PersistentExclusive => matches!(
            policy,
            WritableSharingPolicy::ExclusiveOneContext
                | WritableSharingPolicy::ExclusiveOneProcess
                | WritableSharingPolicy::SerializedWriter
        ),
        BrowserProfileMode::PersistentSharedReadonly => {
            matches!(
                policy,
                WritableSharingPolicy::SharedReadonly | WritableSharingPolicy::Forbidden
            )
        }
        BrowserProfileMode::Ephemeral | BrowserProfileMode::Incognito => {
            matches!(policy, WritableSharingPolicy::Forbidden)
        }
        BrowserProfileMode::ManagedRemote | BrowserProfileMode::OtherRegistered => true,
    };
    if valid {
        Ok(())
    } else {
        Err(BrowserError::InvalidProfileSharing)
    }
}

const fn is_persistent(mode: BrowserProfileMode) -> bool {
    matches!(
        mode,
        BrowserProfileMode::PersistentExclusive
            | BrowserProfileMode::PersistentSharedReadonly
            | BrowserProfileMode::ManagedRemote
    )
}

const fn writable_allowed(mode: BrowserProfileMode, policy: WritableSharingPolicy) -> bool {
    matches!(
        mode,
        BrowserProfileMode::PersistentExclusive
            | BrowserProfileMode::ManagedRemote
            | BrowserProfileMode::OtherRegistered
    ) && matches!(
        policy,
        WritableSharingPolicy::ExclusiveOneContext
            | WritableSharingPolicy::ExclusiveOneProcess
            | WritableSharingPolicy::SerializedWriter
            | WritableSharingPolicy::OtherRegistered
    )
}

const fn dangerous_challenge(state: BrowserChallengeState) -> bool {
    matches!(
        state,
        BrowserChallengeState::LoginRequired
            | BrowserChallengeState::MfaRequired
            | BrowserChallengeState::CaptchaOrAntiBot
            | BrowserChallengeState::ConsentOrTerms
            | BrowserChallengeState::CertificateOrDeviceApproval
            | BrowserChallengeState::HumanCompletionRequired
            | BrowserChallengeState::BlockedByPolicy
    )
}

fn require_nonempty<T>(values: &[T], field: &'static str) -> Result<(), BrowserError> {
    if values.is_empty() {
        return Err(BrowserError::MissingPolicy(field));
    }
    Ok(())
}

fn require_text(value: &str, field: &'static str) -> Result<(), BrowserError> {
    if value.trim().is_empty() {
        return Err(BrowserError::EmptyField(field));
    }
    Ok(())
}

fn same_entity(left: &EntityRef, right: &EntityRef) -> bool {
    left.entity_id == right.entity_id && left.entity_kind == right.entity_kind
}

fn document(
    reference: &EntityRef,
    schema_id: &str,
    record_revision: u64,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    now: &str,
    fields: Map<String, Value>,
) -> Result<Value, BrowserError> {
    require_text(now, "timestamp")?;
    let envelope = json!({
        "entity_id": reference.entity_id.to_string(),
        "entity_kind": reference.entity_kind.as_str(),
        "schema_id": schema_id,
        "schema_version": A11_SCHEMA_VERSION,
        "record_revision": record_revision,
        "created_at": now,
        "updated_at": now,
        "workspace_ref": workspace_ref,
        "authority_ref": authority_ref,
        "privacy_class": "internal",
        "audience": "workspace",
        "redaction_policy": "browser_privacy_policy",
        "retention_policy": {
            "policy_id": "ptah.a11.browser.canonical",
            "policy_version": A11_SCHEMA_VERSION,
            "retention_class": "historical",
            "delete_bytes_when_unreferenced": false
        },
        "extensions": {}
    });
    let mut root = Map::new();
    root.insert("envelope".into(), envelope);
    root.extend(fields);
    Ok(Value::Object(root))
}

fn state_projection(
    machine: &str,
    state: &str,
    transition_sequence: u64,
    changed_at: &str,
    changed_by_ref: &EntityRef,
    receipt_refs: &[EntityRef],
) -> Result<Value, BrowserError> {
    require_text(machine, "state machine")?;
    require_text(state, "state")?;
    Ok(json!({
        "machine": machine,
        "machine_version": A11_SCHEMA_VERSION,
        "state": state,
        "transition_sequence": transition_sequence,
        "changed_at": changed_at,
        "changed_by_ref": changed_by_ref,
        "receipt_refs": receipt_refs
    }))
}

fn refs(values: &[EntityRef]) -> Result<Value, BrowserError> {
    Ok(serde_json::to_value(values)?)
}

fn body_fields(document: &Value) -> Result<Map<String, Value>, BrowserError> {
    let object = document.as_object().ok_or(BrowserError::TypeMismatch)?;
    Ok(object
        .iter()
        .filter(|(key, _)| key.as_str() != "envelope")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

fn envelope(document: &Value) -> Result<&Map<String, Value>, BrowserError> {
    document
        .get("envelope")
        .and_then(Value::as_object)
        .ok_or(BrowserError::TypeMismatch)
}

fn workspace_ref(document: &Value) -> Result<EntityRef, BrowserError> {
    serde_json::from_value(
        envelope(document)?
            .get("workspace_ref")
            .cloned()
            .ok_or(BrowserError::MissingEvidence("workspace_ref"))?,
    )
    .map_err(BrowserError::from)
}

fn field_ref(document: &Value, field: &'static str) -> Result<EntityRef, BrowserError> {
    serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(BrowserError::MissingEvidence(field))?,
    )
    .map_err(BrowserError::from)
}

fn optional_ref_field(
    document: &Value,
    field: &'static str,
) -> Result<Option<EntityRef>, BrowserError> {
    document
        .get(field)
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(BrowserError::from)
}

fn field_refs(document: &Value, field: &'static str) -> Result<Vec<EntityRef>, BrowserError> {
    match document.get(field) {
        Some(value) => serde_json::from_value(value.clone()).map_err(BrowserError::from),
        None => Ok(Vec::new()),
    }
}

fn optional_ref_array(
    document: &Value,
    field: &'static str,
) -> Result<Vec<EntityRef>, BrowserError> {
    field_refs(document, field)
}

fn field_u64(document: &Value, field: &'static str) -> Result<u64, BrowserError> {
    document
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(BrowserError::MissingEvidence(field))
}

fn require_ref_field(
    document: &Value,
    field: &'static str,
    expected: &EntityRef,
) -> Result<(), BrowserError> {
    let actual = field_ref(document, field)?;
    if same_entity(&actual, expected) {
        Ok(())
    } else {
        Err(BrowserError::TypeMismatch)
    }
}

fn require_generation(
    document: &Value,
    field: &'static str,
    expected: u64,
) -> Result<(), BrowserError> {
    if expected == 0 || field_u64(document, field)? != expected {
        Err(BrowserError::StaleGeneration)
    } else {
        Ok(())
    }
}

fn state(document: &Value) -> Result<&str, BrowserError> {
    document
        .get("state_projection")
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str)
        .ok_or(BrowserError::MissingEvidence("state_projection.state"))
}

fn state_sequence(document: &Value) -> Result<u64, BrowserError> {
    document
        .get("state_projection")
        .and_then(|value| value.get("transition_sequence"))
        .and_then(Value::as_u64)
        .ok_or(BrowserError::MissingEvidence(
            "state_projection.transition_sequence",
        ))
}

fn require_state(document: &Value, allowed: &[&str]) -> Result<(), BrowserError> {
    let current = state(document)?;
    if allowed.contains(&current) {
        Ok(())
    } else {
        Err(BrowserError::InvalidTransition)
    }
}
