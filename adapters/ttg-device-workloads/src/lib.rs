#![forbid(unsafe_code)]
//! C11 Device Manager and MIBU workload admissions.
//!
//! This crate copies no donor implementation. It freezes reviewed source metadata and
//! maps the Device Manager and MIBU workloads onto current C09/C10 Ptah truth. Device
//! Manager is limited to reversible DPC application-visibility policy with independent
//! before/after/rollback read-back. MIBU is correlation/evidence only: nonce correlation
//! is not authentication, stale Provider/connection epochs fail closed, automatic replay
//! stays disabled, and official external results remain separate from runtime acknowledgements.

use ptah_android_runtime::{
    ApplicationSession, ApplicationSessionState, DeviceSession, DeviceSessionState,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::ProviderGeneration;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;
use ttg_device_xray_admission::{
    AdmittedXrayWorkload, XrayEvidenceDisposition, XrayEvidenceFreshness,
};

/// Exact private Device Manager repository recorded by the reviewed archive.
pub const DEVICE_MANAGER_REPOSITORY_URL: &str =
    "https://github.com/jaydumisuni/thetechguy-device-manager";
/// Exact Device Manager commit admitted by C11.
pub const DEVICE_MANAGER_COMMIT_SHA: &str = "e40189f6a4832124c91172b77967c46c06b5c66a";
/// Exact Git tree for [`DEVICE_MANAGER_COMMIT_SHA`].
pub const DEVICE_MANAGER_TREE_SHA1: &str = "6d1d07b9ca3ddd41dc27c3c159954b578fd16229";
/// Device Manager Android package identity.
pub const DEVICE_MANAGER_PACKAGE_ID: &str = "com.thetechguy.ttgdevicemanager";
/// Exact Android version declared by the admitted Device Manager build.
pub const DEVICE_MANAGER_APP_VERSION: &str = "1.0-v1-dev-build";
/// Exact `app/build.gradle` blob that declares package/version/signing configuration.
pub const DEVICE_MANAGER_BUILD_GRADLE_BLOB_SHA1: &str = "1788d909b968d7f61fdae1faed68e9e35fcf5196";
/// Exact manifest blob identity at the admitted Device Manager revision.
pub const DEVICE_MANAGER_MANIFEST_BLOB_SHA1: &str = "6cb1b744f4cf79f13c84b6757b70124a0b9f4281";
/// Exact main activity blob identity at the admitted Device Manager revision.
pub const DEVICE_MANAGER_MAIN_ACTIVITY_BLOB_SHA1: &str = "3c7a7844b94bc1ee0d4f2131dbf83fbcbc597fe5";
/// Exact Device Admin receiver blob identity at the admitted Device Manager revision.
pub const DEVICE_MANAGER_ADMIN_RECEIVER_BLOB_SHA1: &str =
    "93a6577dc3a5356d8950f5102efd6a3f71cb9bcf";
/// Exact policy preset blob identity at the admitted Device Manager revision.
pub const DEVICE_MANAGER_POLICY_PRESET_BLOB_SHA1: &str = "f8446ab9ec4fd346ecb49bce60cdac7fda09b93c";

/// Exact MIBU repository recorded by the reviewed archive.
pub const MIBU_REPOSITORY_URL: &str = "https://github.com/jaydumisuni/MIBU";
/// Exact MIBU commit admitted by C11.
pub const MIBU_COMMIT_SHA: &str = "9fb3803dedddc55f07280f660a7c78583f73b138";
/// Exact Git tree for [`MIBU_COMMIT_SHA`].
pub const MIBU_TREE_SHA1: &str = "4a300f3825b12be99f8d40b860eb9338dd241d4c";
/// MIBU Android package identity.
pub const MIBU_PACKAGE_ID: &str = "com.thetechguy.mibu";
/// Exact Android version at the admitted MIBU revision.
pub const MIBU_APP_VERSION: &str = "0.3.0-dev";
/// Exact MIBU proof protocol at the admitted revision.
pub const MIBU_PROOF_PROTOCOL_VERSION: u32 = 3;
/// Exact `ProofContract.kt` blob identity.
pub const MIBU_PROOF_CONTRACT_BLOB_SHA1: &str = "7eb86f163521e23d485b0d48a9763a5080f2d115";
/// Exact `ProofNonce.kt` blob identity.
pub const MIBU_PROOF_NONCE_BLOB_SHA1: &str = "17600f6846259075ddac8fcf019604f8d25a5d5a";
/// Exact proof-review tool blob identity.
pub const MIBU_PROOF_REVIEW_BLOB_SHA1: &str = "3a594bdf1ff57ea9384ebfecc6fc2964406c79c8";
/// Exact Windows helper version-info blob identity.
pub const MIBU_VERSION_INFO_BLOB_SHA1: &str = "e83d0dd62f75477af577fb9897f3f9eb12ef21bb";

/// C11 workload-admission failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum C11AdmissionError {
    /// Device Manager source metadata no longer matches the reviewed private revision.
    #[error("Device Manager source lock mismatch")]
    DeviceManagerSourceLockMismatch,
    /// MIBU source metadata no longer matches the reviewed revision.
    #[error("MIBU source lock mismatch")]
    MibuSourceLockMismatch,
    /// Required evidence or timestamps are absent.
    #[error("required admission evidence is missing")]
    MissingEvidence,
    /// C09 evidence is not a current single-device correlated observation.
    #[error("C09 X-Ray evidence is not current and correlated")]
    XrayNotCurrentCorrelated,
    /// Device/Application/X-Ray/observation Provider or epoch context does not agree.
    #[error("Device workload context mismatch")]
    DeviceContextMismatch,
    /// Device Owner state was not independently observed for the pinned package.
    #[error("Device Owner state was not independently observed")]
    DeviceOwnerNotObserved,
    /// Current C10 Application Session is not the pinned Device Manager package/version/signer.
    #[error("Device Manager Application Session mismatch")]
    DeviceManagerApplicationMismatch,
    /// Reversible DPC policy authorization is absent, stale, denied, or for another scope.
    #[error("reversible DPC authorization mismatch")]
    DpcAuthorizationMismatch,
    /// C11 intentionally excludes this Device Manager action from reversible DPC scope.
    #[error("Device Manager intent is outside reversible C11 policy scope")]
    RestrictedDeviceManagerIntent,
    /// Requested package and independent pre-state do not identify the same target.
    #[error("Device Manager policy target mismatch")]
    PolicyTargetMismatch,
    /// Policy read-back came from stale Provider/connection authority.
    #[error("Device Manager policy read-back is stale")]
    StalePolicyReadback,
    /// Independent policy read-back does not match the requested post-condition.
    #[error("Device Manager policy post-condition mismatch")]
    PolicyPostconditionMismatch,
    /// Independent rollback read-back did not restore the pre-operation state.
    #[error("Device Manager rollback post-condition mismatch")]
    RollbackPostconditionMismatch,
    /// MIBU nonce does not match the reviewed bounded syntax.
    #[error("MIBU nonce is invalid")]
    InvalidMibuNonce,
    /// Current C10 Application Session is not the pinned MIBU package/version.
    #[error("MIBU Application Session mismatch")]
    MibuApplicationMismatch,
    /// Proof operation/application/nonce correlation does not match the admission.
    #[error("MIBU proof correlation mismatch")]
    MibuCorrelationMismatch,
    /// Proof protocol version does not match the pinned donor contract.
    #[error("MIBU proof protocol mismatch")]
    MibuProofProtocolMismatch,
    /// Proof producer application version does not match the pinned donor contract.
    #[error("MIBU proof producer application version mismatch")]
    MibuProofApplicationVersionMismatch,
    /// Proof was produced by an older Provider generation or connection epoch.
    #[error("MIBU proof is stale")]
    StaleMibuProof,
    /// Matching nonce was supplied without independent producer authentication.
    #[error("MIBU proof producer is not independently authenticated")]
    UnauthenticatedMibuProducer,
    /// External-result claim lacks classified authority and a result reference.
    #[error("MIBU external result lacks explicit external authority")]
    MissingExternalAuthority,
    /// Final authoritative result already exists and prevents lower/conflicting replay.
    #[error("MIBU authoritative result is already recorded")]
    AuthoritativeResultAlreadyRecorded,
    /// Rebind evidence is absent or rebind generation cannot advance.
    #[error("MIBU workflow cannot be rebound")]
    MibuRebindRejected,
    /// A required MIBU release role is absent or duplicated.
    #[error("MIBU release bundle is incomplete")]
    IncompleteMibuRelease,
    /// Release artifact digest is not canonical lowercase SHA-256.
    #[error("MIBU release digest is invalid")]
    InvalidReleaseDigest,
}

/// Frozen metadata for the private Device Manager donor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceManagerSourceLock {
    /// Canonical repository URL.
    pub repository_url: String,
    /// Exact admitted commit.
    pub commit_sha: String,
    /// Exact admitted Git tree.
    pub tree_sha1: String,
    /// Android package identity.
    pub package_id: String,
    /// Exact application version.
    pub application_version: String,
    /// Exact build script blob declaring package/version/signing configuration.
    pub build_gradle_blob_sha1: String,
    /// Exact manifest blob.
    pub manifest_blob_sha1: String,
    /// Exact main activity blob.
    pub main_activity_blob_sha1: String,
    /// Exact Device Admin receiver blob.
    pub admin_receiver_blob_sha1: String,
    /// Exact policy preset blob.
    pub policy_preset_blob_sha1: String,
    /// Whether a reviewed public source-reuse grant exists.
    pub public_reuse_grant: bool,
}

impl DeviceManagerSourceLock {
    /// Return the exact private donor metadata admitted by C11.
    #[must_use]
    pub fn frozen() -> Self {
        Self {
            repository_url: DEVICE_MANAGER_REPOSITORY_URL.into(),
            commit_sha: DEVICE_MANAGER_COMMIT_SHA.into(),
            tree_sha1: DEVICE_MANAGER_TREE_SHA1.into(),
            package_id: DEVICE_MANAGER_PACKAGE_ID.into(),
            application_version: DEVICE_MANAGER_APP_VERSION.into(),
            build_gradle_blob_sha1: DEVICE_MANAGER_BUILD_GRADLE_BLOB_SHA1.into(),
            manifest_blob_sha1: DEVICE_MANAGER_MANIFEST_BLOB_SHA1.into(),
            main_activity_blob_sha1: DEVICE_MANAGER_MAIN_ACTIVITY_BLOB_SHA1.into(),
            admin_receiver_blob_sha1: DEVICE_MANAGER_ADMIN_RECEIVER_BLOB_SHA1.into(),
            policy_preset_blob_sha1: DEVICE_MANAGER_POLICY_PRESET_BLOB_SHA1.into(),
            public_reuse_grant: false,
        }
    }

    fn validate(&self) -> Result<(), C11AdmissionError> {
        if self != &Self::frozen() {
            return Err(C11AdmissionError::DeviceManagerSourceLockMismatch);
        }
        Ok(())
    }
}

/// Independently observed Android Device Owner state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceOwnerObservation {
    /// Package observed as Device Owner.
    pub package_id: String,
    /// Device Admin component observed as owner/admin.
    pub component_name: String,
    /// Whether Android independently reported this package as Device Owner.
    pub is_device_owner: bool,
    /// Provider generation that produced the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch that produced the observation.
    pub connection_epoch: u64,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Observation timestamp.
    pub observed_at: String,
}

/// Independently observed application-visibility policy state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationVisibilityObservation {
    /// Policy target Android package.
    pub package_id: String,
    /// Whether Android independently reports the package hidden.
    pub hidden: bool,
    /// Provider generation that produced the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch that produced the observation.
    pub connection_epoch: u64,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Observation timestamp.
    pub observed_at: String,
}

/// Reversible Device Manager DPC scope admitted by C11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReversibleDpcScope {
    /// Application visibility (`setApplicationHidden`) only.
    ApplicationVisibility,
}

/// Explicit current authorization for one reversible DPC policy scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReversibleDpcAuthorization {
    /// Stable authorization identity.
    pub authorization_ref: EntityRef,
    /// Device Session covered by this authorization.
    pub device_session_ref: EntityRef,
    /// Exact reversible scope approved.
    pub scope: ReversibleDpcScope,
    /// Whether the scope was explicitly approved.
    pub approved: bool,
    /// Provider generation bound to the authorization check.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the authorization check.
    pub connection_epoch: u64,
    /// Supporting approval evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Approval timestamp.
    pub approved_at: String,
}

/// Device Manager intent presented to the C11 admission boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceManagerPolicyIntent {
    /// Reversible Device Owner application visibility operation.
    ApplicationVisibility {
        /// Target Android package.
        package_id: String,
        /// Desired hidden state.
        hidden: bool,
    },
    /// Ownership-changing enrollment remains outside C11 reversible policy.
    DeviceOwnerEnrollment,
    /// Factory reset remains outside C11 reversible policy.
    FactoryReset,
    /// FRP-related recovery remains outside C11 reversible policy.
    FrpRemoval,
    /// MDM-removal recovery remains outside C11 reversible policy.
    MdmRemoval,
    /// Raw partition mutation remains outside C11 reversible policy.
    RawPartitionWrite,
    /// OTA policy mutation is not part of the first reversible C11 slice.
    OtaPolicyChange,
}

/// Inputs for admitting one reversible Device Manager DPC policy attempt.
#[derive(Debug)]
pub struct DeviceManagerPolicyRequest<'a> {
    /// Exact frozen donor metadata.
    pub source: &'a DeviceManagerSourceLock,
    /// Current C10 Android Device Session.
    pub session: &'a DeviceSession,
    /// Current C10 Device Manager Application Session with verified package/signature state.
    pub application_session: ApplicationSession,
    /// Current C09 read-only correlated evidence.
    pub xray: &'a AdmittedXrayWorkload,
    /// Independent Device Owner read-back.
    pub device_owner: &'a DeviceOwnerObservation,
    /// Explicit current authorization for the reversible DPC scope.
    pub authorization: ReversibleDpcAuthorization,
    /// Independent policy state before mutation.
    pub before: &'a ApplicationVisibilityObservation,
    /// Requested workload intent.
    pub intent: DeviceManagerPolicyIntent,
    /// Admission evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Request timestamp.
    pub requested_at: String,
}

/// The only mutation authority exposed by the C11 Device Manager adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceManagerAuthority {
    /// Reversible DPC application-visibility policy only.
    ReversibleDpcPolicyOnly,
}

/// Verification lifecycle for an admitted Device Manager policy attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceManagerPolicyProofState {
    /// Command/admission exists but independent post-condition proof does not.
    AwaitingReadback,
    /// Exact independent post-condition proof has been established.
    Verified,
}

/// Admitted but unverified Device Manager policy attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceManagerPolicyAttempt {
    /// Stable Ptah operation identity for the policy attempt.
    pub policy_operation_ref: EntityRef,
    /// Exact private donor commit retained as metadata only.
    pub source_commit_sha: String,
    /// Source extraction is false at this frozen C11 boundary.
    pub source_extraction_allowed: bool,
    /// Device Session identity.
    pub device_session_ref: EntityRef,
    /// Verified Device Manager Application Session identity.
    pub application_session_ref: EntityRef,
    /// Explicit reversible-DPC authorization identity.
    pub authorization_ref: EntityRef,
    /// Target package.
    pub package_id: String,
    /// Independently observed pre-operation hidden state.
    pub previous_hidden: bool,
    /// Desired hidden state.
    pub desired_hidden: bool,
    /// Provider generation bound to the attempt.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the attempt.
    pub connection_epoch: u64,
    /// Bounded C11 authority.
    pub authority: DeviceManagerAuthority,
    /// Admission evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Request timestamp.
    pub requested_at: String,
    /// Current independent proof state.
    pub proof_state: DeviceManagerPolicyProofState,
}

/// Device Manager policy promoted only after exact independent read-back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeviceManagerPolicy {
    /// Original policy operation identity.
    pub policy_operation_ref: EntityRef,
    /// Device Session identity.
    pub device_session_ref: EntityRef,
    /// Target package.
    pub package_id: String,
    /// State that rollback must restore.
    pub previous_hidden: bool,
    /// Verified applied state.
    pub applied_hidden: bool,
    /// Provider generation bound to proof.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to proof.
    pub connection_epoch: u64,
    /// Bounded C11 authority.
    pub authority: DeviceManagerAuthority,
    /// Combined attempt/read-back evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Whether exact post-condition proof was established.
    pub verified: bool,
}

/// Independently verified rollback receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceManagerRollbackReceipt {
    /// Original policy operation identity.
    pub policy_operation_ref: EntityRef,
    /// Target package.
    pub package_id: String,
    /// Whether the independently observed state equals the original state.
    pub restored_original_state: bool,
    /// Rollback evidence.
    pub evidence_refs: Vec<EntityRef>,
}

/// Admit one reversible Device Manager application-visibility policy attempt.
///
/// # Errors
/// Fails closed on donor drift, stale/inconclusive C09/C10 context, absent Device Owner
/// read-back, restricted intent, missing evidence, or target/pre-state disagreement.
pub fn admit_device_manager_policy(
    request: DeviceManagerPolicyRequest<'_>,
) -> Result<DeviceManagerPolicyAttempt, C11AdmissionError> {
    request.source.validate()?;
    validate_session_and_xray(request.session, request.xray)?;
    validate_device_manager_application(request.session, &request.application_session)?;
    validate_dpc_authorization(request.session, &request.authorization)?;
    require_evidence(&request.evidence_refs, &request.requested_at)?;

    if request.device_owner.package_id != DEVICE_MANAGER_PACKAGE_ID
        || request.device_owner.component_name.trim().is_empty()
        || !request.device_owner.is_device_owner
    {
        return Err(C11AdmissionError::DeviceOwnerNotObserved);
    }
    validate_observation_context(
        request.session,
        request.device_owner.provider_generation,
        request.device_owner.connection_epoch,
        &request.device_owner.evidence_refs,
        &request.device_owner.observed_at,
    )?;

    let (package_id, desired_hidden) = match request.intent {
        DeviceManagerPolicyIntent::ApplicationVisibility { package_id, hidden } => {
            if package_id.trim().is_empty() {
                return Err(C11AdmissionError::PolicyTargetMismatch);
            }
            (package_id, hidden)
        }
        DeviceManagerPolicyIntent::DeviceOwnerEnrollment
        | DeviceManagerPolicyIntent::FactoryReset
        | DeviceManagerPolicyIntent::FrpRemoval
        | DeviceManagerPolicyIntent::MdmRemoval
        | DeviceManagerPolicyIntent::RawPartitionWrite
        | DeviceManagerPolicyIntent::OtaPolicyChange => {
            return Err(C11AdmissionError::RestrictedDeviceManagerIntent);
        }
    };

    validate_observation_context(
        request.session,
        request.before.provider_generation,
        request.before.connection_epoch,
        &request.before.evidence_refs,
        &request.before.observed_at,
    )?;
    if request.before.package_id != package_id {
        return Err(C11AdmissionError::PolicyTargetMismatch);
    }

    Ok(DeviceManagerPolicyAttempt {
        policy_operation_ref: EntityRef::new("operation.device_policy")
            .map_err(|_| C11AdmissionError::MissingEvidence)?,
        source_commit_sha: DEVICE_MANAGER_COMMIT_SHA.into(),
        source_extraction_allowed: false,
        device_session_ref: request.session.session_ref.clone(),
        application_session_ref: request.application_session.session_ref.clone(),
        authorization_ref: request.authorization.authorization_ref.clone(),
        package_id,
        previous_hidden: request.before.hidden,
        desired_hidden,
        provider_generation: request.session.provider_generation,
        connection_epoch: request.session.connection_epoch,
        authority: DeviceManagerAuthority::ReversibleDpcPolicyOnly,
        evidence_refs: request.evidence_refs,
        requested_at: request.requested_at,
        proof_state: DeviceManagerPolicyProofState::AwaitingReadback,
    })
}

/// Verify a Device Manager policy attempt using independent Android state read-back.
///
/// # Errors
/// Fails closed when read-back is stale, missing, targets another package, or does not
/// match the requested post-condition.
pub fn verify_device_manager_policy(
    attempt: &DeviceManagerPolicyAttempt,
    readback: &ApplicationVisibilityObservation,
) -> Result<VerifiedDeviceManagerPolicy, C11AdmissionError> {
    require_evidence(&readback.evidence_refs, &readback.observed_at)?;
    if readback.provider_generation != attempt.provider_generation
        || readback.connection_epoch != attempt.connection_epoch
    {
        return Err(C11AdmissionError::StalePolicyReadback);
    }
    if readback.package_id != attempt.package_id {
        return Err(C11AdmissionError::PolicyTargetMismatch);
    }
    if readback.hidden != attempt.desired_hidden {
        return Err(C11AdmissionError::PolicyPostconditionMismatch);
    }
    let mut evidence_refs = attempt.evidence_refs.clone();
    evidence_refs.extend(readback.evidence_refs.iter().cloned());
    Ok(VerifiedDeviceManagerPolicy {
        policy_operation_ref: attempt.policy_operation_ref.clone(),
        device_session_ref: attempt.device_session_ref.clone(),
        package_id: attempt.package_id.clone(),
        previous_hidden: attempt.previous_hidden,
        applied_hidden: readback.hidden,
        provider_generation: attempt.provider_generation,
        connection_epoch: attempt.connection_epoch,
        authority: attempt.authority,
        evidence_refs,
        verified: true,
    })
}

/// Verify rollback restored the exact independently observed pre-operation state.
///
/// # Errors
/// Fails closed when rollback read-back is stale, missing, targets another package, or
/// does not restore the original state.
pub fn verify_device_manager_policy_rollback(
    verified: &VerifiedDeviceManagerPolicy,
    readback: &ApplicationVisibilityObservation,
) -> Result<DeviceManagerRollbackReceipt, C11AdmissionError> {
    require_evidence(&readback.evidence_refs, &readback.observed_at)?;
    if readback.provider_generation != verified.provider_generation
        || readback.connection_epoch != verified.connection_epoch
    {
        return Err(C11AdmissionError::StalePolicyReadback);
    }
    if readback.package_id != verified.package_id {
        return Err(C11AdmissionError::PolicyTargetMismatch);
    }
    if readback.hidden != verified.previous_hidden {
        return Err(C11AdmissionError::RollbackPostconditionMismatch);
    }
    Ok(DeviceManagerRollbackReceipt {
        policy_operation_ref: verified.policy_operation_ref.clone(),
        package_id: verified.package_id.clone(),
        restored_original_state: true,
        evidence_refs: readback.evidence_refs.clone(),
    })
}

/// Frozen source metadata for the public MIBU repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MibuSourceLock {
    /// Canonical repository URL.
    pub repository_url: String,
    /// Exact admitted commit.
    pub commit_sha: String,
    /// Exact admitted Git tree.
    pub tree_sha1: String,
    /// Android package identity.
    pub package_id: String,
    /// Exact application version.
    pub application_version: String,
    /// Exact proof protocol version.
    pub proof_protocol_version: u32,
    /// Exact `ProofContract` blob.
    pub proof_contract_blob_sha1: String,
    /// Exact `ProofNonce` blob.
    pub proof_nonce_blob_sha1: String,
    /// Exact proof review tool blob.
    pub proof_review_blob_sha1: String,
    /// Exact Windows helper version-info blob.
    pub version_info_blob_sha1: String,
    /// Whether a reviewed source-reuse grant exists for code extraction.
    pub public_reuse_grant: bool,
}

impl MibuSourceLock {
    /// Return the exact MIBU donor metadata admitted by C11.
    #[must_use]
    pub fn frozen() -> Self {
        Self {
            repository_url: MIBU_REPOSITORY_URL.into(),
            commit_sha: MIBU_COMMIT_SHA.into(),
            tree_sha1: MIBU_TREE_SHA1.into(),
            package_id: MIBU_PACKAGE_ID.into(),
            application_version: MIBU_APP_VERSION.into(),
            proof_protocol_version: MIBU_PROOF_PROTOCOL_VERSION,
            proof_contract_blob_sha1: MIBU_PROOF_CONTRACT_BLOB_SHA1.into(),
            proof_nonce_blob_sha1: MIBU_PROOF_NONCE_BLOB_SHA1.into(),
            proof_review_blob_sha1: MIBU_PROOF_REVIEW_BLOB_SHA1.into(),
            version_info_blob_sha1: MIBU_VERSION_INFO_BLOB_SHA1.into(),
            public_reuse_grant: false,
        }
    }

    fn validate(&self) -> Result<(), C11AdmissionError> {
        if self != &Self::frozen() {
            return Err(C11AdmissionError::MibuSourceLockMismatch);
        }
        Ok(())
    }
}

/// The only authority exposed by the MIBU C11 adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MibuAuthority {
    /// Correlation and evidence projection only; no protected Device mutation authority.
    CorrelationAndEvidenceOnly,
}

/// Inputs for admitting one MIBU cross-application/device workflow.
#[derive(Debug)]
pub struct MibuWorkflowRequest<'a> {
    /// Exact frozen MIBU source metadata.
    pub source: &'a MibuSourceLock,
    /// Current C10 Device Session.
    pub device_session: &'a DeviceSession,
    /// Current C10 MIBU Application Session.
    pub application_session: &'a ApplicationSession,
    /// Current C09 correlated read-only Device evidence.
    pub xray: &'a AdmittedXrayWorkload,
    /// Stable Ptah operation identity.
    pub operation_ref: EntityRef,
    /// Donor correlation nonce; retained only as digest and length after admission.
    pub nonce: &'a str,
    /// Admission evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Request timestamp.
    pub requested_at: String,
}

/// Admitted MIBU workflow correlation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MibuWorkflowAdmission {
    /// Exact donor commit.
    pub source_commit_sha: String,
    /// Donor source extraction remains disabled absent a reviewed reuse grant.
    pub source_extraction_allowed: bool,
    /// Stable Ptah operation identity.
    pub operation_ref: EntityRef,
    /// Current Device Session identity.
    pub device_session_ref: EntityRef,
    /// Current MIBU Application Session identity.
    pub application_session_ref: EntityRef,
    /// Stable Device identity.
    pub device_ref: EntityRef,
    /// Current Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Current Provider generation.
    pub provider_generation: ProviderGeneration,
    /// Current connection epoch.
    pub connection_epoch: u64,
    /// SHA-256 of the bounded correlation nonce.
    pub nonce_sha256: String,
    /// Original nonce length without retaining its raw value.
    pub nonce_length: usize,
    /// Exact proof protocol version.
    pub proof_protocol_version: u32,
    /// Exact MIBU application version.
    pub application_version: String,
    /// Rebind generation; zero on initial admission.
    pub rebind_generation: u64,
    /// Automatic replay is always false for this physical workflow.
    pub automatic_replay_allowed: bool,
    /// Bounded adapter authority.
    pub authority: MibuAuthority,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Request timestamp.
    pub requested_at: String,
}

/// MIBU proof level retained without collapsing distinct meanings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MibuProofLevel {
    /// Android activity launch acknowledgement only.
    ActivityLaunched,
    /// MIBU runtime/foreground service is independently armed.
    RuntimeArmed,
    /// Product workflow reports correlated completion, but not external authority.
    OperationComplete,
    /// Separately classified official external result exists.
    ExternalAuthoritativeResult,
}

/// Separately classified authority for a MIBU external result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MibuExternalAuthority {
    /// Official external service/result retained as external truth rather than Ptah inference.
    OfficialExternalService,
}

/// One current MIBU proof envelope presented for reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MibuProofEnvelope {
    /// Stable Ptah operation identity.
    pub operation_ref: EntityRef,
    /// Application Session that produced the proof.
    pub application_session_ref: EntityRef,
    /// Raw correlation nonce supplied transiently for this verification call.
    pub nonce: String,
    /// Producer proof protocol version.
    pub proof_protocol_version: u32,
    /// Producer MIBU application version.
    pub producer_application_version: String,
    /// Whether producer identity/authentication was independently established.
    pub producer_authenticated: bool,
    /// Evidence for independent producer authentication.
    pub producer_auth_evidence_refs: Vec<EntityRef>,
    /// Provider generation that produced the proof.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch that produced the proof.
    pub connection_epoch: u64,
    /// Proof level observed.
    pub level: MibuProofLevel,
    /// External authority classification when applicable.
    pub external_authority: Option<MibuExternalAuthority>,
    /// External authoritative result evidence when applicable.
    pub external_result_ref: Option<EntityRef>,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Observation timestamp.
    pub observed_at: String,
}

/// Reconciled MIBU proof receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MibuProofReceipt {
    /// Stable Ptah operation identity.
    pub operation_ref: EntityRef,
    /// Proof level retained exactly.
    pub level: MibuProofLevel,
    /// Whether this proof establishes product-workflow completion.
    pub operation_complete: bool,
    /// Whether this proof is explicitly an external authoritative result.
    pub external_authoritative_result: bool,
    /// External authority retained separately.
    pub external_authority: Option<MibuExternalAuthority>,
    /// External result reference retained separately.
    pub external_result_ref: Option<EntityRef>,
    /// Provider generation bound to proof.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to proof.
    pub connection_epoch: u64,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
}

/// Admit the pinned MIBU workflow under current C09/C10 context.
///
/// # Errors
/// Fails closed on source drift, invalid nonce, stale/inconclusive C09/C10 context,
/// wrong package/version, or missing evidence.
pub fn admit_mibu_workflow(
    request: MibuWorkflowRequest<'_>,
) -> Result<MibuWorkflowAdmission, C11AdmissionError> {
    request.source.validate()?;
    validate_session_and_xray(request.device_session, request.xray)?;
    validate_mibu_application(request.device_session, request.application_session)?;
    require_evidence(&request.evidence_refs, &request.requested_at)?;
    validate_mibu_nonce(request.nonce)?;

    Ok(MibuWorkflowAdmission {
        source_commit_sha: MIBU_COMMIT_SHA.into(),
        source_extraction_allowed: false,
        operation_ref: request.operation_ref,
        device_session_ref: request.device_session.session_ref.clone(),
        application_session_ref: request.application_session.session_ref.clone(),
        device_ref: request.device_session.device_ref.clone(),
        provider_instance_ref: request.device_session.provider_instance_ref.clone(),
        provider_generation: request.device_session.provider_generation,
        connection_epoch: request.device_session.connection_epoch,
        nonce_sha256: sha256_text(request.nonce),
        nonce_length: request.nonce.len(),
        proof_protocol_version: MIBU_PROOF_PROTOCOL_VERSION,
        application_version: MIBU_APP_VERSION.into(),
        rebind_generation: 0,
        automatic_replay_allowed: false,
        authority: MibuAuthority::CorrelationAndEvidenceOnly,
        evidence_refs: request.evidence_refs,
        requested_at: request.requested_at,
    })
}

/// Rebind a MIBU workflow after C10 Device/Application recovery without replaying it.
///
/// # Errors
/// Fails closed unless stable Device Session identity is preserved, C09/C10 context is
/// current, MIBU package/version remain exact, evidence exists, and generation advances.
pub fn rebind_mibu_workflow(
    prior: &MibuWorkflowAdmission,
    session: &DeviceSession,
    application_session: &ApplicationSession,
    xray: &AdmittedXrayWorkload,
    evidence_refs: Vec<EntityRef>,
) -> Result<MibuWorkflowAdmission, C11AdmissionError> {
    validate_session_and_xray(session, xray)?;
    validate_mibu_application(session, application_session)?;
    if session.session_ref != prior.device_session_ref || evidence_refs.is_empty() {
        return Err(C11AdmissionError::MibuRebindRejected);
    }
    let rebind_generation = prior
        .rebind_generation
        .checked_add(1)
        .ok_or(C11AdmissionError::MibuRebindRejected)?;
    Ok(MibuWorkflowAdmission {
        source_commit_sha: prior.source_commit_sha.clone(),
        source_extraction_allowed: false,
        operation_ref: prior.operation_ref.clone(),
        device_session_ref: session.session_ref.clone(),
        application_session_ref: application_session.session_ref.clone(),
        device_ref: session.device_ref.clone(),
        provider_instance_ref: session.provider_instance_ref.clone(),
        provider_generation: session.provider_generation,
        connection_epoch: session.connection_epoch,
        nonce_sha256: prior.nonce_sha256.clone(),
        nonce_length: prior.nonce_length,
        proof_protocol_version: prior.proof_protocol_version,
        application_version: prior.application_version.clone(),
        rebind_generation,
        automatic_replay_allowed: false,
        authority: MibuAuthority::CorrelationAndEvidenceOnly,
        evidence_refs,
        requested_at: prior.requested_at.clone(),
    })
}

/// Reconcile one MIBU proof envelope against current admitted workflow state.
///
/// # Errors
/// Fails closed on stale/cross-operation proof, nonce/protocol/version mismatch,
/// unauthenticated producer, missing evidence, missing external authority, or any attempt
/// to replace an already-recorded final external result with lower/conflicting proof.
pub fn reconcile_mibu_proof(
    admission: &MibuWorkflowAdmission,
    envelope: &MibuProofEnvelope,
    previous: Option<&MibuProofReceipt>,
) -> Result<MibuProofReceipt, C11AdmissionError> {
    if previous.is_some_and(|receipt| receipt.external_authoritative_result) {
        return Err(C11AdmissionError::AuthoritativeResultAlreadyRecorded);
    }
    if envelope.operation_ref != admission.operation_ref
        || envelope.application_session_ref != admission.application_session_ref
    {
        return Err(C11AdmissionError::MibuCorrelationMismatch);
    }
    validate_mibu_nonce(&envelope.nonce)?;
    if sha256_text(&envelope.nonce) != admission.nonce_sha256
        || envelope.nonce.len() != admission.nonce_length
    {
        return Err(C11AdmissionError::MibuCorrelationMismatch);
    }
    if envelope.proof_protocol_version != admission.proof_protocol_version {
        return Err(C11AdmissionError::MibuProofProtocolMismatch);
    }
    if envelope.producer_application_version != admission.application_version {
        return Err(C11AdmissionError::MibuProofApplicationVersionMismatch);
    }
    if envelope.provider_generation != admission.provider_generation
        || envelope.connection_epoch != admission.connection_epoch
    {
        return Err(C11AdmissionError::StaleMibuProof);
    }
    if !envelope.producer_authenticated || envelope.producer_auth_evidence_refs.is_empty() {
        return Err(C11AdmissionError::UnauthenticatedMibuProducer);
    }
    require_evidence(&envelope.evidence_refs, &envelope.observed_at)?;

    let (operation_complete, external_authoritative_result) = match envelope.level {
        MibuProofLevel::ActivityLaunched | MibuProofLevel::RuntimeArmed => (false, false),
        MibuProofLevel::OperationComplete => (true, false),
        MibuProofLevel::ExternalAuthoritativeResult => {
            if envelope.external_authority.is_none() || envelope.external_result_ref.is_none() {
                return Err(C11AdmissionError::MissingExternalAuthority);
            }
            (true, true)
        }
    };

    Ok(MibuProofReceipt {
        operation_ref: admission.operation_ref.clone(),
        level: envelope.level,
        operation_complete,
        external_authoritative_result,
        external_authority: envelope.external_authority,
        external_result_ref: envelope.external_result_ref.clone(),
        provider_generation: admission.provider_generation,
        connection_epoch: admission.connection_epoch,
        evidence_refs: envelope.evidence_refs.clone(),
    })
}

/// Required role in a complete MIBU release Artifact composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MibuReleaseArtifactRole {
    /// Android APK.
    AndroidApk,
    /// Windows helper application.
    WindowsHelper,
    /// Pinned platform-tools bundle.
    PlatformTools,
    /// Expected UI/static evidence bundle.
    ExpectedUiEvidence,
    /// Checksum manifest covering the release.
    ChecksumManifest,
}

/// One digest-bound MIBU release Artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MibuReleaseArtifact {
    /// Required release role.
    pub role: MibuReleaseArtifactRole,
    /// Canonical Artifact reference.
    pub artifact_ref: EntityRef,
    /// Canonical lowercase SHA-256 digest.
    pub sha256: String,
}

/// Candidate MIBU release manifest presented to C11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MibuReleaseManifest {
    /// Exact donor commit from which the release was produced.
    pub source_commit_sha: String,
    /// Exact Android application version.
    pub application_version: String,
    /// Exact proof protocol version.
    pub proof_protocol_version: u32,
    /// Required release Artifacts.
    pub artifacts: Vec<MibuReleaseArtifact>,
    /// Supporting release evidence.
    pub evidence_refs: Vec<EntityRef>,
}

/// Verified complete MIBU release projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMibuRelease {
    /// Exact donor commit.
    pub source_commit_sha: String,
    /// Number of distinct required Artifacts.
    pub artifact_count: usize,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
}

/// Validate that a MIBU release is complete and digest-bound.
///
/// # Errors
/// Fails closed on source/protocol/version drift, missing/duplicate roles, absent evidence,
/// or malformed SHA-256 digests.
pub fn validate_mibu_release(
    source: &MibuSourceLock,
    manifest: &MibuReleaseManifest,
) -> Result<VerifiedMibuRelease, C11AdmissionError> {
    source.validate()?;
    if manifest.source_commit_sha != MIBU_COMMIT_SHA
        || manifest.application_version != MIBU_APP_VERSION
        || manifest.proof_protocol_version != MIBU_PROOF_PROTOCOL_VERSION
        || manifest.evidence_refs.is_empty()
    {
        return Err(C11AdmissionError::IncompleteMibuRelease);
    }
    let required = BTreeSet::from([
        MibuReleaseArtifactRole::AndroidApk,
        MibuReleaseArtifactRole::WindowsHelper,
        MibuReleaseArtifactRole::PlatformTools,
        MibuReleaseArtifactRole::ExpectedUiEvidence,
        MibuReleaseArtifactRole::ChecksumManifest,
    ]);
    let mut observed = BTreeSet::new();
    for artifact in &manifest.artifacts {
        if artifact.artifact_ref.entity_kind.as_str() != "object.artifact" {
            return Err(C11AdmissionError::IncompleteMibuRelease);
        }
        if !is_lower_hex_digest(&artifact.sha256, 64) {
            return Err(C11AdmissionError::InvalidReleaseDigest);
        }
        if !observed.insert(artifact.role) {
            return Err(C11AdmissionError::IncompleteMibuRelease);
        }
    }
    if observed != required {
        return Err(C11AdmissionError::IncompleteMibuRelease);
    }
    Ok(VerifiedMibuRelease {
        source_commit_sha: manifest.source_commit_sha.clone(),
        artifact_count: manifest.artifacts.len(),
        evidence_refs: manifest.evidence_refs.clone(),
    })
}

fn validate_session_and_xray(
    session: &DeviceSession,
    xray: &AdmittedXrayWorkload,
) -> Result<(), C11AdmissionError> {
    if !matches!(
        session.state,
        DeviceSessionState::Connected | DeviceSessionState::PartiallyAvailable
    ) {
        return Err(C11AdmissionError::DeviceContextMismatch);
    }
    if xray.disposition != XrayEvidenceDisposition::Correlated
        || xray.freshness != XrayEvidenceFreshness::Current
    {
        return Err(C11AdmissionError::XrayNotCurrentCorrelated);
    }
    if xray.device_ref != session.device_ref
        || xray.interface_ref != session.interface_ref
        || xray.connection_ref != session.connection_ref
        || xray.provider_instance_ref != session.provider_instance_ref
        || xray.provider_generation != session.provider_generation
        || xray.connection_epoch != session.connection_epoch
    {
        return Err(C11AdmissionError::DeviceContextMismatch);
    }
    Ok(())
}

fn validate_observation_context(
    session: &DeviceSession,
    provider_generation: ProviderGeneration,
    connection_epoch: u64,
    evidence_refs: &[EntityRef],
    observed_at: &str,
) -> Result<(), C11AdmissionError> {
    require_evidence(evidence_refs, observed_at)?;
    if provider_generation != session.provider_generation
        || connection_epoch != session.connection_epoch
    {
        return Err(C11AdmissionError::DeviceContextMismatch);
    }
    Ok(())
}

fn validate_device_manager_application(
    session: &DeviceSession,
    application: &ApplicationSession,
) -> Result<(), C11AdmissionError> {
    if application.device_session_ref != session.session_ref
        || application.package_id != DEVICE_MANAGER_PACKAGE_ID
        || application.installed_version != DEVICE_MANAGER_APP_VERSION
        || application.verified_signer.trim().is_empty()
        || application.provider_instance_ref != session.provider_instance_ref
        || application.provider_generation != session.provider_generation
        || application.connection_epoch != session.connection_epoch
        || !matches!(
            application.state,
            ApplicationSessionState::Visible | ApplicationSessionState::Backgrounded
        )
        || application.evidence_refs.is_empty()
    {
        return Err(C11AdmissionError::DeviceManagerApplicationMismatch);
    }
    Ok(())
}

fn validate_dpc_authorization(
    session: &DeviceSession,
    authorization: &ReversibleDpcAuthorization,
) -> Result<(), C11AdmissionError> {
    if !authorization.approved
        || authorization.device_session_ref != session.session_ref
        || authorization.scope != ReversibleDpcScope::ApplicationVisibility
        || authorization.provider_generation != session.provider_generation
        || authorization.connection_epoch != session.connection_epoch
        || authorization.evidence_refs.is_empty()
        || authorization.approved_at.trim().is_empty()
    {
        return Err(C11AdmissionError::DpcAuthorizationMismatch);
    }
    Ok(())
}

fn validate_mibu_application(
    session: &DeviceSession,
    application: &ApplicationSession,
) -> Result<(), C11AdmissionError> {
    if application.device_session_ref != session.session_ref
        || application.package_id != MIBU_PACKAGE_ID
        || application.installed_version != MIBU_APP_VERSION
        || application.provider_instance_ref != session.provider_instance_ref
        || application.provider_generation != session.provider_generation
        || application.connection_epoch != session.connection_epoch
        || !matches!(
            application.state,
            ApplicationSessionState::Visible | ApplicationSessionState::Backgrounded
        )
        || application.evidence_refs.is_empty()
    {
        return Err(C11AdmissionError::MibuApplicationMismatch);
    }
    Ok(())
}

fn validate_mibu_nonce(value: &str) -> Result<(), C11AdmissionError> {
    if !(8..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(C11AdmissionError::InvalidMibuNonce);
    }
    Ok(())
}

fn require_evidence(evidence_refs: &[EntityRef], timestamp: &str) -> Result<(), C11AdmissionError> {
    if evidence_refs.is_empty() || timestamp.trim().is_empty() {
        return Err(C11AdmissionError::MissingEvidence);
    }
    Ok(())
}

fn sha256_text(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{digest:x}")
}

fn is_lower_hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
