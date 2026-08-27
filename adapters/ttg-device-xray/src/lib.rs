#![forbid(unsafe_code)]
//! C09 TTG Device X-Ray workload admission.
//!
//! This adapter admits one exact public TTG Device X-Ray revision as a read-only
//! evidence producer. It does not execute X-Ray, parse private shop configuration,
//! verify private signing keys, select repair authority, or expose physical Device
//! mutation. C08 remains the authority for current Device/Provider/epoch/lease/fence
//! admission; C09 consumes only already-admitted C08 read-only protocol operations.

use ptah_device_runtime::{AdmittedProtocolOperation, DeviceInterfaceRecord, OperationAuthority};
use ptah_identifiers::EntityRef;
use ptah_provider_api::ProviderGeneration;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Exact public TTG Device X-Ray repository admitted by C09.
pub const XRAY_REPOSITORY_URL: &str = "https://github.com/jaydumisuni/TTG-Device-X-Ray";
/// Exact donor commit admitted by C09.
pub const XRAY_COMMIT_SHA: &str = "ad4ae832ed994944a5d8e99bc3a0785e257826ff";
/// Exact public scanner version observed at [`XRAY_COMMIT_SHA`].
pub const XRAY_SCANNER_VERSION: &str = "0.4.3.dev2";
/// Successful public donor CI run bound to [`XRAY_COMMIT_SHA`].
pub const XRAY_CI_RUN_ID: u64 = 32_939_120_054;
/// Git blob identity of the donor's public read-only command-literal validator.
pub const XRAY_READ_ONLY_CHECK_BLOB_SHA1: &str = "0e3827d7dba201c236e78ab9ff904975862e840e";
/// Git blob identity of the donor's sealed-bundle implementation.
pub const XRAY_BUNDLE_SEAL_BLOB_SHA1: &str = "1a6568a957a3ce9837b34dabab3caf9cc4fca44d";

const FROZEN_PUBLIC_ASSETS: &[(&str, &str, XrayPublicAssetKind)] = &[
    (
        "src/ttg_device_xray/profiles/apple/a8_a11_gaster_reference.json",
        "7a529a9d5ac43f3249d1be31f71b65b3abc88c97",
        XrayPublicAssetKind::Profile,
    ),
    (
        "src/ttg_device_xray/profiles/huawei/vog_l29_c185_kirin.json",
        "b1488c24df6350d901b30ad4beec1e84e9c7b6b5",
        XrayPublicAssetKind::Profile,
    ),
    (
        "src/ttg_device_xray/profiles/transsion/km7.json",
        "e77cdaa5fa2f9c8052779a3355c234eea5856d97",
        XrayPublicAssetKind::Profile,
    ),
    (
        "src/ttg_device_xray/profiles/xiaomi/redmi_sky_parrot.json",
        "7ff402b6b23bc1b1f911b570768f2abed67135a4",
        XrayPublicAssetKind::Profile,
    ),
    (
        "tests/fixtures/mtk_meta_km7.json",
        "1107bb513e16f58963b2a7abbdd3c22ea1bf755c",
        XrayPublicAssetKind::Fixture,
    ),
    (
        "tests/fixtures/qualcomm_edl_sm7250.json",
        "491958e5901ba66561debe945a2ad617a2561189",
        XrayPublicAssetKind::Fixture,
    ),
    (
        "tests/fixtures/samsung_download_exynos.json",
        "02171716cfac3c9d39949f93961a403f1154f5f5",
        XrayPublicAssetKind::Fixture,
    ),
    (
        "tests/fixtures/spd_ums9230.json",
        "7fc931c179df174428aed0e9241ab611cfa06dcf",
        XrayPublicAssetKind::Fixture,
    ),
];

/// C09 workload-admission failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum XrayAdmissionError {
    /// One part of the exact public donor repository lock changed.
    #[error("TTG Device X-Ray source lock mismatch: {0}")]
    SourceLockMismatch(&'static str),
    /// The exact admitted profile/fixture set changed.
    #[error("TTG Device X-Ray public asset lock mismatch")]
    PublicAssetLockMismatch,
    /// The supplied public asset list contains the same path more than once.
    #[error("TTG Device X-Ray public asset path is duplicated")]
    DuplicatePublicAsset,
    /// The sealed evidence manifest digest is not a canonical lowercase SHA-256.
    #[error("TTG Device X-Ray manifest digest is invalid")]
    InvalidManifestDigest,
    /// Required X-Ray evidence is absent or internally inconsistent.
    #[error("TTG Device X-Ray evidence is incomplete")]
    MissingEvidence,
    /// Candidate-count and selected-candidate truth disagree.
    #[error("TTG Device X-Ray candidate selection is inconsistent")]
    CandidateSelectionMismatch,
    /// X-Ray evidence claimed physical write authority.
    #[error("TTG Device X-Ray evidence claims write authority")]
    WriteAuthorityClaim,
    /// No already-admitted C08 protocol operation supports this workload admission.
    #[error("C09 requires at least one admitted C08 read-only protocol operation")]
    MissingC08Operation,
    /// An admitted C08 operation is stale or belongs to another current Device context.
    #[error("C09 C08 Device/Provider/epoch context mismatch")]
    C08ContextMismatch,
}

/// Exact public donor source lock consumed by C09.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XraySourceLock {
    /// Public repository URL.
    pub repository_url: String,
    /// Exact donor commit.
    pub commit_sha: String,
    /// Exact donor scanner version.
    pub scanner_version: String,
    /// Exact successful CI run observed for the donor commit.
    pub ci_run_id: u64,
    /// Exact Git blob identity for `scripts/check_read_only.py`.
    pub read_only_check_blob_sha1: String,
    /// Exact Git blob identity for `src/ttg_device_xray/bundle_seal.py`.
    pub bundle_seal_blob_sha1: String,
}

impl XraySourceLock {
    /// Return the frozen public donor revision admitted by C09.
    #[must_use]
    pub fn frozen() -> Self {
        Self {
            repository_url: XRAY_REPOSITORY_URL.to_owned(),
            commit_sha: XRAY_COMMIT_SHA.to_owned(),
            scanner_version: XRAY_SCANNER_VERSION.to_owned(),
            ci_run_id: XRAY_CI_RUN_ID,
            read_only_check_blob_sha1: XRAY_READ_ONLY_CHECK_BLOB_SHA1.to_owned(),
            bundle_seal_blob_sha1: XRAY_BUNDLE_SEAL_BLOB_SHA1.to_owned(),
        }
    }

    fn validate(&self) -> Result<(), XrayAdmissionError> {
        if self.repository_url != XRAY_REPOSITORY_URL {
            return Err(XrayAdmissionError::SourceLockMismatch("repository_url"));
        }
        if self.commit_sha != XRAY_COMMIT_SHA {
            return Err(XrayAdmissionError::SourceLockMismatch("commit_sha"));
        }
        if self.scanner_version != XRAY_SCANNER_VERSION {
            return Err(XrayAdmissionError::SourceLockMismatch("scanner_version"));
        }
        if self.ci_run_id != XRAY_CI_RUN_ID {
            return Err(XrayAdmissionError::SourceLockMismatch("ci_run_id"));
        }
        if self.read_only_check_blob_sha1 != XRAY_READ_ONLY_CHECK_BLOB_SHA1 {
            return Err(XrayAdmissionError::SourceLockMismatch(
                "read_only_check_blob_sha1",
            ));
        }
        if self.bundle_seal_blob_sha1 != XRAY_BUNDLE_SEAL_BLOB_SHA1 {
            return Err(XrayAdmissionError::SourceLockMismatch(
                "bundle_seal_blob_sha1",
            ));
        }
        Ok(())
    }
}

/// Public donor asset class retained by C09.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum XrayPublicAssetKind {
    /// Reviewed public device profile.
    Profile,
    /// Synthetic public offline evidence fixture.
    Fixture,
}

/// Exact public profile/fixture Git object evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayPublicAssetEvidence {
    /// Repository-relative donor path.
    pub path: String,
    /// Exact Git blob SHA-1 at [`XRAY_COMMIT_SHA`].
    pub git_blob_sha1: String,
    /// Asset class.
    pub kind: XrayPublicAssetKind,
}

/// Return the exact public donor profile/fixture set admitted by C09.
#[must_use]
pub fn frozen_public_assets() -> Vec<XrayPublicAssetEvidence> {
    FROZEN_PUBLIC_ASSETS
        .iter()
        .map(|(path, sha, kind)| XrayPublicAssetEvidence {
            path: (*path).to_owned(),
            git_blob_sha1: (*sha).to_owned(),
            kind: *kind,
        })
        .collect()
}

/// X-Ray certification observation retained without promoting it to Ptah authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayCertificationVerdict {
    /// Donor reported coherent evidence for its own read-first certification domain.
    Certified,
    /// Donor retained ambiguity requiring investigation.
    Investigate,
    /// Donor reported unsafe/contradictory or multi-device evidence.
    Unsafe,
}

/// X-Ray profile-routing observation retained as evidence only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayProfileStatus {
    /// Exact donor profile matched.
    Matched,
    /// Candidate profile requires review.
    Candidate,
    /// High-confidence profile exists but its registry approval remains candidate/review.
    CandidateProfile,
    /// Reviewed registry explicitly did not match.
    NoMatch,
    /// No reviewed profile exists.
    NoProfile,
    /// No single Device candidate was selected.
    NoSelection,
}

/// Freshness observation for the sealed X-Ray evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayEvidenceFreshness {
    /// Evidence is current under the caller's independently checked freshness policy.
    Current,
    /// Evidence is stale and remains visible but cannot be treated as current.
    Stale,
    /// Freshness was not established.
    Unknown,
}

/// Publicly observable signature state.
///
/// C09 deliberately has no `Verified` variant because the public Ptah adapter does
/// not contain or consume THETECHGUY private HMAC signing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XraySignatureObservation {
    /// Donor bundle explicitly reports no signature.
    Unsigned,
    /// Donor bundle reports a signature, but public C09 does not verify private key possession.
    SignedClaimUnverifiedPublicly,
}

/// Minimal sealed X-Ray evidence admitted into Ptah.
///
/// Sensitive device aliases/serials/IMEI values are intentionally absent. Those
/// remain restricted source evidence and are never copied into this public adapter.
#[derive(Debug, Clone)]
pub struct XrayEvidenceSummary {
    /// Canonical Ptah reference to the retained X-Ray evidence bundle.
    pub bundle_ref: EntityRef,
    /// Donor scan identifier.
    pub scan_id: String,
    /// Donor manifest SHA-256.
    pub manifest_sha256: String,
    /// Number of candidate physical Devices retained by X-Ray.
    pub candidate_count: usize,
    /// Selected X-Ray candidate, when exactly one candidate is selected.
    pub selected_candidate_id: Option<String>,
    /// Donor certification observation.
    pub certification: XrayCertificationVerdict,
    /// Donor profile-routing observation.
    pub profile_status: XrayProfileStatus,
    /// Exact reviewed donor profile identifier when matched.
    pub profile_id: Option<String>,
    /// Independently projected evidence freshness.
    pub freshness: XrayEvidenceFreshness,
    /// Bundle-level donor write flag.
    pub bundle_write_allowed: bool,
    /// Certification-level donor write flag.
    pub certification_write_allowed: bool,
    /// Profile-level donor write flag.
    pub profile_write_allowed: bool,
    /// Publicly observable bundle-signature state.
    pub signature: XraySignatureObservation,
    /// Canonical evidence supporting the X-Ray projection.
    pub evidence_refs: Vec<EntityRef>,
    /// Canonical disagreement/challenge evidence retained without forced resolution.
    pub disagreement_refs: Vec<EntityRef>,
}

/// C09 correlation result. This is evidence state, not execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayEvidenceDisposition {
    /// Current single-device evidence correlates cleanly under the admitted profile.
    Correlated,
    /// Evidence is useful but stale, disputed, unmatched, or otherwise incomplete.
    Investigate,
    /// X-Ray retained unsafe or multi-device evidence.
    Unsafe,
}

/// The only authority result C09 can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayAuthority {
    /// X-Ray is admitted strictly as a read-only evidence workload.
    EvidenceOnlyReadOnly,
}

/// Inputs required to admit the pinned TTG Device X-Ray workload.
#[derive(Debug)]
pub struct XrayAdmissionRequest<'a> {
    /// Exact donor source lock.
    pub source: &'a XraySourceLock,
    /// Exact public donor profile and fixture object identities.
    pub public_assets: &'a [XrayPublicAssetEvidence],
    /// Current C08 Device Interface.
    pub current_interface: &'a DeviceInterfaceRecord,
    /// Already-admitted C08 read-only protocol operations supporting this scan.
    pub c08_operations: &'a [AdmittedProtocolOperation],
    /// Sealed X-Ray evidence summary.
    pub evidence: &'a XrayEvidenceSummary,
}

/// Admitted read-only C09 workload projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedXrayWorkload {
    /// Exact admitted donor commit.
    pub source_commit_sha: String,
    /// Exact admitted donor scanner version.
    pub scanner_version: String,
    /// Current stable Ptah Device.
    pub device_ref: EntityRef,
    /// Current C08 Interface.
    pub interface_ref: EntityRef,
    /// Current C08 Connection.
    pub connection_ref: EntityRef,
    /// Current C08 connection epoch.
    pub connection_epoch: u64,
    /// Current exact Device Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Current exact Device Provider generation.
    pub provider_generation: ProviderGeneration,
    /// Retained X-Ray evidence bundle.
    pub bundle_ref: EntityRef,
    /// Donor scan identifier.
    pub scan_id: String,
    /// Exact donor manifest digest.
    pub manifest_sha256: String,
    /// Evidence disposition.
    pub disposition: XrayEvidenceDisposition,
    /// Evidence freshness retained exactly.
    pub freshness: XrayEvidenceFreshness,
    /// Donor certification retained exactly.
    pub certification: XrayCertificationVerdict,
    /// Donor profile status retained exactly.
    pub profile_status: XrayProfileStatus,
    /// Donor profile identifier, when present.
    pub profile_id: Option<String>,
    /// Signature observation without private-key verification.
    pub signature: XraySignatureObservation,
    /// Supporting C08 protocol operation references.
    pub c08_protocol_operation_refs: Vec<EntityRef>,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Disagreement evidence remains visible.
    pub disagreement_refs: Vec<EntityRef>,
    /// Explicit non-mutation authority.
    pub authority: XrayAuthority,
}

/// Admit the exact pinned TTG Device X-Ray revision as a C09 read-only evidence workload.
///
/// This function does not launch a process, send a Device command, verify a private
/// signing key, select a recovery/flashing adapter, or create Mutation Authorization.
///
/// # Errors
/// Fails closed when donor/source/profile/fixture identity drifts, donor evidence
/// claims write authority, candidate truth is inconsistent, the manifest digest is
/// malformed, or supporting C08 operations are absent/stale/mismatched.
pub fn admit_xray_workload(
    request: XrayAdmissionRequest<'_>,
) -> Result<AdmittedXrayWorkload, XrayAdmissionError> {
    request.source.validate()?;
    validate_public_assets(request.public_assets)?;
    validate_evidence(request.evidence)?;

    if request.c08_operations.is_empty() {
        return Err(XrayAdmissionError::MissingC08Operation);
    }

    for operation in request.c08_operations {
        if operation.authority != OperationAuthority::ReadOnly
            || !operation.mutation_class.is_c08_read_only()
            || operation.device_ref != request.current_interface.device_ref
            || operation.interface_ref != request.current_interface.interface_ref
            || operation.connection_ref != request.current_interface.connection_ref
            || operation.connection_epoch != request.current_interface.connection_epoch
            || operation.provider_instance_ref != request.current_interface.provider_instance_ref
            || operation.provider_generation != request.current_interface.provider_generation
        {
            return Err(XrayAdmissionError::C08ContextMismatch);
        }
    }

    let disposition = if request.evidence.candidate_count > 1
        || request.evidence.certification == XrayCertificationVerdict::Unsafe
    {
        XrayEvidenceDisposition::Unsafe
    } else if request.evidence.freshness != XrayEvidenceFreshness::Current
        || !request.evidence.disagreement_refs.is_empty()
        || request.evidence.certification == XrayCertificationVerdict::Investigate
        || request.evidence.profile_status != XrayProfileStatus::Matched
    {
        XrayEvidenceDisposition::Investigate
    } else {
        XrayEvidenceDisposition::Correlated
    };

    Ok(AdmittedXrayWorkload {
        source_commit_sha: request.source.commit_sha.clone(),
        scanner_version: request.source.scanner_version.clone(),
        device_ref: request.current_interface.device_ref.clone(),
        interface_ref: request.current_interface.interface_ref.clone(),
        connection_ref: request.current_interface.connection_ref.clone(),
        connection_epoch: request.current_interface.connection_epoch,
        provider_instance_ref: request.current_interface.provider_instance_ref.clone(),
        provider_generation: request.current_interface.provider_generation,
        bundle_ref: request.evidence.bundle_ref.clone(),
        scan_id: request.evidence.scan_id.clone(),
        manifest_sha256: request.evidence.manifest_sha256.clone(),
        disposition,
        freshness: request.evidence.freshness,
        certification: request.evidence.certification,
        profile_status: request.evidence.profile_status,
        profile_id: request.evidence.profile_id.clone(),
        signature: request.evidence.signature,
        c08_protocol_operation_refs: request
            .c08_operations
            .iter()
            .map(|operation| operation.protocol_operation_ref.clone())
            .collect(),
        evidence_refs: request.evidence.evidence_refs.clone(),
        disagreement_refs: request.evidence.disagreement_refs.clone(),
        authority: XrayAuthority::EvidenceOnlyReadOnly,
    })
}

fn validate_public_assets(observed: &[XrayPublicAssetEvidence]) -> Result<(), XrayAdmissionError> {
    if observed.len() != FROZEN_PUBLIC_ASSETS.len() {
        return Err(XrayAdmissionError::PublicAssetLockMismatch);
    }

    let mut unique = BTreeSet::new();
    let mut observed_by_path = BTreeMap::new();
    for asset in observed {
        if !unique.insert(asset.path.as_str()) {
            return Err(XrayAdmissionError::DuplicatePublicAsset);
        }
        observed_by_path.insert(
            asset.path.as_str(),
            (asset.git_blob_sha1.as_str(), asset.kind),
        );
    }

    for (path, expected_sha, expected_kind) in FROZEN_PUBLIC_ASSETS {
        match observed_by_path.get(path) {
            Some((observed_sha, observed_kind))
                if *observed_sha == *expected_sha && *observed_kind == *expected_kind => {}
            _ => return Err(XrayAdmissionError::PublicAssetLockMismatch),
        }
    }
    Ok(())
}

fn validate_evidence(evidence: &XrayEvidenceSummary) -> Result<(), XrayAdmissionError> {
    if evidence.bundle_ref.entity_kind.as_str() != "object.artifact"
        || evidence.scan_id.trim().is_empty()
        || evidence.evidence_refs.is_empty()
    {
        return Err(XrayAdmissionError::MissingEvidence);
    }
    if !is_lower_hex_digest(&evidence.manifest_sha256, 64) {
        return Err(XrayAdmissionError::InvalidManifestDigest);
    }
    if evidence.candidate_count == 0 {
        return Err(XrayAdmissionError::CandidateSelectionMismatch);
    }
    if evidence.candidate_count == 1 {
        match evidence.selected_candidate_id.as_deref() {
            Some(candidate) if !candidate.trim().is_empty() => {}
            _ => return Err(XrayAdmissionError::CandidateSelectionMismatch),
        }
    } else if evidence.selected_candidate_id.is_some() {
        return Err(XrayAdmissionError::CandidateSelectionMismatch);
    }

    if evidence.bundle_write_allowed
        || evidence.certification_write_allowed
        || evidence.profile_write_allowed
    {
        return Err(XrayAdmissionError::WriteAuthorityClaim);
    }

    match evidence.profile_status {
        XrayProfileStatus::Matched
        | XrayProfileStatus::Candidate
        | XrayProfileStatus::CandidateProfile => match evidence.profile_id.as_deref() {
            Some(profile) if !profile.trim().is_empty() => {}
            _ => return Err(XrayAdmissionError::MissingEvidence),
        },
        XrayProfileStatus::NoMatch
        | XrayProfileStatus::NoProfile
        | XrayProfileStatus::NoSelection => {
            if evidence.profile_id.is_some() {
                return Err(XrayAdmissionError::MissingEvidence);
            }
        }
    }

    Ok(())
}

fn is_lower_hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
