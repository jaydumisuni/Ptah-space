use std::path::Path;

use ptah_identifiers::EntityRef;
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{D05Error, InstallRequest, PackageInstallHandle};

const INSTALL_SCHEMA: &str = "urn:ptah:schema:knowledge:package-installation:0.1.0";
const VERIFY_SCHEMA: &str = "urn:ptah:schema:knowledge:package-verification:0.1.0";

const PACKAGE_CATALOG_SCHEMAS: &[(&str, &str)] = &[
    ("urn:ptah:schema:knowledge:package:0.1.0", "package.package"),
    (
        "urn:ptah:schema:knowledge:package-revision:0.1.0",
        "package.revision",
    ),
    (
        "urn:ptah:schema:knowledge:package-manifest:0.1.0",
        "package.manifest",
    ),
    (
        "urn:ptah:schema:knowledge:package-dependency-constraint:0.1.0",
        "package.dependency_constraint",
    ),
    (
        "urn:ptah:schema:knowledge:package-resolved-graph:0.1.0",
        "package.resolved_graph",
    ),
    (
        "urn:ptah:schema:knowledge:package-lock-record:0.1.0",
        "package.lock_record",
    ),
    (
        "urn:ptah:schema:knowledge:package-registry-source:0.1.0",
        "package.registry_source",
    ),
];

/// Independent package-verification scope from frozen WP10.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationScope {
    /// Content/integrity verification.
    Integrity,
    /// Source verification.
    Source,
    /// Provenance verification.
    Provenance,
    /// Dependency-graph verification.
    DependencyGraph,
    /// Lock-consistency verification.
    LockConsistency,
    /// Installed-state readback verification.
    InstalledState,
    /// Policy verification.
    Policy,
    /// Functional verification.
    Functionality,
}

impl VerificationScope {
    const fn text(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Source => "source",
            Self::Provenance => "provenance",
            Self::DependencyGraph => "dependency_graph",
            Self::LockConsistency => "lock_consistency",
            Self::InstalledState => "installed_state",
            Self::Policy => "policy",
            Self::Functionality => "functionality",
        }
    }
}

/// Frozen package verification decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationDecision {
    /// Verification passed completely for the declared scopes.
    Verified,
    /// Verification passed with retained limitations.
    VerifiedWithLimitations,
    /// Verification failed.
    Failed,
    /// Verification could not conclude.
    Inconclusive,
    /// Verification evidence is stale.
    Stale,
}

impl VerificationDecision {
    const fn text(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::VerifiedWithLimitations => "verified_with_limitations",
            Self::Failed => "failed",
            Self::Inconclusive => "inconclusive",
            Self::Stale => "stale",
        }
    }
}

/// Caller-supplied independent package verification evidence.
#[derive(Clone, Debug)]
pub struct PackageVerificationInput {
    /// Exact scopes independently checked.
    pub scopes: Vec<VerificationScope>,
    /// Stable check labels retained as evidence metadata.
    pub checks: Vec<String>,
    /// Verification decision.
    pub decision: VerificationDecision,
    /// Whether separate signature evidence was observed.
    pub signature_verified: bool,
    /// Verification timestamp.
    pub verified_at: String,
    /// Supporting evidence refs.
    pub evidence_refs: Vec<EntityRef>,
    /// Supporting receipt refs.
    pub receipt_refs: Vec<EntityRef>,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

impl PackageVerificationInput {
    /// Whether this independent verification explicitly includes functionality.
    #[must_use]
    pub fn proves_functionality(&self) -> bool {
        self.scopes.contains(&VerificationScope::Functionality)
            && matches!(
                self.decision,
                VerificationDecision::Verified | VerificationDecision::VerifiedWithLimitations
            )
    }

    fn proves_installed_verified(&self) -> bool {
        matches!(self.decision, VerificationDecision::Verified)
            && self.scopes.contains(&VerificationScope::Integrity)
            && self.scopes.contains(&VerificationScope::InstalledState)
    }
}

/// A03-backed canonical package lifecycle store.
pub struct PackageStore {
    ledger: Ledger,
}

impl PackageStore {
    /// Open or create the canonical A03 ledger.
    ///
    /// # Errors
    /// Returns [`D05Error`] when the A03 ledger cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, D05Error> {
        Ok(Self {
            ledger: Ledger::open(path).map_err(ledger_error)?,
        })
    }

    /// Persist an A04-bound installation as `installed_unverified`.
    ///
    /// # Errors
    /// Returns [`D05Error`] when bindings are inconsistent or A03 rejects the record.
    pub fn record_installation(
        &mut self,
        handle: &PackageInstallHandle,
        request: &InstallRequest,
    ) -> Result<(), D05Error> {
        if handle.package_ref != request.package_ref
            || handle.package_revision_ref != request.package_revision_ref
            || handle.provider_instance_ref != request.provider_instance_ref
            || handle.provider_generation != request.provider_generation
            || request.installed_object_refs.is_empty()
        {
            return Err(D05Error::InvalidLifecycleRecord);
        }
        let activity_ref =
            EntityRef::from_id(handle.activity_id, "core.activity").map_err(identifier_error)?;
        let operation_ref =
            EntityRef::from_id(handle.operation_id, "core.operation").map_err(identifier_error)?;
        let attempt_ref =
            EntityRef::from_id(handle.attempt_id, "core.attempt").map_err(identifier_error)?;
        let record = canonical(json!({
            "envelope": envelope(&handle.installation_ref, INSTALL_SCHEMA, 1, &request.authority_ref),
            "lifecycle": lifecycle("installed_unverified", 1, &handle.ack.accepted_at),
            "package_ref": request.package_ref,
            "package_revision_ref": request.package_revision_ref,
            "resolved_graph_ref": request.resolved_graph_ref,
            "lock_record_ref": request.lock_record_ref,
            "workspace_ref": request.workspace_ref,
            "provider_instance_ref": request.provider_instance_ref,
            "provider_generation": request.provider_generation,
            "activity_ref": activity_ref,
            "operation_ref": operation_ref,
            "attempt_ref": attempt_ref,
            "installed_object_refs": request.installed_object_refs,
            "verification_refs": [],
            "started_at": handle.ack.accepted_at,
            "extensions": {
                "ptah.d05.install_ack": {
                    "backend_alias": handle.ack.backend_alias,
                    "evidence_refs": handle.ack.evidence_refs
                }
            }
        }))?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&record).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)
    }

    /// Persist independent verification and advance installation state only when required scopes pass.
    ///
    /// # Errors
    /// Returns [`D05Error`] when verification is incomplete, bindings are absent, or A03 rejects persistence.
    pub fn record_verification(
        &mut self,
        handle: &PackageInstallHandle,
        input: &PackageVerificationInput,
    ) -> Result<EntityRef, D05Error> {
        if input.scopes.is_empty() || input.checks.is_empty() || input.evidence_refs.is_empty() {
            return Err(D05Error::VerificationIncomplete);
        }
        let current = self
            .ledger
            .latest_record(handle.installation_ref.entity_id)
            .map_err(ledger_error)?
            .ok_or(D05Error::InvalidLifecycleRecord)?;
        if current.entity_kind().as_str() != "package.installation" {
            return Err(D05Error::InvalidLifecycleRecord);
        }
        let verification_ref = EntityRef::new("package.verification").map_err(identifier_error)?;
        let checks = input
            .checks
            .iter()
            .map(|name| json!({"check": name}))
            .collect::<Vec<_>>();
        let verification = canonical(json!({
            "envelope": envelope(&verification_ref, VERIFY_SCHEMA, 1, current.authority_ref()),
            "package_revision_ref": handle.package_revision_ref,
            "installation_ref": handle.installation_ref,
            "verification_scope": input.scopes.iter().map(|scope| scope.text()).collect::<Vec<_>>(),
            "checks": checks,
            "decision": input.decision.text(),
            "verified_at": input.verified_at,
            "evidence_refs": input.evidence_refs,
            "receipt_refs": input.receipt_refs,
            "limitations": input.limitations,
            "extensions": {"ptah.d05.signature_verified": input.signature_verified}
        }))?;
        let mut updated = current.document().clone();
        let next_revision = current
            .record_revision()
            .value()
            .checked_add(1)
            .ok_or(D05Error::InvalidLifecycleRecord)?;
        update_envelope_revision(&mut updated, next_revision)?;
        let refs = updated
            .get_mut("verification_refs")
            .and_then(Value::as_array_mut)
            .ok_or(D05Error::InvalidLifecycleRecord)?;
        refs.push(serde_json::to_value(&verification_ref).map_err(json_error)?);
        if input.proves_installed_verified() {
            updated["lifecycle"] = lifecycle("installed_verified", 2, &input.verified_at);
            updated["ended_at"] = json!(input.verified_at);
        } else if matches!(
            input.decision,
            VerificationDecision::VerifiedWithLimitations
        ) {
            updated["lifecycle"] = lifecycle("installed_with_limitations", 2, &input.verified_at);
            updated["ended_at"] = json!(input.verified_at);
        }
        let updated = canonical(updated)?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&verification).map_err(ledger_error)?;
        write.insert(&updated).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)?;
        Ok(verification_ref)
    }

    /// Persist one complete frozen WP10 package-catalog document through A03.
    ///
    /// The method is intentionally bounded to the seven D05 package catalog schema/kind pairs;
    /// A03 performs the complete frozen-schema validation before storage.
    ///
    /// # Errors
    /// Returns [`D05Error`] for any non-D05 schema/kind pair or invalid canonical document.
    pub fn record_catalog_document(&mut self, document: Value) -> Result<EntityRef, D05Error> {
        let record = canonical(document)?;
        let allowed = PACKAGE_CATALOG_SCHEMAS.iter().any(|(schema, kind)| {
            record.schema_id() == *schema && record.entity_kind().as_str() == *kind
        });
        if !allowed {
            return Err(D05Error::InvalidLifecycleRecord);
        }
        let entity_ref = EntityRef::from_id(record.entity_id(), record.entity_kind().as_str())
            .map_err(identifier_error)?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&record).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)?;
        Ok(entity_ref)
    }

    /// Read the current canonical installation lifecycle state.
    ///
    /// # Errors
    /// Returns [`D05Error`] when the installation is absent or malformed.
    pub fn installation_state(&self, installation_ref: &EntityRef) -> Result<String, D05Error> {
        let record = self
            .ledger
            .latest_record(installation_ref.entity_id)
            .map_err(ledger_error)?
            .ok_or(D05Error::InvalidLifecycleRecord)?;
        record
            .document()
            .pointer("/lifecycle/current_state")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(D05Error::InvalidLifecycleRecord)
    }
}

fn envelope(
    entity_ref: &EntityRef,
    schema_id: &str,
    revision: u64,
    authority_ref: &EntityRef,
) -> Value {
    json!({
        "entity_id": entity_ref.entity_id,
        "entity_kind": entity_ref.entity_kind,
        "schema_id": schema_id,
        "schema_version": "0.1.0",
        "record_revision": revision,
        "authority_ref": authority_ref,
    })
}

fn lifecycle(state: &str, sequence: u64, entered_at: &str) -> Value {
    json!({
        "state_machine_name": "package.installation.lifecycle",
        "state_machine_version": "0.1.0",
        "current_state": state,
        "state_sequence": sequence,
        "entered_at": entered_at,
        "transition_receipt_refs": [],
    })
}

fn canonical(document: Value) -> Result<CanonicalRecord, D05Error> {
    CanonicalRecord::from_document(document).map_err(ledger_error)
}

fn update_envelope_revision(document: &mut Value, revision: u64) -> Result<(), D05Error> {
    let envelope = document
        .get_mut("envelope")
        .and_then(Value::as_object_mut)
        .ok_or(D05Error::InvalidLifecycleRecord)?;
    envelope.insert("record_revision".into(), json!(revision));
    Ok(())
}

fn ledger_error(error: impl std::fmt::Display) -> D05Error {
    D05Error::Ledger(error.to_string())
}

fn identifier_error(_error: impl std::fmt::Display) -> D05Error {
    D05Error::InvalidLifecycleRecord
}

fn json_error(error: impl std::fmt::Display) -> D05Error {
    D05Error::Ledger(error.to_string())
}
