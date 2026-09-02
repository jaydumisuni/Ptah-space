use std::path::Path;

use ptah_identifiers::EntityRef;
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use serde_json::{Value, json};

use crate::{ActivationRequest, D05Error, PluginRevisionInput};

const PLUGIN_SCHEMA: &str = "urn:ptah:schema:knowledge:plugin:0.1.0";
const REVISION_SCHEMA: &str = "urn:ptah:schema:knowledge:plugin-revision:0.1.0";
const COMPAT_SCHEMA: &str = "urn:ptah:schema:knowledge:plugin-compatibility:0.1.0";
const INSTALL_SCHEMA: &str = "urn:ptah:schema:knowledge:plugin-installation:0.1.0";
const ACTIVATE_SCHEMA: &str = "urn:ptah:schema:knowledge:plugin-activation:0.1.0";

const PLUGIN_RUNTIME_SCHEMAS: &[(&str, &str)] = &[
    (
        "urn:ptah:schema:knowledge:plugin-instance:0.1.0",
        "plugin.instance",
    ),
    (
        "urn:ptah:schema:knowledge:plugin-health-observation:0.1.0",
        "plugin.health_observation",
    ),
    (
        "urn:ptah:schema:knowledge:plugin-capability-grant:0.1.0",
        "plugin.capability_grant",
    ),
    (
        "urn:ptah:schema:knowledge:plugin-dependency-binding:0.1.0",
        "plugin.dependency_binding",
    ),
    (
        "urn:ptah:schema:knowledge:plugin-service-registration:0.1.0",
        "plugin.service_registration",
    ),
    (
        "urn:ptah:schema:knowledge:plugin-port-registration:0.1.0",
        "plugin.port_registration",
    ),
    (
        "urn:ptah:schema:knowledge:plugin-update-decision:0.1.0",
        "plugin.update_decision",
    ),
    (
        "urn:ptah:schema:knowledge:plugin-rollback:0.1.0",
        "plugin.rollback",
    ),
    (
        "urn:ptah:schema:knowledge:plugin-removal:0.1.0",
        "plugin.removal",
    ),
];

/// Stable logical Plugin metadata supplied by the caller.
#[derive(Clone, Debug)]
pub struct PluginIdentityInput {
    /// Stable namespaced Plugin key.
    pub plugin_key: String,
    /// Human-readable name.
    pub name: String,
    /// Exact authority reference retained by A03.
    pub authority_ref: EntityRef,
    /// Exact creation timestamp.
    pub created_at: String,
}

/// Exact-context compatibility observation for one Plugin Revision.
#[derive(Clone, Debug)]
pub struct PluginCompatibilityInput {
    /// Provider/platform context retained as neutral structured data.
    pub target_context: Value,
    /// Required capability names.
    pub required_capabilities: Vec<String>,
    /// Frozen WP10 compatibility decision.
    pub decision: String,
    /// Exact check timestamp.
    pub checked_at: String,
    /// Exact expiry timestamp.
    pub valid_until: String,
    /// Supporting evidence refs.
    pub evidence_refs: Vec<EntityRef>,
}

/// Exact canonical Plugin Installation input.
#[derive(Clone, Debug)]
pub struct PluginInstallationInput {
    /// Stable logical Plugin.
    pub plugin_ref: EntityRef,
    /// Exact immutable Plugin Revision.
    pub plugin_revision_ref: EntityRef,
    /// Exact compatibility observation.
    pub compatibility_ref: EntityRef,
    /// Exact Package Installation refs.
    pub package_installation_refs: Vec<EntityRef>,
    /// Target Workspace.
    pub workspace_ref: EntityRef,
    /// Exact Provider Instance.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation.
    pub provider_generation: u64,
    /// Exact A04 Activity.
    pub activity_ref: EntityRef,
    /// Exact A04 Operation.
    pub operation_ref: EntityRef,
    /// Exact A04 Attempt.
    pub attempt_ref: EntityRef,
    /// Independent verification refs, if already present.
    pub verification_refs: Vec<EntityRef>,
    /// Installation start timestamp.
    pub started_at: String,
    /// Exact authority ref.
    pub authority_ref: EntityRef,
}

/// A03-backed canonical WP10 Plugin persistence facade.
pub struct PluginStore {
    ledger: Ledger,
}

impl PluginStore {
    /// Open or create the canonical A03 ledger.
    ///
    /// # Errors
    /// Returns [`D05Error`] when A03 cannot open the ledger.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, D05Error> {
        Ok(Self {
            ledger: Ledger::open(path).map_err(ledger_error)?,
        })
    }

    /// Atomically create one stable Plugin and first immutable Revision.
    ///
    /// # Errors
    /// Returns [`D05Error`] for invalid exact bindings or A03 persistence failure.
    pub fn create_plugin_with_revision(
        &mut self,
        plugin: &PluginIdentityInput,
        revision: &PluginRevisionInput,
    ) -> Result<(EntityRef, EntityRef), D05Error> {
        revision.validate_exact()?;
        if plugin.plugin_key.trim().is_empty()
            || plugin.name.trim().is_empty()
            || plugin.created_at.trim().is_empty()
        {
            return Err(D05Error::InvalidLifecycleRecord);
        }
        let plugin_ref = EntityRef::new("plugin.plugin").map_err(identifier_error)?;
        let revision_ref = EntityRef::new("plugin.revision").map_err(identifier_error)?;
        let revision_record = canonical(json!({
            "envelope": envelope(&revision_ref, REVISION_SCHEMA, 1, &plugin.authority_ref),
            "plugin_ref": plugin_ref,
            "revision": revision.revision,
            "object_revision_refs": revision.object_revision_refs,
            "manifest_ref": revision.manifest_ref,
            "package_lock_refs": revision.package_lock_refs,
            "created_at": revision.created_at,
            "extensions": {}
        }))?;
        let plugin_record = canonical(json!({
            "envelope": envelope(&plugin_ref, PLUGIN_SCHEMA, 1, &plugin.authority_ref),
            "lifecycle": lifecycle("plugin.lifecycle", "active", 1, &plugin.created_at),
            "plugin_key": plugin.plugin_key,
            "name": plugin.name,
            "current_revision_ref": revision_ref,
            "revision_refs": [revision_ref],
            "created_at": plugin.created_at,
            "extensions": {}
        }))?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&revision_record).map_err(ledger_error)?;
        write.insert(&plugin_record).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)?;
        Ok((plugin_ref, revision_ref))
    }

    /// Persist one exact expiring compatibility observation.
    ///
    /// # Errors
    /// Returns [`D05Error`] for unsupported/malformed decision evidence or A03 failure.
    pub fn record_compatibility(
        &mut self,
        plugin_revision_ref: &EntityRef,
        authority_ref: &EntityRef,
        input: &PluginCompatibilityInput,
    ) -> Result<EntityRef, D05Error> {
        const DECISIONS: &[&str] = &[
            "compatible",
            "compatible_with_conditions",
            "partial",
            "incompatible",
            "unsupported",
            "unknown",
            "stale",
        ];
        if plugin_revision_ref.entity_kind != "plugin.revision"
            || !DECISIONS.contains(&input.decision.as_str())
            || input.checked_at.trim().is_empty()
            || input.valid_until.trim().is_empty()
            || input.evidence_refs.is_empty()
        {
            return Err(D05Error::InvalidLifecycleRecord);
        }
        let compatibility_ref = EntityRef::new("plugin.compatibility").map_err(identifier_error)?;
        let record = canonical(json!({
            "envelope": envelope(&compatibility_ref, COMPAT_SCHEMA, 1, authority_ref),
            "plugin_revision_ref": plugin_revision_ref,
            "target_context": input.target_context,
            "required_capabilities": input.required_capabilities,
            "decision": input.decision,
            "checked_at": input.checked_at,
            "valid_until": input.valid_until,
            "evidence_refs": input.evidence_refs,
            "extensions": {}
        }))?;
        insert_one(&mut self.ledger, &record)?;
        Ok(compatibility_ref)
    }

    /// Persist a Plugin Installation separately from Activation.
    ///
    /// # Errors
    /// Returns [`D05Error`] when exact bindings are invalid or A03 rejects persistence.
    pub fn record_installation(
        &mut self,
        input: &PluginInstallationInput,
    ) -> Result<EntityRef, D05Error> {
        if input.plugin_ref.entity_kind != "plugin.plugin"
            || input.plugin_revision_ref.entity_kind != "plugin.revision"
            || input.compatibility_ref.entity_kind != "plugin.compatibility"
            || input.package_installation_refs.is_empty()
            || input
                .package_installation_refs
                .iter()
                .any(|value| value.entity_kind != "package.installation")
            || input.workspace_ref.entity_kind != "core.workspace"
            || input.provider_instance_ref.entity_kind != "runtime.provider_instance"
            || input.provider_generation == 0
            || input.activity_ref.entity_kind != "core.activity"
            || input.operation_ref.entity_kind != "core.operation"
            || input.attempt_ref.entity_kind != "core.attempt"
        {
            return Err(D05Error::InvalidLifecycleRecord);
        }
        let installation_ref = EntityRef::new("plugin.installation").map_err(identifier_error)?;
        let record = canonical(json!({
            "envelope": envelope(&installation_ref, INSTALL_SCHEMA, 1, &input.authority_ref),
            "lifecycle": lifecycle("plugin.installation.lifecycle", "installed_unverified", 1, &input.started_at),
            "plugin_ref": input.plugin_ref,
            "plugin_revision_ref": input.plugin_revision_ref,
            "compatibility_ref": input.compatibility_ref,
            "package_installation_refs": input.package_installation_refs,
            "workspace_ref": input.workspace_ref,
            "provider_instance_ref": input.provider_instance_ref,
            "provider_generation": input.provider_generation,
            "activity_ref": input.activity_ref,
            "operation_ref": input.operation_ref,
            "attempt_ref": input.attempt_ref,
            "verification_refs": input.verification_refs,
            "started_at": input.started_at,
            "extensions": {}
        }))?;
        insert_one(&mut self.ledger, &record)?;
        Ok(installation_ref)
    }

    /// Persist an already-authorized Activation decision as its own canonical record.
    ///
    /// # Errors
    /// Returns [`D05Error`] when the request lacks exact policy/Grant identity or A03 rejects persistence.
    pub fn record_activation(
        &mut self,
        request: &ActivationRequest,
        authority_ref: &EntityRef,
    ) -> Result<EntityRef, D05Error> {
        let grant_ref = request
            .grant_ref
            .as_ref()
            .ok_or(D05Error::ActivationAuthorityMissing)?;
        if request.policy_refs.is_empty()
            || request.plugin_revision_ref.entity_kind != "plugin.revision"
            || request.installation_ref.entity_kind != "plugin.installation"
        {
            return Err(D05Error::ActivationAuthorityMissing);
        }
        let activation_ref = EntityRef::new("plugin.activation").map_err(identifier_error)?;
        let record = canonical(json!({
            "envelope": envelope(&activation_ref, ACTIVATE_SCHEMA, 1, authority_ref),
            "lifecycle": lifecycle("plugin.activation.lifecycle", "approved", 1, &request.decided_at),
            "plugin_revision_ref": request.plugin_revision_ref,
            "installation_ref": request.installation_ref,
            "workspace_ref": request.workspace_ref,
            "policy_refs": request.policy_refs,
            "grant_refs": [grant_ref],
            "decision": "approved",
            "decided_at": request.decided_at,
            "decided_by_ref": request.decided_by_ref,
            "extensions": {}
        }))?;
        insert_one(&mut self.ledger, &record)?;
        Ok(activation_ref)
    }

    /// Persist one complete frozen WP10 Plugin runtime/lifecycle document through A03.
    ///
    /// This is bounded to the nine D05 Plugin runtime/lifecycle schema/kind pairs; A03 performs
    /// complete frozen-schema validation, so D05 does not duplicate or weaken WP10 schemas.
    ///
    /// # Errors
    /// Returns [`D05Error`] for any non-D05 schema/kind pair or invalid canonical document.
    pub fn record_runtime_document(&mut self, document: Value) -> Result<EntityRef, D05Error> {
        let record = canonical(document)?;
        let allowed = PLUGIN_RUNTIME_SCHEMAS.iter().any(|(schema, kind)| {
            record.schema_id() == *schema && record.entity_kind().as_str() == *kind
        });
        if !allowed {
            return Err(D05Error::InvalidLifecycleRecord);
        }
        let entity_ref = EntityRef::from_id(record.entity_id(), record.entity_kind().as_str())
            .map_err(identifier_error)?;
        insert_one(&mut self.ledger, &record)?;
        Ok(entity_ref)
    }

    /// Read one exact canonical record document for inspection/projection.
    ///
    /// # Errors
    /// Returns [`D05Error`] when the record is absent or A03 read validation fails.
    pub fn record_document(&self, entity_ref: &EntityRef) -> Result<Value, D05Error> {
        self.ledger
            .latest_record(entity_ref.entity_id)
            .map_err(ledger_error)?
            .map(|record| record.document().clone())
            .ok_or(D05Error::InvalidLifecycleRecord)
    }
}

fn insert_one(ledger: &mut Ledger, record: &CanonicalRecord) -> Result<(), D05Error> {
    let write = ledger.begin_write().map_err(ledger_error)?;
    write.insert(record).map_err(ledger_error)?;
    write.commit().map_err(ledger_error)
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

fn lifecycle(machine: &str, state: &str, sequence: u64, entered_at: &str) -> Value {
    json!({
        "state_machine_name": machine,
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

fn ledger_error(error: impl std::fmt::Display) -> D05Error {
    D05Error::Ledger(error.to_string())
}

fn identifier_error(error: impl std::fmt::Display) -> D05Error {
    D05Error::Ledger(error.to_string())
}
