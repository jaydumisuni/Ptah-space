use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

use crate::D05Error;

/// Exact immutable Plugin Revision declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRevisionInput {
    /// Caller/plugin revision label retained as immutable metadata.
    pub revision: String,
    /// Exact retained Object Revisions comprising the Plugin Revision.
    pub object_revision_refs: Vec<EntityRef>,
    /// Exact frozen Plugin Manifest.
    pub manifest_ref: EntityRef,
    /// Exact package lock records required by this Plugin Revision.
    pub package_lock_refs: Vec<EntityRef>,
    /// Exact creation timestamp.
    pub created_at: String,
}

impl PluginRevisionInput {
    /// Validate the exact frozen WP10 identity boundaries.
    ///
    /// # Errors
    /// Returns [`D05Error::InvalidLifecycleRecord`] for missing or wrong-kind exact bindings.
    pub fn validate_exact(&self) -> Result<(), D05Error> {
        if self.revision.trim().is_empty()
            || self.object_revision_refs.is_empty()
            || self
                .object_revision_refs
                .iter()
                .any(|value| value.entity_kind != "core.object_revision")
            || self.manifest_ref.entity_kind != "plugin.manifest"
            || self.package_lock_refs.is_empty()
            || self
                .package_lock_refs
                .iter()
                .any(|value| value.entity_kind != "package.lock_record")
            || self.created_at.trim().is_empty()
        {
            return Err(D05Error::InvalidLifecycleRecord);
        }
        Ok(())
    }
}
