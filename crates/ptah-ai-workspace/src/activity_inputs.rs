//! Exact caller-admitted D02 Activity input and Grant envelope.

use crate::D02Error;
use ptah_identifiers::EntityRef;

/// Exact immutable inputs admitted for one caller-submitted D02 invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityInputEnvelope {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Exact caller request identity.
    pub request_ref: EntityRef,
    /// Exact Object/Artifact/Revision references admitted as inputs.
    pub input_refs: Vec<EntityRef>,
    /// Exact Provider references selected by the caller where applicable.
    pub provider_refs: Vec<EntityRef>,
    /// Exact Facility references selected by the caller where applicable.
    pub facility_refs: Vec<EntityRef>,
    /// Exact configured Grant references admitted for this invocation.
    pub grant_refs: Vec<EntityRef>,
    /// Optional caller-supplied schedule identity; presence does not widen authority.
    pub schedule_ref: Option<EntityRef>,
}

impl ActivityInputEnvelope {
    /// Prove an input was explicitly declared for this invocation.
    ///
    /// # Errors
    /// Returns [`D02Error::InputNotDeclared`] for any unlisted exact reference.
    pub fn ensure_declared_input(&self, requested: &EntityRef) -> Result<(), D02Error> {
        if self.input_refs.iter().any(|item| item == requested) {
            Ok(())
        } else {
            Err(D02Error::InputNotDeclared)
        }
    }

    /// Prove an optional Grant was explicitly declared for this invocation.
    ///
    /// `None` means the caller is not presenting a Grant at this boundary.
    ///
    /// # Errors
    /// Returns [`D02Error::GrantNotDeclared`] for an unlisted Grant.
    pub fn ensure_declared_grant(&self, grant: Option<&EntityRef>) -> Result<(), D02Error> {
        match grant {
            None => Ok(()),
            Some(grant) if self.grant_refs.iter().any(|item| item == grant) => Ok(()),
            Some(_) => Err(D02Error::GrantNotDeclared),
        }
    }
}
