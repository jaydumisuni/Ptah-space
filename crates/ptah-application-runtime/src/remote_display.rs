//! D08 non-executing remote-display dependency gate.

use crate::{ApplicationOperation, D08Error, RemoteNodeRequirement};

/// Retain an exact remote-display blocker without manufacturing remote runtime authority.
///
/// This function deliberately returns only the validated requirement. It cannot create an
/// Application Session, Display Session, transport, VM, simulator, or remote service.
///
/// # Errors
/// Returns [`D08Error`] when the requirement is not for remote display or omits the exact
/// Programme E dependency/evidence needed to explain the blocker.
pub fn require_remote_display(
    requirement: &RemoteNodeRequirement,
) -> Result<RemoteNodeRequirement, D08Error> {
    if requirement.operation != ApplicationOperation::RemoteDisplay {
        return Err(D08Error::CompatibilityOperationMismatch);
    }
    if requirement.roadmap_dependency != "Programme E"
        || requirement.required_execution_class.trim().is_empty()
        || requirement.required_capabilities.is_empty()
        || requirement.evidence_refs.is_empty()
    {
        return Err(D08Error::RemoteNodeRequired);
    }
    Ok(requirement.clone())
}
