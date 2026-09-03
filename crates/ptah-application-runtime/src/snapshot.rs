//! D08 read-only snapshots consumed by human-facing projections.

use crate::{
    ApplicationSessionProjection, DisplaySessionProjection, PlatformClass, RemoteNodeRequirement,
};
use ptah_identifiers::EntityRef;

/// Validated D08 backing state that may be projected into a human shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationPlatformSnapshot {
    /// One already-validated Application Session with optional validated Display Session evidence.
    Session {
        /// Roadmap platform class represented by the session.
        platform: PlatformClass,
        /// Validated D08 Application Session projection.
        session: ApplicationSessionProjection,
        /// Optional validated Display Session associated with the Application Session.
        display: Option<DisplaySessionProjection>,
    },
    /// An exact Application Revision that remains blocked on Programme E remote-Node authority.
    RemoteRequirement {
        /// Stable Application identity.
        application_ref: EntityRef,
        /// Exact Application Revision.
        application_revision_ref: EntityRef,
        /// Mechanical remote-Node requirement retained without synthetic runtime state.
        requirement: RemoteNodeRequirement,
    },
}
