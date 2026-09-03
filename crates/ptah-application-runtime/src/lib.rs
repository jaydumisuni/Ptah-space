#![forbid(unsafe_code)]
//! D08 Application platform expansion composition boundary.
//!
//! D08 composes existing Ptah Application, Process, Device and human-shell contracts. It does not
//! manufacture remote Node authority, reinterpret static package analysis as execution success, or
//! replace the lower-level Providers that own mechanical execution.

mod compatibility;
mod error;

pub use compatibility::{
    ApplicationOperation, CompatibilityDecision, CompatibilityRequirement, ExecutionDisposition,
    NodeLocalCompatibility, PlatformClass, RemoteNodeRequirement, RequirementOutcome,
};
pub use error::D08Error;

/// Frozen Application schema identifier.
pub const APPLICATION_SCHEMA_ID: &str = "urn:ptah:schema:application:application:0.1.0";
/// Frozen Application Revision schema identifier.
pub const APPLICATION_REVISION_SCHEMA_ID: &str =
    "urn:ptah:schema:application:application-revision:0.1.0";
/// Frozen Application Compatibility schema identifier.
pub const APPLICATION_COMPATIBILITY_SCHEMA_ID: &str =
    "urn:ptah:schema:application:application-compatibility:0.1.0";
/// Frozen Application Session schema identifier.
pub const APPLICATION_SESSION_SCHEMA_ID: &str =
    "urn:ptah:schema:application:application-session:0.1.0";
/// Frozen Application Window schema identifier.
pub const APPLICATION_WINDOW_SCHEMA_ID: &str =
    "urn:ptah:schema:application:application-window:0.1.0";
/// Frozen Application Window Observation schema identifier.
pub const APPLICATION_WINDOW_OBSERVATION_SCHEMA_ID: &str =
    "urn:ptah:schema:application:application-window-observation:0.1.0";
/// Frozen Display Session schema identifier.
pub const DISPLAY_SESSION_SCHEMA_ID: &str = "urn:ptah:schema:application:display-session:0.1.0";
/// Frozen Display Observation schema identifier.
pub const DISPLAY_OBSERVATION_SCHEMA_ID: &str =
    "urn:ptah:schema:application:display-observation:0.1.0";
/// Frozen Application Session lifecycle-machine name.
pub const APPLICATION_SESSION_LIFECYCLE: &str = "application.session.lifecycle";
/// Frozen Application Window lifecycle-machine name.
pub const APPLICATION_WINDOW_LIFECYCLE: &str = "application.window.lifecycle";
/// Frozen Display Session lifecycle-machine name.
pub const DISPLAY_SESSION_LIFECYCLE: &str = "application.display_session.lifecycle";
