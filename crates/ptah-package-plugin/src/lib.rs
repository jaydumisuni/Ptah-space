#![forbid(unsafe_code)]
#![doc = "D05 package and Plugin lifecycle composition."]

mod activation;
mod admission;
mod change;
mod error;
mod install;
mod package;
mod plugin;
mod plugin_store;
mod runtime;
mod store;

pub use activation::{ActivationRequest, ActivationService};
pub use admission::{
    AdmissionService, DistributionClass, LicenceDecision, PackageAdmission, PackageAdmissionRequest,
};
pub use error::D05Error;
pub use install::{InstallRequest, PackageInstallAck, PackageInstallHandle, PackageInstaller};
pub use package::{
    PackageCandidate, PackageCatalog, PackageConstraint, PackageCoordinate, PackageLock,
    RegistrySource, ResolvedGraph,
};
pub use store::{PackageStore, PackageVerificationInput, VerificationDecision, VerificationScope};

pub use plugin::PluginRevisionInput;

pub use runtime::{
    CapabilityGrantState, DependencyBinding, HealthObservation, PluginInstanceRecord,
    PluginPortRegistration, PluginRuntime, PluginServiceRegistration,
};

pub use change::{
    PluginChangeEvidence, PluginChangeExecutor, PluginChangeHandle, PluginChangeKind,
    PluginChangeRequest, PluginUninstallAck, PluginUpdateDecision, RemovalProof, RemovalStage,
    UpdateDecision,
};

pub use plugin_store::{
    PluginCompatibilityInput, PluginIdentityInput, PluginInstallationInput, PluginStore,
};
