#![forbid(unsafe_code)]
#![doc = "D05 package and Plugin lifecycle composition."]

mod activation;
mod admission;
mod error;
mod install;
mod package;
mod plugin;
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
