#![forbid(unsafe_code)]
#![doc = "D05 package and Plugin lifecycle composition."]

mod admission;
mod error;
mod package;

pub use admission::{
    AdmissionService, DistributionClass, LicenceDecision, PackageAdmission, PackageAdmissionRequest,
};
pub use error::D05Error;
pub use package::{
    PackageCandidate, PackageCatalog, PackageConstraint, PackageCoordinate, PackageLock,
    RegistrySource, ResolvedGraph,
};
