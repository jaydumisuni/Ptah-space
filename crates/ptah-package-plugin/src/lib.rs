#![forbid(unsafe_code)]
#![doc = "D05 package and Plugin lifecycle composition."]

mod error;
mod package;

pub use error::D05Error;
pub use package::{
    PackageCandidate, PackageCatalog, PackageConstraint, PackageCoordinate, PackageLock,
    RegistrySource, ResolvedGraph,
};
