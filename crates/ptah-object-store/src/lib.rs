#![forbid(unsafe_code)]
//! A07 durable Object/CAS materialization and integrity projection.
//!
//! A07 keeps logical Object identity, immutable Object Revisions, exact Content
//! identity, physical Storage Locations and verification evidence separate. The
//! A03 ledger remains canonical metadata truth; local CAS paths are backend
//! aliases only and never become Ptah identity.

use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

mod documents_entities;
mod documents_model;
mod documents_support;
mod model;
mod store_backend;
mod store_projection;
mod store_registration;

pub use model::*;

#[cfg(test)]
mod tests;
