use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

use crate::D06Error;

/// Exact immutable proof subject plus caller-visible aliases kept outside identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactSubject {
    /// Canonical immutable Ptah subject identity.
    pub subject_ref: EntityRef,
    /// Exact digest-bearing evidence references for the subject.
    pub digest_refs: Vec<EntityRef>,
    /// Mutable/display aliases retained as evidence only.
    pub aliases: Vec<String>,
}

impl ExactSubject {
    /// Validate that the subject is revision/run/artifact scoped and digest-bound.
    ///
    /// # Errors
    /// Returns [`D06Error::InexactSubject`] for mutable/non-exact subject kinds or missing digest refs.
    pub fn validate(&self) -> Result<(), D06Error> {
        if self.digest_refs.is_empty() || !exact_subject_kind(self.subject_ref.entity_kind.as_str())
        {
            return Err(D06Error::InexactSubject);
        }
        Ok(())
    }
}

fn exact_subject_kind(kind: &str) -> bool {
    kind.ends_with(".revision")
        || kind.ends_with("_revision")
        || kind.ends_with(".artifact")
        || matches!(
            kind,
            "build.run"
                | "build.output_record"
                | "package.installation"
                | "plugin.installation"
                | "plugin.instance"
                | "proof.reproduction_run"
                | "proof.comparison"
        )
}
