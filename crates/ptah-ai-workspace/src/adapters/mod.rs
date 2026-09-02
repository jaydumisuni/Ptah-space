//! D02 caller adapters. These remain application boundaries, not Ptah authorities.

mod hunter;
mod sergeant;

pub use hunter::HunterAdapter;
pub use sergeant::{SergeantAdapter, SergeantReviewPayload};
