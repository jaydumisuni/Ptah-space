use crate::{
    D04Error, ExactPrecondition, ObservedPrecondition, PreconditionConflict, evaluate_preconditions,
};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

/// Caller-authored D04 schedule class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleKind {
    /// One caller-authored occurrence.
    OneOff,
    /// Caller-authored recurrence expression evaluated outside D04.
    Recurring,
    /// Caller-authored condition evaluated from explicit evidence.
    ConditionWatch,
}

/// Mechanical timing mode admitted for one schedule class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingMode {
    /// Exact caller-authored clock boundary.
    Exact,
    /// Caller-authored flexible time window.
    FlexibleWindow,
    /// Execution depends on explicit condition evidence.
    ConditionDependent,
}

/// Mechanical caller-authored schedule specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleSpec {
    /// Schedule class.
    pub kind: ScheduleKind,
    /// Timing behavior compatible with `kind`.
    pub timing_mode: TimingMode,
    /// Optional strict UTC start instant (`YYYY-MM-DDTHH:MM:SSZ`).
    pub starts_at: Option<String>,
    /// Opaque non-empty caller recurrence expression for recurring schedules.
    pub recurrence_expression: Option<String>,
    /// Exact condition identity for condition-watch schedules.
    pub condition_ref: Option<EntityRef>,
    /// Explicit caller limitations.
    pub limitations: Vec<String>,
}

impl ScheduleSpec {
    /// Validate the exact schedule-kind/timing/input matrix.
    ///
    /// # Errors
    /// Returns [`D04Error`] for an incompatible timing mode, malformed UTC
    /// timestamp, missing recurrence, or missing/unexpected condition identity.
    pub fn validate(&self) -> Result<(), D04Error> {
        if let Some(starts_at) = &self.starts_at
            && !strict_utc(starts_at)
        {
            return Err(D04Error::InvalidSchedule(
                "starts_at must be strict UTC".to_owned(),
            ));
        }
        match (self.kind, self.timing_mode) {
            (
                ScheduleKind::OneOff | ScheduleKind::Recurring,
                TimingMode::Exact | TimingMode::FlexibleWindow,
            )
            | (ScheduleKind::ConditionWatch, TimingMode::ConditionDependent) => {}
            _ => {
                return Err(D04Error::InvalidSchedule(
                    "kind/timing_mode matrix".to_owned(),
                ));
            }
        }
        match self.kind {
            ScheduleKind::OneOff => {
                if self.recurrence_expression.is_some() || self.condition_ref.is_some() {
                    return Err(D04Error::InvalidSchedule("one_off extra inputs".to_owned()));
                }
            }
            ScheduleKind::Recurring => {
                let recurrence = self.recurrence_expression.as_deref().unwrap_or_default();
                if recurrence.trim().is_empty() || self.condition_ref.is_some() {
                    return Err(D04Error::InvalidSchedule(
                        "recurring expression/condition".to_owned(),
                    ));
                }
            }
            ScheduleKind::ConditionWatch => {
                if self.condition_ref.is_none() || self.recurrence_expression.is_some() {
                    return Err(D04Error::InvalidSchedule(
                        "condition_watch condition/recurrence".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Immutable caller-supplied scheduled Recipe invocation boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledRecipeInvocation {
    /// Exact Workspace identity.
    pub workspace_ref: EntityRef,
    /// Exact immutable Recipe Revision.
    pub recipe_revision_ref: EntityRef,
    /// Exact separate Acceptance.
    pub acceptance_ref: EntityRef,
    /// Exact canonical Compiled Plan.
    pub compiled_plan_ref: EntityRef,
    /// Exact immutable execution-plan digest.
    pub plan_digest: String,
    /// Exact immutable caller inputs.
    pub immutable_input_refs: Vec<EntityRef>,
    /// Exact caller-selected Provider Revisions.
    pub provider_revision_refs: Vec<EntityRef>,
    /// Exact caller-authorized Grant refs.
    pub grant_refs: Vec<EntityRef>,
    /// Exact preconditions frozen with the invocation.
    pub preconditions: Vec<ExactPrecondition>,
    /// Exact expected output declarations.
    pub expected_output_refs: Vec<EntityRef>,
    /// Exact caller/application identity.
    pub caller_ref: EntityRef,
    /// Caller-authored mechanical schedule.
    pub schedule: ScheduleSpec,
}

impl ScheduledRecipeInvocation {
    /// Validate the immutable scheduled invocation envelope.
    ///
    /// # Errors
    /// Returns [`D04Error`] for invalid schedule data or absent plan digest.
    pub fn validate(&self) -> Result<(), D04Error> {
        self.schedule.validate()?;
        if self.plan_digest.trim().is_empty() {
            return Err(D04Error::InvalidSchedule("plan_digest".to_owned()));
        }
        Ok(())
    }
}

/// Pure mechanical schedule-evaluation outcome supplied to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleEvaluation {
    /// Explicit occurrence evidence says this invocation is not due.
    NotDue,
    /// Explicit occurrence evidence says a non-condition schedule is due.
    Due,
    /// Explicit condition evidence is false.
    ConditionFalse,
    /// Explicit condition evidence is true.
    ConditionTrue,
    /// Frozen preconditions no longer match explicit observations.
    InvalidatedByPrecondition(Box<PreconditionConflict>),
}

/// Evaluate one caller-authored schedule from explicit occurrence/condition evidence.
///
/// D04 performs no clock polling, recurrence expansion, background scheduling, or
/// condition discovery. `occurrence_due` and `condition_met` are caller-supplied
/// mechanical evidence.
#[must_use]
pub fn evaluate_schedule(
    invocation: &ScheduledRecipeInvocation,
    occurrence_due: bool,
    condition_met: Option<bool>,
    observed_preconditions: &[ObservedPrecondition],
) -> ScheduleEvaluation {
    if let Err(conflict) = evaluate_preconditions(&invocation.preconditions, observed_preconditions)
    {
        return ScheduleEvaluation::InvalidatedByPrecondition(conflict);
    }
    if !occurrence_due {
        return ScheduleEvaluation::NotDue;
    }
    match invocation.schedule.kind {
        ScheduleKind::ConditionWatch => {
            if condition_met == Some(true) {
                ScheduleEvaluation::ConditionTrue
            } else {
                ScheduleEvaluation::ConditionFalse
            }
        }
        ScheduleKind::OneOff | ScheduleKind::Recurring => ScheduleEvaluation::Due,
    }
}

fn strict_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 7 | 10 | 13 | 16 | 19) {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
    }
    let parse = |range: std::ops::Range<usize>| value[range].parse::<u32>().ok();
    matches!(parse(5..7), Some(1..=12))
        && matches!(parse(8..10), Some(1..=31))
        && matches!(parse(11..13), Some(0..=23))
        && matches!(parse(14..16), Some(0..=59))
        && matches!(parse(17..19), Some(0..=59))
}
