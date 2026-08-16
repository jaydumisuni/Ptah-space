#![forbid(unsafe_code)]
//! A04 Activity, Operation and Attempt orchestration runtime.
//!
//! The three lifecycle families remain independent. Physical Attempt completion
//! is not Operation success, Event delivery is not proof, and worker completion
//! is not caller/result acceptance.

use ptah_events::{Event, EventBus, EventClass, EventError, EventPayload, EventSpec};
use ptah_identifiers::{EntityId, EntityRef, IdentifierError, RecordRevision};
use ptah_ledger::{CanonicalRecord, Ledger, LedgerError};
use ptah_receipts::{ProofLevel, Receipt, ReceiptError, ReceiptSpec, ReceiptStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::Path,
    sync::{Arc, Mutex},
};
use thiserror::Error;

/// Frozen Activity schema identifier.
pub const ACTIVITY_SCHEMA_ID: &str = "urn:ptah:schema:activity:activity:0.1.0";
/// Frozen Operation schema identifier.
pub const OPERATION_SCHEMA_ID: &str = "urn:ptah:schema:activity:operation:0.1.0";
/// Frozen Attempt schema identifier.
pub const ATTEMPT_SCHEMA_ID: &str = "urn:ptah:schema:activity:attempt:0.1.0";
/// Shared A04 schema version for the three frozen runtime records.
pub const A04_SCHEMA_VERSION: &str = "0.1.0";

const ACTIVITY_KIND: &str = "core.activity";
const OPERATION_KIND: &str = "core.operation";
const ATTEMPT_KIND: &str = "core.attempt";
const REPEATED_FAILURE_THRESHOLD: u32 = 3;

/// Activity lifecycle from `activity.lifecycle` 0.1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityState {
    Queued,
    Preparing,
    Running,
    Waiting,
    Paused,
    Resuming,
    Recovering,
    Completed,
    Failed,
    Cancelled,
}

impl ActivityState {
    fn terminal(self) -> bool { matches!(self, Self::Completed | Self::Failed | Self::Cancelled) }
}

/// Operation lifecycle from `operation.lifecycle` 0.1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Planned,
    Ready,
    Dispatching,
    Executing,
    Waiting,
    Uncertain,
    Succeeded,
    Failed,
    Cancelled,
    Blocked,
}

impl OperationState {
    fn terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled | Self::Blocked)
    }
}

/// Attempt lifecycle from `attempt.lifecycle` 0.1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Created,
    Dispatched,
    Accepted,
    Executing,
    Waiting,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Abandoned,
    Superseded,
}

impl AttemptState {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::TimedOut | Self::Cancelled | Self::Abandoned | Self::Superseded
        )
    }
}

/// Frozen Operation side-effect class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    ObservationOnly,
    Reversible,
    IdempotentMutation,
    NonIdempotentMutation,
    Destructive,
    ExternalAuthoritative,
}

/// Frozen Operation retry class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    RetrySafe,
    RetryRequiresIdempotencyReceipt,
    NonRetryable,
    ManualResumeOnly,
    CompensatingActionRequired,
}

impl RetryClass {
    fn automated_retry_permitted(self) -> bool {
        matches!(self, Self::RetrySafe | Self::RetryRequiresIdempotencyReceipt)
    }
}

/// Frozen Operation idempotency class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyClass {
    NoneRequired,
    OperationIdentity,
    ExplicitKey,
    ProviderKey,
    ReceiptGuarded,
    ManualOnly,
    Compensating,
}

impl IdempotencyClass {
    fn requires_key(self) -> bool {
        matches!(self, Self::ExplicitKey | Self::ProviderKey | Self::ReceiptGuarded)
    }
}

/// Caller-supplied durable Activity specification.
#[derive(Debug, Clone)]
pub struct ActivitySpec {
    pub request_ref: EntityRef,
    pub workspace_ref: EntityRef,
    pub caller_ref: EntityRef,
    pub authority_ref: EntityRef,
    pub activity_kind: String,
    pub intent_ref: EntityRef,
    pub priority: i64,
    pub max_attempts: u64,
}

/// Logical Operation specification. Operation identity survives retries.
#[derive(Debug, Clone)]
pub struct OperationSpec {
    pub operation_kind: String,
    pub logical_target_refs: Vec<EntityRef>,
    pub command_or_action_ref: EntityRef,
    pub side_effect_class: SideEffectClass,
    pub retry_class: RetryClass,
    pub idempotency_class: IdempotencyClass,
    pub idempotency_key: Option<String>,
    pub required_authority_refs: Vec<EntityRef>,
    pub precondition_refs: Vec<EntityRef>,
    pub desired_proof_refs: Vec<EntityRef>,
}

/// Fixed physical execution context for one Attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptContext {
    pub node_ref: EntityRef,
    pub node_generation: u64,
    pub provider_ref: EntityRef,
    pub provider_generation: u64,
    pub workload_generation: u64,
    pub connection_epoch: u64,
    pub facility_ref: EntityRef,
    pub producer_instance_ref: EntityRef,
    pub producer_version: String,
}

/// Retained resource/timing observation for one Attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceUsage {
    pub cpu_seconds: f64,
    pub memory_bytes: u64,
    pub network_bytes: u64,
    pub observed_at: String,
}

/// Durable caller-visible Activity projection.
#[derive(Debug, Clone)]
pub struct ActivityRecord {
    id: EntityId,
    revision: RecordRevision,
    state: ActivityState,
    spec: ActivitySpec,
    operation_ids: Vec<EntityId>,
    result_refs: Vec<EntityRef>,
    receipt_refs: Vec<EntityRef>,
    failure_code: Option<String>,
    cancellation_state: &'static str,
    cancellation_request_ref: Option<EntityRef>,
    created_at: String,
    completed_at: Option<String>,
}

impl ActivityRecord {
    #[must_use] pub const fn id(&self) -> EntityId { self.id }
    #[must_use] pub const fn state(&self) -> ActivityState { self.state }
    #[must_use] pub const fn revision(&self) -> RecordRevision { self.revision }
    #[must_use] pub fn operation_ids(&self) -> &[EntityId] { &self.operation_ids }
    #[must_use] pub fn result_refs(&self) -> &[EntityRef] { &self.result_refs }
    #[must_use] pub fn failure_code(&self) -> Option<&str> { self.failure_code.as_deref() }
    #[must_use] pub const fn cancellation_request_ref(&self) -> Option<&EntityRef> { self.cancellation_request_ref.as_ref() }
}

/// Durable logical Operation projection.
#[derive(Debug, Clone)]
pub struct OperationRecord {
    id: EntityId,
    activity_id: EntityId,
    revision: RecordRevision,
    state: OperationState,
    spec: OperationSpec,
    attempt_ids: Vec<EntityId>,
    current_attempt_id: Option<EntityId>,
    receipt_refs: Vec<EntityRef>,
    result_refs: Vec<EntityRef>,
    retry_policy_refs: Vec<EntityRef>,
    failure_code: Option<String>,
    created_at: String,
    completed_at: Option<String>,
}

impl OperationRecord {
    #[must_use] pub const fn id(&self) -> EntityId { self.id }
    #[must_use] pub const fn activity_id(&self) -> EntityId { self.activity_id }
    #[must_use] pub const fn state(&self) -> OperationState { self.state }
    #[must_use] pub const fn revision(&self) -> RecordRevision { self.revision }
    #[must_use] pub fn attempt_ids(&self) -> &[EntityId] { &self.attempt_ids }
    #[must_use] pub const fn current_attempt_id(&self) -> Option<EntityId> { self.current_attempt_id }
    #[must_use] pub fn retry_policy_refs(&self) -> &[EntityRef] { &self.retry_policy_refs }
    #[must_use] pub fn result_refs(&self) -> &[EntityRef] { &self.result_refs }
}

/// Durable physical Attempt projection.
#[derive(Debug, Clone)]
pub struct AttemptRecord {
    id: EntityId,
    operation_id: EntityId,
    attempt_number: u64,
    revision: RecordRevision,
    state: AttemptState,
    correlation_nonce: String,
    context: AttemptContext,
    receipt_refs: Vec<EntityRef>,
    resource_usage: Vec<ResourceUsage>,
    outcome_code: Option<String>,
    uncertainty_reason: Option<String>,
    superseded_by: Option<EntityId>,
    started_at: String,
    completed_at: Option<String>,
}

impl AttemptRecord {
    #[must_use] pub const fn id(&self) -> EntityId { self.id }
    #[must_use] pub const fn operation_id(&self) -> EntityId { self.operation_id }
    #[must_use] pub const fn attempt_number(&self) -> u64 { self.attempt_number }
    #[must_use] pub const fn state(&self) -> AttemptState { self.state }
    #[must_use] pub const fn revision(&self) -> RecordRevision { self.revision }
    #[must_use] pub fn correlation_nonce(&self) -> &str { &self.correlation_nonce }
    #[must_use] pub const fn context(&self) -> &AttemptContext { &self.context }
    #[must_use] pub fn resource_usage(&self) -> &[ResourceUsage] { &self.resource_usage }
}

/// Worker role declared by the caller's Recipe/Plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerRole {
    Primary,
    Verifier,
    Named(String),
}

/// Current worker-slot projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState { Ready, Completed, Failed }

/// One bounded worker slot. A slot is orchestration state, not an AI model.
#[derive(Debug, Clone)]
pub struct WorkerSlot {
    pub id: EntityId,
    pub role: WorkerRole,
    pub independence_group: String,
    pub state: WorkerState,
    pub checkpoint_refs: Vec<EntityRef>,
    pub partial_result_refs: Vec<EntityRef>,
    pub output_ref: Option<EntityRef>,
}

/// Caller-selected formation specification.
#[derive(Debug, Clone)]
pub struct WorkerFormationSpec {
    pub recipe_or_plan_ref: EntityRef,
    pub roles: Vec<WorkerRole>,
    pub workers_per_role: usize,
    pub max_slots: usize,
    pub require_independent_verifier: bool,
}

/// Worker formation projection retained by A04.
#[derive(Debug, Clone)]
pub struct WorkerFormation {
    pub id: EntityId,
    pub activity_id: EntityId,
    pub recipe_or_plan_ref: EntityRef,
    pub slots: Vec<WorkerSlot>,
    pub accepted_result_ref: Option<EntityRef>,
}

/// Visible disagreement between completed worker outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerConflict {
    pub left_worker_id: EntityId,
    pub left_output_ref: EntityRef,
    pub right_worker_id: EntityId,
    pub right_output_ref: EntityRef,
}

/// Backend-neutral append-only canonical journal used by A04.
pub trait RuntimeJournal: Send + Sync {
    /// Append one canonical revision/document.
    fn append(&self, document: Value) -> Result<(), JournalError>;
}

/// Deterministic in-memory journal for tests and embedding.
#[derive(Debug, Clone, Default)]
pub struct MemoryJournal { records: Arc<Mutex<Vec<Value>>> }

impl MemoryJournal {
    /// Snapshot all appended canonical records.
    pub fn records(&self) -> Result<Vec<Value>, JournalError> {
        Ok(self.records.lock().map_err(|_| JournalError::Poisoned)?.clone())
    }
}

impl RuntimeJournal for MemoryJournal {
    fn append(&self, document: Value) -> Result<(), JournalError> {
        self.records.lock().map_err(|_| JournalError::Poisoned)?.push(document);
        Ok(())
    }
}

/// A03-backed canonical runtime journal.
pub struct LedgerJournal { ledger: Mutex<Ledger> }

impl LedgerJournal {
    /// Open an A03 ledger for A04 canonical revisions.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        Ok(Self { ledger: Mutex::new(Ledger::open(path).map_err(JournalError::ledger)?) })
    }
}

impl RuntimeJournal for LedgerJournal {
    fn append(&self, document: Value) -> Result<(), JournalError> {
        let record = CanonicalRecord::from_document(document).map_err(JournalError::ledger)?;
        let mut ledger = self.ledger.lock().map_err(|_| JournalError::Poisoned)?;
        let write = ledger.begin_write().map_err(JournalError::ledger)?;
        write.insert(&record).map_err(JournalError::ledger)?;
        write.commit().map_err(JournalError::ledger)
    }
}

/// Runtime-journal failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JournalError {
    #[error("A03 ledger rejected A04 canonical truth: {0}")]
    Ledger(String),
    #[error("runtime journal state is unavailable")]
    Poisoned,
}

impl JournalError {
    fn ledger(error: LedgerError) -> Self { Self::Ledger(error.to_string()) }
}

#[derive(Debug, Default)]
struct RuntimeState {
    activities: HashMap<EntityId, ActivityRecord>,
    operations: HashMap<EntityId, OperationRecord>,
    attempts: HashMap<EntityId, AttemptRecord>,
    queue: VecDeque<EntityId>,
    running: HashSet<EntityId>,
    formations: HashMap<EntityId, WorkerFormation>,
    failure_correlation: HashMap<String, u32>,
}

type Clock = Arc<dyn Fn() -> String + Send + Sync>;

/// A04 orchestration runtime.
pub struct ActivityRuntime {
    state: Mutex<RuntimeState>,
    events: EventBus,
    receipts: ReceiptStore,
    journal: Arc<dyn RuntimeJournal>,
    clock: Clock,
    max_concurrency: usize,
}

impl ActivityRuntime {
    /// Construct the runtime with explicit durability and clock authorities.
    ///
    /// # Errors
    /// Returns an error when `max_concurrency` is zero.
    pub fn new(
        max_concurrency: usize,
        journal: Arc<dyn RuntimeJournal>,
        clock: Clock,
    ) -> Result<Self, RuntimeError> {
        if max_concurrency == 0 { return Err(RuntimeError::InvalidConcurrencyLimit); }
        Ok(Self {
            state: Mutex::new(RuntimeState::default()),
            events: EventBus::default(),
            receipts: ReceiptStore::default(),
            journal,
            clock,
            max_concurrency,
        })
    }

    /// Event bus used for live and replay projections.
    #[must_use]
    pub const fn events(&self) -> &EventBus { &self.events }

    /// Immutable Receipt repository.
    #[must_use]
    pub const fn receipts(&self) -> &ReceiptStore { &self.receipts }

    /// Number of registered Activities, including terminal work.
    pub fn activity_count(&self) -> Result<usize, RuntimeError> {
        Ok(self.lock_state()?.activities.len())
    }

    /// Number of simultaneously admitted non-terminal running Activities.
    pub fn running_count(&self) -> Result<usize, RuntimeError> {
        Ok(self.lock_state()?.running.len())
    }

    /// Read an Activity even after failure/cancellation.
    pub fn activity(&self, id: EntityId) -> Result<Option<ActivityRecord>, RuntimeError> {
        Ok(self.lock_state()?.activities.get(&id).cloned())
    }

    /// Read an Operation even after terminal failure/cancellation.
    pub fn operation(&self, id: EntityId) -> Result<Option<OperationRecord>, RuntimeError> {
        Ok(self.lock_state()?.operations.get(&id).cloned())
    }

    /// Read one exact Attempt.
    pub fn attempt(&self, id: EntityId) -> Result<Option<AttemptRecord>, RuntimeError> {
        Ok(self.lock_state()?.attempts.get(&id).cloned())
    }

    /// Accept and durably register a new queued Activity.
    pub fn create_activity(&self, spec: ActivitySpec) -> Result<EntityId, RuntimeError> {
        if !valid_namespaced(&spec.activity_kind) { return Err(RuntimeError::InvalidNamespacedKind); }
        if spec.max_attempts == 0 { return Err(RuntimeError::InvalidAttemptBudget); }
        let now = self.now();
        let id = EntityId::new_v7();
        let record = ActivityRecord {
            id,
            revision: revision(1)?,
            state: ActivityState::Queued,
            spec,
            operation_ids: Vec::new(),
            result_refs: Vec::new(),
            receipt_refs: Vec::new(),
            failure_code: None,
            cancellation_state: "none",
            cancellation_request_ref: None,
            created_at: now.clone(),
            completed_at: None,
        };
        self.journal.append(activity_document(&record))?;
        {
            let mut state = self.lock_state()?;
            state.activities.insert(id, record.clone());
            state.queue.push_back(id);
        }
        self.emit_activity_event(&record, "activity.accepted")?;
        Ok(id)
    }

    /// Admit the next queued Activity when concurrency capacity is available.
    /// A04 only admits orchestration work; A05 owns physical process/PTY execution.
    pub fn admit_next(&self) -> Result<Option<EntityId>, RuntimeError> {
        let candidate = {
            let mut state = self.lock_state()?;
            if state.running.len() >= self.max_concurrency { return Ok(None); }
            loop {
                let Some(id) = state.queue.pop_front() else { return Ok(None); };
                if state.activities.get(&id).is_some_and(|activity| activity.state == ActivityState::Queued) {
                    break id;
                }
            }
        };
        self.transition_activity(candidate, ActivityState::Preparing, None, None)?;
        self.transition_activity(candidate, ActivityState::Running, None, None)?;
        self.lock_state()?.running.insert(candidate);
        Ok(Some(candidate))
    }

    /// Create a logical Operation under one Activity.
    pub fn create_operation(&self, activity_id: EntityId, spec: OperationSpec) -> Result<EntityId, RuntimeError> {
        if !valid_namespaced(&spec.operation_kind) { return Err(RuntimeError::InvalidNamespacedKind); }
        if spec.logical_target_refs.is_empty() { return Err(RuntimeError::MissingLogicalTarget); }
        if spec.idempotency_class.requires_key() && spec.idempotency_key.as_deref().is_none_or(str::is_empty) {
            return Err(RuntimeError::MissingIdempotencyKey);
        }
        let activity = self.activity_required(activity_id)?;
        if activity.state.terminal() { return Err(RuntimeError::ParentActivityTerminal); }
        let now = self.now();
        let id = EntityId::new_v7();
        let record = OperationRecord {
            id,
            activity_id,
            revision: revision(1)?,
            state: OperationState::Planned,
            spec,
            attempt_ids: Vec::new(),
            current_attempt_id: None,
            receipt_refs: Vec::new(),
            result_refs: Vec::new(),
            retry_policy_refs: Vec::new(),
            failure_code: None,
            created_at: now,
            completed_at: None,
        };
        self.journal.append(operation_document(&record, &activity))?;
        {
            let mut state = self.lock_state()?;
            state.operations.insert(id, record);
            let parent = state.activities.get(&activity_id).ok_or(RuntimeError::ActivityNotFound(activity_id))?.clone();
            let mut updated = parent;
            updated.operation_ids.push(id);
            updated.revision = next_revision(updated.revision)?;
            self.journal.append(activity_document(&updated))?;
            state.activities.insert(activity_id, updated);
        }
        Ok(id)
    }

    /// Make a planned/waiting/uncertain Operation eligible for a fresh Attempt.
    pub fn make_operation_ready(&self, operation_id: EntityId) -> Result<(), RuntimeError> {
        self.transition_operation(operation_id, OperationState::Ready, None)
    }

    /// Allocate a new physical Attempt with generated UUIDv7 identity and nonce.
    pub fn create_attempt(&self, operation_id: EntityId, context: AttemptContext) -> Result<EntityId, RuntimeError> {
        let id = EntityId::new_v7();
        let nonce = format!("attempt-{id}");
        self.create_attempt_with_id_and_nonce(operation_id, id, nonce, context)
    }

    /// Allocate with explicit identity/nonce for recovery and adversarial collision proof.
    pub fn create_attempt_with_id_and_nonce(
        &self,
        operation_id: EntityId,
        id: EntityId,
        nonce: String,
        context: AttemptContext,
    ) -> Result<EntityId, RuntimeError> {
        if nonce.len() < 8 { return Err(RuntimeError::InvalidCorrelationNonce); }
        let operation = self.operation_required(operation_id)?;
        if operation.state != OperationState::Ready { return Err(invalid_operation_transition(operation.state, OperationState::Dispatching)); }
        let activity = self.activity_required(operation.activity_id)?;
        if operation.attempt_ids.len() >= usize::try_from(activity.spec.max_attempts).map_err(|_| RuntimeError::AttemptBudgetOverflow)? {
            return Err(RuntimeError::AttemptBudgetExhausted);
        }
        if context.producer_version.trim().is_empty() { return Err(RuntimeError::EmptyProducerVersion); }
        let mut state = self.lock_state()?;
        if state.attempts.contains_key(&id) { return Err(RuntimeError::AttemptIdentityReused(id)); }
        if operation.attempt_ids.iter().filter_map(|attempt_id| state.attempts.get(attempt_id)).any(|attempt| attempt.correlation_nonce == nonce) {
            return Err(RuntimeError::AttemptNonceReused);
        }
        let number = u64::try_from(operation.attempt_ids.len()).map_err(|_| RuntimeError::AttemptBudgetOverflow)?
            .checked_add(1).ok_or(RuntimeError::AttemptBudgetOverflow)?;
        let record = AttemptRecord {
            id,
            operation_id,
            attempt_number: number,
            revision: revision(1)?,
            state: AttemptState::Created,
            correlation_nonce: nonce,
            context,
            receipt_refs: Vec::new(),
            resource_usage: Vec::new(),
            outcome_code: None,
            uncertainty_reason: None,
            superseded_by: None,
            started_at: self.now(),
            completed_at: None,
        };
        self.journal.append(attempt_document(&record, &operation, &activity))?;
        state.attempts.insert(id, record);
        let mut updated = operation;
        updated.attempt_ids.push(id);
        updated.current_attempt_id = Some(id);
        updated.state = OperationState::Dispatching;
        updated.revision = next_revision(updated.revision)?;
        self.journal.append(operation_document(&updated, &activity))?;
        state.operations.insert(operation_id, updated);
        Ok(id)
    }

    /// Mark an Attempt as dispatched/routed.
    pub fn dispatch_attempt(&self, attempt_id: EntityId) -> Result<(), RuntimeError> {
        self.transition_attempt(attempt_id, AttemptState::Dispatched, None, None)
    }

    /// Record producer acceptance and advance the parent Operation to executing.
    pub fn accept_attempt(&self, attempt_id: EntityId) -> Result<(), RuntimeError> {
        self.transition_attempt(attempt_id, AttemptState::Accepted, None, None)?;
        let operation_id = self.attempt_required(attempt_id)?.operation_id;
        self.transition_operation(operation_id, OperationState::Executing, None)
    }

    /// Mark current physical execution as active.
    pub fn begin_attempt_execution(&self, attempt_id: EntityId) -> Result<(), RuntimeError> {
        self.transition_attempt(attempt_id, AttemptState::Executing, None, None)
    }

    /// Append immutable exact-context proof and attach its identity to the hierarchy.
    pub fn append_receipt(&self, spec: ReceiptSpec) -> Result<EntityId, RuntimeError> {
        self.validate_receipt_context(&spec)?;
        let receipt = self.receipts.append(spec)?;
        self.journal.append(receipt.canonical_document())?;
        let receipt_ref = EntityRef::from_id(receipt.id(), "proof.receipt")?;
        let context = receipt.context().clone();
        let activity_id = context.activity_ref.entity_id;
        let operation_id = context.operation_ref.entity_id;
        let attempt_id = context.attempt_ref.entity_id;
        self.attach_receipt(activity_id, operation_id, attempt_id, receipt_ref.clone())?;
        self.events.emit(EventSpec {
            event_type: "proof.receipt_recorded".to_owned(),
            event_class: EventClass::ProofNotification,
            source_ref: context.producer_instance_ref,
            subject_ref: context.attempt_ref,
            activity_ref: Some(context.activity_ref),
            operation_ref: Some(context.operation_ref),
            attempt_ref: Some(context.attempt_ref),
            sequence_scope_ref: receipt_activity_ref(activity_id)?,
            occurred_at: self.now(),
            payload: EventPayload::none(),
            receipt_ref: Some(receipt_ref),
        })?;
        Ok(receipt.id())
    }

    /// Mark physical Attempt completion only after exact completion proof.
    /// Parent Operation success remains a separate proof evaluation.
    pub fn complete_attempt(&self, attempt_id: EntityId, receipt_id: EntityId) -> Result<(), RuntimeError> {
        let receipt = self.receipt_required(receipt_id)?;
        self.require_receipt_for_attempt(&receipt, attempt_id)?;
        if !receipt.proves(ProofLevel::OperationCompleted) { return Err(RuntimeError::InsufficientCompletionProof); }
        self.transition_attempt(attempt_id, AttemptState::Completed, Some("PTAH_ATTEMPT_COMPLETED"), None)
    }

    /// Evaluate logical Operation proof separately from physical Attempt completion.
    pub fn prove_operation_succeeded(
        &self,
        operation_id: EntityId,
        receipt_id: EntityId,
        result_refs: Vec<EntityRef>,
    ) -> Result<(), RuntimeError> {
        if result_refs.is_empty() { return Err(RuntimeError::MissingAcceptedResults); }
        let operation = self.operation_required(operation_id)?;
        let attempt_id = operation.current_attempt_id.ok_or(RuntimeError::NoCurrentAttempt)?;
        let attempt = self.attempt_required(attempt_id)?;
        if attempt.state != AttemptState::Completed { return Err(RuntimeError::AttemptNotCompleted); }
        let receipt = self.receipt_required(receipt_id)?;
        self.require_receipt_for_attempt(&receipt, attempt_id)?;
        if !receipt.proves(ProofLevel::OperationCompleted) { return Err(RuntimeError::InsufficientCompletionProof); }
        let activity = self.activity_required(operation.activity_id)?;
        let mut updated = operation;
        updated.state = OperationState::Succeeded;
        updated.result_refs = result_refs;
        updated.completed_at = Some(self.now());
        updated.revision = next_revision(updated.revision)?;
        self.journal.append(operation_document(&updated, &activity))?;
        self.lock_state()?.operations.insert(operation_id, updated);
        Ok(())
    }

    /// Record a physical Attempt failure. Retryable Operations wait for explicit
    /// submitted Policy authority; non-retryable/exhausted Operations fail.
    pub fn fail_attempt(&self, attempt_id: EntityId, stable_code: impl Into<String>) -> Result<(), RuntimeError> {
        let stable_code = stable_code.into();
        let attempt = self.attempt_required(attempt_id)?;
        let operation = self.operation_required(attempt.operation_id)?;
        let activity = self.activity_required(operation.activity_id)?;
        let mut failed_attempt = attempt;
        ensure_attempt_transition(failed_attempt.state, AttemptState::Failed)?;
        failed_attempt.state = AttemptState::Failed;
        failed_attempt.outcome_code = Some(stable_code.clone());
        failed_attempt.completed_at = Some(self.now());
        failed_attempt.revision = next_revision(failed_attempt.revision)?;
        self.journal.append(attempt_document(&failed_attempt, &operation, &activity))?;

        let retry_capacity = operation.attempt_ids.len()
            < usize::try_from(activity.spec.max_attempts).map_err(|_| RuntimeError::AttemptBudgetOverflow)?;
        let mut updated_operation = operation;
        if updated_operation.spec.retry_class.automated_retry_permitted() && retry_capacity {
            updated_operation.state = OperationState::Waiting;
        } else {
            updated_operation.state = OperationState::Failed;
            updated_operation.failure_code = Some(stable_code.clone());
            updated_operation.completed_at = Some(self.now());
        }
        updated_operation.revision = next_revision(updated_operation.revision)?;
        self.journal.append(operation_document(&updated_operation, &activity))?;
        {
            let mut state = self.lock_state()?;
            state.attempts.insert(attempt_id, failed_attempt);
            state.operations.insert(updated_operation.id, updated_operation.clone());
        }
        self.record_failure_correlation(&stable_code, &activity, &updated_operation)?;
        Ok(())
    }

    /// Authorize a retry with an explicit submitted Policy reference and create a
    /// fresh Attempt identity/nonce.
    pub fn retry_operation(
        &self,
        operation_id: EntityId,
        policy_ref: Option<EntityRef>,
        context: AttemptContext,
    ) -> Result<EntityId, RuntimeError> {
        let policy_ref = policy_ref.ok_or(RuntimeError::RetryPolicyRequired)?;
        let operation = self.operation_required(operation_id)?;
        if operation.state != OperationState::Waiting { return Err(RuntimeError::RetryNotWaiting); }
        if !operation.spec.retry_class.automated_retry_permitted() { return Err(RuntimeError::RetryNotPermitted); }
        let activity = self.activity_required(operation.activity_id)?;
        let mut updated = operation;
        updated.retry_policy_refs.push(policy_ref);
        updated.state = OperationState::Ready;
        updated.revision = next_revision(updated.revision)?;
        self.journal.append(operation_document(&updated, &activity))?;
        self.lock_state()?.operations.insert(operation_id, updated);
        self.create_attempt(operation_id, context)
    }

    /// Retain resource/timing evidence on one exact Attempt.
    pub fn record_resource_usage(&self, attempt_id: EntityId, usage: ResourceUsage) -> Result<(), RuntimeError> {
        if !usage.cpu_seconds.is_finite() || usage.cpu_seconds < 0.0 { return Err(RuntimeError::InvalidResourceUsage); }
        let attempt = self.attempt_required(attempt_id)?;
        if attempt.state.terminal() { return Err(RuntimeError::AttemptTerminal); }
        let operation = self.operation_required(attempt.operation_id)?;
        let activity = self.activity_required(operation.activity_id)?;
        let mut updated = attempt;
        updated.resource_usage.push(usage);
        updated.revision = next_revision(updated.revision)?;
        self.journal.append(attempt_document(&updated, &operation, &activity))?;
        self.lock_state()?.attempts.insert(attempt_id, updated);
        Ok(())
    }

    /// Complete an Activity only after every child Operation has explicit success
    /// proof and caller-visible result references exist.
    pub fn complete_activity(&self, activity_id: EntityId, result_refs: Vec<EntityRef>) -> Result<(), RuntimeError> {
        if result_refs.is_empty() { return Err(RuntimeError::MissingAcceptedResults); }
        let activity = self.activity_required(activity_id)?;
        if !matches!(activity.state, ActivityState::Running | ActivityState::Recovering) {
            return Err(invalid_activity_transition(activity.state, ActivityState::Completed));
        }
        if activity.operation_ids.is_empty() { return Err(RuntimeError::MissingRequiredOperations); }
        {
            let state = self.lock_state()?;
            if activity.operation_ids.iter().any(|id| state.operations.get(id).is_none_or(|operation| operation.state != OperationState::Succeeded)) {
                return Err(RuntimeError::RequiredOperationUnproven);
            }
        }
        let mut updated = activity;
        updated.state = ActivityState::Completed;
        updated.result_refs = result_refs;
        updated.completed_at = Some(self.now());
        updated.revision = next_revision(updated.revision)?;
        self.journal.append(activity_document(&updated))?;
        let mut state = self.lock_state()?;
        state.activities.insert(activity_id, updated);
        state.running.remove(&activity_id);
        Ok(())
    }

    /// Explicitly fail one Activity without affecting unrelated work.
    pub fn fail_activity(&self, activity_id: EntityId, stable_code: impl Into<String>) -> Result<(), RuntimeError> {
        let activity = self.activity_required(activity_id)?;
        if activity.state.terminal() { return Err(RuntimeError::ActivityTerminal); }
        let mut updated = activity;
        updated.state = ActivityState::Failed;
        updated.failure_code = Some(stable_code.into());
        updated.completed_at = Some(self.now());
        updated.revision = next_revision(updated.revision)?;
        self.journal.append(activity_document(&updated))?;
        let mut state = self.lock_state()?;
        state.activities.insert(activity_id, updated);
        state.running.remove(&activity_id);
        Ok(())
    }

    /// Cancel only the selected Activity and its own non-terminal children.
    pub fn cancel_activity(&self, activity_id: EntityId, cancellation_request_ref: EntityRef) -> Result<(), RuntimeError> {
        let activity = self.activity_required(activity_id)?;
        if activity.state.terminal() { return Err(RuntimeError::ActivityTerminal); }
        let now = self.now();
        let (operation_updates, attempt_updates) = {
            let state = self.lock_state()?;
            let mut operations = Vec::new();
            let mut attempts = Vec::new();
            for operation_id in &activity.operation_ids {
                if let Some(operation) = state.operations.get(operation_id) {
                    if !operation.state.terminal() {
                        let mut updated = operation.clone();
                        updated.state = OperationState::Cancelled;
                        updated.completed_at = Some(now.clone());
                        updated.revision = next_revision(updated.revision)?;
                        operations.push(updated);
                    }
                    for attempt_id in &operation.attempt_ids {
                        if let Some(attempt) = state.attempts.get(attempt_id) {
                            if !attempt.state.terminal() {
                                let mut updated = attempt.clone();
                                updated.state = AttemptState::Cancelled;
                                updated.outcome_code = Some("PTAH_ATTEMPT_CANCELLED".to_owned());
                                updated.completed_at = Some(now.clone());
                                updated.revision = next_revision(updated.revision)?;
                                attempts.push(updated);
                            }
                        }
                    }
                }
            }
            (operations, attempts)
        };
        for operation in &operation_updates {
            self.journal.append(operation_document(operation, &activity))?;
        }
        for attempt in &attempt_updates {
            let operation = self.operation_required(attempt.operation_id)?;
            self.journal.append(attempt_document(attempt, &operation, &activity))?;
        }
        let mut cancelled = activity;
        cancelled.state = ActivityState::Cancelled;
        cancelled.cancellation_state = "completed";
        cancelled.cancellation_request_ref = Some(cancellation_request_ref);
        cancelled.completed_at = Some(now);
        cancelled.revision = next_revision(cancelled.revision)?;
        self.journal.append(activity_document(&cancelled))?;
        let mut state = self.lock_state()?;
        for operation in operation_updates { state.operations.insert(operation.id, operation); }
        for attempt in attempt_updates { state.attempts.insert(attempt.id, attempt); }
        state.activities.insert(activity_id, cancelled);
        state.running.remove(&activity_id);
        Ok(())
    }

    /// Create caller-defined bounded worker slots for one Activity.
    pub fn create_worker_formation(
        &self,
        activity_id: EntityId,
        spec: WorkerFormationSpec,
    ) -> Result<EntityId, RuntimeError> {
        let activity = self.activity_required(activity_id)?;
        if activity.state.terminal() { return Err(RuntimeError::ActivityTerminal); }
        if spec.roles.is_empty() || spec.workers_per_role == 0 { return Err(RuntimeError::EmptyWorkerFormation); }
        let count = spec.roles.len().checked_mul(spec.workers_per_role).ok_or(RuntimeError::WorkerFormationOverflow)?;
        if count > spec.max_slots { return Err(RuntimeError::WorkerFormationExceedsBound); }
        if spec.require_independent_verifier {
            let primary = spec.roles.iter().any(|role| *role == WorkerRole::Primary);
            let verifier = spec.roles.iter().any(|role| *role == WorkerRole::Verifier);
            if !primary || !verifier { return Err(RuntimeError::IndependentVerifierMissing); }
        }
        let mut slots = Vec::with_capacity(count);
        for role in &spec.roles {
            let group = independence_group(role);
            for _ in 0..spec.workers_per_role {
                slots.push(WorkerSlot {
                    id: EntityId::new_v7(),
                    role: role.clone(),
                    independence_group: group.clone(),
                    state: WorkerState::Ready,
                    checkpoint_refs: Vec::new(),
                    partial_result_refs: Vec::new(),
                    output_ref: None,
                });
            }
        }
        let id = EntityId::new_v7();
        self.lock_state()?.formations.insert(id, WorkerFormation {
            id,
            activity_id,
            recipe_or_plan_ref: spec.recipe_or_plan_ref,
            slots,
            accepted_result_ref: None,
        });
        Ok(id)
    }

    /// Read one worker formation.
    pub fn worker_formation(&self, id: EntityId) -> Result<Option<WorkerFormation>, RuntimeError> {
        Ok(self.lock_state()?.formations.get(&id).cloned())
    }

    /// Retain a worker checkpoint without accepting a result.
    pub fn record_worker_checkpoint(&self, formation_id: EntityId, worker_id: EntityId, checkpoint_ref: EntityRef) -> Result<(), RuntimeError> {
        let mut state = self.lock_state()?;
        let formation = state.formations.get_mut(&formation_id).ok_or(RuntimeError::WorkerFormationNotFound(formation_id))?;
        let worker = formation.slots.iter_mut().find(|slot| slot.id == worker_id).ok_or(RuntimeError::WorkerNotFound(worker_id))?;
        worker.checkpoint_refs.push(checkpoint_ref);
        Ok(())
    }

    /// Retain a partial result without accepting it.
    pub fn record_worker_partial_result(&self, formation_id: EntityId, worker_id: EntityId, partial_ref: EntityRef) -> Result<(), RuntimeError> {
        let mut state = self.lock_state()?;
        let formation = state.formations.get_mut(&formation_id).ok_or(RuntimeError::WorkerFormationNotFound(formation_id))?;
        let worker = formation.slots.iter_mut().find(|slot| slot.id == worker_id).ok_or(RuntimeError::WorkerNotFound(worker_id))?;
        worker.partial_result_refs.push(partial_ref);
        Ok(())
    }

    /// Mark a worker slot complete. This never accepts its output as the result.
    pub fn complete_worker(&self, formation_id: EntityId, worker_id: EntityId, output_ref: EntityRef) -> Result<(), RuntimeError> {
        let mut state = self.lock_state()?;
        let formation = state.formations.get_mut(&formation_id).ok_or(RuntimeError::WorkerFormationNotFound(formation_id))?;
        let worker = formation.slots.iter_mut().find(|slot| slot.id == worker_id).ok_or(RuntimeError::WorkerNotFound(worker_id))?;
        worker.state = WorkerState::Completed;
        worker.output_ref = Some(output_ref);
        Ok(())
    }

    /// Return all visible disagreements; no winner is manufactured.
    pub fn worker_conflicts(&self, formation_id: EntityId) -> Result<Vec<WorkerConflict>, RuntimeError> {
        let state = self.lock_state()?;
        let formation = state.formations.get(&formation_id).ok_or(RuntimeError::WorkerFormationNotFound(formation_id))?;
        let completed: Vec<_> = formation.slots.iter().filter_map(|slot| slot.output_ref.as_ref().map(|output| (slot.id, output))).collect();
        let mut conflicts = Vec::new();
        for left in 0..completed.len() {
            for right in (left + 1)..completed.len() {
                if completed[left].1 != completed[right].1 {
                    conflicts.push(WorkerConflict {
                        left_worker_id: completed[left].0,
                        left_output_ref: completed[left].1.clone(),
                        right_worker_id: completed[right].0,
                        right_output_ref: completed[right].1.clone(),
                    });
                }
            }
        }
        Ok(conflicts)
    }

    /// Explicit caller/reviewer acceptance of one formation result.
    pub fn accept_worker_result(&self, formation_id: EntityId, result_ref: EntityRef) -> Result<(), RuntimeError> {
        let mut state = self.lock_state()?;
        let formation = state.formations.get_mut(&formation_id).ok_or(RuntimeError::WorkerFormationNotFound(formation_id))?;
        formation.accepted_result_ref = Some(result_ref);
        Ok(())
    }

    fn transition_activity(
        &self,
        id: EntityId,
        target: ActivityState,
        failure_code: Option<String>,
        cancellation_ref: Option<EntityRef>,
    ) -> Result<(), RuntimeError> {
        let current = self.activity_required(id)?;
        ensure_activity_transition(current.state, target)?;
        let mut updated = current;
        updated.state = target;
        updated.failure_code = failure_code;
        if let Some(reference) = cancellation_ref {
            updated.cancellation_request_ref = Some(reference);
        }
        if target.terminal() { updated.completed_at = Some(self.now()); }
        updated.revision = next_revision(updated.revision)?;
        self.journal.append(activity_document(&updated))?;
        self.lock_state()?.activities.insert(id, updated.clone());
        self.emit_activity_event(&updated, "activity.state_changed")?;
        Ok(())
    }

    fn transition_operation(&self, id: EntityId, target: OperationState, failure_code: Option<String>) -> Result<(), RuntimeError> {
        let current = self.operation_required(id)?;
        ensure_operation_transition(current.state, target)?;
        let activity = self.activity_required(current.activity_id)?;
        let mut updated = current;
        updated.state = target;
        updated.failure_code = failure_code;
        if target.terminal() { updated.completed_at = Some(self.now()); }
        updated.revision = next_revision(updated.revision)?;
        self.journal.append(operation_document(&updated, &activity))?;
        self.lock_state()?.operations.insert(id, updated);
        Ok(())
    }

    fn transition_attempt(
        &self,
        id: EntityId,
        target: AttemptState,
        outcome_code: Option<&str>,
        uncertainty_reason: Option<&str>,
    ) -> Result<(), RuntimeError> {
        let current = self.attempt_required(id)?;
        ensure_attempt_transition(current.state, target)?;
        let operation = self.operation_required(current.operation_id)?;
        let activity = self.activity_required(operation.activity_id)?;
        let mut updated = current;
        updated.state = target;
        if let Some(code) = outcome_code { updated.outcome_code = Some(code.to_owned()); }
        if let Some(reason) = uncertainty_reason { updated.uncertainty_reason = Some(reason.to_owned()); }
        if target.terminal() { updated.completed_at = Some(self.now()); }
        updated.revision = next_revision(updated.revision)?;
        self.journal.append(attempt_document(&updated, &operation, &activity))?;
        self.lock_state()?.attempts.insert(id, updated);
        Ok(())
    }

    fn validate_receipt_context(&self, spec: &ReceiptSpec) -> Result<(), RuntimeError> {
        let context = &spec.context;
        let attempt = self.attempt_required(context.attempt_ref.entity_id)?;
        let operation = self.operation_required(context.operation_ref.entity_id)?;
        if attempt.operation_id != operation.id || operation.activity_id != context.activity_ref.entity_id {
            return Err(RuntimeError::ReceiptHierarchyMismatch);
        }
        if attempt.id != context.attempt_ref.entity_id
            || attempt.correlation_nonce != context.correlation_nonce
            || attempt.context.node_ref != context.node_ref
            || attempt.context.node_generation != context.node_generation
            || attempt.context.provider_ref != context.provider_ref
            || attempt.context.provider_generation != context.provider_generation
            || attempt.context.workload_generation != context.workload_generation
            || attempt.context.connection_epoch != context.connection_epoch
            || attempt.context.facility_ref != context.facility_ref
            || attempt.context.producer_instance_ref != context.producer_instance_ref
            || attempt.context.producer_version != context.producer_version
        {
            return Err(RuntimeError::ReceiptExecutionContextMismatch);
        }
        if operation.spec.idempotency_key != context.idempotency_key {
            return Err(RuntimeError::ReceiptIdempotencyMismatch);
        }
        Ok(())
    }

    fn attach_receipt(
        &self,
        activity_id: EntityId,
        operation_id: EntityId,
        attempt_id: EntityId,
        receipt_ref: EntityRef,
    ) -> Result<(), RuntimeError> {
        let activity = self.activity_required(activity_id)?;
        let operation = self.operation_required(operation_id)?;
        let attempt = self.attempt_required(attempt_id)?;
        let mut updated_activity = activity;
        let mut updated_operation = operation;
        let mut updated_attempt = attempt;
        updated_activity.receipt_refs.push(receipt_ref.clone());
        updated_operation.receipt_refs.push(receipt_ref.clone());
        updated_attempt.receipt_refs.push(receipt_ref);
        updated_activity.revision = next_revision(updated_activity.revision)?;
        updated_operation.revision = next_revision(updated_operation.revision)?;
        updated_attempt.revision = next_revision(updated_attempt.revision)?;
        self.journal.append(activity_document(&updated_activity))?;
        self.journal.append(operation_document(&updated_operation, &updated_activity))?;
        self.journal.append(attempt_document(&updated_attempt, &updated_operation, &updated_activity))?;
        let mut state = self.lock_state()?;
        state.activities.insert(activity_id, updated_activity);
        state.operations.insert(operation_id, updated_operation);
        state.attempts.insert(attempt_id, updated_attempt);
        Ok(())
    }

    fn require_receipt_for_attempt(&self, receipt: &Receipt, attempt_id: EntityId) -> Result<(), RuntimeError> {
        let attempt = self.attempt_required(attempt_id)?;
        if receipt.context().attempt_ref.entity_id != attempt.id
            || receipt.context().correlation_nonce != attempt.correlation_nonce
        {
            return Err(RuntimeError::ReceiptExecutionContextMismatch);
        }
        Ok(())
    }

    fn record_failure_correlation(
        &self,
        stable_code: &str,
        activity: &ActivityRecord,
        operation: &OperationRecord,
    ) -> Result<(), RuntimeError> {
        let count = {
            let mut state = self.lock_state()?;
            let count = state.failure_correlation.entry(stable_code.to_owned()).or_insert(0);
            *count = count.checked_add(1).ok_or(RuntimeError::FailureCorrelationOverflow)?;
            *count
        };
        if count == REPEATED_FAILURE_THRESHOLD {
            self.events.emit(EventSpec {
                event_type: "diagnostic.repeated_failure".to_owned(),
                event_class: EventClass::Replayable,
                source_ref: activity.spec.authority_ref.clone(),
                subject_ref: operation_ref(operation.id)?,
                activity_ref: Some(activity_ref(activity.id)?),
                operation_ref: Some(operation_ref(operation.id)?),
                attempt_ref: None,
                sequence_scope_ref: activity_ref(activity.id)?,
                occurred_at: self.now(),
                payload: EventPayload::none(),
                receipt_ref: None,
            })?;
        }
        Ok(())
    }

    fn emit_activity_event(&self, activity: &ActivityRecord, event_type: &str) -> Result<Event, RuntimeError> {
        Ok(self.events.emit(EventSpec {
            event_type: event_type.to_owned(),
            event_class: EventClass::Replayable,
            source_ref: activity.spec.authority_ref.clone(),
            subject_ref: activity_ref(activity.id)?,
            activity_ref: Some(activity_ref(activity.id)?),
            operation_ref: None,
            attempt_ref: None,
            sequence_scope_ref: activity_ref(activity.id)?,
            occurred_at: self.now(),
            payload: EventPayload::none(),
            receipt_ref: None,
        })?)
    }

    fn activity_required(&self, id: EntityId) -> Result<ActivityRecord, RuntimeError> {
        self.lock_state()?.activities.get(&id).cloned().ok_or(RuntimeError::ActivityNotFound(id))
    }

    fn operation_required(&self, id: EntityId) -> Result<OperationRecord, RuntimeError> {
        self.lock_state()?.operations.get(&id).cloned().ok_or(RuntimeError::OperationNotFound(id))
    }

    fn attempt_required(&self, id: EntityId) -> Result<AttemptRecord, RuntimeError> {
        self.lock_state()?.attempts.get(&id).cloned().ok_or(RuntimeError::AttemptNotFound(id))
    }

    fn receipt_required(&self, id: EntityId) -> Result<Receipt, RuntimeError> {
        self.receipts.get(id)?.ok_or(RuntimeError::ReceiptNotFound(id))
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, RuntimeState>, RuntimeError> {
        self.state.lock().map_err(|_| RuntimeError::Poisoned)
    }

    fn now(&self) -> String { (self.clock)() }
}

/// A04 runtime failure with stable fail-closed boundaries.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("max concurrency must be greater than zero")]
    InvalidConcurrencyLimit,
    #[error("Activity not found: {0}")]
    ActivityNotFound(EntityId),
    #[error("Operation not found: {0}")]
    OperationNotFound(EntityId),
    #[error("Attempt not found: {0}")]
    AttemptNotFound(EntityId),
    #[error("Receipt not found: {0}")]
    ReceiptNotFound(EntityId),
    #[error("worker formation not found: {0}")]
    WorkerFormationNotFound(EntityId),
    #[error("worker slot not found: {0}")]
    WorkerNotFound(EntityId),
    #[error("invalid lower-case namespaced kind")]
    InvalidNamespacedKind,
    #[error("Activity attempt budget must be positive")]
    InvalidAttemptBudget,
    #[error("attempt budget conversion/number overflow")]
    AttemptBudgetOverflow,
    #[error("attempt budget exhausted")]
    AttemptBudgetExhausted,
    #[error("Operation requires at least one logical target")]
    MissingLogicalTarget,
    #[error("declared idempotency class requires a key")]
    MissingIdempotencyKey,
    #[error("parent Activity is terminal")]
    ParentActivityTerminal,
    #[error("Activity is terminal")]
    ActivityTerminal,
    #[error("Attempt is terminal")]
    AttemptTerminal,
    #[error("Attempt identity was reused: {0}")]
    AttemptIdentityReused(EntityId),
    #[error("Attempt correlation nonce was reused for the same Operation")]
    AttemptNonceReused,
    #[error("Attempt correlation nonce is invalid")]
    InvalidCorrelationNonce,
    #[error("producer version must not be empty")]
    EmptyProducerVersion,
    #[error("invalid Activity transition {from:?} -> {to:?}")]
    InvalidActivityTransition { from: ActivityState, to: ActivityState },
    #[error("invalid Operation transition {from:?} -> {to:?}")]
    InvalidOperationTransition { from: OperationState, to: OperationState },
    #[error("invalid Attempt transition {from:?} -> {to:?}")]
    InvalidAttemptTransition { from: AttemptState, to: AttemptState },
    #[error("Receipt hierarchy does not match canonical Activity/Operation/Attempt")]
    ReceiptHierarchyMismatch,
    #[error("Receipt execution context/generations/nonce do not match the Attempt")]
    ReceiptExecutionContextMismatch,
    #[error("Receipt idempotency binding does not match the Operation")]
    ReceiptIdempotencyMismatch,
    #[error("completion requires exact positive operation-completed proof")]
    InsufficientCompletionProof,
    #[error("current Attempt has not physically completed")]
    AttemptNotCompleted,
    #[error("Operation has no current Attempt")]
    NoCurrentAttempt,
    #[error("caller-visible result acceptance cannot be empty")]
    MissingAcceptedResults,
    #[error("Activity has no required Operations")]
    MissingRequiredOperations,
    #[error("at least one required Operation lacks accepted terminal proof")]
    RequiredOperationUnproven,
    #[error("retry requires a submitted Policy authority reference")]
    RetryPolicyRequired,
    #[error("Operation is not waiting for retry")]
    RetryNotWaiting,
    #[error("retry class does not permit automatic replacement Attempt")]
    RetryNotPermitted,
    #[error("resource usage is invalid")]
    InvalidResourceUsage,
    #[error("worker formation is empty")]
    EmptyWorkerFormation,
    #[error("worker formation size overflow")]
    WorkerFormationOverflow,
    #[error("worker formation exceeds caller-declared bound")]
    WorkerFormationExceedsBound,
    #[error("independent primary/verifier lanes are required")]
    IndependentVerifierMissing,
    #[error("repeated-failure correlation counter overflow")]
    FailureCorrelationOverflow,
    #[error("runtime state is unavailable")]
    Poisoned,
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    #[error(transparent)]
    Event(#[from] EventError),
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
    #[error(transparent)]
    Journal(#[from] JournalError),
}

fn ensure_activity_transition(from: ActivityState, to: ActivityState) -> Result<(), RuntimeError> {
    let allowed = matches!(
        (from, to),
        (ActivityState::Queued, ActivityState::Preparing)
            | (ActivityState::Preparing, ActivityState::Running)
            | (ActivityState::Waiting, ActivityState::Preparing)
            | (ActivityState::Resuming, ActivityState::Preparing)
            | (ActivityState::Recovering, ActivityState::Preparing)
            | (ActivityState::Running, ActivityState::Waiting)
            | (ActivityState::Running, ActivityState::Completed)
            | (ActivityState::Recovering, ActivityState::Completed)
    );
    if allowed { Ok(()) } else { Err(invalid_activity_transition(from, to)) }
}

fn ensure_operation_transition(from: OperationState, to: OperationState) -> Result<(), RuntimeError> {
    let allowed = matches!(
        (from, to),
        (OperationState::Planned, OperationState::Ready)
            | (OperationState::Waiting, OperationState::Ready)
            | (OperationState::Uncertain, OperationState::Ready)
            | (OperationState::Dispatching, OperationState::Executing)
    );
    if allowed { Ok(()) } else { Err(invalid_operation_transition(from, to)) }
}

fn ensure_attempt_transition(from: AttemptState, to: AttemptState) -> Result<(), RuntimeError> {
    let allowed = matches!(
        (from, to),
        (AttemptState::Created, AttemptState::Dispatched)
            | (AttemptState::Dispatched, AttemptState::Accepted)
            | (AttemptState::Accepted, AttemptState::Executing)
            | (AttemptState::Waiting, AttemptState::Executing)
            | (AttemptState::Accepted, AttemptState::Completed)
            | (AttemptState::Executing, AttemptState::Completed)
            | (AttemptState::Waiting, AttemptState::Completed)
            | (AttemptState::Created, AttemptState::Failed)
            | (AttemptState::Dispatched, AttemptState::Failed)
            | (AttemptState::Accepted, AttemptState::Failed)
            | (AttemptState::Executing, AttemptState::Failed)
            | (AttemptState::Waiting, AttemptState::Failed)
    );
    if allowed { Ok(()) } else { Err(invalid_attempt_transition(from, to)) }
}

fn invalid_activity_transition(from: ActivityState, to: ActivityState) -> RuntimeError {
    RuntimeError::InvalidActivityTransition { from, to }
}
fn invalid_operation_transition(from: OperationState, to: OperationState) -> RuntimeError {
    RuntimeError::InvalidOperationTransition { from, to }
}
fn invalid_attempt_transition(from: AttemptState, to: AttemptState) -> RuntimeError {
    RuntimeError::InvalidAttemptTransition { from, to }
}

fn revision(value: u64) -> Result<RecordRevision, RuntimeError> { Ok(RecordRevision::new(value)?) }
fn next_revision(value: RecordRevision) -> Result<RecordRevision, RuntimeError> {
    revision(value.value().checked_add(1).ok_or(RuntimeError::AttemptBudgetOverflow)?)
}

fn valid_namespaced(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() >= 2 && parts.iter().all(|part| {
        let mut chars = part.chars();
        chars.next().is_some_and(|first| first.is_ascii_lowercase())
            && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-'))
    })
}

fn activity_ref(id: EntityId) -> Result<EntityRef, RuntimeError> { Ok(EntityRef::from_id(id, ACTIVITY_KIND)?) }
fn receipt_activity_ref(id: EntityId) -> Result<EntityRef, RuntimeError> { activity_ref(id) }
fn operation_ref(id: EntityId) -> Result<EntityRef, RuntimeError> { Ok(EntityRef::from_id(id, OPERATION_KIND)?) }
fn attempt_ref(id: EntityId) -> Result<EntityRef, RuntimeError> { Ok(EntityRef::from_id(id, ATTEMPT_KIND)?) }

fn independence_group(role: &WorkerRole) -> String {
    match role {
        WorkerRole::Primary => "primary".to_owned(),
        WorkerRole::Verifier => "verifier".to_owned(),
        WorkerRole::Named(name) => format!("named:{name}"),
    }
}

struct EnvelopeInput<'a> {
    id: EntityId,
    kind: &'a str,
    schema_id: &'a str,
    revision: RecordRevision,
    created_at: &'a str,
    updated_at: &'a str,
    workspace_ref: &'a EntityRef,
    authority_ref: &'a EntityRef,
}

fn envelope(input: EnvelopeInput<'_>) -> Value {
    json!({
        "entity_id": input.id,
        "entity_kind": input.kind,
        "schema_id": input.schema_id,
        "schema_version": A04_SCHEMA_VERSION,
        "record_revision": input.revision.value(),
        "created_at": input.created_at,
        "updated_at": input.updated_at,
        "workspace_ref": input.workspace_ref,
        "authority_ref": input.authority_ref,
        "privacy_class": "internal",
        "audience": "workspace",
        "redaction_policy": "none",
        "retention_policy": {
            "policy_id": "ptah.a04.runtime",
            "policy_version": "0.1.0",
            "retention_class": "historical"
        },
        "extensions": {}
    })
}

fn state_projection(machine: &str, state: impl Serialize, revision: RecordRevision) -> Value {
    json!({
        "state_machine_name": machine,
        "state_machine_version": A04_SCHEMA_VERSION,
        "current_state": state,
        "state_sequence": revision.value() - 1
    })
}

fn stable_outcome(code: &str, outcome_class: &str, retryability: &str) -> Value {
    json!({
        "outcome_class": outcome_class,
        "stable_code": code,
        "summary": code,
        "retryability": retryability
    })
}

fn activity_document(record: &ActivityRecord) -> Value {
    let now = record.completed_at.as_deref().unwrap_or(&record.created_at);
    let mut value = json!({
        "envelope": envelope(EnvelopeInput {
            id: record.id,
            kind: ACTIVITY_KIND,
            schema_id: ACTIVITY_SCHEMA_ID,
            revision: record.revision,
            created_at: &record.created_at,
            updated_at: now,
            workspace_ref: &record.spec.workspace_ref,
            authority_ref: &record.spec.authority_ref,
        }),
        "request_ref": record.spec.request_ref,
        "workspace_ref": record.spec.workspace_ref,
        "caller_ref": record.spec.caller_ref,
        "activity_kind": record.spec.activity_kind,
        "intent_ref": record.spec.intent_ref,
        "lifecycle": state_projection("activity.lifecycle", record.state, record.revision),
        "cancellation_state": record.cancellation_state,
        "projection_health": "current",
        "priority": record.spec.priority,
        "budgets": { "max_attempts": record.spec.max_attempts },
        "dependency_refs": [],
        "input_refs": [],
        "operation_refs": record.operation_ids.iter().filter_map(|id| activity_child_ref(*id, OPERATION_KIND)).collect::<Vec<_>>(),
        "current_attempt_refs": [],
        "result_refs": record.result_refs,
        "receipt_refs": record.receipt_refs,
        "created_at": record.created_at,
        "extensions": {}
    });
    let object = value.as_object_mut().expect("Activity document object");
    if let Some(reference) = &record.cancellation_request_ref { object.insert("current_cancellation_request_ref".to_owned(), json!(reference)); }
    if let Some(completed_at) = &record.completed_at { object.insert("completed_at".to_owned(), json!(completed_at)); }
    if record.state == ActivityState::Failed {
        let code = record.failure_code.as_deref().unwrap_or("PTAH_ACTIVITY_FAILED");
        object.insert("failure_class".to_owned(), json!("control_failure"));
        object.insert("failure_outcome".to_owned(), stable_outcome(code, "failed", "manual_review_required"));
    }
    value
}

fn operation_document(record: &OperationRecord, activity: &ActivityRecord) -> Value {
    let now = record.completed_at.as_deref().unwrap_or(&record.created_at);
    let mut value = json!({
        "envelope": envelope(EnvelopeInput {
            id: record.id,
            kind: OPERATION_KIND,
            schema_id: OPERATION_SCHEMA_ID,
            revision: record.revision,
            created_at: &record.created_at,
            updated_at: now,
            workspace_ref: &activity.spec.workspace_ref,
            authority_ref: &activity.spec.authority_ref,
        }),
        "activity_ref": activity_ref_value(activity.id),
        "operation_kind": record.spec.operation_kind,
        "lifecycle": state_projection("operation.lifecycle", record.state, record.revision),
        "logical_target_refs": record.spec.logical_target_refs,
        "command_or_action_ref": record.spec.command_or_action_ref,
        "side_effect_class": record.spec.side_effect_class,
        "retry_class": record.spec.retry_class,
        "idempotency_class": record.spec.idempotency_class,
        "required_authority_refs": record.spec.required_authority_refs,
        "permission_grant_refs": record.retry_policy_refs,
        "precondition_refs": record.spec.precondition_refs,
        "desired_proof_refs": record.spec.desired_proof_refs,
        "attempt_refs": record.attempt_ids.iter().filter_map(|id| activity_child_ref(*id, ATTEMPT_KIND)).collect::<Vec<_>>(),
        "receipt_refs": record.receipt_refs,
        "result_refs": record.result_refs,
        "created_at": record.created_at,
        "extensions": {}
    });
    let object = value.as_object_mut().expect("Operation document object");
    if let Some(key) = &record.spec.idempotency_key { object.insert("idempotency_key".to_owned(), json!(key)); }
    if let Some(id) = record.current_attempt_id { object.insert("current_attempt_ref".to_owned(), activity_ref_value_kind(id, ATTEMPT_KIND)); }
    if record.state == OperationState::Waiting { object.insert("wait_reason".to_owned(), json!("retry_backoff")); }
    if record.state == OperationState::Failed {
        let code = record.failure_code.as_deref().unwrap_or("PTAH_OPERATION_FAILED");
        object.insert("failure_class".to_owned(), json!("provider_failure"));
        object.insert("failure_outcome".to_owned(), stable_outcome(code, "failed", "manual_review_required"));
    }
    if let Some(completed_at) = &record.completed_at { object.insert("completed_at".to_owned(), json!(completed_at)); }
    value
}

fn attempt_document(record: &AttemptRecord, operation: &OperationRecord, activity: &ActivityRecord) -> Value {
    let mut value = json!({
        "envelope": envelope(EnvelopeInput {
            id: record.id,
            kind: ATTEMPT_KIND,
            schema_id: ATTEMPT_SCHEMA_ID,
            revision: record.revision,
            created_at: &record.started_at,
            updated_at: record.completed_at.as_deref().unwrap_or(&record.started_at),
            workspace_ref: &activity.spec.workspace_ref,
            authority_ref: &activity.spec.authority_ref,
        }),
        "operation_ref": activity_ref_value_kind(operation.id, OPERATION_KIND),
        "attempt_number": record.attempt_number,
        "lifecycle": state_projection("attempt.lifecycle", record.state, record.revision),
        "correlation_nonce": record.correlation_nonce,
        "node_ref": record.context.node_ref,
        "node_generation": record.context.node_generation,
        "provider_ref": record.context.provider_ref,
        "provider_generation": record.context.provider_generation,
        "workload_generation": record.context.workload_generation,
        "connection_epoch": record.context.connection_epoch,
        "facility_ref": record.context.facility_ref,
        "producer_instance_ref": record.context.producer_instance_ref,
        "producer_version": record.context.producer_version,
        "backend_alias_refs": [],
        "receipt_refs": record.receipt_refs,
        "resource_usage_refs": [],
        "started_at": record.started_at,
        "extensions": {}
    });
    let object = value.as_object_mut().expect("Attempt document object");
    if record.state.terminal() {
        let code = record.outcome_code.as_deref().unwrap_or("PTAH_ATTEMPT_TERMINAL");
        let class = if record.state == AttemptState::Completed { "success" } else if record.state == AttemptState::Cancelled { "cancelled" } else { "failed" };
        object.insert("outcome".to_owned(), stable_outcome(code, class, "new_attempt_required"));
        object.insert("completed_at".to_owned(), json!(record.completed_at));
    }
    if let Some(reason) = &record.uncertainty_reason { object.insert("uncertainty_reason".to_owned(), json!(reason)); }
    if let Some(id) = record.superseded_by { object.insert("superseded_by_attempt_ref".to_owned(), activity_ref_value_kind(id, ATTEMPT_KIND)); }
    value
}

fn activity_child_ref(id: EntityId, kind: &str) -> Option<EntityRef> { EntityRef::from_id(id, kind).ok() }
fn activity_ref_value(id: EntityId) -> Value { activity_ref_value_kind(id, ACTIVITY_KIND) }
fn activity_ref_value_kind(id: EntityId, kind: &str) -> Value {
    json!({ "entity_id": id, "entity_kind": kind })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptah_ledger::EntityRecordRepository;
    use ptah_receipts::{AuthorityClass, ReceiptContext, ReceiptKind, ReceiptOutcome};
    use std::{fs, sync::Arc};

    fn reference(kind: &str) -> EntityRef { EntityRef::new(kind).expect("reference") }
    fn fixed_clock() -> Clock { Arc::new(|| "2026-08-16T16:30:00Z".to_owned()) }
    fn runtime(limit: usize) -> ActivityRuntime {
        ActivityRuntime::new(limit, Arc::new(MemoryJournal::default()), fixed_clock()).expect("runtime")
    }
    fn activity_spec() -> ActivitySpec {
        ActivitySpec {
            request_ref: reference("core.activity_request"),
            workspace_ref: reference("workspace.workspace"),
            caller_ref: reference("identity.principal"),
            authority_ref: reference("identity.principal"),
            activity_kind: "test.concurrent_work".to_owned(),
            intent_ref: reference("knowledge.intent"),
            priority: 0,
            max_attempts: 3,
        }
    }
    fn operation_spec() -> OperationSpec {
        OperationSpec {
            operation_kind: "test.observe".to_owned(),
            logical_target_refs: vec![reference("object.object")],
            command_or_action_ref: reference("runtime.action"),
            side_effect_class: SideEffectClass::ObservationOnly,
            retry_class: RetryClass::RetrySafe,
            idempotency_class: IdempotencyClass::ExplicitKey,
            idempotency_key: Some("test-operation-key".to_owned()),
            required_authority_refs: vec![reference("isolation.policy")],
            precondition_refs: Vec::new(),
            desired_proof_refs: vec![reference("proof.claim")],
        }
    }
    fn attempt_context() -> AttemptContext {
        AttemptContext {
            node_ref: reference("core.node"),
            node_generation: 4,
            provider_ref: reference("runtime.provider"),
            provider_generation: 2,
            workload_generation: 8,
            connection_epoch: 5,
            facility_ref: reference("runtime.facility"),
            producer_instance_ref: reference("runtime.provider_instance"),
            producer_version: "1.0.0".to_owned(),
        }
    }
    fn setup_attempt(runtime: &ActivityRuntime) -> (EntityId, EntityId, EntityId) {
        let activity = runtime.create_activity(activity_spec()).expect("Activity");
        assert_eq!(runtime.admit_next().expect("admit"), Some(activity));
        let operation = runtime.create_operation(activity, operation_spec()).expect("Operation");
        runtime.make_operation_ready(operation).expect("ready");
        let attempt = runtime.create_attempt(operation, attempt_context()).expect("Attempt");
        runtime.dispatch_attempt(attempt).expect("dispatch");
        runtime.accept_attempt(attempt).expect("accept");
        runtime.begin_attempt_execution(attempt).expect("execute");
        (activity, operation, attempt)
    }
    fn receipt_spec(runtime: &ActivityRuntime, activity: EntityId, operation: EntityId, attempt: EntityId, levels: Vec<ProofLevel>) -> ReceiptSpec {
        let attempt_record = runtime.attempt(attempt).expect("query").expect("Attempt");
        let context = attempt_record.context().clone();
        ReceiptSpec {
            kind: ReceiptKind::OperationObservation,
            outcome: ReceiptOutcome::Positive,
            authority_class: AuthorityClass::PtahNode,
            context: ReceiptContext {
                activity_ref: EntityRef::from_id(activity, ACTIVITY_KIND).expect("activity ref"),
                operation_ref: EntityRef::from_id(operation, OPERATION_KIND).expect("operation ref"),
                attempt_ref: EntityRef::from_id(attempt, ATTEMPT_KIND).expect("attempt ref"),
                idempotency_key: Some("test-operation-key".to_owned()),
                correlation_nonce: attempt_record.correlation_nonce().to_owned(),
                node_ref: context.node_ref,
                node_generation: context.node_generation,
                provider_ref: context.provider_ref,
                provider_generation: context.provider_generation,
                workload_generation: context.workload_generation,
                connection_epoch: context.connection_epoch,
                facility_ref: context.facility_ref,
                producer_instance_ref: context.producer_instance_ref,
                producer_version: context.producer_version,
            },
            producer_identity_evidence_refs: vec![reference("proof.evidence")],
            proof_claim_refs: vec![reference("proof.claim")],
            proof_levels: levels,
            summary: "bounded exact execution evidence".to_owned(),
            limitations: Vec::new(),
            occurred_at: "2026-08-16T16:30:00Z".to_owned(),
        }
    }

    #[test]
    fn ten_independent_activities_can_be_running_together() {
        let runtime = runtime(10);
        let ids: Vec<_> = (0..10).map(|_| runtime.create_activity(activity_spec()).expect("Activity")).collect();
        for id in &ids { assert_eq!(runtime.admit_next().expect("admit"), Some(*id)); }
        assert_eq!(runtime.running_count().expect("running"), 10);
        for id in ids { assert_eq!(runtime.activity(id).expect("query").expect("Activity").state(), ActivityState::Running); }
    }

    #[test]
    fn one_attempt_failure_does_not_collapse_unrelated_activity() {
        let runtime = runtime(2);
        let (first, _, attempt) = setup_attempt(&runtime);
        let second = runtime.create_activity(activity_spec()).expect("second");
        assert_eq!(runtime.admit_next().expect("admit second"), Some(second));
        runtime.fail_attempt(attempt, "PTAH_TEST_FAILURE").expect("fail");
        assert_eq!(runtime.activity(first).expect("first").expect("first").state(), ActivityState::Running);
        assert_eq!(runtime.activity(second).expect("second").expect("second").state(), ActivityState::Running);
    }

    #[test]
    fn cancellation_is_scoped_and_terminal_work_remains_queryable() {
        let runtime = runtime(2);
        let first = runtime.create_activity(activity_spec()).expect("first");
        let second = runtime.create_activity(activity_spec()).expect("second");
        runtime.admit_next().expect("admit first");
        runtime.admit_next().expect("admit second");
        runtime.cancel_activity(first, reference("core.cancellation_request")).expect("cancel");
        assert_eq!(runtime.activity(first).expect("query").expect("first").state(), ActivityState::Cancelled);
        assert_eq!(runtime.activity(second).expect("query").expect("second").state(), ActivityState::Running);
    }

    #[test]
    fn retry_requires_policy_and_creates_distinct_attempt() {
        let runtime = runtime(1);
        let (_, operation, first) = setup_attempt(&runtime);
        runtime.fail_attempt(first, "PTAH_RETRYABLE").expect("fail");
        assert!(matches!(runtime.retry_operation(operation, None, attempt_context()), Err(RuntimeError::RetryPolicyRequired)));
        let second = runtime.retry_operation(operation, Some(reference("isolation.policy")), attempt_context()).expect("retry");
        assert_ne!(first, second);
        assert_eq!(runtime.operation(operation).expect("query").expect("Operation").attempt_ids().len(), 2);
    }

    #[test]
    fn reused_attempt_identity_and_nonce_fail_closed() {
        let runtime = runtime(1);
        let activity = runtime.create_activity(activity_spec()).expect("Activity");
        runtime.admit_next().expect("admit");
        let operation = runtime.create_operation(activity, operation_spec()).expect("Operation");
        runtime.make_operation_ready(operation).expect("ready");
        let id = EntityId::new_v7();
        let nonce = "fixed-nonce-0001".to_owned();
        runtime.create_attempt_with_id_and_nonce(operation, id, nonce.clone(), attempt_context()).expect("first");
        runtime.fail_attempt(id, "PTAH_RETRYABLE").expect("fail");
        runtime.make_operation_ready(operation).expect("ready again");
        assert!(matches!(runtime.create_attempt_with_id_and_nonce(operation, id, "other-nonce-0002".to_owned(), attempt_context()), Err(RuntimeError::AttemptIdentityReused(_))));
        assert!(matches!(runtime.create_attempt_with_id_and_nonce(operation, EntityId::new_v7(), nonce, attempt_context()), Err(RuntimeError::AttemptNonceReused)));
    }

    #[test]
    fn acknowledgement_only_cannot_complete_attempt_or_operation() {
        let runtime = runtime(1);
        let (activity, operation, attempt) = setup_attempt(&runtime);
        let receipt = runtime.append_receipt(receipt_spec(&runtime, activity, operation, attempt, vec![ProofLevel::Accepted])).expect("ack receipt");
        assert!(matches!(runtime.complete_attempt(attempt, receipt), Err(RuntimeError::InsufficientCompletionProof)));
        assert_eq!(runtime.operation(operation).expect("query").expect("Operation").state(), OperationState::Executing);
    }

    #[test]
    fn attempt_completion_does_not_accept_operation_or_activity() {
        let runtime = runtime(1);
        let (activity, operation, attempt) = setup_attempt(&runtime);
        let receipt = runtime.append_receipt(receipt_spec(&runtime, activity, operation, attempt, vec![ProofLevel::OperationCompleted])).expect("proof");
        runtime.complete_attempt(attempt, receipt).expect("physical completion");
        assert_eq!(runtime.attempt(attempt).expect("query").expect("Attempt").state(), AttemptState::Completed);
        assert_eq!(runtime.operation(operation).expect("query").expect("Operation").state(), OperationState::Executing);
        assert_eq!(runtime.activity(activity).expect("query").expect("Activity").state(), ActivityState::Running);
    }

    #[test]
    fn exact_proof_and_explicit_results_complete_hierarchy() {
        let runtime = runtime(1);
        let (activity, operation, attempt) = setup_attempt(&runtime);
        let receipt = runtime.append_receipt(receipt_spec(&runtime, activity, operation, attempt, vec![ProofLevel::OperationCompleted])).expect("proof");
        runtime.complete_attempt(attempt, receipt).expect("Attempt complete");
        let result = reference("object.result");
        runtime.prove_operation_succeeded(operation, receipt, vec![result.clone()]).expect("Operation proof");
        runtime.complete_activity(activity, vec![result]).expect("Activity complete");
        assert_eq!(runtime.operation(operation).expect("Operation").expect("Operation").state(), OperationState::Succeeded);
        assert_eq!(runtime.activity(activity).expect("Activity").expect("Activity").state(), ActivityState::Completed);
    }

    #[test]
    fn receipt_generation_mismatch_fails_closed() {
        let runtime = runtime(1);
        let (activity, operation, attempt) = setup_attempt(&runtime);
        let mut spec = receipt_spec(&runtime, activity, operation, attempt, vec![ProofLevel::OperationCompleted]);
        spec.context.provider_generation += 1;
        assert!(matches!(runtime.append_receipt(spec), Err(RuntimeError::ReceiptExecutionContextMismatch)));
    }

    #[test]
    fn ten_for_two_recipe_creates_twenty_independent_bounded_slots() {
        let runtime = runtime(1);
        let activity = runtime.create_activity(activity_spec()).expect("Activity");
        let formation = runtime.create_worker_formation(activity, WorkerFormationSpec {
            recipe_or_plan_ref: reference("build.recipe"),
            roles: vec![WorkerRole::Primary, WorkerRole::Verifier],
            workers_per_role: 10,
            max_slots: 20,
            require_independent_verifier: true,
        }).expect("formation");
        let formation = runtime.worker_formation(formation).expect("query").expect("formation");
        assert_eq!(formation.slots.len(), 20);
        let primary: HashSet<_> = formation.slots.iter().filter(|slot| slot.role == WorkerRole::Primary).map(|slot| slot.independence_group.as_str()).collect();
        let verifier: HashSet<_> = formation.slots.iter().filter(|slot| slot.role == WorkerRole::Verifier).map(|slot| slot.independence_group.as_str()).collect();
        assert_eq!(primary, HashSet::from(["primary"]));
        assert_eq!(verifier, HashSet::from(["verifier"]));
    }

    #[test]
    fn conflicting_worker_outputs_remain_visible_until_explicit_acceptance() {
        let runtime = runtime(1);
        let activity = runtime.create_activity(activity_spec()).expect("Activity");
        let formation = runtime.create_worker_formation(activity, WorkerFormationSpec {
            recipe_or_plan_ref: reference("build.recipe"),
            roles: vec![WorkerRole::Primary, WorkerRole::Verifier],
            workers_per_role: 1,
            max_slots: 2,
            require_independent_verifier: true,
        }).expect("formation");
        let slots = runtime.worker_formation(formation).expect("query").expect("formation").slots;
        let left = reference("object.result");
        let right = reference("object.result");
        runtime.complete_worker(formation, slots[0].id, left.clone()).expect("left");
        runtime.complete_worker(formation, slots[1].id, right.clone()).expect("right");
        assert_eq!(runtime.worker_conflicts(formation).expect("conflicts").len(), 1);
        assert!(runtime.worker_formation(formation).expect("query").expect("formation").accepted_result_ref.is_none());
        runtime.accept_worker_result(formation, left).expect("explicit acceptance");
        assert!(runtime.worker_formation(formation).expect("query").expect("formation").accepted_result_ref.is_some());
    }

    #[test]
    fn worker_completion_does_not_accept_activity_result() {
        let runtime = runtime(1);
        let activity = runtime.create_activity(activity_spec()).expect("Activity");
        let formation = runtime.create_worker_formation(activity, WorkerFormationSpec {
            recipe_or_plan_ref: reference("build.recipe"),
            roles: vec![WorkerRole::Primary],
            workers_per_role: 1,
            max_slots: 1,
            require_independent_verifier: false,
        }).expect("formation");
        let worker = runtime.worker_formation(formation).expect("query").expect("formation").slots[0].id;
        runtime.complete_worker(formation, worker, reference("object.result")).expect("worker complete");
        assert!(runtime.worker_formation(formation).expect("query").expect("formation").accepted_result_ref.is_none());
        assert!(runtime.activity(activity).expect("query").expect("Activity").result_refs().is_empty());
    }

    #[test]
    fn repeated_failure_emits_advisory_without_starting_new_work() {
        let runtime = runtime(3);
        let before = runtime.activity_count().expect("count");
        for _ in 0..3 {
            let (_, _, attempt) = setup_attempt(&runtime);
            runtime.fail_attempt(attempt, "PTAH_REPEATED").expect("fail");
        }
        assert_eq!(runtime.activity_count().expect("count"), before + 3);
        let diagnostic = (0..runtime.activity_count().expect("count")).count();
        assert!(diagnostic >= 3);
        assert!(runtime.events().len().expect("events") >= 7);
    }

    #[test]
    fn failed_activity_remains_queryable() {
        let runtime = runtime(1);
        let activity = runtime.create_activity(activity_spec()).expect("Activity");
        runtime.admit_next().expect("admit");
        runtime.fail_activity(activity, "PTAH_ACTIVITY_TEST_FAILED").expect("fail");
        let retained = runtime.activity(activity).expect("query").expect("retained");
        assert_eq!(retained.state(), ActivityState::Failed);
        assert_eq!(retained.failure_code(), Some("PTAH_ACTIVITY_TEST_FAILED"));
    }

    #[test]
    fn worker_checkpoint_and_partial_are_retained_without_acceptance() {
        let runtime = runtime(1);
        let activity = runtime.create_activity(activity_spec()).expect("Activity");
        let formation = runtime.create_worker_formation(activity, WorkerFormationSpec {
            recipe_or_plan_ref: reference("build.recipe"),
            roles: vec![WorkerRole::Primary],
            workers_per_role: 1,
            max_slots: 1,
            require_independent_verifier: false,
        }).expect("formation");
        let worker = runtime.worker_formation(formation).expect("query").expect("formation").slots[0].id;
        runtime.record_worker_checkpoint(formation, worker, reference("workspace.checkpoint")).expect("checkpoint");
        runtime.record_worker_partial_result(formation, worker, reference("object.partial_result")).expect("partial");
        let formation = runtime.worker_formation(formation).expect("query").expect("formation");
        assert_eq!(formation.slots[0].checkpoint_refs.len(), 1);
        assert_eq!(formation.slots[0].partial_result_refs.len(), 1);
        assert!(formation.accepted_result_ref.is_none());
    }

    #[test]
    fn resource_and_timing_evidence_are_retained() {
        let runtime = runtime(1);
        let (_, _, attempt) = setup_attempt(&runtime);
        runtime.record_resource_usage(attempt, ResourceUsage {
            cpu_seconds: 1.25,
            memory_bytes: 4096,
            network_bytes: 512,
            observed_at: "2026-08-16T16:31:00Z".to_owned(),
        }).expect("resource evidence");
        let attempt = runtime.attempt(attempt).expect("query").expect("Attempt");
        assert_eq!(attempt.resource_usage().len(), 1);
        assert_eq!(attempt.resource_usage()[0].memory_bytes, 4096);
    }

    #[test]
    fn a03_ledger_journal_persists_canonical_activity() {
        let path = std::env::temp_dir().join(format!("ptah-a04-ledger-{}.sqlite3", EntityId::new_v7()));
        let journal = Arc::new(LedgerJournal::open(&path).expect("ledger journal"));
        let runtime = ActivityRuntime::new(1, journal, fixed_clock()).expect("runtime");
        let activity = runtime.create_activity(activity_spec()).expect("Activity");
        drop(runtime);
        let ledger = Ledger::open(&path).expect("reopen ledger");
        let retained = ledger.latest_record(activity).expect("query").expect("record");
        assert_eq!(retained.entity_id(), activity);
        assert_eq!(retained.schema_id(), ACTIVITY_SCHEMA_ID);
        fs::remove_file(&path).ok();
        fs::remove_file(path.with_extension("sqlite3-wal")).ok();
        fs::remove_file(path.with_extension("sqlite3-shm")).ok();
    }
}
