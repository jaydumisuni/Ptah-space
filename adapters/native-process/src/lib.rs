#![forbid(unsafe_code)]
//! A05 native process and PTY Provider.
//!
//! The adapter owns mechanical process/terminal execution only. Canonical Ptah
//! identities remain independent of operating-system PIDs. PTY output is
//! intentionally represented as one merged terminal stream; pipe-mode processes
//! retain independent stdout and stderr streams.

use portable_pty::{CommandBuilder, MasterPty, PtySize, PtySystem, native_pty_system};
use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::{EntityId, EntityRef, IdentifierError};
use ptah_provider_api::{
    EndpointAlias, ProviderContext, ProviderError, ProviderGeneration, ProviderInstance,
    ProviderRevision,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    io::{Read, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

const PROCESS_KIND: &str = "runtime.native_process";
const TERMINAL_KIND: &str = "runtime.terminal";
const ATTACHMENT_KIND: &str = "workspace.session_attachment";
const LEASE_KIND: &str = "isolation.lease";

/// A05 native-process execution errors.
#[derive(Debug, Error)]
pub enum NativeProcessError {
    /// Provider contract validation failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Canonical identity construction failed.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    /// Standard operating-system I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// PTY backend failed.
    #[error("PTY backend failed: {0}")]
    Pty(String),
    /// Process identity is unknown to this Provider instance.
    #[error("unknown native process")]
    ProcessNotFound,
    /// Operation requires a PTY-backed process.
    #[error("operation requires a PTY-backed process")]
    NotTerminal,
    /// The process has already exited.
    #[error("process has already exited")]
    ProcessExited,
    /// Current Provider generation differs from the process/handle generation.
    #[error("stale provider generation")]
    StaleProviderGeneration,
    /// Attachment is absent, detached, or no longer current.
    #[error("stale terminal attachment")]
    StaleAttachment,
    /// Control lease has been replaced or revoked.
    #[error("stale terminal control lease")]
    StaleLease,
    /// Lease does not authorize the requested mechanical control.
    #[error("terminal control lease lacks required scope")]
    LeaseScopeMissing,
    /// Command or stream configuration is invalid.
    #[error("invalid process specification: {0}")]
    InvalidSpec(&'static str),
    /// Internal synchronized state became poisoned.
    #[error("native process state lock poisoned")]
    Poisoned,
    /// Timed out waiting for an independently observed exit.
    #[error("timed out waiting for process exit")]
    ExitTimeout,
}

/// How client disconnect affects a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectPolicy {
    /// Detaching a client leaves the process running.
    Retain,
    /// Detaching the last explicit attachment terminates the process.
    Terminate,
}

/// Process I/O mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessMode {
    /// Native process with independent stdin/stdout/stderr pipes.
    Pipes,
    /// PTY-backed terminal process.
    Pty {
        /// Initial terminal size.
        size: TerminalSize,
    },
}

/// Terminal dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalSize {
    /// Terminal rows.
    pub rows: u16,
    /// Terminal columns.
    pub cols: u16,
    /// Pixel width where the platform supports it.
    pub pixel_width: u16,
    /// Pixel height where the platform supports it.
    pub pixel_height: u16,
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

impl From<TerminalSize> for PtySize {
    fn from(value: TerminalSize) -> Self {
        Self {
            rows: value.rows,
            cols: value.cols,
            pixel_width: value.pixel_width,
            pixel_height: value.pixel_height,
        }
    }
}

/// Native process launch request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSpec {
    /// Executable path or command name.
    pub program: String,
    /// Argument vector excluding argv[0].
    pub args: Vec<String>,
    /// Explicit environment additions/replacements.
    pub env: BTreeMap<String, String>,
    /// Clear inherited environment before applying `env`.
    pub clear_env: bool,
    /// Optional working directory.
    pub cwd: Option<String>,
    /// I/O mode.
    pub mode: ProcessMode,
    /// Maximum retained bytes per logical stream.
    pub max_stream_bytes: usize,
    /// Client-disconnect behavior.
    pub disconnect_policy: DisconnectPolicy,
}

impl ProcessSpec {
    fn validate(&self) -> Result<(), NativeProcessError> {
        if self.program.trim().is_empty() {
            return Err(NativeProcessError::InvalidSpec("program"));
        }
        if self.max_stream_bytes == 0 {
            return Err(NativeProcessError::InvalidSpec("max_stream_bytes"));
        }
        if let ProcessMode::Pty { size } = &self.mode
            && (size.rows == 0 || size.cols == 0)
        {
            return Err(NativeProcessError::InvalidSpec("terminal size"));
        }
        Ok(())
    }
}

/// Process lifecycle projection owned by A05.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    /// Process launch has completed and exit has not been independently observed.
    Running,
    /// Process exit has been independently observed.
    Exited,
}

/// Logical stream identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    /// Independent stdout pipe.
    Stdout,
    /// Independent stderr pipe.
    Stderr,
    /// Combined PTY terminal stream.
    Terminal,
}

/// Stream topology retained as an explicit limitation/evidence fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTopology {
    /// stdout and stderr are independently observable.
    SeparatedStdoutStderr,
    /// PTY semantics combine terminal output into one stream.
    PtyMergedTerminal,
}

/// Bounded stream observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamSnapshot {
    /// Stream identity.
    pub kind: StreamKind,
    /// Number of append observations incorporated.
    pub sequence: u64,
    /// Total bytes observed before retention limits.
    pub total_bytes: u64,
    /// Bytes currently retained.
    pub retained_bytes: usize,
    /// Bytes deliberately dropped by the configured retention bound.
    pub truncated_bytes: u64,
    /// Retained byte suffix.
    pub bytes: Vec<u8>,
}

/// Independently observed process exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitObservation {
    /// Observation timestamp.
    pub observed_at: String,
    /// Platform exit code when available.
    pub exit_code: Option<i32>,
    /// Signal description when the backend reports one.
    pub signal: Option<String>,
    /// Backend-reported success.
    pub success: bool,
}

/// Queryable process record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRecord {
    /// Canonical Ptah process identity.
    pub process_ref: EntityRef,
    /// Canonical terminal identity for PTY mode.
    pub terminal_ref: Option<EntityRef>,
    /// Exact Provider revision.
    pub provider_revision_ref: EntityRef,
    /// Exact Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Provider generation at process launch.
    pub provider_generation: ProviderGeneration,
    /// Node reference at launch.
    pub node_ref: EntityRef,
    /// Node generation at launch.
    pub node_generation: u64,
    /// Backend aliases/evidence, including OS PID where available.
    pub aliases: Vec<EndpointAlias>,
    /// Launch request.
    pub spec: ProcessSpec,
    /// Explicit stream topology.
    pub stream_topology: StreamTopology,
    /// Current process lifecycle.
    pub state: ProcessState,
    /// Independently observed exit, never inferred from spawn acknowledgement.
    pub exit: Option<ExitObservation>,
    /// Launch timestamp.
    pub started_at: String,
    /// Retained limitations.
    pub limitations: Vec<String>,
}

/// Mechanical terminal attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalAttachment {
    /// Canonical session-attachment reference.
    pub attachment_ref: EntityRef,
    /// Canonical terminal reference.
    pub terminal_ref: EntityRef,
    /// Holder principal/session reference.
    pub holder_ref: EntityRef,
    /// Provider generation to which this attachment is fenced.
    pub provider_generation: ProviderGeneration,
    /// Provider connection epoch to which this attachment is fenced.
    pub connection_epoch: u64,
    /// Attach time.
    pub attached_at: String,
}

/// Mechanical terminal-control scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlScope {
    /// Write terminal input.
    Input,
    /// Resize the PTY.
    Resize,
    /// Terminate the process.
    Terminate,
}

/// Fenced terminal-control lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalLease {
    /// Canonical isolation-lease reference.
    pub lease_ref: EntityRef,
    /// Canonical terminal subject.
    pub terminal_ref: EntityRef,
    /// Lease holder.
    pub holder_ref: EntityRef,
    /// Authorized control scopes.
    pub scopes: Vec<ControlScope>,
    /// Monotonic fence token within the process.
    pub fence_token: u64,
    /// Provider generation fence.
    pub provider_generation: ProviderGeneration,
    /// Issue time.
    pub issued_at: String,
}

/// Runtime snapshot returned without leaking internal handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    /// Process record.
    pub record: ProcessRecord,
    /// stdout observation for pipe mode.
    pub stdout: Option<StreamSnapshot>,
    /// stderr observation for pipe mode.
    pub stderr: Option<StreamSnapshot>,
    /// terminal observation for PTY mode.
    pub terminal: Option<StreamSnapshot>,
}

/// Exact construction inputs for the native process Provider.
#[derive(Clone)]
pub struct NativeProcessProviderConfig {
    /// Frozen process Provider revision.
    pub revision: ProviderRevision,
    /// Frozen local Provider instance.
    pub instance: ProviderInstance,
    /// Clock used for retained evidence timestamps.
    pub clock: Arc<dyn Fn() -> String + Send + Sync>,
}

/// A05 native process Provider.
pub struct NativeProcessProvider {
    context: Mutex<ProviderContext>,
    clock: Arc<dyn Fn() -> String + Send + Sync>,
    processes: Mutex<HashMap<EntityId, ProcessEntry>>,
}

impl NativeProcessProvider {
    /// Construct a process Provider from exact frozen revision/instance evidence.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProcessError::Provider`] when Provider evidence is invalid.
    pub fn new(config: NativeProcessProviderConfig) -> Result<Self, NativeProcessError> {
        let context = ProviderContext::from_process(&config.revision, &config.instance)?;
        Ok(Self {
            context: Mutex::new(context),
            clock: config.clock,
            processes: Mutex::new(HashMap::new()),
        })
    }

    /// Return the exact current Provider execution context.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProcessError::Poisoned`] if synchronized state is poisoned.
    pub fn context(&self) -> Result<ProviderContext, NativeProcessError> {
        Ok(lock(&self.context)?.clone())
    }

    /// Build the exact A04 Attempt context for work routed to this Provider.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProcessError::Poisoned`] if synchronized state is poisoned.
    pub fn attempt_context(
        &self,
        workload_generation: u64,
        facility_ref: EntityRef,
    ) -> Result<AttemptContext, NativeProcessError> {
        let context = self.context()?;
        Ok(AttemptContext {
            node_ref: context.node_ref,
            node_generation: context.node_generation,
            provider_ref: context.provider_ref,
            provider_generation: context.provider_generation.value(),
            workload_generation,
            connection_epoch: context.connection_epoch,
            facility_ref,
            producer_instance_ref: context.provider_instance_ref,
            producer_version: context.implementation_version,
        })
    }

    /// Spawn a native process with either separated pipes or a PTY.
    ///
    /// Spawn success establishes only `Running`; it never proves successful exit.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeProcessError`] for invalid specs, Provider state failures,
    /// PTY backend failures, identity failures, or OS spawn failures.
    pub fn spawn(&self, spec: ProcessSpec) -> Result<EntityId, NativeProcessError> {
        spec.validate()?;
        let context = self.context()?;
        let id = EntityId::new_v7();
        let process_ref = EntityRef::from_id(id, PROCESS_KIND)?;
        let started_at = (self.clock)();

        let (record, entry) = match spec.mode.clone() {
            ProcessMode::Pipes => self.spawn_pipes(process_ref, spec, started_at, context)?,
            ProcessMode::Pty { size } => {
                self.spawn_pty(process_ref, spec, size, started_at, context)?
            }
        };
        let mut processes = lock(&self.processes)?;
        processes.insert(id, ProcessEntry { record, ..entry });
        Ok(id)
    }

    /// Query a process and current bounded stream observations.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProcessError::ProcessNotFound`] or a synchronization error.
    pub fn snapshot(&self, process_id: EntityId) -> Result<ProcessSnapshot, NativeProcessError> {
        self.poll_exit(process_id)?;
        let processes = lock(&self.processes)?;
        let entry = processes
            .get(&process_id)
            .ok_or(NativeProcessError::ProcessNotFound)?;
        snapshot_entry(entry)
    }

    /// Poll for independently observed exit without blocking.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeProcessError`] when the process is unknown or backend
    /// polling fails.
    pub fn poll_exit(
        &self,
        process_id: EntityId,
    ) -> Result<Option<ExitObservation>, NativeProcessError> {
        let mut processes = lock(&self.processes)?;
        let entry = processes
            .get_mut(&process_id)
            .ok_or(NativeProcessError::ProcessNotFound)?;
        if let Some(exit) = &entry.record.exit {
            return Ok(Some(exit.clone()));
        }
        let status = match &mut entry.child {
            ChildHandle::Pipes(child) => child.try_wait()?.map(ExitStatus::from_std),
            ChildHandle::Pty(child) => child.try_wait()?.map(|status| ExitStatus {
                exit_code: Some(i32::try_from(status.exit_code()).unwrap_or(i32::MAX)),
                signal: status.signal().map(ToOwned::to_owned),
                success: status.success(),
            }),
        };
        if let Some(status) = status {
            let observed = ExitObservation {
                observed_at: (self.clock)(),
                exit_code: status.exit_code,
                signal: status.signal,
                success: status.success,
            };
            entry.record.state = ProcessState::Exited;
            entry.record.exit = Some(observed.clone());
            return Ok(Some(observed));
        }
        Ok(None)
    }

    /// Wait until process exit is independently observed or the bound expires.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProcessError::ExitTimeout`] when `timeout` expires, plus
    /// ordinary polling errors.
    pub fn wait_for_exit(
        &self,
        process_id: EntityId,
        timeout: Duration,
    ) -> Result<ExitObservation, NativeProcessError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(exit) = self.poll_exit(process_id)? {
                thread::sleep(Duration::from_millis(15));
                return Ok(exit);
            }
            if Instant::now() >= deadline {
                return Err(NativeProcessError::ExitTimeout);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Create a fresh terminal attachment to a live PTY.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeProcessError`] when the process is not a current live PTY.
    pub fn attach(
        &self,
        process_id: EntityId,
        holder_ref: EntityRef,
    ) -> Result<TerminalAttachment, NativeProcessError> {
        let context = self.context()?;
        let mut processes = lock(&self.processes)?;
        let entry = current_entry_mut(&mut processes, process_id, &context)?;
        let terminal_ref = entry
            .record
            .terminal_ref
            .clone()
            .ok_or(NativeProcessError::NotTerminal)?;
        if entry.record.state == ProcessState::Exited {
            return Err(NativeProcessError::ProcessExited);
        }
        let attachment = TerminalAttachment {
            attachment_ref: EntityRef::new(ATTACHMENT_KIND)?,
            terminal_ref,
            holder_ref,
            provider_generation: context.provider_generation,
            connection_epoch: context.connection_epoch,
            attached_at: (self.clock)(),
        };
        entry
            .attachments
            .insert(attachment.attachment_ref.entity_id, attachment.clone());
        Ok(attachment)
    }

    /// Detach a terminal attachment without implicitly killing durable work.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeProcessError`] for stale/unknown attachments or backend
    /// termination failures when the explicit disconnect Policy is `Terminate`.
    pub fn detach(
        &self,
        process_id: EntityId,
        attachment: &TerminalAttachment,
    ) -> Result<(), NativeProcessError> {
        let context = self.context()?;
        let mut processes = lock(&self.processes)?;
        let entry = current_entry_mut(&mut processes, process_id, &context)?;
        validate_attachment(entry, attachment, &context)?;
        entry.attachments.remove(&attachment.attachment_ref.entity_id);
        if entry.record.spec.disconnect_policy == DisconnectPolicy::Terminate
            && entry.attachments.is_empty()
            && entry.record.state == ProcessState::Running
        {
            kill_child(&mut entry.child)?;
        }
        Ok(())
    }

    /// Read a stream through a current attachment.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeProcessError`] for stale attachments, unknown processes,
    /// unavailable stream kinds, or synchronization failures.
    pub fn read_attached(
        &self,
        process_id: EntityId,
        attachment: &TerminalAttachment,
        kind: StreamKind,
    ) -> Result<StreamSnapshot, NativeProcessError> {
        let context = self.context()?;
        let processes = lock(&self.processes)?;
        let entry = current_entry(&processes, process_id, &context)?;
        validate_attachment(entry, attachment, &context)?;
        stream_snapshot(entry, kind)
    }

    /// Acquire a fresh fenced control lease, replacing any prior lease.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeProcessError`] when the process is not a current live PTY,
    /// scopes are empty, or fence arithmetic overflows.
    pub fn acquire_control(
        &self,
        process_id: EntityId,
        holder_ref: EntityRef,
        scopes: Vec<ControlScope>,
    ) -> Result<TerminalLease, NativeProcessError> {
        if scopes.is_empty() {
            return Err(NativeProcessError::InvalidSpec("lease scopes"));
        }
        let context = self.context()?;
        let mut processes = lock(&self.processes)?;
        let entry = current_entry_mut(&mut processes, process_id, &context)?;
        let terminal_ref = entry
            .record
            .terminal_ref
            .clone()
            .ok_or(NativeProcessError::NotTerminal)?;
        if entry.record.state == ProcessState::Exited {
            return Err(NativeProcessError::ProcessExited);
        }
        entry.next_fence = entry
            .next_fence
            .checked_add(1)
            .ok_or(NativeProcessError::InvalidSpec("lease fence overflow"))?;
        let lease = TerminalLease {
            lease_ref: EntityRef::new(LEASE_KIND)?,
            terminal_ref,
            holder_ref,
            scopes,
            fence_token: entry.next_fence,
            provider_generation: context.provider_generation,
            issued_at: (self.clock)(),
        };
        entry.control_lease = Some(lease.clone());
        Ok(lease)
    }

    /// Write PTY input under the current fenced lease.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeProcessError`] for stale/missing scope or backend I/O.
    pub fn write_input(
        &self,
        process_id: EntityId,
        lease: &TerminalLease,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        let context = self.context()?;
        let mut processes = lock(&self.processes)?;
        let entry = current_entry_mut(&mut processes, process_id, &context)?;
        validate_lease(entry, lease, &context, ControlScope::Input)?;
        let writer = entry
            .pty_writer
            .as_ref()
            .ok_or(NativeProcessError::NotTerminal)?;
        let mut writer = lock(writer)?;
        writer.write_all(bytes)?;
        writer.flush()?;
        Ok(())
    }

    /// Resize a PTY under the current fenced lease.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeProcessError`] for invalid dimensions, stale lease or
    /// PTY backend failure.
    pub fn resize(
        &self,
        process_id: EntityId,
        lease: &TerminalLease,
        size: TerminalSize,
    ) -> Result<(), NativeProcessError> {
        if size.rows == 0 || size.cols == 0 {
            return Err(NativeProcessError::InvalidSpec("terminal size"));
        }
        let context = self.context()?;
        let mut processes = lock(&self.processes)?;
        let entry = current_entry_mut(&mut processes, process_id, &context)?;
        validate_lease(entry, lease, &context, ControlScope::Resize)?;
        let master = entry
            .pty_master
            .as_ref()
            .ok_or(NativeProcessError::NotTerminal)?;
        lock(master)?
            .resize(size.into())
            .map_err(|error| NativeProcessError::Pty(error.to_string()))
    }

    /// Terminate a process under the current terminal-control lease.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeProcessError`] for stale/missing scope or backend failure.
    pub fn terminate(
        &self,
        process_id: EntityId,
        lease: &TerminalLease,
    ) -> Result<(), NativeProcessError> {
        let context = self.context()?;
        let mut processes = lock(&self.processes)?;
        let entry = current_entry_mut(&mut processes, process_id, &context)?;
        validate_lease(entry, lease, &context, ControlScope::Terminate)?;
        kill_child(&mut entry.child)
    }

    /// Advance Provider generation and fence all old process-control handles.
    ///
    /// A05 does not reconcile old-generation processes into the new generation;
    /// later recovery work owns that behavior.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProcessError::Provider`] on generation overflow or a
    /// synchronization error.
    pub fn advance_provider_generation(&self) -> Result<ProviderGeneration, NativeProcessError> {
        let mut context = lock(&self.context)?;
        context.provider_generation = context.provider_generation.next()?;
        Ok(context.provider_generation)
    }

    fn spawn_pipes(
        &self,
        process_ref: EntityRef,
        spec: ProcessSpec,
        started_at: String,
        context: ProviderContext,
    ) -> Result<(ProcessRecord, ProcessEntry), NativeProcessError> {
        let mut command = Command::new(&spec.program);
        command.args(&spec.args);
        if spec.clear_env {
            command.env_clear();
        }
        command.envs(&spec.env);
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let pid = child.id();
        let stdin = child
            .stdin
            .take()
            .ok_or(NativeProcessError::InvalidSpec("stdin pipe"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or(NativeProcessError::InvalidSpec("stdout pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or(NativeProcessError::InvalidSpec("stderr pipe"))?;
        let stdout_stream = Arc::new(Mutex::new(BoundedStream::new(
            StreamKind::Stdout,
            spec.max_stream_bytes,
        )));
        let stderr_stream = Arc::new(Mutex::new(BoundedStream::new(
            StreamKind::Stderr,
            spec.max_stream_bytes,
        )));
        spawn_reader(stdout, Arc::clone(&stdout_stream));
        spawn_reader(stderr, Arc::clone(&stderr_stream));

        let record = ProcessRecord {
            process_ref,
            terminal_ref: None,
            provider_revision_ref: context.provider_revision_ref,
            provider_instance_ref: context.provider_instance_ref,
            provider_generation: context.provider_generation,
            node_ref: context.node_ref,
            node_generation: context.node_generation,
            aliases: vec![EndpointAlias::process_id(pid, started_at.clone())],
            spec,
            stream_topology: StreamTopology::SeparatedStdoutStderr,
            state: ProcessState::Running,
            exit: None,
            started_at,
            limitations: Vec::new(),
        };
        Ok((
            record.clone(),
            ProcessEntry {
                record,
                child: ChildHandle::Pipes(child),
                stdin: Some(Arc::new(Mutex::new(Box::new(stdin)))),
                pty_writer: None,
                pty_master: None,
                stdout: Some(stdout_stream),
                stderr: Some(stderr_stream),
                terminal: None,
                attachments: HashMap::new(),
                control_lease: None,
                next_fence: 0,
            },
        ))
    }

    fn spawn_pty(
        &self,
        process_ref: EntityRef,
        spec: ProcessSpec,
        size: TerminalSize,
        started_at: String,
        context: ProviderContext,
    ) -> Result<(ProcessRecord, ProcessEntry), NativeProcessError> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(size.into())
            .map_err(|error| NativeProcessError::Pty(error.to_string()))?;
        let mut command = CommandBuilder::new(&spec.program);
        command.args(&spec.args);
        if spec.clear_env {
            command.env_clear();
        }
        for (key, value) in &spec.env {
            command.env(key, value);
        }
        if let Some(cwd) = &spec.cwd {
            command.cwd(cwd);
        }
        let child = pair
            .slave
            .spawn_command(command)
            .map_err(|error| NativeProcessError::Pty(error.to_string()))?;
        let pid = child.process_id();
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|error| NativeProcessError::Pty(error.to_string()))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|error| NativeProcessError::Pty(error.to_string()))?;
        let terminal_stream = Arc::new(Mutex::new(BoundedStream::new(
            StreamKind::Terminal,
            spec.max_stream_bytes,
        )));
        spawn_reader(reader, Arc::clone(&terminal_stream));
        let terminal_ref = EntityRef::new(TERMINAL_KIND)?;
        let mut aliases = Vec::new();
        if let Some(pid) = pid {
            aliases.push(EndpointAlias::process_id(pid, started_at.clone()));
        }
        let record = ProcessRecord {
            process_ref,
            terminal_ref: Some(terminal_ref),
            provider_revision_ref: context.provider_revision_ref,
            provider_instance_ref: context.provider_instance_ref,
            provider_generation: context.provider_generation,
            node_ref: context.node_ref,
            node_generation: context.node_generation,
            aliases,
            spec,
            stream_topology: StreamTopology::PtyMergedTerminal,
            state: ProcessState::Running,
            exit: None,
            started_at,
            limitations: vec![
                "PTY mode exposes one merged terminal stream; stdout/stderr separation is not claimed"
                    .to_owned(),
            ],
        };
        Ok((
            record.clone(),
            ProcessEntry {
                record,
                child: ChildHandle::Pty(child),
                stdin: None,
                pty_writer: Some(Arc::new(Mutex::new(writer))),
                pty_master: Some(Arc::new(Mutex::new(pair.master))),
                stdout: None,
                stderr: None,
                terminal: Some(terminal_stream),
                attachments: HashMap::new(),
                control_lease: None,
                next_fence: 0,
            },
        ))
    }
}

struct ProcessEntry {
    record: ProcessRecord,
    child: ChildHandle,
    #[allow(dead_code)]
    stdin: Option<Arc<Mutex<Box<dyn Write + Send>>>>,
    pty_writer: Option<Arc<Mutex<Box<dyn Write + Send>>>>,
    pty_master: Option<Arc<Mutex<Box<dyn MasterPty + Send>>>>,
    stdout: Option<Arc<Mutex<BoundedStream>>>,
    stderr: Option<Arc<Mutex<BoundedStream>>>,
    terminal: Option<Arc<Mutex<BoundedStream>>>,
    attachments: HashMap<EntityId, TerminalAttachment>,
    control_lease: Option<TerminalLease>,
    next_fence: u64,
}

enum ChildHandle {
    Pipes(std::process::Child),
    Pty(Box<dyn portable_pty::Child + Send + Sync>),
}

struct ExitStatus {
    exit_code: Option<i32>,
    signal: Option<String>,
    success: bool,
}

impl ExitStatus {
    fn from_std(status: std::process::ExitStatus) -> Self {
        Self {
            exit_code: status.code(),
            signal: None,
            success: status.success(),
        }
    }
}

struct BoundedStream {
    kind: StreamKind,
    max_bytes: usize,
    sequence: u64,
    total_bytes: u64,
    bytes: Vec<u8>,
}

impl BoundedStream {
    fn new(kind: StreamKind, max_bytes: usize) -> Self {
        Self {
            kind,
            max_bytes,
            sequence: 0,
            total_bytes: 0,
            bytes: Vec::new(),
        }
    }

    fn append(&mut self, chunk: &[u8]) {
        self.sequence = self.sequence.saturating_add(1);
        self.total_bytes = self
            .total_bytes
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if chunk.len() >= self.max_bytes {
            self.bytes.clear();
            self.bytes
                .extend_from_slice(&chunk[chunk.len() - self.max_bytes..]);
            return;
        }
        let overflow = self
            .bytes
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(self.max_bytes);
        if overflow > 0 {
            self.bytes.drain(..overflow);
        }
        self.bytes.extend_from_slice(chunk);
    }

    fn snapshot(&self) -> StreamSnapshot {
        let retained = self.bytes.len();
        StreamSnapshot {
            kind: self.kind,
            sequence: self.sequence,
            total_bytes: self.total_bytes,
            retained_bytes: retained,
            truncated_bytes: self
                .total_bytes
                .saturating_sub(u64::try_from(retained).unwrap_or(u64::MAX)),
            bytes: self.bytes.clone(),
        }
    }
}

fn spawn_reader<R>(mut reader: R, stream: Arc<Mutex<BoundedStream>>)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    if let Ok(mut stream) = stream.lock() {
                        stream.append(&buffer[..count]);
                    } else {
                        break;
                    }
                }
            }
        }
    });
}

fn snapshot_entry(entry: &ProcessEntry) -> Result<ProcessSnapshot, NativeProcessError> {
    Ok(ProcessSnapshot {
        record: entry.record.clone(),
        stdout: entry
            .stdout
            .as_ref()
            .map(|stream| lock(stream).map(|value| value.snapshot()))
            .transpose()?,
        stderr: entry
            .stderr
            .as_ref()
            .map(|stream| lock(stream).map(|value| value.snapshot()))
            .transpose()?,
        terminal: entry
            .terminal
            .as_ref()
            .map(|stream| lock(stream).map(|value| value.snapshot()))
            .transpose()?,
    })
}

fn stream_snapshot(
    entry: &ProcessEntry,
    kind: StreamKind,
) -> Result<StreamSnapshot, NativeProcessError> {
    let stream = match kind {
        StreamKind::Stdout => entry.stdout.as_ref(),
        StreamKind::Stderr => entry.stderr.as_ref(),
        StreamKind::Terminal => entry.terminal.as_ref(),
    }
    .ok_or(NativeProcessError::InvalidSpec("stream unavailable"))?;
    Ok(lock(stream)?.snapshot())
}

fn current_entry<'a>(
    processes: &'a HashMap<EntityId, ProcessEntry>,
    process_id: EntityId,
    context: &ProviderContext,
) -> Result<&'a ProcessEntry, NativeProcessError> {
    let entry = processes
        .get(&process_id)
        .ok_or(NativeProcessError::ProcessNotFound)?;
    ensure_current(entry, context)?;
    Ok(entry)
}

fn current_entry_mut<'a>(
    processes: &'a mut HashMap<EntityId, ProcessEntry>,
    process_id: EntityId,
    context: &ProviderContext,
) -> Result<&'a mut ProcessEntry, NativeProcessError> {
    let entry = processes
        .get_mut(&process_id)
        .ok_or(NativeProcessError::ProcessNotFound)?;
    ensure_current(entry, context)?;
    Ok(entry)
}

fn ensure_current(
    entry: &ProcessEntry,
    context: &ProviderContext,
) -> Result<(), NativeProcessError> {
    if entry.record.provider_generation != context.provider_generation {
        return Err(NativeProcessError::StaleProviderGeneration);
    }
    Ok(())
}

fn validate_attachment(
    entry: &ProcessEntry,
    attachment: &TerminalAttachment,
    context: &ProviderContext,
) -> Result<(), NativeProcessError> {
    if attachment.provider_generation != context.provider_generation
        || attachment.connection_epoch != context.connection_epoch
    {
        return Err(NativeProcessError::StaleProviderGeneration);
    }
    let stored = entry
        .attachments
        .get(&attachment.attachment_ref.entity_id)
        .ok_or(NativeProcessError::StaleAttachment)?;
    if stored != attachment {
        return Err(NativeProcessError::StaleAttachment);
    }
    Ok(())
}

fn validate_lease(
    entry: &ProcessEntry,
    lease: &TerminalLease,
    context: &ProviderContext,
    required: ControlScope,
) -> Result<(), NativeProcessError> {
    if lease.provider_generation != context.provider_generation {
        return Err(NativeProcessError::StaleProviderGeneration);
    }
    let current = entry
        .control_lease
        .as_ref()
        .ok_or(NativeProcessError::StaleLease)?;
    if current != lease {
        return Err(NativeProcessError::StaleLease);
    }
    if !lease.scopes.contains(&required) {
        return Err(NativeProcessError::LeaseScopeMissing);
    }
    Ok(())
}

fn kill_child(child: &mut ChildHandle) -> Result<(), NativeProcessError> {
    match child {
        ChildHandle::Pipes(child) => child.kill().map_err(NativeProcessError::Io),
        ChildHandle::Pty(child) => child.kill().map_err(NativeProcessError::Io),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, NativeProcessError> {
    mutex.lock().map_err(|_| NativeProcessError::Poisoned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptah_provider_api::{ProviderHealth, ProviderKind, ProviderReadiness, ProviderReachability};

    fn reference(kind: &str) -> EntityRef {
        EntityRef::new(kind).expect("valid ref")
    }

    fn provider() -> NativeProcessProvider {
        let revision_ref = reference("runtime.provider_revision");
        NativeProcessProvider::new(NativeProcessProviderConfig {
            revision: ProviderRevision {
                revision_ref: revision_ref.clone(),
                provider_ref: reference("runtime.provider"),
                provider_kind: ProviderKind::Process,
                implementation_name: "native-process".to_owned(),
                implementation_version: "0.1.0".to_owned(),
                build_or_package_digest: "sha256:test-native-process".to_owned(),
                configuration_digest: "sha256:test-config".to_owned(),
                supported_facility_refs: vec![reference("runtime.facility")],
                capability_claim_refs: vec![reference("runtime.capability_claim")],
                dependency_refs: Vec::new(),
                node_requirements: Vec::new(),
                security_requirements: Vec::new(),
                known_limitations: Vec::new(),
            },
            instance: ProviderInstance {
                instance_ref: reference("runtime.provider_instance"),
                provider_revision_ref: revision_ref,
                node_ref: reference("core.node"),
                node_generation: 4,
                provider_generation: ProviderGeneration::new(2).expect("generation"),
                connection_epoch: 5,
                reachability: ProviderReachability::Reachable,
                readiness: ProviderReadiness::Ready,
                health: ProviderHealth::Healthy,
                endpoint_aliases: Vec::new(),
                process_or_service_refs: Vec::new(),
                observation_refs: vec![reference("proof.evidence")],
                started_at: "2026-08-17T00:00:00Z".to_owned(),
                limitations: Vec::new(),
            },
            clock: Arc::new(|| "2026-08-17T00:00:00Z".to_owned()),
        })
        .expect("provider")
    }

    fn pipe_spec(script: &str, max_stream_bytes: usize) -> ProcessSpec {
        ProcessSpec {
            program: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), script.to_owned()],
            env: BTreeMap::new(),
            clear_env: false,
            cwd: None,
            mode: ProcessMode::Pipes,
            max_stream_bytes,
            disconnect_policy: DisconnectPolicy::Retain,
        }
    }

    fn pty_spec(script: &str) -> ProcessSpec {
        ProcessSpec {
            program: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), script.to_owned()],
            env: BTreeMap::new(),
            clear_env: false,
            cwd: None,
            mode: ProcessMode::Pty {
                size: TerminalSize::default(),
            },
            max_stream_bytes: 4096,
            disconnect_policy: DisconnectPolicy::Retain,
        }
    }

    #[cfg(unix)]
    #[test]
    fn pipe_mode_keeps_stdout_and_stderr_independent_and_exit_is_observed() {
        let provider = provider();
        let id = provider
            .spawn(pipe_spec("printf OUT; printf ERR >&2", 1024))
            .expect("spawn");
        let initial = provider.snapshot(id).expect("snapshot");
        assert_eq!(initial.record.state, ProcessState::Running);
        assert!(initial.record.exit.is_none());

        let exit = provider
            .wait_for_exit(id, Duration::from_secs(2))
            .expect("exit");
        assert!(exit.success);
        let snapshot = provider.snapshot(id).expect("snapshot");
        assert_eq!(snapshot.record.state, ProcessState::Exited);
        assert_eq!(
            snapshot.record.stream_topology,
            StreamTopology::SeparatedStdoutStderr
        );
        assert_eq!(snapshot.stdout.expect("stdout").bytes, b"OUT");
        assert_eq!(snapshot.stderr.expect("stderr").bytes, b"ERR");
    }

    #[cfg(unix)]
    #[test]
    fn pty_input_resize_and_merged_stream_limitation_are_explicit() {
        let provider = provider();
        let id = provider
            .spawn(pty_spec(
                "printf 'READY\\n'; IFS= read -r line; printf 'GOT:%s\\n' \"$line\"",
            ))
            .expect("spawn");
        let holder = reference("identity.principal");
        let attachment = provider.attach(id, holder.clone()).expect("attach");
        let lease = provider
            .acquire_control(
                id,
                holder,
                vec![ControlScope::Input, ControlScope::Resize],
            )
            .expect("lease");
        provider
            .resize(
                id,
                &lease,
                TerminalSize {
                    rows: 40,
                    cols: 120,
                    pixel_width: 0,
                    pixel_height: 0,
                },
            )
            .expect("resize");
        provider
            .write_input(id, &lease, b"hello\n")
            .expect("input");
        provider
            .wait_for_exit(id, Duration::from_secs(2))
            .expect("exit");
        let stream = provider
            .read_attached(id, &attachment, StreamKind::Terminal)
            .expect("terminal");
        let text = String::from_utf8_lossy(&stream.bytes);
        assert!(text.contains("GOT:hello"));
        let record = provider.snapshot(id).expect("snapshot").record;
        assert_eq!(record.stream_topology, StreamTopology::PtyMergedTerminal);
        assert!(record.limitations.iter().any(|value| value.contains("merged")));
    }

    #[cfg(unix)]
    #[test]
    fn durable_detach_does_not_terminate_terminal() {
        let provider = provider();
        let id = provider
            .spawn(pty_spec("sleep 0.1; printf DONE"))
            .expect("spawn");
        let attachment = provider
            .attach(id, reference("identity.principal"))
            .expect("attach");
        provider.detach(id, &attachment).expect("detach");
        let exit = provider
            .wait_for_exit(id, Duration::from_secs(2))
            .expect("natural exit");
        assert!(exit.success);
    }

    #[cfg(unix)]
    #[test]
    fn stale_attachment_and_control_lease_fail_closed() {
        let provider = provider();
        let id = provider.spawn(pty_spec("sleep 0.15")).expect("spawn");
        let holder = reference("identity.principal");
        let attachment = provider.attach(id, holder.clone()).expect("attach");
        provider.detach(id, &attachment).expect("detach");
        assert!(matches!(
            provider.read_attached(id, &attachment, StreamKind::Terminal),
            Err(NativeProcessError::StaleAttachment)
        ));

        let first = provider
            .acquire_control(id, holder.clone(), vec![ControlScope::Input])
            .expect("first");
        let second = provider
            .acquire_control(id, holder, vec![ControlScope::Input])
            .expect("second");
        assert!(matches!(
            provider.write_input(id, &first, b"x"),
            Err(NativeProcessError::StaleLease)
        ));
        provider.write_input(id, &second, b"x").expect("current lease");
        provider
            .wait_for_exit(id, Duration::from_secs(2))
            .expect("exit");
    }

    #[cfg(unix)]
    #[test]
    fn provider_generation_fences_old_terminal_handles() {
        let provider = provider();
        let id = provider.spawn(pty_spec("sleep 0.1")).expect("spawn");
        let holder = reference("identity.principal");
        let lease = provider
            .acquire_control(id, holder, vec![ControlScope::Input])
            .expect("lease");
        provider.advance_provider_generation().expect("generation");
        assert!(matches!(
            provider.write_input(id, &lease, b"x"),
            Err(NativeProcessError::StaleProviderGeneration)
        ));
        provider
            .wait_for_exit(id, Duration::from_secs(2))
            .expect("exit");
        assert_eq!(
            provider.snapshot(id).expect("snapshot").record.provider_generation,
            ProviderGeneration::new(2).expect("generation")
        );
    }

    #[cfg(unix)]
    #[test]
    fn several_terminals_remain_independent() {
        let provider = provider();
        let ids: Vec<_> = (0..4)
            .map(|index| {
                provider
                    .spawn(pty_spec(&format!("printf TERMINAL-{index}")))
                    .expect("spawn")
            })
            .collect();
        for (index, id) in ids.into_iter().enumerate() {
            provider
                .wait_for_exit(id, Duration::from_secs(2))
                .expect("exit");
            let snapshot = provider.snapshot(id).expect("snapshot");
            let text = String::from_utf8_lossy(&snapshot.terminal.expect("terminal").bytes);
            assert!(text.contains(&format!("TERMINAL-{index}")));
        }
    }

    #[cfg(unix)]
    #[test]
    fn truncation_is_visible_not_silent() {
        let provider = provider();
        let id = provider
            .spawn(pipe_spec("printf 0123456789", 4))
            .expect("spawn");
        provider
            .wait_for_exit(id, Duration::from_secs(2))
            .expect("exit");
        let stdout = provider
            .snapshot(id)
            .expect("snapshot")
            .stdout
            .expect("stdout");
        assert_eq!(stdout.bytes, b"6789");
        assert_eq!(stdout.total_bytes, 10);
        assert_eq!(stdout.truncated_bytes, 6);
    }

    #[cfg(unix)]
    #[test]
    fn os_pid_is_only_alias_and_attempt_context_is_provider_bound() {
        let provider = provider();
        let id = provider.spawn(pipe_spec(":", 32)).expect("spawn");
        let snapshot = provider.snapshot(id).expect("snapshot");
        let pid_alias = snapshot.record.aliases.first().expect("pid alias");
        assert_ne!(
            pid_alias.value,
            snapshot.record.process_ref.entity_id.to_string()
        );
        let context = provider
            .attempt_context(8, reference("runtime.facility"))
            .expect("attempt context");
        assert_eq!(context.provider_generation, 2);
        assert_eq!(context.node_generation, 4);
        assert_eq!(
            context.producer_instance_ref,
            provider.context().expect("context").provider_instance_ref
        );
        provider
            .wait_for_exit(id, Duration::from_secs(2))
            .expect("exit");
    }
}
