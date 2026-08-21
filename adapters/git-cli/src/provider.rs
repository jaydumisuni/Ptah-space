use crate::util::{
    OUTPUT_LIMIT, bounded_text, canonical_root, detect_protocol, remote_label,
    safe_new_destination, validate_commit_id,
};
use crate::{
    CloneMode, GitCloneSpec, GitCommandObservation, GitExecutionContext, GitMaterialization,
    GitMaterializationFailure, GitMaterializationFailureKind, GitProjectionEvidence, GitProtocol,
    GitProviderError, LfsPolicy, ResolvedGitSource, SubmodulePolicy,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::{ProviderContext, ProviderInstance, ProviderRevision};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};

const GIT_COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const GIT_WAIT_POLL: Duration = Duration::from_millis(10);

/// UTC observation clock used by the Git Provider.
pub type GitClock = Arc<dyn Fn() -> String + Send + Sync>;

/// Hardened A09 Git CLI Provider.
pub struct GitProvider {
    git_path: PathBuf,
    root: PathBuf,
    hooks_root: PathBuf,
    template_root: PathBuf,
    context: ProviderContext,
    allowed_protocols: BTreeSet<GitProtocol>,
    clock: GitClock,
}

impl GitProvider {
    /// Construct a Git Provider over one exact Provider Revision/Instance pair.
    ///
    /// # Errors
    /// Fails for invalid Provider evidence, non-absolute Git path, or unsafe root.
    pub fn open(
        git_path: impl AsRef<Path>,
        root: impl AsRef<Path>,
        revision: &ProviderRevision,
        instance: &ProviderInstance,
        allowed_protocols: impl IntoIterator<Item = GitProtocol>,
        clock: GitClock,
    ) -> Result<Self, GitProviderError> {
        let context = ProviderContext::from_process(revision, instance)?;
        let git_path = fs::canonicalize(git_path)?;
        if !git_path.is_file() {
            return Err(GitProviderError::InvalidSpec("git_path"));
        }
        let root = canonical_root(root.as_ref())?;
        let hooks_root = root.join(".ptah-empty-hooks");
        let template_root = root.join(".ptah-empty-template");
        fs::create_dir_all(&hooks_root)?;
        fs::create_dir_all(&template_root)?;
        let hooks_root = fs::canonicalize(hooks_root)?;
        let template_root = fs::canonicalize(template_root)?;
        let allowed_protocols: BTreeSet<_> = allowed_protocols.into_iter().collect();
        if allowed_protocols.is_empty() {
            return Err(GitProviderError::InvalidSpec("allowed_protocols"));
        }
        Ok(Self {
            git_path,
            root,
            hooks_root,
            template_root,
            context,
            allowed_protocols,
            clock,
        })
    }

    /// Resolve one remote/ref pair to an exact Git commit before materialization.
    ///
    /// `spec.reference` must be `HEAD` or a fully qualified refname such as
    /// `refs/heads/main` or `refs/tags/v1`; shorthand branch/tag names are not
    /// accepted as exact resolution identities.
    ///
    /// # Errors
    /// Rejects denied protocols, embedded network credentials, mismatched execution
    /// context, ambiguous resolution, option-shaped operands, or Git command failure.
    pub fn resolve_source(
        &self,
        spec: &GitCloneSpec,
        execution: &GitExecutionContext,
    ) -> Result<(ResolvedGitSource, GitCommandObservation), GitProviderError> {
        self.validate_spec(spec)?;
        self.validate_execution(execution)?;
        let protocol = detect_protocol(&spec.remote)?;
        if !self.allowed_protocols.contains(&protocol) {
            return Err(GitProviderError::ProtocolDenied);
        }
        let peeled_reference = format!("{}^{{}}", spec.reference);
        let args = vec![
            "ls-remote".to_owned(),
            "--exit-code".to_owned(),
            "--".to_owned(),
            spec.remote.clone(),
            spec.reference.clone(),
            peeled_reference.clone(),
        ];
        let output = self.run_git("resolve", None, &args, protocol)?;
        let observation = command_observation("resolve", &args, &output);
        if !output.status.success() {
            return Err(command_failure("resolve", &output));
        }
        let resolved_commit =
            resolve_remote_commit(&output.stdout, &spec.reference, &peeled_reference)?;
        Ok((
            ResolvedGitSource {
                remote_label: remote_label(&spec.remote),
                requested_reference: spec.reference.clone(),
                resolved_commit,
                protocol,
                observed_at: (self.clock)(),
            },
            observation,
        ))
    }

    /// Materialize a previously resolved source without re-resolving moving refs.
    ///
    /// The exact commit must exist after clone/mirror and, for checkout mode,
    /// becomes detached `HEAD`. Hooks, templates, global/system Git config, LFS
    /// smudge/process and recursive submodules are disabled mechanically.
    ///
    /// # Errors
    /// Rejects path escape, provider drift, denied metadata policy, clone failure,
    /// timeout, or any exact-commit mismatch.
    pub fn materialize_resolved(
        &self,
        spec: &GitCloneSpec,
        source: &ResolvedGitSource,
        execution: &GitExecutionContext,
    ) -> Result<GitMaterialization, GitProviderError> {
        self.validate_spec(spec)?;
        self.validate_execution(execution)?;
        if source.remote_label != remote_label(&spec.remote)
            || source.requested_reference != spec.reference
            || !self.allowed_protocols.contains(&source.protocol)
            || !validate_commit_id(&source.resolved_commit)
        {
            return Err(GitProviderError::InvalidResolution);
        }
        let target = safe_new_destination(&self.root, &spec.destination)?;
        let target_text = target.to_string_lossy().into_owned();
        let mut commands = Vec::new();
        let mut clone_args = vec!["clone".to_owned()];
        if source.protocol == GitProtocol::File {
            clone_args.push("--no-local".to_owned());
        }
        match spec.mode {
            CloneMode::Checkout => {
                clone_args.extend([
                    "--no-checkout".to_owned(),
                    "--no-recurse-submodules".to_owned(),
                ]);
            }
            CloneMode::Mirror => clone_args.push("--mirror".to_owned()),
        }
        clone_args.extend(["--".to_owned(), spec.remote.clone(), target_text]);
        let clone_output = match self.run_git("clone", None, &clone_args, source.protocol) {
            Ok(output) => output,
            Err(GitProviderError::CommandTimeout { stage }) => {
                return self.materialization_failure(
                    spec,
                    source,
                    execution,
                    &target,
                    commands,
                    GitMaterializationFailureKind::Timeout { stage },
                );
            }
            Err(error) => return Err(error),
        };
        commands.push(command_observation("clone", &clone_args, &clone_output));
        if !clone_output.status.success() {
            let failure = GitMaterializationFailureKind::Command {
                stage: "clone".to_owned(),
                exit_code: clone_output.status.code().unwrap_or(-1),
                stderr: bounded_text(&clone_output.stderr),
            };
            return self
                .materialization_failure(spec, source, execution, &target, commands, failure);
        }

        match self.finish_materialization(spec, source, execution, &target, &mut commands) {
            Ok(materialization) => Ok(materialization),
            Err(error) => {
                let Some(failure) = expected_materialization_failure(&error) else {
                    let _ = fs::remove_dir_all(&target);
                    return Err(error);
                };
                self.materialization_failure(spec, source, execution, &target, commands, failure)
            }
        }
    }

    fn finish_materialization(
        &self,
        spec: &GitCloneSpec,
        source: &ResolvedGitSource,
        execution: &GitExecutionContext,
        target: &Path,
        commands: &mut Vec<GitCommandObservation>,
    ) -> Result<GitMaterialization, GitProviderError> {
        if spec.mode == CloneMode::Checkout {
            let checkout_args = vec![
                "checkout".to_owned(),
                "--detach".to_owned(),
                "--force".to_owned(),
                source.resolved_commit.clone(),
            ];
            let checkout =
                self.run_git("checkout", Some(target), &checkout_args, source.protocol)?;
            commands.push(command_observation("checkout", &checkout_args, &checkout));
            if !checkout.status.success() {
                return Err(command_failure("checkout", &checkout));
            }
        }

        let rev_args = vec![
            "rev-parse".to_owned(),
            format!("{}^{{commit}}", source.resolved_commit),
        ];
        let rev = self.run_git("verify_commit", Some(target), &rev_args, source.protocol)?;
        commands.push(command_observation("verify_commit", &rev_args, &rev));
        if !rev.status.success() {
            return Err(command_failure("verify_commit", &rev));
        }
        let exact_commit = String::from_utf8_lossy(&rev.stdout).trim().to_owned();
        if exact_commit != source.resolved_commit {
            return Err(GitProviderError::CommitMismatch);
        }
        if spec.mode == CloneMode::Checkout {
            let head_args = vec!["rev-parse".to_owned(), "HEAD^{commit}".to_owned()];
            let head = self.run_git("verify_head", Some(target), &head_args, source.protocol)?;
            commands.push(command_observation("verify_head", &head_args, &head));
            if !head.status.success()
                || String::from_utf8_lossy(&head.stdout).trim() != exact_commit
            {
                return Err(GitProviderError::CommitMismatch);
            }
        }

        let submodules_present = self.tree_contains_path(
            target,
            &exact_commit,
            ".gitmodules",
            source.protocol,
            commands,
        )?;
        if submodules_present && spec.submodule_policy == SubmodulePolicy::DenyIfPresent {
            return Err(GitProviderError::SubmoduleDenied);
        }
        let lfs_metadata_present =
            self.tree_references_lfs(target, &exact_commit, source.protocol, commands)?;
        if lfs_metadata_present && spec.lfs_policy == LfsPolicy::DenyIfReferenced {
            return Err(GitProviderError::LfsDenied);
        }

        let materialization_ref = EntityRef::new("git.materialization")?;
        let observed_at = (self.clock)();
        let projection_evidence = GitProjectionEvidence {
            remote_label: source.remote_label.clone(),
            resolved_commit: exact_commit.clone(),
            materialization_ref: materialization_ref.clone(),
            provider_context: self.context.clone(),
            activity_ref: execution.activity_ref.clone(),
            operation_ref: execution.operation_ref.clone(),
            attempt_ref: execution.attempt_ref.clone(),
            clone_mode: spec.mode,
            submodules_present,
            lfs_metadata_present,
            hooks_suppressed: true,
            credential_refs: spec.credential_refs.clone(),
            observed_at,
        };
        Ok(GitMaterialization {
            materialization_ref,
            source: source.clone(),
            exact_commit,
            relative_path_alias: spec.destination.clone(),
            projection_evidence,
            commands: commands.clone(),
        })
    }

    fn materialization_failure(
        &self,
        spec: &GitCloneSpec,
        source: &ResolvedGitSource,
        execution: &GitExecutionContext,
        target: &Path,
        commands: Vec<GitCommandObservation>,
        failure: GitMaterializationFailureKind,
    ) -> Result<GitMaterialization, GitProviderError> {
        let _ = fs::remove_dir_all(target);
        let partial_removed = fs::symlink_metadata(target).is_err();
        let evidence = GitMaterializationFailure {
            failure_ref: EntityRef::new("git.materialization_failure")?,
            source: source.clone(),
            relative_path_alias: spec.destination.clone(),
            provider_context: self.context.clone(),
            activity_ref: execution.activity_ref.clone(),
            operation_ref: execution.operation_ref.clone(),
            attempt_ref: execution.attempt_ref.clone(),
            failure,
            partial_removed,
            commands,
            observed_at: (self.clock)(),
        };
        Err(GitProviderError::MaterializationFailed(Box::new(evidence)))
    }

    fn tree_contains_path(
        &self,
        repo: &Path,
        commit: &str,
        path: &str,
        protocol: GitProtocol,
        commands: &mut Vec<GitCommandObservation>,
    ) -> Result<bool, GitProviderError> {
        let args = vec![
            "ls-tree".to_owned(),
            "-z".to_owned(),
            "--name-only".to_owned(),
            commit.to_owned(),
            "--".to_owned(),
            path.to_owned(),
        ];
        let output = self.run_git("inspect_tree_path", Some(repo), &args, protocol)?;
        commands.push(command_observation("inspect_tree_path", &args, &output));
        if !output.status.success() {
            return Err(command_failure("inspect_tree_path", &output));
        }
        Ok(output
            .stdout
            .split(|byte| *byte == 0)
            .any(|entry| entry == path.as_bytes()))
    }

    fn tree_references_lfs(
        &self,
        repo: &Path,
        commit: &str,
        protocol: GitProtocol,
        commands: &mut Vec<GitCommandObservation>,
    ) -> Result<bool, GitProviderError> {
        let args = vec![
            "grep".to_owned(),
            "-q".to_owned(),
            "-E".to_owned(),
            "filter[[:space:]]*=[[:space:]]*lfs".to_owned(),
            commit.to_owned(),
            "--".to_owned(),
            ".gitattributes".to_owned(),
            ":(glob)**/.gitattributes".to_owned(),
        ];
        let output = self.run_git("inspect_lfs_attributes", Some(repo), &args, protocol)?;
        commands.push(command_observation(
            "inspect_lfs_attributes",
            &args,
            &output,
        ));
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(command_failure("inspect_lfs_attributes", &output)),
        }
    }

    fn validate_spec(&self, spec: &GitCloneSpec) -> Result<(), GitProviderError> {
        if spec.remote.trim() != spec.remote
            || spec.remote.is_empty()
            || spec.remote.len() > 4096
            || spec.remote.starts_with('-')
        {
            return Err(GitProviderError::InvalidSpec("remote"));
        }
        if spec.reference.trim().is_empty()
            || spec.reference.len() > 1024
            || spec.reference.starts_with('-')
            || spec.reference.chars().any(char::is_whitespace)
            || spec.reference.contains(['*', '?', '['])
            || (spec.reference != "HEAD" && !spec.reference.starts_with("refs/"))
        {
            return Err(GitProviderError::InvalidSpec("reference"));
        }
        if spec.credential_refs.len() > 64 {
            return Err(GitProviderError::InvalidSpec("credential_refs"));
        }
        let protocol = detect_protocol(&spec.remote)?;
        if !self.allowed_protocols.contains(&protocol) {
            return Err(GitProviderError::ProtocolDenied);
        }
        Ok(())
    }

    fn validate_execution(&self, execution: &GitExecutionContext) -> Result<(), GitProviderError> {
        if execution.attempt.provider_ref != self.context.provider_ref
            || execution.attempt.producer_instance_ref != self.context.provider_instance_ref
            || execution.attempt.provider_generation != self.context.provider_generation.value()
            || execution.attempt.connection_epoch != self.context.connection_epoch
            || execution.attempt.node_ref != self.context.node_ref
            || execution.attempt.node_generation != self.context.node_generation
        {
            return Err(GitProviderError::ExecutionContextMismatch);
        }
        Ok(())
    }

    fn run_git(
        &self,
        stage: &str,
        cwd: Option<&Path>,
        args: &[String],
        protocol: GitProtocol,
    ) -> Result<Output, GitProviderError> {
        let mut command = Command::new(&self.git_path);
        command.env_clear();
        command.env("LANG", "C");
        command.env("LC_ALL", "C");
        command.env("GIT_CONFIG_NOSYSTEM", "1");
        command.env("GIT_CONFIG_GLOBAL", "/dev/null");
        command.env("GIT_CONFIG_SYSTEM", "/dev/null");
        command.env("GIT_TERMINAL_PROMPT", "0");
        command.env("GCM_INTERACTIVE", "never");
        command.env("GIT_LFS_SKIP_SMUDGE", "1");
        command.env(
            "GIT_ALLOW_PROTOCOL",
            self.allowed_protocols
                .iter()
                .map(|item| item.git_allow_protocol_token())
                .collect::<Vec<_>>()
                .join(":"),
        );
        command
            .arg("-c")
            .arg(format!("core.hooksPath={}", self.hooks_root.display()));
        command
            .arg("-c")
            .arg(format!("init.templateDir={}", self.template_root.display()));
        command.arg("-c").arg("credential.helper=");
        command.arg("-c").arg("core.askPass=");
        command.arg("-c").arg("filter.lfs.smudge=");
        command.arg("-c").arg("filter.lfs.process=");
        command.arg("-c").arg("filter.lfs.required=false");
        command.arg("-c").arg("submodule.recurse=false");
        command.args(args);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        let output = run_command_with_timeout(command, GIT_COMMAND_TIMEOUT, stage)?;
        let _ = protocol;
        Ok(output)
    }
}

fn run_command_with_timeout(
    mut command: Command,
    timeout: Duration,
    stage: &str,
) -> Result<Output, GitProviderError> {
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Git stdout pipe unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("Git stderr pipe unavailable"))?;
    let stdout_reader = spawn_bounded_reader(stdout);
    let stderr_reader = spawn_bounded_reader(stderr);
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_reader(stdout_reader, "stdout");
            let _ = join_reader(stderr_reader, "stderr");
            return Err(GitProviderError::CommandTimeout {
                stage: stage.to_owned(),
            });
        }
        std::thread::sleep(GIT_WAIT_POLL);
    };
    Ok(Output {
        status,
        stdout: join_reader(stdout_reader, "stdout")?,
        stderr: join_reader(stderr_reader, "stderr")?,
    })
}

fn spawn_bounded_reader<R>(mut reader: R) -> JoinHandle<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut retained = Vec::with_capacity(OUTPUT_LIMIT.min(16 * 1024));
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            if retained.len() < OUTPUT_LIMIT {
                let keep = (OUTPUT_LIMIT - retained.len()).min(read);
                retained.extend_from_slice(&buffer[..keep]);
            }
        }
        Ok(retained)
    })
}

fn join_reader(
    handle: JoinHandle<io::Result<Vec<u8>>>,
    stream: &'static str,
) -> Result<Vec<u8>, GitProviderError> {
    handle
        .join()
        .map_err(|_| io::Error::other(format!("Git {stream} reader thread panicked")))?
        .map_err(GitProviderError::from)
}

fn resolve_remote_commit(
    stdout: &[u8],
    requested_reference: &str,
    peeled_reference: &str,
) -> Result<String, GitProviderError> {
    let mut direct = BTreeSet::new();
    let mut peeled = BTreeSet::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let mut fields = line.split_whitespace();
        let Some(object_id) = fields.next() else {
            continue;
        };
        let Some(reference) = fields.next() else {
            continue;
        };
        if !validate_commit_id(object_id) {
            return Err(GitProviderError::InvalidResolution);
        }
        if reference == requested_reference {
            direct.insert(object_id.to_owned());
        } else if reference == peeled_reference {
            peeled.insert(object_id.to_owned());
        } else {
            return Err(GitProviderError::InvalidResolution);
        }
    }
    if peeled.len() == 1 {
        return peeled
            .into_iter()
            .next()
            .ok_or(GitProviderError::InvalidResolution);
    }
    if peeled.is_empty() && direct.len() == 1 {
        return direct
            .into_iter()
            .next()
            .ok_or(GitProviderError::InvalidResolution);
    }
    Err(GitProviderError::InvalidResolution)
}

fn expected_materialization_failure(
    error: &GitProviderError,
) -> Option<GitMaterializationFailureKind> {
    match error {
        GitProviderError::CommandFailed {
            stage,
            exit_code,
            stderr,
        } => Some(GitMaterializationFailureKind::Command {
            stage: stage.clone(),
            exit_code: *exit_code,
            stderr: stderr.clone(),
        }),
        GitProviderError::CommandTimeout { stage } => {
            Some(GitMaterializationFailureKind::Timeout {
                stage: stage.clone(),
            })
        }
        GitProviderError::CommitMismatch => Some(GitMaterializationFailureKind::CommitMismatch),
        GitProviderError::SubmoduleDenied => Some(GitMaterializationFailureKind::SubmoduleDenied),
        GitProviderError::LfsDenied => Some(GitMaterializationFailureKind::LfsDenied),
        _ => None,
    }
}

fn command_observation(stage: &str, args: &[String], output: &Output) -> GitCommandObservation {
    GitCommandObservation {
        stage: stage.to_owned(),
        argv: args.iter().map(|arg| sanitize_arg(arg)).collect(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout: bounded_text(&output.stdout),
        stderr: bounded_text(&output.stderr),
    }
}

fn command_failure(stage: &str, output: &Output) -> GitProviderError {
    GitProviderError::CommandFailed {
        stage: stage.to_owned(),
        exit_code: output.status.code().unwrap_or(-1),
        stderr: bounded_text(&output.stderr),
    }
}

fn sanitize_arg(value: &str) -> String {
    if value.starts_with("https://")
        || value.starts_with("ssh://")
        || value.starts_with("git://")
        || (!value.contains("://") && value.contains('@') && value.contains(':'))
    {
        return remote_label(value);
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_helper_kills_a_stalled_process() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("sleep 5");
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let result = run_command_with_timeout(command, Duration::from_millis(25), "timeout-test");
        assert!(matches!(
            result,
            Err(GitProviderError::CommandTimeout { stage }) if stage == "timeout-test"
        ));
    }

    #[test]
    fn network_arguments_are_sanitized_for_retained_evidence() {
        assert_eq!(
            sanitize_arg("ssh://user@example.invalid/repo.git"),
            "ssh://example.invalid/repo.git"
        );
        assert_eq!(
            sanitize_arg("user@example.invalid:repo.git"),
            "example.invalid:repo.git"
        );
        assert_eq!(
            sanitize_arg("git://example.invalid/repo.git"),
            "git://example.invalid/repo.git"
        );
    }
}
