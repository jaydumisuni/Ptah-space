//! A09 hardened Git Provider acceptance suite.

use git_cli::{
    CloneMode, GitCloneSpec, GitExecutionContext, GitMaterializationFailure,
    GitMaterializationFailureKind, GitProtocol, GitProvider, GitProviderError, LfsPolicy,
    SubmodulePolicy,
};
use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::EntityRef;
use ptah_provider_api::{
    ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind, ProviderReachability,
    ProviderReadiness, ProviderRevision,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const NOW: &str = "2026-08-19T21:00:00Z";

struct TempRoot {
    root: PathBuf,
}
impl TempRoot {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("ptah-a09-git-{}-{serial}", std::process::id()));
        fs::create_dir_all(&root).expect("temp root");
        Self { root }
    }
    fn provider_root(&self) -> PathBuf {
        self.root.join("provider")
    }
    fn remote(&self) -> PathBuf {
        self.root.join("remote.git")
    }
    fn seed(&self) -> PathBuf {
        self.root.join("seed")
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("ref")
}
fn git_path() -> PathBuf {
    let output = Command::new("sh")
        .args(["-lc", "command -v git"])
        .output()
        .expect("which git");
    PathBuf::from(String::from_utf8(output.stdout).expect("utf8").trim())
}
fn provider_fixture() -> &'static (ProviderRevision, ProviderInstance) {
    static FIXTURE: OnceLock<(ProviderRevision, ProviderInstance)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let revision = ProviderRevision {
            revision_ref: reference("runtime.provider_revision"),
            provider_ref: reference("runtime.provider"),
            provider_kind: ProviderKind::Process,
            implementation_name: "git-cli".to_owned(),
            implementation_version: "2.47.3".to_owned(),
            build_or_package_digest: "sha256:a09-git-cli-test".to_owned(),
            configuration_digest: "sha256:a09-config-test".to_owned(),
            supported_facility_refs: vec![reference("runtime.facility")],
            capability_claim_refs: vec![reference("capability.claim")],
            dependency_refs: vec![reference("proof.evidence")],
            node_requirements: Vec::new(),
            security_requirements: vec![
                "hooks_disabled".to_owned(),
                "protocol_allowlist".to_owned(),
            ],
            known_limitations: Vec::new(),
        };
        let instance = ProviderInstance {
            instance_ref: reference("runtime.provider_instance"),
            provider_revision_ref: revision.revision_ref.clone(),
            node_ref: reference("core.node"),
            node_generation: 4,
            provider_generation: ProviderGeneration::new(3).expect("generation"),
            connection_epoch: 7,
            reachability: ProviderReachability::Reachable,
            readiness: ProviderReadiness::Ready,
            health: ProviderHealth::Healthy,
            endpoint_aliases: Vec::new(),
            process_or_service_refs: vec![reference("runtime.service")],
            observation_refs: vec![reference("proof.evidence")],
            started_at: NOW.to_owned(),
            limitations: Vec::new(),
        };
        (revision, instance)
    })
}
fn provider_with_git(
    temp: &TempRoot,
    path: PathBuf,
    protocols: impl IntoIterator<Item = GitProtocol>,
) -> GitProvider {
    let (revision, instance) = provider_fixture();
    GitProvider::open(
        path,
        temp.provider_root(),
        revision,
        instance,
        protocols,
        Arc::new(|| NOW.to_owned()),
    )
    .expect("provider")
}
fn provider(temp: &TempRoot, protocols: impl IntoIterator<Item = GitProtocol>) -> GitProvider {
    provider_with_git(temp, git_path(), protocols)
}
fn execution() -> GitExecutionContext {
    let (revision, instance) = provider_fixture();
    GitExecutionContext {
        activity_ref: reference("core.activity"),
        operation_ref: reference("core.operation"),
        attempt_ref: reference("core.attempt"),
        attempt: AttemptContext {
            node_ref: instance.node_ref.clone(),
            node_generation: instance.node_generation,
            provider_ref: revision.provider_ref.clone(),
            provider_generation: instance.provider_generation.value(),
            workload_generation: 9,
            connection_epoch: instance.connection_epoch,
            facility_ref: reference("runtime.facility"),
            producer_instance_ref: instance.instance_ref.clone(),
            producer_version: "git-cli-test".to_owned(),
        },
    }
}
fn run_git(cwd: Option<&Path>, args: &[&str]) -> Output {
    let mut cmd = Command::new(git_path());
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    cmd.args(args).output().expect("git command")
}
fn must_git(cwd: Option<&Path>, args: &[&str]) -> String {
    let output = run_git(cwd, args);
    assert!(
        output.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}
fn create_remote(temp: &TempRoot, extra: impl FnOnce(&Path)) -> String {
    fs::create_dir_all(temp.seed()).expect("seed dir");
    must_git(Some(&temp.seed()), &["init", "-b", "main"]);
    fs::write(temp.seed().join("README.md"), b"one\n").expect("readme");
    extra(&temp.seed());
    must_git(Some(&temp.seed()), &["add", "."]);
    must_git(
        Some(&temp.seed()),
        &[
            "-c",
            "user.name=Ptah",
            "-c",
            "user.email=ptah@example.invalid",
            "commit",
            "-m",
            "first",
        ],
    );
    let commit = must_git(Some(&temp.seed()), &["rev-parse", "HEAD^{commit}"]);
    must_git(
        None,
        &[
            "init",
            "--bare",
            temp.remote().to_str().expect("remote path"),
        ],
    );
    must_git(
        Some(&temp.seed()),
        &[
            "remote",
            "add",
            "origin",
            temp.remote().to_str().expect("remote path"),
        ],
    );
    must_git(
        Some(&temp.seed()),
        &["push", "origin", "HEAD:refs/heads/main"],
    );
    commit
}
fn advance_remote(temp: &TempRoot) -> String {
    fs::write(temp.seed().join("README.md"), b"two\n").expect("update");
    must_git(Some(&temp.seed()), &["add", "README.md"]);
    must_git(
        Some(&temp.seed()),
        &[
            "-c",
            "user.name=Ptah",
            "-c",
            "user.email=ptah@example.invalid",
            "commit",
            "-m",
            "second",
        ],
    );
    let commit = must_git(Some(&temp.seed()), &["rev-parse", "HEAD^{commit}"]);
    must_git(
        Some(&temp.seed()),
        &["push", "origin", "HEAD:refs/heads/main"],
    );
    commit
}
fn spec(temp: &TempRoot, mode: CloneMode) -> GitCloneSpec {
    GitCloneSpec {
        remote: temp.remote().to_string_lossy().into_owned(),
        reference: "refs/heads/main".to_owned(),
        destination: PathBuf::from(match mode {
            CloneMode::Checkout => "checkout",
            CloneMode::Mirror => "mirror.git",
        }),
        mode,
        credential_refs: vec![reference("security.credential")],
        submodule_policy: SubmodulePolicy::PreserveMetadataNoRecurse,
        lfs_policy: LfsPolicy::PreservePointers,
    }
}

fn materialization_failure(error: GitProviderError) -> GitMaterializationFailure {
    match error {
        GitProviderError::MaterializationFailed(failure) => *failure,
        other => panic!("expected materialization failure, got {other}"),
    }
}

fn loose_object_path(repo: &Path, object_id: &str) -> PathBuf {
    repo.join("objects")
        .join(&object_id[..2])
        .join(&object_id[2..])
}

#[test]
fn moving_branch_is_resolved_once_then_materialized_at_exact_old_commit() {
    let temp = TempRoot::new();
    let first = create_remote(&temp, |_| {});
    let provider = provider(&temp, [GitProtocol::File]);
    let spec = spec(&temp, CloneMode::Checkout);
    let (resolved, _) = provider
        .resolve_source(&spec, &execution())
        .expect("resolve");
    assert_eq!(resolved.resolved_commit, first);
    let second = advance_remote(&temp);
    assert_ne!(first, second);
    let materialized = provider
        .materialize_resolved(&spec, &resolved, &execution())
        .expect("materialize");
    assert_eq!(materialized.exact_commit, first);
    assert_eq!(
        must_git(
            Some(&temp.provider_root().join("checkout")),
            &["rev-parse", "HEAD^{commit}"]
        ),
        first
    );
    assert_eq!(
        materialized
            .projection_evidence
            .provider_context
            .provider_generation
            .value(),
        3
    );
}

#[test]
fn mirror_materialization_retains_exact_commit_without_worktree_claim() {
    let temp = TempRoot::new();
    let first = create_remote(&temp, |_| {});
    let provider = provider(&temp, [GitProtocol::File]);
    let spec = spec(&temp, CloneMode::Mirror);
    let (resolved, _) = provider
        .resolve_source(&spec, &execution())
        .expect("resolve");
    let materialized = provider
        .materialize_resolved(&spec, &resolved, &execution())
        .expect("mirror");
    assert_eq!(materialized.exact_commit, first);
    assert!(temp.provider_root().join("mirror.git/HEAD").exists());
    assert!(!temp.provider_root().join("mirror.git/.git").exists());
}

#[test]
fn denied_protocol_and_embedded_https_credentials_fail_before_git_execution() {
    let temp = TempRoot::new();
    let provider = provider(&temp, [GitProtocol::Https]);
    let mut request = spec(&temp, CloneMode::Checkout);
    request.remote = "file:///tmp/forbidden".to_owned();
    assert!(matches!(
        provider.resolve_source(&request, &execution()),
        Err(GitProviderError::ProtocolDenied)
    ));
    request.remote = "https://user:secret@example.invalid/repo.git".to_owned();
    assert!(matches!(
        provider.resolve_source(&request, &execution()),
        Err(GitProviderError::EmbeddedCredential)
    ));
}

#[test]
fn traversal_and_symlinked_destination_parent_are_rejected() {
    let temp = TempRoot::new();
    create_remote(&temp, |_| {});
    let provider = provider(&temp, [GitProtocol::File]);
    let mut request = spec(&temp, CloneMode::Checkout);
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("resolve");
    request.destination = PathBuf::from("../escape");
    assert!(matches!(
        provider.materialize_resolved(&request, &resolved, &execution()),
        Err(GitProviderError::UnsafeDestination)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = temp.root.join("outside");
        fs::create_dir_all(&outside).expect("outside");
        fs::create_dir_all(temp.provider_root()).expect("provider root");
        symlink(&outside, temp.provider_root().join("redirect")).expect("symlink");
        request.destination = PathBuf::from("redirect/escape");
        assert!(matches!(
            provider.materialize_resolved(&request, &resolved, &execution()),
            Err(GitProviderError::UnsafeDestination)
        ));
        assert!(!outside.join("escape").exists());
    }
}

#[test]
fn submodule_metadata_cannot_be_silently_admitted() {
    let temp = TempRoot::new();
    create_remote(&temp, |seed| {
        fs::write(
            seed.join(".gitmodules"),
            b"[submodule \"x\"]\n\tpath = x\n\turl = https://example.invalid/x.git\n",
        )
        .expect("gitmodules");
    });
    let provider = provider(&temp, [GitProtocol::File]);
    let mut request = spec(&temp, CloneMode::Checkout);
    request.submodule_policy = SubmodulePolicy::DenyIfPresent;
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("resolve");
    let failure = materialization_failure(
        provider
            .materialize_resolved(&request, &resolved, &execution())
            .expect_err("submodule policy must reject"),
    );
    assert_eq!(
        failure.failure,
        GitMaterializationFailureKind::SubmoduleDenied
    );
    assert!(failure.partial_removed);
    assert!(!temp.provider_root().join("checkout").exists());
}

#[test]
fn lfs_metadata_is_policy_gated_and_smudge_is_never_run() {
    let temp = TempRoot::new();
    create_remote(&temp, |seed| {
        fs::write(
            seed.join(".gitattributes"),
            b"*.bin filter=lfs diff=lfs merge=lfs -text\n",
        )
        .expect("attributes");
        fs::write(
            seed.join("payload.bin"),
            b"version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 4\n",
        )
        .expect("pointer");
    });
    let provider = provider(&temp, [GitProtocol::File]);
    let mut request = spec(&temp, CloneMode::Checkout);
    request.lfs_policy = LfsPolicy::DenyIfReferenced;
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("resolve");
    let failure = materialization_failure(
        provider
            .materialize_resolved(&request, &resolved, &execution())
            .expect_err("LFS policy must reject"),
    );
    assert_eq!(failure.failure, GitMaterializationFailureKind::LfsDenied);
    assert!(failure.partial_removed);
    request.destination = PathBuf::from("pointer-checkout");
    request.lfs_policy = LfsPolicy::PreservePointers;
    let materialized = provider
        .materialize_resolved(&request, &resolved, &execution())
        .expect("pointer clone");
    assert!(materialized.projection_evidence.lfs_metadata_present);
    let payload = fs::read_to_string(temp.provider_root().join("pointer-checkout/payload.bin"))
        .expect("pointer bytes");
    assert!(payload.starts_with("version https://git-lfs.github.com/spec/v1"));
}

#[test]
fn failed_clone_after_exact_resolution_retains_evidence_and_removes_partial_target() {
    let temp = TempRoot::new();
    let first = create_remote(&temp, |_| {});
    let provider = provider(&temp, [GitProtocol::File]);
    let request = spec(&temp, CloneMode::Checkout);
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("resolve before corruption");
    assert_eq!(resolved.resolved_commit, first);

    let object = loose_object_path(&temp.remote(), &first);
    assert!(object.is_file(), "fresh pushed commit should be loose");
    fs::remove_file(object).expect("corrupt remote after exact resolution");

    let failure = materialization_failure(
        provider
            .materialize_resolved(&request, &resolved, &execution())
            .expect_err("clone must fail after remote corruption"),
    );
    assert_eq!(failure.source.resolved_commit, first);
    assert!(failure.partial_removed);
    assert_eq!(
        failure.commands.first().map(|item| item.stage.as_str()),
        Some("clone")
    );
    assert!(matches!(
        failure.failure,
        GitMaterializationFailureKind::Command { ref stage, .. } if stage == "clone"
    ));
    assert!(!temp.provider_root().join("checkout").exists());
}

#[test]
fn annotated_tag_resolution_peels_to_exact_commit() {
    let temp = TempRoot::new();
    let first = create_remote(&temp, |_| {});
    must_git(
        Some(&temp.seed()),
        &[
            "-c",
            "user.name=Ptah",
            "-c",
            "user.email=ptah@example.invalid",
            "tag",
            "-a",
            "v1",
            "-m",
            "v1",
            &first,
        ],
    );
    must_git(Some(&temp.seed()), &["push", "origin", "refs/tags/v1"]);
    let tag_object = must_git(Some(&temp.seed()), &["rev-parse", "refs/tags/v1"]);
    assert_ne!(tag_object, first);

    let provider = provider(&temp, [GitProtocol::File]);
    let mut request = spec(&temp, CloneMode::Checkout);
    request.reference = "refs/tags/v1".to_owned();
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("annotated tag resolution");
    assert_eq!(resolved.resolved_commit, first);
    let materialized = provider
        .materialize_resolved(&request, &resolved, &execution())
        .expect("annotated tag materialization");
    assert_eq!(materialized.exact_commit, first);
}

#[cfg(unix)]
#[test]
fn local_clone_is_forced_through_transport_without_shared_object_hardlinks() {
    use std::os::unix::fs::MetadataExt;

    let temp = TempRoot::new();
    let first = create_remote(&temp, |_| {});
    let source_object = loose_object_path(&temp.remote(), &first);
    let before = fs::metadata(&source_object)
        .expect("source commit object")
        .nlink();

    let provider = provider(&temp, [GitProtocol::File]);
    let request = spec(&temp, CloneMode::Checkout);
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("resolve");
    let materialized = provider
        .materialize_resolved(&request, &resolved, &execution())
        .expect("clone");

    let after = fs::metadata(&source_object)
        .expect("source commit object")
        .nlink();
    assert_eq!(
        after, before,
        "--no-local must prevent source-object hardlinks"
    );
    assert!(
        materialized.commands[0]
            .argv
            .iter()
            .any(|arg| arg == "--no-local")
    );
}

#[test]
fn network_query_or_fragment_secret_surfaces_fail_closed_before_execution() {
    let temp = TempRoot::new();
    let provider = provider(&temp, [GitProtocol::Https]);
    let mut request = spec(&temp, CloneMode::Checkout);
    request.remote = "https://example.invalid/repo.git?access_token=secret".to_owned();
    assert!(matches!(
        provider.resolve_source(&request, &execution()),
        Err(GitProviderError::EmbeddedCredential)
    ));
    request.remote = "https://example.invalid/repo.git#secret".to_owned();
    assert!(matches!(
        provider.resolve_source(&request, &execution()),
        Err(GitProviderError::EmbeddedCredential)
    ));
}

#[cfg(unix)]
#[test]
fn hostile_global_hook_configuration_cannot_execute_checkout_hook() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempRoot::new();
    create_remote(&temp, |_| {});
    let hostile_hooks = temp.root.join("hostile-hooks");
    fs::create_dir_all(&hostile_hooks).expect("hostile hooks");
    let marker = temp.root.join("hook-ran");
    let hook = hostile_hooks.join("post-checkout");
    fs::write(
        &hook,
        format!("#!/bin/sh\nprintf ran > '{}'\n", marker.display()),
    )
    .expect("hook");
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("hook mode");
    let malicious_config = temp.root.join("malicious.gitconfig");
    fs::write(
        &malicious_config,
        format!("[core]\n\thooksPath = {}\n", hostile_hooks.display()),
    )
    .expect("malicious config");

    let wrapper = temp.root.join("git-wrapper.sh");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexport GIT_CONFIG_GLOBAL='{}'\nexec '{}' \"$@\"\n",
            malicious_config.display(),
            git_path().display(),
        ),
    )
    .expect("wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).expect("wrapper mode");

    let provider = provider_with_git(&temp, wrapper, [GitProtocol::File]);
    let request = spec(&temp, CloneMode::Checkout);
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("resolve");
    let materialized = provider
        .materialize_resolved(&request, &resolved, &execution())
        .expect("materialize");
    assert!(materialized.projection_evidence.hooks_suppressed);
    assert!(
        !marker.exists(),
        "hostile post-checkout hook must not execute"
    );
}

#[test]
fn stale_provider_generation_is_rejected_before_git_execution() {
    let temp = TempRoot::new();
    create_remote(&temp, |_| {});
    let provider = provider(&temp, [GitProtocol::File]);
    let mut context = execution();
    context.attempt.provider_generation += 1;
    assert!(matches!(
        provider.resolve_source(&spec(&temp, CloneMode::Checkout), &context),
        Err(GitProviderError::ExecutionContextMismatch)
    ));
}

#[test]
fn materialization_returns_projection_evidence_not_a07_identity() {
    let temp = TempRoot::new();
    let first = create_remote(&temp, |_| {});
    let provider = provider(&temp, [GitProtocol::File]);
    let request = spec(&temp, CloneMode::Checkout);
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("resolve");
    let materialized = provider
        .materialize_resolved(&request, &resolved, &execution())
        .expect("clone");
    assert_eq!(materialized.exact_commit, first);
    assert_eq!(
        materialized.materialization_ref.entity_kind.as_str(),
        "git.materialization"
    );
    assert_ne!(
        materialized.materialization_ref.entity_kind.as_str(),
        "object.object"
    );
    assert_ne!(
        materialized.materialization_ref.entity_kind.as_str(),
        "object.revision"
    );
    assert!(materialized.projection_evidence.hooks_suppressed);
}
