//! A09 review-hardening regressions.

use git_cli::{
    CloneMode, GitCloneSpec, GitExecutionContext, GitMaterializationFailureKind, GitProtocol,
    GitProvider, GitProviderError, LfsPolicy, SubmodulePolicy,
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
    process::Command,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const NOW: &str = "2026-08-21T23:00:00Z";

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ptah-a09-hardening-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("temp root");
        Self(root)
    }

    fn provider_root(&self) -> PathBuf {
        self.0.join("provider")
    }

    fn seed(&self) -> PathBuf {
        self.0.join("seed")
    }

    fn remote(&self) -> PathBuf {
        self.0.join("remote.git")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("entity ref")
}

fn git_path() -> PathBuf {
    let output = Command::new("sh")
        .args(["-lc", "command -v git"])
        .output()
        .expect("find git");
    assert!(output.status.success());
    PathBuf::from(String::from_utf8(output.stdout).expect("utf8").trim())
}

fn fixture() -> &'static (ProviderRevision, ProviderInstance) {
    static FIXTURE: OnceLock<(ProviderRevision, ProviderInstance)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let revision = ProviderRevision {
            revision_ref: reference("runtime.provider_revision"),
            provider_ref: reference("runtime.provider"),
            provider_kind: ProviderKind::Process,
            implementation_name: "git-cli".to_owned(),
            implementation_version: "review-hardening".to_owned(),
            build_or_package_digest: "sha256:a09-review-hardening".to_owned(),
            configuration_digest: "sha256:a09-review-hardening-config".to_owned(),
            supported_facility_refs: vec![reference("runtime.facility")],
            capability_claim_refs: vec![reference("capability.claim")],
            dependency_refs: vec![reference("proof.evidence")],
            node_requirements: Vec::new(),
            security_requirements: vec!["git_hardening".to_owned()],
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

fn execution() -> GitExecutionContext {
    let (revision, instance) = fixture();
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
            producer_version: "a09-review-hardening".to_owned(),
        },
    }
}

fn provider_with_git(
    temp: &TempRoot,
    git: impl AsRef<Path>,
    protocols: impl IntoIterator<Item = GitProtocol>,
) -> GitProvider {
    let (revision, instance) = fixture();
    GitProvider::open(
        git,
        temp.provider_root(),
        revision,
        instance,
        protocols,
        Arc::new(|| NOW.to_owned()),
    )
    .expect("provider")
}

fn must_git(cwd: Option<&Path>, args: &[&str]) -> String {
    let mut command = Command::new(git_path());
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.output().expect("git command");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8")
        .trim()
        .to_owned()
}

fn create_remote(temp: &TempRoot, populate: impl FnOnce(&Path)) {
    fs::create_dir_all(temp.seed()).expect("seed");
    must_git(Some(&temp.seed()), &["init", "-b", "main"]);
    fs::write(temp.seed().join("README.md"), b"A09\n").expect("readme");
    populate(&temp.seed());
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
            "seed",
        ],
    );
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
}

fn spec(temp: &TempRoot) -> GitCloneSpec {
    GitCloneSpec {
        remote: temp.remote().to_string_lossy().into_owned(),
        reference: "refs/heads/main".to_owned(),
        destination: PathBuf::from("checkout"),
        mode: CloneMode::Checkout,
        credential_refs: vec![reference("security.credential")],
        submodule_policy: SubmodulePolicy::PreserveMetadataNoRecurse,
        lfs_policy: LfsPolicy::PreservePointers,
    }
}

#[test]
fn option_shaped_remote_reference_and_shorthand_reference_fail_before_git() {
    let temp = TempRoot::new();
    let provider = provider_with_git(&temp, git_path(), [GitProtocol::Ssh, GitProtocol::File]);
    let mut request = spec(&temp);
    request.remote = "--upload-pack=evil@host:repo".to_owned();
    assert!(matches!(
        provider.resolve_source(&request, &execution()),
        Err(GitProviderError::InvalidSpec("remote"))
    ));

    request.remote = temp.remote().to_string_lossy().into_owned();
    request.reference = "--config".to_owned();
    assert!(matches!(
        provider.resolve_source(&request, &execution()),
        Err(GitProviderError::InvalidSpec("reference"))
    ));

    request.reference = "main".to_owned();
    assert!(matches!(
        provider.resolve_source(&request, &execution()),
        Err(GitProviderError::InvalidSpec("reference"))
    ));
}

#[test]
fn ssh_password_surfaces_fail_before_execution() {
    let temp = TempRoot::new();
    let provider = provider_with_git(&temp, git_path(), [GitProtocol::Ssh]);
    let mut request = spec(&temp);
    request.remote = "ssh://user:secret@example.invalid/repo.git".to_owned();
    assert!(matches!(
        provider.resolve_source(&request, &execution()),
        Err(GitProviderError::EmbeddedCredential)
    ));
    request.remote = "user:secret@example.invalid:repo.git".to_owned();
    assert!(matches!(
        provider.resolve_source(&request, &execution()),
        Err(GitProviderError::EmbeddedCredential)
    ));
}

#[test]
fn lfs_detection_does_not_truncate_after_128_attribute_files() {
    let temp = TempRoot::new();
    create_remote(&temp, |seed| {
        for index in 0..140 {
            let dir = seed.join(format!("d{index:03}"));
            fs::create_dir_all(&dir).expect("attribute dir");
            let bytes: &[u8] = if index == 139 {
                b"*.bin filter=lfs diff=lfs merge=lfs -text\n"
            } else {
                b"*.txt text\n"
            };
            fs::write(dir.join(".gitattributes"), bytes).expect("attributes");
        }
        fs::write(seed.join("foo.gitattributes"), b"*.bin filter=lfs\n").expect("decoy");
    });
    let provider = provider_with_git(&temp, git_path(), [GitProtocol::File]);
    let mut request = spec(&temp);
    request.lfs_policy = LfsPolicy::DenyIfReferenced;
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("resolve");
    let error = provider
        .materialize_resolved(&request, &resolved, &execution())
        .expect_err("late LFS metadata must be rejected");
    let GitProviderError::MaterializationFailed(failure) = error else {
        panic!("expected retained materialization failure");
    };
    assert_eq!(failure.failure, GitMaterializationFailureKind::LfsDenied);
}

#[cfg(unix)]
#[test]
fn submodule_inspection_command_failure_is_not_treated_as_absence() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempRoot::new();
    create_remote(&temp, |_| {});
    let real_git = git_path();
    let wrapper = temp.0.join("git-wrapper.sh");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = ls-tree ]; then\n    printf 'forced tree inspection failure\\n' >&2\n    exit 73\n  fi\ndone\nexec '{}' \"$@\"\n",
            real_git.display()
        ),
    )
    .expect("wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).expect("mode");

    let provider = provider_with_git(&temp, &wrapper, [GitProtocol::File]);
    let request = spec(&temp);
    let (resolved, _) = provider
        .resolve_source(&request, &execution())
        .expect("resolve");
    let error = provider
        .materialize_resolved(&request, &resolved, &execution())
        .expect_err("inspection failure must fail closed");
    let GitProviderError::MaterializationFailed(failure) = error else {
        panic!("expected retained materialization failure");
    };
    assert!(matches!(
        failure.failure,
        GitMaterializationFailureKind::Command { ref stage, exit_code: 73, .. }
            if stage == "inspect_tree_path"
    ));
}
