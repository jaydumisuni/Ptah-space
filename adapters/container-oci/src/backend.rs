use crate::{
    BackendCompletion, BackendLaunchPlan, BackendStartAck, CONTAINERD_VERSION, MountAccess,
    OciBackend, OciProviderError, RUNC_BINARY_SHA256, RUNC_VERSION,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, MutexGuard},
    thread::JoinHandle,
};

const CTR_BINARY_SHA256: &str = "adb91679d414d86b09bfff2b0091b6de0a1ab9af8fba44ceab0f5a1f40f77817";

/// Clock used for retained backend evidence timestamps.
pub type OciClock = Arc<dyn Fn() -> String + Send + Sync>;

/// Pinned `ctr`/runc mechanical backend for an already-qualified containerd Provider instance.
///
/// The enclosing [`crate::OciProvider`] owns identity, generation and policy
/// validation. This type owns only command construction, subprocess start and
/// terminal process observation. It never promotes a container ID to canonical
/// identity.
pub struct ContainerdCliBackend {
    ctr_path: PathBuf,
    runc_path: PathBuf,
    address: String,
    namespace: String,
    clock: OciClock,
    running: Mutex<HashMap<String, Child>>,
}

impl ContainerdCliBackend {
    /// Open a mechanical backend and qualify the exact `ctr` and runc executable
    /// bytes before either executable is invoked, then verify their locked versions.
    ///
    /// # Errors
    /// Fails for missing tools, executable-digest/version drift, a non-absolute
    /// local containerd socket path, or an invalid namespace token.
    pub fn open(
        ctr_path: impl AsRef<Path>,
        runc_path: impl AsRef<Path>,
        address: impl Into<String>,
        namespace: impl Into<String>,
        clock: OciClock,
    ) -> Result<Self, OciProviderError> {
        let ctr_path = std::fs::canonicalize(ctr_path.as_ref())?;
        let runc_path = std::fs::canonicalize(runc_path.as_ref())?;
        if !ctr_path.is_file() {
            return Err(OciProviderError::InvalidSpec("ctr_path"));
        }
        if !runc_path.is_file() {
            return Err(OciProviderError::InvalidSpec("runc_path"));
        }
        let address = address.into();
        let namespace = namespace.into();
        if !Path::new(&address).is_absolute()
            || address.len() > 4096
            || address.contains(['\0', '\n', '\r'])
        {
            return Err(OciProviderError::InvalidSpec("containerd address"));
        }
        if namespace.is_empty()
            || namespace.len() > 128
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(OciProviderError::InvalidSpec("containerd namespace"));
        }

        if sha256_file(&ctr_path)? != CTR_BINARY_SHA256 {
            return Err(OciProviderError::BackendPinMismatch(
                "ctr executable digest",
            ));
        }
        if sha256_file(&runc_path)? != RUNC_BINARY_SHA256 {
            return Err(OciProviderError::BackendPinMismatch(
                "runc executable digest",
            ));
        }

        let ctr_version = qualified_command(&ctr_path).arg("--version").output()?;
        if !ctr_version.status.success()
            || !has_exact_version_token(&ctr_version.stdout, CONTAINERD_VERSION)
        {
            return Err(OciProviderError::BackendPinMismatch("ctr version"));
        }
        let runc_version = qualified_command(&runc_path).arg("--version").output()?;
        if !runc_version.status.success()
            || !has_exact_version_token(&runc_version.stdout, RUNC_VERSION)
        {
            return Err(OciProviderError::BackendPinMismatch("runc version"));
        }

        Ok(Self {
            ctr_path,
            runc_path,
            address,
            namespace,
            clock,
            running: Mutex::new(HashMap::new()),
        })
    }

    /// Return the exact runc path qualified by this backend.
    #[must_use]
    pub fn runc_path(&self) -> &Path {
        &self.runc_path
    }

    fn command(&self, plan: &BackendLaunchPlan) -> Command {
        let mut command = qualified_command(&self.ctr_path);
        command
            .arg("--address")
            .arg(&self.address)
            .arg("--namespace")
            .arg(&self.namespace)
            .arg("run")
            .arg("--rm")
            .arg("--runtime")
            .arg("io.containerd.runc.v2")
            .arg("--runc-binary")
            .arg(&self.runc_path)
            .arg("--memory-limit")
            .arg(plan.resources.memory_bytes.to_string())
            .arg("--cpu-period")
            .arg(plan.resources.cpu_period_micros.to_string())
            .arg("--cpu-quota")
            .arg(plan.resources.cpu_quota_micros.to_string());
        if plan.host_network {
            command.arg("--net-host");
        }
        for mount in &plan.mounts {
            let access = match mount.access {
                MountAccess::ReadOnly => "ro",
                MountAccess::ReadWrite => "rw",
            };
            command.arg("--mount").arg(format!(
                "type=bind,src={},dst={},options=rbind:{access}",
                mount.source_alias, mount.destination
            ));
        }
        command
            .arg(&plan.image_reference)
            .arg(&plan.container_alias)
            .args(&plan.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

impl OciBackend for ContainerdCliBackend {
    fn start(&self, plan: &BackendLaunchPlan) -> Result<BackendStartAck, OciProviderError> {
        let mut running = lock(&self.running)?;
        if running.contains_key(&plan.container_alias) {
            return Err(OciProviderError::Backend(
                "duplicate backend container alias".to_owned(),
            ));
        }
        let child = self.command(plan).spawn()?;
        running.insert(plan.container_alias.clone(), child);
        Ok(BackendStartAck {
            container_alias: plan.container_alias.clone(),
            observed_at: (self.clock)(),
            detail: "ctr launch submitted; this acknowledgement is not workload success".to_owned(),
        })
    }

    fn wait(
        &self,
        start: &BackendStartAck,
        max_output_bytes: usize,
    ) -> Result<BackendCompletion, OciProviderError> {
        let mut child = lock(&self.running)?
            .remove(&start.container_alias)
            .ok_or(OciProviderError::InvalidBackendAck)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| OciProviderError::Backend("ctr stdout pipe unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| OciProviderError::Backend("ctr stderr pipe unavailable".to_owned()))?;
        let stdout_reader =
            std::thread::spawn(move || read_bounded_suffix(stdout, max_output_bytes));
        let stderr_reader =
            std::thread::spawn(move || read_bounded_suffix(stderr, max_output_bytes));

        let status = child.wait();
        let stdout = join_output_reader(stdout_reader, "stdout");
        let stderr = join_output_reader(stderr_reader, "stderr");
        let status = status?;
        let (stdout, stdout_truncated_bytes) = stdout?;
        let (stderr, stderr_truncated_bytes) = stderr?;

        Ok(BackendCompletion {
            observed_at: (self.clock)(),
            exit_code: status.code(),
            success: status.success(),
            stdout,
            stderr,
            stdout_truncated_bytes,
            stderr_truncated_bytes,
        })
    }
}

fn sha256_file(path: &Path) -> Result<String, OciProviderError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn has_exact_version_token(stdout: &[u8], expected: &str) -> bool {
    let expected_with_v = format!("v{expected}");
    String::from_utf8_lossy(stdout)
        .split_ascii_whitespace()
        .any(|token| token == expected || token == expected_with_v)
}

fn read_bounded_suffix<R: Read>(mut reader: R, max: usize) -> io::Result<(Vec<u8>, u64)> {
    let mut retained = VecDeque::new();
    let mut dropped = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        retained.extend(&buffer[..read]);
        let overflow = retained.len().saturating_sub(max);
        if overflow != 0 {
            retained.drain(..overflow);
            dropped = dropped.saturating_add(u64::try_from(overflow).unwrap_or(u64::MAX));
        }
    }
    Ok((retained.into_iter().collect(), dropped))
}

fn join_output_reader(
    handle: JoinHandle<io::Result<(Vec<u8>, u64)>>,
    stream: &'static str,
) -> Result<(Vec<u8>, u64), OciProviderError> {
    handle
        .join()
        .map_err(|_| OciProviderError::Backend(format!("ctr {stream} reader thread panicked")))?
        .map_err(OciProviderError::from)
}

fn qualified_command(path: &Path) -> Command {
    let mut command = Command::new(path);
    command.env_clear().env("LANG", "C").env("LC_ALL", "C");
    command
}

impl Drop for ContainerdCliBackend {
    fn drop(&mut self) {
        if let Ok(running) = self.running.get_mut() {
            for child in running.values_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            running.clear();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, OciProviderError> {
    mutex
        .lock()
        .map_err(|_| OciProviderError::Backend("OCI backend state lock poisoned".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResourceLimits;
    use std::io::Cursor;

    #[test]
    fn launch_command_binds_the_exact_qualified_runc_path() {
        let backend = ContainerdCliBackend {
            ctr_path: PathBuf::from("/opt/ptah/containerd/bin/ctr"),
            runc_path: PathBuf::from("/opt/ptah/containerd/bin/runc"),
            address: "/run/ptah/containerd.sock".to_owned(),
            namespace: "ptah-a10".to_owned(),
            clock: Arc::new(|| "2026-08-21T00:00:00Z".to_owned()),
            running: Mutex::new(HashMap::new()),
        };
        let plan = BackendLaunchPlan {
            image_reference: "registry.example/tool@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            container_alias: "ptah-a10-test".to_owned(),
            args: Vec::new(),
            resources: ResourceLimits {
                memory_bytes: 64 * 1024 * 1024,
                cpu_period_micros: 100_000,
                cpu_quota_micros: 50_000,
            },
            host_network: false,
            mounts: Vec::new(),
            max_output_bytes: 64 * 1024,
        };

        let command = backend.command(&plan);
        let args: Vec<_> = command.get_args().collect();
        let bound_runc = args
            .iter()
            .position(|arg| *arg == "--runc-binary")
            .and_then(|flag| args.get(flag + 1))
            .copied();
        assert_eq!(bound_runc, Some(backend.runc_path.as_os_str()));
    }

    #[test]
    fn exact_version_tokens_reject_prefix_drift() {
        assert!(has_exact_version_token(
            b"ctr github.com/containerd/containerd/v2 v2.3.1 abc",
            CONTAINERD_VERSION
        ));
        assert!(!has_exact_version_token(
            b"ctr github.com/containerd/containerd/v2 v2.3.10 abc",
            CONTAINERD_VERSION
        ));
        assert!(has_exact_version_token(
            b"runc version 1.4.2\ncommit: abc",
            RUNC_VERSION
        ));
        assert!(!has_exact_version_token(
            b"runc version 1.4.20\ncommit: abc",
            RUNC_VERSION
        ));
    }

    #[test]
    fn bounded_reader_retains_only_suffix_and_counts_discarded_bytes() {
        let source = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let (retained, dropped) =
            read_bounded_suffix(Cursor::new(source), 10).expect("bounded read");
        assert_eq!(retained, b"qrstuvwxyz");
        assert_eq!(dropped, 26);

        let (retained, dropped) =
            read_bounded_suffix(Cursor::new(source), 0).expect("zero retention read");
        assert!(retained.is_empty());
        assert_eq!(dropped, u64::try_from(source.len()).expect("small source"));
    }

    #[cfg(unix)]
    #[test]
    fn ctr_digest_mismatch_is_rejected_before_the_candidate_is_executed() {
        use std::{
            fs,
            os::unix::fs::PermissionsExt,
            process,
            time::{SystemTime, UNIX_EPOCH},
        };

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ptah-a10-hash-before-exec-{}-{nonce}",
            process::id()
        ));
        fs::create_dir_all(&root).expect("create temp root");
        let ctr = root.join("ctr");
        let runc = root.join("runc");
        fs::write(
            &ctr,
            "#!/bin/sh\n: > \"$0.executed\"\nprintf 'ctr github.com/containerd/containerd/v2 v2.3.1\\n'\n",
        )
        .expect("write fake ctr");
        fs::write(&runc, "not the locked runc bytes\n").expect("write fake runc");
        let mut permissions = fs::metadata(&ctr).expect("ctr metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&ctr, permissions).expect("make fake ctr executable");
        let marker = PathBuf::from(format!("{}.executed", ctr.display()));

        let result = ContainerdCliBackend::open(
            &ctr,
            &runc,
            "/run/ptah/containerd.sock",
            "ptah-a10",
            Arc::new(|| "2026-08-21T00:00:00Z".to_owned()),
        );
        assert!(matches!(
            result,
            Err(OciProviderError::BackendPinMismatch(
                "ctr executable digest"
            ))
        ));
        assert!(!marker.exists(), "untrusted ctr bytes were executed");

        fs::remove_dir_all(root).expect("remove temp root");
    }
}
