use crate::{
    BackendCompletion, BackendLaunchPlan, BackendStartAck, MountAccess, OciBackend,
    OciProviderError, CONTAINERD_VERSION, RUNC_BINARY_SHA256, RUNC_VERSION,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, MutexGuard},
};

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
    /// Open a mechanical backend and qualify exact tool versions plus the locked
    /// runc executable digest.
    ///
    /// The containerd release-archive digest remains validated by
    /// [`crate::OciProvider::new`] because `ctr` has no separately frozen artifact
    /// digest in the Phase 0C lock.
    ///
    /// # Errors
    /// Fails for missing tools, version drift, wrong runc bytes, a non-absolute
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

        let ctr_version = qualified_command(&ctr_path).arg("--version").output()?;
        if !ctr_version.status.success()
            || !String::from_utf8_lossy(&ctr_version.stdout).contains(CONTAINERD_VERSION)
        {
            return Err(OciProviderError::BackendPinMismatch("ctr version"));
        }
        let runc_version = qualified_command(&runc_path).arg("--version").output()?;
        if !runc_version.status.success()
            || !String::from_utf8_lossy(&runc_version.stdout).contains(RUNC_VERSION)
        {
            return Err(OciProviderError::BackendPinMismatch("runc version"));
        }
        if sha256_file(&runc_path)? != RUNC_BINARY_SHA256 {
            return Err(OciProviderError::BackendPinMismatch(
                "runc executable digest",
            ));
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
        let child = lock(&self.running)?
            .remove(&start.container_alias)
            .ok_or(OciProviderError::InvalidBackendAck)?;
        let output = child.wait_with_output()?;
        let (stdout, stdout_truncated_bytes) = bounded_suffix(output.stdout, max_output_bytes);
        let (stderr, stderr_truncated_bytes) = bounded_suffix(output.stderr, max_output_bytes);
        Ok(BackendCompletion {
            observed_at: (self.clock)(),
            exit_code: output.status.code(),
            success: output.status.success(),
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

fn bounded_suffix(bytes: Vec<u8>, max: usize) -> (Vec<u8>, u64) {
    if bytes.len() <= max {
        return (bytes, 0);
    }
    let dropped = bytes.len() - max;
    (
        bytes[dropped..].to_vec(),
        u64::try_from(dropped).map_or(u64::MAX, |value| value),
    )
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
