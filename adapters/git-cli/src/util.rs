use crate::{GitProtocol, GitProviderError};
use std::{
    fs, io,
    path::{Component, Path, PathBuf},
};

pub(crate) const OUTPUT_LIMIT: usize = 64 * 1024;

pub(crate) fn detect_protocol(remote: &str) -> Result<GitProtocol, GitProviderError> {
    let remote = remote.trim();
    if remote.is_empty() {
        return Err(GitProviderError::InvalidSpec("remote"));
    }
    if remote.starts_with("https://") {
        reject_network_secret_surfaces(remote, "https://")?;
        return Ok(GitProtocol::Https);
    }
    if remote.starts_with("ssh://") {
        reject_network_secret_surfaces(remote, "ssh://")?;
        return Ok(GitProtocol::Ssh);
    }
    if remote.starts_with("git://") {
        reject_network_secret_surfaces(remote, "git://")?;
        return Ok(GitProtocol::Git);
    }
    if remote.starts_with("file://") || Path::new(remote).is_absolute() {
        return Ok(GitProtocol::File);
    }
    if remote.contains('@') && remote.contains(':') && !remote.contains("://") {
        return Ok(GitProtocol::Ssh);
    }
    Err(GitProviderError::ProtocolDenied)
}

fn reject_network_secret_surfaces(remote: &str, prefix: &str) -> Result<(), GitProviderError> {
    let rest = remote
        .strip_prefix(prefix)
        .ok_or(GitProviderError::InvalidSpec("remote"))?;
    let authority = rest
        .split('/')
        .next()
        .ok_or(GitProviderError::InvalidSpec("remote"))?;
    if authority.contains('@') && prefix == "https://" {
        return Err(GitProviderError::EmbeddedCredential);
    }
    if rest.contains('?') || rest.contains('#') {
        return Err(GitProviderError::EmbeddedCredential);
    }
    Ok(())
}

pub(crate) fn validate_commit_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn canonical_root(path: &Path) -> Result<PathBuf, GitProviderError> {
    fs::create_dir_all(path)?;
    let root = fs::canonicalize(path)?;
    let metadata = fs::symlink_metadata(&root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GitProviderError::UnsafeDestination);
    }
    Ok(root)
}

pub(crate) fn safe_new_destination(
    root: &Path,
    relative: &Path,
) -> Result<PathBuf, GitProviderError> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(GitProviderError::UnsafeDestination);
    }
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_os_string()),
            _ => return Err(GitProviderError::UnsafeDestination),
        }
    }
    let (name, parents) = parts
        .split_last()
        .ok_or(GitProviderError::UnsafeDestination)?;
    let mut current = root.to_path_buf();
    for component in parents {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(GitProviderError::UnsafeDestination);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                let metadata = fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(GitProviderError::UnsafeDestination);
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    let parent = fs::canonicalize(current)?;
    if !parent.starts_with(root) {
        return Err(GitProviderError::UnsafeDestination);
    }
    let target = parent.join(name);
    if fs::symlink_metadata(&target).is_ok() {
        return Err(GitProviderError::UnsafeDestination);
    }
    Ok(target)
}

pub(crate) fn bounded_text(bytes: &[u8]) -> String {
    let bytes = if bytes.len() > OUTPUT_LIMIT {
        &bytes[..OUTPUT_LIMIT]
    } else {
        bytes
    };
    String::from_utf8_lossy(bytes).into_owned()
}

pub(crate) fn remote_label(remote: &str) -> String {
    let remote = remote.split_once('#').map_or(remote, |(value, _)| value);
    let remote = remote.split_once('?').map_or(remote, |(value, _)| value);
    if let Some(rest) = remote.strip_prefix("ssh://")
        && let Some((_, host_path)) = rest.split_once('@')
    {
        return format!("ssh://{host_path}");
    }
    if !remote.contains("://")
        && let Some((_, host_path)) = remote.split_once('@')
        && host_path.contains(':')
    {
        return host_path.to_owned();
    }
    remote.to_owned()
}
