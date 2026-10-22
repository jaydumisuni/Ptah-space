//! Optional, bounded Node-local exact candidate source for E03.
//! Not a verifier, E03 issuer, nor authority to replay execution.
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub fn persist_candidate_once(
    dir: &Path,
    attempt: &str,
    bytes: &[u8],
) -> Result<(PathBuf, String), String> {
    if bytes.is_empty() || bytes.len() > 16384 {
        return Err("candidate empty or exceeds captured stdout ceiling".into());
    }
    if attempt.is_empty()
        || attempt.len() > 128
        || !attempt
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("unsafe candidate attempt identity".into());
    }
    let metadata = dir
        .symlink_metadata()
        .map_err(|e| format!("candidate workspace unavailable: {e}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("candidate directory must be an existing real directory".into());
    }
    let digest = format!("{:x}", Sha256::digest(bytes));
    let final_path = dir.join(format!("formula-{attempt}-{digest}.bin"));
    let temp_path = dir.join(format!(
        ".formula-{attempt}-{}.part",
        ptah_identifiers::EntityId::new_v7()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result = (|| -> Result<(), String> {
        let mut file = options
            .open(&temp_path)
            .map_err(|e| format!("candidate create: {e}"))?;
        file.write_all(bytes)
            .map_err(|e| format!("candidate write: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("candidate flush: {e}"))?;
        drop(file);
        // Atomic create-if-absent across Windows NTFS and Linux. A retry
        // cannot replace an independently persisted candidate.
        match fs::hard_link(&temp_path, &final_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = final_path
                    .symlink_metadata()
                    .map_err(|e| format!("candidate metadata: {e}"))?;
                if !meta.is_file()
                    || meta.file_type().is_symlink()
                    || fs::read(&final_path).map_err(|e| format!("candidate readback: {e}"))?
                        != bytes
                {
                    return Err("existing candidate conflicts with exact output".into());
                }
            }
            Err(e) => return Err(format!("candidate atomic commit: {e}")),
        }
        let readback = fs::read(&final_path).map_err(|e| format!("candidate readback: {e}"))?;
        if readback != bytes {
            return Err("candidate persistence differs from observed output".into());
        }
        Ok(())
    })();
    let _ = fs::remove_file(&temp_path);
    write_result?;
    Ok((final_path, format!("sha256:{digest}")))
}
/// Reopen a durably published A05 candidate as the exact range source for
/// Ptah's EXISTING E03 transfer engine. Current E01/E02/E03 tickets and leases
/// are still independently owned and checked by the transport authority.
pub struct DurableCandidateSource {
    file: fs::File,
    len: u64,
    sha256: String,
}
impl DurableCandidateSource {
    pub fn open(path: &Path, expected_stdout_sha256: &str) -> Result<Self, String> {
        use std::io::{Read, Seek, SeekFrom};
        let meta = path
            .symlink_metadata()
            .map_err(|e| format!("candidate metadata: {e}"))?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() == 0 || meta.len() > 16384
        {
            return Err("unsafe persisted candidate source".into());
        }
        let mut file = fs::File::open(path).map_err(|e| format!("candidate open: {e}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("candidate read: {e}"))?;
        if bytes.len() as u64 != meta.len() {
            return Err("candidate size changed".into());
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        if format!("sha256:{sha256}") != expected_stdout_sha256 {
            return Err("candidate evidence digest mismatch".into());
        }
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        Ok(Self {
            file,
            len: meta.len(),
            sha256,
        })
    }
}
impl ptah_node_transfer::ExactRangeSource for DurableCandidateSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn canonical_sha256(&self) -> &str {
        &self.sha256
    }
    fn read_exact_range(&mut self, start: u64, len: u64) -> Result<Vec<u8>, String> {
        use std::io::{Read, Seek, SeekFrom};
        let end = start.checked_add(len).ok_or("candidate range overflow")?;
        if end > self.len || len > ptah_node_transfer::MAX_RANGE_BYTES as u64 {
            return Err("candidate range out of bounds".into());
        }
        self.file
            .seek(SeekFrom::Start(start))
            .map_err(|e| e.to_string())?;
        let size = usize::try_from(len).map_err(|e| e.to_string())?;
        let mut bytes = vec![0_u8; size];
        self.file
            .read_exact(&mut bytes)
            .map_err(|e| e.to_string())?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ptah-e07-candidate-{}",
            ptah_identifiers::EntityId::new_v7()
        ));
        fs::create_dir(&p).unwrap();
        p
    }
    #[test]
    fn exact_output_survives_reopen_and_replay_without_duplicate_files() {
        let dir = directory();
        let (path, digest) = persist_candidate_once(&dir, "attempt-1", b"9\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"9\n");

        use ptah_node_transfer::ExactRangeSource;
        let mut source = DurableCandidateSource::open(&path, &digest).unwrap();
        assert_eq!(source.len(), 2);
        assert_eq!(source.read_exact_range(0, 2).unwrap(), b"9\n");
        assert!(source.read_exact_range(2, 1).is_err());
        assert_eq!(
            source.canonical_sha256(),
            digest.strip_prefix("sha256:").unwrap()
        );
        assert_eq!(
            persist_candidate_once(&dir, "attempt-1", b"9\n").unwrap(),
            (path.clone(), digest)
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn invalid_or_conflicting_output_cannot_overwrite_proof() {
        let dir = directory();
        let (path, _) = persist_candidate_once(&dir, "attempt-1", b"9\n").unwrap();
        assert!(persist_candidate_once(&dir, "../escape", b"x").is_err());
        assert!(persist_candidate_once(&dir, "attempt-1", &[]).is_err());
        fs::write(&path, b"corrupted").unwrap();
        let original = format!("sha256:{:x}", Sha256::digest(b"9\n"));
        assert!(DurableCandidateSource::open(&path, &original).is_err());
        assert!(persist_candidate_once(&dir, "attempt-1", b"9\n").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"corrupted");
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn candidate_workspace_must_exist() {
        let dir = directory();
        fs::remove_dir_all(&dir).unwrap();
        assert!(persist_candidate_once(&dir, "attempt-1", b"9\n").is_err());
    }
}
