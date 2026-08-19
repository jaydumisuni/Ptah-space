use super::{EntityRef, TransferError};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

const HASH_BUFFER: usize = 16 * 1024;

pub(crate) fn canonicalize_root(path: &Path) -> Result<PathBuf, TransferError> {
    fs::create_dir_all(path)?;
    let root = fs::canonicalize(path)?;
    let metadata = fs::symlink_metadata(&root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TransferError::UnsafeDestination);
    }
    Ok(root)
}

pub(crate) fn safe_relative_path(root: &Path, relative: &Path) -> Result<PathBuf, TransferError> {
    let parts = safe_components(relative)?;
    let (file_name, parents) = parts.split_last().ok_or(TransferError::UnsafeDestination)?;
    let mut current = root.to_path_buf();
    for component in parents {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(TransferError::UnsafeDestination);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                let metadata = fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(TransferError::UnsafeDestination);
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    let canonical_parent = fs::canonicalize(&current)?;
    if !canonical_parent.starts_with(root) {
        return Err(TransferError::UnsafeDestination);
    }
    Ok(canonical_parent.join(file_name))
}

pub(crate) fn safe_existing_path(root: &Path, relative: &Path) -> Result<PathBuf, TransferError> {
    let parts = safe_components(relative)?;
    let mut current = root.to_path_buf();
    for (index, component) in parts.iter().enumerate() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        let last = index + 1 == parts.len();
        if metadata.file_type().is_symlink()
            || (last && !metadata.is_file())
            || (!last && !metadata.is_dir())
        {
            return Err(TransferError::UnsafeDestination);
        }
    }
    let canonical = fs::canonicalize(&current)?;
    if !canonical.starts_with(root) {
        return Err(TransferError::UnsafeDestination);
    }
    Ok(canonical)
}

fn safe_components(relative: &Path) -> Result<Vec<std::ffi::OsString>, TransferError> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(TransferError::UnsafeDestination);
    }
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_os_string()),
            _ => return Err(TransferError::UnsafeDestination),
        }
    }
    if parts.is_empty() {
        return Err(TransferError::UnsafeDestination);
    }
    Ok(parts)
}

pub(crate) fn partial_path(root: &Path, run_ref: &EntityRef) -> PathBuf {
    root.join(format!("{}.partial", run_ref.entity_id))
}

pub(crate) fn sha256_reader(mut reader: impl Read) -> Result<(String, u64), TransferError> {
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; HASH_BUFFER];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(u64::try_from(read).map_err(|_| TransferError::AccountingOverflow)?)
            .ok_or(TransferError::AccountingOverflow)?;
    }
    Ok((format!("{:x}", hasher.finalize()), size))
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn utc_shape(value: &str) -> bool {
    let Some(without_z) = value.strip_suffix('Z') else {
        return false;
    };
    let Some(separator) = without_z.find(['T', 't']) else {
        return false;
    };
    let (date, time_with_separator) = without_z.split_at(separator);
    let time = &time_with_separator[1..];
    if date.len() != 10
        || date.as_bytes().get(4) != Some(&b'-')
        || date.as_bytes().get(7) != Some(&b'-')
    {
        return false;
    }
    let Some(year) = fixed_decimal(&date[0..4]) else {
        return false;
    };
    let Some(month) = fixed_decimal(&date[5..7]) else {
        return false;
    };
    let Some(day) = fixed_decimal(&date[8..10]) else {
        return false;
    };
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return false;
    }

    let (clock, fraction) = time
        .split_once('.')
        .map_or((time, None), |(clock, fraction)| (clock, Some(fraction)));
    if clock.len() != 8
        || clock.as_bytes().get(2) != Some(&b':')
        || clock.as_bytes().get(5) != Some(&b':')
        || fraction
            .is_some_and(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    let Some(hour) = fixed_decimal(&clock[0..2]) else {
        return false;
    };
    let Some(minute) = fixed_decimal(&clock[3..5]) else {
        return false;
    };
    let Some(second) = fixed_decimal(&clock[6..8]) else {
        return false;
    };
    hour <= 23 && minute <= 59 && second <= 60
}

fn fixed_decimal(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}
