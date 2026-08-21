//! Physical A12 qualification against the exact libarchive helper.
//!
//! These tests are ignored in ordinary workspace runs. The A12 physical proof
//! lane must set `PTAH_A12_LIBARCHIVE_HELPER` and execute them explicitly.

use decomposition_libarchive::{LibarchiveBackend, LibarchiveConfig, helper_sha256};
use ptah_archive_decomposition::{
    DecompositionBudget, DecompositionOutcome, DecompositionSpec, decompose,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::ProductionEvidence;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const SOURCE_SHA: &str = "d3a8ba457ae25c27c84fd2830a2efdcc5b1d40bf585d4eb0d35f47e99e5d4774";
static SERIAL: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ptah-a12-physical-{}-{serial}", std::process::id()));
        fs::create_dir_all(&path).expect("temp root");
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("reference")
}
fn helper_path() -> PathBuf {
    PathBuf::from(std::env::var("PTAH_A12_LIBARCHIVE_HELPER").expect("physical helper env"))
}
fn backend() -> LibarchiveBackend {
    let path = helper_path();
    let digest = helper_sha256(&path).expect("helper digest");
    LibarchiveBackend::open(LibarchiveConfig {
        helper_path: path,
        expected_helper_sha256: digest,
        expected_source_sha256: SOURCE_SHA.to_owned(),
        expected_version: "3.8.7".to_owned(),
        provider_ref: reference("runtime.provider"),
        provider_generation: 12,
        max_members: 1000,
        max_member_bytes: 8 * 1024 * 1024,
        max_total_bytes: 32 * 1024 * 1024,
        max_path_bytes: 8192,
    })
    .expect("qualified exact helper")
}
fn spec() -> DecompositionSpec {
    DecompositionSpec {
        workspace_ref: reference("core.workspace"),
        authority_ref: reference("identity.principal"),
        source_revision_ref: reference("object.revision"),
        production: ProductionEvidence {
            activity_ref: reference("core.activity"),
            operation_ref: reference("core.operation"),
            attempt_ref: reference("core.attempt"),
            receipt_refs: vec![reference("proof.receipt")],
        },
        budget: DecompositionBudget {
            max_depth: 4,
            max_members: 1000,
            max_expanded_bytes: 32 * 1024 * 1024,
            max_member_bytes: 8 * 1024 * 1024,
            max_path_chars: 8192,
        },
        requested_level: "L3_decomposed".to_owned(),
    }
}
fn python(root: &Path, script: &str) {
    let status = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(root)
        .status()
        .expect("python");
    assert!(status.success());
}

#[test]
#[ignore = "requires exact locked libarchive 3.8.7 helper"]
fn tar_zip_and_compressed_tar_decode() {
    let temp = Temp::new();
    python(
        &temp.0,
        r"import io,sys,tarfile,zipfile,pathlib
r=pathlib.Path(sys.argv[1])
for mode,name in [('w','plain.tar'),('w:gz','a.tar.gz'),('w:bz2','a.tar.bz2'),('w:xz','a.tar.xz')]:
    with tarfile.open(r/name,mode) as t:
        d=b'hello'; i=tarfile.TarInfo('dir/file.txt'); i.size=len(d); t.addfile(i,io.BytesIO(d))
with zipfile.ZipFile(r/'a.zip','w') as z:z.writestr('zip.txt',b'zip')
",
    );
    let b = backend();
    for name in ["plain.tar", "a.tar.gz", "a.tar.bz2", "a.tar.xz", "a.zip"] {
        let bytes = fs::read(temp.0.join(name)).expect("archive");
        let plan = decompose(&bytes, &spec(), &b).expect("plan");
        assert_eq!(plan.outcome, DecompositionOutcome::Complete, "{name}");
        assert!(!plan.recovered_members.is_empty(), "{name}");
    }
    let source = temp.0.join("zstd.tar");
    let payload = temp.0.join("zstd.txt");
    fs::write(&payload, b"zstd").expect("payload");
    let status = Command::new("tar")
        .args(["--zstd", "-cf"])
        .arg(&source)
        .arg("-C")
        .arg(&temp.0)
        .arg("zstd.txt")
        .status()
        .expect("tar zstd");
    assert!(status.success());
    let plan = decompose(&fs::read(source).expect("zstd archive"), &spec(), &b).expect("plan");
    assert_eq!(plan.outcome, DecompositionOutcome::Complete);
}

#[test]
#[ignore = "requires exact locked libarchive 3.8.7 helper"]
fn random_bytes_and_encrypted_zip_are_honest() {
    let b = backend();
    let random = decompose(b"not an archive", &spec(), &b).expect("bounded unsupported");
    assert_eq!(random.outcome, DecompositionOutcome::UnsupportedFormat);
    let temp = Temp::new();
    fs::write(temp.0.join("secret.txt"), b"secret").expect("secret");
    let status = Command::new("zip")
        .current_dir(&temp.0)
        .args(["-q", "-P", "pw", "encrypted.zip", "secret.txt"])
        .status()
        .expect("zip");
    assert!(status.success());
    let encrypted = decompose(
        &fs::read(temp.0.join("encrypted.zip")).expect("zip"),
        &spec(),
        &b,
    )
    .expect("bounded encrypted");
    assert_eq!(encrypted.outcome, DecompositionOutcome::LockedEncrypted);
    assert!(!encrypted.outcome.is_complete());
}

#[test]
#[ignore = "requires exact locked libarchive 3.8.7 helper"]
fn traversal_duplicate_and_symlink_fail_closed() {
    let temp = Temp::new();
    python(
        &temp.0,
        r"import io,sys,tarfile,zipfile,pathlib
r=pathlib.Path(sys.argv[1])
with zipfile.ZipFile(r/'bad.zip','w') as z:
    z.writestr('good.txt',b'good');z.writestr('../escape.txt',b'bad')
with zipfile.ZipFile(r/'dup.zip','w') as z:
    z.writestr('a/./b',b'1');z.writestr('a/b',b'2')
with tarfile.open(r/'link.tar','w') as t:
    i=tarfile.TarInfo('link');i.type=tarfile.SYMTYPE;i.linkname='../../escape';t.addfile(i)
",
    );
    let b = backend();
    for name in ["bad.zip", "dup.zip", "link.tar"] {
        let plan = decompose(&fs::read(temp.0.join(name)).expect("archive"), &spec(), &b)
            .expect("bounded plan");
        assert!(!plan.outcome.is_complete(), "{name}");
    }
    assert!(!temp.0.join("escape.txt").exists());
}

#[test]
#[ignore = "requires exact locked libarchive 3.8.7 helper"]
fn nested_provenance_is_container_bound_and_tamper_sensitive() {
    let temp = Temp::new();
    python(
        &temp.0,
        r"import io,sys,tarfile,zipfile,pathlib
r=pathlib.Path(sys.argv[1]); inner=io.BytesIO()
with zipfile.ZipFile(inner,'w') as z:z.writestr('child.bin',b'payload')
data=inner.getvalue()
with tarfile.open(r/'outer.tar','w') as t:
    i=tarfile.TarInfo('nested.zip');i.size=len(data);t.addfile(i,io.BytesIO(data))
",
    );
    let bytes = fs::read(temp.0.join("outer.tar")).expect("outer");
    let b = backend();
    let plan = decompose(&bytes, &spec(), &b).expect("plan");
    assert_eq!(plan.recovered_members.len(), 2);
    assert_eq!(
        plan.recovered_members[1].parent_inventory_index,
        Some(plan.recovered_members[0].inventory_index)
    );
    assert_eq!(
        plan.recovered_members[1].logical_path,
        "nested.zip/child.bin"
    );
    let mut tampered = plan.recovered_members[0].bytes.clone();
    tampered.push(0);
    assert_ne!(
        ptah_object_store::ObjectStore::sha256(&tampered),
        plan.recovered_members[0].member_sha256
    );
}

#[test]
#[ignore = "requires exact locked libarchive 3.8.7 helper"]
fn helper_replacement_is_fenced_before_parse() {
    let path = helper_path();
    let temp = Temp::new();
    let copy = temp.0.join("helper");
    fs::copy(&path, &copy).expect("copy");
    let expected = helper_sha256(&copy).expect("digest");
    fs::OpenOptions::new()
        .append(true)
        .open(&copy)
        .expect("open")
        .write_all(b"tamper")
        .expect("tamper");
    let result = LibarchiveBackend::open(LibarchiveConfig {
        helper_path: copy,
        expected_helper_sha256: expected,
        expected_source_sha256: SOURCE_SHA.to_owned(),
        expected_version: "3.8.7".to_owned(),
        provider_ref: reference("runtime.provider"),
        provider_generation: 12,
        max_members: 10,
        max_member_bytes: 1024,
        max_total_bytes: 4096,
        max_path_bytes: 1024,
    });
    assert!(result.is_err());
}

#[test]
#[ignore = "requires host-linked wrong-version helper"]
fn host_libarchive_3_7_4_cannot_qualify_as_a12_backend() {
    let path =
        PathBuf::from(std::env::var("PTAH_A12_WRONG_LIBARCHIVE_HELPER").expect("wrong helper env"));
    let digest = helper_sha256(&path).expect("digest");
    let result = LibarchiveBackend::open(LibarchiveConfig {
        helper_path: path,
        expected_helper_sha256: digest,
        expected_source_sha256: SOURCE_SHA.to_owned(),
        expected_version: "3.8.7".to_owned(),
        provider_ref: reference("runtime.provider"),
        provider_generation: 12,
        max_members: 10,
        max_member_bytes: 1024,
        max_total_bytes: 4096,
        max_path_bytes: 1024,
    });
    assert!(result.is_err());
}
