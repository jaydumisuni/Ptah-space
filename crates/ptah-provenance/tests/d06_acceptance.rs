//! D06 provenance/SBOM/signing acceptance corpus.

use ptah_identifiers::EntityRef;
use ptah_provenance::{D06Error, ExactSubject};

fn er(kind: &str) -> EntityRef {
    EntityRef::new(kind).unwrap()
}

#[test]
fn exact_immutable_subject_and_digest_are_required() {
    let exact = ExactSubject {
        subject_ref: er("core.object_revision"),
        digest_refs: vec![er("core.object_revision")],
        aliases: vec!["registry.example/app:latest".into()],
    };
    assert_eq!(exact.validate(), Ok(()));

    let missing_digest = ExactSubject {
        digest_refs: vec![],
        ..exact.clone()
    };
    assert_eq!(missing_digest.validate(), Err(D06Error::InexactSubject));
}

#[test]
fn mutable_alias_cannot_become_proof_subject_identity() {
    let mutable = ExactSubject {
        subject_ref: er("knowledge.source"),
        digest_refs: vec![er("core.object_revision")],
        aliases: vec!["main".into(), "latest".into()],
    };
    assert_eq!(mutable.validate(), Err(D06Error::InexactSubject));
}
