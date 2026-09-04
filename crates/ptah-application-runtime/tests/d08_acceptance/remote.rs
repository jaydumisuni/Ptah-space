use ptah_application_runtime::{
    ApplicationOperation, ExecutionDisposition, PlatformClass, RemoteNodeRequirement,
    require_remote_display,
};
use ptah_identifiers::EntityRef;

fn evidence() -> EntityRef {
    EntityRef::new("proof.evidence").expect("valid evidence kind")
}

#[test]
fn d08_25_remote_display_requirement_remains_a_non_executing_programme_e_blocker() {
    let disposition = ExecutionDisposition::for_platform(
        PlatformClass::WindowsNode,
        ApplicationOperation::RemoteDisplay,
        None,
        vec![evidence()],
        "2026-09-03T12:00:00Z",
    )
    .expect("remote platform should retain a Programme E blocker");
    let ExecutionDisposition::RequiresRemoteNode(requirement) = disposition else {
        panic!("remote display must not become an executable D08 session");
    };

    let retained: RemoteNodeRequirement =
        require_remote_display(&requirement).expect("blocker should remain mechanically visible");
    assert_eq!(retained, requirement);
    assert_eq!(retained.operation, ApplicationOperation::RemoteDisplay);
    assert_eq!(retained.roadmap_dependency, "Programme E");
    assert!(!retained.evidence_refs.is_empty());
}
