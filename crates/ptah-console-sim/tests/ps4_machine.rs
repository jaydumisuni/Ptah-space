//! Acceptance tests for the Ptah PS4 simulated-console startup contract.

use ptah_console_sim::{
    ConsoleSimError, FirmwareStatus, Ps4Engine, Ps4FirmwareRegistry, CONSOLE_FAMILY,
};
use ptah_device_runtime::DeviceKind;

#[test]
fn registry_exposes_only_recovered_firmware_profiles() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    assert_eq!(
        registry.firmware_versions(),
        vec![
            "11.00", "11.50", "12.00", "12.02", "12.50", "12.52", "13.00", "14.00"
        ]
    );
}

#[test]
fn proved_1200_boots_as_ptah_virtual_machine() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let machine = registry.boot("12.00").expect("boot 12.00");

    assert_eq!(machine.console_family, CONSOLE_FAMILY);
    assert_eq!(machine.device_kind, DeviceKind::VirtualMachine);
    assert_eq!(machine.firmware, "12.00");
    assert_eq!(machine.profile.ttg_status, FirmwareStatus::Proved);
    assert_eq!(machine.profile.engine, Some(Ps4Engine::Lapse));
    assert_eq!(machine.profile.boot_material().expect("boot material").payload_size, 286_336);
    assert!(machine.profile_identity.profile_key.starts_with("ps4-fw-12.00-"));
    assert_eq!(machine.profile_identity.profile_digest.len(), 64);
    assert_eq!(machine.profile_revision_ref.record_revision.map(|value| value.value()), Some(1));
}

#[test]
fn candidate_1250_selects_poops_without_promoting_it() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let machine = registry.boot("12.50").expect("boot 12.50");

    assert_eq!(machine.profile.ttg_status, FirmwareStatus::Candidate);
    assert_eq!(machine.profile.engine, Some(Ps4Engine::Poops));
}

#[test]
fn blocked_1400_fails_closed() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    assert!(matches!(
        registry.boot("14.00"),
        Err(ConsoleSimError::BlockedFirmware(version)) if version == "14.00"
    ));
}

#[test]
fn unknown_firmware_is_not_nearest_version_fallback() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    assert!(matches!(
        registry.boot("12.01"),
        Err(ConsoleSimError::UnsupportedFirmware(version)) if version == "12.01"
    ));
}

#[test]
fn repeated_boots_keep_profile_identity_but_get_new_ptah_entities() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let first = registry.boot("12.00").expect("first boot");
    let second = registry.boot("12.00").expect("second boot");

    assert_eq!(first.profile_identity, second.profile_identity);
    assert_ne!(first.device_ref.entity_id, second.device_ref.entity_id);
    assert_ne!(
        first.profile_revision_ref.entity_id,
        second.profile_revision_ref.entity_id
    );
}
