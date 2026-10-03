//! Acceptance tests for the Ptah PS4 simulated-console startup contract.

use ptah_console_sim::{
    CONSOLE_FAMILY, ConsoleSimError, FirmwareStatus, Ps4Console, Ps4Engine, Ps4FirmwareRegistry,
};
use ptah_device_runtime::DeviceKind;

#[test]
fn registry_exposes_only_recovered_firmware_profiles() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    assert_eq!(
        registry.firmware_versions(),
        vec![
            "11.00", "11.50", "12.00", "12.02", "12.50", "12.52", "13.00", "13.02", "13.04",
            "13.50", "13.52", "14.00"
        ]
    );
}

#[test]
fn one_console_boots_1200_as_ptah_virtual_machine() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let mut console = Ps4Console::new().expect("console");
    let machine = console
        .select_and_boot(&registry, "12.00")
        .expect("boot 12.00");

    assert_eq!(machine.console_family, CONSOLE_FAMILY);
    assert_eq!(machine.device_kind, DeviceKind::VirtualMachine);
    assert_eq!(machine.firmware, "12.00");
    assert_eq!(machine.profile.ttg_status, FirmwareStatus::Proved);
    assert_eq!(machine.profile.engine, Some(Ps4Engine::Lapse));
    let material = machine.profile.boot_material().expect("boot material");
    assert_eq!(material.payload_size, 290_016);
    assert_eq!(
        material.engine_sha256,
        "fd0cc044e03be88d1c89089a7d8dbb2d2c9ea2f3a485f0ab9089bb36d92d1a34"
    );
    assert_eq!(machine.device_ref.entity_id, console.device_ref.entity_id);
    assert_eq!(
        machine
            .profile_revision_ref
            .record_revision
            .expect("profile record revision")
            .value(),
        1
    );
    assert_eq!(machine.boot_generation, 1);
}

#[test]
fn same_console_changes_firmware_without_changing_device_identity() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let mut console = Ps4Console::new().expect("console");

    let first = console
        .select_and_boot(&registry, "12.00")
        .expect("boot 12.00");
    let device_id = first.device_ref.entity_id;
    let first_profile_revision = first.profile_revision_ref.entity_id;

    let second = console
        .select_and_boot(&registry, "12.50")
        .expect("boot 12.50");

    assert_eq!(second.device_ref.entity_id, device_id);
    assert_ne!(
        second.profile_revision_ref.entity_id,
        first_profile_revision
    );
    assert_eq!(
        second
            .profile_revision_ref
            .record_revision
            .expect("profile record revision")
            .value(),
        2
    );
    assert_eq!(second.boot_generation, 2);
    assert_eq!(second.firmware, "12.50");
    assert_eq!(second.profile.engine, Some(Ps4Engine::Poops));
    assert_eq!(second.profile.ttg_status, FirmwareStatus::Candidate);
}

#[test]
fn reboot_same_firmware_keeps_profile_revision_and_console_identity() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let mut console = Ps4Console::new().expect("console");

    let first = console
        .select_and_boot(&registry, "12.00")
        .expect("first boot");
    let second = console
        .select_and_boot(&registry, "12.00")
        .expect("second boot");

    assert_eq!(second.device_ref.entity_id, first.device_ref.entity_id);
    assert_eq!(
        second.profile_revision_ref.entity_id,
        first.profile_revision_ref.entity_id
    );
    assert_eq!(second.profile_identity, first.profile_identity);
    assert_eq!(second.boot_generation, 2);
}

#[test]
fn same_console_can_cross_all_supported_engine_families() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let mut console = Ps4Console::new().expect("console");

    let lapse = console
        .select_and_boot(&registry, "12.00")
        .expect("boot 12.00");
    let device_id = lapse.device_ref.entity_id;

    let poops = console
        .select_and_boot(&registry, "13.00")
        .expect("boot 13.00");
    let raw13g = console
        .select_and_boot(&registry, "13.52")
        .expect("boot 13.52");

    assert_eq!(poops.device_ref.entity_id, device_id);
    assert_eq!(raw13g.device_ref.entity_id, device_id);
    assert_eq!(lapse.profile.engine, Some(Ps4Engine::Lapse));
    assert_eq!(poops.profile.engine, Some(Ps4Engine::Poops));
    assert_eq!(raw13g.profile.engine, Some(Ps4Engine::Raw13g663));
    assert_eq!(raw13g.boot_generation, 3);
    assert_eq!(
        raw13g
            .profile_revision_ref
            .record_revision
            .expect("revision")
            .value(),
        3
    );
}

#[test]
fn blocked_firmware_does_not_mutate_existing_console() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let mut console = Ps4Console::new().expect("console");
    let first = console
        .select_and_boot(&registry, "12.00")
        .expect("boot 12.00");
    let snapshot = console.clone();

    assert!(matches!(
        console.install_firmware(&registry, "14.00"),
        Err(ConsoleSimError::BlockedFirmware(version)) if version == "14.00"
    ));
    assert_eq!(console, snapshot);
    assert_eq!(console.device_ref.entity_id, first.device_ref.entity_id);
}

#[test]
fn unknown_firmware_is_not_nearest_version_fallback() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let mut console = Ps4Console::new().expect("console");

    assert!(matches!(
        console.install_firmware(&registry, "12.01"),
        Err(ConsoleSimError::UnsupportedFirmware(version)) if version == "12.01"
    ));
    assert!(console.installed.is_none());
}

#[test]
fn console_state_round_trip_preserves_identity_and_installed_firmware() {
    let registry = Ps4FirmwareRegistry::embedded().expect("embedded registry");
    let mut console = Ps4Console::new().expect("console");
    console
        .select_and_boot(&registry, "12.00")
        .expect("boot 12.00");

    let encoded = serde_json::to_string(&console).expect("serialize console");
    let mut restored: Ps4Console = serde_json::from_str(&encoded).expect("restore console");
    let device_id = restored.device_ref.entity_id;

    let next = restored
        .select_and_boot(&registry, "12.50")
        .expect("change firmware");

    assert_eq!(next.device_ref.entity_id, device_id);
    assert_eq!(next.firmware, "12.50");
    assert_eq!(next.boot_generation, 2);
}
