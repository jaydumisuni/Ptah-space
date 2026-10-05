use ptah_device_runtime::DeviceKind;
use ptah_router_sim::{ROUTER_FAMILY, X100MachineState, X100Router};

#[test]
fn x100_is_persistent_ptah_virtual_machine() {
    let mut router = X100Router::new().unwrap();
    let first = router.cold_boot().unwrap();
    let second = router.cold_boot().unwrap();
    assert_eq!(first.device_kind, DeviceKind::VirtualMachine);
    assert_eq!(first.router_family, ROUTER_FAMILY);
    assert_eq!(first.device_ref, second.device_ref);
    assert_eq!(first.profile_revision_ref, second.profile_revision_ref);
    assert_eq!(first.boot_generation, 1);
    assert_eq!(second.boot_generation, 2);
    assert_eq!(second.state, X100MachineState::Bootrom);
}

#[test]
fn vendor_wire_contract_matches_recovered_x100_authority() {
    let mut router = X100Router::new().unwrap();
    let machine = router.cold_boot().unwrap();
    let wire = machine.profile.vendor_wire;
    assert_eq!(wire.change_baud, 115200);
    assert_eq!(wire.change_baud_payload_hex, "00c20100");
    assert_eq!(wire.change_baud_byte_order, "little_endian");
    assert!(!wire.keep_charge_after_change_baud);
    assert_eq!(wire.fdl2_exec_payload_hex, "9efffe00");
    assert_eq!(wire.fdl2_exec_payload_byte_order, "big_endian");
    assert!(!wire.fdl2_exec_ack_required);
    assert_eq!(wire.fdl2_exec_settle_ms, 2000);
    assert!(wire.same_process_same_usb_handle);
}
