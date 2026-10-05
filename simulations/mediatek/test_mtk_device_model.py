from __future__ import annotations

import unittest

from mtk_device_model import (
    Backend,
    Capability,
    Mode,
    Qualification,
    SimulationError,
    mt6768_fixture,
    sha256,
)


class MtkDeviceSimulationTests(unittest.TestCase):
    def test_01_current_physical_meta_inventory_is_preserved(self) -> None:
        dev = mt6768_fixture()
        info = dev.meta_inventory()
        self.assertEqual(info["platform"], "MT6768")
        self.assertEqual(info["apdb_name"], "APDB_MT6768_S01__W2518")
        self.assertTrue(dev.promotion_ready(Capability.META_INVENTORY))
        self.assertTrue(dev.promotion_ready(Capability.IMEI_READ))

    def test_02_preloader_boot_requires_observed_pid2007(self) -> None:
        dev = mt6768_fixture()
        dev.mode = Mode.PRELOADER
        dev.usb_pid = "2000"
        with self.assertRaisesRegex(SimulationError, "PID 2007"):
            dev.boot_meta_from_preloader(observed_pid="2000")
        dev.boot_meta_from_preloader(observed_pid="2007")
        self.assertEqual(dev.mode, Mode.META)
        self.assertEqual(dev.usb_pid, "2007")

    def test_03_serial_psn_remains_blocked_until_independent_proof(self) -> None:
        dev = mt6768_fixture()
        with self.assertRaisesRegex(SimulationError, "blocked"):
            dev.read_serial_psn()
        self.assertFalse(dev.promotion_ready(Capability.SERIAL_PSN_READ))

    def test_04_exit_meta_remains_blocked_until_backend_mapping(self) -> None:
        dev = mt6768_fixture()
        with self.assertRaisesRegex(SimulationError, "blocked"):
            dev.exit_meta()

    def test_05_partition_list_and_read_use_da_not_meta(self) -> None:
        dev = mt6768_fixture()
        with self.assertRaisesRegex(SimulationError, "requires mode"):
            dev.partition_list()
        dev.mode = Mode.PRELOADER
        dev.enter_da_from_preloader()
        names = dev.partition_list()
        self.assertIn("boot", names)
        self.assertEqual(dev.read_partition("boot"), b"BOOT-SIM")
        self.assertFalse(dev.promotion_ready(Capability.PARTITION_READ))

    def test_06_partition_write_requires_matching_backup_and_readback(self) -> None:
        dev = mt6768_fixture()
        dev.mode = Mode.PRELOADER
        dev.enter_da_from_preloader()
        backup = dev.backup_partition("boot")
        stale = dev.backup_partition("vbmeta")
        with self.assertRaisesRegex(SimulationError, "backup target mismatch"):
            dev.write_partition("boot", b"BOOT-NEW", backup=stale)
        receipt = dev.write_partition("boot", b"BOOT-NEW", backup=backup)
        self.assertTrue(receipt.post_readback_verified)
        self.assertEqual(receipt.post_readback_sha256, sha256(b"BOOT-NEW"))
        self.assertFalse(dev.promotion_ready(Capability.PARTITION_WRITE))
        dev.rollback_partition(receipt, backup)
        self.assertTrue(receipt.rollback_verified)
        self.assertEqual(dev.read_partition("boot"), b"BOOT-SIM")

    def test_07_partition_erase_requires_backup_and_rollback(self) -> None:
        dev = mt6768_fixture()
        dev.mode = Mode.PRELOADER
        dev.enter_da_from_preloader()
        backup = dev.backup_partition("vbmeta")
        receipt = dev.erase_partition("vbmeta", backup=backup)
        self.assertTrue(receipt.post_readback_verified)
        self.assertEqual(dev.read_partition("vbmeta"), b"\x00" * len(backup.data))
        dev.rollback_partition(receipt, backup)
        self.assertTrue(receipt.rollback_verified)
        self.assertEqual(dev.read_partition("vbmeta"), backup.data)

    def test_08_factory_reset_semantics_can_be_exercised_without_promotion(self) -> None:
        dev = mt6768_fixture()
        dev.install_candidate(
            Capability.FACTORY_RESET,
            backend=Backend.METACORE,
            required_modes=[Mode.META],
            donor="candidate-only",
            evidence=["simulation-semantics-only"],
        )
        backup = dev.backup_partition("userdata")
        receipt = dev.factory_reset(backup=backup)
        self.assertTrue(receipt.post_readback_verified)
        self.assertFalse(dev.userdata_initialized)
        self.assertFalse(dev.promotion_ready(Capability.FACTORY_RESET))
        dev.rollback_partition(receipt, backup)
        self.assertTrue(receipt.rollback_verified)

    def test_09_frp_erase_semantics_can_be_exercised_without_promotion(self) -> None:
        dev = mt6768_fixture()
        dev.install_candidate(
            Capability.FRP_ERASE,
            backend=Backend.MTKCLIENT_DA,
            required_modes=[Mode.DA],
            donor="candidate-only",
            evidence=["simulation-semantics-only"],
        )
        dev.mode = Mode.DA
        backup = dev.backup_partition("frp")
        receipt = dev.frp_erase(backup=backup)
        self.assertTrue(receipt.post_readback_verified)
        self.assertFalse(dev.frp_present)
        self.assertFalse(dev.promotion_ready(Capability.FRP_ERASE))
        dev.rollback_partition(receipt, backup)
        self.assertTrue(receipt.rollback_verified)

    def test_10_imei_write_semantics_require_backup_and_never_self_promote(self) -> None:
        dev = mt6768_fixture()
        dev.install_candidate(
            Capability.IMEI_WRITE,
            backend=Backend.METACORE,
            required_modes=[Mode.META],
            donor="candidate-only",
            evidence=["simulation-semantics-only"],
        )
        backup = dev.backup_identity()
        receipt = dev.write_imeis(
            ["490154203237518", "356938035643809"],
            backup=backup,
        )
        self.assertTrue(receipt.post_readback_verified)
        self.assertFalse(dev.promotion_ready(Capability.IMEI_WRITE))
        dev.rollback_imeis(receipt, backup)
        self.assertTrue(receipt.rollback_verified)

    def test_11_bootloader_unlock_and_relock_can_be_modeled_without_backend_claim(self) -> None:
        dev = mt6768_fixture()
        dev.install_candidate(
            Capability.BOOTLOADER_UNLOCK,
            backend=Backend.FASTBOOT,
            required_modes=[Mode.FASTBOOT],
            donor="candidate-only",
            evidence=["simulation-semantics-only"],
        )
        dev.install_candidate(
            Capability.BOOTLOADER_RELOCK,
            backend=Backend.FASTBOOT,
            required_modes=[Mode.FASTBOOT],
            donor="candidate-only",
            evidence=["simulation-semantics-only"],
        )
        dev.mode = Mode.FASTBOOT
        unlock = dev.bootloader_unlock()
        self.assertTrue(unlock.post_readback_verified)
        self.assertFalse(dev.bootloader_locked)
        self.assertFalse(dev.promotion_ready(Capability.BOOTLOADER_UNLOCK))
        dev.bootloader_relock(unlock)
        self.assertTrue(dev.bootloader_locked)
        self.assertTrue(unlock.rollback_verified)

    def test_12_simulation_cannot_install_physical_proof(self) -> None:
        dev = mt6768_fixture()
        with self.assertRaisesRegex(SimulationError, "cannot manufacture physical proof"):
            dev.install_candidate(
                Capability.FRP_ERASE,
                backend=Backend.MTKCLIENT_DA,
                required_modes=[Mode.DA],
                donor="fake",
                qualification=Qualification.PHYSICAL_PROVEN,
            )

    def test_13_blocked_capabilities_remain_blocked_by_default(self) -> None:
        dev = mt6768_fixture()
        for capability in (
            Capability.SERIAL_PSN_READ,
            Capability.EXIT_META,
            Capability.FACTORY_RESET,
            Capability.FRP_ERASE,
            Capability.IMEI_WRITE,
            Capability.BOOTLOADER_UNLOCK,
            Capability.BOOTLOADER_RELOCK,
            Capability.ADB_REBOOT_TO_META,
        ):
            self.assertEqual(
                dev.capability_records[capability].qualification,
                Qualification.BLOCKED,
            )

    def test_14_partition_mutation_is_donor_mapped_but_not_physically_proven(self) -> None:
        dev = mt6768_fixture()
        for capability in (
            Capability.PARTITION_LIST,
            Capability.PARTITION_READ,
            Capability.PARTITION_WRITE,
            Capability.PARTITION_ERASE,
            Capability.ENTER_DA_FROM_PRELOADER,
        ):
            self.assertEqual(
                dev.capability_records[capability].qualification,
                Qualification.DONOR_MAPPED,
            )
            self.assertFalse(dev.promotion_ready(capability))


if __name__ == "__main__":
    unittest.main()
