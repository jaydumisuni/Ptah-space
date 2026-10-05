"""MTK device simulation candidate for Ptah.

This module is deliberately outside frozen C05/C08 runtime authority.  It models
state transitions and proof obligations for Sleeper MTK development without
claiming physical mutation authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
from typing import Iterable


class Mode(str, Enum):
    OFFLINE = "offline"
    ANDROID_ADB = "android_adb"
    PRELOADER = "preloader"
    META = "meta"
    DA = "download_agent"
    FASTBOOT = "fastboot"


class Backend(str, Enum):
    METACORE = "metacore"
    MTK_BOOTMODE = "mtk_functions_bootmode"
    MTKCLIENT_DA = "mtkclient_da"
    ADB = "adb"
    FASTBOOT = "fastboot"
    UNKNOWN = "unknown"


class Qualification(str, Enum):
    PHYSICAL_PROVEN = "physical_proven"
    DONOR_MAPPED = "donor_mapped"
    SIMULATED_ONLY = "simulated_only"
    BLOCKED = "blocked"


class Capability(str, Enum):
    BOOT_META_FROM_PRELOADER = "boot_meta_from_preloader"
    META_INVENTORY = "meta_inventory"
    SERIAL_PSN_READ = "serial_psn_read"
    IMEI_READ = "imei_read"
    EXIT_META = "exit_meta"
    ENTER_DA_FROM_PRELOADER = "enter_da_from_preloader"
    PARTITION_LIST = "partition_list"
    PARTITION_READ = "partition_read"
    PARTITION_WRITE = "partition_write"
    PARTITION_ERASE = "partition_erase"
    FACTORY_RESET = "factory_reset"
    FRP_ERASE = "frp_erase"
    IMEI_WRITE = "imei_write"
    BOOTLOADER_UNLOCK = "bootloader_unlock"
    BOOTLOADER_RELOCK = "bootloader_relock"
    ADB_REBOOT_TO_META = "adb_reboot_to_meta"
    ENTER_FASTBOOT = "enter_fastboot"


MUTATING_CAPABILITIES = frozenset(
    {
        Capability.PARTITION_WRITE,
        Capability.PARTITION_ERASE,
        Capability.FACTORY_RESET,
        Capability.FRP_ERASE,
        Capability.IMEI_WRITE,
        Capability.BOOTLOADER_UNLOCK,
        Capability.BOOTLOADER_RELOCK,
    }
)


class SimulationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CapabilityRecord:
    capability: Capability
    backend: Backend
    required_modes: frozenset[Mode]
    qualification: Qualification
    donor: str | None = None
    evidence: tuple[str, ...] = ()

    @property
    def simulated(self) -> bool:
        return self.qualification is not Qualification.BLOCKED

    @property
    def physically_proven(self) -> bool:
        return self.qualification is Qualification.PHYSICAL_PROVEN


@dataclass(frozen=True)
class BackupArtifact:
    target: str
    data: bytes
    sha256: str


@dataclass
class MutationReceipt:
    capability: Capability
    target: str
    before_sha256: str
    after_sha256: str
    post_readback_sha256: str
    post_readback_verified: bool
    rollback_sha256: str | None = None
    rollback_verified: bool = False


@dataclass(frozen=True)
class IdentityBackup:
    imeis: tuple[str, ...]


@dataclass
class MtkSimDevice:
    platform: str
    firmware: str
    apdb_name: str
    mode: Mode = Mode.ANDROID_ADB
    usb_vid: str = "0e8d"
    usb_pid: str | None = None
    bootloader_locked: bool = True
    frp_present: bool = True
    userdata_initialized: bool = True
    serial: str = "SIM-MTK-0001"
    imeis: list[str] = field(default_factory=lambda: ["490154203237518", "356938035643809"])
    partitions: dict[str, bytes] = field(default_factory=dict)
    capability_records: dict[Capability, CapabilityRecord] = field(default_factory=dict)
    mutation_history: list[MutationReceipt] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.partitions:
            self.partitions = {
                "preloader": b"PRELOADER-SIM",
                "boot": b"BOOT-SIM",
                "vbmeta": b"VBMETA-SIM",
                "super": b"SUPER-SIM",
                "userdata": b"USERDATA-SIM",
                "frp": b"FRP-PRESENT",
                "nvram": b"NVRAM-SIM",
                "nvdata": b"NVDATA-SIM",
            }
        if not self.capability_records:
            self.capability_records = default_capability_records()

    def install_candidate(
        self,
        capability: Capability,
        *,
        backend: Backend,
        required_modes: Iterable[Mode],
        donor: str,
        evidence: Iterable[str] = (),
        qualification: Qualification = Qualification.SIMULATED_ONLY,
    ) -> None:
        if qualification is Qualification.PHYSICAL_PROVEN:
            raise SimulationError("Simulation cannot manufacture physical proof")
        self.capability_records[capability] = CapabilityRecord(
            capability=capability,
            backend=backend,
            required_modes=frozenset(required_modes),
            qualification=qualification,
            donor=donor,
            evidence=tuple(evidence),
        )

    def _require(self, capability: Capability) -> CapabilityRecord:
        record = self.capability_records[capability]
        if record.qualification is Qualification.BLOCKED:
            raise SimulationError(f"{capability.value} is blocked pending donor/physical proof")
        if self.mode not in record.required_modes:
            modes = ",".join(sorted(mode.value for mode in record.required_modes))
            raise SimulationError(
                f"{capability.value} requires mode {{{modes}}}, current={self.mode.value}"
            )
        return record

    def boot_meta_from_preloader(self, *, observed_pid: str) -> None:
        self._require(Capability.BOOT_META_FROM_PRELOADER)
        if observed_pid.lower() != "2007":
            raise SimulationError("BootMode acknowledgement without PID 2007 is not META proof")
        self.mode = Mode.META
        self.usb_pid = "2007"

    def adb_reboot_to_meta(self, *, observed_pid: str) -> None:
        self._require(Capability.ADB_REBOOT_TO_META)
        if observed_pid.lower() != "2007":
            raise SimulationError("ADB reboot request without observed PID 2007 is not META proof")
        self.mode = Mode.META
        self.usb_pid = "2007"

    def enter_da_from_preloader(self) -> None:
        self._require(Capability.ENTER_DA_FROM_PRELOADER)
        self.mode = Mode.DA
        self.usb_pid = "da"

    def enter_fastboot(self, *, observed_fastboot: bool) -> None:
        self._require(Capability.ENTER_FASTBOOT)
        if not observed_fastboot:
            raise SimulationError("fastboot request without observed Fastboot interface is not proof")
        self.mode = Mode.FASTBOOT
        self.usb_pid = None

    def meta_inventory(self) -> dict[str, object]:
        self._require(Capability.META_INVENTORY)
        return {
            "platform": self.platform,
            "firmware": self.firmware,
            "apdb_name": self.apdb_name,
            "imeis": tuple(self.imeis),
            "serial": None,
        }

    def read_serial_psn(self) -> str:
        self._require(Capability.SERIAL_PSN_READ)
        return self.serial

    def exit_meta(self, *, observed_android: bool = False) -> None:
        self._require(Capability.EXIT_META)
        if not observed_android:
            raise SimulationError("META exit acknowledgement without observed Android/ADB is not proof")
        self.mode = Mode.ANDROID_ADB
        self.usb_pid = None

    def partition_list(self) -> tuple[str, ...]:
        self._require(Capability.PARTITION_LIST)
        return tuple(sorted(self.partitions))

    def backup_partition(self, name: str) -> BackupArtifact:
        if name not in self.partitions:
            raise SimulationError(f"unknown partition: {name}")
        data = bytes(self.partitions[name])
        return BackupArtifact(name, data, sha256(data))

    def read_partition(self, name: str) -> bytes:
        self._require(Capability.PARTITION_READ)
        if name not in self.partitions:
            raise SimulationError(f"unknown partition: {name}")
        return bytes(self.partitions[name])

    def write_partition(
        self,
        name: str,
        data: bytes,
        *,
        backup: BackupArtifact,
    ) -> MutationReceipt:
        self._require(Capability.PARTITION_WRITE)
        self._validate_backup(name, backup)
        expected = sha256(data)
        self.partitions[name] = bytes(data)
        observed = sha256(self.partitions[name])
        receipt = MutationReceipt(
            capability=Capability.PARTITION_WRITE,
            target=name,
            before_sha256=backup.sha256,
            after_sha256=expected,
            post_readback_sha256=observed,
            post_readback_verified=(observed == expected),
        )
        self.mutation_history.append(receipt)
        return receipt

    def erase_partition(self, name: str, *, backup: BackupArtifact) -> MutationReceipt:
        self._require(Capability.PARTITION_ERASE)
        self._validate_backup(name, backup)
        erased = b"\x00" * len(self.partitions[name])
        self.partitions[name] = erased
        observed = sha256(self.partitions[name])
        receipt = MutationReceipt(
            capability=Capability.PARTITION_ERASE,
            target=name,
            before_sha256=backup.sha256,
            after_sha256=sha256(erased),
            post_readback_sha256=observed,
            post_readback_verified=(observed == sha256(erased)),
        )
        self.mutation_history.append(receipt)
        return receipt

    def rollback_partition(
        self,
        receipt: MutationReceipt,
        backup: BackupArtifact,
    ) -> MutationReceipt:
        if receipt.target != backup.target:
            raise SimulationError("rollback target does not match backup")
        self.partitions[backup.target] = bytes(backup.data)
        restored = sha256(self.partitions[backup.target])
        receipt.rollback_sha256 = restored
        receipt.rollback_verified = restored == backup.sha256
        return receipt

    def factory_reset(self, *, backup: BackupArtifact) -> MutationReceipt:
        self._require(Capability.FACTORY_RESET)
        self._validate_backup("userdata", backup)
        erased = b"\x00" * len(self.partitions["userdata"])
        self.partitions["userdata"] = erased
        self.userdata_initialized = False
        receipt = MutationReceipt(
            capability=Capability.FACTORY_RESET,
            target="userdata",
            before_sha256=backup.sha256,
            after_sha256=sha256(erased),
            post_readback_sha256=sha256(self.partitions["userdata"]),
            post_readback_verified=self.partitions["userdata"] == erased,
        )
        self.mutation_history.append(receipt)
        return receipt

    def frp_erase(self, *, backup: BackupArtifact) -> MutationReceipt:
        self._require(Capability.FRP_ERASE)
        self._validate_backup("frp", backup)
        erased = b"\x00" * len(self.partitions["frp"])
        self.partitions["frp"] = erased
        self.frp_present = False
        receipt = MutationReceipt(
            capability=Capability.FRP_ERASE,
            target="frp",
            before_sha256=backup.sha256,
            after_sha256=sha256(erased),
            post_readback_sha256=sha256(self.partitions["frp"]),
            post_readback_verified=(not self.frp_present and self.partitions["frp"] == erased),
        )
        self.mutation_history.append(receipt)
        return receipt

    def backup_identity(self) -> IdentityBackup:
        return IdentityBackup(tuple(self.imeis))

    def write_imeis(self, new_imeis: Iterable[str], *, backup: IdentityBackup) -> MutationReceipt:
        self._require(Capability.IMEI_WRITE)
        if tuple(self.imeis) != backup.imeis:
            raise SimulationError("identity backup is stale")
        values = tuple(new_imeis)
        if not values or any(not value.isdigit() or len(value) != 15 for value in values):
            raise SimulationError("simulated IMEI values must be 15 decimal digits")
        before = sha256("|".join(backup.imeis).encode())
        self.imeis = list(values)
        after = sha256("|".join(values).encode())
        observed = sha256("|".join(self.imeis).encode())
        receipt = MutationReceipt(
            capability=Capability.IMEI_WRITE,
            target="imei_slots",
            before_sha256=before,
            after_sha256=after,
            post_readback_sha256=observed,
            post_readback_verified=(observed == after),
        )
        self.mutation_history.append(receipt)
        return receipt

    def rollback_imeis(self, receipt: MutationReceipt, backup: IdentityBackup) -> MutationReceipt:
        self.imeis = list(backup.imeis)
        restored = sha256("|".join(self.imeis).encode())
        receipt.rollback_sha256 = restored
        receipt.rollback_verified = restored == receipt.before_sha256
        return receipt

    def bootloader_unlock(self) -> MutationReceipt:
        self._require(Capability.BOOTLOADER_UNLOCK)
        before = b"locked" if self.bootloader_locked else b"unlocked"
        self.bootloader_locked = False
        after = b"unlocked"
        receipt = MutationReceipt(
            capability=Capability.BOOTLOADER_UNLOCK,
            target="bootloader_lock_state",
            before_sha256=sha256(before),
            after_sha256=sha256(after),
            post_readback_sha256=sha256(b"unlocked" if not self.bootloader_locked else b"locked"),
            post_readback_verified=not self.bootloader_locked,
        )
        self.mutation_history.append(receipt)
        return receipt

    def bootloader_relock(self, unlock_receipt: MutationReceipt) -> MutationReceipt:
        self._require(Capability.BOOTLOADER_RELOCK)
        self.bootloader_locked = True
        restored = sha256(b"locked")
        unlock_receipt.rollback_sha256 = restored
        unlock_receipt.rollback_verified = restored == unlock_receipt.before_sha256
        return unlock_receipt

    def promotion_ready(self, capability: Capability) -> bool:
        record = self.capability_records[capability]
        if not record.physically_proven:
            return False
        if capability not in MUTATING_CAPABILITIES:
            return True
        receipts = [r for r in self.mutation_history if r.capability is capability]
        return bool(
            receipts
            and receipts[-1].post_readback_verified
            and receipts[-1].rollback_verified
        )

    def _validate_backup(self, target: str, backup: BackupArtifact) -> None:
        if backup.target != target:
            raise SimulationError("backup target mismatch")
        if target not in self.partitions:
            raise SimulationError(f"unknown partition: {target}")
        current = sha256(self.partitions[target])
        if current != backup.sha256:
            raise SimulationError("backup does not match current target state")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def default_capability_records() -> dict[Capability, CapabilityRecord]:
    def rec(
        capability: Capability,
        backend: Backend,
        modes: Iterable[Mode],
        qualification: Qualification,
        donor: str | None,
        *evidence: str,
    ) -> CapabilityRecord:
        return CapabilityRecord(
            capability=capability,
            backend=backend,
            required_modes=frozenset(modes),
            qualification=qualification,
            donor=donor,
            evidence=tuple(evidence),
        )

    return {
        Capability.BOOT_META_FROM_PRELOADER: rec(
            Capability.BOOT_META_FROM_PRELOADER,
            Backend.MTK_BOOTMODE,
            [Mode.PRELOADER],
            Qualification.PHYSICAL_PROVEN,
            "Sleeper/MTK_Functions",
            "0e8d:2000/2001 -> 0e8d:2007",
        ),
        Capability.META_INVENTORY: rec(
            Capability.META_INVENTORY,
            Backend.METACORE,
            [Mode.META],
            Qualification.PHYSICAL_PROVEN,
            "AndroidUtility.v200",
            "TargetVerInfo+ChipID+dynamic APDB+PRODUCT_INFO",
        ),
        Capability.IMEI_READ: rec(
            Capability.IMEI_READ,
            Backend.METACORE,
            [Mode.META],
            Qualification.PHYSICAL_PROVEN,
            "AndroidUtility.v200",
            "APDB-qualified IMEI array",
        ),
        Capability.SERIAL_PSN_READ: rec(
            Capability.SERIAL_PSN_READ,
            Backend.METACORE,
            [Mode.META],
            Qualification.BLOCKED,
            "AndroidUtility.v200",
            "ADBSeriaNo schema known; nested location not yet independently proved",
        ),
        Capability.EXIT_META: rec(
            Capability.EXIT_META,
            Backend.UNKNOWN,
            [Mode.META],
            Qualification.BLOCKED,
            None,
        ),
        Capability.ENTER_DA_FROM_PRELOADER: rec(
            Capability.ENTER_DA_FROM_PRELOADER,
            Backend.MTKCLIENT_DA,
            [Mode.PRELOADER],
            Qualification.DONOR_MAPPED,
            "Phoenix",
            "Partition Manager -> mtkclient Preloader/DA",
        ),
        Capability.PARTITION_LIST: rec(
            Capability.PARTITION_LIST,
            Backend.MTKCLIENT_DA,
            [Mode.DA],
            Qualification.DONOR_MAPPED,
            "Phoenix",
            "Partition Manager -> mtkclient",
        ),
        Capability.PARTITION_READ: rec(
            Capability.PARTITION_READ,
            Backend.MTKCLIENT_DA,
            [Mode.DA],
            Qualification.DONOR_MAPPED,
            "Phoenix",
            "mtkclient read",
        ),
        Capability.PARTITION_WRITE: rec(
            Capability.PARTITION_WRITE,
            Backend.MTKCLIENT_DA,
            [Mode.DA],
            Qualification.DONOR_MAPPED,
            "Phoenix",
            "mtkclient write; physical proof blocked",
        ),
        Capability.PARTITION_ERASE: rec(
            Capability.PARTITION_ERASE,
            Backend.MTKCLIENT_DA,
            [Mode.DA],
            Qualification.DONOR_MAPPED,
            "Phoenix",
            "mtkclient erase; physical proof blocked",
        ),
        Capability.FACTORY_RESET: rec(
            Capability.FACTORY_RESET,
            Backend.UNKNOWN,
            [Mode.META, Mode.DA],
            Qualification.BLOCKED,
            None,
        ),
        Capability.FRP_ERASE: rec(
            Capability.FRP_ERASE,
            Backend.UNKNOWN,
            [Mode.META, Mode.DA],
            Qualification.BLOCKED,
            None,
        ),
        Capability.IMEI_WRITE: rec(
            Capability.IMEI_WRITE,
            Backend.UNKNOWN,
            [Mode.META],
            Qualification.BLOCKED,
            None,
        ),
        Capability.BOOTLOADER_UNLOCK: rec(
            Capability.BOOTLOADER_UNLOCK,
            Backend.UNKNOWN,
            [Mode.FASTBOOT],
            Qualification.BLOCKED,
            None,
        ),
        Capability.BOOTLOADER_RELOCK: rec(
            Capability.BOOTLOADER_RELOCK,
            Backend.UNKNOWN,
            [Mode.FASTBOOT],
            Qualification.BLOCKED,
            None,
        ),
        Capability.ADB_REBOOT_TO_META: rec(
            Capability.ADB_REBOOT_TO_META,
            Backend.UNKNOWN,
            [Mode.ANDROID_ADB],
            Qualification.BLOCKED,
            None,
        ),
        Capability.ENTER_FASTBOOT: rec(
            Capability.ENTER_FASTBOOT,
            Backend.UNKNOWN,
            [Mode.ANDROID_ADB],
            Qualification.BLOCKED,
            None,
        ),
    }


def mt6768_fixture() -> MtkSimDevice:
    """Return a non-identifying MT6768 fixture derived from the COM18 proof shape."""

    return MtkSimDevice(
        platform="MT6768",
        firmware="alps-mp-v0.mp1.rc-V13.29_reallytek.v0mp1rc.k6991v1.64_P4",
        apdb_name="APDB_MT6768_S01__W2518",
        mode=Mode.META,
        usb_pid="2007",
    )
